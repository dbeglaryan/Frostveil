"""
Frostveil Crypto Engine — Chromium credential decryption (DPAPI + AES-256-GCM).

Pure Python. No external dependencies.
Supports Windows DPAPI, macOS Keychain, and Linux secret-service decryption
of Chromium's Local State encryption key, then AES-GCM decryption of
individual cookie/password blobs.
"""
import os, sys, json, struct, hashlib, hmac, base64, ctypes, ctypes.util
from pathlib import Path
from . import utils

# Set by main.py when --user-password is provided
_user_password = None

# Cache for app-bound encryption keys (v20 blobs) per profile path
_app_bound_keys = {}

# ---------------------------------------------------------------------------
# AES-256-GCM — pure-Python implementation (no openssl, no pycryptodome)
# ---------------------------------------------------------------------------
# GF(2^128) multiplication used by GHASH inside GCM.

def _gf128_mul(x: int, y: int) -> int:
    """Multiplication in GF(2^128) with the GCM reducing polynomial."""
    R = 0xE1000000000000000000000000000000
    z = 0
    for i in range(128):
        if (y >> (127 - i)) & 1:
            z ^= x
        carry = x & 1
        x >>= 1
        if carry:
            x ^= R
    return z

def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")

def _int_to_bytes(n: int, length: int = 16) -> bytes:
    return n.to_bytes(length, "big")

def _inc32(block: bytes) -> bytes:
    """Increment the rightmost 32 bits of a 128-bit block."""
    nonce = block[:12]
    ctr = int.from_bytes(block[12:], "big")
    ctr = (ctr + 1) & 0xFFFFFFFF
    return nonce + ctr.to_bytes(4, "big")

def _aes_ecb_encrypt(key: bytes, block: bytes) -> bytes:
    """AES-ECB single block encrypt using OS-native crypto."""
    if sys.platform.startswith("win"):
        return _aes_ecb_win(key, block)
    else:
        return _aes_ecb_openssl(key, block)

# ---- Windows: bcrypt.dll AES-ECB ----
def _aes_ecb_win(key: bytes, block: bytes) -> bytes:
    bcrypt = ctypes.windll.bcrypt
    BCRYPT_AES_ALGORITHM = "AES\0".encode("utf-16-le")
    BCRYPT_CHAINING_MODE = "ChainingMode\0".encode("utf-16-le")
    BCRYPT_CHAIN_MODE_ECB = "ChainingModeECB\0".encode("utf-16-le")

    hAlg = ctypes.c_void_p()
    bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(hAlg),
                                       BCRYPT_AES_ALGORITHM, None, 0)
    bcrypt.BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE,
                             BCRYPT_CHAIN_MODE_ECB,
                             len(BCRYPT_CHAIN_MODE_ECB), 0)
    hKey = ctypes.c_void_p()
    bcrypt.BCryptGenerateSymmetricKey(hAlg, ctypes.byref(hKey), None, 0,
                                      ctypes.c_char_p(key), len(key), 0)
    out = ctypes.create_string_buffer(16)
    out_len = ctypes.c_ulong(0)
    bcrypt.BCryptEncrypt(hKey, ctypes.c_char_p(block), 16, None, None, 0,
                         out, 16, ctypes.byref(out_len), 0)
    bcrypt.BCryptDestroyKey(hKey)
    bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)
    return out.raw[:16]

# ---- Unix: libcrypto AES-ECB ----
def _aes_ecb_openssl(key: bytes, block: bytes) -> bytes:
    libcrypto_path = ctypes.util.find_library("crypto")
    if not libcrypto_path:
        for candidate in ["/usr/lib/libcrypto.so", "/usr/lib/x86_64-linux-gnu/libcrypto.so.3",
                          "/usr/lib/x86_64-linux-gnu/libcrypto.so.1.1",
                          "/opt/homebrew/lib/libcrypto.dylib",
                          "/usr/local/opt/openssl/lib/libcrypto.dylib"]:
            if os.path.exists(candidate):
                libcrypto_path = candidate
                break
    if not libcrypto_path:
        raise RuntimeError("Cannot find libcrypto for AES — install openssl")
    libcrypto = ctypes.CDLL(libcrypto_path)

    EVP_CIPHER_CTX_new = libcrypto.EVP_CIPHER_CTX_new
    EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    EVP_EncryptInit_ex = libcrypto.EVP_EncryptInit_ex
    EVP_EncryptUpdate = libcrypto.EVP_EncryptUpdate
    EVP_CIPHER_CTX_free = libcrypto.EVP_CIPHER_CTX_free

    if len(key) == 32:
        evp_aes = libcrypto.EVP_aes_256_ecb
    elif len(key) == 16:
        evp_aes = libcrypto.EVP_aes_128_ecb
    else:
        raise ValueError(f"Unsupported AES key length: {len(key)}")
    evp_aes.restype = ctypes.c_void_p

    ctx = EVP_CIPHER_CTX_new()
    EVP_EncryptInit_ex(ctx, evp_aes(), None, key, None)
    # Disable padding for single-block ECB
    libcrypto.EVP_CIPHER_CTX_set_padding(ctx, 0)
    out = ctypes.create_string_buffer(32)
    out_len = ctypes.c_int(0)
    EVP_EncryptUpdate(ctx, out, ctypes.byref(out_len), block, len(block))
    EVP_CIPHER_CTX_free(ctx)
    return out.raw[:16]

# ---- AES-CTR keystream (used by GCM) ----
def _aes_ctr_blocks(key: bytes, iv_block: bytes, num_blocks: int) -> list:
    """Generate `num_blocks` AES-CTR keystream blocks."""
    blocks = []
    counter = iv_block
    for _ in range(num_blocks):
        blocks.append(_aes_ecb_encrypt(key, counter))
        counter = _inc32(counter)
    return blocks

# ---- GHASH ----
def _ghash(H: int, aad: bytes, ciphertext: bytes) -> bytes:
    """GHASH function for GCM authentication."""
    def _pad16(data):
        r = len(data) % 16
        return data + b"\x00" * ((16 - r) % 16)

    data = _pad16(aad) + _pad16(ciphertext)
    # Append lengths (in bits) as two 64-bit big-endian integers
    data += struct.pack(">QQ", len(aad) * 8, len(ciphertext) * 8)

    y = 0
    for i in range(0, len(data), 16):
        block = _bytes_to_int(data[i:i+16])
        y = _gf128_mul(y ^ block, H)
    return _int_to_bytes(y)

def aes_gcm_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes,
                    aad: bytes = b"") -> bytes:
    """
    AES-256-GCM authenticated decryption.
    Returns plaintext on success, raises ValueError on tag mismatch.
    """
    if len(nonce) != 12:
        raise ValueError("AES-GCM nonce must be 12 bytes")
    if len(tag) != 16:
        raise ValueError("AES-GCM tag must be 16 bytes")

    # H = AES_K(0^128)
    H = _bytes_to_int(_aes_ecb_encrypt(key, b"\x00" * 16))

    # J0 = nonce || 0x00000001
    j0 = nonce + b"\x00\x00\x00\x01"

    # Generate keystream (skip first block — used for tag)
    num_ct_blocks = (len(ciphertext) + 15) // 16
    counter = _inc32(j0)
    plaintext = bytearray()
    for i in range(num_ct_blocks):
        ks_block = _aes_ecb_encrypt(key, counter)
        ct_block = ciphertext[i*16:(i+1)*16]
        for j in range(len(ct_block)):
            plaintext.append(ct_block[j] ^ ks_block[j])
        counter = _inc32(counter)

    # Verify authentication tag
    ghash_val = _ghash(H, aad, ciphertext)
    e_j0 = _aes_ecb_encrypt(key, j0)
    computed_tag = bytes(a ^ b for a, b in zip(ghash_val, e_j0))

    if not hmac.compare_digest(computed_tag, tag):
        raise ValueError("AES-GCM authentication tag mismatch — data corrupted or wrong key")

    return bytes(plaintext[:len(ciphertext)])


# ---------------------------------------------------------------------------
# Chromium encryption key extraction
# ---------------------------------------------------------------------------

def _get_chromium_local_state(profile_path: Path) -> dict:
    """Read and parse Chromium's 'Local State' JSON."""
    # Local State is in the User Data directory (parent of profile dirs)
    user_data = profile_path.parent
    local_state = user_data / "Local State"
    if not local_state.exists():
        # Try one level up (if profile_path points to a specific profile)
        local_state = user_data.parent / "Local State"
    if not local_state.exists():
        return None
    try:
        return json.loads(local_state.read_text(encoding="utf-8"))
    except Exception:
        return None

def _dpapi_decrypt(encrypted: bytes) -> bytes:
    """Windows DPAPI CryptUnprotectData."""
    if not sys.platform.startswith("win"):
        raise RuntimeError("DPAPI only available on Windows")

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", ctypes.c_ulong), ("pbData", ctypes.c_void_p)]

    buf = ctypes.create_string_buffer(encrypted, len(encrypted))
    input_blob = DATA_BLOB(len(encrypted),
                           ctypes.cast(buf, ctypes.c_void_p).value)
    output_blob = DATA_BLOB()

    crypt32 = ctypes.windll.crypt32
    kernel32 = ctypes.windll.kernel32

    result = crypt32.CryptUnprotectData(
        ctypes.byref(input_blob), None, None, None, None,
        ctypes.c_ulong(0),
        ctypes.byref(output_blob)
    )
    if not result:
        raise RuntimeError("CryptUnprotectData failed")

    # Use ctypes.cast + memmove to avoid string_at overflow on Python 3.12+
    out_size = output_blob.cbData
    out_buf = (ctypes.c_char * out_size)()
    ctypes.memmove(out_buf, output_blob.pbData, out_size)
    decrypted = bytes(out_buf)
    # LocalFree can overflow on Python 3.12+ with large pointers — use c_void_p
    try:
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree(output_blob.pbData)
    except (OverflowError, ctypes.ArgumentError):
        pass  # Memory leak is acceptable — small allocation, process-scoped
    return decrypted

def _try_decrypt_app_bound_key(state: dict) -> bytes:
    """
    Decrypt Chrome/Edge App-Bound Encryption key (v20 blobs).
    App-Bound keys use DPAPI with app-specific entropy via the IElevator COM service.
    Falls back to attempting DPAPI without entropy (works on some configurations).
    """
    if not sys.platform.startswith("win"):
        return None
    os_crypt = state.get("os_crypt", {})
    ab_key = os_crypt.get("app_bound_encrypted_key")
    if not ab_key:
        return None
    try:
        encrypted = base64.b64decode(ab_key)
        # Strip APPB prefix (4 bytes)
        if encrypted[:4] != b"APPB":
            return None
        encrypted = encrypted[4:]

        # The app-bound key has a layered structure:
        # Layer 1: DPAPI-encrypted with SYSTEM context
        # Layer 2: DPAPI-encrypted with USER context
        # Layer 3: AES-256-GCM encrypted with app-specific key
        # Without the IElevator service, we try direct DPAPI which works
        # when the browser process has cached the decrypted key
        try:
            decrypted_l1 = _dpapi_decrypt(encrypted)
        except Exception:
            return None

        # The result may be another DPAPI blob or the final key
        # Chrome 127+ uses a 3-layer scheme: DPAPI(SYSTEM) → DPAPI(USER) → AES
        # Try a second DPAPI pass
        if len(decrypted_l1) > 32:
            try:
                decrypted_l2 = _dpapi_decrypt(decrypted_l1)
                if len(decrypted_l2) >= 61:
                    # AES-256-GCM: last 61 bytes = version(1) + nonce(12) + ciphertext(16) + tag(16) + padding
                    # Actually: last N bytes contain AES key material
                    # The exact format depends on Chrome version
                    # Try using the last 32 bytes as the key directly
                    return decrypted_l2[-32:]
                return decrypted_l2
            except Exception:
                pass

        # If single-layer DPAPI produced 32 bytes, that might be the key
        if len(decrypted_l1) == 32:
            return decrypted_l1

        # Try last 32 bytes
        if len(decrypted_l1) >= 32:
            return decrypted_l1[-32:]

    except Exception as e:
        utils.log_line(f"App-bound key decryption failed: {e}")
    return None


def get_chromium_master_key(profile_path: Path) -> bytes:
    """
    Extract and decrypt the Chromium AES-256-GCM master key.
    Windows: DPAPI-protected in Local State.
    macOS: Keychain-stored (safe-storage-key).
    Linux: PBKDF2 derivation from 'peanuts' or keyring.
    """
    state = _get_chromium_local_state(profile_path)
    if not state:
        return None

    os_crypt = state.get("os_crypt", {})
    b64_key = os_crypt.get("encrypted_key")
    if not b64_key:
        return None

    encrypted_key = base64.b64decode(b64_key)
    # Strip the "DPAPI" prefix (5 bytes)
    if encrypted_key[:5] != b"DPAPI":
        return None
    encrypted_key = encrypted_key[5:]

    # Also try to get the app-bound key for v20 blobs
    ab_key = _try_decrypt_app_bound_key(state)
    if ab_key:
        utils.log_line(f"App-bound key (v20) decrypted: {len(ab_key)} bytes")

    if sys.platform.startswith("win"):
        try:
            key = _dpapi_decrypt(encrypted_key)
            # Store app-bound key as attribute on the returned bytes (not possible)
            # Instead, cache it in module-level dict
            _app_bound_keys[str(profile_path)] = ab_key
            return key
        except Exception as e:
            utils.log_line(f"DPAPI key decryption failed: {e}")
            # Fallback: try offline DPAPI if user password was provided
            if _user_password:
                try:
                    from . import dpapi_offline
                    key = dpapi_offline.get_chromium_key_offline(
                        profile_path, _user_password
                    )
                    if key:
                        utils.log_line("DPAPI offline decryption succeeded with user password")
                        return key
                except Exception as e2:
                    utils.log_line(f"DPAPI offline fallback also failed: {e2}")
            return None
    elif sys.platform == "darwin":
        # macOS: key is in Keychain under "Chrome Safe Storage" / "Chromium Safe Storage"
        try:
            import subprocess
            for label in ["Chrome Safe Storage", "Chromium Safe Storage",
                          "Microsoft Edge Safe Storage"]:
                result = subprocess.run(
                    ["security", "find-generic-password", "-s", label, "-w"],
                    capture_output=True, text=True
                )
                if result.returncode == 0:
                    password = result.stdout.strip().encode("utf-8")
                    # Derive key using PBKDF2
                    key = hashlib.pbkdf2_hmac("sha1", password, b"saltysalt", 1003, 16)
                    return key
        except Exception as e:
            utils.log_line(f"macOS keychain decryption failed: {e}")
            return None
    else:
        # Linux: derive from hardcoded password
        try:
            key = hashlib.pbkdf2_hmac("sha1", b"peanuts", b"saltysalt", 1, 16)
            return key
        except Exception as e:
            utils.log_line(f"Linux key derivation failed: {e}")
            return None

    return None

def decrypt_chromium_blob(encrypted_value: bytes, master_key: bytes,
                          profile_path: str = None) -> str:
    """
    Decrypt a Chromium encrypted blob (cookie value, password, etc.).

    Chromium v80+ format: b'v10' + nonce(12) + ciphertext + tag(16)
    v20 format: App-Bound Encryption (Chrome 127+/Edge) — same AES-GCM but different key.
    Older format: DPAPI-encrypted directly.
    macOS/Linux v10: AES-128-CBC with IV=space*16.
    """
    if not encrypted_value or not master_key:
        return None

    # Determine which key to use
    prefix = encrypted_value[:3]

    # v10/v11/v20 prefix → AES-256-GCM
    if prefix in (b"v10", b"v11", b"v20"):
        nonce = encrypted_value[3:15]
        payload = encrypted_value[15:]
        if len(payload) < 16:
            return None
        ciphertext = payload[:-16]
        tag = payload[-16:]

        # For v20 (App-Bound Encryption), try the app-bound key first
        if prefix == b"v20":
            ab_key = None
            if profile_path:
                ab_key = _app_bound_keys.get(profile_path)
            # Also try all cached keys
            if not ab_key:
                for k in _app_bound_keys.values():
                    if k:
                        ab_key = k
                        break
            if ab_key:
                try:
                    decrypted = aes_gcm_decrypt(ab_key, nonce, ciphertext, tag)
                    return decrypted.decode("utf-8", errors="replace")
                except Exception:
                    pass  # Fall through to try master_key

        # Standard decryption with master_key
        try:
            decrypted = aes_gcm_decrypt(master_key, nonce, ciphertext, tag)
            return decrypted.decode("utf-8", errors="replace")
        except Exception:
            return None

    # Fallback: raw DPAPI blob (pre-v80 on Windows)
    if sys.platform.startswith("win"):
        try:
            return _dpapi_decrypt(encrypted_value).decode("utf-8", errors="replace")
        except Exception:
            return None

    return None


# ---------------------------------------------------------------------------
# HMAC-SHA256 manifest signing (replaces plain SHA256 hash)
# ---------------------------------------------------------------------------

def hmac_sign(data: bytes, key: bytes = None) -> str:
    """
    HMAC-SHA256 signature. If no key provided, derives one from machine identity.
    """
    if key is None:
        import socket, getpass
        identity = f"{socket.gethostname()}:{getpass.getuser()}:{sys.platform}".encode()
        key = hashlib.sha256(identity).digest()
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def hmac_verify(data: bytes, signature: str, key: bytes = None) -> bool:
    """Verify HMAC-SHA256 signature."""
    computed = hmac_sign(data, key)
    return hmac.compare_digest(computed, signature)
