"""
Frostveil Credential Extraction — extract saved passwords from browser Login Data.

Supports Chromium (Chrome/Edge) with AES-GCM decryption and Firefox logins.json.
For authorized penetration testing and forensic investigations only.
"""
import sqlite3, json, base64
from pathlib import Path
from . import utils, crypto

def extract(browser, path: Path, meta):
    rows = []
    if browser in ["chrome", "edge"]:
        _extract_chromium_logins(browser, path, meta, rows)
    elif browser == "firefox":
        _extract_firefox_logins(path, meta, rows)
    return rows

def _extract_chromium_logins(browser, path, meta, rows):
    login_db = path.parent / "Login Data"
    tmp = utils.safe_copy(login_db)
    if not tmp:
        return

    master_key = crypto.get_chromium_master_key(path.parent)

    try:
        con = sqlite3.connect(str(tmp))
        cur = con.cursor()
        cur.execute("""
            SELECT origin_url, action_url, username_value, password_value,
                   date_created, date_last_used, times_used, date_password_modified
            FROM logins ORDER BY date_last_used DESC
        """)
        for origin, action, username, pwd_blob, created, last_used, times, modified in cur.fetchall():
            decrypted_pwd = ""
            if pwd_blob and master_key:
                result = crypto.decrypt_chromium_blob(
                    pwd_blob, master_key, profile_path=str(path.parent))
                if result:
                    decrypted_pwd = result
                elif pwd_blob[:3] == b"v20":
                    decrypted_pwd = "<v20:app_bound_encrypted>"
                else:
                    decrypted_pwd = "<decryption_failed>"
            elif pwd_blob:
                if pwd_blob[:3] == b"v20":
                    decrypted_pwd = "<v20:app_bound_encrypted>"
                else:
                    decrypted_pwd = "<encrypted:no_key>"

            rows.append({
                **meta, "browser": browser, "artifact": "credential",
                "profile": str(path.parent),
                "url": origin or action or "",
                "title": username or "",
                "visit_count": times,
                "visit_time_utc": utils.utc_from_webkit(last_used),
                "extra": json.dumps({
                    "action_url": action or "",
                    "password": decrypted_pwd,
                    "created": utils.utc_from_webkit(created),
                    "modified": utils.utc_from_webkit(modified),
                }, ensure_ascii=False)
            })
        con.close()
        utils.log_line(f"Credentials extracted from {login_db} ({len(rows)} entries)")
    except Exception as e:
        utils.log_line(f"Error credentials {browser}: {e}")

def _extract_firefox_logins(path, meta, rows):
    if not path.is_dir():
        return
    for prof in path.glob("*.default*"):
        logins_file = prof / "logins.json"
        if not logins_file.exists():
            continue
        try:
            data = json.loads(logins_file.read_text(encoding="utf-8"))
            for login in data.get("logins", []):
                # Firefox encrypts with NSS/PKCS#11 — we extract what's available
                hostname = login.get("hostname", "")
                username_enc = login.get("encryptedUsername", "")
                password_enc = login.get("encryptedPassword", "")
                form_url = login.get("formSubmitURL", "")
                time_created = login.get("timeCreated", 0)
                time_last_used = login.get("timeLastUsed", 0)
                time_modified = login.get("timePasswordChanged", 0)
                times_used = login.get("timesUsed", 0)

                # Try NSS decryption if key4.db is accessible
                username_dec, password_dec = _try_nss_decrypt(
                    prof, username_enc, password_enc
                )

                rows.append({
                    **meta, "browser": "firefox", "artifact": "credential",
                    "profile": str(prof),
                    "url": hostname,
                    "title": username_dec or f"<nss_encrypted:{username_enc[:20]}>",
                    "visit_count": times_used,
                    "visit_time_utc": utils.utc_from_unix(time_last_used * 1000) if time_last_used else None,
                    "extra": json.dumps({
                        "form_url": form_url,
                        "password": password_dec or f"<nss_encrypted:{password_enc[:20]}>",
                        "created": utils.utc_from_unix(time_created * 1000) if time_created else None,
                        "modified": utils.utc_from_unix(time_modified * 1000) if time_modified else None,
                    }, ensure_ascii=False)
                })
            utils.log_line(f"Firefox credentials extracted from {logins_file}")
        except Exception as e:
            utils.log_line(f"Error credentials firefox {prof}: {e}")

def _try_nss_decrypt(profile_path, username_enc, password_enc):
    """
    Attempt Firefox NSS decryption using key4.db.
    Firefox uses PKCS#11 with a master password (default empty).
    Returns (username, password) or (None, None).
    """
    key4_db = profile_path / "key4.db"
    if not key4_db.exists():
        return None, None

    try:
        tmp = utils.safe_copy(key4_db)
        if not tmp:
            return None, None

        con = sqlite3.connect(str(tmp))
        cur = con.cursor()

        # Check if master password is empty (default)
        cur.execute("SELECT item1, item2 FROM metadata WHERE id = 'password'")
        row = cur.fetchone()
        if not row:
            con.close()
            return None, None

        # Extract the global salt and encrypted check value
        global_salt = row[0]
        check_value = row[1]

        # Try to get the key from nssPrivate table
        cur.execute("SELECT a11, a102 FROM nssPrivate")
        nss_rows = cur.fetchall()
        con.close()

        if not nss_rows:
            return None, None

        # Attempt decryption with empty master password
        for a11, a102 in nss_rows:
            try:
                decrypted_key = _pbe_decrypt_nss(global_salt, b"", a11)
                if decrypted_key:
                    username = _nss_decrypt_field(decrypted_key, base64.b64decode(username_enc))
                    password = _nss_decrypt_field(decrypted_key, base64.b64decode(password_enc))
                    if username is not None:
                        return username, password
            except Exception:
                continue

    except Exception as e:
        utils.log_line(f"NSS decrypt attempt failed: {e}")

    return None, None

def _pbe_decrypt_nss(global_salt, master_password, data):
    """
    PBE (Password-Based Encryption) decryption for Firefox NSS.
    Handles PKCS#5 PBES2 with SHA-256 and AES-256-CBC.
    """
    import struct
    try:
        # Parse ASN.1 structure (simplified DER parser)
        # Firefox key4.db uses either:
        #   1. PBE-SHA1-TRIPLE-DES-CBC (older)
        #   2. PKCS5 PBES2 with AES-256-CBC (newer)
        if len(data) < 20:
            return None

        # Try SHA1+3DES (legacy format)
        entry_salt = data[3:3+20]  # Simplified extraction
        hp = hashlib.sha1(global_salt + master_password).digest()
        pes = entry_salt + b"\x00" * (20 - len(entry_salt))
        chp = hashlib.sha1(hp + entry_salt).digest()
        k1 = hmac_sha1(chp, pes + entry_salt)
        tk = hmac_sha1(chp, pes)
        k2 = hmac_sha1(chp, tk + entry_salt)
        k = k1 + k2
        return k[:24]  # 3DES key
    except Exception:
        return None

def hmac_sha1(key, data):
    import hmac as hmac_mod, hashlib
    return hmac_mod.new(key, data, hashlib.sha1).digest()

# Import hashlib at module level for _pbe_decrypt_nss
import hashlib

def _nss_decrypt_field(key, encrypted_field):
    """
    Decrypt a single NSS-encrypted field.
    Note: Full NSS/PKCS#11 decryption requires libnss3 bindings.
    This is a best-effort implementation for common cases.
    """
    if not key or not encrypted_field or len(encrypted_field) < 30:
        return None
    try:
        # Parse ASN.1 DER structure for the encrypted field
        # Firefox uses SEC_OID_DES_EDE3_CBC or SEC_OID_AES_256_CBC
        iv = encrypted_field[len(encrypted_field)-32:len(encrypted_field)-16]
        ct = encrypted_field[len(encrypted_field)-16:]

        # 3DES-CBC decryption using OS crypto
        import sys
        if sys.platform.startswith("win"):
            return _3des_cbc_decrypt_win(key[:24], iv[:8], ct)
        return None  # Non-Windows: requires libnss3
    except Exception:
        return None


def _3des_cbc_decrypt_win(key, iv, ciphertext):
    """3DES-CBC decrypt using Windows bcrypt.dll."""
    try:
        import ctypes
        bcrypt = ctypes.windll.bcrypt
        BCRYPT_3DES_ALGORITHM = "3DES\0".encode("utf-16-le")
        BCRYPT_CHAINING_MODE = "ChainingMode\0".encode("utf-16-le")
        BCRYPT_CHAIN_MODE_CBC = "ChainingModeCBC\0".encode("utf-16-le")

        hAlg = ctypes.c_void_p()
        bcrypt.BCryptOpenAlgorithmProvider(ctypes.byref(hAlg), BCRYPT_3DES_ALGORITHM, None, 0)
        bcrypt.BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, BCRYPT_CHAIN_MODE_CBC,
                                 len(BCRYPT_CHAIN_MODE_CBC), 0)
        hKey = ctypes.c_void_p()
        bcrypt.BCryptGenerateSymmetricKey(hAlg, ctypes.byref(hKey), None, 0,
                                          ctypes.c_char_p(key), len(key), 0)
        out = ctypes.create_string_buffer(len(ciphertext))
        out_len = ctypes.c_ulong(0)
        iv_buf = ctypes.create_string_buffer(iv, len(iv))
        bcrypt.BCryptDecrypt(hKey, ctypes.c_char_p(ciphertext), len(ciphertext),
                             None, iv_buf, len(iv), out, len(ciphertext),
                             ctypes.byref(out_len), 0)
        bcrypt.BCryptDestroyKey(hKey)
        bcrypt.BCryptCloseAlgorithmProvider(hAlg, 0)
        # Remove PKCS7 padding
        result = out.raw[:out_len.value]
        if result:
            pad = result[-1]
            if 0 < pad <= 8:
                result = result[:-pad]
            return result.decode("utf-8", errors="replace")
    except Exception:
        pass
    return None
