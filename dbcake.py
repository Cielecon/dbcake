from typing import Any, Dict, Optional, List, Tuple, Literal
import os
import json
import threading
import pickle
import base64
import struct
import shutil
import hashlib
import hmac
import secrets
import builtins
import argparse
import sys
import subprocess
import getpass
import time

# Optional cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    _HAS_CRYPTO: bool = True
except Exception:
    AESGCM = None
    PBKDF2HMAC = None
    hashes = None
    default_backend = None
    _HAS_CRYPTO = False

# defaults and constants
_MODULE_DIR = os.path.dirname(__file__) or "."
_DEFAULT_DATA_PATH = os.path.join(_MODULE_DIR, "data.dbce")
_LEN_STRUCT = struct.Struct("<I")
_DB_HEADER = b"DBCEv1\n"
StoreFormat = Literal["binary", "bits01", "dec", "hex"]

# ---------------------------
# cross-platform file lock
# ---------------------------
class FileLock:
    """
    Cross-process file lock using a simple lock file.
    POSIX uses fcntl.flock for advisory locking.
    Windows uses msvcrt.locking.
    """

    def __init__(self, path: str, timeout: float = 10.0) -> None:
        self.lockfile = path + ".lock"
        self._f = None
        self.timeout = timeout

    def __enter__(self):
        start = time.time()
        # open lock file for reading/writing
        # use binary mode so msvcrt works
        while True:
            try:
                self._f = builtins.open(self.lockfile, "a+b")
                # attempt lock
                if os.name == "nt":
                    import msvcrt  # type: ignore
                    # blocking lock; msvcrt.locking doesn't block on some windows versions
                    try:
                        msvcrt.locking(self._f.fileno(), msvcrt.LK_LOCK, 1)
                        break
                    except OSError:
                        pass
                else:
                    import fcntl  # type: ignore
                    try:
                        fcntl.flock(self._f.fileno(), fcntl.LOCK_EX)
                        break
                    except OSError:
                        pass
            except Exception:
                # race to create lock file - try again
                pass
            # timeout check
            if (time.time() - start) > self.timeout:
                raise TimeoutError(f"Timeout acquiring lock {self.lockfile}")
            time.sleep(0.05)
        # keep file handle open while locked
        return self

    def __exit__(self, exc_type, exc, tb):
        try:
            if self._f:
                if os.name == "nt":
                    import msvcrt  # type: ignore
                    try:
                        self._f.seek(0)
                        msvcrt.locking(self._f.fileno(), msvcrt.LK_UNLCK, 1)
                    except Exception:
                        pass
                else:
                    import fcntl  # type: ignore
                    try:
                        fcntl.flock(self._f.fileno(), fcntl.LOCK_UN)
                    except Exception:
                        pass
                try:
                    self._f.close()
                except Exception:
                    pass
                # we keep lockfile around; removing can cause races on some platforms
                self._f = None
        except Exception:
            pass

# ---------------------------
# small helpers: serializers
# ---------------------------
def _json_safe(value: Any) -> Dict[str, Any]:
    """Wrap a Python value into JSON-safe wrapper or a pickled base64 wrapper."""
    try:
        json.dumps(value)
        return {"__fmt": "json", "v": value}
    except Exception:
        pickled = pickle.dumps(value, protocol=pickle.HIGHEST_PROTOCOL)
        return {"__fmt": "pickle", "v": base64.b64encode(pickled).decode("ascii")}

def _json_restore(obj: Any) -> Any:
    if isinstance(obj, dict) and obj.get("__fmt") == "pickle":
        b64 = obj.get("v", "")
        try:
            raw = base64.b64decode(b64.encode("ascii"))
            return pickle.loads(raw)
        except Exception:
            return None
    if isinstance(obj, dict) and obj.get("__fmt") == "json" and "v" in obj:
        return obj["v"]
    return obj

# ---------------------------
# format conversions
# ---------------------------
def _bytes_to_bits01(b: bytes) -> bytes:
    return "".join(f"{byte:08b}" for byte in b).encode("ascii")

def _bits01_to_bytes(s: bytes) -> bytes:
    text = s.decode("ascii")
    if len(text) % 8 != 0:
        raise ValueError("bits01 string length not a multiple of 8")
    out = bytearray()
    for i in range(0, len(text), 8):
        out.append(int(text[i : i + 8], 2))
    return bytes(out)

def _bytes_to_dec(b: bytes) -> bytes:
    # each byte -> 3 decimal digits
    return "".join(f"{byte:03d}" for byte in b).encode("ascii")

def _dec_to_bytes(s: bytes) -> bytes:
    text = s.decode("ascii")
    if len(text) % 3 != 0:
        raise ValueError("dec encoding length must be multiple of 3")
    out = bytearray()
    for i in range(0, len(text), 3):
        out.append(int(text[i : i + 3]))
    return bytes(out)

def _bytes_to_hex(b: bytes) -> bytes:
    return b.hex().encode("ascii")

def _hex_to_bytes(s: bytes) -> bytes:
    return bytes.fromhex(s.decode("ascii"))

# ---------------------------
# format helper map
# ---------------------------
_ENCODE_DISK = {
    "binary": lambda b: b,
    "bits01": _bytes_to_bits01,
    "dec": _bytes_to_dec,
    "hex": _bytes_to_hex,
}
_DECODE_DISK = {
    "binary": lambda b: b,
    "bits01": _bits01_to_bytes,
    "dec": _dec_to_bytes,
    "hex": _hex_to_bytes,
}

# ---------------------------
# helpers for cross-platform reveal
# ---------------------------
def reveal_in_file_manager(path: str) -> None:
    if not os.path.exists(path):
        raise FileNotFoundError(path)
    target = path if os.path.isdir(path) else os.path.dirname(path) or path
    if sys.platform.startswith("win"):
        os.startfile(target)  # type: ignore
        return
    if sys.platform == "darwin":
        subprocess.call(["open", target])
        return
    try:
        subprocess.call(["xdg-open", target])
    except Exception:
        print("Open folder:", target)

# ---------------------------
# low-level binary append-only store with .dbce header + format handling
# ---------------------------
class BinaryKV:
    def __init__(self, path: str = _DEFAULT_DATA_PATH, store_format: StoreFormat = "binary") -> None:
        self.path: str = path
        self._lock = threading.RLock()
        self._index: Dict[str, Optional[object]] = {}
        self.store_format: StoreFormat = store_format
        # ensure dir
        dirn = os.path.dirname(self.path)
        if dirn:
            os.makedirs(dirn, exist_ok=True)
        # create file with header
        if not os.path.exists(self.path):
            with builtins.open(self.path, "wb") as f:
                f.write(_DB_HEADER)
                try:
                    f.flush()
                    os.fsync(f.fileno())
                except Exception:
                    pass
        # open file handle for reading/writing
        self._open_file = builtins.open(self.path, "r+b")
        # build index (no key material yet)
        self._load_index(key_material=None)
        self._open_file.seek(0, os.SEEK_END)

    def _file_start_offset(self, f) -> int:
        f.seek(0)
        hdr = f.read(len(_DB_HEADER))
        if hdr == _DB_HEADER:
            return len(_DB_HEADER)
        return 0

    def _maybe_decode_format(self, payload: bytes) -> bytes:
        """Convert disk payload to raw bytes depending on format."""
        try:
            return _DECODE_DISK[self.store_format](payload)
        except Exception:
            return payload

    def _encode_for_disk(self, data: bytes) -> bytes:
        """Convert raw bytes into disk payload per format."""
        try:
            return _ENCODE_DISK[self.store_format](data)
        except Exception:
            return data

    def _load_index(self, key_material: Optional[bytes] = None) -> None:
        idx: Dict[str, Optional[object]] = {}
        try:
            with FileLock(self.path):
                with builtins.open(self.path, "rb") as f:
                    start = self._file_start_offset(f)
                    f.seek(start, os.SEEK_SET)
                    while True:
                        lenb = f.read(_LEN_STRUCT.size)
                        if not lenb or len(lenb) < _LEN_STRUCT.size:
                            break
                        (ln,) = _LEN_STRUCT.unpack(lenb)
                        payload_raw = f.read(ln)
                        if len(payload_raw) < ln:
                            break
                        payload = self._maybe_decode_format(payload_raw)
                        try:
                            if payload[:1] == b"E":
                                if key_material is not None and _HAS_CRYPTO:
                                    try:
                                        plain = _decrypt_record_bytes(payload, key_material)
                                        obj = _parse_plaintext_record(plain)
                                        k = obj.get("key")
                                        if k is not None:
                                            if obj.get("deleted", False):
                                                idx[k] = None
                                            else:
                                                idx[k] = obj.get("value")
                                    except Exception:
                                        pass
                                else:
                                    pass
                            else:
                                obj = json.loads(payload.decode("utf-8"))
                                key = obj.get("key")
                                if obj.get("deleted", False):
                                    idx[key] = None
                                else:
                                    idx[key] = _json_restore(obj.get("value"))
                        except Exception:
                            continue
        except FileNotFoundError:
            pass
        self._index = idx

    def _append_payload(self, raw_payload: bytes) -> None:
        payload_to_write = self._encode_for_disk(raw_payload)
        ln = len(payload_to_write)
        data = _LEN_STRUCT.pack(ln) + payload_to_write
        with FileLock(self.path):
            with self._lock:
                f = self._open_file
                f.seek(0, os.SEEK_END)
                f.write(data)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass

    def _append_plain_record(self, key: str, wrapped_value: Dict[str, Any]) -> None:
        rec = {"key": key, "deleted": False, "value": wrapped_value}
        payload = json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._append_payload(payload)
        with self._lock:
            self._index[key] = _json_restore(wrapped_value)

    def _append_delete_record(self, key: str) -> None:
        rec = {"key": key, "deleted": True}
        payload = json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self._append_payload(payload)
        with self._lock:
            self._index[key] = None

    def _append_encrypted_payload(self, encrypted_bytes: bytes) -> None:
        self._append_payload(encrypted_bytes)
        # index will be updated by caller with plaintext version

    # high-level ops used by wrapper
    def set_wrapped_plain(self, key: str, wrapped_value: Dict[str, Any]) -> None:
        self._append_plain_record(key, wrapped_value)

    def set_wrapped_encrypted(self, key: str, wrapped_value_bytes: bytes, encrypted_payload: bytes) -> None:
        # encrypted_payload raw bytes (starts with b'E')
        self._append_encrypted_payload(encrypted_payload)
        with self._lock:
            obj = _parse_plaintext_record(wrapped_value_bytes)
            if obj["key"] is not None:
                self._index[obj["key"]] = obj["value"]

    def delete_key(self, key: str) -> None:
        self._append_delete_record(key)

    def get_indexed(self, key: str, default: Any = None) -> Any:
        with self._lock:
            return self._index.get(key, default)

    def contains(self, key: str) -> bool:
        with self._lock:
            return key in self._index and self._index.get(key) is not None

    def keys(self) -> List[str]:
        with self._lock:
            return [k for k, v in self._index.items() if v is not None]

    def preview(self, limit: int = 20) -> List[Tuple[str, Any]]:
        with self._lock:
            out: List[Tuple[str, Any]] = []
            for k, v in list(self._index.items()):
                if v is None:
                    continue
                out.append((k, v))
                if len(out) >= limit:
                    break
            return out

    def export(self, dest_path: str) -> str:
        with FileLock(self.path):
            with self._lock:
                self._open_file.flush()
                try:
                    os.fsync(self._open_file.fileno())
                except Exception:
                    pass
                shutil.copy2(self.path, dest_path)
        return dest_path

    def compact(self, key_material: Optional[bytes] = None) -> None:
        with FileLock(self.path):
            with self._lock:
                tmp = self.path + ".compact.tmp"
                with builtins.open(tmp, "wb") as tf:
                    tf.write(_DB_HEADER)
                    for k, v in self._index.items():
                        if v is None:
                            continue
                        wrapped = _json_safe(v)
                        plain_payload = json.dumps({"key": k, "deleted": False, "value": wrapped}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                        if key_material is not None and _HAS_CRYPTO:
                            enc_payload = _encrypt_record_bytes(plain_payload, key_material)
                            tf.write(_LEN_STRUCT.pack(len(enc_payload)))
                            tf.write(self._encode_for_disk(enc_payload))
                        else:
                            tf.write(_LEN_STRUCT.pack(len(plain_payload)))
                            tf.write(self._encode_for_disk(plain_payload))
                    tf.flush()
                    try:
                        os.fsync(tf.fileno())
                    except Exception:
                        pass
                # rotate files
                self._open_file.close()
                backup = self.path + ".bak"
                try:
                    os.replace(self.path, backup)
                except Exception:
                    try:
                        os.remove(self.path)
                    except Exception:
                        pass
                os.replace(tmp, self.path)
                self._open_file = builtins.open(self.path, "r+b")
                self._open_file.seek(0, os.SEEK_END)
                # reload index with key_material if available
                self._load_index(key_material=key_material)
                try:
                    os.remove(backup)
                except Exception:
                    pass

    def close(self) -> None:
        with self._lock:
            try:
                if self._open_file:
                    self._open_file.flush()
                    try:
                        os.fsync(self._open_file.fileno())
                    except Exception:
                        pass
                    self._open_file.close()
            except Exception:
                pass
            self._open_file = None

    def pretty_print_preview(self, limit: int = 10) -> None:
        rows = self.preview(limit)
        if not rows:
            print("<empty>")
            return
        maxk = max(len(k) for k, _ in rows)
        print("-" * (maxk + 2 + 40))
        print(f"{'key'.ljust(maxk)} | value (repr up to 40 chars)")
        print("-" * (maxk + 2 + 40))
        for k, v in rows:
            s = repr(v)
            if len(s) > 40:
                s = s[:37] + "..."
            print(f"{k.ljust(maxk)} | {s}")
        print("-" * (maxk + 2 + 40))

# ---------------------------
# encryption helpers
# ---------------------------
def _derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 390000) -> bytes:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography required for PBKDF2 (preferred)")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
    key = kdf.derive(passphrase.encode("utf-8"))
    return key

def _encrypt_record_bytes(plain_payload: bytes, key_material: bytes) -> bytes:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography required for AES-GCM")
    aesgcm = AESGCM(key_material)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plain_payload, None)
    return b"E" + nonce + ciphertext

def _decrypt_record_bytes(payload: bytes, key_material: bytes) -> bytes:
    if not _HAS_CRYPTO:
        raise RuntimeError("cryptography required for AES-GCM")
    if not payload.startswith(b"E"):
        raise ValueError("payload not encrypted")
    data = payload[1:]
    if len(data) < 12 + 16:
        raise ValueError("payload too short")
    nonce = data[:12]
    ciphertext = data[12:]
    aesgcm = AESGCM(key_material)
    plain = aesgcm.decrypt(nonce, ciphertext, None)
    return plain

def _parse_plaintext_record(plain_bytes: bytes) -> Dict[str, Any]:
    try:
        obj = json.loads(plain_bytes.decode("utf-8"))
        key = obj.get("key")
        deleted = obj.get("deleted", False)
        value = _json_restore(obj.get("value")) if not deleted else None
        return {"key": key, "value": value, "deleted": deleted}
    except Exception:
        return {"key": None, "value": None, "deleted": False}

# ---------------------------
# fallback stdlib authenticated stream cipher (educational)
# ---------------------------
def _hmac_sha256(key: bytes, data: bytes) -> bytes:
    return hmac.new(key, data, hashlib.sha256).digest()

def _stdlib_encrypt(key_material: bytes, plaintext: bytes) -> bytes:
    enc_key = key_material[:16]; mac_key = key_material[16:32]
    nonce = secrets.token_bytes(16)
    out = bytearray()
    counter = 0
    i = 0
    while i < len(plaintext):
        ctrb = counter.to_bytes(8, "big")
        block = _hmac_sha256(enc_key, nonce + ctrb)
        take = min(len(block), len(plaintext) - i)
        for j in range(take):
            out.append(plaintext[i + j] ^ block[j])
        i += take
        counter += 1
    ciphertext = bytes(out)
    tag = _hmac_sha256(mac_key, nonce + ciphertext)
    return b"E" + nonce + ciphertext + tag

def _stdlib_decrypt(key_material: bytes, payload: bytes) -> bytes:
    if not payload.startswith(b"E"):
        raise ValueError("not stdlib encrypted payload")
    data = payload[1:]
    if len(data) < 16 + 32:
        raise ValueError("payload too short")
    nonce = data[:16]; tag = data[-32:]; ciphertext = data[16:-32]
    enc_key = key_material[:16]; mac_key = key_material[16:32]
    expected = _hmac_sha256(mac_key, nonce + ciphertext)
    if not hmac.compare_digest(expected, tag):
        raise ValueError("bad tag")
    out = bytearray()
    counter = 0
    i = 0
    while i < len(ciphertext):
        ctrb = counter.to_bytes(8, "big")
        block = _hmac_sha256(enc_key, nonce + ctrb)
        take = min(len(block), len(ciphertext) - i)
        for j in range(take):
            out.append(ciphertext[i + j] ^ block[j])
        i += take
        counter += 1
    return bytes(out)

# ---------------------------
# DB wrapper (with rotation API)
# ---------------------------
class DB:
    def __init__(self, backend: BinaryKV) -> None:
        self._backend = backend
        self._level: str = "normal"
        self._passphrase: Optional[str] = None
        self._keyfile: str = backend.path + ".key"
        self._saltfile: str = backend.path + ".salt"
        self._key_material: Optional[bytes] = None

    def title(self, filename: str, store_format: Optional[StoreFormat] = None) -> None:
        """Switch to another .dbce file. If store_format provided, create with that format."""
        if not filename.endswith(".dbce"):
            filename = filename + ".dbce"
        new_path = filename if os.path.isabs(filename) else os.path.join(os.getcwd(), filename)
        try:
            self._backend.close()
        except Exception:
            pass
        fmt = store_format or self._backend.store_format
        new_backend = BinaryKV(new_path, store_format=fmt)
        self._backend = new_backend
        self._keyfile = new_backend.path + ".key"
        self._saltfile = new_backend.path + ".salt"
        if self._level == "high":
            self._derive_key_material()
            self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)
        else:
            self._backend._load_index(key_material=None)

    def set_format(self, fmt: StoreFormat) -> None:
        """Change store format for the current DB file (reopens backend and reloads index)."""
        if fmt not in ("binary", "bits01", "dec", "hex"):
            raise ValueError("format must be one of: binary, bits01, dec, hex")
        current_path = self._backend.path
        try:
            self._backend.close()
        except Exception:
            pass
        self._backend = BinaryKV(current_path, store_format=fmt)
        self._keyfile = self._backend.path + ".key"
        self._saltfile = self._backend.path + ".salt"
        if self._level == "high":
            self._derive_key_material()
            self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)
        else:
            self._backend._load_index(key_material=None)

    def set_passphrase(self, passphrase: str) -> None:
        """Set in-memory passphrase (does not write it to disk)."""
        self._passphrase = passphrase
        if self._level == "high":
            self._derive_key_material()
            self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)

    def clear_passphrase(self) -> None:
        self._passphrase = None
        self._key_material = None

    def _derive_key_material(self) -> bytes:
        if self._passphrase:
            if os.path.exists(self._saltfile):
                salt = builtins.open(self._saltfile, "rb").read()
            else:
                salt = secrets.token_bytes(16)
                tmp = self._saltfile + ".tmp"
                with builtins.open(tmp, "wb") as f:
                    f.write(salt)
                os.replace(tmp, self._saltfile)
                try:
                    os.chmod(self._saltfile, 0o600)
                except Exception:
                    pass
            if _HAS_CRYPTO:
                km = _derive_key_from_passphrase(self._passphrase, salt)
            else:
                km = hashlib.pbkdf2_hmac("sha256", self._passphrase.encode("utf-8"), salt, 200_000, dklen=32)
            self._key_material = km
            return km
        # else use/create keyfile
        if os.path.exists(self._keyfile):
            km = builtins.open(self._keyfile, "rb").read()
        else:
            km = secrets.token_bytes(32)
            tmp = self._keyfile + ".tmp"
            with builtins.open(tmp, "wb") as f:
                f.write(km)
            os.replace(tmp, self._keyfile)
            try:
                os.chmod(self._keyfile, 0o600)
            except Exception:
                pass
        self._key_material = km
        return km

    @property
    def pw(self) -> str:
        return self._level

    @pw.setter
    def pw(self, v: str) -> None:
        v = (v or "normal").lower()
        if v not in ("low", "normal", "high"):
            raise ValueError("pw must be low|normal|high")
        if v == self._level:
            return
        self._level = v
        if v == "high":
            self._derive_key_material()
            self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)
        else:
            self._key_material = None
            self._backend._load_index(key_material=None)

    def set(self, key: str, value: Any) -> None:
        if not isinstance(key, str):
            raise TypeError("key must be a string")
        wrapped = _json_safe(value)
        plain_record = json.dumps({"key": key, "deleted": False, "value": wrapped}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if self._level == "high":
            km = self._key_material or self._derive_key_material()
            if _HAS_CRYPTO:
                enc_payload = _encrypt_record_bytes(plain_record, km)
            else:
                enc_payload = _stdlib_encrypt(km, plain_record)
            self._backend.set_wrapped_encrypted(key, plain_record, enc_payload)
        else:
            self._backend.set_wrapped_plain(key, wrapped)

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        val = self._backend.get_indexed(key, None)
        if val is not None:
            return val
        return default

    def delete(self, key: str) -> bool:
        existed = self._backend.contains(key)
        self._backend.delete_key(key)
        return existed

    def __contains__(self, key: str) -> bool:
        return self._backend.contains(key)

    def keys(self) -> List[str]:
        return self._backend.keys()

    def preview(self, limit: int = 20) -> List[Tuple[str, Any]]:
        return self._backend.preview(limit)

    def export(self, dest: str) -> str:
        return self._backend.export(dest)

    def compact(self) -> None:
        km = self._key_material if self._level == "high" else None
        self._backend.compact(key_material=km)

    def close(self) -> None:
        self._backend.close()

    # ---------- key rotation ----------
    def rotate_key(self, new_passphrase: Optional[str] = None, interactive: bool = False) -> None:
        """
        Re-encrypt the whole DB using a new passphrase (or new keyfile).
        - Must be in "high" mode (pw == 'high') and we must have key material to decrypt existing entries.
        - If interactive=True and new_passphrase is None, prompts for the new passphrase (no echo).
        - If new_passphrase is empty string, a new random keyfile is created instead (random keyfile).
        """
        if self._level != "high":
            raise RuntimeError("rotate_key requires db.pw == 'high' (enable 'high' mode first)")

        # ensure we have the old key material (decrypt ability)
        if self._key_material is None:
            # we may need to prompt for current passphrase
            if interactive:
                old_pass = getpass.getpass("Enter current passphrase to decrypt existing DB: ")
                self.set_passphrase(old_pass)
            else:
                raise RuntimeError("No key material available to decrypt DB. Set passphrase or use interactive=True.")

        old_km = self._key_material
        if old_km is None:
            raise RuntimeError("failed to derive current key material")

        # get new key material
        if interactive and new_passphrase is None:
            new_passphrase = getpass.getpass("Enter NEW passphrase (leave empty to use random keyfile): ")
            confirm = getpass.getpass("Confirm NEW passphrase: ")
            if new_passphrase != confirm:
                raise RuntimeError("new passphrase mismatch")
        # prepare new key material
        if new_passphrase is None:
            # create new random keyfile for new backend
            new_km = secrets.token_bytes(32)
            # write to default keyfile for this DB (overwrite)
            tmp = self._keyfile + ".tmp.new"
            with builtins.open(tmp, "wb") as f:
                f.write(new_km)
            os.replace(tmp, self._keyfile)
            try:
                os.chmod(self._keyfile, 0o600)
            except Exception:
                pass
        elif new_passphrase == "":
            # empty string indicates create a random keyfile instead of a passphrase-derived key
            new_km = secrets.token_bytes(32)
            tmp = self._keyfile + ".tmp.new"
            with builtins.open(tmp, "wb") as f:
                f.write(new_km)
            os.replace(tmp, self._keyfile)
            try:
                os.chmod(self._keyfile, 0o600)
            except Exception:
                pass
        else:
            # derive new_km from new_passphrase and new salt
            new_salt = secrets.token_bytes(16)
            tmp_salt = self._saltfile + ".tmp.new"
            with builtins.open(tmp_salt, "wb") as f:
                f.write(new_salt)
            os.replace(tmp_salt, self._saltfile)
            try:
                os.chmod(self._saltfile, 0o600)
            except Exception:
                pass
            if _HAS_CRYPTO:
                new_km = _derive_key_from_passphrase(new_passphrase, new_salt)
            else:
                new_km = hashlib.pbkdf2_hmac("sha256", new_passphrase.encode("utf-8"), new_salt, 200_000, dklen=32)

        # Now we must read all live entries (decrypt with old_km) and write them re-encrypted with new_km.
        # Acquire file lock to avoid concurrent writers.
        path = self._backend.path
        with FileLock(path, timeout=30.0):
            # build list of (key, value) by scanning file and decrypting each encrypted record
            entries: Dict[str, Any] = {}
            # Use backend._index as best-effort source; if some encrypted records were skipped earlier,
            # we attempt to scan file and decrypt with old_km
            # First, copy existing in-memory index for plaintext/decrypted entries:
            entries.update({k: v for k, v in self._backend._index.items() if v is not None})

            # Now scan file to find any encrypted records we may have missed and decrypt with old_km
            with builtins.open(path, "rb") as f:
                start = 0
                hdr = f.read(len(_DB_HEADER))
                if hdr == _DB_HEADER:
                    start = len(_DB_HEADER)
                f.seek(start, os.SEEK_SET)
                while True:
                    lenb = f.read(_LEN_STRUCT.size)
                    if not lenb or len(lenb) < _LEN_STRUCT.size:
                        break
                    (ln,) = _LEN_STRUCT.unpack(lenb)
                    payload_raw = f.read(ln)
                    if len(payload_raw) < ln:
                        break
                    try:
                        # decode disk format to raw bytes (if format uses ascii encodings)
                        payload = self._backend._maybe_decode_format(payload_raw) if hasattr(self._backend, "_maybe_decode_format") else payload_raw
                        if payload[:1] == b"E":
                            # try decrypt via cryptography or stdlib fallback
                            try:
                                if _HAS_CRYPTO:
                                    plain = _decrypt_record_bytes(payload, old_km)
                                else:
                                    plain = _stdlib_decrypt(old_km, payload)
                                obj = _parse_plaintext_record(plain)
                                if obj["key"] is not None:
                                    if obj["deleted"]:
                                        if obj["key"] in entries:
                                            del entries[obj["key"]]
                                    else:
                                        entries[obj["key"]] = obj["value"]
                            except Exception:
                                # can't decrypt (bad key) -> raise; rotation cannot proceed
                                raise RuntimeError("Failed to decrypt existing record during rotation. Wrong passphrase/key?")
                        else:
                            obj = json.loads(payload.decode("utf-8"))
                            if obj.get("deleted", False):
                                if obj["key"] in entries:
                                    del entries[obj["key"]]
                            else:
                                entries[obj["key"]] = _json_restore(obj.get("value"))
                    except Exception:
                        continue

            # Now write a new compacted file encrypted with new_km
            tmp = path + ".rotate.tmp"
            with builtins.open(tmp, "wb") as tf:
                tf.write(_DB_HEADER)
                for k, v in entries.items():
                    wrapped = _json_safe(v)
                    plain_payload = json.dumps({"key": k, "deleted": False, "value": wrapped}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    # encrypt with new_km using AES-GCM if available, else stdlib
                    if _HAS_CRYPTO:
                        enc_payload = _encrypt_record_bytes(plain_payload, new_km)
                    else:
                        enc_payload = _stdlib_encrypt(new_km, plain_payload)
                    # encode for disk format
                    disk_payload = self._backend._encode_for_disk(enc_payload)
                    tf.write(_LEN_STRUCT.pack(len(disk_payload)))
                    tf.write(disk_payload)
                tf.flush()
                try:
                    os.fsync(tf.fileno())
                except Exception:
                    pass
            # rotate files
            backup = path + ".bak.rotate"
            try:
                os.replace(path, backup)
            except Exception:
                try:
                    os.remove(path)
                except Exception:
                    pass
            os.replace(tmp, path)
            # replace keyfile/saltfile already saved earlier
            # reload backend file handles and index using new_km
            try:
                self._backend._open_file.close()
            except Exception:
                pass
            self._backend._open_file = builtins.open(self._backend.path, "r+b")
            self._backend._open_file.seek(0, os.SEEK_END)
            # set self._key_material to new_km
            self._key_material = new_km
            # reload index using new_km
            if _HAS_CRYPTO:
                self._backend._load_index(key_material=new_km)
            else:
                # stdlib fallback: cannot call AESGCM decrypt but our decrypt implementation is available
                self._backend._load_index(key_material=new_km)
            try:
                os.remove(backup)
            except Exception:
                pass

    # attribute-style sugar & rest of API
    def __setattr__(self, name, value):
        if name.startswith("_"):
            return object.__setattr__(self, name, value)
        self.set(name, value)

    def __getattr__(self, name):
        if name.startswith("_"):
            raise AttributeError(name)
        val = self.get(name, default=None)
        if val is None:
            raise AttributeError(name)
        return val

# ---------------------------
# factory & module-level instance
# ---------------------------
def open_db(path: str = _DEFAULT_DATA_PATH, store_format: StoreFormat = "binary") -> DB:
    b = BinaryKV(path, store_format=store_format)
    return DB(b)

_binary = BinaryKV(_DEFAULT_DATA_PATH, store_format="binary")
db = DB(_binary)

# ---------------------------
# CLI helpers
# ---------------------------
def _get_db_for_cli(path: Optional[str], format_hint: Optional[str]) -> DB:
    if not path:
        return db
    path = path if path.endswith(".dbce") else path + ".dbce"
    backend = BinaryKV(path, store_format=format_hint or "binary")
    return DB(backend)

def cli_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="dbcake", description="dbcake CLI")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def add_path_arg(p):
        p.add_argument("dbpath", nargs="?", help="path to .dbce file (optional)")

    p = sub.add_parser("create", help="create .dbce file")
    add_path_arg(p)
    p.add_argument("--format", choices=["binary", "bits01", "dec", "hex"], default="binary")

    p = sub.add_parser("set", help="set key")
    add_path_arg(p)
    p.add_argument("key")
    p.add_argument("value")

    p = sub.add_parser("get", help="get key")
    add_path_arg(p)
    p.add_argument("key")

    p = sub.add_parser("delete", help="delete key")
    add_path_arg(p)
    p.add_argument("key")

    p = sub.add_parser("preview", help="preview keys")
    add_path_arg(p)
    p.add_argument("--limit", type=int, default=10)

    p = sub.add_parser("compact", help="compact DB")
    add_path_arg(p)

    p = sub.add_parser("export", help="export db file to path")
    add_path_arg(p)
    p.add_argument("dest")

    p = sub.add_parser("set-passphrase", help="set passphrase for DB (in memory)")
    add_path_arg(p)
    p.add_argument("--passphrase", nargs="?", default=None)
    p.add_argument("--interactive", action="store_true", help="prompt for passphrase without echo")

    p = sub.add_parser("set-format", help="set storage format for DB (reopens file)")
    add_path_arg(p)
    p.add_argument("format", choices=["binary", "bits01", "dec", "hex"])

    p = sub.add_parser("title", help="switch to DB file (create if missing)")
    add_path_arg(p)
    p.add_argument("--format", choices=["binary", "bits01", "dec", "hex"], default=None)

    p = sub.add_parser("keys", help="list keys")
    add_path_arg(p)

    p = sub.add_parser("reveal", help="reveal DB file in OS file manager")
    add_path_arg(p)

    # rotate-key CLI
    p = sub.add_parser("rotate-key", help="rotate encryption key for DB (re-encrypt all data)")
    add_path_arg(p)
    p.add_argument("--old-passphrase", nargs="?", default=None)
    p.add_argument("--new-passphrase", nargs="?", default=None)
    p.add_argument("--interactive", action="store_true", help="prompt for old and new passphrases (no echo)")

    args = parser.parse_args(argv)
    path = args.dbpath if hasattr(args, "dbpath") and args.dbpath else None

    try:
        if args.cmd == "create":
            fmt = args.format
            target = path or _DEFAULT_DATA_PATH
            target = target if target.endswith(".dbce") else target + ".dbce"
            open_db(target, store_format=fmt).compact()
            print("created", target)
            return 0

        if args.cmd == "set":
            dbobj = _get_db_for_cli(path, None)
            try:
                val = json.loads(args.value)
            except Exception:
                val = args.value
            dbobj.set(args.key, val)
            print("ok")
            return 0

        if args.cmd == "get":
            dbobj = _get_db_for_cli(path, None)
            v = dbobj.get(args.key, None)
            print(repr(v))
            return 0

        if args.cmd == "delete":
            dbobj = _get_db_for_cli(path, None)
            ok = dbobj.delete(args.key)
            print("deleted" if ok else "not found")
            return 0

        if args.cmd == "preview":
            dbobj = _get_db_for_cli(path, None)
            rows = dbobj.preview(limit=args.limit)
            if not rows:
                print("<empty>")
            else:
                for k, v in rows:
                    print(f"{k} : {v!r}")
            return 0

        if args.cmd == "compact":
            dbobj = _get_db_for_cli(path, None)
            dbobj.compact()
            print("compacted")
            return 0

        if args.cmd == "export":
            dbobj = _get_db_for_cli(path, None)
            dbobj.export(args.dest)
            print("exported to", args.dest)
            return 0

        if args.cmd == "set-passphrase":
            dbobj = _get_db_for_cli(path, None)
            if args.interactive or args.passphrase is None:
                pp = getpass.getpass("Passphrase (not stored): ")
            else:
                pp = args.passphrase
            dbobj.set_passphrase(pp)
            print("passphrase set in memory. To persist effect, run: set pw=high")
            return 0

        if args.cmd == "set-format":
            dbobj = _get_db_for_cli(path, args.format)
            dbobj.set_format(args.format)
            print("format set to", args.format)
            return 0

        if args.cmd == "title":
            dbobj = _get_db_for_cli(path, args.format)
            if path:
                dbobj.title(path, store_format=args.format)
                print("switched to", path)
            else:
                print("no path supplied")
            return 0

        if args.cmd == "keys":
            dbobj = _get_db_for_cli(path, None)
            for k in dbobj.keys():
                print(k)
            return 0

        if args.cmd == "reveal":
            target = path if path else _DEFAULT_DATA_PATH
            if not target.endswith(".dbce"):
                target = target + ".dbce"
            reveal_in_file_manager(target)
            return 0

        if args.cmd == "rotate-key":
            dbobj = _get_db_for_cli(path, None)
            if args.interactive:
                # prompt for old & new
                oldp = getpass.getpass("Current passphrase (leave empty if using keyfile): ")
                if oldp:
                    dbobj.set_passphrase(oldp)
                newp = getpass.getpass("NEW passphrase (leave empty to use random keyfile): ")
                confirm = getpass.getpass("Confirm NEW passphrase: ")
                if newp != confirm:
                    print("New passphrase mismatch", file=sys.stderr)
                    return 2
                dbobj.rotate_key(new_passphrase=newp, interactive=False)
                print("rotation complete")
                return 0
            else:
                # non-interactive: use provided passphrases
                if args.old_passphrase:
                    dbobj.set_passphrase(args.old_passphrase)
                dbobj.rotate_key(new_passphrase=args.new_passphrase, interactive=False)
                print("rotation complete")
                return 0

    except Exception as e:
        print("error:", e, file=sys.stderr)
        return 2

    return 0

# ---------------------------
# run CLI if module executed
# ---------------------------
if __name__ == "__main__":
    raise SystemExit(cli_main())
