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
import urllib.request
import urllib.error
import urllib.parse
import tkinter as tk
from tkinter import messagebox
import asyncio
import functools
import datetime
import types

# Optional cryptography imports
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    from cryptography.fernet import Fernet
    _HAS_CRYPTO: bool = True
    _HAS_FERNET: bool = True
except Exception:
    AESGCM = None
    PBKDF2HMAC = None
    hashes = None
    default_backend = None
    Fernet = None
    _HAS_CRYPTO = False
    _HAS_FERNET = False

# ---------------------------
# Defaults & constants
# ---------------------------
_MODULE_DIR = os.path.dirname(__file__) or "."
_DEFAULT_DATA_PATH = os.path.join(_MODULE_DIR, "data.dbce")
_LEN_STRUCT = struct.Struct("<I")
_DB_HEADER = b"DBCEv1\n"
StoreFormat = Literal["binary", "bits01", "dec", "hex"]

# ---------------------------
# File lock (cross-platform)
# ---------------------------
class FileLock:
    def __init__(self, path: str, timeout: float = 10.0) -> None:
        self.lockfile = path + ".lock"
        self._f = None
        self.timeout = timeout

    def __enter__(self):
        start = time.time()
        while True:
            try:
                self._f = builtins.open(self.lockfile, "a+b")
                if os.name == "nt":
                    import msvcrt  # type: ignore
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
                pass
            if (time.time() - start) > self.timeout:
                raise TimeoutError(f"Timeout acquiring lock {self.lockfile}")
            time.sleep(0.05)
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
                self._f = None
        except Exception:
            pass

# ---------------------------
# JSON/pickle wrappers
# ---------------------------
def _json_safe(value: Any) -> Dict[str, Any]:
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
# Format conversions
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
# Reveal helper
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
# BinaryKV (centralized)
# ---------------------------
class BinaryKV:
    def __init__(self, path: str = _DEFAULT_DATA_PATH, store_format: StoreFormat = "binary") -> None:
        self.path: str = path
        self._lock = threading.RLock()
        self._index: Dict[str, Optional[object]] = {}
        self.store_format: StoreFormat = store_format
        dirn = os.path.dirname(self.path)
        if dirn:
            os.makedirs(dirn, exist_ok=True)
        if not os.path.exists(self.path):
            with builtins.open(self.path, "wb") as f:
                f.write(_DB_HEADER)
                try:
                    f.flush(); os.fsync(f.fileno())
                except Exception:
                    pass
        self._open_file = builtins.open(self.path, "r+b")
        self._load_index(key_material=None)
        self._open_file.seek(0, os.SEEK_END)

    def _file_start_offset(self, f) -> int:
        f.seek(0)
        hdr = f.read(len(_DB_HEADER))
        if hdr == _DB_HEADER:
            return len(_DB_HEADER)
        return 0

    def _maybe_decode_format(self, payload: bytes) -> bytes:
        try:
            return _DECODE_DISK[self.store_format](payload)
        except Exception:
            return payload

    def _encode_for_disk(self, data: bytes) -> bytes:
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
                                if key_material is not None:
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

    # API used by DB
    def set_wrapped_plain(self, key: str, wrapped_value: Dict[str, Any]) -> None:
        self._append_plain_record(key, wrapped_value)

    def set_wrapped_encrypted(self, key: str, wrapped_value_bytes: bytes, encrypted_payload: bytes) -> None:
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
                        if key_material is not None:
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
# DecentralizedKV
# ---------------------------
class DecentralizedKV:
    def __init__(self, path: str, store_format: StoreFormat = "binary") -> None:
        self.base_path = path
        self.dir_path = path + ".d"
        self.store_format = store_format
        self._lock = threading.RLock()
        self._index: Dict[str, Optional[object]] = {}
        os.makedirs(self.dir_path, exist_ok=True)
        self._load_index()

    def _keyfile_name(self, key: str) -> str:
        h = hashlib.sha256(key.encode("utf-8")).hexdigest()
        return os.path.join(self.dir_path, f"{h}.rec")

    def _read_file_raw(self, fname: str) -> Optional[bytes]:
        try:
            with builtins.open(fname, "rb") as f:
                return f.read()
        except Exception:
            return None

    def _write_file_atomic(self, fname: str, data: bytes) -> None:
        tmp = fname + ".tmp"
        with builtins.open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, fname)

    def _maybe_decode_format(self, payload: bytes) -> bytes:
        try:
            return _DECODE_DISK[self.store_format](payload)
        except Exception:
            return payload

    def _encode_for_disk(self, data: bytes) -> bytes:
        try:
            return _ENCODE_DISK[self.store_format](data)
        except Exception:
            return data

    def _load_index(self) -> None:
        idx: Dict[str, Optional[object]] = {}
        try:
            with FileLock(self.base_path):
                for fname in os.listdir(self.dir_path):
                    if not fname.endswith(".rec"):
                        continue
                    fpath = os.path.join(self.dir_path, fname)
                    raw = self._read_file_raw(fpath)
                    if not raw:
                        continue
                    payload = self._maybe_decode_format(raw)
                    try:
                        if payload[:1] == b"E":
                            continue
                        else:
                            obj = json.loads(payload.decode("utf-8"))
                            key = obj.get("key")
                            if obj.get("deleted", False):
                                idx[key] = None
                            else:
                                idx[key] = _json_restore(obj.get("value"))
                    except Exception:
                        continue
        except Exception:
            pass
        self._index = idx

    @property
    def path(self) -> str:
        return self.base_path

    def set_wrapped_plain(self, key: str, wrapped_value: Dict[str, Any]) -> None:
        rec = {"key": key, "deleted": False, "value": wrapped_value}
        payload = json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        disk = self._encode_for_disk(payload)
        fname = self._keyfile_name(key)
        with FileLock(self.base_path):
            with self._lock:
                self._write_file_atomic(fname, disk)
                self._index[key] = _json_restore(wrapped_value)

    def set_wrapped_encrypted(self, key: str, wrapped_value_bytes: bytes, encrypted_payload: bytes) -> None:
        disk = self._encode_for_disk(encrypted_payload)
        fname = self._keyfile_name(key)
        with FileLock(self.base_path):
            with self._lock:
                self._write_file_atomic(fname, disk)
                obj = _parse_plaintext_record(wrapped_value_bytes)
                if obj["key"] is not None:
                    self._index[obj["key"]] = obj["value"]

    def delete_key(self, key: str) -> None:
        fname = self._keyfile_name(key)
        with FileLock(self.base_path):
            with self._lock:
                try:
                    os.remove(fname)
                except FileNotFoundError:
                    pass
                if key in self._index:
                    del self._index[key]

    def get_indexed(self, key: str, default: Any = None) -> Any:
        with self._lock:
            if key in self._index:
                val = self._index.get(key)
                if val is not None:
                    return val
        fname = self._keyfile_name(key)
        raw = self._read_file_raw(fname)
        if raw is None:
            return default
        payload = self._maybe_decode_format(raw)
        try:
            if payload[:1] == b"E":
                return {"__fmt": "enc-raw", "v": base64.b64encode(payload).decode("ascii")}
            else:
                obj = json.loads(payload.decode("utf-8"))
                if obj.get("deleted", False):
                    return default
                val = _json_restore(obj.get("value"))
                with self._lock:
                    self._index[key] = val
                return val
        except Exception:
            return default

    def contains(self, key: str) -> bool:
        with self._lock:
            if key in self._index and self._index.get(key) is not None:
                return True
        fname = self._keyfile_name(key)
        return os.path.exists(fname)

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
        with FileLock(self.base_path):
            if os.path.isdir(dest_path):
                target = os.path.join(dest_path, os.path.basename(self.dir_path))
                shutil.copytree(self.dir_path, target, dirs_exist_ok=True)
            else:
                base = dest_path
                if not base.endswith(".zip"):
                    base = base + ".zip"
                shutil.make_archive(base[:-4], 'zip', self.dir_path)
                target = base
        return target

    def compact(self, key_material: Optional[bytes] = None) -> None:
        with FileLock(self.base_path):
            with self._lock:
                self._load_index()
                if key_material is None:
                    return
                for k, v in list(self._index.items()):
                    if v is None:
                        continue
                    wrapped = _json_safe(v)
                    plain_payload = json.dumps({"key": k, "deleted": False, "value": wrapped}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
                    enc_payload = _encrypt_record_bytes(plain_payload, key_material)
                    fname = self._keyfile_name(k)
                    disk = self._encode_for_disk(enc_payload)
                    self._write_file_atomic(fname, disk)
                self._load_index()

    def close(self) -> None:
        pass

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
# Encryption helpers
# ---------------------------
def _derive_key_from_passphrase(passphrase: str, salt: bytes, iterations: int = 390000) -> bytes:
    if _HAS_CRYPTO:
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations, backend=default_backend())
        key = kdf.derive(passphrase.encode("utf-8"))
        return key
    else:
        return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, 200_000, dklen=32)

def _encrypt_record_bytes(plain_payload: bytes, key_material: bytes) -> bytes:
    if _HAS_CRYPTO:
        aesgcm = AESGCM(key_material)
        nonce = secrets.token_bytes(12)
        ciphertext = aesgcm.encrypt(nonce, plain_payload, None)
        return b"E" + nonce + ciphertext
    else:
        return _stdlib_encrypt(key_material, plain_payload)

def _decrypt_record_bytes(payload: bytes, key_material: bytes) -> bytes:
    if _HAS_CRYPTO:
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
    else:
        return _stdlib_decrypt(key_material, payload)

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
# stdlib fallback cipher
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
# DB wrapper with server sync + installer + rotate_key
# ---------------------------
class DB:
    def __init__(self, backend: Any) -> None:
        self._backend = backend
        self._level: str = "normal"
        self._passphrase: Optional[str] = None
        self._keyfile: str = getattr(backend, "path", _DEFAULT_DATA_PATH) + ".key"
        self._saltfile: str = getattr(backend, "path", _DEFAULT_DATA_PATH) + ".salt"
        self._key_material: Optional[bytes] = None

        # server sync config
        self._server_url: Optional[str] = None
        self._server_headers: Dict[str, str] = {}

    # ----- storage switching helpers -----
    def title(self, filename: str, store_format: Optional[StoreFormat] = None) -> None:
        if not filename.endswith(".dbce"):
            filename = filename + ".dbce"
        new_path = filename if os.path.isabs(filename) else os.path.join(os.getcwd(), filename)
        try:
            self._backend.close()
        except Exception:
            pass
        fmt = store_format or getattr(self._backend, "store_format", "binary")
        new_backend = BinaryKV(new_path, store_format=fmt)
        self._backend = new_backend
        self._keyfile = new_backend.path + ".key"
        self._saltfile = new_backend.path + ".salt"
        if self._level == "high":
            self._derive_key_material()
            try:
                self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)
            except Exception:
                pass
        else:
            try:
                self._backend._load_index(key_material=None)
            except Exception:
                pass

    def set_format(self, fmt: StoreFormat) -> None:
        if fmt not in ("binary", "bits01", "dec", "hex"):
            raise ValueError("format must be one of: binary, bits01, dec, hex")
        current_path = self._backend.path
        try:
            self._backend.close()
        except Exception:
            pass
        if isinstance(self._backend, DecentralizedKV):
            self._backend = DecentralizedKV(current_path, store_format=fmt)
        else:
            self._backend = BinaryKV(current_path, store_format=fmt)
        self._keyfile = self._backend.path + ".key"
        self._saltfile = self._backend.path + ".salt"
        if self._level == "high":
            self._derive_key_material()
            try:
                self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)
            except Exception:
                pass
        else:
            try:
                self._backend._load_index(key_material=None)
            except Exception:
                pass

    def centerilized(self) -> None:
        """Switch to centralized .dbce append-only store (explicit method)."""
        current_path = self._backend.path
        fmt = getattr(self._backend, "store_format", "binary")
        try:
            self._backend.close()
        except Exception:
            pass
        self._backend = BinaryKV(current_path, store_format=fmt)
        self._keyfile = self._backend.path + ".key"
        self._saltfile = self._backend.path + ".salt"
        if self._level == "high":
            self._derive_key_material()
            try:
                self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)
            except Exception:
                pass
        else:
            try:
                self._backend._load_index(key_material=None)
            except Exception:
                pass

    def decentralized(self) -> None:
        """Switch to decentralized per-key directory store (explicit method)."""
        current_path = self._backend.path
        fmt = getattr(self._backend, "store_format", "binary")
        try:
            self._backend.close()
        except Exception:
            pass
        self._backend = DecentralizedKV(current_path, store_format=fmt)
        self._keyfile = getattr(self._backend, "path", current_path) + ".key"
        self._saltfile = getattr(self._backend, "path", current_path) + ".salt"
        if self._level == "high":
            self._derive_key_material()
            try:
                self._backend._load_index()
            except Exception:
                pass
        else:
            try:
                self._backend._load_index()
            except Exception:
                pass

    # ----- passphrase / key helpers -----
    def set_passphrase(self, passphrase: str) -> None:
        self._passphrase = passphrase
        if self._level == "high":
            self._derive_key_material()
            try:
                self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)
            except Exception:
                pass

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
            km = _derive_key_from_passphrase(self._passphrase, salt)
            self._key_material = km
            return km
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
            try:
                self._backend._load_index(key_material=self._key_material if _HAS_CRYPTO else None)
            except Exception:
                pass
        else:
            self._key_material = None
            try:
                self._backend._load_index(key_material=None)
            except Exception:
                pass

    # ----- basic API: set/get/delete/keys/preview/export/compact/close -----
    def set(self, key: str, value: Any) -> None:
        if not isinstance(key, str):
            raise TypeError("key must be a string")
        wrapped = _json_safe(value)
        plain_record = json.dumps({"key": key, "deleted": False, "value": wrapped}, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        if self._level == "high":
            km = self._key_material or self._derive_key_material()
            enc_payload = _encrypt_record_bytes(plain_record, km)
            self._backend.set_wrapped_encrypted(key, plain_record, enc_payload)
        else:
            self._backend.set_wrapped_plain(key, wrapped)

    def get(self, key: str, default: Optional[Any] = None) -> Any:
        val = self._backend.get_indexed(key, None)
        if val is None:
            return default
        if isinstance(val, dict) and val.get("__fmt") == "enc-raw":
            b64 = val.get("v", "")
            try:
                blob = base64.b64decode(b64.encode("ascii"))
                km = self._key_material
                if km is None and self._passphrase:
                    km = self._derive_key_material()
                if km is None:
                    return default
                plain = _decrypt_record_bytes(blob, km)
                obj = _parse_plaintext_record(plain)
                return obj.get("value", default)
            except Exception:
                return default
        return val

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

    # ----- key rotation (kept) -----
    def rotate_key(self, new_passphrase: Optional[str] = None, interactive: bool = False) -> None:
        current_km: Optional[bytes] = None
        if self._level == "high":
            if self._passphrase:
                current_km = self._derive_key_material()
            elif os.path.exists(self._keyfile):
                current_km = builtins.open(self._keyfile, "rb").read()
            else:
                current_km = None

        if interactive:
            newp = getpass.getpass("New passphrase (leave empty to use random keyfile): ")
            if newp:
                self.set_passphrase(newp)
                new_km = self._key_material
            else:
                nm = secrets.token_bytes(32)
                tmp = self._keyfile + ".newtmp"
                with builtins.open(tmp, "wb") as f:
                    f.write(nm)
                os.replace(tmp, self._keyfile)
                try:
                    os.chmod(self._keyfile, 0o600)
                except Exception:
                    pass
                new_km = nm
                self._key_material = new_km
        else:
            if new_passphrase:
                self.set_passphrase(new_passphrase)
                new_km = self._key_material
            else:
                nm = secrets.token_bytes(32)
                tmp = self._keyfile + ".newtmp"
                with builtins.open(tmp, "wb") as f:
                    f.write(nm)
                os.replace(tmp, self._keyfile)
                try:
                    os.chmod(self._keyfile, 0o600)
                except Exception:
                    pass
                new_km = nm
                self._key_material = new_km

        try:
            if current_km is not None:
                try:
                    self._backend._load_index(key_material=current_km)
                except Exception:
                    pass
            else:
                try:
                    self._backend._load_index(key_material=None)
                except Exception:
                    pass

            if isinstance(self._backend, BinaryKV):
                self._backend.compact(key_material=new_km)
            else:
                self._backend.compact(key_material=new_km)
        except Exception as e:
            raise RuntimeError(f"rotate_key failed: {e}") from e

    # ----- server sync methods (simple HTTP JSON REST client using stdlib) -----
    def connect_server(self, base_url: str, headers: Optional[Dict[str, str]] = None) -> None:
        self._server_url = base_url.rstrip("/")
        self._server_headers = headers.copy() if headers else {}

    def _http_request(self, method: str, url: str, data: Optional[bytes] = None, headers: Optional[Dict[str, str]] = None, timeout: float = 10.0) -> Tuple[int, bytes]:
        req = urllib.request.Request(url, data=data, method=method)
        hdrs = (self._server_headers or {}).copy()
        if headers:
            hdrs.update(headers)
        for k, v in hdrs.items():
            req.add_header(k, v)
        if data is not None:
            req.add_header("Content-Type", "application/json")
            req.add_header("Content-Length", str(len(data)))
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.getcode(), resp.read()
        except urllib.error.HTTPError as e:
            try:
                body = e.read()
            except Exception:
                body = b""
            return e.code, body
        except Exception as e:
            raise

    def push_key(self, key: str) -> bool:
        if not self._server_url:
            raise RuntimeError("Server not configured. Call connect_server(url) first.")
        val = self.get(key, None)
        if val is None:
            raise KeyError("key not found")
        url = f"{self._server_url}/store"
        payload = json.dumps({"key": key, "value": val}, ensure_ascii=False).encode("utf-8")
        code, body = self._http_request("POST", url, data=payload)
        return 200 <= code < 300

    def push_all(self) -> bool:
        if not self._server_url:
            raise RuntimeError("Server not configured. Call connect_server(url) first.")
        items = []
        for k in self.keys():
            v = self.get(k, None)
            items.append({"key": k, "value": v})
        url = f"{self._server_url}/store/bulk"
        payload = json.dumps({"items": items}, ensure_ascii=False).encode("utf-8")
        code, body = self._http_request("POST", url, data=payload)
        return 200 <= code < 300

    def pull_key(self, key: str) -> Any:
        if not self._server_url:
            raise RuntimeError("Server not configured. Call connect_server(url) first.")
        url = f"{self._server_url}/store/{urllib.parse.quote(key, safe='')}"
        code, body = self._http_request("GET", url)
        if not (200 <= code < 300):
            raise RuntimeError(f"server error {code}: {body!r}")
        doc = json.loads(body.decode("utf-8"))
        val = doc.get("value")
        self.set(key, val)
        return val

    def pull_all(self) -> List[Tuple[str, Any]]:
        if not self._server_url:
            raise RuntimeError("Server not configured. Call connect_server(url) first.")
        url = f"{self._server_url}/store/bulk"
        code, body = self._http_request("GET", url)
        if not (200 <= code < 300):
            raise RuntimeError(f"server error {code}: {body!r}")
        doc = json.loads(body.decode("utf-8"))
        items = doc.get("items", [])
        out = []
        for it in items:
            k = it.get("key")
            v = it.get("value")
            if k is not None:
                self.set(k, v)
                out.append((k, v))
        return out

    # ----- graphical package installer -----
    def launch_installer(self) -> None:
        def _install_package(pkg: str, button, status_label):
            button.config(state="disabled")
            status_label.config(text=f"Installing {pkg}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                status_label.config(text=f"{pkg} installed.")
                messagebox.showinfo("Installer", f"{pkg} installed successfully.")
            except Exception as e:
                status_label.config(text=f"Failed: {e}")
                messagebox.showerror("Installer", f"Installation failed: {e}")
            finally:
                button.config(state="normal")

        root = tk.Tk()
        root.title("dbcake - Package Installer")
        frm = tk.Frame(root, padx=12, pady=12)
        frm.pack(fill="both", expand=True)
        tk.Label(frm, text="Optional packages for dbcake", font=("TkDefaultFont", 12, "bold")).pack(anchor="w")
        status = tk.Label(frm, text="Install optional packages (cryptography recommended).")
        status.pack(anchor="w", pady=(6, 12))

        def make_row(pkg):
            row = tk.Frame(frm)
            row.pack(fill="x", pady=4)
            tk.Label(row, text=pkg).pack(side="left")
            btn = tk.Button(row, text=f"Install {pkg}", width=14, command=lambda: _install_package(pkg, btn, status))
            btn.pack(side="right")
        make_row("cryptography")
        tk.Button(frm, text="Close", command=root.destroy).pack(pady=(12, 0))
        root.mainloop()

# ---------------------------
# Factory & module-level instance
# ---------------------------
def open_db(path: str = _DEFAULT_DATA_PATH, store_format: StoreFormat = "binary", dataset: str = "centerilized") -> DB:
    if dataset and dataset.strip().lower() == "decentralized":
        backend = DecentralizedKV(path, store_format=store_format)
    else:
        backend = BinaryKV(path, store_format=store_format)
    return DB(backend)

_binary = BinaryKV(_DEFAULT_DATA_PATH, store_format="binary")
db = DB(_binary)

# ---------------------------
# Secrets Client (HTTP) — sync + async
# ---------------------------
class DBcakeError(Exception):
    pass

class NotFoundError(DBcakeError):
    pass

class AuthError(DBcakeError):
    pass

class SecretMeta:
    def __init__(self, name: str, created_at: str, updated_at: str, tags: Optional[List[str]] = None) -> None:
        self.name = name
        self.created_at = created_at
        self.updated_at = updated_at
        self.tags = tags or []

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "SecretMeta":
        return cls(name=d["name"], created_at=d["created_at"], updated_at=d["updated_at"], tags=d.get("tags") or [])

    def to_dict(self) -> dict:
        return {"name": self.name, "created_at": self.created_at, "updated_at": self.updated_at, "tags": self.tags}

class Secret:
    def __init__(self, name: str, value: Optional[Any], created_at: str, updated_at: str, tags: Optional[List[str]] = None) -> None:
        self.name = name
        self.value = value
        self.created_at = created_at
        self.updated_at = updated_at
        self.tags = tags or []

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Secret":
        return cls(name=d["name"], value=d.get("value"), created_at=d["created_at"], updated_at=d["updated_at"], tags=d.get("tags") or [])

    def __repr__(self) -> str:
        return f"<Secret name={self.name!r} value={'***' if self.value is not None else None} created_at={self.created_at}>"

def _http_request(method: str, url: str, api_key: Optional[str] = None, data: Optional[bytes] = None, headers: Optional[dict] = None, timeout: float = 10.0) -> tuple[int, bytes]:
    req = urllib.request.Request(url, data=data, method=method)
    hdrs = (headers or {}).copy()
    if api_key:
        hdrs.setdefault("Authorization", f"Bearer {api_key}")
    for k, v in hdrs.items():
        req.add_header(k, v)
    if data is not None:
        req.add_header("Content-Type", "application/json")
        req.add_header("Content-Length", str(len(data)))
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.getcode(), resp.read()
    except urllib.error.HTTPError as e:
        try:
            body = e.read()
        except Exception:
            body = b""
        return e.code, body
    except urllib.error.URLError as e:
        raise DBcakeError(f"Connection error: {e}") from e

class Client:
    def __init__(self, base_url: str, api_key: Optional[str] = None, fernet_key: Optional[str] = None, default_headers: Optional[dict] = None) -> None:
        if not base_url:
            raise ValueError("base_url is required")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self._headers = default_headers or {}
        self.fernet_key = fernet_key
        self._fernet = None
        if self.fernet_key:
            if not _HAS_FERNET:
                raise RuntimeError("Fernet support requires 'cryptography' package. Install it or omit fernet_key.")
            self._fernet = Fernet(self.fernet_key.encode() if isinstance(self.fernet_key, str) else self.fernet_key)

    @classmethod
    def from_env(cls) -> "Client":
        url = os.environ.get("DBCAKE_URL") or os.environ.get("DBCAKE_BASE_URL")
        key = os.environ.get("DBCAKE_API_KEY") or os.environ.get("DBCAKE_KEY")
        fkey = os.environ.get("DBCAKE_FERNET_KEY")
        if not url:
            raise ValueError("Environment variable DBCAKE_URL (or DBCAKE_BASE_URL) is required")
        return cls(url, api_key=key, fernet_key=fkey)

    def _url(self, path: str) -> str:
        return f"{self.base_url.rstrip('/')}/{path.lstrip('/')}"

    def _handle_response(self, code: int, body: bytes) -> Any:
        if 200 <= code < 300:
            if not body:
                return None
            try:
                return json.loads(body.decode("utf-8"))
            except Exception:
                return body
        if code == 401 or code == 403:
            raise AuthError(f"authentication error: {code} {body!r}")
        if code == 404:
            raise NotFoundError("not found")
        raise DBcakeError(f"server error {code}: {body.decode('utf-8', errors='replace')}")

    def set(self, name: str, value: Any, tags: Optional[List[str]] = None) -> SecretMeta:
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string")
        if self._fernet:
            raw = json.dumps(value, ensure_ascii=False).encode("utf-8")
            token = self._fernet.encrypt(raw)
            payload_value = base64.b64encode(token).decode("ascii")
            payload = {"name": name, "value_encrypted": payload_value, "tags": tags or []}
        else:
            payload = {"name": name, "value": value, "tags": tags or []}
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        url = self._url("/secrets")
        code, body = _http_request("POST", url, api_key=self.api_key, data=data, headers=self._headers)
        resp = self._handle_response(code, body)
        meta = resp if isinstance(resp, dict) else {}
        return SecretMeta.from_dict({
            "name": meta.get("name", name),
            "created_at": meta.get("created_at", datetime.datetime.utcnow().isoformat()),
            "updated_at": meta.get("updated_at", datetime.datetime.utcnow().isoformat()),
            "tags": meta.get("tags", tags or []),
        })

    def get(self, name: str, reveal: bool = False) -> Secret:
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string")
        url = self._url(f"/secrets/{urllib.parse.quote(name, safe='')}")
        if reveal:
            url += "?reveal=1"
        code, body = _http_request("GET", url, api_key=self.api_key, headers=self._headers)
        resp = self._handle_response(code, body)
        if not isinstance(resp, dict):
            raise DBcakeError("unexpected server response")
        name_r = resp.get("name", name)
        created_at = resp.get("created_at", datetime.datetime.utcnow().isoformat())
        updated_at = resp.get("updated_at", created_at)
        tags = resp.get("tags", [])
        if "value_encrypted" in resp:
            enc_b64 = resp["value_encrypted"]
            try:
                token = base64.b64decode(enc_b64.encode("ascii"))
                if self._fernet:
                    raw = self._fernet.decrypt(token)
                else:
                    if reveal:
                        raise DBcakeError("value is encrypted on server; client lacks fernet_key to decrypt locally")
                    return Secret(name_r, None, created_at, updated_at, tags)
                val = json.loads(raw.decode("utf-8"))
                return Secret(name_r, val, created_at, updated_at, tags)
            except Exception as e:
                raise DBcakeError(f"failed to decrypt secret: {e}") from e
        else:
            value = resp.get("value")
            return Secret(name_r, value if reveal else None, created_at, updated_at, tags)

    def list(self, tag: Optional[str] = None) -> List[SecretMeta]:
        url = self._url("/secrets")
        if tag:
            url += "?tag=" + urllib.parse.quote(tag, safe="")
        code, body = _http_request("GET", url, api_key=self.api_key, headers=self._headers)
        resp = self._handle_response(code, body)
        if not isinstance(resp, dict):
            raise DBcakeError("unexpected server response")
        items = resp.get("items", [])
        out: List[SecretMeta] = []
        for it in items:
            if not isinstance(it, dict):
                continue
            out.append(SecretMeta.from_dict({
                "name": it.get("name"),
                "created_at": it.get("created_at", datetime.datetime.utcnow().isoformat()),
                "updated_at": it.get("updated_at", it.get("created_at", datetime.datetime.utcnow().isoformat())),
                "tags": it.get("tags", []),
            }))
        return out

    def delete(self, name: str) -> None:
        if not isinstance(name, str) or not name:
            raise ValueError("name must be a non-empty string")
        url = self._url(f"/secrets/{urllib.parse.quote(name, safe='')}")
        code, body = _http_request("DELETE", url, api_key=self.api_key, headers=self._headers)
        if code == 204 or (200 <= code < 300):
            return
        self._handle_response(code, body)

class AsyncClient:
    def __init__(self, client: Client) -> None:
        self._client = client

    @classmethod
    def from_env(cls) -> "AsyncClient":
        return cls(Client.from_env())

    async def set(self, name: str, value: Any, tags: Optional[List[str]] = None) -> SecretMeta:
        loop = asyncio.get_running_loop()
        fn = functools.partial(self._client.set, name, value, tags)
        return await loop.run_in_executor(None, fn)

    async def get(self, name: str, reveal: bool = False) -> Secret:
        loop = asyncio.get_running_loop()
        fn = functools.partial(self._client.get, name, reveal)
        return await loop.run_in_executor(None, fn)

    async def list(self, tag: Optional[str] = None) -> List[SecretMeta]:
        loop = asyncio.get_running_loop()
        fn = functools.partial(self._client.list, tag)
        return await loop.run_in_executor(None, fn)

    async def delete(self, name: str) -> None:
        loop = asyncio.get_running_loop()
        fn = functools.partial(self._client.delete, name)
        return await loop.run_in_executor(None, fn)

# ---------------------------
# CLI: local DB and secrets client
# ---------------------------
def _get_db_for_cli(path: Optional[str], format_hint: Optional[str], dataset_hint: Optional[str] = None) -> DB:
    if not path:
        return db
    path = path if path.endswith(".dbce") else path + ".dbce"
    ds = (dataset_hint or "centerilized").lower()
    backend = DecentralizedKV(path, store_format=format_hint or "binary") if ds == "decentralized" else BinaryKV(path, store_format=format_hint or "binary")
    return DB(backend)

def cli_main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="dbcake", description="dbcake CLI (DB + secrets client)")
    parser.add_argument("--installer", action="store_true", help="Launch graphical installer (tkinter)")
    sub = parser.add_subparsers(dest="mode", required=False, help="mode: 'db' commands (default) or 'secret' client commands")

    # top-level DB subparser group
    db_parser = sub.add_parser("db", help="local DB operations")
    db_sub = db_parser.add_subparsers(dest="cmd", required=True)

    def db_add_path_arg(p):
        p.add_argument("dbpath", nargs="?", help="path to .dbce file (optional)")

    p = db_sub.add_parser("create", help="create .dbce file")
    db_add_path_arg(p)
    p.add_argument("--format", choices=["binary", "bits01", "dec", "hex"], default="binary")
    p.add_argument("--dataset", choices=["centerilized", "decentralized", "centralized"], default="centerilized")

    p = db_sub.add_parser("set", help="set key")
    db_add_path_arg(p)
    p.add_argument("key")
    p.add_argument("value")

    p = db_sub.add_parser("get", help="get key")
    db_add_path_arg(p)
    p.add_argument("key")

    p = db_sub.add_parser("delete", help="delete key")
    db_add_path_arg(p)
    p.add_argument("key")

    p = db_sub.add_parser("preview", help="preview keys")
    db_add_path_arg(p)
    p.add_argument("--limit", type=int, default=10)

    p = db_sub.add_parser("compact", help="compact DB")
    db_add_path_arg(p)

    p = db_sub.add_parser("export", help="export db file to path")
    db_add_path_arg(p)
    p.add_argument("dest")

    p = db_sub.add_parser("set-passphrase", help="set passphrase for DB (in memory)")
    db_add_path_arg(p)
    p.add_argument("--passphrase", nargs="?", default=None)
    p.add_argument("--interactive", action="store_true", help="prompt for passphrase without echo")

    p = db_sub.add_parser("set-format", help="set storage format for DB (reopens file)")
    db_add_path_arg(p)
    p.add_argument("format", choices=["binary", "bits01", "dec", "hex"])

    p = db_sub.add_parser("title", help="switch to DB file (create if missing)")
    db_add_path_arg(p)
    p.add_argument("--format", choices=["binary", "bits01", "dec", "hex"], default=None)
    p.add_argument("--dataset", choices=["centerilized", "decentralized", "centralized"], default=None)

    p = db_sub.add_parser("keys", help="list keys")
    db_add_path_arg(p)

    p = db_sub.add_parser("reveal", help="reveal DB file in OS file manager")
    db_add_path_arg(p)

    p = db_sub.add_parser("rotate-key", help="rotate encryption key for DB (re-encrypt all data)")
    db_add_path_arg(p)
    p.add_argument("--old-passphrase", nargs="?", default=None)
    p.add_argument("--new-passphrase", nargs="?", default=None)
    p.add_argument("--interactive", action="store_true", help="prompt for old and new passphrases (no echo)")

    # Secrets client subparser group
    sec_parser = sub.add_parser("secret", help="secrets client operations (HTTP)")
    sec_sub = sec_parser.add_subparsers(dest="scmd", required=True)

    sp = sec_sub.add_parser("set", help="set secret")
    sp.add_argument("name")
    sp.add_argument("value")
    sp.add_argument("--tags", help="comma separated tags", default=None)
    sp.add_argument("--url", help="server base url", default=os.environ.get("DBCAKE_URL"))
    sp.add_argument("--api-key", help="API key", default=os.environ.get("DBCAKE_API_KEY"))
    sp.add_argument("--fernet-key", help="Fernet key (optional)", default=os.environ.get("DBCAKE_FERNET_KEY"))

    sp = sec_sub.add_parser("get", help="get secret")
    sp.add_argument("name")
    sp.add_argument("--reveal", action="store_true")
    sp.add_argument("--url", help="server base url", default=os.environ.get("DBCAKE_URL"))
    sp.add_argument("--api-key", help="API key", default=os.environ.get("DBCAKE_API_KEY"))
    sp.add_argument("--fernet-key", help="Fernet key (optional)", default=os.environ.get("DBCAKE_FERNET_KEY"))

    sp = sec_sub.add_parser("list", help="list secrets")
    sp.add_argument("--tag", help="filter by tag", default=None)
    sp.add_argument("--url", help="server base url", default=os.environ.get("DBCAKE_URL"))
    sp.add_argument("--api-key", help="API key", default=os.environ.get("DBCAKE_API_KEY"))

    sp = sec_sub.add_parser("delete", help="delete secret")
    sp.add_argument("name")
    sp.add_argument("--url", help="server base url", default=os.environ.get("DBCAKE_URL"))
    sp.add_argument("--api-key", help="API key", default=os.environ.get("DBCAKE_API_KEY"))

    args = parser.parse_args(argv)

    # installer quick path
    if getattr(args, "installer", False):
        db.launch_installer()
        return 0

    # default to db mode if no mode specified
    mode = args.mode or "db"
    try:
        if mode == "db":
            cmd = getattr(args, "cmd", None)
            if cmd == "create":
                fmt = args.format
                ds = args.dataset
                target = args.dbpath or _DEFAULT_DATA_PATH
                target = target if target.endswith(".dbce") else target + ".dbce"
                open_db(target, store_format=fmt, dataset=ds).compact()
                print("created", target)
                return 0

            if cmd == "set":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                try:
                    val = json.loads(args.value)
                except Exception:
                    val = args.value
                dbobj.set(args.key, val)
                print("ok")
                return 0

            if cmd == "get":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                v = dbobj.get(args.key, None)
                print(repr(v))
                return 0

            if cmd == "delete":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                ok = dbobj.delete(args.key)
                print("deleted" if ok else "not found")
                return 0

            if cmd == "preview":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                rows = dbobj.preview(limit=args.limit)
                if not rows:
                    print("<empty>")
                else:
                    for k, v in rows:
                        print(f"{k} : {v!r}")
                return 0

            if cmd == "compact":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                dbobj.compact()
                print("compacted")
                return 0

            if cmd == "export":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                dbobj.export(args.dest)
                print("exported to", args.dest)
                return 0

            if cmd == "set-passphrase":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                if args.interactive or args.passphrase is None:
                    pp = getpass.getpass("Passphrase (not stored): ")
                else:
                    pp = args.passphrase
                dbobj.set_passphrase(pp)
                print("passphrase set in memory. To enable, run: db.pw = 'high' in code")
                return 0

            if cmd == "set-format":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                dbobj.set_format(args.format)
                print("format set to", args.format)
                return 0

            if cmd == "title":
                ds = args.dataset
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None, ds)
                if getattr(args, "dbpath", None):
                    dbobj.title(args.dbpath, store_format=args.format)
                    if ds:
                        if ds == "decentralized":
                            dbobj.decentralized()
                        else:
                            dbobj.centerilized()
                    print("switched to", args.dbpath)
                else:
                    print("no path supplied")
                return 0

            if cmd == "keys":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                for k in dbobj.keys():
                    print(k)
                return 0

            if cmd == "reveal":
                target = getattr(args, "dbpath", None) or _DEFAULT_DATA_PATH
                if not target.endswith(".dbce"):
                    target = target + ".dbce"
                reveal_in_file_manager(target)
                return 0

            if cmd == "rotate-key":
                dbobj = _get_db_for_cli(getattr(args, "dbpath", None), None)
                if args.interactive:
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
                    if args.old_passphrase:
                        dbobj.set_passphrase(args.old_passphrase)
                    dbobj.rotate_key(new_passphrase=args.new_passphrase, interactive=False)
                    print("rotation complete")
                    return 0

        elif mode == "secret":
            scmd = getattr(args, "scmd", None)
            url = getattr(args, "url", None)
            if scmd == "set":
                if not url:
                    print("Error: server URL is required (pass --url or set DBCAKE_URL env)", file=sys.stderr)
                    return 2
                api_key = getattr(args, "api_key", None)
                fkey = getattr(args, "fernet_key", None)
                client = Client(url, api_key=api_key, fernet_key=fkey)
                tags = []
                if args.tags:
                    tags = [t.strip() for t in args.tags.split(",") if t.strip()]
                try:
                    val = json.loads(args.value)
                except Exception:
                    val = args.value
                meta = client.set(args.name, val, tags=tags)
                print(json.dumps(meta.to_dict(), ensure_ascii=False))
                return 0

            if scmd == "get":
                if not url:
                    print("Error: server URL is required (pass --url or set DBCAKE_URL env)", file=sys.stderr)
                    return 2
                api_key = getattr(args, "api_key", None)
                fkey = getattr(args, "fernet_key", None)
                client = Client(url, api_key=api_key, fernet_key=fkey)
                sec = client.get(args.name, reveal=args.reveal)
                out = {"name": sec.name, "created_at": sec.created_at, "updated_at": sec.updated_at, "tags": sec.tags}
                if args.reveal:
                    out["value"] = sec.value
                print(json.dumps(out, ensure_ascii=False))
                return 0

            if scmd == "list":
                if not url:
                    print("Error: server URL is required (pass --url or set DBCAKE_URL env)", file=sys.stderr)
                    return 2
                api_key = getattr(args, "api_key", None)
                client = Client(url, api_key=api_key)
                metas = client.list(tag=args.tag)
                print(json.dumps([m.to_dict() for m in metas], ensure_ascii=False))
                return 0

            if scmd == "delete":
                if not url:
                    print("Error: server URL is required (pass --url or set DBCAKE_URL env)", file=sys.stderr)
                    return 2
                api_key = getattr(args, "api_key", None)
                client = Client(url, api_key=api_key)
                client.delete(args.name)
                print(json.dumps({"deleted": args.name}))
                return 0

    except NotFoundError:
        print("Error: not found", file=sys.stderr)
        return 3
    except AuthError:
        print("Error: authentication failed", file=sys.stderr)
        return 4
    except Exception as e:
        print("error:", e, file=sys.stderr)
        return 2

    return 0

# ---------------------------
# Extension: transactions, indexes, schema, query engine, migrator, backup
# (merged into same file to avoid circular import)
# ---------------------------

# Utilities for extension
def _atomic_copy(src: str, dst: str) -> None:
    tmp = dst + ".tmp"
    shutil.copy2(src, tmp)
    os.replace(tmp, dst)

def _ensure_dir(path: str) -> None:
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)

# Index Manager
class IndexManager:
    def __init__(self, db_obj: DB):
        self.db = db_obj
        self.backend = db_obj._backend
        self.index_dir = getattr(self.backend, "path", _DEFAULT_DATA_PATH) + ".idx"
        os.makedirs(self.index_dir, exist_ok=True)
        self._locks: Dict[str, threading.RLock] = {}

    def _index_path(self, field: str) -> str:
        safe = field.replace("/", "_")
        return os.path.join(self.index_dir, f"{safe}.idx")

    def create_index(self, field: str, reindex: bool = True) -> None:
        p = self._index_path(field)
        lock = self._locks.setdefault(field, threading.RLock())
        with lock:
            index_map: Dict[str, List[str]] = {}
            if not reindex and os.path.exists(p):
                return
            for k in self.db.keys():
                v = self.db.get(k, None)
                if v is None:
                    continue
                try:
                    if isinstance(v, dict) and field in v:
                        fv = v[field]
                        key = json.dumps(fv, sort_keys=True, ensure_ascii=False)
                        index_map.setdefault(key, []).append(k)
                except Exception:
                    continue
            with open(p + ".tmp", "w", encoding="utf-8") as f:
                json.dump(index_map, f, ensure_ascii=False)
            os.replace(p + ".tmp", p)

    def drop_index(self, field: str) -> None:
        p = self._index_path(field)
        try:
            os.remove(p)
        except FileNotFoundError:
            pass

    def query_index(self, field: str, value: Any) -> List[str]:
        p = self._index_path(field)
        if not os.path.exists(p):
            return []
        key = json.dumps(value, sort_keys=True, ensure_ascii=False)
        try:
            with open(p, "r", encoding="utf-8") as f:
                idx = json.load(f)
            return idx.get(key, [])
        except Exception:
            return []

    def update_indexes_on_set(self, key: str, value: Any) -> None:
        for fname in os.listdir(self.index_dir):
            if not fname.endswith(".idx"):
                continue
            field = fname[:-4]
            p = os.path.join(self.index_dir, fname)
            try:
                with open(p, "r", encoding="utf-8") as f:
                    idx = json.load(f)
            except Exception:
                idx = {}
            for vlist in idx.values():
                if key in vlist:
                    vlist.remove(key)
            try:
                if isinstance(value, dict) and field in value:
                    fv = value[field]
                    kstr = json.dumps(fv, sort_keys=True, ensure_ascii=False)
                    idx.setdefault(kstr, []).append(key)
            except Exception:
                pass
            with open(p + ".tmp", "w", encoding="utf-8") as f:
                json.dump(idx, f, ensure_ascii=False)
            os.replace(p + ".tmp", p)

# Schema Manager
class SchemaManager:
    def __init__(self, db_obj: DB):
        self.db = db_obj
        self.backend = db_obj._backend
        self.schema_path = getattr(self.backend, "path", _DEFAULT_DATA_PATH) + ".schema.json"
        self._lock = threading.RLock()
        self._load()

    def _load(self):
        try:
            with open(self.schema_path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
        except Exception:
            self._data = {}

    def _save(self):
        with self._lock:
            with open(self.schema_path + ".tmp", "w", encoding="utf-8") as f:
                json.dump(self._data, f, ensure_ascii=False, indent=2)
            os.replace(self.schema_path + ".tmp", self.schema_path)

    def create_table(self, table: str, schema: Dict[str, Dict[str, Any]]) -> None:
        with self._lock:
            if table in self._data:
                raise ValueError("table already exists")
            self._data[table] = schema
            self._save()

    def drop_table(self, table: str) -> None:
        with self._lock:
            if table in self._data:
                del self._data[table]
                self._save()

    def validate(self, table: str, obj: Dict[str, Any], key: Optional[str] = None) -> None:
        schema = self._data.get(table)
        if not schema:
            return
        for fld, meta in schema.items():
            if meta.get("required") and fld not in obj:
                raise ValueError(f"Field {fld} is required for table {table}")
            if fld in obj and meta.get("type") and meta.get("type") != "any":
                tname = meta["type"]
                val = obj[fld]
                if tname == "int" and not isinstance(val, int):
                    raise TypeError(f"{fld} must be int")
                if tname == "str" and not isinstance(val, str):
                    raise TypeError(f"{fld} must be str")
        for fld, meta in schema.items():
            if meta.get("unique"):
                prefix = f"{table}:"
                for existing in self.db.keys():
                    if not existing.startswith(prefix):
                        continue
                    if key is not None and existing == key:
                        continue
                    val = self.db.get(existing, None)
                    if isinstance(val, dict) and fld in val and fld in obj and val[fld] == obj[fld]:
                        raise ValueError(f"Unique constraint failed on {fld}")
        for fld, meta in schema.items():
            fk = meta.get("fk")
            if fk and fld in obj:
                target_table, target_field = fk
                pref = f"{target_table}:"
                found = False
                for existing in self.db.keys():
                    if not existing.startswith(pref):
                        continue
                    val = self.db.get(existing, None)
                    if isinstance(val, dict) and target_field in val and val[target_field] == obj[fld]:
                        found = True
                        break
                if not found:
                    raise ValueError(f"Foreign key constraint failed: {fld} -> {target_table}.{target_field}")

# Transaction manager
class TransactionError(Exception):
    pass

class Transaction:
    def __init__(self, db_obj: DB, txname: Optional[str] = None):
        self.db = db_obj
        self.staged: List[Tuple[str, str, Any]] = []
        self.active = False
        self._lock = threading.RLock()
        self.txname = txname or f"tx-{int(time.time()*1000)}"
        self._index_manager = IndexManager(db_obj)

    def begin(self):
        with self._lock:
            if self.active:
                raise TransactionError("already active")
            self.active = True
            return self

    def set(self, key: str, value: Any):
        if not self.active:
            raise TransactionError("not active")
        self.staged.append(("set", key, value))

    def delete(self, key: str):
        if not self.active:
            raise TransactionError("not active")
        self.staged.append(("del", key, None))

    def commit(self):
        if not self.active:
            raise TransactionError("not active")
        path = getattr(self.db._backend, "path", None)
        if not path:
            raise TransactionError("backend has no path to lock")
        with FileLock(path):
            try:
                for op, key, val in self.staged:
                    if op == "set":
                        self.db.set(key, val)
                        try:
                            self._index_manager.update_indexes_on_set(key, val)
                        except Exception:
                            pass
                    elif op == "del":
                        self.db.delete(key)
            except Exception as e:
                raise TransactionError(f"commit failed: {e}") from e
            finally:
                self.active = False
                self.staged.clear()

    def abort(self):
        if not self.active:
            raise TransactionError("not active")
        self.active = False
        self.staged.clear()

# Query engine
class QueryEngine:
    def __init__(self, db_obj: DB, index_manager: Optional[IndexManager] = None):
        self.db = db_obj
        self.index = index_manager or IndexManager(db_obj)

    def _table_keys(self, table: str) -> List[str]:
        prefix = f"{table}:"
        return [k for k in self.db.keys() if k.startswith(prefix)]

    def select(self, table: str, where: Optional[callable] = None, fields: Optional[List[str]] = None, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        out: List[Dict[str, Any]] = []
        for k in self._table_keys(table):
            v = self.db.get(k, None)
            if v is None:
                continue
            if where is None or where(v):
                if fields:
                    rec = {f: v.get(f) for f in fields}
                else:
                    rec = v
                out.append(rec)
                if limit and len(out) >= limit:
                    break
        return out

    def join(self, left_table: str, right_table: str, left_on: str, right_on: str, where: Optional[callable] = None, limit: Optional[int] = None) -> List[Tuple[Dict[str, Any], Dict[str, Any]]]:
        out: List[Tuple[Dict[str, Any], Dict[str, Any]]] = []
        right_index_exists = os.path.exists(self.index._index_path(right_on))
        right_keys_map: Dict[str, List[str]] = {}
        if right_index_exists:
            idxpath = self.index._index_path(right_on)
            try:
                with open(idxpath, "r", encoding="utf-8") as f:
                    idx = json.load(f)
                right_keys_map = {k: v for k, v in idx.items()}
            except Exception:
                right_keys_map = {}
        for lk in self._table_keys(left_table):
            lv = self.db.get(lk)
            if lv is None:
                continue
            lval = lv.get(left_on)
            candidates = []
            if right_index_exists and lval is not None:
                keystr = json.dumps(lval, sort_keys=True, ensure_ascii=False)
                candidates = right_keys_map.get(keystr, [])
            else:
                candidates = self._table_keys(right_table)
            for rk in candidates:
                rv = self.db.get(rk)
                if rv is None:
                    continue
                rval = rv.get(right_on)
                if lval == rval:
                    if where is None or where({"left": lv, "right": rv}):
                        out.append((lv, rv))
                        if limit and len(out) >= limit:
                            return out
        return out

# Backup & restore
def backup_db(db_obj: DB, dest_dir: str) -> str:
    backend = db_obj._backend
    base = getattr(backend, "path", _DEFAULT_DATA_PATH)
    os.makedirs(dest_dir, exist_ok=True)
    timestamp = time.strftime("%Y%m%d%H%M%S")
    name = os.path.basename(base)
    dest = os.path.join(dest_dir, f"{name}.backup.{timestamp}")
    os.makedirs(dest, exist_ok=True)
    try:
        shutil.copy2(base, os.path.join(dest, os.path.basename(base)))
    except Exception:
        pass
    for ext in (".key", ".salt", ".schema.json"):
        p = base + ext
        if os.path.exists(p):
            shutil.copy2(p, os.path.join(dest, os.path.basename(p)))
    idxdir = base + ".idx"
    if os.path.isdir(idxdir):
        shutil.copytree(idxdir, os.path.join(dest, os.path.basename(idxdir)), dirs_exist_ok=True)
    ddir = base + ".d"
    if os.path.isdir(ddir):
        shutil.copytree(ddir, os.path.join(dest, os.path.basename(ddir)), dirs_exist_ok=True)
    return dest

def restore_from_backup(db_path: str, backup_dir: str) -> None:
    for fname in os.listdir(backup_dir):
        src = os.path.join(backup_dir, fname)
        dst = os.path.join(os.path.dirname(db_path), fname)
        if os.path.isdir(src):
            if os.path.exists(dst):
                if os.path.isdir(dst):
                    shutil.rmtree(dst)
                else:
                    os.remove(dst)
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)

# Migrator
class Migrator:
    def __init__(self, db_obj: DB):
        self.db = db_obj
        self.backend = db_obj._backend
        self.mig_dir = getattr(self.backend, "path", _DEFAULT_DATA_PATH) + ".migrations"
        os.makedirs(self.mig_dir, exist_ok=True)
        self.state_file = os.path.join(self.mig_dir, ".migrations_state.json")
        self._load_state()

    def _load_state(self):
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                self._state = json.load(f)
        except Exception:
            self._state = {"applied": []}

    def _save_state(self):
        with open(self.state_file + ".tmp", "w", encoding="utf-8") as f:
            json.dump(self._state, f, ensure_ascii=False, indent=2)
        os.replace(self.state_file + ".tmp", self.state_file)

    def available_migrations(self) -> List[str]:
        files = [f for f in os.listdir(self.mig_dir) if f.endswith(".py") and not f.startswith(".")]
        files.sort()
        return files

    def apply_all(self):
        for fn in self.available_migrations():
            if fn in self._state.get("applied", []):
                continue
            self.apply(fn)

    def apply(self, filename: str):
        path = os.path.join(self.mig_dir, filename)
        modname = f"dbcake_mig_{int(time.time()*1000)}"
        spec = types.ModuleType(modname)
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        exec(code, spec.__dict__)
        up = spec.__dict__.get("upgrade")
        if callable(up):
            up(self.db)
            self._state.setdefault("applied", []).append(filename)
            self._save_state()
        else:
            raise RuntimeError("migration has no upgrade(db) function")

    def rollback(self, filename: str):
        path = os.path.join(self.mig_dir, filename)
        modname = f"dbcake_mig_{int(time.time()*1000)}"
        spec = types.ModuleType(modname)
        with open(path, "r", encoding="utf-8") as f:
            code = f.read()
        exec(code, spec.__dict__)
        down = spec.__dict__.get("downgrade")
        if callable(down):
            down(self.db)
            if filename in self._state.get("applied", []):
                self._state["applied"].remove(filename)
            self._save_state()
        else:
            raise RuntimeError("migration has no downgrade(db) function")

# Attach extension helpers to DB instances
def extend_db(db_obj: DB) -> None:
    if hasattr(db_obj, "_ext_attached") and db_obj._ext_attached:
        return
    db_obj._ext_attached = True
    db_obj.index_mgr = IndexManager(db_obj)
    db_obj.schema_mgr = SchemaManager(db_obj)
    db_obj.query_engine = QueryEngine(db_obj, index_manager=db_obj.index_mgr)
    db_obj.migrator = Migrator(db_obj)
    def tx_begin():
        return Transaction(db_obj).begin()
    db_obj.tx_begin = tx_begin
    def backup(dest_dir: str) -> str:
        return backup_db(db_obj, dest_dir)
    db_obj.backup = backup
    def restore(backup_dir: str) -> None:
        restore_from_backup(getattr(db_obj._backend, "path", _DEFAULT_DATA_PATH), backup_dir)
    db_obj.restore = restore

# Auto-extend module-level db
extend_db(db)

# ---------------------------
# Module exports
# ---------------------------
__all__ = ["db", "open_db", "DB", "BinaryKV", "DecentralizedKV", "Client", "AsyncClient", "DBcakeError", "NotFoundError", "AuthError", "extend_db"]

# ---------------------------
# CLI entrypoint
# ---------------------------
if __name__ == "__main__":
    raise SystemExit(cli_main())
