from typing import Any, List, Optional, Tuple, Iterator, Dict
import os
import sqlite3
import threading
import json
import pickle
import base64
import sys
import subprocess
import shutil
import contextlib
import datetime

# module defaults
_MODULE_DIR = os.path.dirname(__file__) or "."
_DEFAULT_DB_PATH = os.path.join(_MODULE_DIR, "database.db")
_DEFAULT_SECURE_DB_PATH = os.path.join(_MODULE_DIR, "database.high.db")

# Optional cryptography
try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.backends import default_backend
    _CRYPTO = True
except Exception:
    Fernet = None
    InvalidToken = Exception
    PBDKF2HMAC = None
    _CRYPTO = False

class _AttrDB:
    def __init__(self, path: str):
        object.__setattr__(self, "_path", path)
        object.__setattr__(self, "_conn", sqlite3.connect(path, check_same_thread=False))
        object.__setattr__(self, "_lock", threading.RLock())
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value BLOB NOT NULL)")
            self._conn.commit()

    def _serialize(self, v: Any) -> bytes:
        try:
            s = json.dumps(v, ensure_ascii=False, separators=(",", ":"), default=None)
            return b"J" + s.encode("utf-8")
        except Exception:
            p = pickle.dumps(v, protocol=pickle.HIGHEST_PROTOCOL)
            return b"P" + base64.b64encode(p)

    def _deserialize(self, blob: bytes) -> Any:
        if not blob:
            return None
        head = blob[:1]; body = blob[1:]
        if head == b"J":
            try: return json.loads(body.decode("utf-8"))
            except: pass
        if head == b"P":
            try: return pickle.loads(base64.b64decode(body))
            except: return body
        return blob

    def _set(self, key: str, value: Any):
        data = self._serialize(value)
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)", (key, sqlite3.Binary(data)))
            self._conn.commit()

    def _get(self, key: str):
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT value FROM kv WHERE key = ?", (key,))
            row = cur.fetchone()
            if not row:
                raise KeyError(key)
            return self._deserialize(row[0])

    def _delete(self, key: str):
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("DELETE FROM kv WHERE key = ?", (key,))
            changed = cur.rowcount
            self._conn.commit()
        if changed == 0:
            raise KeyError(key)

    def _keys(self) -> List[str]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute("SELECT key FROM kv")
            return [r[0] for r in cur.fetchall()]

    # friendly API
    def __setattr__(self, name: str, value: Any):
        if name.startswith("_"): return object.__setattr__(self, name, value)
        if not name.isidentifier(): raise AttributeError("Use simple identifier-like names.")
        self._set(name, value)

    def __getattr__(self, name: str):
        if name.startswith("_"): raise AttributeError(name)
        if not name.isidentifier(): raise AttributeError(name)
        try: return self._get(name)
        except KeyError: raise AttributeError(name)

    def __delattr__(self, name: str):
        if name.startswith("_"): return object.__delattr__(self, name)
        try: self._delete(name)
        except KeyError: raise AttributeError(name)

    def keys(self) -> List[str]: return self._keys()
    def items(self) -> Iterator[Tuple[str, Any]]:
        for k in self._keys(): yield (k, getattr(self, k))
    def preview(self, limit:int=10) -> List[Tuple[str, Any]]:
        ks = self._keys(); out=[]
        for k in ks[:limit]:
            try: out.append((k, getattr(self,k)))
            except: out.append((k,"<error>"))
        return out
    def export(self, dest:str) -> str:
        src = getattr(self,"_path", None)
        if not src or not os.path.exists(src): raise FileNotFoundError("DB file not found")
        shutil.copy2(src, dest); return dest
    def close(self):
        try: self._conn.close()
        except: pass
    def __repr__(self):
        try: c=len(self._keys())
        except: c="?"
        return f"<AttrDB keys={c} path={getattr(self,'_path',None)!r}>"

# ---------------------------
# Obfuscation fallback (educational)
# ---------------------------
class _ObfuscateDB(_AttrDB):
    def _xor(self, data: bytes, key: bytes) -> bytes:
        return bytes([b ^ key[i % len(key)] for i,b in enumerate(data)])
    def _serialize(self, v: Any) -> bytes:
        raw = super()._serialize(v)
        key = (getattr(self,"_path","").encode("utf-8") or b"kiddo-key")[:16]
        x = self._xor(raw, key)
        return b"O" + base64.b64encode(x)
    def _deserialize(self, blob: bytes) -> Any:
        if not blob: return None
        head = blob[:1]; body = blob[1:]
        if head != b"O": return super()._deserialize(blob)
        try:
            raw = base64.b64decode(body)
            key = (getattr(self,"_path","").encode("utf-8") or b"kiddo-key")[:16]
            r = self._xor(raw, key)
            return super()._deserialize(r)
        except Exception:
            return "<corrupt>"

# ---------------------------
# Secure DB (Fernet) if available
# ---------------------------
class _SecureDB(_AttrDB):
    def __init__(self, path: str, fernet: "Fernet"):
        super().__init__(path)
        object.__setattr__(self, "_fernet", fernet)
    def _serialize(self, v: Any) -> bytes:
        plain = super()._serialize(v)
        token = object.__getattribute__(self,"_fernet").encrypt(plain)
        return b"E" + token
    def _deserialize(self, blob: bytes) -> Any:
        if not blob: return None
        head = blob[:1]; body = blob[1:]
        if head != b"E": return super()._deserialize(blob)
        try:
            plain = object.__getattribute__(self,"_fernet").decrypt(body)
            return super()._deserialize(plain)
        except InvalidToken:
            raise ValueError("decryption failed")

# helper for simple Fernet key from path (educational KDF; ok for learning — not recommended for real production)
def _simple_fernet_key(path: str) -> bytes:
    import hashlib
    h = hashlib.sha256(path.encode("utf-8")).digest()[:32]
    return base64.urlsafe_b64encode(h)

# ---------------------------
# Public kid-friendly wrapper
# ---------------------------
class PublicDB:
    def __init__(self):
        object.__setattr__(self, "_level", "normal")
        object.__setattr__(self, "_impl", _AttrDB(_DEFAULT_DB_PATH))
        object.__setattr__(self, "_paths", {"low": _DEFAULT_DB_PATH, "normal": _DEFAULT_DB_PATH, "high": _DEFAULT_SECURE_DB_PATH})
    @property
    def pw(self) -> str: return object.__getattribute__(self,"_level")
    @pw.setter
    def pw(self, v: str):
        v = (v or "").lower()
        if v not in ("low","normal","high"): raise ValueError("pw must be low|normal|high")
        cur = object.__getattribute__(self,"_level")
        if v == cur: return
        object.__setattr__(self,"_level", v)
        # switch impl
        path = object.__getattribute__(self,"_paths")[v]
        if v == "high":
            if _CRYPTO:
                key = _simple_fernet_key(path); f = Fernet(key); impl = _SecureDB(path, f)
            else:
                print("WARNING: cryptography not installed — 'high' uses educational obfuscation (NOT SECURE).")
                impl = _ObfuscateDB(path)
        else:
            impl = _AttrDB(path)
        # close old
        try: object.__getattribute__(self,"_impl").close()
        except: pass
        object.__setattr__(self,"_impl", impl)

    # attribute forwarding
    def __setattr__(self, name: str, value: Any):
        if name.startswith("_"): return object.__setattr__(self, name, value)
        impl = object.__getattribute__(self,"_impl"); setattr(impl, name, value)
    def __getattr__(self, name: str):
        if name.startswith("_"): raise AttributeError(name)
        impl = object.__getattribute__(self,"_impl")
        try: return getattr(impl, name)
        except AttributeError: raise AttributeError(name)
    def __delattr__(self, name: str):
        if name.startswith("_"): return object.__delattr__(self, name)
        impl = object.__getattribute__(self,"_impl");
        try:
            delattr(impl, name);
        except AttributeError: raise AttributeError(name)

    # friendly helpers
    def set(self, k, v): setattr(self, k, v)
    def get(self, k, default=None):
        try: return getattr(self,k)
        except AttributeError: return default
    def delete(self,k):
        try: delattr(self,k)
        except AttributeError: pass
    def preview(self, limit=10): return object.__getattribute__(self,"_impl").preview(limit)
    def export(self, dest): return object.__getattribute__(self,"_impl").export(dest)
    def file(self): return getattr(object.__getattribute__(self,"_impl"), "_path", None)
    def close(self): object.__getattribute__(self,"_impl").close()
    def __repr__(self): return f"<PublicDB level={self.pw!r} impl={object.__getattribute__(self,'_impl')!r}>"

# module db
db = PublicDB()

# ---------------------------
# SQL Layer
# - SQLDatabase: wraps sqlite connection and returns dict rows
# - Table: simple query-builder: select/where/order/limit/insert/update/delete
# ---------------------------
def _row_to_dict(cursor: sqlite3.Cursor, row: sqlite3.Row) -> Dict[str, Any]:
    return {k[0]: row[idx] for idx,k in enumerate(cursor.description)} if row is not None else None

class SQLDatabase:
    def __init__(self, path: str = _DEFAULT_DB_PATH, timeout: float = 5.0):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False, timeout=timeout)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()

    def close(self):
        try: self._conn.close()
        except: pass

    def execute(self, sql: str, params: Optional[Tuple]=None) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, params or ())
            self._conn.commit()
            return cur

    def executemany(self, sql: str, seq_params: List[Tuple]) -> sqlite3.Cursor:
        with self._lock:
            cur = self._conn.cursor()
            cur.executemany(sql, seq_params)
            self._conn.commit()
            return cur

    def query(self, sql: str, params: Optional[Tuple]=None) -> List[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, params or ())
            rows = cur.fetchall()
            return [dict(r) for r in rows]

    def fetchone(self, sql: str, params: Optional[Tuple]=None) -> Optional[Dict[str, Any]]:
        with self._lock:
            cur = self._conn.cursor()
            cur.execute(sql, params or ())
            row = cur.fetchone()
            return dict(row) if row is not None else None

    @contextlib.contextmanager
    def transaction(self):
        with self._lock:
            cur = self._conn.cursor()
            try:
                cur.execute("BEGIN")
            except:
                pass
            try:
                yield
            except:
                self._conn.rollback()
                raise
            else:
                self._conn.commit()

    # create table helper (columns dict or SQL string)
    def create_table(self, name: str, columns: Optional[Dict[str,str]] = None, if_not_exists: bool=True, raw_sql: Optional[str]=None):
        if raw_sql:
            self.execute(raw_sql)
            return
        if not columns:
            raise ValueError("columns dict required when no raw_sql provided")
        ine = "IF NOT EXISTS " if if_not_exists else ""
        cols = ", ".join(f"{k} {v}" for k,v in columns.items())
        sql = f"CREATE TABLE {ine}{name} ({cols})"
        self.execute(sql)

    def drop_table(self, name: str, if_exists: bool=True):
        ine = "IF EXISTS " if if_exists else ""
        self.execute(f"DROP TABLE {ine}{name}")

    def table(self, name: str):
        return Table(self, name)

    def migrations(self, migrations: List[Tuple[str,str]], table_name: str = "_migrations"):
        # very small migrations table mechanism
        self.execute(f"CREATE TABLE IF NOT EXISTS {table_name} (name TEXT PRIMARY KEY, applied_at TEXT NOT NULL)")
        applied = set(r["name"] for r in self.query(f"SELECT name FROM {table_name}"))
        for name, sql in migrations:
            if name in applied: continue
            self.execute(sql)
            now = datetime.datetime.utcnow().isoformat()
            self.execute(f"INSERT INTO {table_name} (name, applied_at) VALUES (?, ?)", (name, now))

class Table:
    def __init__(self, db: SQLDatabase, name: str):
        self.db = db
        self.name = name
        self._select_cols = "*"
        self._where = None
        self._params = ()
        self._order = None
        self._limit = None
        self._joins = []  # list of raw join snippets

    # builder methods (return self for chaining)
    def select(self, columns: Optional[List[str]] = None):
        self._select_cols = ", ".join(columns) if columns else "*"
        return self

    def where(self, clause: str, params: Optional[Tuple] = None):
        self._where = clause
        self._params = params or ()
        return self

    def order_by(self, expr: str):
        self._order = expr
        return self

    def limit(self, n: int):
        self._limit = int(n)
        return self

    def join(self, join_sql: str):
        """
        Add a raw JOIN clause like:
            'INNER JOIN other ON main.id = other.main_id'
        or
            'LEFT JOIN other ON ...'
        Use this if you want joins. This builder is intentionally simple.
        """
        self._joins.append(join_sql)
        return self

    # materialize
    def _build_sql(self) -> Tuple[str, Tuple]:
        sql = f"SELECT {self._select_cols} FROM {self.name}"
        if self._joins:
            sql += " " + " ".join(self._joins)
        if self._where:
            sql += f" WHERE {self._where}"
        if self._order:
            sql += f" ORDER BY {self._order}"
        if self._limit is not None:
            sql += f" LIMIT {self._limit}"
        return sql, self._params

    def all(self) -> List[Dict[str, Any]]:
        sql, params = self._build_sql()
        return self.db.query(sql, params)

    def one(self) -> Optional[Dict[str, Any]]:
        prev_limit = self._limit
        self._limit = 1
        sql, params = self._build_sql()
        rows = self.db.query(sql, params)
        self._limit = prev_limit
        return rows[0] if rows else None

    def count(self, where: Optional[str]=None, params: Optional[Tuple]=None) -> int:
        w = where or self._where
        p = params or self._params
        sql = f"SELECT COUNT(*) as cnt FROM {self.name}"
        if w: sql += f" WHERE {w}"
        row = self.db.fetchone(sql, p)
        return int(row["cnt"]) if row else 0

    def insert(self, values: Dict[str, Any]) -> int:
        cols = ", ".join(values.keys())
        placeholders = ", ".join(["?"] * len(values))
        sql = f"INSERT INTO {self.name} ({cols}) VALUES ({placeholders})"
        cur = self.db.execute(sql, tuple(values.values()))
        return getattr(cur, "lastrowid", 0)

    def insert_many(self, cols: List[str], rows: List[Tuple]):
        placeholders = ", ".join(["?"] * len(cols))
        sql = f"INSERT INTO {self.name} ({', '.join(cols)}) VALUES ({placeholders})"
        self.db.executemany(sql, rows)

    def update(self, values: Dict[str, Any], where: Optional[str]=None, params: Optional[Tuple]=None):
        set_clause = ", ".join(f"{k}=?" for k in values.keys())
        sql = f"UPDATE {self.name} SET {set_clause}"
        if where:
            sql += f" WHERE {where}"
        all_params = tuple(values.values()) + tuple(params or ())
        cur = self.db.execute(sql, all_params)
        return getattr(cur, "rowcount", -1)

    def delete(self, where: Optional[str]=None, params: Optional[Tuple]=None):
        sql = f"DELETE FROM {self.name}"
        if where:
            sql += f" WHERE {where}"
        cur = self.db.execute(sql, params or ())
        return getattr(cur, "rowcount", -1)

    def drop(self):
        self.db.drop_table(self.name)

# ---------------------------
# Expose default SQL instance and factory
# ---------------------------
# default SQL instance points to the plain DB path (not secure blob store!)
sql = SQLDatabase(_DEFAULT_DB_PATH)

def open_sql(path: str = _DEFAULT_DB_PATH, *, timeout: float = 5.0) -> SQLDatabase:
    """
    Factory for SQLDatabase if you want a separate connection to any SQLite file.
    """
    return SQLDatabase(path, timeout=timeout)

# ---------------------------
# Hide helpers (preview/export/reveal)
# ---------------------------
class _Hide:
    def __init__(self, getter):
        self._get = getter
    @property
    def database(self):
        return type("X", (), {"db": self._get()})()
    def preview(self, limit:int=10):
        inst = self._get()
        return inst.preview(limit)
    def export(self, dest: str):
        inst = self._get()
        return inst.export(dest)
    def reveal(self, open_folder: bool = True):
        path = self._get().file()
        if not path: raise FileNotFoundError("No path available")
        if not os.path.exists(path): raise FileNotFoundError(f"Path not found: {path!r}")
        try:
            if sys.platform.startswith("win"):
                target = os.path.dirname(path) if open_folder else path
                os.startfile(target); return
            if sys.platform == "darwin":
                target = os.path.dirname(path) if open_folder else path
                subprocess.call(["open", target]); return
            target = os.path.dirname(path) if open_folder else path
            subprocess.call(["xdg-open", target]); return
        except Exception:
            print("DB path:", path)

# module-level hide uses the kid-friendly db instance
hide = type("H", (), {})()
object.__setattr__(hide, "database", _Hide(lambda: db).database)
object.__setattr__(hide, "preview", _Hide(lambda: db).preview)
object.__setattr__(hide, "export", _Hide(lambda: db).export)
object.__setattr__(hide, "reveal", _Hide(lambda: db).reveal)

def run_demo_sql():
    """Internal demo showing SQL usage — not run automatically."""
    # create sample table
    database = open_sql(":memory:")
    database.create_table("people", {"id":"INTEGER PRIMARY KEY AUTOINCREMENT", "name":"TEXT", "age":"INTEGER"})
    t = database.table("people")
    t.insert({"name":"Alice","age":30})
    t.insert({"name":"Bob","age":22})
    rows = t.select(columns=["id","name","age"]).all() if hasattr(t,'select') else database.query("SELECT * FROM people")
    print("rows:", rows)
    database.close()
__all__ = ["db", "hide", "sql", "open_sql", "SQLDatabase", "Table"]
