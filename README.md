# dbcake

**dbcake** — single-file, easy-to-use key/value database + secrets client for learning, quick prototypes, and small projects.

`dbcake.py` is a self-contained Python module that provides:

- Local key/value store in a single append-only `.dbce` file (centralized) **or** per-key files (decentralized).
- Multiple on-disk formats: `binary`, `bits01`, `dec`, `hex`.
- Encryption modes: `low | normal | high`. Uses AES-GCM (via `cryptography`) when available; otherwise a secure stdlib fallback.
- Key rotation, file-locking for multi-process safety, compaction, export, preview, and per-key operations.
- A small HTTP secrets client (`Client` / `AsyncClient`) for talking to a remote secrets API (optional).
- CLI for DB + secrets client and a tiny Tkinter GUI installer for optional packages.
- Single-file distribution — `dbcake.py` — drop into a project and import or call from command line.

---

## Table of contents

- [Quick start](#quick-start)  
- [Installation](#installation)  
- [Basic usage (Python API)](#basic-usage-python-api)  
- [Storage formats & modes](#storage-formats--modes)  
- [Encryption, passphrases & key rotation](#encryption-passphrases--key-rotation)  
- [CLI usage](#cli-usage)  
- [Secrets HTTP client](#secrets-http-client)  
- [Examples: local server (for testing client)](#examples-local-server-for-testing-client)  
- [Security notes](#security-notes)  
- [Troubleshooting](#troubleshooting)  

---

## Quick start

1. Save `dbcake.py` into your project folder.

2. Use the module-level `db` object or create your own database instance:

```python
import dbcake

# simple use (module-level default DB file: data.dbce)
dbcake.db.set("username", "armin")
print(dbcake.db.get("username"))   # -> "armin"

# create/open a custom DB file
mydb = dbcake.open_db("project.dbce", store_format="binary", dataset="centerilized")
mydb.set("score", 100)
print(mydb.get("score"))
```
# Installation

dbcake.py is a single-file module — no installation required beyond having Python.

Optional (recommended) packages:

cryptography — provides AES-GCM & Fernet support (stronger, standard crypto).

tkinter — required only if you want to run the graphical installer.

# Install cryptography:
```bash
python -m pip install cryptography
```
Run the GUI installer (uses tkinter) to install optional packages:
```bash
python dbcake.py --installer
```
# Basic usage (Python API)

Module-level convenience DB
```python
import dbcake

# default DB (data.dbce)
dbcake.db.set("a", 123)
print(dbcake.db.get("a"))           # -> 123

# change file & format
dbcake.db.title("mydata.dbce", store_format="binary")
dbcake.db.set("user", {"name": "alice"})
print(dbcake.db.get("user"))

# switch to decentralized per-key files
dbcake.db.decentralized()
dbcake.db.set("session", {"id": 1})

# list keys
print(dbcake.db.keys())

# preview a few entries
print(dbcake.db.preview(limit=5))
dbcake.db._backend.pretty_print_preview(limit=5)  # helper that prints nice table
```
Factory style (explicit DB object)
```python
mydb = dbcake.open_db("project.dbce", store_format="hex", dataset="centerilized")
mydb.set("k", "v")
v = mydb.get("k")
```
# Storage formats & modes

store_format options when creating or switching DB:

binary — raw bytes (fast).

bits01 — ASCII '0' / '1' bit string.

dec — decimal digits grouped by 3 per byte.

hex — hex representation.

Switch format programmatically:
```python
dbcake.db.set_format("hex")
```
Switch dataset mode:
```python
dbcake.db.centerilized()   # centralized append-only .dbce
dbcake.db.decentralized()  # per-key files in .d directory
```
# Encryption, passphrases & key rotation

db.pw controls on-disk security:

db.pw = "low" — minimal (fast).

db.pw = "normal" — default (no re-encryption).

db.pw = "high" — records encrypted before writing (AES-GCM if cryptography is installed; otherwise a fallback).

Set passphrase (derive key from passphrase):
```python
dbcake.db.pw = "high"
dbcake.db.set_passphrase("my secret passphrase")
dbcake.db.set("secret", "value")
```
Generate/store keyfile (if you do not use passphrase) — DB will generate .key next to the DB file.

Rotate keys (re-encrypt everything):

CLI (interactive):
```bash
python dbcake.py db rotate-key mydata.dbce --interactive
```
**Programmatic:**
```python
dbcake.db.set_passphrase("old")
dbcake.db.rotate_key(new_passphrase="new")
```
rotate_key rewrites the DB and re-encrypts records under the new key.

# CLI usage

The single file exposes a CLI for both local DB and the secrets client.

# Local DB commands
```bash
# create file
python dbcake.py db create mydata.dbce --format binary

# set key
python dbcake.py db set mydata.dbce username '"armin"'

# get key
python dbcake.py db get mydata.dbce username

# list keys
python dbcake.py db keys mydata.dbce

# preview
python dbcake.py db preview mydata.dbce --limit 5

# compact (rewrite to keep only current items)
python dbcake.py db compact mydata.dbce

# set passphrase (interactive)
python dbcake.py db set-passphrase mydata.dbce --interactive

# rotate key (interactive)
python dbcake.py db rotate-key mydata.dbce --interactive

# reveal DB file in OS file manager
python dbcake.py db reveal mydata.dbce
```
CLI values attempt JSON parsing; unparseable input will be stored as raw string.

# Secrets HTTP client (CLI)
```bash
# set secret
python dbcake.py secret set myname "value" --url https://secrets.example.com --api-key S3CR

# get secret (reveal)
python dbcake.py secret get myname --reveal --url https://secrets.example.com --api-key S3CR

# list
python dbcake.py secret list --url https://secrets.example.com --api-key S3CR

# delete
python dbcake.py secret delete myname --url https://secrets.example.com --api-key S3CR
```
# Secrets HTTP client (Python)
```python
from dbcake import Client

client = Client("https://secrets.example.com", api_key="S3CR")
meta = client.set("db_token", "S3cR3tV@lue", tags=["prod","db"])
secret = client.get("db_token", reveal=True)
print(secret.value)

# With Fernet (encrypt locally before send)
from cryptography.fernet import Fernet
fkey = Fernet.generate_key().decode()
client2 = Client("https://secrets.example.com", api_key="S3", fernet_key=fkey)
client2.set("encrypted", "very-secret")
s = client2.get("encrypted", reveal=True)
print(s.value)
```
AsyncClient is available for async code (AsyncClient.from_env() to read env vars).

Env vars for convenience: DBCAKE_URL, DBCAKE_API_KEY, DBCAKE_FERNET_KEY.

Examples: local server (for testing client)

Below is a tiny example (not included in dbcake.py) of a simple HTTP test server you can use to exercise the Client:
```python
# tiny_test_server.py (example only; not production-ready)
from http.server import BaseHTTPRequestHandler, HTTPServer
import json, urllib.parse

STORE = {}

class Handler(BaseHTTPRequestHandler):
    def _send(self, code, data):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_POST(self):
        if self.path == "/secrets":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            doc = json.loads(body.decode("utf-8"))
            name = doc["name"]
            STORE[name] = doc
            now = "2025-10-16T00:00:00Z"
            self._send(201, {"name": name, "created_at": now, "updated_at": now, "tags": doc.get("tags", [])})
            return
        self.send_error(404)

    def do_GET(self):
        if self.path.startswith("/secrets"):
            parsed = urllib.parse.urlparse(self.path)
            parts = parsed.path.split("/")
            if len(parts) == 3 and parts[2]:
                name = parts[2]
                item = STORE.get(name)
                if not item:
                    self.send_error(404)
                    return
                reveal = urllib.parse.parse_qs(parsed.query).get("reveal", [])
                doc = item.copy()
                self._send(200, doc)
                return
        self.send_error(404)

    def do_DELETE(self):
        parts = self.path.split("/")
        if len(parts) == 3 and parts[2]:
            name = parts[2]
            if name in STORE:
                del STORE[name]
                self._send(204, {})
                return
        self.send_error(404)

if __name__ == '__main__':
    server = HTTPServer(("localhost", 8000), Handler)
    print("Listening on http://localhost:8000")
    server.serve_forever()
```
# Security notes

If you use db.set_passphrase("..."), a salt file (.salt) is created and used to derive an encryption key. Keep passphrases secret.

If you don't set a passphrase, the DB generates a .key keyfile next to the DB. Keep that file safe.

Use TLS for server communication (HTTPS) and protect API keys.

rotate_key rewrites and re-encrypts stored data — use it regularly for long-lived data.

This project is intended for learning and small projects. For production secrets management, consider hardened solutions (HashiCorp Vault, AWS KMS/Secrets Manager, etc.).
# Troubleshooting

cryptography not installed — AES-GCM and Fernet features disabled; library will use a secure fallback. Install cryptography if you need standard AES-GCM/Fernet.

tkinter missing — GUI installer will not run. Install system package (e.g., python3-tk) or use pip-installed packages via CLI.

Lock timeouts — another process may hold the DB. Wait or increase timeout; ensure only compatible writers access the DB.

Permission errors — ensure the process can write to DB folder and key/salt files.
>[!CAUTION]
>please read LICENSE and ©️ copyright by Cielecon all rights reversed.
