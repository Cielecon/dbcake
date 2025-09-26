# dbcake

`dbcake` — tiny single-file key/value database using `.dbce` files.

Features
- Simple Python API: `dbcake.db.set("k", val)`, `dbcake.db.get("k")`
- Choose storage format: `binary`, `bits01` (ASCII '0'/'1'), `dec` (3-digit per byte), `hex`
- `.dbce` files include a small header to identify them
- Three security levels via `db.pw`:
  - `low` / `normal` — plain storage
  - `high` — encrypted storage (AES-GCM via `cryptography` if installed; stdlib fallback if not)
- Interactive CLI with `create`, `set`, `get`, `preview`, `compact`, `export`, `set-passphrase`, `set-format`, `rotate-key`, etc.
- Interactive passphrase prompts (no echo) for CLI
- Key rotation: re-encrypt the whole DB with a new passphrase/key
- Cross-process file locking (POSIX `fcntl` and Windows `msvcrt`) for safety on Linux/macOS/Windows
- Single-file module — drop `dbcake.py` into your project

> **Security note**: For production encryption, install `cryptography`:
> ```bash
> pip install cryptography
> ```
> The stdlib fallback provides an authenticated XOR-like stream cipher which is educational but not a substitute for vetted crypto libraries.

---

## Quick install

Place `dbcake.py` next to your Python script, or `git clone` the repo and `import dbcake`.

Install `cryptography` (recommended):

```bash
pip install cryptography
```

---

## Basic usage (Python)

```py
import dbcake

# set default DB file and storage format:
dbcake.db.title("mydata.dbce", store_format="binary")  # formats: binary, bits01, dec, hex

# set/get plain values:
dbcake.db.set("username", "armin")
print(dbcake.db.get("username"))

# change storage format:
dbcake.db.set_format("bits01")  # stores record payloads as ASCII '0'/'1' strings like '101000010...'

# enable secure mode:
dbcake.db.set_passphrase("my secret")  # in-memory only; or leave unset and db will use a keyfile
dbcake.db.pw = "high"
dbcake.db.set("secret", {"pin": 1234})
print(dbcake.db.get("secret"))

# rotate key (programmatically)
# rotate to a new passphrase (you must be in high mode and have the current passphrase set)
dbcake.db.rotate_key(new_passphrase="my new passphrase")

# compact to rewrite file and reduce size
dbcake.db.compact()

# close when done
dbcake.db.close()
```

---

## CLI usage

Run `python dbcake.py <command> [args]`:

Examples:

Create file:
```bash
python dbcake.py create mydata.dbce --format dec
```

Set key:
```bash
python dbcake.py set mydata.dbce username armin
```

Get key:
```bash
python dbcake.py get mydata.dbce username
```

Preview:
```bash
python dbcake.py preview mydata.dbce --limit 20
```

Compact:
```bash
python dbcake.py compact mydata.dbce
```

Set passphrase (interactive, no echo):
```bash
python dbcake.py set-passphrase mydata.dbce --interactive
```

Rotate key (interactive):
```bash
python dbcake.py rotate-key mydata.dbce --interactive
```

Switch storage format:
```bash
python dbcake.py set-format mydata.dbce hex
```

Reveal DB in file manager:
```bash
python dbcake.py reveal mydata.dbce
```

---

## Notes & tips

- Use `db.pw = "high"` and `db.set_passphrase(...)` to enable encryption. `set_passphrase` stores the passphrase only in memory — the CLI offers an interactive prompt so you don't have to put passphrases in shell history.
- The `rotate-key` operation requires the ability to decrypt the current data (i.e., you must provide the current passphrase if the in-memory key isn't present). Rotation writes a new file and replaces the old file atomically (best-effort).
- The module uses a coarse-grained file lock for multi-process safety. This works well for small-to-medium apps and scripts; for heavy concurrent workloads use a real DB server.
- For portability and maximum security, install `cryptography` — AES-GCM is used for encryption when available.
- If you choose `bits01` or `dec` formats, the on-disk bytes become ASCII strings (e.g. `10100010...` or `065003...`), which you requested; the API still operates with Python objects.

>[!CAUTION]
>please read LICENSE and ©️ copyright by Cielecon all rights reversed.
