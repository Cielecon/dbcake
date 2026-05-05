![Header](./dbcake.png)

# 🍰 dbcake v1.4.3

*Today, We all always needed to learn DB! But is it too hard duh :(*
  
**BUT WE ARE HERE!**

**Use your easiest DataBase In any time, Everywhere**

[![Python Version](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.4.3-orange.svg)]()

`dbcake` is Python module that requires **zero dependencies** (optional packages for advanced features). Just drop the single file into your project and start using your favorite database now!

___⭐ +200 devices,servers are using DBcake join now!___

## Contacts

- [Features](#-features)
- [Quick Start](#-quick-start)
- [Installation](#-installation)
- [Basic Usage](#-basic-usage)
- [Data Structures](#-data-structures)
  - [Dictionary Manager](#dictionary-manager)
  - [List Manager](#list-manager)
  - [Tuple Manager](#tuple-manager)
  - [Sum Manager](#sum-manager)
- [Storage Options](#-storage-options)
- [Security & Encryption](#-security--encryption)
- [File Operations](#-file-operations)
- [Database Connectors](#-database-connectors)
- [Secrets HTTP Client](#-secrets-http-client)
- [CLI Usage](#-cli-usage)
- [Examples](#-examples)
- [Troubleshooting](#-troubleshooting)
- [License](#-license)

## Features

- **Single File**! Drop `dbcake.py` into any project, no installation needed
- **Multiple Data Types** - Store strings, numbers, lists, tuples, dictionaries, and any Python object
- **Dictionary Manager** - Native dictionary operations with nested access
- **List and Tuple Support** Actually tou can Append, remove, pop, extend like native Python lists
- **Sum Manager** Built-in arithmetic operations like add, subtract, multiply, divide!
- **Multiple Storage Formats** have access on `binary | bits01 | dec | hex`
- **Encryption Modes**: `low | normal | high` AES-GCM when available
- **Two Storage Modes**: Centralized single file or Decentralized per-key files
- **Key Rotation** like Re-encrypt all data with new keys
- **File Locking**! Safe for multi-process access
- **Database Connectors** have Connection with MySQL, SQLite, PostgreSQL, MongoDB, Redis, Prisma
- **Secrets Client** have access HTTP client for remote secrets API
- **CLI Interface**! Full command-line control
- **Data Persistence** Your data survives library updates

## Quick Start

1. **Save `dbcake.py`** into your project folder

2. **Start using it:**

```python
import dbcake

# Simple key-value storage
dbcake.db.set("username", "armin")
print(dbcake.db.get("username"))  # -> "armin"

# Create/open a custom database
mydb = dbcake.open_db("project.dbce")
mydb.set("score", 100)
print(mydb.get("score"))  # -> 100

# List operations
dbcake.db.list['fruits'] = ['apple', 'banana']
dbcake.db.list.append('fruits', 'orange')
print(dbcake.db.list['fruits'])  # -> ['apple', 'banana', 'orange']

# Dictionary operations
dbcake.db.dict['user'] = {'name': 'Armin', 'age': 25}
print(dbcake.db.dict['user']['name'])  # -> 'Armin'
```

## Installation

### Option 1: Direct Download (Recommended)
```bash
# Download the single file in github

# Or just create a new file and copy the code
```

### Option 2: Install Optional Packages
```bash
# For encryption support
pip install cryptography

# For HTTP client
pip install requests

# For async support
pip install aiohttp

# For database connectors
pip install mysql-connector-python  # MySQL
pip install psycopg2-binary         # PostgreSQL
pip install pymongo                  # MongoDB
pip install redis                    # Redis
pip install prisma                   # Prisma
```

## Basic Usage

### Module-level Convenience DB
```python
import dbcake

# Default database (data.dbce)
dbcake.db.set("name", "Alice")
dbcake.db.set("age", 30)
dbcake.db.set("scores", [95, 88, 92])

# Retrieve values
print(dbcake.db.get("name"))    # -> "Alice"
print(dbcake.db.get("age"))     # -> 30
print(dbcake.db.get("scores"))  # -> [95, 88, 92]

# Check existence
if dbcake.db.exists("name"):
    print("Key exists!")

# List all keys
print(dbcake.db.keys())  # -> ['name', 'age', 'scores']

# Delete a key
dbcake.db.delete("age")

# Preview database
dbcake.db.pretty_print_preview(limit=5)
```

### Custom Database Instance
```python
from dbcake import open_db

# Create/open a custom database
db = open_db("mydata.dbce", store_format="binary", dataset="centerilized")

# Use it like the default db
db.set("key", "value")
value = db.get("key")
```

## Data Structures

### Dictionary Manager
Work with dictionaries like native Python objects:

```python
import dbcake

# Create a dictionary
dbcake.db.dict['user'] = {
    'name': 'Armin',
    'age': 25,
    'email': 'armin@example.com',
    'address': {
        'city': 'Tehran',
        'country': 'Iran',
        'zip': '12345'
    }
}

# Access nested values
print(dbcake.db.dict['user']['name'])           # -> 'Armin'
print(dbcake.db.dict['user']['address']['city'])  # -> 'Tehran'

# Update specific fields
dbcake.db.dict['user']['age'] = 26

# Add new fields
dbcake.db.dict['user']['phone'] = '+98 123456789'

# Update multiple fields
dbcake.db.dict['user'].update({'city': 'New York', 'job': 'Developer'})

# Get specific field
email = dbcake.db.dict.get_field('user', 'email')

# Remove a field
removed = dbcake.db.dict.pop('user', 'email')

# Dictionary operations
user = dbcake.db.dict['user']
print(user.keys())     # -> dict_keys(['name', 'age', 'address', 'phone', 'city', 'job'])
print(user.values())   # -> dict_values(['Armin', 26, {...}, '+98 123456789', 'New York', 'Developer'])
print(len(user))       # -> 6
print('name' in user)  # -> True
```

### List Manager
Work with lists intuitively:

```python
import dbcake

# Create a list
dbcake.db.list['fruits'] = ['apple', 'banana', 'orange']
print(dbcake.db.list['fruits'])  # -> ['apple', 'banana', 'orange']

# Append items
dbcake.db.list.append('fruits', 'grape')
dbcake.db.list.append('fruits', 'mango')
print(dbcake.db.list['fruits'])  # -> ['apple', 'banana', 'orange', 'grape', 'mango']

# Extend with multiple items
dbcake.db.list.extend('fruits', ['pineapple', 'kiwi'])

# Insert at specific index
dbcake.db.list.insert('fruits', 2, 'strawberry')

# Remove specific item
dbcake.db.list.remove('fruits', 'banana')

# Pop last item
last = dbcake.db.list.pop('fruits')
print(f"Popped: {last}")

# Get with default (if key doesn't exist)
colors = dbcake.db.list.get('colors', default=['red', 'green', 'blue'])

# Check if key exists in list manager
if 'fruits' in dbcake.db.list:
    print("fruits is a list")

# Clear list
dbcake.db.list.clear('fruits')
```

### Tuple Manager
For immutable sequences:

```python
import dbcake

# Create a tuple
dbcake.db.tuple['coordinates'] = (10, 20, 30)
print(dbcake.db.tuple['coordinates'])  # -> (10, 20, 30)

# Convert list to tuple automatically
dbcake.db.tuple['point'] = [100, 200]  # Stored as (100, 200)

# Count occurrences
count = dbcake.db.tuple.count('coordinates', 20)  # -> 1

# Find index
index = dbcake.db.tuple.index('coordinates', 30)  # -> 2

# Get with default
coords = dbcake.db.tuple.get('missing', default=(0, 0, 0))
```

### Sum Manager
Built-in arithmetic operations:

```python
import dbcake

# Add values
dbcake.db.sum.add('counter', 10)
dbcake.db.sum.add('counter', 5)
dbcake.db.sum.add('counter', 3)
print(dbcake.db.sum.get('counter'))  # -> 18

# Subtract
dbcake.db.sum.subtract('counter', 4)  # -> 14

# Increment/Decrement
dbcake.db.sum.increment('counter')     # -> 15
dbcake.db.sum.decrement('counter', 2)  # -> 13

# Multiply/Divide
dbcake.db.sum.multiply('counter', 3)   # -> 39
dbcake.db.sum.divide('counter', 2)     # -> 19.5

# Reset to zero
dbcake.db.sum.reset('counter')          # -> 0

# Working with lists - min/max/average
dbcake.db.set('scores', [95, 88, 92, 87, 91])
print(f"Min: {dbcake.db.sum.min('scores')}")        # -> 87
print(f"Max: {dbcake.db.sum.max('scores')}")        # -> 95
print(f"Avg: {dbcake.db.sum.average('scores'):.2f}")  # -> 90.6

# Working with dictionaries
dbcake.db.set('grades', {'math': 95, 'physics': 88, 'chemistry': 92})
print(f"Max grade: {dbcake.db.sum.max('grades')}")  # -> 95
```

## Storage Options

### Storage Formats
```python
from dbcake import open_db, StoreFormat

# Available formats
db = open_db("data.dbce", store_format="binary")   # Raw bytes (fastest)
db = open_db("data.dbce", store_format="hex")      # Hex representation
db = open_db("data.dbce", store_format="dec")      # Decimal digits
db = open_db("data.dbce", store_format="bits01")   # ASCII '0'/'1' bits

# Change format at runtime
dbcake.db.set_format("hex")
```

### Storage Modes
```python
from dbcake import open_db, DatasetMode

# Centralized - single append-only file (default)
db = open_db("data.dbce", dataset="centerilized")

# Decentralized - per-key files in .d directory
db = open_db("data.dbce", dataset="decentralized")

# Switch modes at runtime
dbcake.db.centralized()
dbcake.db.decentralized()
```

## Security & Encryption

### Encryption Levels
```python
import dbcake

# Three security levels
dbcake.db.encryption_level = "low"     # Fast, minimal encryption
dbcake.db.encryption_level = "normal"  # Default, balanced
dbcake.db.encryption_level = "high"    # Maximum security (AES-GCM)
```

### Passphrase Protection
```python
# Set a passphrase (derives key with PBKDF2)
dbcake.db.set_passphrase("my secret passphrase")

# Now all data is encrypted
dbcake.db.set("secret", "classified information")
value = dbcake.db.get("secret")  # Automatically decrypted
```

### Keyfile Authentication
```python
# Generate a random keyfile
dbcake.db.encryption.generate_keyfile()

# Load existing keyfile
dbcake.db.encryption.load_keyfile()
```

### Key Rotation
```python
# Rotate to new key (re-encrypts all data)
dbcake.db.set_passphrase("old password")
dbcake.db.rotate_key(new_passphrase="new password")
```

## File Operations

### Secure File Manager
Save and load files with password protection:

```python
import dbcake

# Save data with password
secret_data = {
    'username': 'admin',
    'password': 'supersecret',
    'api_keys': ['key1', 'key2', 'key3']
}
dbcake.db.secure.save("secret.dat", secret_data, password="mypass")

# Load data with password
loaded = dbcake.db.secure.load("secret.dat", password="mypass")
print(loaded['username'])  # -> 'admin'

# Save as JSON
dbcake.db.secure.save_json("config.json", secret_data, password="mypass", indent=2)

# Load JSON
config = dbcake.db.secure.load_json("config.json", password="mypass")

# Save text files
dbcake.db.secure.save_text("message.txt", "Hello World", password="mypass")
text = dbcake.db.secure.load_text("message.txt", password="mypass")
```

## Database Connectors

Connect to various databases with a unified interface:

```python
from dbcake import connector

# SQLite (built-in, no extra install)
with connector.sqlite("mydb.sqlite") as conn:
    conn.execute("CREATE TABLE users (id INT, name TEXT)")
    conn.execute("INSERT INTO users VALUES (?, ?)", (1, "Armin"))
    users = conn.query("SELECT * FROM users")
    for user in users:
        print(user['id'], user['name'])

# MySQL (requires mysql-connector-python)
with connector.mysql(
    host='localhost',
    user='root',
    password='',
    database='test'
) as conn:
    conn.execute("INSERT INTO products (name, price) VALUES (%s, %s)", ('Laptop', 999.99))
    products = conn.query("SELECT * FROM products")

# PostgreSQL (requires psycopg2-binary)
with connector.postgresql(
    host='localhost',
    user='postgres',
    password='postgres',
    database='postgres'
) as conn:
    conn.execute("CREATE TABLE employees (id SERIAL, name VARCHAR(255))")
    conn.execute("INSERT INTO employees (name) VALUES (%s)", ('John',))

# MongoDB (requires pymongo)
with connector.mongodb(
    host='localhost',
    port=27017,
    database='test_db',
    collection='users'
) as conn:
    doc_id = conn.insert({'name': 'Alice', 'age': 30})
    docs = conn.find({'age': 30})

# Redis (requires redis)
with connector.redis(
    host='localhost',
    port=6379,
    db=0
) as conn:
    conn.set('key', 'value')
    value = conn.get('key')

# Prisma (requires prisma)
with connector.prisma(database_url="file:./dev.db") as conn:
    prisma_client = conn.get_client()
    # Use prisma_client for ORM operations
```

## Secrets HTTP Client

### Synchronous Client
```python
from dbcake import Client

# Create client
client = Client("https://secrets.example.com", api_key="your-api-key")

# Set a secret
secret = client.set("db_password", "S3cR3tV@lue", tags=["prod", "database"])
print(f"Secret created: {secret.name}")

# Get a secret (with value revealed)
secret = client.get("db_password", reveal=True)
print(f"Value: {secret.value}")

# Get metadata only
secret = client.get("db_password", reveal=False)
print(f"Created: {secret.created_at}")
print(f"Tags: {secret.tags}")

# Delete a secret
client.delete("db_password")
```

### With Client-Side Encryption
```python
from dbcake import Client
from cryptography.fernet import Fernet

# Generate a Fernet key
key = Fernet.generate_key().decode()

# Create client with encryption
client = Client(
    "https://secrets.example.com",
    api_key="your-api-key",
    fernet_key=key
)

# Value is encrypted before sending
client.set("encrypted_secret", "very-sensitive-data")

# Automatically decrypted when retrieved with reveal=True
secret = client.get("encrypted_secret", reveal=True)
print(secret.value)  # Decrypted value
```

### Async Client
```python
from dbcake import AsyncClient
import asyncio

async def main():
    # Create from environment variables
    client = AsyncClient.from_env()
    
    # Or create manually
    client = AsyncClient(
        "https://secrets.example.com",
        api_key="your-api-key"
    )
    
    # Set secret
    secret = await client.set("api_key", "sk-123456")
    
    # Get secret
    secret = await client.get("api_key", reveal=True)
    print(secret.value)

asyncio.run(main())
```

### Environment Variables
```bash
# Set these in your environment
export DBCAKE_URL="https://secrets.example.com"
export DBCAKE_API_KEY="your-api-key"
export DBCAKE_FERNET_KEY="your-fernet-key"
```

## CLI Usage

### Database Commands
```bash
# Create a new database
python dbcake.py db create mydata.dbce --format binary

# Set a key-value pair
python dbcake.py db set mydata.dbce username '"armin"'

# Get a value
python dbcake.py db get mydata.dbce username

# List all keys
python dbcake.py db keys mydata.dbce

# Preview database contents
python dbcake.py db preview mydata.dbce --limit 10

# Compact database (remove deleted records)
python dbcake.py db compact mydata.dbce

# Set encryption passphrase (interactive)
python dbcake.py db set-passphrase mydata.dbce --interactive

# Rotate encryption key (interactive)
python dbcake.py db rotate-key mydata.dbce --interactive

# Reconfigure database
python dbcake.py db reconfigure mydata.dbce --new-path newdata.dbce --format hex

# Reveal database folder in file manager
python dbcake.py db reveal mydata.dbce
```

### List Operations (CLI)
```bash
# Get a list
python dbcake.py list get mydata.dbce fruits

# Append to list
python dbcake.py list append mydata.dbce fruits '"orange"'

# Remove from list
python dbcake.py list remove mydata.dbce fruits '"apple"'

# Clear list
python dbcake.py list clear mydata.dbce fruits
```

### Secrets Client (CLI)
```bash
# Set a secret
python dbcake.py secret set db_password "secret123" --url http://localhost:8000 --api-key your-key

# Get a secret (reveal value)
python dbcake.py secret get db_password --reveal --url http://localhost:8000 --api-key your-key

# List all secrets
python dbcake.py secret list --url http://localhost:8000 --api-key your-key

# Delete a secret
python dbcake.py secret delete db_password --url http://localhost:8000 --api-key your-key
```

## Examples

### Complete User Management System
```python
import dbcake

# Initialize database
db = dbcake.open_db("users.dbce")

# Store user profiles
db.dict['user:1'] = {
    'name': 'Armin',
    'email': 'armin@example.com',
    'age': 25,
    'preferences': {
        'theme': 'dark',
        'notifications': True
    }
}

db.dict['user:2'] = {
    'name': 'Ali',
    'email': 'ali@example.com',
    'age': 30,
    'preferences': {
        'theme': 'light',
        'notifications': False
    }
}

# Store user roles as list
db.list['roles:1'] = ['admin', 'editor']
db.list['roles:2'] = ['viewer']

# Track all user IDs
db.list['all_users'] = [1, 2]

# Add login counts
db.sum.add('logins:1', 42)
db.sum.add('logins:2', 17)

# Query active users
for user_id in db.list['all_users']:
    user = db.dict[f'user:{user_id}']
    logins = db.sum.get(f'logins:{user_id}')
    roles = db.list.get(f'roles:{user_id}', default=['guest'])
    
    print(f"User: {user['name']}")
    print(f"  Email: {user['email']}")
    print(f"  Logins: {logins}")
    print(f"  Roles: {roles}")

# Update user preferences
db.dict['user:1']['preferences']['theme'] = 'light'

# Add new user
new_id = 3
db.list.append('all_users', new_id)
db.dict[f'user:{new_id}'] = {'name': 'Mahsa', 'email': 'mahsa@example.com', 'age': 28}
db.list[f'roles:{new_id}'] = ['editor']
db.sum.set(f'logins:{new_id}', 0)

# Compact database periodically
db.compact()
```

### Todo List Application
```python
import dbcake
from datetime import datetime

class TodoApp:
    def __init__(self, db_path="todos.dbce"):
        self.db = dbcake.open_db(db_path)
        if not self.db.list.get('todos'):
            self.db.list['todos'] = []
        if not self.db.sum.get('next_id'):
            self.db.sum.set('next_id', 1)
    
    def add_todo(self, task, priority='medium'):
        todo_id = int(self.db.sum.increment('next_id') - 1)
        todo = {
            'id': todo_id,
            'task': task,
            'priority': priority,
            'completed': False,
            'created': datetime.now().isoformat()
        }
        self.db.list.append('todos', todo)
        print(f"Added todo #{todo_id}: {task}")
        return todo_id
    
    def list_todos(self, show_completed=False):
        todos = self.db.list['todos']
        if not show_completed:
            todos = [t for t in todos if not t['completed']]
        
        print(f"\n📋 Todos ({len(todos)}):")
        for todo in todos:
            status = "✅" if todo['completed'] else "⬜"
            print(f"  {status} #{todo['id']}: {todo['task']} ({todo['priority']})")
    
    def complete_todo(self, todo_id):
        todos = self.db.list['todos']
        for todo in todos:
            if todo['id'] == todo_id:
                todo['completed'] = True
                todo['completed_at'] = datetime.now().isoformat()
                self.db.list['todos'] = todos
                print(f"Completed todo #{todo_id}")
                return True
        print(f"Todo #{todo_id} not found")
        return False
    
    def delete_completed(self):
        todos = self.db.list['todos']
        active = [t for t in todos if not t['completed']]
        deleted = len(todos) - len(active)
        self.db.list['todos'] = active
        print(f"Deleted {deleted} completed todos")
        return deleted
    
    def stats(self):
        todos = self.db.list['todos']
        completed = len([t for t in todos if t['completed']])
        total = len(todos)
        
        priorities = {'high': 0, 'medium': 0, 'low': 0}
        for todo in todos:
            if not todo['completed']:
                priorities[todo['priority']] += 1
        
        print(f"\n📊 Statistics:")
        print(f"  Total todos: {total}")
        print(f"  Completed: {completed}")
        print(f"  Active: {total - completed}")
        print(f"  By priority (active):")
        print(f"    🔴 High: {priorities['high']}")
        print(f"    🟡 Medium: {priorities['medium']}")
        print(f"    🟢 Low: {priorities['low']}")

# Usage
app = TodoApp()
app.add_todo("Learn Python", "high")
app.add_todo("Build a project", "medium")
app.add_todo("Write documentation", "low")
app.list_todos()
app.complete_todo(1)
app.stats()
```

### Configuration Manager
```python
import dbcake

class ConfigManager:
    def __init__(self, app_name):
        self.db = dbcake.open_db(f"{app_name}_config.dbce")
        self.app_name = app_name
    
    def get(self, key, default=None):
        return self.db.dict.get_field('config', key, default)
    
    def set(self, key, value):
        self.db.dict.set_field('config', key, value)
    
    def update(self, **kwargs):
        self.db.dict.update('config', **kwargs)
    
    def export(self, filepath, password=None):
        config = self.db.dict['config']
        self.db.secure.save_json(filepath, config, password=password, indent=2)
    
    def import_config(self, filepath, password=None):
        config = self.db.secure.load_json(filepath, password=password)
        self.db.dict['config'] = config

# Usage
config = ConfigManager("myapp")
config.set("theme", "dark")
config.set("language", "en")
config.update(notifications=True, autosave=True, max_items=100)

print(f"Theme: {config.get('theme')}")
print(f"All settings: {config.db.dict['config']}")

# Export with encryption
config.export("config.json.enc", password="secure123")
```

## Troubleshooting

### Common Issues and Solutions

#### 1. **ImportError: No module named 'cryptography'**
```python
# This is fine! dbcake uses a secure fallback
# To install cryptography for better encryption:
pip install cryptography
```

#### 2. **"Failed to connect to secrets server"**
```python
# Make sure your server is running
# For testing, you can use the example server:
from http.server import HTTPServer, BaseHTTPRequestHandler
# (see documentation for complete example)
```

#### 3. **Database file is corrupted**
```python
# dbcake automatically skips corrupted records
# To recover, you can:
db = dbcake.open_db("corrupted.dbce")
db.compact()  # Rewrites only valid records
```

#### 4. **Permission denied when writing files**
```python
# Check file permissions
# Use absolute paths or ensure write access to directory
db = dbcake.open_db("/path/with/write/permissions/data.dbce")
```

#### 5. **KeyError when accessing dictionary**
```python
# Always check if key exists
if 'user' in dbcake.db.dict:
    print(dbcake.db.dict['user']['name'])

# Or use get() with default
name = dbcake.db.dict.get_field('user', 'name', default='Guest')
```

### Debug Mode
```python
import logging
logging.basicConfig(level=logging.DEBUG)
# Now dbcake will show detailed operation logs
```
## 📄 License

MIT License - feel free to use in personal and commercial projects.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## ⭐ Support

If you find dbcake useful, please give it a star on GitHub!

**Happy coding with dbcake!** 
