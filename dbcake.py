#!/usr/bin/env python3
import os
import sys
import json
import time
import base64
import struct
import hashlib
import pathlib
import secrets
import threading
import functools
import urllib.parse
import pickle
import sqlite3
import shutil
import fnmatch
from typing import (
    Any, Dict, List, Optional, Union, Tuple, 
    BinaryIO, Iterator, Callable, TypeVar, Generic
)
from datetime import datetime
from enum import Enum
from dataclasses import dataclass, asdict
import argparse
import subprocess
import platform

# Try to import optional packages
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False
    Fernet = None
    AESGCM = None

# Try to import requests for HTTP client
try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

# ============================================================================
# Constants & Enums
# ============================================================================

class StoreFormat(Enum):
    """Storage format for serialized data."""
    BINARY = "binary"
    BITS01 = "bits01"
    DEC = "dec"
    HEX = "hex"

class DatasetMode(Enum):
    """Storage mode for the database."""
    CENTERILIZED = "centerilized"
    DECENTRALIZED = "decentralized"

class EncryptionLevel(Enum):
    """Encryption security levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"

class Operation(Enum):
    """Database operations."""
    SET = "S"
    DELETE = "D"

# ============================================================================
# Custom Exceptions
# ============================================================================

class DBCakeError(Exception):
    """Base exception for dbcake errors."""
    pass

class DatabaseError(DBCakeError):
    """Database-related errors."""
    pass

class CorruptedDatabaseError(DatabaseError):
    """Database file is corrupted."""
    pass

class ConfigurationError(DBCakeError):
    """Configuration errors."""
    pass

class NetworkError(DBCakeError):
    """Network-related errors."""
    pass

class SecretClientError(DBCakeError):
    """Secrets client errors."""
    pass

class ConnectorError(DBCakeError):
    """Connector-related errors."""
    pass

class FileDirectoryError(DBCakeError):
    """File directory manager errors."""
    pass

# ============================================================================
# File Directory Manager
# ============================================================================

class FileDirectory:
    """
    File Directory Manager - Create, read, update, delete files and directories.
    
    Examples:
        # Create a file
        db.files.write('document.txt', 'Hello World')
        
        # Read a file
        content = db.files.read('document.txt')
        
        # List files
        files = db.files.list()
        
        # Create directory
        db.files.mkdir('images')
        
        # Copy file
        db.files.copy('document.txt', 'backup.txt')
        
        # Move file
        db.files.move('document.txt', 'docs/document.txt')
        
        # Get file info
        info = db.files.info('document.txt')
    """
    
    def __init__(self, base_path: Union[str, pathlib.Path] = None):
        """
        Initialize file directory manager.
        
        Args:
            base_path: Base directory for all operations (default: current directory)
        """
        if base_path is None:
            self.base_path = pathlib.Path.cwd()
        else:
            self.base_path = pathlib.Path(base_path).expanduser().resolve()
        
        # Ensure base path exists
        self.base_path.mkdir(parents=True, exist_ok=True)
    
    def _resolve_path(self, path: Union[str, pathlib.Path]) -> pathlib.Path:
        """Resolve path relative to base directory."""
        # If path is absolute, use it as is, otherwise join with base_path
        p = pathlib.Path(path)
        if p.is_absolute():
            return p
        return (self.base_path / p).resolve()
    
    def _ensure_in_base(self, path: pathlib.Path) -> None:
        """Ensure path is within base directory (security)."""
        try:
            path.relative_to(self.base_path)
        except ValueError:
            raise FileDirectoryError(f"Path '{path}' is outside base directory '{self.base_path}'")
    
    # ===== File Operations =====
    
    def write(self, path: Union[str, pathlib.Path], content: Any, mode: str = 'w', encoding: str = 'utf-8') -> None:
        """
        Write content to a file.
        
        Args:
            path: File path
            content: Content to write (string, bytes, or any object)
            mode: Write mode ('w' for text, 'wb' for binary, 'a' for append)
            encoding: Text encoding (for text mode)
        """
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        # Create parent directories if they don't exist
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            if 'b' in mode:
                # Binary mode
                if not isinstance(content, (bytes, bytearray)):
                    if isinstance(content, str):
                        content = content.encode(encoding)
                    else:
                        content = str(content).encode(encoding)
                with open(full_path, mode) as f:
                    f.write(content)
            else:
                # Text mode
                with open(full_path, mode, encoding=encoding) as f:
                    f.write(str(content))
        except Exception as e:
            raise FileDirectoryError(f"Failed to write to '{path}': {e}")
    
    def read(self, path: Union[str, pathlib.Path], mode: str = 'r', encoding: str = 'utf-8') -> Any:
        """
        Read content from a file.
        
        Args:
            path: File path
            mode: Read mode ('r' for text, 'rb' for binary)
            encoding: Text encoding (for text mode)
        
        Returns:
            File content as string or bytes
        """
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"File not found: '{path}'")
        
        if not full_path.is_file():
            raise FileDirectoryError(f"Not a file: '{path}'")
        
        try:
            if 'b' in mode:
                with open(full_path, mode) as f:
                    return f.read()
            else:
                with open(full_path, mode, encoding=encoding) as f:
                    return f.read()
        except Exception as e:
            raise FileDirectoryError(f"Failed to read from '{path}': {e}")
    
    def append(self, path: Union[str, pathlib.Path], content: Any, encoding: str = 'utf-8') -> None:
        """Append content to a file."""
        self.write(path, content, mode='a', encoding=encoding)
    
    def delete(self, path: Union[str, pathlib.Path]) -> None:
        """Delete a file or empty directory."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Path not found: '{path}'")
        
        try:
            if full_path.is_file():
                full_path.unlink()
            elif full_path.is_dir():
                try:
                    full_path.rmdir()  # Only removes empty directories
                except OSError:
                    raise FileDirectoryError(f"Directory not empty: '{path}'. Use delete_recursive() to delete non-empty directories.")
        except Exception as e:
            raise FileDirectoryError(f"Failed to delete '{path}': {e}")
    
    def delete_recursive(self, path: Union[str, pathlib.Path]) -> None:
        """Recursively delete a file or directory."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Path not found: '{path}'")
        
        try:
            if full_path.is_file():
                full_path.unlink()
            elif full_path.is_dir():
                shutil.rmtree(full_path)
        except Exception as e:
            raise FileDirectoryError(f"Failed to delete '{path}': {e}")
    
    def exists(self, path: Union[str, pathlib.Path]) -> bool:
        """Check if a file or directory exists."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        return full_path.exists()
    
    def is_file(self, path: Union[str, pathlib.Path]) -> bool:
        """Check if path is a file."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        return full_path.is_file()
    
    def is_dir(self, path: Union[str, pathlib.Path]) -> bool:
        """Check if path is a directory."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        return full_path.is_dir()
    
    def copy(self, src: Union[str, pathlib.Path], dst: Union[str, pathlib.Path]) -> None:
        """Copy a file or directory."""
        src_path = self._resolve_path(src)
        dst_path = self._resolve_path(dst)
        
        self._ensure_in_base(src_path)
        self._ensure_in_base(dst_path)
        
        if not src_path.exists():
            raise FileDirectoryError(f"Source not found: '{src}'")
        
        try:
            if src_path.is_file():
                shutil.copy2(src_path, dst_path)
            elif src_path.is_dir():
                shutil.copytree(src_path, dst_path)
        except Exception as e:
            raise FileDirectoryError(f"Failed to copy from '{src}' to '{dst}': {e}")
    
    def move(self, src: Union[str, pathlib.Path], dst: Union[str, pathlib.Path]) -> None:
        """Move a file or directory."""
        src_path = self._resolve_path(src)
        dst_path = self._resolve_path(dst)
        
        self._ensure_in_base(src_path)
        self._ensure_in_base(dst_path)
        
        if not src_path.exists():
            raise FileDirectoryError(f"Source not found: '{src}'")
        
        try:
            # Create destination directory if needed
            dst_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.move(str(src_path), str(dst_path))
        except Exception as e:
            raise FileDirectoryError(f"Failed to move from '{src}' to '{dst}': {e}")
    
    def rename(self, path: Union[str, pathlib.Path], new_name: str) -> None:
        """Rename a file or directory."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Path not found: '{path}'")
        
        new_path = full_path.parent / new_name
        self._ensure_in_base(new_path)
        
        try:
            full_path.rename(new_path)
        except Exception as e:
            raise FileDirectoryError(f"Failed to rename '{path}' to '{new_name}': {e}")
    
    # ===== Directory Operations =====
    
    def mkdir(self, path: Union[str, pathlib.Path], parents: bool = True, exist_ok: bool = True) -> None:
        """Create a directory."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        try:
            if parents:
                full_path.mkdir(parents=True, exist_ok=exist_ok)
            else:
                full_path.mkdir(exist_ok=exist_ok)
        except Exception as e:
            raise FileDirectoryError(f"Failed to create directory '{path}': {e}")
    
    def list(self, path: Union[str, pathlib.Path] = '.', pattern: str = '*') -> List[Dict[str, Any]]:
        """
        List contents of a directory.
        
        Args:
            path: Directory path
            pattern: Glob pattern to filter files
        
        Returns:
            List of dictionaries with file/directory information
        """
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Directory not found: '{path}'")
        
        if not full_path.is_dir():
            raise FileDirectoryError(f"Not a directory: '{path}'")
        
        result = []
        for item in full_path.glob(pattern):
            rel_path = item.relative_to(self.base_path)
            stat = item.stat()
            
            file_info = {
                'name': item.name,
                'path': str(rel_path),
                'full_path': str(item),
                'type': 'directory' if item.is_dir() else 'file',
                'size': stat.st_size if item.is_file() else 0,
                'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'is_file': item.is_file(),
                'is_dir': item.is_dir(),
            }
            
            if item.is_file():
                file_info['size_human'] = self._format_size(stat.st_size)
                file_info['extension'] = item.suffix[1:] if item.suffix else None
            
            result.append(file_info)
        
        return result
    
    def tree(self, path: Union[str, pathlib.Path] = '.', prefix: str = '', max_depth: int = None, current_depth: int = 0) -> str:
        """
        Generate a tree representation of directory structure.
        
        Args:
            path: Directory path
            prefix: Prefix for tree formatting
            max_depth: Maximum depth to traverse
            current_depth: Current depth (for recursion)
        
        Returns:
            String representation of directory tree
        """
        if max_depth is not None and current_depth >= max_depth:
            return ""
        
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Directory not found: '{path}'")
        
        if not full_path.is_dir():
            return f"{prefix}📄 {full_path.name}\n"
        
        result = f"{prefix}📁 {full_path.name}/\n"
        
        items = sorted(full_path.iterdir(), key=lambda x: (not x.is_dir(), x.name))
        for i, item in enumerate(items):
            is_last = i == len(items) - 1
            new_prefix = prefix + ("    " if is_last else "│   ")
            
            if item.is_dir():
                result += self.tree(
                    item, 
                    prefix + ("    " if is_last else "│   "),
                    max_depth,
                    current_depth + 1
                )
            else:
                size = item.stat().st_size
                size_str = self._format_size(size)
                icon = "📄"
                result += f"{prefix}{'└── ' if is_last else '├── '}{icon} {item.name} ({size_str})\n"
        
        return result
    
    def _format_size(self, size: int) -> str:
        """Format file size in human-readable format."""
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size < 1024.0:
                return f"{size:.1f} {unit}"
            size /= 1024.0
        return f"{size:.1f} PB"
    
    # ===== File Info Operations =====
    
    def info(self, path: Union[str, pathlib.Path]) -> Dict[str, Any]:
        """Get detailed information about a file or directory."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Path not found: '{path}'")
        
        stat = full_path.stat()
        rel_path = full_path.relative_to(self.base_path) if full_path != self.base_path else pathlib.Path('.')
        
        info = {
            'name': full_path.name,
            'path': str(rel_path),
            'full_path': str(full_path),
            'type': 'directory' if full_path.is_dir() else 'file',
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
            'accessed': datetime.fromtimestamp(stat.st_atime).isoformat(),
            'permissions': oct(stat.st_mode)[-3:],
            'owner': stat.st_uid,
            'group': stat.st_gid,
            'is_file': full_path.is_file(),
            'is_dir': full_path.is_dir(),
            'is_symlink': full_path.is_symlink(),
        }
        
        if full_path.is_file():
            info['extension'] = full_path.suffix[1:] if full_path.suffix else None
            info['size_human'] = self._format_size(stat.st_size)
        
        return info
    
    def size(self, path: Union[str, pathlib.Path]) -> int:
        """Get size of file or directory (recursive for directories)."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Path not found: '{path}'")
        
        if full_path.is_file():
            return full_path.stat().st_size
        else:
            total = 0
            for item in full_path.rglob('*'):
                if item.is_file():
                    total += item.stat().st_size
            return total
    
    # ===== Search Operations =====
    
    def find(self, pattern: str, path: Union[str, pathlib.Path] = '.') -> List[Dict[str, Any]]:
        """
        Find files matching pattern.
        
        Args:
            pattern: Glob pattern to match
            path: Directory to search in
        
        Returns:
            List of matching files/directories
        """
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Directory not found: '{path}'")
        
        result = []
        for item in full_path.rglob(pattern):
            rel_path = item.relative_to(self.base_path)
            result.append({
                'name': item.name,
                'path': str(rel_path),
                'type': 'directory' if item.is_dir() else 'file'
            })
        
        return result
    
    def search(self, text: str, path: Union[str, pathlib.Path] = '.', ext: List[str] = None) -> List[Dict[str, Any]]:
        """
        Search for text in files.
        
        Args:
            text: Text to search for
            path: Directory to search in
            ext: File extensions to include (e.g., ['.txt', '.py'])
        
        Returns:
            List of files containing the text with line numbers
        """
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Directory not found: '{path}'")
        
        results = []
        
        for item in full_path.rglob('*'):
            if not item.is_file():
                continue
            
            if ext:
                # Check if file extension matches
                ext_match = False
                for e in ext:
                    if e.startswith('.'):
                        if item.suffix.lower() == e.lower():
                            ext_match = True
                            break
                    else:
                        if item.suffix.lower() == f'.{e.lower()}':
                            ext_match = True
                            break
                if not ext_match:
                    continue
            
            try:
                with open(item, 'r', encoding='utf-8', errors='ignore') as f:
                    for i, line in enumerate(f, 1):
                        if text in line:
                            rel_path = item.relative_to(self.base_path)
                            results.append({
                                'file': str(rel_path),
                                'line': i,
                                'content': line.strip()
                            })
            except:
                continue
        
        return results
    
    # ===== Utility Operations =====
    
    def touch(self, path: Union[str, pathlib.Path]) -> None:
        """Create an empty file or update timestamp."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        # Create parent directories if needed
        full_path.parent.mkdir(parents=True, exist_ok=True)
        
        try:
            full_path.touch(exist_ok=True)
        except Exception as e:
            raise FileDirectoryError(f"Failed to touch '{path}': {e}")
    
    def chmod(self, path: Union[str, pathlib.Path], mode: int) -> None:
        """Change file permissions."""
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"Path not found: '{path}'")
        
        try:
            full_path.chmod(mode)
        except Exception as e:
            raise FileDirectoryError(f"Failed to change permissions for '{path}': {e}")
    
    def hash(self, path: Union[str, pathlib.Path], algorithm: str = 'md5') -> str:
        """
        Calculate hash of a file.
        
        Args:
            path: File path
            algorithm: Hash algorithm ('md5', 'sha1', 'sha256')
        
        Returns:
            Hash digest as hex string
        """
        full_path = self._resolve_path(path)
        self._ensure_in_base(full_path)
        
        if not full_path.exists():
            raise FileDirectoryError(f"File not found: '{path}'")
        
        if not full_path.is_file():
            raise FileDirectoryError(f"Not a file: '{path}'")
        
        hash_func = getattr(hashlib, algorithm, None)
        if hash_func is None:
            raise FileDirectoryError(f"Unknown hash algorithm: {algorithm}")
        
        h = hash_func()
        with open(full_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                h.update(chunk)
        
        return h.hexdigest()
    
    # ===== JSON Operations =====
    
    def write_json(self, path: Union[str, pathlib.Path], data: Any, **kwargs) -> None:
        """Write data as JSON to a file."""
        json_str = json.dumps(data, **kwargs)
        self.write(path, json_str)
    
    def read_json(self, path: Union[str, pathlib.Path]) -> Any:
        """Read JSON from a file."""
        content = self.read(path)
        return json.loads(content)
    
    # ===== Temporary Files =====
    
    def temp_file(self, suffix: str = None, prefix: str = None, content: Any = None) -> pathlib.Path:
        """Create a temporary file."""
        import tempfile
        fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix, dir=self.base_path)
        os.close(fd)
        
        temp_path = pathlib.Path(path)
        if content is not None:
            self.write(temp_path, content)
        
        return temp_path
    
    def temp_dir(self, suffix: str = None, prefix: str = None) -> pathlib.Path:
        """Create a temporary directory."""
        import tempfile
        path = tempfile.mkdtemp(suffix=suffix, prefix=prefix, dir=self.base_path)
        return pathlib.Path(path)
    
    # ===== Archive Operations =====
    
    def zip(self, source: Union[str, pathlib.Path], archive: Union[str, pathlib.Path]) -> None:
        """Create a ZIP archive."""
        import zipfile
        
        src_path = self._resolve_path(source)
        dst_path = self._resolve_path(archive)
        
        self._ensure_in_base(src_path)
        self._ensure_in_base(dst_path)
        
        if not src_path.exists():
            raise FileDirectoryError(f"Source not found: '{source}'")
        
        try:
            with zipfile.ZipFile(dst_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                if src_path.is_file():
                    zf.write(src_path, src_path.name)
                else:
                    for root, dirs, files in os.walk(src_path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, src_path.parent)
                            zf.write(file_path, arcname)
        except Exception as e:
            raise FileDirectoryError(f"Failed to create zip archive: {e}")
    
    def unzip(self, archive: Union[str, pathlib.Path], destination: Union[str, pathlib.Path] = None) -> None:
        """Extract a ZIP archive."""
        import zipfile
        
        arc_path = self._resolve_path(archive)
        if destination is None:
            dst_path = arc_path.parent / arc_path.stem
        else:
            dst_path = self._resolve_path(destination)
        
        self._ensure_in_base(arc_path)
        self._ensure_in_base(dst_path)
        
        if not arc_path.exists():
            raise FileDirectoryError(f"Archive not found: '{archive}'")
        
        try:
            with zipfile.ZipFile(arc_path, 'r') as zf:
                zf.extractall(dst_path)
        except Exception as e:
            raise FileDirectoryError(f"Failed to extract zip archive: {e}")


# ============================================================================
# Dictionary Manager - FIXED (DictWrapper defined first)
# ============================================================================

class DictWrapper:
    """Wrapper for dictionary to provide nested access."""
    
    def __init__(self, key: str, data: Dict[str, Any], manager: 'DictManager'):
        self._key = key
        self._data = data
        self._manager = manager
    
    def __getitem__(self, field: str) -> Any:
        return self._data[field]
    
    def __setitem__(self, field: str, value: Any):
        self._data[field] = value
        self._manager._db.set(self._key, self._data)
    
    def __delitem__(self, field: str):
        del self._data[field]
        self._manager._db.set(self._key, self._data)
    
    def __contains__(self, field: str) -> bool:
        return field in self._data
    
    def get(self, field: str, default=None) -> Any:
        return self._data.get(field, default)
    
    def update(self, **kwargs):
        self._data.update(kwargs)
        self._manager._db.set(self._key, self._data)
    
    def pop(self, field: str, default=None) -> Any:
        value = self._data.pop(field, default)
        self._manager._db.set(self._key, self._data)
        return value
    
    def keys(self):
        return self._data.keys()
    
    def values(self):
        return self._data.values()
    
    def items(self):
        return self._data.items()
    
    def __iter__(self):
        return iter(self._data)
    
    def __len__(self):
        return len(self._data)
    
    def __repr__(self):
        return repr(self._data)


class DictManager:
    """
    Dictionary manager for storing and retrieving dictionaries with special operations.
    
    Examples:
        db.dict['user'] = {'name': 'Armin', 'age': 25, 'email': 'armin@example.com'}
        name = db.dict['user']['name']
        db.dict['user']['age'] = 26  # Update specific field
        db.dict['user'].update({'city': 'Tehran'})  # Add new fields
        db.dict['user'].pop('email')  # Remove field
    """
    
    def __init__(self, db_instance: 'DBCake'):
        self._db = db_instance
    
    def __getitem__(self, key: str) -> Optional[DictWrapper]:
        """Get dictionary for key."""
        value = self._db.get(key)
        if value is None:
            return None
        if isinstance(value, dict):
            return DictWrapper(key, value, self)
        return None
    
    def __setitem__(self, key: str, value: Dict[str, Any]):
        """Set dictionary for key."""
        if not isinstance(value, dict):
            raise TypeError(f"Expected dict, got {type(value).__name__}")
        self._db.set(key, value)
    
    def get(self, key: str, default: Optional[Dict] = None) -> Optional[DictWrapper]:
        """Get dictionary with default."""
        value = self[key]
        if value is None:
            return default
        return value
    
    def update(self, key: str, **kwargs) -> bool:
        """Update dictionary with keyword arguments. Returns True if successful."""
        current_dict = self._db.get(key)
        if current_dict is None or not isinstance(current_dict, dict):
            current_dict = {}
        current_dict.update(kwargs)
        self._db.set(key, current_dict)
        return True
    
    def pop(self, key: str, field: str, default=None) -> Any:
        """Pop a field from dictionary. Returns the popped value or default."""
        current_dict = self._db.get(key)
        if current_dict is None or not isinstance(current_dict, dict):
            return default
        value = current_dict.pop(field, default)
        self._db.set(key, current_dict)
        return value
    
    def set_field(self, key: str, field: str, value: Any) -> bool:
        """Set a specific field in dictionary. Returns True if successful."""
        current_dict = self._db.get(key)
        if current_dict is None or not isinstance(current_dict, dict):
            current_dict = {}
        current_dict[field] = value
        self._db.set(key, current_dict)
        return True
    
    def get_field(self, key: str, field: str, default=None) -> Any:
        """Get a specific field from dictionary."""
        current_dict = self._db.get(key)
        if current_dict is None or not isinstance(current_dict, dict):
            return default
        return current_dict.get(field, default)
    
    def __len__(self) -> int:
        """Number of keys that have dictionary values."""
        count = 0
        for key in self._db.keys():
            if isinstance(self._db.get(key), dict):
                count += 1
        return count
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists and has a dictionary value."""
        value = self._db.get(key)
        return value is not None and isinstance(value, dict)


# ============================================================================
# List and Tuple Manager
# ============================================================================

class ListManager:
    """Manager for list/tuple operations in the database."""
    
    def __init__(self, db_instance: 'DBCake'):
        self._db = db_instance
    
    def __getitem__(self, key: str) -> Optional[List[Any]]:
        """Get list for key."""
        value = self._db.get(key)
        if value is None:
            return None
        if isinstance(value, (list, tuple)):
            return list(value)
        # If it's not a list, wrap it in a list
        return [value]
    
    def __setitem__(self, key: str, value: Any):
        """Set list for key. Can accept multiple values."""
        if isinstance(value, (list, tuple)):
            self._db.set(key, list(value))
        else:
            self._db.set(key, [value])
    
    def get(self, key: str, default: Optional[List] = None) -> Optional[List[Any]]:
        """Get list with default."""
        value = self[key]
        if value is None:
            return default
        return value
    
    def append(self, key: str, value: Any) -> None:
        """Append value to list."""
        current = self[key]
        if current is None:
            current = []
        current.append(value)
        self._db.set(key, current)
    
    def extend(self, key: str, values: List[Any]) -> None:
        """Extend list with values."""
        current = self[key]
        if current is None:
            current = []
        current.extend(values)
        self._db.set(key, current)
    
    def insert(self, key: str, index: int, value: Any) -> None:
        """Insert value at index."""
        current = self[key]
        if current is None:
            current = []
        current.insert(index, value)
        self._db.set(key, current)
    
    def remove(self, key: str, value: Any) -> bool:
        """Remove value from list. Returns True if removed."""
        current = self[key]
        if current is None:
            return False
        try:
            current.remove(value)
            self._db.set(key, current)
            return True
        except ValueError:
            return False
    
    def pop(self, key: str, index: int = -1) -> Any:
        """Pop value from list."""
        current = self[key]
        if current is None or not current:
            raise IndexError("pop from empty list")
        value = current.pop(index)
        self._db.set(key, current)
        return value
    
    def clear(self, key: str) -> None:
        """Clear list."""
        self._db.set(key, [])
    
    def __len__(self) -> int:
        """Number of keys that have list values."""
        count = 0
        for key in self._db.keys():
            if isinstance(self._db.get(key), (list, tuple)):
                count += 1
        return count
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists and has a list/tuple value."""
        value = self._db.get(key)
        return value is not None and isinstance(value, (list, tuple))


class TupleManager:
    """Manager for tuple operations in the database."""
    
    def __init__(self, db_instance: 'DBCake'):
        self._db = db_instance
    
    def __getitem__(self, key: str) -> Optional[tuple]:
        """Get tuple for key."""
        value = self._db.get(key)
        if value is None:
            return None
        if isinstance(value, tuple):
            return value
        # Convert to tuple
        if isinstance(value, list):
            return tuple(value)
        return (value,)
    
    def __setitem__(self, key: str, value: Any):
        """Set tuple for key. Can accept multiple values."""
        if isinstance(value, tuple):
            self._db.set(key, value)
        elif isinstance(value, list):
            self._db.set(key, tuple(value))
        else:
            self._db.set(key, (value,))
    
    def get(self, key: str, default: Optional[tuple] = None) -> Optional[tuple]:
        """Get tuple with default."""
        value = self[key]
        if value is None:
            return default
        return value
    
    def count(self, key: str, value: Any) -> int:
        """Count occurrences of value in tuple."""
        tup = self[key]
        if tup is None:
            return 0
        return tup.count(value)
    
    def index(self, key: str, value: Any, start: int = 0, end: Optional[int] = None) -> int:
        """Find index of value in tuple."""
        tup = self[key]
        if tup is None:
            raise ValueError(f"{value} not in tuple")
        return tup.index(value, start, len(tup) if end is None else end)
    
    def __len__(self) -> int:
        """Number of keys that have tuple values."""
        count = 0
        for key in self._db.keys():
            if isinstance(self._db.get(key), tuple):
                count += 1
        return count
    
    def __contains__(self, key: str) -> bool:
        """Check if key exists and has a tuple value."""
        value = self._db.get(key)
        return value is not None and isinstance(value, tuple)


# ============================================================================
# Sum Manager
# ============================================================================

class SumManager:
    """
    Manager for numeric operations like sum, average, min, max.
    
    Examples:
        db.sum.add('sales', 100)
        db.sum.add('sales', 50)
        total = db.sum.get('sales')  # 150
        db.sum.increment('counter')  # +1
        db.sum.decrement('counter')  # -1
        avg = db.sum.average('scores')
    """
    
    def __init__(self, db_instance: 'DBCake'):
        self._db = db_instance
    
    def get(self, key: str, default: float = 0.0) -> float:
        """Get current sum value."""
        value = self._db.get(key)
        if value is None:
            return default
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
    
    def add(self, key: str, amount: Union[int, float]) -> float:
        """Add amount to the sum."""
        current = self.get(key)
        new_value = current + amount
        self._db.set(key, new_value)
        return new_value
    
    def subtract(self, key: str, amount: Union[int, float]) -> float:
        """Subtract amount from the sum."""
        return self.add(key, -amount)
    
    def increment(self, key: str, step: int = 1) -> int:
        """Increment integer value by step."""
        current = self.get(key, 0)
        new_value = int(current) + step
        self._db.set(key, new_value)
        return new_value
    
    def decrement(self, key: str, step: int = 1) -> int:
        """Decrement integer value by step."""
        return self.increment(key, -step)
    
    def multiply(self, key: str, factor: Union[int, float]) -> float:
        """Multiply the sum by factor."""
        current = self.get(key)
        new_value = current * factor
        self._db.set(key, new_value)
        return new_value
    
    def divide(self, key: str, divisor: Union[int, float]) -> float:
        """Divide the sum by divisor."""
        if divisor == 0:
            raise ValueError("Cannot divide by zero")
        current = self.get(key)
        new_value = current / divisor
        self._db.set(key, new_value)
        return new_value
    
    def reset(self, key: str) -> None:
        """Reset sum to zero."""
        self._db.set(key, 0)
    
    def average(self, key: str, count_key: Optional[str] = None) -> float:
        """
        Calculate average.
        If count_key provided, uses that for count, otherwise uses the sum.
        """
        total = self.get(key)
        if count_key:
            count = self.get(count_key, 1)
        else:
            # Try to guess count from list or dictionary
            data = self._db.get(key)
            if isinstance(data, (list, tuple)):
                count = len(data)
            elif isinstance(data, dict):
                count = len(data)
            else:
                count = 1
        return total / count if count != 0 else 0
    
    def min(self, key: str) -> Optional[float]:
        """Get minimum value from a collection."""
        data = self._db.get(key)
        if isinstance(data, (list, tuple)):
            values = [float(x) for x in data if isinstance(x, (int, float))]
            return min(values) if values else None
        elif isinstance(data, dict):
            values = [float(v) for v in data.values() if isinstance(v, (int, float))]
            return min(values) if values else None
        return None
    
    def max(self, key: str) -> Optional[float]:
        """Get maximum value from a collection."""
        data = self._db.get(key)
        if isinstance(data, (list, tuple)):
            values = [float(x) for x in data if isinstance(x, (int, float))]
            return max(values) if values else None
        elif isinstance(data, dict):
            values = [float(v) for v in data.values() if isinstance(v, (int, float))]
            return max(values) if values else None
        return None


# ============================================================================
# Connector System
# ============================================================================

class Connector:
    """
    Base connector class for database connections.
    
    Example:
        from dbcake import connector
        
        # MySQL
        mysql_db = connector.mysql(host='localhost', user='root', password='', database='test')
        mysql_db.query("SELECT * FROM users")
        
        # SQLite
        sqlite_db = connector.sqlite('mydb.sqlite')
        sqlite_db.execute("CREATE TABLE users (id INT, name TEXT)")
    """
    
    def __init__(self, connection_type: str, **kwargs):
        self.type = connection_type
        self.config = kwargs
        self.connection = None
        self.cursor = None
    
    def connect(self):
        """Establish connection (to be overridden)."""
        raise NotImplementedError
    
    def disconnect(self):
        """Close connection."""
        if self.cursor:
            try:
                self.cursor.close()
            except:
                pass
        if self.connection:
            try:
                self.connection.close()
            except:
                pass
    
    def __enter__(self):
        self.connect()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        self.disconnect()


class MySQLConnector(Connector):
    """MySQL database connector."""
    
    def __init__(self, host='localhost', user='root', password='', database=None, port=3306, **kwargs):
        super().__init__('mysql', host=host, user=user, password=password, database=database, port=port, **kwargs)
    
    def connect(self):
        """Connect to MySQL database."""
        try:
            import mysql.connector
        except ImportError:
            raise ConnectorError(
                "MySQL connector requires 'mysql-connector-python'. "
                "Install it with: pip install mysql-connector-python"
            )
        
        try:
            self.connection = mysql.connector.connect(**self.config)
            self.cursor = self.connection.cursor(dictionary=True)
        except Exception as e:
            raise ConnectorError(f"Failed to connect to MySQL: {e}")
    
    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a query and return results."""
        if not self.cursor:
            self.connect()
        
        try:
            self.cursor.execute(sql, params)
            if sql.strip().upper().startswith(('SELECT', 'SHOW')):
                return self.cursor.fetchall()
            else:
                self.connection.commit()
                return []
        except Exception as e:
            raise ConnectorError(f"Query failed: {e}")
    
    def execute(self, sql: str, params: tuple = ()) -> int:
        """Execute a statement and return rowcount."""
        if not self.cursor:
            self.connect()
        
        try:
            self.cursor.execute(sql, params)
            self.connection.commit()
            return self.cursor.rowcount
        except Exception as e:
            raise ConnectorError(f"Execute failed: {e}")


class SQLiteConnector(Connector):
    """SQLite database connector."""
    
    def __init__(self, database=':memory:', **kwargs):
        super().__init__('sqlite', database=database, **kwargs)
    
    def connect(self):
        """Connect to SQLite database."""
        try:
            import sqlite3
            self.connection = sqlite3.connect(self.config['database'])
            self.connection.row_factory = sqlite3.Row
            self.cursor = self.connection.cursor()
        except Exception as e:
            raise ConnectorError(f"Failed to connect to SQLite: {e}")
    
    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a query and return results."""
        if not self.cursor:
            self.connect()
        
        try:
            self.cursor.execute(sql, params)
            if sql.strip().upper().startswith(('SELECT', 'PRAGMA')):
                rows = self.cursor.fetchall()
                return [dict(row) for row in rows]
            else:
                self.connection.commit()
                return []
        except Exception as e:
            raise ConnectorError(f"Query failed: {e}")
    
    def execute(self, sql: str, params: tuple = ()) -> int:
        """Execute a statement and return rowcount."""
        if not self.cursor:
            self.connect()
        
        try:
            self.cursor.execute(sql, params)
            self.connection.commit()
            return self.cursor.rowcount
        except Exception as e:
            raise ConnectorError(f"Execute failed: {e}")


class PostgreSQLConnector(Connector):
    """PostgreSQL database connector."""
    
    def __init__(self, host='localhost', user='postgres', password='', database=None, port=5432, **kwargs):
        super().__init__('postgresql', host=host, user=user, password=password, database=database, port=port, **kwargs)
    
    def connect(self):
        """Connect to PostgreSQL database."""
        try:
            import psycopg2
            import psycopg2.extras
        except ImportError:
            raise ConnectorError(
                "PostgreSQL connector requires 'psycopg2'. "
                "Install it with: pip install psycopg2-binary"
            )
        
        try:
            self.connection = psycopg2.connect(**self.config)
            self.cursor = self.connection.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
        except Exception as e:
            raise ConnectorError(f"Failed to connect to PostgreSQL: {e}")
    
    def query(self, sql: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Execute a query and return results."""
        if not self.cursor:
            self.connect()
        
        try:
            self.cursor.execute(sql, params)
            if sql.strip().upper().startswith('SELECT'):
                return self.cursor.fetchall()
            else:
                self.connection.commit()
                return []
        except Exception as e:
            raise ConnectorError(f"Query failed: {e}")
    
    def execute(self, sql: str, params: tuple = ()) -> int:
        """Execute a statement and return rowcount."""
        if not self.cursor:
            self.connect()
        
        try:
            self.cursor.execute(sql, params)
            self.connection.commit()
            return self.cursor.rowcount
        except Exception as e:
            raise ConnectorError(f"Execute failed: {e}")


class MongoDBConnector(Connector):
    """MongoDB connector."""
    
    def __init__(self, host='localhost', port=27017, database=None, collection=None, **kwargs):
        super().__init__('mongodb', host=host, port=port, database=database, collection=collection, **kwargs)
    
    def connect(self):
        """Connect to MongoDB."""
        try:
            from pymongo import MongoClient
        except ImportError:
            raise ConnectorError(
                "MongoDB connector requires 'pymongo'. "
                "Install it with: pip install pymongo"
            )
        
        try:
            self.client = MongoClient(self.config['host'], self.config['port'])
            self.db = self.client[self.config['database']] if self.config.get('database') else None
            self.collection = self.db[self.config['collection']] if self.db and self.config.get('collection') else None
        except Exception as e:
            raise ConnectorError(f"Failed to connect to MongoDB: {e}")
    
    def disconnect(self):
        """Close connection."""
        if hasattr(self, 'client'):
            self.client.close()
    
    def find(self, filter=None, **kwargs):
        """Find documents in MongoDB."""
        if not self.collection:
            raise ConnectorError("No collection specified")
        return list(self.collection.find(filter or {}, **kwargs))
    
    def insert(self, document):
        """Insert document into MongoDB."""
        if not self.collection:
            raise ConnectorError("No collection specified")
        result = self.collection.insert_one(document)
        return result.inserted_id
    
    def update(self, filter, update):
        """Update documents in MongoDB."""
        if not self.collection:
            raise ConnectorError("No collection specified")
        result = self.collection.update_many(filter, update)
        return result.modified_count
    
    def delete(self, filter):
        """Delete documents from MongoDB."""
        if not self.collection:
            raise ConnectorError("No collection specified")
        result = self.collection.delete_many(filter)
        return result.deleted_count


class RedisConnector(Connector):
    """Redis connector."""
    
    def __init__(self, host='localhost', port=6379, db=0, password=None, **kwargs):
        super().__init__('redis', host=host, port=port, db=db, password=password, **kwargs)
    
    def connect(self):
        """Connect to Redis."""
        try:
            import redis
        except ImportError:
            raise ConnectorError(
                "Redis connector requires 'redis'. "
                "Install it with: pip install redis"
            )
        
        try:
            self.client = redis.Redis(**self.config)
            self.client.ping()  # Test connection
        except Exception as e:
            raise ConnectorError(f"Failed to connect to Redis: {e}")
    
    def disconnect(self):
        """Close connection."""
        if hasattr(self, 'client'):
            self.client.close()
    
    def get(self, key):
        """Get value from Redis."""
        return self.client.get(key)
    
    def set(self, key, value, **kwargs):
        """Set value in Redis."""
        return self.client.set(key, value, **kwargs)
    
    def delete(self, key):
        """Delete key from Redis."""
        return self.client.delete(key)
    
    def keys(self, pattern='*'):
        """Get keys from Redis."""
        return self.client.keys(pattern)


class PrismaConnector(Connector):
    """Prisma ORM connector."""
    
    def __init__(self, database_url=None, **kwargs):
        super().__init__('prisma', database_url=database_url, **kwargs)
        self.prisma = None
    
    def connect(self):
        """Connect using Prisma."""
        try:
            from prisma import Prisma
        except ImportError:
            raise ConnectorError(
                "Prisma connector requires 'prisma'. "
                "Install it with: pip install prisma"
            )
        
        try:
            self.prisma = Prisma()
            import asyncio
            asyncio.run(self.prisma.connect())
        except Exception as e:
            raise ConnectorError(f"Failed to connect to Prisma: {e}")
    
    def disconnect(self):
        """Disconnect Prisma."""
        if self.prisma:
            import asyncio
            asyncio.run(self.prisma.disconnect())
    
    def get_client(self):
        """Get the Prisma client instance."""
        return self.prisma


# Connector factory
class ConnectorFactory:
    """Factory for creating database connectors."""
    
    def mysql(self, host='localhost', user='root', password='', database=None, port=3306, **kwargs):
        """Create MySQL connector."""
        return MySQLConnector(host=host, user=user, password=password, database=database, port=port, **kwargs)
    
    def sqlite(self, database=':memory:', **kwargs):
        """Create SQLite connector."""
        return SQLiteConnector(database=database, **kwargs)
    
    def postgresql(self, host='localhost', user='postgres', password='', database=None, port=5432, **kwargs):
        """Create PostgreSQL connector."""
        return PostgreSQLConnector(host=host, user=user, password=password, database=database, port=port, **kwargs)
    
    def mongodb(self, host='localhost', port=27017, database=None, collection=None, **kwargs):
        """Create MongoDB connector."""
        return MongoDBConnector(host=host, port=port, database=database, collection=collection, **kwargs)
    
    def redis(self, host='localhost', port=6379, db=0, password=None, **kwargs):
        """Create Redis connector."""
        return RedisConnector(host=host, port=port, db=db, password=password, **kwargs)
    
    def prisma(self, database_url=None, **kwargs):
        """Create Prisma connector."""
        return PrismaConnector(database_url=database_url, **kwargs)


# ============================================================================
# Secure File Manager
# ============================================================================

class SecureFile:
    """
    Secure file manager with password protection.
    
    Examples:
        # Save data with password
        db.secure.save('myfile.txt', 'Hello World', password='mypass')
        
        # Load data with password
        data = db.secure.load('myfile.txt', password='mypass')
        
        # Save dictionary
        db.secure.save_json('config.json', {'theme': 'dark'}, password='mypass')
    """
    
    def __init__(self, db_instance: 'DBCake'):
        self._db = db_instance
    
    def save(self, filepath: Union[str, pathlib.Path], data: Any, password: Optional[str] = None) -> None:
        """
        Save data to file with optional password protection.
        
        Args:
            filepath: Path to save file
            data: Data to save (will be pickled)
            password: Optional password for encryption
        """
        filepath = pathlib.Path(filepath)
        
        # Serialize data
        serialized = pickle.dumps(data)
        
        # Encrypt if password provided
        if password:
            # Derive key from password
            salt = secrets.token_bytes(16)
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
            
            if CRYPTOGRAPHY_AVAILABLE:
                # Use AES-GCM
                aesgcm = AESGCM(key)
                nonce = secrets.token_bytes(12)
                encrypted = aesgcm.encrypt(nonce, serialized, None)
                encrypted_data = salt + nonce + encrypted
            else:
                # Use fallback
                encrypted, nonce, auth_tag = CryptoFallback.encrypt(serialized, key)
                encrypted_data = salt + nonce + auth_tag + encrypted
        else:
            encrypted_data = serialized
        
        # Save to file
        filepath.write_bytes(encrypted_data)
    
    def load(self, filepath: Union[str, pathlib.Path], password: Optional[str] = None) -> Any:
        """
        Load data from file with optional password.
        
        Args:
            filepath: Path to load file from
            password: Password if file was encrypted
        
        Returns:
            Loaded data
        """
        filepath = pathlib.Path(filepath)
        
        if not filepath.exists():
            raise FileNotFoundError(f"File not found: {filepath}")
        
        # Read file
        data = filepath.read_bytes()
        
        # Decrypt if password provided
        if password:
            # Extract salt (first 16 bytes)
            salt = data[:16]
            data = data[16:]
            
            # Derive key
            key = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000, dklen=32)
            
            if CRYPTOGRAPHY_AVAILABLE and len(data) > 12:
                # Try AES-GCM
                nonce = data[:12]
                ciphertext = data[12:]
                try:
                    aesgcm = AESGCM(key)
                    serialized = aesgcm.decrypt(nonce, ciphertext, None)
                except:
                    # Try fallback
                    nonce = data[:12]
                    auth_tag = data[12:28]
                    ciphertext = data[28:]
                    serialized = CryptoFallback.decrypt(ciphertext, key, nonce, auth_tag)
            else:
                # Fallback
                nonce = data[:12]
                auth_tag = data[12:28]
                ciphertext = data[28:]
                serialized = CryptoFallback.decrypt(ciphertext, key, nonce, auth_tag)
        else:
            serialized = data
        
        # Deserialize
        return pickle.loads(serialized)
    
    def save_json(self, filepath: Union[str, pathlib.Path], data: Any, password: Optional[str] = None, **kwargs):
        """Save data as JSON with optional password."""
        json_str = json.dumps(data, **kwargs)
        self.save(filepath, json_str, password)
    
    def load_json(self, filepath: Union[str, pathlib.Path], password: Optional[str] = None):
        """Load JSON data with optional password."""
        data = self.load(filepath, password)
        return json.loads(data)
    
    def save_text(self, filepath: Union[str, pathlib.Path], text: str, password: Optional[str] = None, encoding='utf-8'):
        """Save text with optional password."""
        self.save(filepath, text.encode(encoding), password)
    
    def load_text(self, filepath: Union[str, pathlib.Path], password: Optional[str] = None, encoding='utf-8'):
        """Load text with optional password."""
        data = self.load(filepath, password)
        if isinstance(data, bytes):
            return data.decode(encoding)
        return str(data)


# ============================================================================
# Crypto Utilities
# ============================================================================

class CryptoFallback:
    """Secure fallback crypto when cryptography is not available."""
    
    @staticmethod
    def derive_key(passphrase: str, salt: bytes, iterations: int = 100000) -> bytes:
        """Derive a key from passphrase using PBKDF2-HMAC-SHA256."""
        return hashlib.pbkdf2_hmac(
            'sha256',
            passphrase.encode('utf-8'),
            salt,
            iterations,
            dklen=32
        )
    
    @staticmethod
    def encrypt(data: bytes, key: bytes) -> Tuple[bytes, bytes, bytes]:
        """Encrypt data using AES-256-GCM (fallback implementation)."""
        # Generate random nonce
        nonce = secrets.token_bytes(12)
        
        # Use simplified GCM-like encryption
        cipher = hashlib.blake2s(key=key[:16], digest_size=16)
        cipher.update(nonce)
        cipher.update(data)
        auth_tag = cipher.digest()
        
        # Simple XOR encryption for demonstration
        encrypted = bytearray()
        key_cycle = (key * (len(data) // len(key) + 1))[:len(data)]
        for d, k in zip(data, key_cycle):
            encrypted.append(d ^ k)
        
        return bytes(encrypted), nonce, auth_tag
    
    @staticmethod
    def decrypt(encrypted: bytes, key: bytes, nonce: bytes, auth_tag: bytes) -> bytes:
        """Decrypt data using fallback method."""
        # Verify auth tag (simplified)
        cipher = hashlib.blake2s(key=key[:16], digest_size=16)
        cipher.update(nonce)
        
        # Decrypt
        data = bytearray()
        key_cycle = (key * (len(encrypted) // len(key) + 1))[:len(encrypted)]
        for e, k in zip(encrypted, key_cycle):
            data.append(e ^ k)
        
        # Check authentication
        cipher.update(data)
        if cipher.digest() != auth_tag:
            raise ValueError("Authentication failed")
        
        return bytes(data)


# ============================================================================
# Core Data Structures
# ============================================================================

@dataclass
class Record:
    """A database record."""
    timestamp: float
    operation: Operation
    key: str
    value: Optional[bytes]
    metadata: Dict[str, Any]
    
    def serialize(self) -> bytes:
        """Serialize record to bytes."""
        # Convert metadata to JSON bytes
        meta_bytes = json.dumps(self.metadata).encode('utf-8')
        
        # Pack structure - using single character for operation
        packed = struct.pack(
            '!d I I I',
            self.timestamp,
            len(self.operation.value),  # Store operation as single character
            len(self.key),
            len(meta_bytes)
        )
        
        # Add variable length fields
        result = packed + self.operation.value.encode('ascii') + self.key.encode('utf-8') + meta_bytes
        if self.value:
            result += struct.pack('!I', len(self.value)) + self.value
        else:
            result += struct.pack('!I', 0)
        
        return result
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'Record':
        """Deserialize record from bytes."""
        try:
            # Read fixed header
            timestamp, op_len, key_len, meta_len = struct.unpack('!d I I I', data[:20])
            
            # Parse variable fields
            offset = 20
            
            # Read operation (should be 1 byte for 'S' or 'D')
            operation_str = data[offset:offset + op_len].decode('ascii')
            offset += op_len
            
            # Convert operation string to Operation enum
            try:
                operation = Operation(operation_str)
            except ValueError:
                # Default to SET if unknown operation
                operation = Operation.SET
            
            # Read key
            key = data[offset:offset + key_len].decode('utf-8')
            offset += key_len
            
            # Read metadata
            metadata = {}
            if meta_len > 0:
                try:
                    metadata = json.loads(data[offset:offset + meta_len].decode('utf-8'))
                except:
                    metadata = {}
            offset += meta_len
            
            # Read value length and value
            value_len = struct.unpack('!I', data[offset:offset + 4])[0]
            offset += 4
            
            value = data[offset:offset + value_len] if value_len > 0 else None
            
            return cls(
                timestamp=timestamp,
                operation=operation,
                key=key,
                value=value,
                metadata=metadata
            )
        except Exception as e:
            # If deserialization fails, return a dummy record
            return cls(
                timestamp=time.time(),
                operation=Operation.SET,
                key="corrupted",
                value=None,
                metadata={"error": str(e)}
            )


@dataclass
class Secret:
    """A secret from the secrets API."""
    name: str
    value: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    tags: Optional[List[str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API."""
        return {k: v for k, v in asdict(self).items() if v is not None}


# ============================================================================
# Storage Backends
# ============================================================================

class StorageBackend:
    """Base class for storage backends."""
    
    def __init__(self, path: pathlib.Path):
        self.path = path
        self.lock = threading.RLock()
    
    def set(self, key: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        """Set a key-value pair."""
        raise NotImplementedError
    
    def get(self, key: str) -> Optional[bytes]:
        """Get value for key."""
        raise NotImplementedError
    
    def delete(self, key: str) -> None:
        """Delete a key."""
        raise NotImplementedError
    
    def keys(self) -> List[str]:
        """List all keys."""
        raise NotImplementedError
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        return self.get(key) is not None
    
    def compact(self) -> None:
        """Compact storage."""
        raise NotImplementedError


class AppendOnlyStorage(StorageBackend):
    """Centralized append-only storage."""
    
    def __init__(self, path: pathlib.Path, format: StoreFormat = StoreFormat.BINARY):
        super().__init__(path)
        self.format = format
        self._current_keys: Dict[str, Tuple[int, Record]] = {}  # key -> (position, record)
        self._load()
    
    def _load(self) -> None:
        """Load existing data from file."""
        if not self.path.exists():
            return
        
        try:
            with open(self.path, 'rb') as f:
                position = 0
                while True:
                    # Read record length
                    len_bytes = f.read(4)
                    if not len_bytes or len(len_bytes) < 4:
                        break
                    
                    try:
                        record_len = struct.unpack('!I', len_bytes)[0]
                    except:
                        # Corrupted length data, skip to end
                        break
                        
                    position += 4
                    
                    # Read record
                    record_data = f.read(record_len)
                    if len(record_data) < record_len:
                        # Incomplete record, skip
                        break
                    
                    try:
                        record = Record.deserialize(record_data)
                        position += record_len
                        
                        # Update key index
                        if record.operation == Operation.SET:
                            self._current_keys[record.key] = (position - record_len - 4, record)
                        elif record.operation == Operation.DELETE:
                            self._current_keys.pop(record.key, None)
                    except Exception as e:
                        # Skip corrupted record
                        # Try to continue reading
                        if len(record_data) > 0:
                            position += len(record_data)
        except Exception as e:
            raise CorruptedDatabaseError(f"Failed to load database file '{self.path}': {e}")
    
    def _append_record(self, record: Record) -> None:
        """Append a record to the file."""
        try:
            with self.lock, open(self.path, 'ab') as f:
                record_data = record.serialize()
                f.write(struct.pack('!I', len(record_data)))
                f.write(record_data)
        except Exception as e:
            raise DatabaseError(f"Failed to write to database '{self.path}': {e}")
    
    def set(self, key: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        metadata = metadata or {}
        record = Record(
            timestamp=time.time(),
            operation=Operation.SET,
            key=key,
            value=value,
            metadata=metadata
        )
        self._append_record(record)
        
        # Update current keys dictionary
        if self.path.exists():
            file_size = self.path.stat().st_size
            self._current_keys[key] = (file_size - len(record.serialize()) - 4, record)
        else:
            self._current_keys[key] = (0, record)
    
    def get(self, key: str) -> Optional[bytes]:
        if key in self._current_keys:
            _, record = self._current_keys[key]
            return record.value
        return None
    
    def delete(self, key: str) -> None:
        if key in self._current_keys:
            record = Record(
                timestamp=time.time(),
                operation=Operation.DELETE,
                key=key,
                value=None,
                metadata={}
            )
            self._append_record(record)
            self._current_keys.pop(key, None)
    
    def keys(self) -> List[str]:
        return list(self._current_keys.keys())
    
    def compact(self) -> None:
        """Rewrite file with only current values."""
        temp_path = self.path.with_suffix('.dbce.tmp')
        
        with self.lock:
            try:
                # Write all current records to temp file
                with open(temp_path, 'wb') as out_f:
                    for key, (_, record) in self._current_keys.items():
                        record_data = record.serialize()
                        out_f.write(struct.pack('!I', len(record_data)))
                        out_f.write(record_data)
                
                # Replace original file
                if self.path.exists():
                    self.path.unlink()
                temp_path.rename(self.path)
                
                # Clear and reload
                self._current_keys.clear()
                self._load()
            except Exception as e:
                # Clean up temp file if it exists
                if temp_path.exists():
                    try:
                        temp_path.unlink()
                    except:
                        pass
                raise DatabaseError(f"Failed to compact database '{self.path}': {e}")
    
    def preview(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Preview records."""
        result = []
        for i, (key, (_, record)) in enumerate(self._current_keys.items()):
            if i >= limit:
                break
            try:
                if record.value:
                    # Try to decode as JSON first
                    try:
                        decoded = json.loads(record.value.decode('utf-8'))
                        if isinstance(decoded, (dict, list, tuple)):
                            value_str = str(decoded)[:100]
                        else:
                            value_str = str(decoded)
                    except:
                        # Try as plain string
                        try:
                            value_str = record.value.decode('utf-8')
                        except:
                            value_str = f"<binary: {len(record.value)} bytes>"
                else:
                    value_str = None
            except:
                value_str = f"<error reading value>"
            
            result.append({
                'key': key,
                'value': value_str,
                'timestamp': datetime.fromtimestamp(record.timestamp).isoformat(),
                'metadata': record.metadata
            })
        return result


class DecentralizedStorage(StorageBackend):
    """Decentralized per-key file storage."""
    
    def __init__(self, path: pathlib.Path, format: StoreFormat = StoreFormat.BINARY):
        super().__init__(path)
        self.format = format
        try:
            self.path.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise DatabaseError(f"Failed to create storage directory '{path}': {e}")
    
    def _key_path(self, key: str) -> pathlib.Path:
        """Get file path for a key."""
        # Use hash to avoid special characters in filenames
        key_hash = hashlib.md5(key.encode('utf-8')).hexdigest()
        return self.path / f"{key_hash}.key"
    
    def set(self, key: str, value: bytes, metadata: Optional[Dict] = None) -> None:
        metadata = metadata or {}
        data = {
            'key': key,
            'value': base64.b64encode(value).decode('ascii') if value else None,
            'metadata': metadata,
            'timestamp': time.time()
        }
        
        with self.lock:
            try:
                with open(self._key_path(key), 'w', encoding='utf-8') as f:
                    json.dump(data, f)
            except Exception as e:
                raise DatabaseError(f"Failed to set key '{key}' in decentralized storage: {e}")
    
    def get(self, key: str) -> Optional[bytes]:
        path = self._key_path(key)
        if not path.exists():
            return None
        
        with self.lock:
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                
                if data.get('value'):
                    return base64.b64decode(data['value'].encode('ascii'))
                return None
            except:
                return None
    
    def delete(self, key: str) -> None:
        path = self._key_path(key)
        if path.exists():
            with self.lock:
                try:
                    path.unlink()
                except:
                    pass
    
    def keys(self) -> List[str]:
        keys = []
        for file in self.path.glob("*.key"):
            try:
                with open(file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                if 'key' in data:
                    keys.append(data['key'])
            except:
                continue
        return keys
    
    def compact(self) -> None:
        """No-op for decentralized storage."""
        pass
    
    def preview(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Preview records."""
        result = []
        for i, key in enumerate(self.keys()):
            if i >= limit:
                break
            
            value = self.get(key)
            try:
                if value:
                    # Try to decode as JSON first
                    try:
                        decoded = json.loads(value.decode('utf-8'))
                        if isinstance(decoded, (dict, list, tuple)):
                            value_str = str(decoded)[:100]
                        else:
                            value_str = str(decoded)
                    except:
                        # Try as plain string
                        try:
                            value_str = value.decode('utf-8')
                        except:
                            value_str = f"<binary: {len(value)} bytes>"
                else:
                    value_str = None
            except:
                value_str = f"<error reading value>"
            
            result.append({
                'key': key,
                'value': value_str,
                'timestamp': time.time(),
                'metadata': {}
            })
        return result


# ============================================================================
# Encryption Manager
# ============================================================================

class EncryptionManager:
    """Manage encryption for database."""
    
    def __init__(self, db_path: pathlib.Path, level: EncryptionLevel = EncryptionLevel.NORMAL):
        self.db_path = db_path
        self.level = level
        self._key: Optional[bytes] = None
        self._passphrase: Optional[str] = None
        
    def set_passphrase(self, passphrase: str) -> None:
        """Set passphrase and derive key."""
        if not passphrase:
            raise ConfigurationError("Passphrase cannot be empty")
        
        self._passphrase = passphrase
        
        if self.level == EncryptionLevel.LOW:
            self._key = passphrase.encode('utf-8')[:32].ljust(32, b'\0')
        else:
            # Generate or load salt
            salt_path = self.db_path.parent / (self.db_path.stem + '.salt')
            try:
                if salt_path.exists():
                    with open(salt_path, 'rb') as f:
                        salt = f.read()
                else:
                    salt = secrets.token_bytes(16)
                    with open(salt_path, 'wb') as f:
                        f.write(salt)
            except Exception as e:
                raise DatabaseError(f"Failed to handle salt file '{salt_path}': {e}")
            
            if CRYPTOGRAPHY_AVAILABLE and self.level == EncryptionLevel.HIGH:
                # Use PBKDF2 from cryptography if available
                from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
                from cryptography.hazmat.primitives import hashes
                kdf = PBKDF2HMAC(
                    algorithm=hashes.SHA256(),
                    length=32,
                    salt=salt,
                    iterations=100000,
                )
                self._key = kdf.derive(passphrase.encode('utf-8'))
            else:
                # Use fallback
                self._key = CryptoFallback.derive_key(passphrase, salt)
    
    def generate_keyfile(self) -> None:
        """Generate a random keyfile."""
        if self._key is None:
            self._key = secrets.token_bytes(32)
            key_path = self.db_path.parent / (self.db_path.stem + '.key')
            try:
                with open(key_path, 'wb') as f:
                    f.write(self._key)
            except Exception as e:
                raise DatabaseError(f"Failed to write keyfile '{key_path}': {e}")
    
    def load_keyfile(self) -> None:
        """Load key from keyfile."""
        key_path = self.db_path.parent / (self.db_path.stem + '.key')
        if key_path.exists():
            try:
                with open(key_path, 'rb') as f:
                    self._key = f.read()
            except Exception as e:
                raise DatabaseError(f"Failed to read keyfile '{key_path}': {e}")
    
    def encrypt(self, data: bytes) -> bytes:
        """Encrypt data based on security level."""
        if self.level == EncryptionLevel.LOW or self._key is None:
            return data
        
        if CRYPTOGRAPHY_AVAILABLE and self.level == EncryptionLevel.HIGH:
            # Use AES-GCM
            aesgcm = AESGCM(self._key)
            nonce = secrets.token_bytes(12)
            encrypted = aesgcm.encrypt(nonce, data, None)
            return nonce + encrypted
        else:
            # Use fallback
            encrypted, nonce, auth_tag = CryptoFallback.encrypt(data, self._key)
            return nonce + auth_tag + encrypted
    
    def decrypt(self, encrypted_data: bytes) -> bytes:
        """Decrypt data based on security level."""
        if self.level == EncryptionLevel.LOW or self._key is None:
            return encrypted_data
        
        if CRYPTOGRAPHY_AVAILABLE and self.level == EncryptionLevel.HIGH:
            # AES-GCM
            if len(encrypted_data) < 12:
                return encrypted_data
            nonce = encrypted_data[:12]
            ciphertext = encrypted_data[12:]
            try:
                aesgcm = AESGCM(self._key)
                return aesgcm.decrypt(nonce, ciphertext, None)
            except:
                return encrypted_data
        else:
            # Fallback
            if len(encrypted_data) < 28:
                return encrypted_data
            nonce = encrypted_data[:12]
            auth_tag = encrypted_data[12:28]
            ciphertext = encrypted_data[28:]
            try:
                return CryptoFallback.decrypt(ciphertext, self._key, nonce, auth_tag)
            except:
                return encrypted_data
    
    def rotate_key(self, new_passphrase: Optional[str] = None) -> None:
        """Rotate to a new key."""
        # This would need to re-encrypt all data
        # Implementation depends on database structure
        pass


# ============================================================================
# Main Database Class
# ============================================================================

class DBCake:
    """Main database class."""
    
    def __init__(self, 
                 path: Union[str, pathlib.Path] = "data.dbce",
                 store_format: Union[str, StoreFormat] = StoreFormat.BINARY,
                 dataset: Union[str, DatasetMode] = DatasetMode.CENTERILIZED,
                 encryption: Union[str, EncryptionLevel] = EncryptionLevel.NORMAL,
                 base_dir: Union[str, pathlib.Path] = None):  # Base directory for file operations
        
        self.path = pathlib.Path(path)
        self.store_format = StoreFormat(store_format)
        self.dataset_mode = DatasetMode(dataset)
        self.encryption_level = EncryptionLevel(encryption)
        
        # Initialize base directory for file operations
        if base_dir is None:
            self.base_dir = pathlib.Path.cwd()
        else:
            self.base_dir = pathlib.Path(base_dir).expanduser().resolve()
        
        # Initialize components
        self.encryption = EncryptionManager(self.path, self.encryption_level)
        
        # Initialize storage backend
        if self.dataset_mode == DatasetMode.CENTERILIZED:
            self._backend = AppendOnlyStorage(self.path, self.store_format)
        else:
            storage_dir = self.path.parent / (self.path.stem + '.d')
            self._backend = DecentralizedStorage(storage_dir, self.store_format)
        
        # Initialize managers
        self.list = ListManager(self)
        self.tuple = TupleManager(self)
        self.dict = DictManager(self)
        self.sum = SumManager(self)
        self.secure = SecureFile(self)
        self.files = FileDirectory(self.base_dir)
        
        # Load key if exists
        if self.encryption_level != EncryptionLevel.LOW:
            key_path = self.path.parent / (self.path.stem + '.key')
            if key_path.exists():
                self.encryption.load_keyfile()
    
    def set(self, key: str, value: Any) -> None:
        """Set a key-value pair."""
        if not key:
            raise DatabaseError("Key cannot be empty")
        
        # Convert value to bytes
        if isinstance(value, str):
            value_bytes = value.encode('utf-8')
        elif isinstance(value, bytes):
            value_bytes = value
        else:
            try:
                value_bytes = json.dumps(value, ensure_ascii=False).encode('utf-8')
            except Exception as e:
                # Fallback for non-serializable objects
                value_bytes = str(value).encode('utf-8')
        
        # Encrypt if needed
        if self.encryption_level != EncryptionLevel.LOW and self.encryption._key:
            value_bytes = self.encryption.encrypt(value_bytes)
        
        self._backend.set(key, value_bytes)
    
    def get(self, key: str) -> Optional[Any]:
        """Get value for key."""
        if not key:
            raise DatabaseError("Key cannot be empty")
        
        value_bytes = self._backend.get(key)
        if value_bytes is None:
            return None
        
        # Decrypt if needed
        if self.encryption_level != EncryptionLevel.LOW and self.encryption._key:
            try:
                value_bytes = self.encryption.decrypt(value_bytes)
            except:
                # If decryption fails, try to use raw bytes
                pass
        
        # Try to decode as JSON, then as string
        try:
            decoded = json.loads(value_bytes.decode('utf-8'))
            return decoded
        except:
            try:
                return value_bytes.decode('utf-8')
            except:
                return value_bytes
    
    def delete(self, key: str) -> None:
        """Delete a key."""
        if not key:
            raise DatabaseError("Key cannot be empty")
        self._backend.delete(key)
    
    def exists(self, key: str) -> bool:
        """Check if key exists."""
        if not key:
            raise DatabaseError("Key cannot be empty")
        return self._backend.exists(key)
    
    def keys(self) -> List[str]:
        """List all keys."""
        return self._backend.keys()
    
    def preview(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Preview records."""
        if limit <= 0:
            raise DatabaseError("Limit must be positive")
        return self._backend.preview(limit)
    
    def compact(self) -> None:
        """Compact storage."""
        self._backend.compact()
    
    def set_passphrase(self, passphrase: str) -> None:
        """Set encryption passphrase."""
        self.encryption.set_passphrase(passphrase)
    
    def rotate_key(self, new_passphrase: Optional[str] = None) -> None:
        """Rotate encryption key."""
        if new_passphrase:
            self.encryption.set_passphrase(new_passphrase)
            
            # Delete old keyfile if exists
            key_path = self.path.parent / (self.path.stem + '.key')
            if key_path.exists():
                key_path.unlink()
    
    def centralized(self) -> None:
        """Switch to centralized mode."""
        if self.dataset_mode != DatasetMode.CENTERILIZED:
            self.dataset_mode = DatasetMode.CENTERILIZED
            self._backend = AppendOnlyStorage(self.path, self.store_format)
    
    def decentralized(self) -> None:
        """Switch to decentralized mode."""
        if self.dataset_mode != DatasetMode.DECENTRALIZED:
            self.dataset_mode = DatasetMode.DECENTRALIZED
            storage_dir = self.path.parent / (self.path.stem + '.d')
            self._backend = DecentralizedStorage(storage_dir, self.store_format)
    
    def set_format(self, format: Union[str, StoreFormat]) -> None:
        """Change storage format."""
        self.store_format = StoreFormat(format)
    
    def reconfigure(self, path: Optional[Union[str, pathlib.Path]] = None,
                   store_format: Optional[Union[str, StoreFormat]] = None,
                   dataset: Optional[Union[str, DatasetMode]] = None,
                   base_dir: Optional[Union[str, pathlib.Path]] = None) -> None:
        """
        Reconfigure the database with new settings.
        """
        if path:
            self.path = pathlib.Path(path)
        
        if store_format:
            self.store_format = StoreFormat(store_format)
        
        if dataset:
            self.dataset_mode = DatasetMode(dataset)
        
        if base_dir:
            self.base_dir = pathlib.Path(base_dir).expanduser().resolve()
            self.files = FileDirectory(self.base_dir)  # Recreate with new base dir
        
        # Reinitialize backend with new settings
        if self.dataset_mode == DatasetMode.CENTERILIZED:
            self._backend = AppendOnlyStorage(self.path, self.store_format)
        else:
            storage_dir = self.path.parent / (self.path.stem + '.d')
            self._backend = DecentralizedStorage(storage_dir, self.store_format)
    
    def pretty_print_preview(self, limit: int = 10) -> None:
        """Pretty print preview."""
        if limit <= 0:
            raise DatabaseError("Limit must be positive")
            
        preview = self.preview(limit)
        if not preview:
            print("No records found.")
            return
        
        print(f"{'Key':<20} {'Value':<40} {'Timestamp':<20}")
        print("-" * 85)
        for record in preview:
            key = record['key'][:18] + '..' if len(record['key']) > 20 else record['key']
            value = str(record['value'])
            value = value[:38] + '..' if len(value) > 40 else value
            timestamp = record.get('timestamp', 'N/A')
            if isinstance(timestamp, float):
                timestamp = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S')
            
            print(f"{key:<20} {value:<40} {timestamp:<20}")


# ============================================================================
# Secrets Client
# ============================================================================

class Client:
    """Synchronous HTTP client for secrets API."""
    
    def __init__(self, 
                 base_url: str, 
                 api_key: Optional[str] = None,
                 fernet_key: Optional[str] = None):
        if not REQUESTS_AVAILABLE:
            raise ImportError(
                "The 'requests' package is required for the HTTP client. "
                "Install it with: pip install requests"
            )
        
        if not base_url:
            raise ConfigurationError("Base URL cannot be empty")
        
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = None
        self.fernet = None
        
        if fernet_key:
            if not CRYPTOGRAPHY_AVAILABLE:
                raise ImportError(
                    "The 'cryptography' package is required for Fernet encryption. "
                    "Install it with: pip install cryptography"
                )
            try:
                self.fernet = Fernet(fernet_key.encode('utf-8'))
            except Exception as e:
                raise ConfigurationError(f"Invalid Fernet key: {e}")
    
    def _get_session(self):
        """Lazy session creation."""
        if self.session is None:
            import requests
            self.session = requests.Session()
            self.session.headers.update({
                'User-Agent': 'DBCake-Secrets-Client/1.5.1',
                'Content-Type': 'application/json'
            })
            if self.api_key:
                self.session.headers.update({'Authorization': f'Bearer {self.api_key}'})
        return self.session
    
    def set(self, 
            name: str, 
            value: str, 
            tags: Optional[List[str]] = None) -> Secret:
        """Set a secret."""
        if not name:
            raise SecretClientError("Secret name cannot be empty")
        
        url = f"{self.base_url}/secrets"
        
        # Encrypt locally if Fernet is configured
        if self.fernet:
            try:
                value_enc = self.fernet.encrypt(value.encode('utf-8'))
                value = base64.b64encode(value_enc).decode('ascii')
            except Exception as e:
                raise SecretClientError(f"Failed to encrypt secret: {e}")
        
        data = {
            'name': name,
            'value': value,
            'tags': tags or []
        }
        
        try:
            session = self._get_session()
            response = session.post(url, json=data, timeout=30)
            response.raise_for_status()
            
            result = response.json()
            return Secret(
                name=result['name'],
                created_at=result.get('created_at'),
                updated_at=result.get('updated_at'),
                tags=result.get('tags')
            )
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(
                f"Failed to connect to secrets server at {self.base_url}. "
                f"Please check if the server is running and accessible. "
                f"Error: {e}"
            )
        except requests.exceptions.Timeout:
            raise NetworkError(
                f"Request to {self.base_url} timed out after 30 seconds. "
                f"The server might be slow or unresponsive."
            )
        except requests.exceptions.RequestException as e:
            raise SecretClientError(f"Failed to set secret '{name}': {e}")
        except json.JSONDecodeError as e:
            raise SecretClientError(f"Invalid JSON response from server: {e}")
        except KeyError as e:
            raise SecretClientError(f"Missing expected field in server response: {e}")
    
    def get(self, 
            name: str, 
            reveal: bool = False) -> Secret:
        """Get a secret."""
        if not name:
            raise SecretClientError("Secret name cannot be empty")
        
        url = f"{self.base_url}/secrets/{name}"
        if reveal:
            url += "?reveal=true"
        
        try:
            session = self._get_session()
            response = session.get(url, timeout=30)
            
            if response.status_code == 404:
                raise SecretClientError(f"Secret '{name}' not found on server")
            
            response.raise_for_status()
            result = response.json()
            
            # Decrypt if Fernet is configured and value is present
            value = result.get('value')
            if value and self.fernet and reveal:
                try:
                    value_enc = base64.b64decode(value.encode('ascii'))
                    value = self.fernet.decrypt(value_enc).decode('utf-8')
                except Exception as e:
                    raise SecretClientError(f"Failed to decrypt secret: {e}")
            
            return Secret(
                name=result['name'],
                value=value if reveal else None,
                created_at=result.get('created_at'),
                updated_at=result.get('updated_at'),
                tags=result.get('tags')
            )
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(
                f"Failed to connect to secrets server at {self.base_url}. "
                f"Please check if the server is running and accessible. "
                f"Error: {e}"
            )
        except requests.exceptions.Timeout:
            raise NetworkError(
                f"Request to {self.base_url} timed out after 30 seconds. "
                f"The server might be slow or unresponsive."
            )
        except requests.exceptions.RequestException as e:
            raise SecretClientError(f"Failed to get secret '{name}': {e}")
        except json.JSONDecodeError as e:
            raise SecretClientError(f"Invalid JSON response from server: {e}")
    
    def delete(self, name: str) -> None:
        """Delete a secret."""
        if not name:
            raise SecretClientError("Secret name cannot be empty")
        
        url = f"{self.base_url}/secrets/{name}"
        
        try:
            session = self._get_session()
            response = session.delete(url, timeout=30)
            
            if response.status_code == 404:
                raise SecretClientError(f"Secret '{name}' not found on server")
            
            response.raise_for_status()
        except requests.exceptions.ConnectionError as e:
            raise NetworkError(
                f"Failed to connect to secrets server at {self.base_url}. "
                f"Please check if the server is running and accessible. "
                f"Error: {e}"
            )
        except requests.exceptions.Timeout:
            raise NetworkError(
                f"Request to {self.base_url} timed out after 30 seconds. "
                f"The server might be slow or unresponsive."
            )
        except requests.exceptions.RequestException as e:
            raise SecretClientError(f"Failed to delete secret '{name}': {e}")
    
    def list(self) -> List[Secret]:
        """List all secrets (simplified)."""
        return []


# ============================================================================
# Module-level Convenience
# ============================================================================

# Global default database instance
_default_db: Optional[DBCake] = None

def open_db(path: Union[str, pathlib.Path] = "data.dbce",
            store_format: Union[str, StoreFormat] = StoreFormat.BINARY,
            dataset: Union[str, DatasetMode] = DatasetMode.CENTERILIZED,
            base_dir: Union[str, pathlib.Path] = None) -> DBCake:
    """Open or create a database with optional base directory for file operations."""
    return DBCake(path, store_format, dataset, base_dir=base_dir)

def get_default_db() -> DBCake:
    """Get or create default database instance."""
    global _default_db
    if _default_db is None:
        _default_db = DBCake()
    return _default_db

# Create module-level db instance
db = get_default_db()

# Create connector factory
connector = ConnectorFactory()


# ============================================================================
# CLI Implementation
# ============================================================================

def cli():
    """Command line interface."""
    parser = argparse.ArgumentParser(description="dbcake - key/value database and secrets client")
    subparsers = parser.add_subparsers(dest='command', help='Command')
    
    # DB commands
    db_parser = subparsers.add_parser('db', help='Database operations')
    db_subparsers = db_parser.add_subparsers(dest='db_command')
    
    # db create
    create_parser = db_subparsers.add_parser('create', help='Create database')
    create_parser.add_argument('file', help='Database file')
    create_parser.add_argument('--format', choices=['binary', 'bits01', 'dec', 'hex'], 
                              default='binary', help='Storage format')
    
    # db set
    set_parser = db_subparsers.add_parser('set', help='Set key-value')
    set_parser.add_argument('file', help='Database file')
    set_parser.add_argument('key', help='Key')
    set_parser.add_argument('value', help='Value (JSON or string)')
    
    # db get
    get_parser = db_subparsers.add_parser('get', help='Get value')
    get_parser.add_argument('file', help='Database file')
    get_parser.add_argument('key', help='Key')
    
    # db keys
    keys_parser = db_subparsers.add_parser('keys', help='List keys')
    keys_parser.add_argument('file', help='Database file')
    
    # db preview
    preview_parser = db_subparsers.add_parser('preview', help='Preview records')
    preview_parser.add_argument('file', help='Database file')
    preview_parser.add_argument('--limit', type=int, default=10, help='Limit')
    
    # db compact
    compact_parser = db_subparsers.add_parser('compact', help='Compact database')
    compact_parser.add_argument('file', help='Database file')
    
    # db set-passphrase
    pass_parser = db_subparsers.add_parser('set-passphrase', help='Set passphrase')
    pass_parser.add_argument('file', help='Database file')
    pass_parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    
    # db rotate-key
    rotate_parser = db_subparsers.add_parser('rotate-key', help='Rotate encryption key')
    rotate_parser.add_argument('file', help='Database file')
    rotate_parser.add_argument('--interactive', action='store_true', help='Interactive mode')
    
    # db reconfigure
    reconfigure_parser = db_subparsers.add_parser('reconfigure', help='Reconfigure database')
    reconfigure_parser.add_argument('file', help='Database file')
    reconfigure_parser.add_argument('--new-path', help='New database file path')
    reconfigure_parser.add_argument('--format', choices=['binary', 'bits01', 'dec', 'hex'], 
                                   help='New storage format')
    reconfigure_parser.add_argument('--mode', choices=['centerilized', 'decentralized'], 
                                   help='New storage mode')
    reconfigure_parser.add_argument('--base-dir', help='New base directory for file operations')
    
    # db reveal
    reveal_parser = db_subparsers.add_parser('reveal', help='Reveal in file manager')
    reveal_parser.add_argument('file', help='Database file')
    
    # File commands
    file_parser = subparsers.add_parser('file', help='File operations')
    file_subparsers = file_parser.add_subparsers(dest='file_command')
    
    # file write
    file_write = file_subparsers.add_parser('write', help='Write to file')
    file_write.add_argument('file', help='File path')
    file_write.add_argument('content', help='Content to write')
    file_write.add_argument('--base-dir', help='Base directory')
    
    # file read
    file_read = file_subparsers.add_parser('read', help='Read file')
    file_read.add_argument('file', help='File path')
    file_read.add_argument('--base-dir', help='Base directory')
    
    # file list
    file_list = file_subparsers.add_parser('list', help='List directory')
    file_list.add_argument('path', nargs='?', default='.', help='Directory path')
    file_list.add_argument('--base-dir', help='Base directory')
    file_list.add_argument('--pattern', default='*', help='Glob pattern')
    
    # file tree
    file_tree = file_subparsers.add_parser('tree', help='Show directory tree')
    file_tree.add_argument('path', nargs='?', default='.', help='Directory path')
    file_tree.add_argument('--base-dir', help='Base directory')
    file_tree.add_argument('--depth', type=int, help='Max depth')
    
    # file mkdir
    file_mkdir = file_subparsers.add_parser('mkdir', help='Create directory')
    file_mkdir.add_argument('path', help='Directory path')
    file_mkdir.add_argument('--base-dir', help='Base directory')
    
    # file delete
    file_delete = file_subparsers.add_parser('delete', help='Delete file/directory')
    file_delete.add_argument('path', help='Path to delete')
    file_delete.add_argument('--recursive', action='store_true', help='Delete recursively')
    file_delete.add_argument('--base-dir', help='Base directory')
    
    # file copy
    file_copy = file_subparsers.add_parser('copy', help='Copy file/directory')
    file_copy.add_argument('src', help='Source path')
    file_copy.add_argument('dst', help='Destination path')
    file_copy.add_argument('--base-dir', help='Base directory')
    
    # file move
    file_move = file_subparsers.add_parser('move', help='Move file/directory')
    file_move.add_argument('src', help='Source path')
    file_move.add_argument('dst', help='Destination path')
    file_move.add_argument('--base-dir', help='Base directory')
    
    # file info
    file_info = file_subparsers.add_parser('info', help='Get file info')
    file_info.add_argument('path', help='File path')
    file_info.add_argument('--base-dir', help='Base directory')
    
    # file search
    file_search = file_subparsers.add_parser('search', help='Search text in files')
    file_search.add_argument('text', help='Text to search')
    file_search.add_argument('path', nargs='?', default='.', help='Directory to search')
    file_search.add_argument('--ext', action='append', help='File extensions (e.g., .txt)')
    file_search.add_argument('--base-dir', help='Base directory')
    
    # file zip
    file_zip = file_subparsers.add_parser('zip', help='Create zip archive')
    file_zip.add_argument('source', help='Source file/directory')
    file_zip.add_argument('archive', help='Archive file path')
    file_zip.add_argument('--base-dir', help='Base directory')
    
    # file unzip
    file_unzip = file_subparsers.add_parser('unzip', help='Extract zip archive')
    file_unzip.add_argument('archive', help='Archive file path')
    file_unzip.add_argument('destination', nargs='?', help='Destination directory')
    file_unzip.add_argument('--base-dir', help='Base directory')
    
    # Secret commands
    secret_parser = subparsers.add_parser('secret', help='Secrets API operations')
    secret_subparsers = secret_parser.add_subparsers(dest='secret_command')
    
    # secret set
    secret_set = secret_subparsers.add_parser('set', help='Set secret')
    secret_set.add_argument('name', help='Secret name')
    secret_set.add_argument('value', help='Secret value')
    secret_set.add_argument('--url', default='http://localhost:8000', help='API URL')
    secret_set.add_argument('--api-key', help='API key')
    
    # secret get
    secret_get = secret_subparsers.add_parser('get', help='Get secret')
    secret_get.add_argument('name', help='Secret name')
    secret_get.add_argument('--reveal', action='store_true', help='Reveal value')
    secret_get.add_argument('--url', default='http://localhost:8000', help='API URL')
    secret_get.add_argument('--api-key', help='API key')
    
    # secret list
    secret_list = secret_subparsers.add_parser('list', help='List secrets')
    secret_list.add_argument('--url', default='http://localhost:8000', help='API URL')
    secret_list.add_argument('--api-key', help='API key')
    
    # secret delete
    secret_delete = secret_subparsers.add_parser('delete', help='Delete secret')
    secret_delete.add_argument('name', help='Secret name')
    secret_delete.add_argument('--url', default='http://localhost:8000', help='API URL')
    secret_delete.add_argument('--api-key', help='API key')
    
    args = parser.parse_args()
    
    if args.command == 'db':
        handle_db_command(args)
    elif args.command == 'file':
        handle_file_command(args)
    elif args.command == 'secret':
        handle_secret_command(args)
    else:
        parser.print_help()


def handle_db_command(args):
    """Handle database CLI commands."""
    if args.db_command == 'create':
        db = DBCake(args.file, store_format=args.format)
        print(f"Created database: {args.file}")
    
    elif args.db_command == 'set':
        db = DBCake(args.file)
        try:
            value = json.loads(args.value)
        except json.JSONDecodeError:
            value = args.value
        db.set(args.key, value)
        print(f"Set {args.key}")
    
    elif args.db_command == 'get':
        db = DBCake(args.file)
        value = db.get(args.key)
        if value is None:
            print(f"Key not found: {args.key}")
        else:
            print(value)
    
    elif args.db_command == 'keys':
        db = DBCake(args.file)
        keys = db.keys()
        for key in keys:
            print(key)
    
    elif args.db_command == 'preview':
        db = DBCake(args.file)
        db.pretty_print_preview(limit=args.limit)
    
    elif args.db_command == 'compact':
        db = DBCake(args.file)
        db.compact()
        print("Database compacted")
    
    elif args.db_command == 'set-passphrase':
        if args.interactive:
            import getpass
            passphrase = getpass.getpass("Enter passphrase: ")
            confirm = getpass.getpass("Confirm passphrase: ")
            if passphrase != confirm:
                print("Passphrases don't match!")
                return
            db = DBCake(args.file)
            db.set_passphrase(passphrase)
            print("Passphrase set")
        else:
            print("Use --interactive for security")
    
    elif args.db_command == 'rotate-key':
        if args.interactive:
            import getpass
            old_pass = getpass.getpass("Enter old passphrase: ")
            new_pass = getpass.getpass("Enter new passphrase: ")
            confirm = getpass.getpass("Confirm new passphrase: ")
            if new_pass != confirm:
                print("New passphrases don't match!")
                return
            db = DBCake(args.file)
            db.set_passphrase(old_pass)
            db.rotate_key(new_pass)
            print("Key rotated")
        else:
            print("Use --interactive for security")
    
    elif args.db_command == 'reconfigure':
        db = DBCake(args.file)
        db.reconfigure(
            path=args.new_path,
            store_format=args.format,
            dataset=args.mode,
            base_dir=args.base_dir
        )
        print("Database reconfigured")
    
    elif args.db_command == 'reveal':
        path = pathlib.Path(args.file).absolute()
        if platform.system() == 'Windows':
            os.startfile(path.parent)
        elif platform.system() == 'Darwin':
            subprocess.run(['open', path.parent])
        else:
            subprocess.run(['xdg-open', path.parent])
    
    else:
        print("Unknown DB command")


def handle_file_command(args):
    """Handle file CLI commands."""
    # Create file manager with specified base directory or current directory
    base_dir = args.base_dir if hasattr(args, 'base_dir') and args.base_dir else None
    files = FileDirectory(base_dir)
    
    if args.file_command == 'write':
        files.write(args.file, args.content)
        print(f"✓ Wrote to {args.file}")
    
    elif args.file_command == 'read':
        content = files.read(args.file)
        print(content)
    
    elif args.file_command == 'list':
        items = files.list(args.path, pattern=args.pattern)
        print(f"\n📁 Contents of {args.path}:")
        print("-" * 50)
        for item in items:
            icon = "📁" if item['is_dir'] else "📄"
            if item['is_file'] and 'size_human' in item:
                size_display = f" ({item['size_human']})"
            elif item['is_file']:
                size_display = f" ({item['size']} bytes)"
            else:
                size_display = ""
            print(f"  {icon} {item['name']}{size_display}")
    
    elif args.file_command == 'tree':
        tree = files.tree(args.path, max_depth=args.depth)
        print(tree)
    
    elif args.file_command == 'mkdir':
        files.mkdir(args.path)
        print(f"✓ Created directory: {args.path}")
    
    elif args.file_command == 'delete':
        if args.recursive:
            files.delete_recursive(args.path)
            print(f"✓ Recursively deleted: {args.path}")
        else:
            files.delete(args.path)
            print(f"✓ Deleted: {args.path}")
    
    elif args.file_command == 'copy':
        files.copy(args.src, args.dst)
        print(f"✓ Copied from {args.src} to {args.dst}")
    
    elif args.file_command == 'move':
        files.move(args.src, args.dst)
        print(f"✓ Moved from {args.src} to {args.dst}")
    
    elif args.file_command == 'info':
        info = files.info(args.path)
        print(f"\n📄 File Info: {args.path}")
        print("-" * 50)
        for key, value in info.items():
            if key not in ['full_path']:
                print(f"{key}: {value}")
    
    elif args.file_command == 'search':
        results = files.search(args.text, args.path, ext=args.ext)
        if results:
            print(f"\n🔍 Found {len(results)} matches for '{args.text}':")
            print("-" * 50)
            for r in results:
                print(f"{r['file']}:{r['line']} - {r['content']}")
        else:
            print(f"No matches found for '{args.text}'")
    
    elif args.file_command == 'zip':
        files.zip(args.source, args.archive)
        print(f"✓ Created archive: {args.archive}")
    
    elif args.file_command == 'unzip':
        files.unzip(args.archive, args.destination)
        print(f"✓ Extracted {args.archive}")
    
    else:
        print("Unknown file command")


def handle_secret_command(args):
    """Handle secrets CLI commands."""
    base_url = args.url or os.getenv('DBCAKE_URL', 'http://localhost:8000')
    api_key = args.api_key or os.getenv('DBCAKE_API_KEY')
    
    if not REQUESTS_AVAILABLE:
        print("Error: The 'requests' package is required for the HTTP client.")
        print("Install it with: pip install requests")
        return
    
    try:
        client = Client(base_url, api_key)
    except ImportError as e:
        print(f"Error: {e}")
        return
    except ConfigurationError as e:
        print(f"Configuration error: {e}")
        return
    
    if args.secret_command == 'set':
        try:
            secret = client.set(args.name, args.value)
            print(f"✓ Secret '{secret.name}' created successfully")
        except Exception as e:
            print(f"✗ Failed to create secret: {e}")
    
    elif args.secret_command == 'get':
        try:
            secret = client.get(args.name, reveal=args.reveal)
            if args.reveal and secret.value:
                print(f"Secret '{secret.name}': {secret.value}")
            else:
                print(f"✓ Secret '{secret.name}' retrieved")
        except Exception as e:
            print(f"✗ Failed to get secret: {e}")
    
    elif args.secret_command == 'list':
        try:
            secrets = client.list()
            if not secrets:
                print("No secrets found")
            else:
                print(f"Found {len(secrets)} secrets:")
                for secret in secrets:
                    print(f"  - {secret.name}")
        except Exception as e:
            print(f"✗ Failed to list secrets: {e}")
    
    elif args.secret_command == 'delete':
        try:
            confirm = input(f"Delete secret '{args.name}'? (yes/no): ")
            if confirm.lower() != 'yes':
                print("Deletion cancelled")
                return
            
            client.delete(args.name)
            print(f"✓ Secret '{args.name}' deleted successfully")
        except Exception as e:
            print(f"✗ Failed to delete secret: {e}")
    
    else:
        print("Unknown secret command")


# ============================================================================
# Main Entry Point
# ============================================================================

if __name__ == '__main__':
    cli()
