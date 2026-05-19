#!/usr/bin/env python3
"""
Input validation and file locking utilities for AutoSecureChain CLI.
Provides validation for key names, file paths, and concurrent access controls.
"""
import re
import os
import sys
from pathlib import Path
from typing import Optional

try:
    from filelock import FileLock, Timeout
    HAS_FILELOCK = True
except ImportError:
    HAS_FILELOCK = False


# ===== INPUT VALIDATION =====

class ValidationError(Exception):
    """Raised when input validation fails."""
    pass


def validate_key_name(name: str, max_length: int = 64) -> str:
    """
    Validate a key name.
    
    Rules:
    - Alphanumeric, hyphens, underscores only
    - 1-64 characters
    - Cannot start with hyphen or underscore
    - Cannot contain directory separators
    
    Args:
        name: Key name to validate
        max_length: Maximum allowed length (default: 64)
    
    Returns:
        Validated key name
    
    Raises:
        ValidationError: If validation fails
    """
    if not name:
        raise ValidationError("Key name cannot be empty")
    
    if len(name) > max_length:
        raise ValidationError(f"Key name exceeds maximum length ({max_length} chars): {name}")
    
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9_-]{0,}$', name):
        raise ValidationError(
            f"Key name '{name}' contains invalid characters. "
            "Must start with letter, contain only alphanumeric, hyphens, underscores"
        )
    
    if '/' in name or '\\' in name:
        raise ValidationError(f"Key name cannot contain directory separators: {name}")
    
    return name


def validate_file_path(path_str: str, must_exist: bool = True, writable: bool = False) -> Path:
    """
    Validate a file path.
    
    Args:
        path_str: Path string to validate
        must_exist: If True, file must exist; if False, parent directory must exist
        writable: If True, file/parent directory must be writable
    
    Returns:
        Validated Path object
    
    Raises:
        ValidationError: If validation fails
    """
    if not path_str:
        raise ValidationError("File path cannot be empty")
    
    try:
        path = Path(path_str).resolve()
    except Exception as e:
        raise ValidationError(f"Invalid file path: {path_str} - {e}")
    
    if must_exist:
        if not path.exists():
            raise ValidationError(f"File not found: {path}")
        
        if not path.is_file():
            raise ValidationError(f"Path is not a file: {path}")
        
        if not os.access(path, os.R_OK):
            raise ValidationError(f"File is not readable: {path} (permission denied)")
    else:
        # Parent directory must exist
        parent = path.parent
        if not parent.exists():
            raise ValidationError(f"Parent directory does not exist: {parent}")
        
        if not parent.is_dir():
            raise ValidationError(f"Parent is not a directory: {parent}")
    
    if writable:
        check_path = path if path.exists() else path.parent
        if not os.access(check_path, os.W_OK):
            raise ValidationError(f"No write permission: {check_path} (permission denied)")
    
    return path


def validate_key_size(size: int) -> int:
    """
    Validate RSA key size.
    
    Args:
        size: Key size in bits
    
    Returns:
        Validated key size
    
    Raises:
        ValidationError: If key size is invalid
    """
    if size not in [2048, 3072, 4096]:
        raise ValidationError(
            f"Invalid key size: {size}. Supported sizes: 2048, 3072, 4096 bits"
        )
    
    return size


def validate_passphrase(passphrase: Optional[str], min_length: int = 8) -> Optional[str]:
    """
    Validate passphrase strength.
    
    Args:
        passphrase: Passphrase to validate (None is valid for unencrypted keys)
        min_length: Minimum passphrase length (default: 8)
    
    Returns:
        Validated passphrase or None
    
    Raises:
        ValidationError: If passphrase is too weak
    """
    if passphrase is None:
        return None
    
    if not isinstance(passphrase, str):
        raise ValidationError("Passphrase must be a string")
    
    if len(passphrase) < min_length:
        raise ValidationError(
            f"Passphrase too short: minimum {min_length} characters required"
        )
    
    return passphrase


# ===== FILE LOCKING =====

class KeyFileLock:
    """
    Context manager for file-based locking to prevent concurrent key operations.
    Uses filelock library if available, falls back to simple lock file on error.
    """
    
    def __init__(self, key_name: str, timeout: float = 30.0):
        """
        Initialize key file lock.
        
        Args:
            key_name: Name of key being protected
            timeout: Lock acquisition timeout in seconds (default: 30)
        """
        self.key_name = key_name
        self.timeout = timeout
        self.lock = None
        self._init_lock()
    
    def _init_lock(self):
        """Initialize lock file object."""
        try:
            lock_dir = self._get_lock_dir()
            lock_file = lock_dir / f".{self.key_name}.lock"
            
            if HAS_FILELOCK:
                self.lock = FileLock(str(lock_file), timeout=self.timeout)
            else:
                self.lock = SimpleLockFile(lock_file, timeout=self.timeout)
        except Exception as e:
            # Non-critical: log warning but don't fail
            print(f"⚠️  Warning: Could not initialize file lock: {e}", file=sys.stderr)
            self.lock = None
    
    @staticmethod
    def _get_lock_dir() -> Path:
        """Get lock directory."""
        try:
            lock_dir = Path.home() / ".autosecurechain" / "locks"
        except (RuntimeError, OSError):
            lock_dir = Path(".autosecurechain") / "locks"
        
        lock_dir.mkdir(parents=True, exist_ok=True)
        return lock_dir
    
    def __enter__(self):
        """Acquire lock."""
        if self.lock is None:
            return
        
        try:
            self.lock.acquire()
        except Timeout:
            raise ValidationError(
                f"Could not acquire lock for key '{self.key_name}'. "
                f"Another operation may be in progress. Try again in {self.timeout}s"
            )
        except Exception as e:
            raise ValidationError(f"Lock error: {e}")
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Release lock."""
        if self.lock is None:
            return
        
        try:
            self.lock.release()
        except Exception as e:
            print(f"⚠️  Warning: Could not release lock: {e}", file=sys.stderr)


class SimpleLockFile:
    """
    Simple lock file implementation for systems without filelock library.
    Creates a lock file and monitors for stale locks.
    """
    
    def __init__(self, lock_path: Path, timeout: float = 30.0):
        self.lock_path = lock_path
        self.timeout = timeout
        self.acquired = False
    
    def acquire(self):
        """Acquire lock by creating lock file."""
        import time
        start_time = time.time()
        
        while True:
            try:
                # Try to create lock file exclusively
                self.lock_path.touch(exist_ok=False)
                self.acquired = True
                return
            except FileExistsError:
                # Lock file exists, check if stale (older than timeout)
                if self.lock_path.exists():
                    age = time.time() - self.lock_path.stat().st_mtime
                    if age > self.timeout:
                        # Lock is stale, remove it
                        try:
                            self.lock_path.unlink()
                            continue
                        except OSError:
                            pass
                
                # Check timeout
                if time.time() - start_time > self.timeout:
                    raise Timeout(f"Could not acquire lock within {self.timeout}s")
                
                time.sleep(0.1)
    
    def release(self):
        """Release lock by removing lock file."""
        if self.acquired and self.lock_path.exists():
            try:
                self.lock_path.unlink()
                self.acquired = False
            except OSError:
                pass


# ===== ERROR MESSAGE FORMATTING =====

def format_file_error(operation: str, path: Path, error: OSError) -> str:
    """
    Format file operation error with helpful message.
    
    Args:
        operation: Operation attempted (e.g., "read", "write", "delete")
        path: File path
        error: OSError from operation
    
    Returns:
        Formatted error message
    """
    if error.errno == 2:  # ENOENT
        return f"File not found during {operation}: {path}"
    elif error.errno == 13:  # EACCES
        return f"Permission denied while attempting to {operation}: {path}"
    elif error.errno == 21:  # EISDIR
        return f"Expected file but found directory: {path}"
    elif error.errno == 28:  # ENOSPC
        return f"No space left on device while attempting to {operation}: {path}"
    else:
        return f"Error during {operation}: {path} - {error.strerror}"


def format_permission_error(action: str, path: Path) -> str:
    """Format permission error message."""
    return (
        f"Permission denied: cannot {action} {path}\n"
        f"Check file/directory permissions or run with appropriate privileges"
    )


def format_key_error(key_name: str, operation: str, details: Optional[str] = None) -> str:
    """Format key operation error message."""
    msg = f"Key operation failed - {operation} key '{key_name}'"
    if details:
        msg += f"\nDetails: {details}"
    return msg
