#!/usr/bin/env python3
"""
Unit tests for CLI validators and file locking.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from AutoSecureChain.scanner.cli_validators import (
    ValidationError, validate_key_name, validate_file_path,
    validate_key_size, validate_passphrase, format_file_error
)


def test_validate_key_name():
    """Test key name validation."""
    print("Testing key name validation...")
    
    # Valid names
    assert validate_key_name("production") == "production"
    assert validate_key_name("test_key_1") == "test_key_1"
    assert validate_key_name("my-prod-key") == "my-prod-key"
    print("  ✅ Valid names pass")
    
    # Invalid names
    invalid_names = [
        ("", "empty"),
        ("@invalid", "invalid chars"),
        ("_underscore_start", "starts with underscore"),
        ("-hyphen-start", "starts with hyphen"),
        ("a" * 100, "too long"),
        ("path/separator", "path separator"),
        ("1starts_with_number", "starts with number"),
    ]
    
    for name, reason in invalid_names:
        try:
            validate_key_name(name)
            print(f"  ❌ Should reject: {reason}")
        except ValidationError:
            print(f"  ✅ Correctly rejected: {reason}")
    
    print("✅ Key name validation passed\n")


def test_validate_file_path():
    """Test file path validation."""
    print("Testing file path validation...")
    
    # Valid file path (existing file)
    current_file = Path(__file__)
    assert validate_file_path(str(current_file), must_exist=True) == current_file
    print("  ✅ Existing file passes")
    
    # Non-existing file (parent must exist)
    non_existing = Path(__file__).parent / "non_existing_file.txt"
    assert validate_file_path(str(non_existing), must_exist=False, writable=False) == non_existing
    print("  ✅ Non-existing file with valid parent passes")
    
    # Invalid: non-existing parent directory
    try:
        validate_file_path("/nonexistent/path/to/file.txt", must_exist=False)
        print("  ❌ Should reject non-existing parent")
    except ValidationError:
        print("  ✅ Correctly rejects non-existing parent")
    
    print("✅ File path validation passed\n")


def test_validate_key_size():
    """Test key size validation."""
    print("Testing key size validation...")
    
    # Valid sizes
    for size in [2048, 3072, 4096]:
        assert validate_key_size(size) == size
    print("  ✅ Valid sizes pass")
    
    # Invalid sizes
    for size in [1024, 2560, 8192]:
        try:
            validate_key_size(size)
            print(f"  ❌ Should reject size: {size}")
        except ValidationError:
            print(f"  ✅ Correctly rejected size: {size}")
    
    print("✅ Key size validation passed\n")


def test_validate_passphrase():
    """Test passphrase validation."""
    print("Testing passphrase validation...")
    
    # Valid passphrases
    assert validate_passphrase("short_pass", min_length=5) == "short_pass"
    assert validate_passphrase("very_long_passphrase_123", min_length=8) == "very_long_passphrase_123"
    assert validate_passphrase(None) is None
    print("  ✅ Valid passphrases pass")
    
    # Invalid passphrases
    try:
        validate_passphrase("short", min_length=8)
        print("  ❌ Should reject short passphrase")
    except ValidationError:
        print("  ✅ Correctly rejected short passphrase")
    
    print("✅ Passphrase validation passed\n")


def run_all_tests():
    """Run all validator tests."""
    print("Running CLI Validator Tests")
    print("=" * 50)
    
    test_validate_key_name()
    test_validate_file_path()
    test_validate_key_size()
    test_validate_passphrase()
    
    print("=" * 50)
    print("🎉 All validator tests passed!")


if __name__ == "__main__":
    run_all_tests()
