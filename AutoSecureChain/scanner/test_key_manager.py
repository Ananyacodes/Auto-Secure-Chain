#!/usr/bin/env python3
"""
Test script for AutoSecureChain key management functionality.
Tests key generation, signing, verification, rotation, and audit logging.
"""
import os
import sys
import tempfile
import shutil
from pathlib import Path

# Add scanner directory to path
sys.path.insert(0, str(Path(__file__).parent / "AutoSecureChain" / "scanner"))

try:
    from key_manager import KeyManager, AuditLogger
except ImportError as e:
    print(f"❌ Failed to import key management modules: {e}")
    sys.exit(1)

def test_key_generation():
    """Test keypair generation."""
    print("Testing key generation...")

    with tempfile.TemporaryDirectory() as temp_dir:
        key_dir = Path(temp_dir) / "keys"
        km = KeyManager(key_dir)

        # Generate a key
        result = km.generate_keypair("test_key", 2048)

        assert result["key_id"], "Key ID should be generated"
        assert (key_dir / "test_key_private.pem").exists(), "Private key file should exist"
        assert (key_dir / "test_key_public.pem").exists(), "Public key file should exist"
        assert (key_dir / "test_key_info.json").exists(), "Key info file should exist"

        # Check key info
        info = km.get_key_info("test_key")
        assert info["name"] == "test_key", "Key name should match"
        assert info["key_size"] == 2048, "Key size should match"
        assert info["status"] == "active", "Key should be active"

        print("✅ Key generation test passed")

def test_firmware_signing():
    """Test firmware signing and verification."""
    print("Testing firmware signing...")

    with tempfile.TemporaryDirectory() as temp_dir:
        key_dir = Path(temp_dir) / "keys"
        km = KeyManager(key_dir)

        # Generate test firmware
        firmware_data = b"Hello, this is test firmware data!" * 100
        firmware_path = Path(temp_dir) / "test_firmware.bin"
        firmware_path.write_bytes(firmware_data)

        # Generate key and sign
        km.generate_keypair("signing_key", 2048)
        sig_path = km.sign_firmware(firmware_path, "signing_key")

        assert sig_path.exists(), "Signature file should be created"
        assert str(sig_path).endswith(".bin.sig"), "Signature should have correct extension"

        # Verify signature
        is_valid = km.verify_signature(firmware_path, "signing_key")
        assert is_valid, "Signature verification should succeed"

        # Test with modified firmware (sign first, then modify content)
        modified_firmware = Path(temp_dir) / "modified_firmware.bin"
        modified_firmware.write_bytes(firmware_data)  # Same content initially
        km.sign_firmware(modified_firmware, "signing_key")  # Sign it
        modified_firmware.write_bytes(firmware_data + b"modified")  # Now modify content
        is_valid_modified = km.verify_signature(modified_firmware, "signing_key")
        assert not is_valid_modified, "Modified firmware should fail verification"

        print("✅ Firmware signing test passed")

def test_key_rotation():
    """Test key rotation functionality."""
    print("Testing key rotation...")

    with tempfile.TemporaryDirectory() as temp_dir:
        key_dir = Path(temp_dir) / "keys"
        km = KeyManager(key_dir)

        # Generate original key
        original = km.generate_keypair("original", 2048)

        # Rotate key
        rotated = km.rotate_key("original", "rotated")

        # Check that old key is marked as rotated
        old_info = km.get_key_info("original")
        assert old_info["status"] == "rotated", "Old key should be marked as rotated"
        assert old_info["rotated_to"] == rotated["key_id"], "Old key should reference new key"

        # Check that new key exists
        new_info = km.get_key_info("rotated")
        assert new_info["status"] == "active", "New key should be active"

        print("✅ Key rotation test passed")

def test_audit_logging():
    """Test audit logging functionality."""
    print("Testing audit logging...")

    with tempfile.TemporaryDirectory() as temp_dir:
        log_dir = Path(temp_dir) / "logs"
        al = AuditLogger(log_dir)

        # Log some events
        al.log_event("test_event", "info", "Test message", {"test": "data"})
        al.log_security_finding("test_file.bin", "test_finding", "warning")
        al.log_scan_start("test_target")
        al.log_scan_complete("test_target", 5, 1.23)

        # Check audit log
        events = al.get_recent_events(10)
        assert len(events) >= 4, "Should have at least 4 audit events"

        # Test search
        security_events = al.search_events("security_finding")
        assert len(security_events) >= 1, "Should find security finding events"

        print("✅ Audit logging test passed")

def test_key_listing():
    """Test key listing functionality."""
    print("Testing key listing...")

    with tempfile.TemporaryDirectory() as temp_dir:
        key_dir = Path(temp_dir) / "keys"
        km = KeyManager(key_dir)

        # Generate multiple keys
        km.generate_keypair("key1", 2048)
        km.generate_keypair("key2", 2048)

        # List keys
        keys = km.list_keys()
        assert len(keys) == 2, "Should list 2 keys"
        assert all(k["name"] in ["key1", "key2"] for k in keys), "Should list correct keys"

        print("✅ Key listing test passed")

def test_encrypted_key_with_keyring():
    """Test generating an encrypted private key and signing using passphrase stored in OS keyring."""
    print("Testing encrypted key generation with keyring retrieval...")

    import importlib

    with tempfile.TemporaryDirectory() as temp_dir:
        key_dir = Path(temp_dir) / "keys"
        km = KeyManager(key_dir)

        # If keyring is not available in the runtime, skip this test gracefully
        try:
            km_module = importlib.import_module('key_manager')
        except Exception:
            print("Key manager module import failed; skipping keyring test")
            return

        if not getattr(km_module, '_KEYRING_AVAILABLE', False):
            print("OS keyring not available; skipping keyring-specific test")
            return

        # Create a small firmware file to sign
        firmware_data = b"Encrypted keyring test firmware"
        firmware_path = Path(temp_dir) / "enc_test_firmware.bin"
        firmware_path.write_bytes(firmware_data)

        passphrase = "TestPass!@#123"

        # Generate encrypted key and request storing passphrase in keyring
        km.generate_keypair("enc_key", 2048, passphrase=passphrase, use_keyring=True)

        # Ensure private key exists and is not stored unencrypted (basic check)
        priv = key_dir / "enc_key_private.pem"
        assert priv.exists(), "Encrypted private key should exist"
        content = priv.read_text()
        assert "ENCRYPTED" in content or "Proc-Type: 4,ENCRYPTED" in content or "BEGIN ENCRYPTED PRIVATE KEY" in content

        # Sign using keyring retrieval (no explicit passphrase)
        sig_path = km.sign_firmware(firmware_path, "enc_key", passphrase=None, use_keyring=True)
        assert sig_path.exists(), "Signature should be created using keyring-retrieved passphrase"

        # Cleanup: remove passphrase from keyring
        try:
            if km_module.keyring:
                km_module.keyring.delete_password("AutoSecureChain", "enc_key")
        except Exception:
            pass

        print("✅ Encrypted key + keyring test passed")

def run_all_tests():
    """Run all key management tests."""
    print("Running AutoSecureChain Key Management Tests")
    print("=" * 50)

    tests = [
        test_key_generation,
        test_firmware_signing,
        test_key_rotation,
        test_audit_logging,
        test_key_listing
        ,
        test_encrypted_key_with_keyring
    ]

    passed = 0
    failed = 0

    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed: {e}")
            failed += 1

    print("=" * 50)
    print(f"Tests completed: {passed} passed, {failed} failed")

    if failed > 0:
        sys.exit(1)
    else:
        print("🎉 All tests passed!")

if __name__ == "__main__":
    run_all_tests()