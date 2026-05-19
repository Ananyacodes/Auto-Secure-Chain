#!/usr/bin/env python3
"""
Unit tests for AutoSecureChain firmware scanner.
Tests entropy analysis, string extraction, suspicious pattern detection, and signature verification.
"""
import os
import sys
import tempfile
import json
from pathlib import Path

# Add scanner directory to path
sys.path.insert(0, str(Path(__file__).parent))

from scanner import shannon_entropy, extract_strings, hash_file, scan_file, verify_external_signature


def test_shannon_entropy():
    """Test entropy calculation."""
    print("Testing Shannon entropy...")
    
    # Low entropy: highly repetitive data
    low_entropy_data = b"AAAAAAAAAAAAAAAA"
    entropy = shannon_entropy(low_entropy_data)
    assert entropy < 2.0, f"Low entropy data should have low score, got {entropy}"
    
    # Medium entropy: mixed data
    medium_entropy_data = b"The quick brown fox jumps over the lazy dog" * 10
    entropy = shannon_entropy(medium_entropy_data)
    assert 2.0 < entropy < 5.0, f"Medium entropy should be between 2-5, got {entropy}"
    
    # High entropy: random-like data
    high_entropy_data = os.urandom(256)
    entropy = shannon_entropy(high_entropy_data)
    assert entropy > 7.0, f"High entropy data should score > 7, got {entropy}"
    
    # Empty data
    assert shannon_entropy(b"") == 0.0, "Empty data should have 0 entropy"
    
    print("✅ Shannon entropy test passed")


def test_extract_strings():
    """Test string extraction."""
    print("Testing string extraction...")
    
    # Mixed data with printable strings
    data = b"HEADER\x00\x01\x02\x03teststring\x00\x00\x00anothertest"
    strings = extract_strings(data, min_len=4)
    
    assert "teststring" in strings, "Should find 'teststring'"
    assert "anothertest" in strings, "Should find 'anothertest'"
    assert "HEADER" in strings, "Should find 'HEADER'"
    
    # Short strings should be filtered
    short_data = b"abc\x00def\x00"
    short_strings = extract_strings(short_data, min_len=4)
    assert len(short_strings) == 0, "Strings < 4 chars should be filtered"
    
    print("✅ String extraction test passed")


def test_suspicious_strings():
    """Test detection of suspicious patterns."""
    print("Testing suspicious string detection...")
    
    suspicious_patterns = [
        b"telnet\x00root\x00",
        b"password=admin",
        b"-----BEGIN RSA PRIVATE KEY-----",
        b"JTAG_DEBUG\x00",
        b"hardcoded_secret",
    ]
    
    for pattern in suspicious_patterns:
        strings = extract_strings(pattern)
        found = False
        for s in strings:
            low = s.lower()
            if any(tok in low for tok in ("telnet", "root", "password", "private key", "jtag", "debug", "hardcoded")):
                found = True
                break
        assert found, f"Should detect suspicious pattern in {pattern}"
    
    print("✅ Suspicious string detection test passed")


def test_hash_file():
    """Test file hashing."""
    print("Testing file hashing...")
    
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp_path = Path(tmp.name)
        test_data = b"Test firmware data for hashing"
        tmp.write(test_data)
        tmp.close()
    
    try:
        # Hash the file
        hash1 = hash_file(tmp_path, "sha256")
        assert len(hash1) == 64, "SHA-256 should be 64 hex chars"
        
        # Hash should be deterministic
        hash2 = hash_file(tmp_path, "sha256")
        assert hash1 == hash2, "Same file should produce same hash"
        
        # Verify it matches expected value
        import hashlib
        expected = hashlib.sha256(test_data).hexdigest()
        assert hash1 == expected, f"Hash mismatch: {hash1} != {expected}"
        
        print("✅ File hashing test passed")
    finally:
        tmp_path.unlink()


def test_scan_file_basic():
    """Test basic firmware file scanning."""
    print("Testing firmware file scanning...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Create test firmware with various patterns
        firmware_data = b"TEST_FW_HEADER" + os.urandom(512) + b"telnet\x00root\x00admin" + b"\x00" * 256
        fw_path = tmpdir / "test_firmware.bin"
        fw_path.write_bytes(firmware_data)
        
        # Scan without YARA rules (rules might not be available)
        result = scan_file(fw_path, None)
        
        # Verify basic fields
        assert result["file"] == "test_firmware.bin", "File name should match"
        assert result["size_bytes"] > 0, "Size should be > 0"
        assert len(result["sha256"]) == 64, "Should have valid SHA-256"
        assert 0 <= result["entropy"] <= 8, "Entropy should be 0-8"
        assert result["strings_count"] > 0, "Should find some strings"
        assert isinstance(result["matches"], list), "YARA matches should be list"
        assert isinstance(result["suspicious_strings"], list), "Suspicious strings should be list"
        assert isinstance(result["recommended_mitigations"], list), "Mitigations should be list"
        assert result["severity_score"] >= 0, "Severity score should be non-negative"
        
        print("✅ Firmware file scanning test passed")


def test_signature_verification_missing_files():
    """Test signature verification when key/sig files are missing."""
    print("Testing signature verification (missing files)...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        fw_path = tmpdir / "firmware.bin"
        fw_path.write_bytes(b"test firmware data")
        
        # When called in temp dir without key/sig, should report missing
        result = verify_external_signature(fw_path)
        
        assert result["sig_found"] is False, "Should report sig not found"
        assert isinstance(result["pubkey_found"], bool), "Should report pubkey status"
        assert result["valid"] is None, "Valid should be None when skipped"
        
        print("✅ Signature verification (missing files) test passed")


def test_signature_generation_and_verification():
    """Test generating and verifying a valid signature."""
    print("Testing signature generation and verification...")
    
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa, padding
        from cryptography.hazmat.backends import default_backend
    except ImportError:
        print("⚠️  Skipping signature verification test (cryptography not available)")
        return
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # Generate a test key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        
        # Save public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        pubkey_path = tmpdir / "public_key.pem"
        pubkey_path.write_bytes(public_pem)
        
        # Create test firmware and sign it
        firmware_data = b"Test firmware for signature verification"
        fw_path = tmpdir / "firmware.bin"
        fw_path.write_bytes(firmware_data)
        
        signature = private_key.sign(
            firmware_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        
        sig_path = fw_path.with_suffix(fw_path.suffix + ".sig")
        sig_path.write_bytes(signature)
        
        # Save original paths and replace with temp versions
        import scanner
        old_pubkey = scanner.PUBKEY_PATH
        old_rules = scanner.RULES_PATH
        
        try:
            scanner.PUBKEY_PATH = pubkey_path
            scanner.RULES_PATH = Path(tmpdir) / "nonexistent.yar"  # YARA rules don't exist
            
            result = verify_external_signature(fw_path)
            
            assert result["sig_found"] is True, "Should find signature"
            assert result["pubkey_found"] is True, "Should find public key"
            assert result["valid"] is True, "Signature should be valid"
            assert result["error"] is None, "Should have no error"
            
        finally:
            scanner.PUBKEY_PATH = old_pubkey
            scanner.RULES_PATH = old_rules
        
        print("✅ Signature generation and verification test passed")


def run_all_tests():
    """Run all scanner tests."""
    print("Running AutoSecureChain Scanner Tests")
    print("=" * 50)
    
    tests = [
        test_shannon_entropy,
        test_extract_strings,
        test_suspicious_strings,
        test_hash_file,
        test_scan_file_basic,
        test_signature_verification_missing_files,
        test_signature_generation_and_verification,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"❌ {test.__name__} failed: {e}")
            import traceback
            traceback.print_exc()
            failed += 1
    
    print("=" * 50)
    print(f"Tests completed: {passed} passed, {failed} failed")
    
    if failed > 0:
        sys.exit(1)
    else:
        print("🎉 All tests passed!")


if __name__ == "__main__":
    run_all_tests()
