#!/usr/bin/env python3
"""
End-to-end integration tests for AutoSecureChain.
Tests the complete workflow: key generation → firmware signing → scanning → report generation.
"""
import os
import sys
import json
import tempfile
from pathlib import Path

# Add scanner directory to path
sys.path.insert(0, str(Path(__file__).parent))

from key_manager import KeyManager, AuditLogger
import scanner
from scanner import scan_file, main as scan_main


def test_e2e_sign_scan_report():
    """Full E2E: Generate key → Sign firmware → Scan → Generate report."""
    print("Testing E2E workflow: sign → scan → report...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # === Step 1: Generate keypair ===
        key_dir = tmpdir / "keys"
        key_manager = KeyManager(key_dir)
        
        result = key_manager.generate_keypair("e2e_test_key", 2048)
        assert result["key_id"], "Key ID should be generated"
        print(f"  ✓ Generated keypair: {result['key_id']}")
        
        # === Step 2: Create test firmware ===
        firmware_dir = tmpdir / "firmware"
        firmware_dir.mkdir()
        
        # Create firmware with various characteristics
        test_firmware = b"ECU_FIRMWARE_V1.0" + os.urandom(1024) + b"telnet\x00root\x00password123"
        firmware_path = firmware_dir / "test_ecu.bin"
        firmware_path.write_bytes(test_firmware)
        print(f"  ✓ Created test firmware: {firmware_path.name}")
        
        # === Step 3: Sign firmware ===
        sig_path = key_manager.sign_firmware(firmware_path, "e2e_test_key")
        assert sig_path.exists(), "Signature file should be created"
        print(f"  ✓ Signed firmware: {sig_path.name}")
        
        # === Step 4: Verify signature was created ===
        sig_data = sig_path.read_bytes()
        assert len(sig_data) > 0, "Signature should not be empty"
        print(f"  ✓ Signature size: {len(sig_data)} bytes")
        
        # === Step 5: Scan firmware (patch scanner's pubkey path) ===
        old_pubkey = scanner.PUBKEY_PATH
        scanner.PUBKEY_PATH = key_dir / "e2e_test_key_public.pem"
        
        try:
            result = scan_file(firmware_path, None)  # No YARA rules for test
            assert result["file"] == "test_ecu.bin", "File name mismatch"
            assert result["size_bytes"] > 0, "File size should be recorded"
            assert len(result["sha256"]) == 64, "SHA-256 hash should be present"
            assert result["entropy"] > 0, "Entropy should be calculated"
            assert "signature" in result, "Signature verification info should be present"
            print(f"  ✓ Scanned firmware: severity={result['severity_score']}, entropy={result['entropy']:.2f}")
            
            # === Step 6: Verify signature was detected ===
            sig_info = result["signature"]
            assert sig_info["sig_found"] is True, "Signature file should be found"
            assert sig_info["pubkey_found"] is True, "Public key should be found"
            assert sig_info["valid"] is True, "Signature should be valid"
            print(f"  ✓ Signature verified: valid={sig_info['valid']}")
            
            # === Step 7: Verify suspicious strings detected ===
            assert len(result["suspicious_strings"]) > 0, "Should detect suspicious strings"
            assert any("telnet" in s.lower() for s in result["suspicious_strings"]), "Should detect 'telnet'"
            print(f"  ✓ Detected {len(result['suspicious_strings'])} suspicious strings")
            
            # === Step 8: Verify mitigations suggested ===
            assert len(result["recommended_mitigations"]) > 0, "Should suggest mitigations"
            mitigation_ids = [m["id"] for m in result["recommended_mitigations"]]
            assert "disable_telnet" in mitigation_ids, "Should suggest disabling telnet"
            print(f"  ✓ Suggested {len(result['recommended_mitigations'])} mitigations")
            
            # === Step 9: Check audit log ===
            audit_log = key_manager.get_audit_log()
            assert len(audit_log) > 0, "Audit log should have entries"
            actions = [entry["action"] for entry in audit_log]
            assert "key_generated" in actions, "Should log key generation"
            assert "firmware_signed" in actions, "Should log firmware signing"
            # Signature verification may be logged by the scanner AuditLogger (separate log); do not require it here
            print(f"  ✓ Audit log: {len(audit_log)} entries")
            
            print("✅ E2E sign → scan → report test passed!")
            return True
        finally:
            scanner.PUBKEY_PATH = old_pubkey


def test_e2e_invalid_signature_detection():
    """E2E test: Verify detection of invalid/tampered firmware."""
    print("Testing E2E workflow: tampered firmware detection...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # === Step 1: Generate key and sign firmware ===
        key_dir = tmpdir / "keys"
        key_manager = KeyManager(key_dir)
        key_manager.generate_keypair("tamper_test_key", 2048)
        
        firmware_dir = tmpdir / "firmware"
        firmware_dir.mkdir()
        
        firmware_data = b"ORIGINAL_FIRMWARE_DATA" + os.urandom(512)
        firmware_path = firmware_dir / "firmware_to_tamper.bin"
        firmware_path.write_bytes(firmware_data)
        
        sig_path = key_manager.sign_firmware(firmware_path, "tamper_test_key")
        print(f"  ✓ Created and signed firmware")
        
        # === Step 2: Tamper with firmware (modify content) ===
        tampered_data = firmware_data + b"TAMPERED"
        firmware_path.write_bytes(tampered_data)
        print(f"  ✓ Tampered with firmware content")
        
        # === Step 3: Scan tampered firmware (patch scanner's pubkey path) ===
        old_pubkey = scanner.PUBKEY_PATH
        scanner.PUBKEY_PATH = key_dir / "tamper_test_key_public.pem"
        
        try:
            result = scan_file(firmware_path, None)
            sig_info = result["signature"]
            
            # === Step 4: Verify tampering was detected ===
            assert sig_info["sig_found"] is True, "Signature should still be found"
            assert sig_info["valid"] is False, "Signature should be invalid (tampering detected)"
            assert sig_info["error"] is not None, "Should have error message about invalid signature"
            print(f"  ✓ Tampering detected: valid={sig_info['valid']}")
            
            # === Step 5: Verify severity increased ===
            assert result["severity_score"] > 0, "Severity should be increased for tampered firmware"
            print(f"  ✓ Severity score increased: {result['severity_score']}")
            
            # === Step 6: Verify mitigation suggested ===
            mitigation_ids = [m["id"] for m in result["recommended_mitigations"]]
            assert "require_fw_signing" in mitigation_ids, "Should suggest enforcing fw signing"
            print(f"  ✓ Mitigations suggested for tampered firmware")
            
            print("✅ E2E tampered firmware detection test passed!")
            return True
        finally:
            scanner.PUBKEY_PATH = old_pubkey


def test_e2e_key_rotation():
    """E2E test: Key rotation and continued scanning."""
    print("Testing E2E workflow: key rotation...")
    
    with tempfile.TemporaryDirectory() as tmpdir:
        tmpdir = Path(tmpdir)
        
        # === Step 1: Generate initial key ===
        key_dir = tmpdir / "keys"
        key_manager = KeyManager(key_dir)
        initial_result = key_manager.generate_keypair("rotation_test", 2048)
        initial_key_id = initial_result["key_id"]
        print(f"  ✓ Generated initial key: {initial_key_id}")
        
        # === Step 2: Sign firmware with initial key ===
        firmware_dir = tmpdir / "firmware"
        firmware_dir.mkdir()
        firmware_path = firmware_dir / "firmware_v1.bin"
        firmware_path.write_bytes(b"FIRMWARE_V1" + os.urandom(256))
        
        sig_path = key_manager.sign_firmware(firmware_path, "rotation_test")
        print(f"  ✓ Signed firmware with initial key")
        
        # === Step 3: Verify with initial key (patch pubkey path) ===
        old_pubkey = scanner.PUBKEY_PATH
        scanner.PUBKEY_PATH = key_dir / "rotation_test_public.pem"
        
        try:
            result1 = scan_file(firmware_path, None)
            assert result1["signature"]["valid"] is True, "Initial signature should be valid"
            print(f"  ✓ Firmware verified with initial key")
            
            # === Step 4: Rotate to new key ===
            rotated_result = key_manager.rotate_key("rotation_test", "rotation_test_rotated")
            new_key_id = rotated_result["key_id"]
            assert new_key_id != initial_key_id, "New key should have different ID"
            print(f"  ✓ Rotated to new key: {new_key_id}")
            
            # === Step 5: Verify old key marked as rotated ===
            old_info = key_manager.get_key_info("rotation_test")
            assert old_info["status"] == "rotated", "Old key should be marked as rotated"
            assert old_info["rotated_to"] == new_key_id, "Should reference new key"
            print(f"  ✓ Old key marked as rotated")
            
            # === Step 6: Old signature should still verify ===
            result2 = scan_file(firmware_path, None)
            assert result2["signature"]["valid"] is True, "Old signature should still verify"
            print(f"  ✓ Old firmware still verifies with rotated key")
            
            # === Step 7: Sign new firmware with new key ===
            firmware_v2_path = firmware_dir / "firmware_v2.bin"
            firmware_v2_path.write_bytes(b"FIRMWARE_V2" + os.urandom(256))
            
            sig_v2_path = key_manager.sign_firmware(firmware_v2_path, "rotation_test_rotated")
            # Update scanner to point at the new public key for verification
            scanner.PUBKEY_PATH = key_dir / "rotation_test_rotated_public.pem"
            result3 = scan_file(firmware_v2_path, None)
            assert result3["signature"]["valid"] is True, "New signature with rotated key should be valid"
            print(f"  ✓ New firmware signed and verified with rotated key")
            
            # === Step 8: Audit log tracks rotation ===
            audit_log = key_manager.get_audit_log()
            actions = [entry["action"] for entry in audit_log]
            assert "key_rotated" in actions, "Should log key rotation"
            print(f"  ✓ Key rotation logged in audit trail")
            
            print("✅ E2E key rotation test passed!")
            return True
        finally:
            scanner.PUBKEY_PATH = old_pubkey


def run_all_tests():
    """Run all E2E tests."""
    print("Running AutoSecureChain E2E Integration Tests")
    print("=" * 60)
    
    tests = [
        test_e2e_sign_scan_report,
        test_e2e_invalid_signature_detection,
        test_e2e_key_rotation,
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
        print()
    
    print("=" * 60)
    print(f"E2E Tests completed: {passed} passed, {failed} failed")
    
    if failed > 0:
        sys.exit(1)
    else:
        print("🎉 All E2E tests passed!")


if __name__ == "__main__":
    run_all_tests()
