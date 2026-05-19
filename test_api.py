#!/usr/bin/env python3
"""
Unit tests for AutoSecureChain Flask API.
Tests REST endpoints for key management, firmware signing/verification, and audit logging.
"""
import os
import sys
import json
import tempfile
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Import after adding to path
from api import app
from auth import generate_token, verify_token


class TestClient:
    """Simple test client wrapper."""
    def __init__(self, flask_app):
        self.app = flask_app
        self.client = flask_app.test_client()


def test_api_health():
    """Test health check endpoint."""
    print("Testing API health check...")
    client = TestClient(app)
    
    response = client.client.get('/api/v1/health')
    assert response.status_code == 200, "Health check should return 200"
    
    data = json.loads(response.data)
    assert data['status'] == 'healthy', "Should be healthy"
    assert 'service' in data, "Should have service name"
    
    print("✅ Health check test passed")


def test_auth_token_generation():
    """Test JWT token generation."""
    print("Testing JWT token generation...")
    client = TestClient(app)
    
    payload = {'client_id': 'test_client', 'client_secret': 'test_secret'}
    
    response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps(payload),
        content_type='application/json'
    )
    
    assert response.status_code == 201, "Should return 201 Created"
    data = json.loads(response.data)
    assert data['status'] == 'success', "Should succeed"
    assert 'token' in data, "Should return token"
    assert data['token_type'] == 'Bearer', "Should be Bearer token"
    assert 'expires_in' in data, "Should include expiration"
    
    # Verify token is valid
    token = data['token']
    payload_data = verify_token(token)
    assert payload_data['user_id'] == 'test_client', "Token should contain client_id"
    
    print("✅ Token generation test passed")


def test_auth_required_without_token():
    """Test that protected endpoints require auth."""
    print("Testing auth requirement...")
    client = TestClient(app)
    
    # Try to list keys without token
    response = client.client.get('/api/v1/keys/list')
    assert response.status_code == 401, "Should return 401 Unauthorized"
    
    data = json.loads(response.data)
    assert 'error' in data, "Should have error message"
    
    print("✅ Auth requirement test passed")


def test_auth_with_token():
    """Test that endpoints work with valid token."""
    print("Testing endpoint access with token...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    assert token_response.status_code == 201, "Token generation should succeed"
    
    token_data = json.loads(token_response.data)
    token = token_data['token']
    
    # Use token to access protected endpoint
    headers = {'Authorization': f'Bearer {token}'}
    response = client.client.get('/api/v1/keys/list', headers=headers)
    assert response.status_code == 200, "Should return 200 with valid token"
    
    print("✅ Token-based access test passed")


def test_invalid_token():
    """Test that invalid token is rejected."""
    print("Testing invalid token rejection...")
    client = TestClient(app)
    
    headers = {'Authorization': 'Bearer invalid_token_xyz'}
    response = client.client.get('/api/v1/keys/list', headers=headers)
    assert response.status_code == 401, "Should return 401 for invalid token"
    
    print("✅ Invalid token rejection test passed")


def test_malformed_auth_header():
    """Test that malformed auth header is rejected."""
    print("Testing malformed auth header...")
    client = TestClient(app)
    
    # Missing Bearer prefix
    headers = {'Authorization': 'token_without_prefix'}
    response = client.client.get('/api/v1/keys/list', headers=headers)
    assert response.status_code == 401, "Should return 401"
    
    print("✅ Malformed auth header test passed")


def test_api_info():
    """Test API info endpoint."""
    print("Testing API info endpoint...")
    client = TestClient(app)
    
    response = client.client.get('/api/v1/info')
    assert response.status_code == 200, "Info endpoint should return 200"
    
    data = json.loads(response.data)
    assert 'endpoints' in data, "Should list endpoints"
    assert 'keys' in data['endpoints'], "Should have keys endpoints"
    assert 'firmware' in data['endpoints'], "Should have firmware endpoints"
    
    print("✅ API info test passed")


def test_generate_key_endpoint():
    """Test key generation via API."""
    print("Testing key generation endpoint...")
    client = TestClient(app)
    
    # Get token first
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    payload = {
        'name': 'test_api_key',
        'size': 2048,
        'passphrase': 'test_pass123',
        'use_keyring': False
    }
    
    response = client.client.post(
        '/api/v1/keys/generate',
        data=json.dumps(payload),
        content_type='application/json',
        headers=headers
    )
    
    assert response.status_code == 201, "Should return 201 Created"
    data = json.loads(response.data)
    assert data['status'] == 'success', "Should succeed"
    assert 'key_id' in data, "Should return key ID"
    assert 'info' in data, "Should return key info"
    
    print("✅ Key generation endpoint test passed")


def test_list_keys_endpoint():
    """Test listing keys via API."""
    print("Testing list keys endpoint...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    # First generate a key
    gen_payload = {'name': 'list_test_key', 'size': 2048}
    gen_response = client.client.post(
        '/api/v1/keys/generate',
        data=json.dumps(gen_payload),
        content_type='application/json',
        headers=headers
    )
    assert gen_response.status_code == 201, "Key generation should succeed"
    
    # Then list keys
    response = client.client.get('/api/v1/keys/list', headers=headers)
    assert response.status_code == 200, "Should return 200"
    
    data = json.loads(response.data)
    assert data['status'] == 'success', "Should succeed"
    assert isinstance(data['keys'], list), "Keys should be a list"
    assert data['count'] >= 0, "Should report count"
    
    print("✅ List keys endpoint test passed")


def test_get_key_info_endpoint():
    """Test getting key info via API."""
    print("Testing key info endpoint...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    # Generate a key first
    gen_payload = {'name': 'info_test_key', 'size': 2048}
    gen_response = client.client.post(
        '/api/v1/keys/generate',
        data=json.dumps(gen_payload),
        content_type='application/json',
        headers=headers
    )
    assert gen_response.status_code == 201, "Key generation should succeed"
    
    # Get key info
    response = client.client.get('/api/v1/keys/info_test_key', headers=headers)
    assert response.status_code == 200, "Should return 200"
    
    data = json.loads(response.data)
    assert data['status'] == 'success', "Should succeed"
    assert 'key_info' in data, "Should return key info"
    
    print("✅ Key info endpoint test passed")


def test_key_info_not_found():
    """Test 404 for non-existent key."""
    print("Testing key info 404 handling...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    response = client.client.get('/api/v1/keys/nonexistent_key_xyz', headers=headers)
    assert response.status_code == 404, "Should return 404"
    
    data = json.loads(response.data)
    assert 'error' in data, "Should have error message"
    
    print("✅ Key info 404 test passed")


def test_sign_firmware_endpoint():
    """Test firmware signing via API."""
    print("Testing firmware signing endpoint...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    # Generate a key
    gen_payload = {'name': 'sign_test_key', 'size': 2048}
    gen_response = client.client.post(
        '/api/v1/keys/generate',
        data=json.dumps(gen_payload),
        content_type='application/json',
        headers=headers
    )
    assert gen_response.status_code == 201, "Key generation should succeed"
    
    # Create test firmware
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp.write(b"Test firmware content for signing")
        tmp_path = tmp.name
    
    try:
        # Upload and sign
        with open(tmp_path, 'rb') as fw_file:
            response = client.client.post(
                '/api/v1/firmware/sign',
                data={
                    'file': fw_file,
                    'key': 'sign_test_key'
                },
                headers=headers
            )
        
        assert response.status_code == 200, "Should return 200"
        data = json.loads(response.data)
        assert data['status'] == 'success', "Should succeed"
        assert 'signature_path' in data, "Should return signature path"
        
        print("✅ Firmware signing endpoint test passed")
    finally:
        os.unlink(tmp_path)


def test_verify_firmware_endpoint():
    """Test firmware verification via API."""
    print("Testing firmware verification endpoint...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    # Generate a key
    gen_payload = {'name': 'verify_test_key', 'size': 2048}
    gen_response = client.client.post(
        '/api/v1/keys/generate',
        data=json.dumps(gen_payload),
        content_type='application/json',
        headers=headers
    )
    assert gen_response.status_code == 201, "Key generation should succeed"
    
    # Create and sign firmware
    with tempfile.NamedTemporaryFile(suffix='.bin', delete=False) as tmp:
        tmp.write(b"Test firmware for verification")
        tmp_path = tmp.name
    
    try:
        # Sign first
        with open(tmp_path, 'rb') as fw_file:
            sign_response = client.client.post(
                '/api/v1/firmware/sign',
                data={
                    'file': fw_file,
                    'key': 'verify_test_key'
                },
                headers=headers
            )
        assert sign_response.status_code == 200, "Signing should succeed"
        
        # Then verify
        with open(tmp_path, 'rb') as fw_file:
            response = client.client.post(
                '/api/v1/firmware/verify',
                data={
                    'file': fw_file,
                    'key': 'verify_test_key'
                },
                headers=headers
            )
        
        assert response.status_code == 200, "Should return 200"
        data = json.loads(response.data)
        assert data['status'] == 'success', "Should succeed"
        assert data['valid'] is True, "Signature should be valid"
        
        print("✅ Firmware verification endpoint test passed")
    finally:
        os.unlink(tmp_path)


def test_audit_recent_endpoint():
    """Test recent audit events endpoint."""
    print("Testing audit recent endpoint...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    response = client.client.get('/api/v1/audit/recent?limit=10', headers=headers)
    assert response.status_code == 200, "Should return 200"
    
    data = json.loads(response.data)
    assert data['status'] == 'success', "Should succeed"
    assert isinstance(data['events'], list), "Events should be a list"
    
    print("✅ Audit recent endpoint test passed")


def test_audit_search_endpoint():
    """Test audit search endpoint."""
    print("Testing audit search endpoint...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    response = client.client.get('/api/v1/audit/search?severity=info&limit=10', headers=headers)
    assert response.status_code == 200, "Should return 200"
    
    data = json.loads(response.data)
    assert data['status'] == 'success', "Should succeed"
    assert 'filters' in data, "Should show filters applied"
    
    print("✅ Audit search endpoint test passed")


def test_missing_json_field():
    """Test JSON validation."""
    print("Testing JSON field validation...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    # Missing 'name' field
    payload = {'size': 2048}
    
    response = client.client.post(
        '/api/v1/keys/generate',
        data=json.dumps(payload),
        content_type='application/json',
        headers=headers
    )
    
    assert response.status_code == 400, "Should return 400 for missing field"
    data = json.loads(response.data)
    assert 'error' in data, "Should have error message"
    
    print("✅ JSON validation test passed")


def test_invalid_key_size():
    """Test invalid key size validation."""
    print("Testing key size validation...")
    client = TestClient(app)
    
    # Get token
    token_response = client.client.post(
        '/api/v1/auth/token',
        data=json.dumps({'client_id': 'test_client'}),
        content_type='application/json'
    )
    token = json.loads(token_response.data)['token']
    headers = {'Authorization': f'Bearer {token}'}
    
    payload = {'name': 'bad_key', 'size': 1024}  # Invalid size
    
    response = client.client.post(
        '/api/v1/keys/generate',
        data=json.dumps(payload),
        content_type='application/json',
        headers=headers
    )
    
    assert response.status_code == 400, "Should reject invalid key size"
    data = json.loads(response.data)
    assert 'error' in data, "Should have error message"
    
    print("✅ Key size validation test passed")


def run_all_tests():
    """Run all API tests."""
    print("Running AutoSecureChain API Tests")
    print("=" * 50)
    
    tests = [
        test_api_health,
        test_auth_token_generation,
        test_auth_required_without_token,
        test_auth_with_token,
        test_invalid_token,
        test_malformed_auth_header,
        test_api_info,
        test_generate_key_endpoint,
        test_list_keys_endpoint,
        test_get_key_info_endpoint,
        test_key_info_not_found,
        test_sign_firmware_endpoint,
        test_verify_firmware_endpoint,
        test_audit_recent_endpoint,
        test_audit_search_endpoint,
        test_missing_json_field,
        test_invalid_key_size,
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
    print(f"API Tests completed: {passed} passed, {failed} failed")
    
    if failed > 0:
        sys.exit(1)
    else:
        print("🎉 All API tests passed!")


if __name__ == "__main__":
    # Disable debug mode for tests
    app.config['TESTING'] = True
    run_all_tests()
