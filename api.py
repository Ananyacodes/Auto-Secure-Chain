#!/usr/bin/env python3
"""
Flask REST API for AutoSecureChain.
Provides REST endpoints for firmware signing, verification, key management, and audit logging.
"""
import os
import sys
import json
from pathlib import Path
from functools import wraps

from flask import Flask, request, jsonify
from flask_cors import CORS
from werkzeug.utils import secure_filename

from auth import (
    generate_token, require_auth, rate_limit_auth, 
    rate_limit_api, limiter, JWT_EXP_DELTA_SECONDS
)

# Add scanner directory to path
scanner_dir = Path(__file__).resolve().parent / "AutoSecureChain" / "scanner"
sys.path.insert(0, str(scanner_dir.parent.parent))
if str(scanner_dir) not in sys.path:
    sys.path.insert(0, str(scanner_dir))

from AutoSecureChain.scanner.key_manager import KeyManager, AuditLogger

# Initialize Flask app
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100 MB max upload

# Set upload folder with fallback
try:
    upload_dir = Path.home() / ".autosecurechain" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
except PermissionError:
    # Fallback to workspace-local uploads
    upload_dir = Path(__file__).parent / ".autosecurechain" / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)

app.config['UPLOAD_FOLDER'] = upload_dir

# Initialize rate limiter and CORS
limiter.init_app(app)
CORS(app, origins=['http://localhost:3000', 'http://localhost:5000'], 
     supports_credentials=True)

# Initialize key manager and audit logger
key_manager = KeyManager()
audit_logger = AuditLogger()


def validate_json(*required_fields):
    """Decorator to validate JSON request has required fields."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({"error": "Request must be JSON"}), 400
            
            data = request.get_json()
            for field in required_fields:
                if field not in data or data[field] is None:
                    return jsonify({"error": f"Missing required field: {field}"}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def validate_file_upload():
    """Decorator to validate file upload."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'file' not in request.files:
                return jsonify({"error": "Missing required file upload"}), 400
            
            file = request.files['file']
            if file.filename == '':
                return jsonify({"error": "Empty filename"}), 400
            
            if not file:
                return jsonify({"error": "Invalid file"}), 400
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ===== AUTHENTICATION ENDPOINTS =====

@app.route('/api/v1/auth/token', methods=['POST'])
@validate_json('client_id')
@rate_limit_auth
def get_auth_token():
    """Generate JWT token for API access.
    
    Request:
        {
            "client_id": "my_app",
            "client_secret": "optional_secret"
        }
    """
    try:
        data = request.get_json()
        client_id = data.get('client_id')
        client_secret = data.get('client_secret', '')
        
        # In production, validate client_secret against stored credentials
        token = generate_token(client_id, {'client_secret_provided': bool(client_secret)})
        
        audit_logger.log_event(
            "auth_token_generated",
            "info",
            f"Token generated for client: {client_id}"
        )
        
        return jsonify({
            "status": "success",
            "token": token,
            "token_type": "Bearer",
            "expires_in": JWT_EXP_DELTA_SECONDS
        }), 201
    
    except Exception as e:
        audit_logger.log_event("auth_error", "error", f"Token generation failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ===== KEY MANAGEMENT ENDPOINTS =====

@app.route('/api/v1/keys/generate', methods=['POST'])
@validate_json('name', 'size')
@require_auth
@rate_limit_api
def generate_key():
    """Generate a new RSA keypair.
    
    Request:
        {
            "name": "production",
            "size": 4096,
            "passphrase": "optional_passphrase",
            "use_keyring": false
        }
    """
    try:
        data = request.get_json()
        name = secure_filename(data['name'])
        size = int(data.get('size', 4096))
        passphrase = data.get('passphrase')
        use_keyring = data.get('use_keyring', False)
        
        # Validate size
        if size not in [2048, 3072, 4096]:
            return jsonify({"error": "Key size must be 2048, 3072, or 4096"}), 400
        
        result = key_manager.generate_keypair(name, size, passphrase=passphrase, use_keyring=use_keyring)
        
        audit_logger.log_key_operation("generate_via_api", result['key_id'], True, {"name": name, "size": size})
        
        return jsonify({
            "status": "success",
            "key_id": result['key_id'],
            "private_key_path": result['private_key_path'],
            "public_key_path": result['public_key_path'],
            "info": result['info']
        }), 201
    
    except Exception as e:
        audit_logger.log_event("api_error", "error", f"Key generation failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/keys/list', methods=['GET'])
@require_auth
@rate_limit_api
def list_keys():
    """List all managed keys."""
    try:
        keys = key_manager.list_keys()
        return jsonify({
            "status": "success",
            "keys": keys,
            "count": len(keys)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/keys/<key_name>', methods=['GET'])
@require_auth
@rate_limit_api
def get_key_info(key_name):
    """Get information about a specific key."""
    try:
        key_name = secure_filename(key_name)
        info = key_manager.get_key_info(key_name)
        return jsonify({
            "status": "success",
            "key_info": info
        }), 200
    except FileNotFoundError:
        return jsonify({"error": f"Key not found: {key_name}"}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/keys/<key_name>/rotate', methods=['POST'])
@validate_json('new_key_name')
@require_auth
@rate_limit_api
def rotate_key(key_name):
    """Rotate a key to a new one."""
    try:
        data = request.get_json()
        key_name = secure_filename(key_name)
        new_key_name = secure_filename(data['new_key_name'])
        
        result = key_manager.rotate_key(key_name, new_key_name)
        
        audit_logger.log_key_operation("rotate_via_api", result['key_id'], True, 
                                      {"old_key": key_name, "new_key": new_key_name})
        
        return jsonify({
            "status": "success",
            "message": f"Key rotated: {key_name} -> {new_key_name}",
            "new_key_id": result['key_id']
        }), 200
    
    except Exception as e:
        audit_logger.log_event("api_error", "error", f"Key rotation failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ===== FIRMWARE SIGNING & VERIFICATION ENDPOINTS =====

@app.route('/api/v1/firmware/sign', methods=['POST'])
@validate_file_upload()
@require_auth
@rate_limit_api
def sign_firmware():
    """Sign firmware file.
    
    Request: multipart/form-data
        file: firmware binary
        key: key name (default: "production")
        backend: "local" or "kms" (default: "local")
        kms_key_id: optional KMS key ID
    """
    try:
        file = request.files['file']
        key_name = request.form.get('key', 'production')
        key_name = secure_filename(key_name)
        backend = request.form.get('backend', 'local')
        kms_key_id = request.form.get('kms_key_id')
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = app.config['UPLOAD_FOLDER'] / filename
        file.save(str(filepath))
        
        # Sign firmware
        sig_path = key_manager.sign_firmware(
            filepath, 
            key_name, 
            backend=backend, 
            kms_key_id=kms_key_id
        )
        
        audit_logger.log_key_operation("sign_via_api", key_name, True, 
                                      {"firmware": filename, "backend": backend})
        
        return jsonify({
            "status": "success",
            "message": f"Firmware signed successfully",
            "firmware": filename,
            "signature_path": str(sig_path),
            "key_used": key_name
        }), 200
    
    except Exception as e:
        audit_logger.log_event("api_error", "error", f"Firmware signing failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/firmware/verify', methods=['POST'])
@validate_file_upload()
@require_auth
@rate_limit_api
def verify_firmware():
    """Verify firmware signature.
    
    Request: multipart/form-data
        file: firmware binary
        key: key name (default: "production")
    """
    try:
        file = request.files['file']
        key_name = request.form.get('key', 'production')
        key_name = secure_filename(key_name)
        
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = app.config['UPLOAD_FOLDER'] / filename
        file.save(str(filepath))
        
        # Verify signature
        is_valid = key_manager.verify_signature(filepath, key_name)
        
        audit_logger.log_key_operation("verify_via_api", key_name, is_valid, 
                                      {"firmware": filename, "valid": is_valid})
        
        return jsonify({
            "status": "success",
            "valid": is_valid,
            "firmware": filename,
            "key_used": key_name,
            "message": "Signature is valid" if is_valid else "Signature is invalid"
        }), 200
    
    except FileNotFoundError as e:
        return jsonify({"error": f"File not found: {str(e)}"}), 404
    except Exception as e:
        audit_logger.log_event("api_error", "error", f"Firmware verification failed: {str(e)}")
        return jsonify({"error": str(e)}), 500


# ===== AUDIT LOGGING ENDPOINTS =====

@app.route('/api/v1/audit/recent', methods=['GET'])
@require_auth
@rate_limit_api
def get_recent_audit():
    """Get recent audit events.
    
    Query params:
        limit: number of events (default: 50, max: 1000)
    """
    try:
        limit = min(int(request.args.get('limit', 50)), 1000)
        events = audit_logger.get_recent_events(limit)
        
        return jsonify({
            "status": "success",
            "events": events,
            "count": len(events)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/v1/audit/search', methods=['GET'])
@require_auth
@rate_limit_api
def search_audit():
    """Search audit events.
    
    Query params:
        event_type: filter by event type
        severity: filter by severity (info, warning, error)
        limit: number of events (default: 100, max: 1000)
    """
    try:
        event_type = request.args.get('event_type')
        severity = request.args.get('severity')
        limit = min(int(request.args.get('limit', 100)), 1000)
        
        events = audit_logger.search_events(event_type, severity, limit)
        
        return jsonify({
            "status": "success",
            "events": events,
            "count": len(events),
            "filters": {
                "event_type": event_type,
                "severity": severity
            }
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ===== HEALTH & INFO ENDPOINTS =====

@app.route('/api/v1/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "AutoSecureChain API",
        "version": "1.0.0"
    }), 200


@app.route('/api/v1/info', methods=['GET'])
def get_info():
    """Get API information."""
    return jsonify({
        "service": "AutoSecureChain REST API",
        "version": "1.0.0",
        "authentication": "Bearer token required for most endpoints. Get token from POST /api/v1/auth/token",
        "endpoints": {
            "auth": {
                "get_token": "POST /api/v1/auth/token (no auth required)"
            },
            "keys": {
                "generate": "POST /api/v1/keys/generate (requires auth)",
                "list": "GET /api/v1/keys/list (requires auth)",
                "get_info": "GET /api/v1/keys/<key_name> (requires auth)",
                "rotate": "POST /api/v1/keys/<key_name>/rotate (requires auth)"
            },
            "firmware": {
                "sign": "POST /api/v1/firmware/sign (requires auth)",
                "verify": "POST /api/v1/firmware/verify (requires auth)"
            },
            "audit": {
                "recent": "GET /api/v1/audit/recent (requires auth)",
                "search": "GET /api/v1/audit/search (requires auth)"
            },
            "public": {
                "health": "GET /api/v1/health (no auth required)",
                "info": "GET /api/v1/info (no auth required)"
            }
        }
    }), 200


# ===== ERROR HANDLERS =====

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({"error": "Endpoint not found"}), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return jsonify({"error": "Method not allowed"}), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    # Run development server
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
