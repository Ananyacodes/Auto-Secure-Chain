#!/usr/bin/env python3
"""
JWT authentication and rate limiting for AutoSecureChain API.
Provides token generation, verification, and Flask decorators for route protection.
"""
import os
import jwt
from datetime import datetime, timedelta
from functools import wraps
from flask import request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

# JWT Configuration
JWT_SECRET = os.environ.get('AUTOS_JWT_SECRET', 'autosecurechain-dev-secret-key-change-in-production')
JWT_ALGORITHM = 'HS256'
JWT_EXP_DELTA_SECONDS = 3600  # 1 hour token validity

# Rate limiter instances
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per day", "50 per hour"])
strict_limiter = Limiter(key_func=get_remote_address, default_limits=["10 per hour"])  # For auth endpoints
api_limiter = Limiter(key_func=get_remote_address, default_limits=["100 per hour"])  # For API endpoints


def generate_token(user_id: str, metadata: dict = None) -> str:
    """
    Generate a JWT token for the given user.
    
    Args:
        user_id: Unique identifier for the user
        metadata: Optional dict with additional claims
    
    Returns:
        JWT token string
    """
    payload = {
        'user_id': user_id,
        'iat': datetime.utcnow(),
        'exp': datetime.utcnow() + timedelta(seconds=JWT_EXP_DELTA_SECONDS),
    }
    
    if metadata:
        payload.update(metadata)
    
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return token


def verify_token(token: str) -> dict:
    """
    Verify a JWT token and return the payload.
    
    Args:
        token: JWT token string
    
    Returns:
        Decoded payload dict
    
    Raises:
        jwt.InvalidTokenError: If token is invalid or expired
    """
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise ValueError("Token has expired")
    except jwt.InvalidTokenError as e:
        raise ValueError(f"Invalid token: {str(e)}")


def extract_token_from_request() -> str:
    """
    Extract JWT token from Authorization header.
    Expected format: "Bearer <token>"
    
    Returns:
        Token string
    
    Raises:
        ValueError: If token not found or invalid format
    """
    auth_header = request.headers.get('Authorization', '')
    
    if not auth_header:
        raise ValueError("Missing Authorization header")
    
    parts = auth_header.split()
    if len(parts) != 2 or parts[0] != 'Bearer':
        raise ValueError("Invalid Authorization header format. Expected: Bearer <token>")
    
    return parts[1]


def require_auth(f):
    """
    Decorator to require JWT authentication for a route.
    Extracts and validates token from Authorization header.
    
    Usage:
        @app.route('/protected')
        @require_auth
        def protected_route():
            return jsonify({'status': 'ok'})
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            token = extract_token_from_request()
            payload = verify_token(token)
            # Store payload in request context
            request.jwt_payload = payload
            return f(*args, **kwargs)
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        except Exception as e:
            return jsonify({'error': f'Authentication failed: {str(e)}'}), 401
    
    return decorated_function


def require_auth_optional(f):
    """
    Decorator that validates token if present, but doesn't require it.
    Useful for endpoints that provide different responses based on auth status.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        request.jwt_payload = None
        try:
            token = extract_token_from_request()
            payload = verify_token(token)
            request.jwt_payload = payload
        except (ValueError, Exception):
            # Token not provided or invalid - continue without auth
            pass
        
        return f(*args, **kwargs)
    
    return decorated_function


def rate_limit_auth(f):
    """
    Apply strict rate limiting to authentication endpoints (e.g., /auth/token).
    Prevents brute force attacks on auth endpoints.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    
    # Chain the limiter
    decorated_function = strict_limiter.limit("10 per hour")(decorated_function)
    return decorated_function


def rate_limit_api(f):
    """
    Apply API rate limiting to firmware operations (sign/verify).
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        return f(*args, **kwargs)
    
    # Chain the limiter
    decorated_function = api_limiter.limit("100 per hour")(decorated_function)
    return decorated_function
