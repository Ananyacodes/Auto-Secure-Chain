# JWT Authentication and Rate Limiting Documentation

## Authentication

### Getting a Token

All protected endpoints require a valid JWT Bearer token. Get one via:

```bash
POST /api/v1/auth/token
Content-Type: application/json

{
  "client_id": "my_app",
  "client_secret": "optional_secret"
}

Response (201):
{
  "status": "success",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGc...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

### Using the Token

Include the token in all protected endpoint requests:

```bash
GET /api/v1/keys/list
Authorization: Bearer <token>
```

### Token Details

- **Algorithm**: HS256
- **Expiration**: 1 hour (3600 seconds)
- **Secret**: Set via `AUTOS_JWT_SECRET` environment variable (default: `autosecurechain-dev-secret-key-change-in-production`)
- **Claims**: `user_id`, `iat`, `exp`, optional metadata

## Rate Limiting

### Limits by Endpoint Type

| Endpoint Type | Limit | Purpose |
|---|---|---|
| Authentication (`/auth/*`) | 10 per hour | Prevent brute force |
| API Operations (`/keys/*, /firmware/*, /audit/*`) | 100 per hour | Prevent abuse |
| Global Limit | 200 per day, 50 per hour | Overall protection |

### Public Endpoints (No Auth Required)

- `GET /api/v1/health` - No limits
- `GET /api/v1/info` - No limits

### Protected Endpoints (Auth Required)

**Key Management** (100 per hour):
- `POST /api/v1/keys/generate`
- `GET /api/v1/keys/list`
- `GET /api/v1/keys/<key_name>`
- `POST /api/v1/keys/<key_name>/rotate`

**Firmware Operations** (100 per hour):
- `POST /api/v1/firmware/sign`
- `POST /api/v1/firmware/verify`

**Audit Logging** (100 per hour):
- `GET /api/v1/audit/recent`
- `GET /api/v1/audit/search`

### Rate Limit Response

When limit exceeded:

```json
{
  "error": "Rate limit exceeded"
}
```

HTTP Status: `429 Too Many Requests`

## Configuration

### Environment Variables

```bash
# JWT secret (recommended: 32+ characters, random string)
export AUTOS_JWT_SECRET="your-secret-key-here"

# API port
export PORT=5000

# Upload folder (optional, defaults to ~/.autosecurechain/uploads)
export AUTOS_UPLOAD_DIR="/path/to/uploads"
```

### Storage Backend for Production

In-memory rate limiting is used by default (development only). For production, configure a persistent storage backend:

```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_redis import FlaskRedis

redis = FlaskRedis()
limiter = Limiter(
    storage_uri="redis://localhost:6379"
)
```

See [Flask-Limiter Documentation](https://flask-limiter.readthedocs.io) for more storage options (Redis, Memcached, etc.).

## Testing

Run API tests including auth and rate limiting:

```bash
python test_api.py
```

Tests include:
- Token generation and validation
- Protected endpoint access control
- Invalid token rejection
- Malformed header handling
- End-to-end workflows with authentication

## Security Recommendations

1. **Change JWT Secret** - Set `AUTOS_JWT_SECRET` to a strong random value in production
2. **HTTPS Only** - Always use HTTPS for API endpoints in production
3. **Token Refresh** - Implement token refresh mechanism for long-lived sessions
4. **Client Credentials** - Validate `client_secret` against stored credentials (implement client database)
5. **Rate Limit Storage** - Use persistent storage (Redis) instead of in-memory for production
6. **CORS Configuration** - Restrict origins to trusted domains only
7. **Audit Logging** - Monitor failed auth attempts and rate limit violations
