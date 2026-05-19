# AutoSecureChain REST API Documentation

## Overview
The AutoSecureChain REST API provides enterprise-grade firmware security operations including key management, firmware signing/verification, and audit logging.

## Base URL
```
http://localhost:5000/api/v1
```

## Authentication
All endpoints except `/health` and `/info` require JWT bearer token authentication.

### Getting a Token

**Endpoint:** `POST /api/v1/auth/token`

**No authentication required**

```bash
curl -X POST http://localhost:5000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{
    "client_id": "my_app",
    "client_secret": "optional_secret"
  }'
```

**Response (201 Created):**
```json
{
  "status": "success",
  "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Token Validity:** 1 hour

**Usage:** Include token in all subsequent requests:
```bash
curl -H "Authorization: Bearer <token>" http://localhost:5000/api/v1/keys/list
```

---

## Endpoints

### Health Check
`GET /api/v1/health`

No authentication required.

**Response:**
```json
{
  "status": "healthy",
  "service": "AutoSecureChain API",
  "version": "1.0.0"
}
```

---

### API Info
`GET /api/v1/info`

No authentication required. Returns endpoint documentation and authentication requirements.

**Response:**
```json
{
  "service": "AutoSecureChain REST API",
  "version": "1.0.0",
  "authentication": "Bearer token required for most endpoints...",
  "endpoints": {
    "auth": {...},
    "keys": {...},
    "firmware": {...},
    "audit": {...},
    "public": {...}
  }
}
```

---

## Key Management Endpoints

### Generate Keypair
`POST /api/v1/keys/generate`

**Authentication:** Required (Bearer token)

**Request:**
```json
{
  "name": "production",
  "size": 4096,
  "passphrase": "optional_passphrase_min_8_chars",
  "use_keyring": false
}
```

**Parameters:**
- `name` (string, required): Key identifier (alphanumeric, hyphens, underscores)
- `size` (integer, required): 2048, 3072, or 4096 bits
- `passphrase` (string, optional): Encryption passphrase (min 8 chars if provided)
- `use_keyring` (boolean, optional): Store passphrase in OS keyring

**Response (201 Created):**
```json
{
  "status": "success",
  "key_id": "23cff81800fc9f84",
  "private_key_path": "/home/user/.autosecurechain/keys/production_private.pem",
  "public_key_path": "/home/user/.autosecurechain/keys/production_public.pem",
  "info": {
    "name": "production",
    "algorithm": "RSA",
    "key_size": 4096,
    "created_at": "2026-05-09T01:11:44.378069+00:00",
    "status": "active"
  }
}
```

**Error Responses:**
- 400: Invalid key size or passphrase too short
- 500: Key generation failed

---

### List Keys
`GET /api/v1/keys/list`

**Authentication:** Required

**Response (200):**
```json
{
  "status": "success",
  "keys": [
    {
      "key_id": "23cff81800fc9f84",
      "name": "production",
      "algorithm": "RSA",
      "key_size": 4096,
      "created_at": "2026-05-09T01:11:44.378069+00:00",
      "status": "active",
      "usage_count": 42,
      "last_used": "2026-05-09T02:30:15.123456+00:00"
    }
  ],
  "count": 1
}
```

---

### Get Key Info
`GET /api/v1/keys/{key_name}`

**Authentication:** Required

**Response (200):**
```json
{
  "status": "success",
  "key_info": {
    "name": "production",
    "algorithm": "RSA",
    "key_size": 4096,
    "created_at": "2026-05-09T01:11:44.378069+00:00",
    "status": "active",
    "usage_count": 42,
    "last_used": "2026-05-09T02:30:15.123456+00:00",
    "public_key_path": "/home/user/.autosecurechain/keys/production_public.pem"
  }
}
```

**Error Responses:**
- 404: Key not found

---

### Rotate Key
`POST /api/v1/keys/{key_name}/rotate`

**Authentication:** Required

**Request:**
```json
{
  "new_key_name": "production_v2"
}
```

**Response (200):**
```json
{
  "status": "success",
  "message": "Key rotated: production -> production_v2",
  "new_key_id": "54694631442ec8b5"
}
```

**Error Responses:**
- 400: Invalid key name
- 404: Old key not found
- 500: Rotation failed

---

## Firmware Operations

### Sign Firmware
`POST /api/v1/firmware/sign`

**Authentication:** Required

**Request:** multipart/form-data
- `file` (binary, required): Firmware binary
- `key` (string, optional): Key name (default: "production")
- `backend` (string, optional): "local" or "kms" (default: "local")
- `kms_key_id` (string, optional): KMS key ID/ARN if backend=kms

**Example:**
```bash
curl -X POST http://localhost:5000/api/v1/firmware/sign \
  -H "Authorization: Bearer <token>" \
  -F "file=@firmware.bin" \
  -F "key=production" \
  -F "backend=local"
```

**Response (200):**
```json
{
  "status": "success",
  "message": "Firmware signed successfully",
  "firmware": "firmware.bin",
  "signature_path": "/home/user/.autosecurechain/uploads/firmware.bin.sig",
  "key_used": "production"
}
```

**Error Responses:**
- 400: Missing file or invalid parameters
- 404: Key not found
- 500: Signing failed

---

### Verify Firmware
`POST /api/v1/firmware/verify`

**Authentication:** Required

**Request:** multipart/form-data
- `file` (binary, required): Firmware binary
- `key` (string, optional): Key name (default: "production")

**Response (200):**
```json
{
  "status": "success",
  "valid": true,
  "firmware": "firmware.bin",
  "key_used": "production",
  "message": "Signature is valid"
}
```

**Invalid Signature Response:**
```json
{
  "status": "success",
  "valid": false,
  "firmware": "firmware.bin",
  "key_used": "production",
  "message": "Signature is invalid"
}
```

---

## Audit Logging

### Get Recent Events
`GET /api/v1/audit/recent?limit=50`

**Authentication:** Required

**Query Parameters:**
- `limit` (integer, optional): Number of events (default: 50, max: 1000)

**Response (200):**
```json
{
  "status": "success",
  "events": [
    {
      "timestamp": "2026-05-09T02:30:15.123456+00:00",
      "event_type": "firmware_signed",
      "severity": "info",
      "message": "Firmware signed with key: production",
      "details": {
        "firmware": "firmware.bin",
        "key": "production"
      }
    }
  ],
  "count": 25
}
```

---

### Search Audit Events
`GET /api/v1/audit/search?event_type=firmware_signed&severity=error&limit=100`

**Authentication:** Required

**Query Parameters:**
- `event_type` (string, optional): Filter by event type
- `severity` (string, optional): "info", "warning", or "error"
- `limit` (integer, optional): Number of events (default: 100, max: 1000)

**Response (200):**
```json
{
  "status": "success",
  "events": [...],
  "count": 12,
  "filters": {
    "event_type": "firmware_signed",
    "severity": "error"
  }
}
```

---

## Rate Limiting

**Global Limits:**
- 200 requests per day
- 50 requests per hour

**Authentication Endpoint:**
- 10 requests per hour (prevents brute force)

**API Operations:**
- 100 requests per hour (per endpoint category)

**Response when limit exceeded:**
```json
{
  "error": "Rate limit exceeded"
}
```
HTTP Status: `429 Too Many Requests`

---

## Error Handling

All errors return JSON with `error` field and appropriate HTTP status:

| Status | Meaning |
|---|---|
| 200 | Success |
| 201 | Created |
| 400 | Bad Request (validation error) |
| 401 | Unauthorized (auth required/invalid) |
| 404 | Not Found |
| 429 | Rate Limited |
| 500 | Internal Server Error |

**Error Format:**
```json
{
  "error": "Descriptive error message"
}
```

---

## Examples

### Full Workflow: Sign and Verify Firmware

1. **Get token:**
```bash
TOKEN=$(curl -s -X POST http://localhost:5000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"my_app"}' \
  | jq -r '.token')
```

2. **Generate key:**
```bash
curl -X POST http://localhost:5000/api/v1/keys/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"firmware_key","size":4096}'
```

3. **Sign firmware:**
```bash
curl -X POST http://localhost:5000/api/v1/firmware/sign \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@firmware.bin" \
  -F "key=firmware_key"
```

4. **Verify firmware:**
```bash
curl -X POST http://localhost:5000/api/v1/firmware/verify \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@firmware.bin" \
  -F "key=firmware_key"
```

5. **Check audit log:**
```bash
curl -X GET "http://localhost:5000/api/v1/audit/recent?limit=10" \
  -H "Authorization: Bearer $TOKEN"
```

---

## Configuration

**Environment Variables:**
```bash
# JWT secret (recommended: 32+ random chars)
export AUTOS_JWT_SECRET="your-secret-key-here"

# API port
export PORT=5000

# Upload directory
export AUTOS_UPLOAD_DIR="/path/to/uploads"
```

**Production Checklist:**
- [ ] Change JWT_SECRET to strong random value
- [ ] Use HTTPS only
- [ ] Configure firewall rules
- [ ] Set up Redis for rate limiting
- [ ] Enable audit log rotation
- [ ] Configure key backup procedures
- [ ] Set up monitoring and alerting
- [ ] Configure CORS for specific origins only
