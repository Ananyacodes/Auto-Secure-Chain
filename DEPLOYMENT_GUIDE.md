# AutoSecureChain Deployment Guide

## Table of Contents
1. [Pre-Deployment Checklist](#pre-deployment-checklist)
2. [Local Development Deployment](#local-development-deployment)
3. [Docker Deployment](#docker-deployment)
4. [Kubernetes Deployment](#kubernetes-deployment)
5. [Production Configuration](#production-configuration)
6. [Health Checks & Monitoring](#health-checks--monitoring)
7. [Troubleshooting](#troubleshooting)

---

## Pre-Deployment Checklist

### Requirements

- **Python:** 3.9+ (recommended: 3.11 or 3.12)
- **Node.js:** 18.x or 20.x (for smart contracts)
- **Operating System:** Linux (production), Windows/macOS (development)
- **Disk Space:** 500 MB minimum (2 GB recommended with logs)
- **Network:** HTTPS/TLS 1.3+ capable

### Security Pre-Flight

```bash
# Verify dependencies for security vulnerabilities
pip-audit
safety check

# Check file permissions on key storage
ls -la ~/.autosecurechain/keys/
# Should show: -rw------- (600) for private keys
#             -rw-r--r-- (644) for public keys

# Verify firewall rules
# Block all inbound except:
#   - Port 443 (HTTPS) from load balancer
#   - Port 22 (SSH) from authorized IPs only
```

### Environment Variables

```bash
# Required - JWT secret (generate: openssl rand -hex 32)
export AUTOS_JWT_SECRET="your-32-byte-random-hex-string"

# Required - Flask configuration
export FLASK_ENV="production"
export FLASK_DEBUG="0"
export SECRET_KEY="$AUTOS_JWT_SECRET"

# Optional - KMS/HSM backend
export AUTOS_KEY_BACKEND="local"  # or "kms" or "hsm"
export AWS_REGION="us-east-1"

# Optional - API configuration
export PORT="5000"
export AUTOS_UPLOAD_DIR="/var/uploads"
export MAX_UPLOAD_SIZE_MB="100"

# Optional - Logging
export AUTOS_LOG_LEVEL="INFO"
export AUTOS_LOG_FILE="/var/log/autosecurechain.log"
```

---

## Local Development Deployment

### Quick Start

1. **Install dependencies:**
```bash
cd c:\Users\Ananya\OneDrive\projects\Auto-Secure-Chain
pip install -r requirements.txt
```

2. **Set environment variables:**
```bash
# Windows PowerShell
$env:AUTOS_JWT_SECRET = "test-secret-change-in-prod"
$env:FLASK_ENV = "development"

# Linux/macOS bash
export AUTOS_JWT_SECRET="test-secret-change-in-prod"
export FLASK_ENV="development"
```

3. **Start the API server:**
```bash
python -m AutoSecureChain.scanner.api
# Server running at http://localhost:5000
```

4. **Test the deployment:**
```bash
# Health check
curl http://localhost:5000/api/v1/health

# Get token
curl -X POST http://localhost:5000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"test"}'
```

### Running Tests

```bash
# Unit tests - key management
python -m pytest AutoSecureChain/scanner/test_key_manager.py -v

# Unit tests - scanner
python -m pytest AutoSecureChain/scanner/test_scanner.py -v

# Unit tests - API
python -m pytest AutoSecureChain/scanner/test_api.py -v

# E2E integration tests
python -m pytest AutoSecureChain/scanner/test_e2e.py -v

# All tests
pytest -v
```

---

## Docker Deployment

### Build Docker Image

Create `Dockerfile`:

```dockerfile
FROM python:3.12-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    libssl-dev \
    yara \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY AutoSecureChain ./AutoSecureChain
COPY contracts ./contracts

# Create directories for keys and uploads
RUN mkdir -p /app/.autosecurechain/keys /app/uploads

# Set permissions
RUN chmod 700 /app/.autosecurechain/keys

# Expose port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/health || exit 1

# Start API
CMD ["python", "-m", "AutoSecureChain.scanner.api"]
```

### Build and Run

```bash
# Build image
docker build -t autosecurechain:latest .

# Run container
docker run -d \
  -p 5000:5000 \
  -e AUTOS_JWT_SECRET="your-secret" \
  -e FLASK_ENV="production" \
  -v /secure/keys:/app/.autosecurechain/keys \
  -v /secure/uploads:/app/uploads \
  --name autosecurechain-api \
  autosecurechain:latest

# View logs
docker logs -f autosecurechain-api

# Stop container
docker stop autosecurechain-api
```

### Docker Compose

Create `docker-compose.yml`:

```yaml
version: "3.9"

services:
  api:
    build: .
    container_name: autosecurechain-api
    ports:
      - "5000:5000"
    environment:
      AUTOS_JWT_SECRET: "${AUTOS_JWT_SECRET}"
      FLASK_ENV: "production"
      AUTOS_LOG_LEVEL: "INFO"
    volumes:
      - ./secure/keys:/app/.autosecurechain/keys
      - ./secure/uploads:/app/uploads
      - ./logs:/app/logs
    restart: unless-stopped
    networks:
      - autosecurechain

  redis:
    image: redis:7-alpine
    container_name: autosecurechain-redis
    ports:
      - "6379:6379"
    volumes:
      - redis-data:/data
    restart: unless-stopped
    networks:
      - autosecurechain

networks:
  autosecurechain:
    driver: bridge

volumes:
  redis-data:
```

Run with Compose:

```bash
# Start services
docker-compose up -d

# View logs
docker-compose logs -f api

# Stop services
docker-compose down
```

---

## Kubernetes Deployment

### Prerequisites

- Kubernetes 1.24+ cluster
- kubectl configured
- Helm (optional but recommended)
- Container registry (Docker Hub, ECR, GCR)

### ConfigMap & Secrets

Create `k8s-secrets.yaml`:

```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: autosecurechain

---
apiVersion: v1
kind: Secret
metadata:
  name: autosecurechain-secrets
  namespace: autosecurechain
type: Opaque
stringData:
  jwt-secret: "your-32-byte-random-hex-string"
  aws-access-key-id: "AKIAIOSFODNN7EXAMPLE"
  aws-secret-access-key: "wJalrXUtnFEMI/K7..."

---
apiVersion: v1
kind: ConfigMap
metadata:
  name: autosecurechain-config
  namespace: autosecurechain
data:
  FLASK_ENV: "production"
  AUTOS_LOG_LEVEL: "INFO"
  AUTOS_KEY_BACKEND: "kms"
```

Apply secrets:

```bash
kubectl apply -f k8s-secrets.yaml
```

### Deployment

Create `k8s-deployment.yaml`:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: autosecurechain-api
  namespace: autosecurechain
  labels:
    app: autosecurechain-api
spec:
  replicas: 3
  strategy:
    type: RollingUpdate
    rollingUpdate:
      maxSurge: 1
      maxUnavailable: 0
  selector:
    matchLabels:
      app: autosecurechain-api
  template:
    metadata:
      labels:
        app: autosecurechain-api
    spec:
      serviceAccountName: autosecurechain
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000

      containers:
      - name: api
        image: your-registry/autosecurechain:latest
        imagePullPolicy: Always
        
        ports:
        - name: http
          containerPort: 5000
          protocol: TCP

        env:
        - name: AUTOS_JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: autosecurechain-secrets
              key: jwt-secret

        - name: AWS_ACCESS_KEY_ID
          valueFrom:
            secretKeyRef:
              name: autosecurechain-secrets
              key: aws-access-key-id
              optional: true

        - name: AWS_SECRET_ACCESS_KEY
          valueFrom:
            secretKeyRef:
              name: autosecurechain-secrets
              key: aws-secret-access-key
              optional: true

        envFrom:
        - configMapRef:
            name: autosecurechain-config

        resources:
          requests:
            cpu: "100m"
            memory: "256Mi"
          limits:
            cpu: "500m"
            memory: "512Mi"

        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: http
          initialDelaySeconds: 30
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3

        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: http
          initialDelaySeconds: 10
          periodSeconds: 5
          timeoutSeconds: 3
          failureThreshold: 3

        volumeMounts:
        - name: keys
          mountPath: /.autosecurechain/keys
          readOnly: false
        - name: uploads
          mountPath: /uploads

        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
              - ALL

      volumes:
      - name: keys
        persistentVolumeClaim:
          claimName: autosecurechain-keys-pvc

      - name: uploads
        persistentVolumeClaim:
          claimName: autosecurechain-uploads-pvc

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: autosecurechain-keys-pvc
  namespace: autosecurechain
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: encrypted-storage
  resources:
    requests:
      storage: 1Gi

---
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: autosecurechain-uploads-pvc
  namespace: autosecurechain
spec:
  accessModes:
    - ReadWriteOnce
  storageClassName: standard
  resources:
    requests:
      storage: 10Gi

---
apiVersion: v1
kind: Service
metadata:
  name: autosecurechain-api
  namespace: autosecurechain
  labels:
    app: autosecurechain-api
spec:
  type: ClusterIP
  selector:
    app: autosecurechain-api
  ports:
  - name: http
    port: 80
    targetPort: http
    protocol: TCP

---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: autosecurechain-api
  namespace: autosecurechain
spec:
  podSelector:
    matchLabels:
      app: autosecurechain-api
  policyTypes:
  - Ingress
  - Egress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          name: ingress-nginx
    ports:
    - port: 5000
  egress:
  - to:
    - namespaceSelector: {}
    ports:
    - protocol: TCP
      port: 443
```

Deploy to Kubernetes:

```bash
# Create namespace and secrets
kubectl apply -f k8s-secrets.yaml

# Deploy application
kubectl apply -f k8s-deployment.yaml

# Verify deployment
kubectl get pods -n autosecurechain
kubectl logs -n autosecurechain -l app=autosecurechain-api -f

# Port forward for testing
kubectl port-forward -n autosecurechain svc/autosecurechain-api 5000:80
```

---

## Production Configuration

### TLS/HTTPS Setup

**Using Let's Encrypt with NGINX reverse proxy:**

```nginx
# /etc/nginx/sites-available/autosecurechain
upstream autosecurechain_api {
    server localhost:5000;
}

server {
    listen 80;
    server_name api.autosecurechain.example.com;
    return 301 https://$server_name$request_uri;
}

server {
    listen 443 ssl http2;
    server_name api.autosecurechain.example.com;

    # SSL certificates
    ssl_certificate /etc/letsencrypt/live/api.autosecurechain.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/api.autosecurechain.example.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "no-referrer" always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=general:10m rate=50r/s;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=10r/m;
    limit_req_status 429;

    location /api/v1/auth/ {
        limit_req zone=auth burst=5 nodelay;
        proxy_pass http://autosecurechain_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 30s;
    }

    location /api/v1/ {
        limit_req zone=general burst=100 nodelay;
        proxy_pass http://autosecurechain_api;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }
}
```

Enable and start:

```bash
sudo ln -s /etc/nginx/sites-available/autosecurechain /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
```

### Systemd Service

Create `/etc/systemd/system/autosecurechain-api.service`:

```ini
[Unit]
Description=AutoSecureChain API Service
After=network.target
Wants=autosecurechain-api.service

[Service]
Type=simple
User=autosecurechain
WorkingDirectory=/opt/autosecurechain
Environment="PATH=/opt/autosecurechain/venv/bin"
Environment="AUTOS_JWT_SECRET=your-secret-here"
Environment="FLASK_ENV=production"
EnvironmentFile=/etc/autosecurechain/api.conf

ExecStart=/opt/autosecurechain/venv/bin/python -m AutoSecureChain.scanner.api

Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=autosecurechain-api

# Security settings
PrivateTmp=true
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/autosecurechain /opt/autosecurechain/.autosecurechain

[Install]
WantedBy=multi-user.target
```

Manage service:

```bash
# Enable and start
sudo systemctl enable autosecurechain-api
sudo systemctl start autosecurechain-api

# Check status
sudo systemctl status autosecurechain-api

# View logs
sudo journalctl -u autosecurechain-api -f
```

---

## Health Checks & Monitoring

### Prometheus Metrics

Create `metrics.py`:

```python
from prometheus_client import Counter, Histogram, Gauge
import time

# Define metrics
signature_count = Counter(
    'autosecurechain_signatures_total',
    'Total signatures created',
    ['key_name']
)

signature_errors = Counter(
    'autosecurechain_signature_errors_total',
    'Total signature errors',
    ['error_type']
)

signature_duration = Histogram(
    'autosecurechain_signature_duration_seconds',
    'Signature operation duration'
)

api_requests = Counter(
    'autosecurechain_api_requests_total',
    'Total API requests',
    ['method', 'endpoint', 'status']
)

active_tokens = Gauge(
    'autosecurechain_active_tokens',
    'Active JWT tokens'
)
```

### Health Endpoint

Test endpoint:

```bash
# Health check (should return 200)
curl http://localhost:5000/api/v1/health

# Expected response
{
  "status": "healthy",
  "service": "AutoSecureChain API",
  "version": "1.0.0"
}
```

### Logging

Configure structured logging:

```python
import logging
import json
from pythonjsonlogger import jsonlogger

# Setup JSON logging
logHandler = logging.StreamHandler()
formatter = jsonlogger.JsonFormatter()
logHandler.setFormatter(formatter)

logger = logging.getLogger()
logger.addHandler(logHandler)
logger.setLevel(logging.INFO)
```

---

## Troubleshooting

### Port Already in Use

```bash
# Find process using port 5000
lsof -i :5000

# Kill process
kill -9 <PID>

# Or use different port
export PORT=5001
```

### Permission Denied on Keys Directory

```bash
# Fix permissions
chmod 700 ~/.autosecurechain/keys
sudo chown -R autosecurechain:autosecurechain /opt/autosecurechain

# Verify
ls -la ~/.autosecurechain/keys/
```

### JWT Secret Not Set

```bash
# Generate random secret
openssl rand -hex 32

# Set in environment
export AUTOS_JWT_SECRET="generated-hex-string"
```

### Out of Memory

```bash
# Check memory usage
free -m
docker stats

# Increase Flask worker processes
gunicorn --workers 4 --worker-class gevent --worker-connections 1000 \
  AutoSecureChain.scanner.api:app
```

---

**Last Updated:** 2026-05-09
**Maintainer:** DevOps Team
