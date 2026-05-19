#  AutoSecureChain

> **Enterprise-grade ECU firmware security scanner**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

AutoSecureChain is a comprehensive automotive ECU firmware security analysis platform that combines static analysis, YARA rule matching, and cryptographic signature verification to detect vulnerabilities and ensure supply chain integrity.

---
## Demo



https://github.com/user-attachments/assets/d8ef7e3c-9599-4203-93e1-009d758d0c54


##  Features

### Core Scanning Engine
- **Static Firmware Analysis**: SHA-256 hashing, entropy analysis, suspicious string detection
- **YARA Rule Matching**: Pattern-based detection for known vulnerabilities
- **Cryptographic Verification**: RSA PKCS#1 v1.5 + SHA-256 signature validation
- **Automated Remediation**: Severity scoring and actionable mitigation recommendations
- **CI/CD Integration**: Machine-readable JSON reports

### Enterprise Security Features
- **Encrypted Key Storage**: PKCS#8 encryption with optional OS keyring support
- **Cloud KMS Integration**: AWS KMS and HSM support for enterprise deployments
- **Multi-Signature Approval**: Blockchain-based provenance tracking with N-of-M approval
- **REST API**: Enterprise integration with JWT authentication and rate limiting
- **Audit Logging**: Comprehensive event tracking with immutable logs
- **Hardware Security Module**: PKCS#11 HSM support (YubiHSM, Thales, etc.)

### Reliability & Testing
- **Unit Tests**: 25+ tests covering key management, scanning, and API endpoints
- **E2E Integration Tests**: Complete workflows from signing to verification
- **CI/CD Pipelines**: GitHub Actions with multi-OS/Python version matrix
- **Gas-Optimized Smart Contracts**: Solidity contracts with 30%+ gas efficiency improvements

---

##  Quick Start

### Prerequisites
- Python 3.11 or higher
- Git

### Installation

```powershell
# Clone repository
git clone https://github.com/Ananyacodes/Auto-Secure-Chain.git
cd Auto-Secure-Chain

# Run setup (creates venv, installs dependencies)
.\setup.ps1

# Place firmware files in ./firmware/ directory
# Then run scanner
.\run-scanner.ps1
```

---

##  Usage

### Basic Scan
```powershell
# Scan all firmware files in ./firmware/
.\run-scanner.ps1

# Scan custom directory
.\run-scanner.ps1 -FirmwareDir "C:\path\to\firmware"

# Key management commands
.\run-scanner.ps1 -KeyCommand list
.\run-scanner.ps1 -KeyCommand generate -KeyName production -KeySize 4096
.\run-scanner.ps1 -KeyCommand sign -FirmwarePath "C:\path\to\firmware.bin" -KeyName production
.\run-scanner.ps1 -KeyCommand verify -FirmwarePath "C:\path\to\firmware.bin" -KeyName production
```

### Manual Execution
```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run scanner directly
python AutoSecureChain\scanner\scanner.py

# View report
Get-Content -Raw AutoSecureChain\reports\report.json | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

---

##  Sample Output

```
 AutoSecureChain - ECU Firmware Scanner
========================================

 Activating virtual environment...
 Checking dependencies...
 Found 2 firmware file(s)

 Running security scan...

Scanned ecu_v1.2.3.bin  severity=3
Scanned bootloader.bin  severity=0

 Scan Results:
================

File: ecu_v1.2.3.bin
  SHA-256: a1b2c3d4...
  Severity: 3
  Entropy: 7.21
  Signature:  Not found
  Suspicious findings: 2

  Recommended Actions:
     Enforce signed firmware with verified public keys
     Protect debug interfaces
```

---

##  Documentation

Complete documentation for deployment, security, and operations is available:

| Document | Purpose |
|---|---|
| [API_DOCUMENTATION.md](API_DOCUMENTATION.md) | REST API endpoints, authentication, examples |
| [API_AUTH.md](API_AUTH.md) | Authentication details and rate limiting configuration |
| [SECURITY_PLAYBOOK.md](SECURITY_PLAYBOOK.md) | Security policies, incident response, threat model |
| [KMS_HSM_SETUP.md](KMS_HSM_SETUP.md) | AWS KMS and HSM configuration guides |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Docker, Kubernetes, production deployments |
| [GAS_OPTIMIZATION_REPORT.md](GAS_OPTIMIZATION_REPORT.md) | Smart contract optimizations and benchmarks |

---

##  REST API Overview

AutoSecureChain exposes a comprehensive REST API for enterprise integration:

### Quick Example
```bash
# Get authentication token
TOKEN=$(curl -s -X POST http://localhost:5000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"my_app"}' | jq -r '.token')

# Generate new key
curl -X POST http://localhost:5000/api/v1/keys/generate \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "production",
    "size": 4096,
    "passphrase": "SecurePassphrase123!"
  }'

# Sign firmware
curl -X POST http://localhost:5000/api/v1/firmware/sign \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@firmware.bin" \
  -F "key=production"

# Verify firmware
curl -X POST http://localhost:5000/api/v1/firmware/verify \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@firmware.bin" \
  -F "key=production"
```

### Endpoints
- **Authentication**: `POST /api/v1/auth/token`
- **Key Management**: `POST/GET /api/v1/keys/*`
- **Firmware Operations**: `POST /api/v1/firmware/sign`, `POST /api/v1/firmware/verify`
- **Audit Logging**: `GET /api/v1/audit/recent`, `GET /api/v1/audit/search`
- **Health**: `GET /api/v1/health`, `GET /api/v1/info`

See [API_DOCUMENTATION.md](API_DOCUMENTATION.md) for complete endpoint reference.

---

##  CLI Commands

### Key Management
```bash
# Generate new keypair
python AutoSecureChain/scanner/key_manager_cli.py generate \
  --name "production" --size 4096 --use-keyring

# Sign firmware
python AutoSecureChain/scanner/key_manager_cli.py sign firmware.bin \
  --key "production" --backend local

# Verify signature
python AutoSecureChain/scanner/key_manager_cli.py verify firmware.bin \
  --key "production"

# Rotate key
python AutoSecureChain/scanner/key_manager_cli.py rotate old_key \
  --new-key new_key_v2

# List keys
python AutoSecureChain/scanner/key_manager_cli.py list

# View audit log
python AutoSecureChain/scanner/key_manager_cli.py audit recent --limit 50
```

### Scanner
```bash
# Run scanner
python AutoSecureChain/scanner/scanner.py

# Scan specific directory
python AutoSecureChain/scanner/scanner.py --firmware-dir "/path/to/firmware"

# Output machine-readable report
cat AutoSecureChain/reports/report.json | jq .
```

---

##  Smart Contract Deployment

AutoSecureChain includes gas-optimized smart contracts for firmware provenance tracking:

```bash
# Compile contracts
npx hardhat compile

# Run tests
npx hardhat test

# View gas benchmarks
npx hardhat test test/autoSecure.gas.test.ts

# Deploy to network
npx hardhat run scripts/deploy.ts --network sepolia
```

See [GAS_OPTIMIZATION_REPORT.md](GAS_OPTIMIZATION_REPORT.md) for optimization details.

---

##  Security Best Practices

### Key Management
```bash
# Generate encrypted keypair with OS keyring support
python AutoSecureChain/scanner/key_manager_cli.py generate \
  --name "production" --size 4096 --passphrase "YourSecurePassword" --use-keyring

# For AWS KMS backend
python AutoSecureChain/scanner/key_manager_cli.py sign firmware.bin \
  --key "production" --backend kms --kms-key-id "alias/autosecurechain-signing"

# For HSM backend
python AutoSecureChain/scanner/key_manager_cli.py sign firmware.bin \
  --key "production" --backend hsm
```

### Encryption at Rest
- Private keys encrypted with PKCS#8 + AES-256
- Passphrases stored in OS keyring (macOS Keychain, Linux Secret Service, Windows Credential Manager)
- Secure file permissions (600) enforced on key files

### Authentication & Rate Limiting
- JWT bearer token authentication (1-hour expiry)
- Strict rate limiting: 10/hr for auth, 100/hr for API operations
- IP-based rate limiting and DDoS protection recommended

### Incident Response
See [SECURITY_PLAYBOOK.md](SECURITY_PLAYBOOK.md) for:
- Threat model and defense-in-depth strategies
- Key compromise response procedures
- Audit log analysis techniques
- Key rotation procedures
- Backup and recovery protocols

---

##  CI/CD Integration

### GitHub Actions
```yaml
# .github/workflows/firmware-scan.yml
- name: Run security scan
  run: |
    python -m venv venv
    source venv/bin/activate
    pip install -r requirements.txt
    python AutoSecureChain/scanner/scanner.py
    
- name: Fail on critical findings
  run: |
    python -c "import json; \
    report = json.load(open('AutoSecureChain/reports/report.json')); \
    exit(1 if any(f['severity_score'] > 5 for f in report['files']) else 0)"

- name: Run tests
  run: |
    pytest -v AutoSecureChain/scanner/
```

### Automated Key Rotation
```bash
# Rotate keys every 90 days
0 0 1 */3 * /opt/autosecurechain/rotate-keys.sh
```

---

##  Project Structure

```
AutoSecureChain/
├── scanner/
│   ├── scanner.py               # Core analysis engine
│   ├── key_manager.py           # Secure key management
│   ├── key_manager_cli.py       # CLI for key operations
│   ├── kms.py                   # KMS/HSM signer adapters
│   ├── cli_validators.py        # Input validation & file locking
│   ├── api.py                   # Flask REST API
│   ├── auth.py                  # JWT authentication
│   ├── rules.yar                # YARA detection rules
│   ├── test_*.py                # Unit tests
│   └── create_test_keys.py      # Test key generator
├── contracts/
│   ├── AutoSecure.sol           # Provenance tracking contract
│   └── interfaces/
│       └── IAutoSecure.sol      # Interface definition
├── test/
│   └── autoSecure.*.test.ts     # Solidity contract tests
├── scripts/
│   ├── deploy.ts                # Contract deployment
│   ├── verify.ts                # Contract verification
│   └── rotate-keys.sh           # Key rotation automation
├── frontend/                    # React UI (future)
├── reports/                     # Generated reports (gitignored)
├── .github/workflows/           # CI/CD pipelines
├── requirements.txt             # Python dependencies
├── package.json                 # Node.js dependencies
├── README.md                    # This file
└── SECURITY_PLAYBOOK.md        # Security documentation
```

---

##  Configuration

### Environment Variables
```bash
# Required in production
export AUTOS_JWT_SECRET="your-32-byte-random-hex"
export FLASK_ENV="production"

# Optional
export AUTOS_KEY_BACKEND="local"  # or "kms" or "hsm"
export AUTOS_LOG_LEVEL="INFO"
export PORT="5000"
```

### Custom YARA Rules
Edit `AutoSecureChain/scanner/rules.yar`:
```yara
rule custom_backdoor
{
  strings:
    $pattern = "CUSTOM_BACKDOOR_SIGNATURE"
  condition:
    $pattern
}
```

---

##  Testing

### Run All Tests
```bash
# Unit tests
pytest -v AutoSecureChain/scanner/test_*.py

# Solidity contract tests
npx hardhat test

# With coverage
pytest --cov=AutoSecureChain/scanner --cov-report=html
```

### CI/CD Test Matrix
- **Python:** 3.9, 3.10, 3.11, 3.12
- **OS:** Ubuntu, Windows, macOS
- **Node.js:** 18.x, 20.x

---

##  Troubleshooting

**Issue: "No firmware files found"**  
 Place `.bin`, `.img`, or `.fw` files in `./firmware/` directory

**Issue: "cryptography not installed"**  
 Run `pip install -r requirements.txt`

**Issue: "Signature verification failed"**  
 Ensure public key matches the signing private key  
 Verify signature algorithm is RSA PKCS#1 v1.5 + SHA-256

**Issue: "Port 5000 already in use"**  
 Change port with `export PORT=5001`

---

##  Performance & Optimization

### Smart Contract Gas Benchmarks
- `storeProvenance`: ~95,000 gas (30% optimization)
- `approveProvenance`: ~50,000 gas (33% optimization)
- `addApprover`: ~40,000 gas (38% optimization)

See [GAS_OPTIMIZATION_REPORT.md](GAS_OPTIMIZATION_REPORT.md) for details.

### API Performance
- Response time: <500ms for typical operations
- Throughput: 100+ requests/sec per instance
- Rate limiting: 100 req/hr per API token

---

##  License

MIT License - see [LICENSE](LICENSE) file for details.

---

##  Contributing

1. Fork the repository
2. Create feature branch (`git checkout -b feature/detection-rule`)
3. Commit changes (`git commit -m 'Add detection rule'`)
4. Push to branch (`git push origin feature/detection-rule`)
5. Open Pull Request

---

**Built with  for automotive cybersecurity**
