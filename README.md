#  AutoSecureChain

> **Enterprise-grade ECU firmware security scanner**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

AutoSecureChain is a comprehensive automotive ECU firmware security analysis platform that combines static analysis, YARA rule matching, and cryptographic signature verification to detect vulnerabilities and ensure supply chain integrity.

---
## Demo



https://github.com/user-attachments/assets/d8ef7e3c-9599-4203-93e1-009d758d0c54


##  Features

- **Static Firmware Analysis**: SHA-256 hashing, entropy analysis, suspicious string detection
- **YARA Rule Matching**: Pattern-based detection for known vulnerabilities
- **Cryptographic Verification**: RSA PKCS#1 v1.5 + SHA-256 signature validation
- **Automated Remediation**: Severity scoring and actionable mitigation recommendations
- **CI/CD Integration**: Machine-readable JSON reports

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
```

### Manual Execution
```powershell
# Activate virtual environment
.\venv\Scripts\Activate.ps1

# Run scanner directly against scanner/ samples
python AutoSecureChain\scanner\scanner.py

# Or scan a custom directory without copying files
python AutoSecureChain\scanner\scanner.py -i C:\path\to\firmware

# Optionally override output directory
python AutoSecureChain\scanner\scanner.py -i C:\path\to\firmware -o C:\path\to\output

# View report
Get-Content -Raw AutoSecureChain\reports\report.json | ConvertFrom-Json | ConvertTo-Json -Depth 10
```

### Scanner CLI Options
```
usage: scanner.py [-h] [-i INPUT] [-o OUTDIR]

  -i INPUT, --input INPUT       Path to firmware file or directory to scan.
                                If omitted, scans scanner/ for .bin/.img/.fw files.
  -o OUTDIR, --outdir OUTDIR    Reports output directory (default: AutoSecureChain/reports)
```

---

##  End-to-End Integration: Scanner → Backend → UI

The complete workflow connects the firmware scanner, Flask backend API, and web UI dashboard:

### 1. Run the Scanner
```powershell
# Activate venv and run scanner
.\venv\Scripts\Activate.ps1
python AutoSecureChain\scanner\scanner.py -i C:\path\to\firmware
# Output: AutoSecureChain\reports\report.json
```

### 2. Start the Flask Backend API
```powershell
# From the repo root (with venv active)
python AutoSecureChain\ui\app.py
# Flask server runs on http://localhost:5000
# API endpoint: http://localhost:5000/api/report (JSON)
# UI dashboard: http://localhost:5000/
```

### 3. View Results in Dashboard
- **Flask UI**: Open http://localhost:5000/ in your browser to view reports in HTML format
- **Frontend SPA** (React): Alternatively, run React frontend (requires Node.js):
  ```powershell
  cd frontend
  npm install
  npm start
  # Opens http://localhost:3000
  # Frontend fetches from Flask API at http://localhost:5000/api/report
  ```

### Integration Flow
```
[Firmware Files] 
    ↓
[scanner.py] → AutoSecureChain/reports/report.json
    ↓
[Flask Backend] (/api/report, /index.html)
    ↓
[React Frontend] (fetches via CORS)
    ↓
[Dashboard UI]
```

### Provenance & Blockchain
On-chain records are stored via `AutoSecure.sol`:
```powershell
# Deploy contract (requires Node.js/Hardhat)
npm install
npx hardhat run scripts/deploy.ts

# Submit firmware hash to blockchain
# Contract stores: hash, submitter, timestamp, approval status
# Enables audit trail and supply-chain verification
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

##  Security Best Practices

### Key Management
```powershell
# Generate production keypair (keep private key secure!)
openssl genpkey -algorithm RSA -out private_key.pem -pkeyopt rsa_keygen_bits:4096
openssl rsa -in private_key.pem -pubout -out public_key.pem

# Sign firmware
openssl dgst -sha256 -sign private_key.pem -out firmware.bin.sig firmware.bin

# Place public key in secure location
Move-Item public_key.pem "$env:USERPROFILE\.autosecurechain\"
```

### CI/CD Integration

This project includes comprehensive GitHub Actions workflows for automated testing and quality assurance:

#### Automated Testing
- **Python CI**: Runs pytest, flake8 linting, and mypy type checking on scanner code
- **Node.js CI**: Runs Hardhat contract tests and frontend TypeScript/ESLint checks
- **Code Quality**: Validates JSON files, checks for large files, and performs security scans
- **Coverage**: Uploads test coverage reports to Codecov

#### Workflow Triggers
- Runs on pushes and pull requests to `main`/`master` branches
- Path-based filtering ensures only relevant workflows run for specific changes
- Supports multiple Python versions (3.8-3.12) for compatibility testing

#### Example: Add to Your CI Pipeline
```yaml
# In your .github/workflows/deploy.yml
- name: Security scan firmware
  run: |
    python AutoSecureChain/scanner/scanner.py -i ./firmware
    # Fail build if critical vulnerabilities found
    python -c "
    import json
    report = json.load(open('AutoSecureChain/reports/report.json'))
    critical = [f for f in report['files'] if f['severity_score'] >= 7]
    if critical:
        print(f'Found {len(critical)} critical vulnerabilities')
        exit(1)
    "
```

#### Local Quality Checks
```bash
# Run Python tests and linting
pip install pytest flake8 mypy
pytest test/ -v
flake8 AutoSecureChain/scanner/
mypy AutoSecureChain/scanner/scanner.py

# Run contract tests
npm install
npx hardhat test

# Run frontend tests
cd frontend
npm install
npm test
npm run build
```

---

##  Project Structure

```
AutoSecureChain/
├── .github/
│   ├── workflows/
│   │   ├── ci.yml              # Combined CI workflow
│   │   ├── python-ci.yml       # Python testing pipeline
│   │   ├── nodejs-ci.yml       # Node.js testing pipeline
│   │   └── code-quality.yml    # Code quality checks
│   └── dependabot.yml          # Automated dependency updates
├── scanner/
│   ├── scanner.py              # Core analysis engine
│   ├── rules.yar               # YARA detection rules
│   └── create_test_keys.py     # Test key generator
├── ui/
│   └── app.py                  # Flask backend API
├── reports/                    # Generated reports (gitignored)
├── firmware/                   # User firmware files (gitignored)
├── contracts/                  # Solidity smart contracts
├── frontend/                   # React dashboard UI
├── test/                       # Python unit tests
├── scripts/                    # Metasploit integration
├── .flake8                     # Python linting config
├── mypy.ini                    # Python type checking config
├── codecov.yml                 # Code coverage config
├── audit-ci.json               # Dependency audit config
├── run-scanner.ps1             # Main execution script
├── setup.ps1                   # Initial setup script
├── requirements.txt            # Python dependencies
└── README.md
```

---

##  Configuration

### Environment Variables
```powershell
# Set public key location
$env:AUTOS_PUBLIC_KEY = "C:\path\to\public_key.pem"

# Make persistent
setx AUTOS_PUBLIC_KEY "C:\path\to\public_key.pem"
```

### Custom YARA Rules
Edit `AutoSecureChain/scanner/rules.yar`:
```yara
rule custom_backdoor
{
  meta:
    description = "Detect custom backdoor pattern"
    score = 5
  strings:
    $pattern = /\bCUSTOM_BACKDOOR_SIGNATURE\b/i
  condition:
    $pattern
}
```

**Rule Scoring**: Each rule has a `score` metadata field (1–8) used to compute severity. Higher scores indicate more critical issues. Rules use word-boundary regex (`\b`) to reduce false positives.

### Signature Verification

The scanner verifies firmware signatures using RSA PKCS#1 v1.5 + SHA256:

```powershell
# Generate test keypair (development only)
python AutoSecureChain\scanner\create_test_keys.py
# Creates: public_key.pem, test_private.pem, sample.bin.sig

# Sign your own firmware
openssl dgst -sha256 -sign private_key.pem -out firmware.bin.sig firmware.bin

# Scanner automatically verifies firmware.bin.sig against public_key.pem
python AutoSecureChain\scanner\scanner.py -i .\firmware
```

---

##  Troubleshooting

**Issue: "No firmware files found"**  
 Place `.bin`, `.img`, or `.fw` files in `./firmware/` directory

**Issue: "cryptography not installed"**  
 Run `.\setup.ps1` or `pip install -r requirements.txt`

**Issue: "Signature verification failed"**  
 Ensure public key matches the signing private key  
 Verify signature algorithm is RSA PKCS#1 v1.5 + SHA-256

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
