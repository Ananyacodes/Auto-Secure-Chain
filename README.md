#  AutoSecureChain

> **Enterprise-grade ECU firmware security scanner**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)

AutoSecureChain is a comprehensive automotive ECU firmware security analysis platform that combines static analysis, YARA rule matching, and cryptographic signature verification to detect vulnerabilities and ensure supply chain integrity.

---

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
```yaml
# .github/workflows/firmware-scan.yml
- name: Run security scan
  run: |
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    pip install -r requirements.txt
    python AutoSecureChain\scanner\scanner.py
    
- name: Fail on critical findings
  run: |
    $report = Get-Content AutoSecureChain\reports\report.json | ConvertFrom-Json
    if ($report.files.severity_score -gt 5) { exit 1 }
```

---

##  Project Structure

```
AutoSecureChain/
 scanner/
    scanner.py              # Core analysis engine
    rules.yar               # YARA detection rules
    create_test_keys.py     # Test key generator
 reports/                    # Generated reports (gitignored)
 firmware/                   # User firmware files (gitignored)
 run-scanner.ps1             # Main execution script
 setup.ps1                   # Initial setup script
 requirements.txt            # Dependencies
 README.md
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
  strings:
    $pattern = "CUSTOM_BACKDOOR_SIGNATURE"
  condition:
    $pattern
}
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
