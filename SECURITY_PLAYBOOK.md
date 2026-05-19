# AutoSecureChain Security Playbook

## Table of Contents
1. [Overview](#overview)
2. [Threat Model](#threat-model)
3. [Security Architecture](#security-architecture)
4. [Key Management](#key-management)
5. [Incident Response](#incident-response)
6. [Operational Security](#operational-security)
7. [Compliance](#compliance)

---

## Overview

AutoSecureChain is an automotive ECU firmware security scanner and signing system. This playbook defines security policies, procedures, and incident response protocols for deployment and operation.

**Target Audience:** Security engineers, DevOps, incident response teams

---

## Threat Model

### Assets
1. **Private Signing Keys** - Used to sign firmware (highest criticality)
2. **Passphrases/Key Encryption Keys** - Protect private keys at rest
3. **Audit Logs** - Provide accountability and non-repudiation
4. **Firmware Hashes** - Attestation of firmware integrity
5. **Approver Credentials** - Multi-sig approval authority

### Threats

| Threat | Impact | Mitigation |
|---|---|---|
| Private key theft/compromise | Attacker can sign malicious firmware | Encryption at rest + HSM/KMS + passphrase |
| Unauthorized firmware signing | Compromised firmware deployed | Multi-sig approval required, audit logging |
| Replay attacks | Old firmware versions accepted | Timestamp validation, version tracking |
| Audit log tampering | Loss of accountability | Immutable audit log, off-chain storage |
| DoS on signing service | Legitimate signing blocked | Rate limiting, request throttling, monitoring |
| Weak passphrases | Key material exposed | Minimum 8 chars enforced, strong entropy check |
| Key loss/deletion | Firmware verification impossible | Key backup procedures, recovery protocol |
| Insider threat | Malicious approver | Audit logging, approval committee, key rotation |

---

## Security Architecture

### Defense in Depth

```
┌─────────────────────────────────────────────────────────────┐
│ Layer 1: Network Security                                   │
│ - HTTPS only (TLS 1.3+)                                     │
│ - Firewall rules (whitelist IPs)                            │
│ - VPN for API access                                        │
└─────────────────────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 2: Authentication & Authorization                     │
│ - JWT bearer tokens (1-hour expiry)                         │
│ - Rate limiting (10/hr for auth, 100/hr for API)            │
│ - Multi-sig approval (configurable N-of-M)                  │
└─────────────────────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 3: Data Protection                                    │
│ - Private keys encrypted at rest (PKCS#8)                   │
│ - Passphrases stored in OS keyring (when available)         │
│ - HSM/KMS integration for key storage                       │
│ - Audit logging with timestamp + signature                  │
└─────────────────────────────────────────────────────────────┘
        ↓
┌─────────────────────────────────────────────────────────────┐
│ Layer 4: Operations & Monitoring                            │
│ - Real-time audit log review                                │
│ - Failed attempt notifications                              │
│ - Key rotation schedule                                     │
│ - Backup & disaster recovery                                │
└─────────────────────────────────────────────────────────────┘
```

### Key Storage Options

#### Option 1: Local Encrypted Keys (Development/Small Deployment)
```
Private Key Storage: ~/.autosecurechain/keys/
├── prod_key_private.pem (encrypted with passphrase)
├── prod_key_public.pem (unencrypted)
└── audit.log (JSON format)

Passphrase Storage: OS Keyring
├── macOS Keychain
├── Linux Secret Service
└── Windows Credential Manager
```

**Setup:**
```bash
# Generate encrypted keypair
python key_manager_cli.py generate \
  --name "production" \
  --size 4096 \
  --use-keyring  # Prompts for passphrase, stores in OS keyring
```

**Risks:** Local disk access compromise = key compromise
**Mitigations:** File permissions (600), encrypted filesystem, access logging

#### Option 2: AWS KMS (Production Recommended)
```
Private Key: Stored in AWS KMS (never leaves AWS)
Signing: CloudHSM or KMS APIs perform signing
Audit: CloudTrail logs all operations
Backup: Managed by AWS (replicated across regions)
```

**Setup:**
```bash
# Configure AWS credentials
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-east-1"

# Sign with KMS
python key_manager_cli.py sign firmware.bin \
  --key "production" \
  --backend kms \
  --kms-key-id "arn:aws:kms:us-east-1:123456789:key/..."
```

**Benefits:** Hardware-backed security, managed backup, compliance ready
**Costs:** ~$0.01-$0.05 per operation + KMS key fee

#### Option 3: PKCS#11 HSM (High Security)
```
Private Key: Hardware Security Module (YubiHSM, Thales, etc.)
Signing: HSM performs signing (key never exported)
Audit: HSM logs all operations
Backup: HSM-managed backup procedures
```

**Setup:**
```bash
# Configure PKCS#11 module
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_SLOT="0"
export PKCS11_PIN="1234"

python key_manager_cli.py sign firmware.bin \
  --key "production" \
  --backend hsm
```

**Benefits:** Highest security, FIPS certified options, tamper-resistant
**Costs:** Initial hardware cost ($2K-$20K) + operational overhead

---

## Key Management

### Key Generation

**Policy:**
- Minimum key size: 2048 bits (RSA)
- Recommended size: 4096 bits (RSA) for firmware signing
- Random number generation: Cryptographically secure (Python `secrets` module)
- Passphrase requirements:
  - Minimum 8 characters
  - Mix of uppercase, lowercase, numbers, special characters
  - Not in dictionary
  - Entropy score > 50 bits

**Procedure:**
```bash
# Generate new key with passphrase
python key_manager_cli.py generate \
  --name "production_$(date +%Y%m%d)" \
  --size 4096 \
  --use-keyring
```

### Key Rotation

**Policy:**
- Primary signing keys: Rotate every 90 days
- Emergency rotation: When compromise suspected
- Retired keys: Archive for 7 years (verification of old signatures)
- Track rotation history in audit log

**Procedure:**
```bash
# View existing keys
python key_manager_cli.py list

# Rotate to new key
python key_manager_cli.py rotate production \
  --new-key production_$(date +%Y%m%d)

# Update configuration to use new key
export AUTOS_SIGNING_KEY="production_$(date +%Y%m%d)"

# Old key remains for verification of previously-signed firmware
```

### Key Backup & Recovery

**Backup Policy:**
- Encrypted backups: Every 24 hours
- Off-site storage: Encrypted backups in S3/GCS with versioning
- Backup encryption: AES-256-GCM with separate master key
- Retention: 7 years minimum (regulatory requirement)

**Backup Procedure:**
```bash
#!/bin/bash
# Backup script - run daily
BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="keys_backup_$BACKUP_DATE.tar.gz.gpg"

# Encrypt backup with GPG
tar czf - ~/.autosecurechain/keys | \
  gpg --symmetric --cipher-algo AES256 \
      --output "/mnt/secure_backup/$BACKUP_FILE"

# Upload to S3
aws s3 cp "/mnt/secure_backup/$BACKUP_FILE" \
    "s3://autosecurechain-backups/$BACKUP_FILE"

# Keep only last 30 days local
find /mnt/secure_backup -name "keys_backup_*" -mtime +30 -delete
```

**Recovery Procedure:**
```bash
# Download backup from S3
aws s3 cp "s3://autosecurechain-backups/keys_backup_YYYYMMDD_HHMMSS.tar.gz.gpg" .

# Decrypt and extract
gpg --output keys_backup.tar.gz --decrypt keys_backup_YYYYMMDD_HHMMSS.tar.gz.gpg
tar xzf keys_backup.tar.gz -C ~/.autosecurechain/

# Verify integrity
python key_manager_cli.py list
```

---

## Incident Response

### Incident Classification

| Severity | Impact | Response Time | Examples |
|---|---|---|---|
| Critical | Key compromise, unauthorized signing | 15 minutes | Private key theft, signing API compromised |
| High | Audit log tampering, unauthorized access | 1 hour | Failed auth attempts spike, suspicious approvals |
| Medium | Degraded service, partial data loss | 4 hours | Rate limiting triggered, backup failure |
| Low | Informational, no immediate action | 24 hours | Deprecated API usage, key rotation reminder |

### Incident Response Procedure

#### Step 1: Detect
- **Monitoring:** Real-time alerts on:
  - Failed authentication attempts (>10 in 5 min)
  - Unusual signing patterns (signatures outside normal hours)
  - Audit log access from unauthorized IPs
  - Service errors or crashes

- **Detection Tools:**
  - CloudWatch / DataDog / New Relic logs
  - Custom audit log analyzer
  - Anomaly detection (ML-based)

#### Step 2: Contain
```bash
# If key compromise suspected:
1. Immediately stop all signing operations
2. Disable the potentially compromised key
3. Notify all stakeholders

python key_manager_cli.py audit recent --limit 100 | \
  jq '.events[] | select(.timestamp > "2026-05-09T00:00:00") | 
       select(.event_type == "firmware_signed")'
```

#### Step 3: Investigate
```bash
# Analyze audit logs
python key_manager_cli.py audit search \
  --event-type "firmware_signed" \
  --severity "error" \
  --limit 1000

# Check for unauthorized approvals
python key_manager_cli.py audit search \
  --event-type "approval" \
  --limit 1000

# Review API access logs
grep "Sign" /var/log/autosecurechain.log | tail -100
```

#### Step 4: Eradicate
```bash
# If key compromise confirmed:
1. Rotate compromised key immediately
   python key_manager_cli.py rotate <old_key> --new-key <new_key>

2. Revoke all active JWT tokens (restart API service)
   systemctl restart autosecurechain-api

3. Reset all approver passphrases
   # Force all approvers to re-authenticate

4. Review and re-approve pending signatures
```

#### Step 5: Recover
```bash
# Restore from backup if needed
./scripts/restore_keys.sh /mnt/secure_backup/keys_backup_20260509_000000.tar.gz.gpg

# Verify system integrity
python key_manager_cli.py list
python -m AutoSecureChain.scanner.test_key_manager  # Run unit tests

# Bring services back online
systemctl start autosecurechain-api
```

#### Step 6: Post-Incident
- Document incident in incident log
- Conduct root cause analysis
- Implement preventive measures
- Share learnings with team
- Update playbook if needed

### Incident Log Template

```
INCIDENT ID: INC-YYYY-00001
DATE: YYYY-MM-DD HH:MM UTC
SEVERITY: [Critical/High/Medium/Low]
STATUS: [Detected/Contained/Investigated/Eradicated/Recovered/Closed]

SUMMARY:
Brief description of incident

TIMELINE:
[HH:MM] - Initial detection/alert
[HH:MM] - Investigation started
[HH:MM] - Key containment action
[HH:MM] - Resolution

ROOT CAUSE:
Description of root cause

IMPACT:
- Unauthorized signatures: [count]
- Audit logs compromised: [Y/N]
- Systems affected: [list]

REMEDIATION:
- Action 1: [completed/in-progress]
- Action 2: [completed/in-progress]

PREVENTION:
- Procedure change: [description]
- Monitoring enhancement: [description]
- Training required: [Y/N]
```

---

## Operational Security

### Access Control

**Principle of Least Privilege:**
- Developers: Read-only to audit logs
- Operations: Deploy, manage keys, view logs
- Security: Full access, incident response
- Business: View metrics/dashboards only

**Access Matrix:**
```
Role        | Keys | Sign | Approve | Rotate | Audit | Admin
------------|------|------|---------|--------|-------|------
Developer   | R    | -    | -       | -      | R     | -
Operator    | RW   | RW   | -       | RW     | RW    | -
Security    | RW   | RW   | RW      | RW     | RW    | R
Approver    | R    | -    | RW      | -      | RW    | -
Admin       | RW   | RW   | RW      | RW     | RW    | RW
```

R = Read, W = Write, - = No Access

### Network Isolation

**Recommended Architecture:**
```
┌─────────────────────────────────────────────────────┐
│ Public Subnet (DMZ)                                 │
│ - API Load Balancer (HTTPS TLS 1.3)                 │
│ - Rate limiting / DDoS protection                   │
└─────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────┐
│ Private Subnet (Application)                        │
│ - AutoSecureChain API instances                     │
│ - VPC-only access                                   │
│ - Security group: Allow 443 from load balancer only │
└─────────────────────────────────────────────────────┘
              ↓
┌─────────────────────────────────────────────────────┐
│ Secure Subnet (Key Storage)                         │
│ - AWS KMS / CloudHSM                                │
│ - No internet access                                │
│ - VPC endpoint access only                          │
└─────────────────────────────────────────────────────┘
```

### Logging & Monitoring

**Logs to Collect:**
1. **Audit Logs** - All key operations (signed and stored)
2. **API Access Logs** - All API requests (authentication, endpoints)
3. **System Logs** - Application errors and warnings
4. **Security Logs** - Failed authentication, permission denials

**Log Retention:**
- Real-time logs: 7 days
- Archive logs: 7 years
- Immutable copies: Off-site encrypted storage

**Monitoring Dashboard Metrics:**
```
- API response time (p50, p95, p99)
- Error rate (5xx, 4xx, validation errors)
- Authentication failures per hour
- Signature operations per hour
- Active JWT token count
- Database query latency
- Disk usage on key storage
- Backup success rate
```

### Vulnerability Management

**Policy:**
- Scan dependencies monthly: `pip-audit`, `safety`
- Test against OWASP Top 10 quarterly
- Penetration testing: Annual, after major changes
- Security advisories: Subscribe and patch within 30 days
- Container scanning: On every build

**Commands:**
```bash
# Scan Python dependencies
pip-audit

# Check for vulnerable libraries
safety check

# Update vulnerable packages
pip install --upgrade <package>

# Rebuild containers with latest base image
docker build --no-cache -t autosecurechain:latest .
```

---

## Compliance

### Standards & Certifications

- **NIST Cybersecurity Framework:** Implemented
- **ISO 27001:** Recommended (information security management)
- **SOC 2 Type II:** Recommended (audit readiness)
- **FIPS 140-2:** Required for government use (HSM integration)

### Regulatory Requirements

**Automotive Industry (OTA Security):**
- UPTANE: Metadata format + update verification
- Secure boot: Bootloader signature validation
- Key rotation: Documented and audited

**Data Protection (GDPR/CCPA):**
- Audit logs: PII handling compliance
- Data retention: 7-year requirement met
- Access logging: Demonstrable accountability
- Encryption in transit: TLS 1.3+

### Audit Checklist

```
Security Audit - AutoSecureChain
Date: _______________
Auditor: ____________

□ Access control properly configured
  - Key file permissions (600): ___
  - API rate limiting active: ___
  - JWT token expiry: 1 hour

□ Encryption in use
  - Keys encrypted at rest: ___
  - TLS 1.3+ in transit: ___
  - Passphrases stored in keyring: ___

□ Audit logging operational
  - Events logged: ___
  - Immutable copies exist: ___
  - Retention policy: 7 years

□ Incident response ready
  - On-call team assigned: ___
  - Runbooks documented: ___
  - Recent DR drill passed: ___

□ Vulnerability management
  - Dependencies scanned: ___
  - No critical CVEs: ___
  - Patch policy enforced: ___

□ Operations
  - Key backup tested: ___
  - Recovery procedure validated: ___
  - Rotation schedule active: ___

Findings:
_________________________________
_________________________________

Recommendations:
_________________________________
_________________________________

Sign-off: __________________ Date: ____
```

---

## Additional Resources

- **Key Management Best Practices:** [NIST SP 800-57](https://csrc.nist.gov/publications/detail/sp/800-57/part-1/final)
- **Incident Response:** [NIST SP 800-61](https://csrc.nist.gov/publications/detail/sp/800-61/rev-2/final)
- **Cryptographic Standards:** [FIPS 140-3](https://csrc.nist.gov/publications/detail/fips/140/3/final)
- **Supply Chain Security:** [NIST SSDF](https://csrc.nist.gov/publications/detail/sp/800-218/final)

---

## Document History

| Version | Date | Changes |
|---|---|---|
| 1.0 | 2026-05-09 | Initial release |

---

**Last Updated:** 2026-05-09
**Next Review:** 2026-08-09 (90 days)
**Owner:** Security Engineering Team
