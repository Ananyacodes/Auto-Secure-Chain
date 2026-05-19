# KMS/HSM Setup Guide

## AWS KMS Configuration (Production Recommended)

### Overview
AWS KMS (Key Management Service) provides hardware-backed key storage and signing operations without exposing private keys. Keys are stored in AWS CloudHSM and operations are performed server-side.

---

## Prerequisites

1. AWS Account with appropriate permissions
2. AWS CLI v2+ installed and configured
3. IAM user with KMS permissions
4. `boto3>=1.26.0` and `botocore>=1.29.0` installed

```bash
pip install boto3>=1.26.0 botocore>=1.29.0
```

---

## Step 1: Create KMS Key

### Option A: AWS Management Console

1. Navigate to **AWS KMS → Customer Managed Keys**
2. Click **Create Key**
3. Select **Symmetric** (for AES-256 encryption) or **Asymmetric** (for RSA signing)
   - For firmware signing: Choose **Asymmetric**
   - Key spec: **RSA_4096** (or RSA_3072/RSA_2048)
4. Enable rotation: **Annual key rotation** (recommended)
5. Add key policy allowing:
   - Your AWS account to manage the key
   - EC2 instances / Lambda functions to use the key

### Option B: AWS CLI

```bash
# Create asymmetric key for signing
aws kms create-key \
  --description "AutoSecureChain Firmware Signing Key" \
  --key-usage SIGN_VERIFY \
  --origin AWS_KMS \
  --region us-east-1

# Output:
# {
#   "KeyMetadata": {
#     "KeyId": "arn:aws:kms:us-east-1:123456789:key/12345678-abcd-1234-...",
#     ...
#   }
# }

# Save the Key ARN
export AWS_KMS_KEY_ARN="arn:aws:kms:us-east-1:123456789:key/..."

# Create alias for easy reference
aws kms create-alias \
  --alias-name alias/autosecurechain-signing \
  --target-key-id "$AWS_KMS_KEY_ARN" \
  --region us-east-1
```

---

## Step 2: Configure IAM Permissions

Create IAM policy for your application:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "KMSKeyOperations",
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:Verify",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789:key/12345678-*"
    },
    {
      "Sid": "KMSListKeys",
      "Effect": "Allow",
      "Action": [
        "kms:ListKeys",
        "kms:ListAliases"
      ],
      "Resource": "*"
    }
  ]
}
```

Attach to IAM user/role used by AutoSecureChain:

```bash
# Create policy
aws iam put-user-policy \
  --user-name autosecurechain-app \
  --policy-name KMSSigningPolicy \
  --policy-document file://kms-policy.json

# Or attach to role
aws iam put-role-policy \
  --role-name autosecurechain-role \
  --policy-name KMSSigningPolicy \
  --policy-document file://kms-policy.json
```

---

## Step 3: Configure AWS Credentials

Set environment variables for the AutoSecureChain application:

```bash
# Option A: Environment variables
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_REGION="us-east-1"

# Option B: AWS credentials file (~/.aws/credentials)
[autosecurechain]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1

# Then set profile
export AWS_PROFILE=autosecurechain
```

---

## Step 4: Get Public Key from KMS

```bash
# Retrieve public key for firmware verification
aws kms get-public-key \
  --key-id alias/autosecurechain-signing \
  --region us-east-1 \
  --query 'PublicKey' \
  --output text | base64 -d > public_key.der

# Convert to PEM format
openssl asn1parse -inform DER -in public_key.der
openssl pkey -inform DER -in public_key.der -out public_key.pem -pubin

# Verify key
openssl pkey -in public_key.pem -text -noout
```

---

## Step 5: Configure AutoSecureChain to Use KMS

### Environment Variables

```bash
# Enable KMS backend
export AUTOS_KEY_BACKEND="kms"
export AUTOS_KMS_KEY_ID="alias/autosecurechain-signing"
export AUTOS_KMS_REGION="us-east-1"

# Keep local copies of public keys for verification
export AUTOS_PUBKEY_PATH="/home/app/.autosecurechain/keys/public_key.pem"
```

### Python Configuration

```python
# config.py
import os

KEY_BACKEND = os.getenv("AUTOS_KEY_BACKEND", "local")
KMS_KEY_ID = os.getenv("AUTOS_KMS_KEY_ID", "alias/autosecurechain-signing")
KMS_REGION = os.getenv("AUTOS_KMS_REGION", "us-east-1")
```

### CLI Usage

```bash
# Generate key (stores metadata, not actual key)
python key_manager_cli.py generate \
  --name "production" \
  --size 4096

# Sign firmware with KMS backend
python key_manager_cli.py sign firmware.bin \
  --key "production" \
  --backend kms \
  --kms-key-id "alias/autosecurechain-signing"

# Verify signature (uses local public key)
python key_manager_cli.py verify firmware.bin \
  --key "production"
```

### REST API Usage

```bash
# Get authentication token
TOKEN=$(curl -s -X POST http://localhost:5000/api/v1/auth/token \
  -H "Content-Type: application/json" \
  -d '{"client_id":"my_app"}' \
  | jq -r '.token')

# Sign firmware with KMS
curl -X POST http://localhost:5000/api/v1/firmware/sign \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@firmware.bin" \
  -F "backend=kms" \
  -F "kms_key_id=alias/autosecurechain-signing"
```

---

## Step 6: Enable KMS Key Rotation

KMS supports automatic annual key rotation:

```bash
# Enable key rotation
aws kms enable-key-rotation \
  --key-id "alias/autosecurechain-signing" \
  --region us-east-1

# Check rotation status
aws kms get-key-rotation-status \
  --key-id "alias/autosecurechain-signing" \
  --region us-east-1

# Output:
# {
#     "KeyRotationEnabled": true
# }
```

**Note:** KMS handles rotation transparently - the key material is rotated, but the KeyId remains the same.

---

## Step 7: Monitor and Audit

### CloudTrail Logging

KMS operations are automatically logged in CloudTrail. View logs:

```bash
# Search for Sign operations
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=Sign \
  --region us-east-1 \
  --query 'Events[*].[EventTime,Username,CloudTrailEvent]' \
  --output table
```

### CloudWatch Metrics

Monitor KMS operations:

```bash
# Get UserErrorCount metric (failed requests)
aws cloudwatch get-metric-statistics \
  --namespace "AWS/KMS" \
  --metric-name "UserErrorCount" \
  --dimensions Name=KeyId,Value="alias/autosecurechain-signing" \
  --statistics Sum \
  --start-time 2026-05-01T00:00:00Z \
  --end-time 2026-05-09T00:00:00Z \
  --period 3600
```

---

## Cost Estimation

| Operation | Cost |
|---|---|
| KMS customer-managed key | $1/month |
| Sign operation | $0.01 per operation |
| Verify operation | Free (local public key) |
| Data key generation | $0.01 per operation |
| Annual key rotation | No additional cost |

**Example:** 1000 firmware signatures/month = $10 KMS costs + $1 base = **$11/month**

---

## Troubleshooting

### Error: "Invalid KMS key ID"
```
Solution: Verify key ARN and region match
aws kms describe-key --key-id "alias/autosecurechain-signing" --region us-east-1
```

### Error: "Access Denied"
```
Solution: Check IAM permissions
aws iam get-user
aws iam list-user-policies --user-name autosecurechain-app
```

### Error: "The key is pending import"
```
Solution: Wait for key import to complete (usually immediate)
Or recreate the key
```

### KMS Throttling
```
Solution: Implement exponential backoff
AWS default: 5,000 requests/second per account
Contact AWS for limit increase if needed
```

---

## PKCS#11 HSM Configuration (Alternative: YubiHSM)

For organizations requiring hardware security modules without cloud dependency.

### Prerequisites

- YubiHSM 2 or compatible PKCS#11 HSM
- `yubihsm-shell` installed
- `python-pkcs11` library

```bash
# Install PKCS#11 library
pip install python-pkcs11>=0.7.0

# Install YubiHSM tools
# macOS
brew install yubihsm-shell

# Linux (Ubuntu/Debian)
sudo apt-get install yubihsm-shell

# Windows
# Download from https://developers.yubico.com/YubiHSM2/Releases/
```

### Step 1: Initialize HSM

```bash
# Connect to HSM (default: localhost:12345)
yubihsm-shell

# In HSM shell:
# > connect
# > open 1 password  # Default password
# > audit list

# Generate RSA 4096 key in HSM
> generate asymmetric 0 0 "autosecurechain-signing" \
    1 sign-pkcs rsa4096 exportable-under-wrap
```

### Step 2: Configure PKCS#11

Create PKCS#11 configuration file:

```ini
# /etc/softhsm/softhsm.conf
directories.tokendir = /var/lib/softhsm/tokens/
objectstore.backend = file
log.level = INFO

# Or for YubiHSM:
# /etc/yubihsm/yubihsm-connector.conf
[connector]
listen = 127.0.0.1:12345
```

### Step 3: Use in AutoSecureChain

```bash
# Set environment variables
export AUTOS_KEY_BACKEND="hsm"
export PKCS11_MODULE="/usr/lib/softhsm/libsofthsm2.so"
export PKCS11_SLOT="0"
export PKCS11_PIN="1234"

# Or for YubiHSM
export PKCS11_MODULE="/usr/lib/libyubihsm.so"
```

```python
# Use HSM for signing
python key_manager_cli.py sign firmware.bin \
  --key "autosecurechain-signing" \
  --backend hsm
```

---

## Production Checklist

- [ ] KMS key created with appropriate key spec (RSA_4096)
- [ ] IAM policy created and attached
- [ ] AWS credentials configured and rotated every 90 days
- [ ] Public key retrieved and stored locally
- [ ] Key rotation enabled (annual)
- [ ] CloudTrail logging enabled
- [ ] CloudWatch alarms configured (error rate, throttling)
- [ ] Backup procedure tested
- [ ] Disaster recovery tested
- [ ] Cost budget set and monitored
- [ ] Access control reviewed
- [ ] Compliance requirements verified

---

## Switching Between KMS and Local Keys

### Backup Current Configuration
```bash
# If using local keys, export them
cp -r ~/.autosecurechain/keys ./backup_keys/
```

### Migrate to KMS
```bash
# 1. Create KMS key (see Step 1)
# 2. Get public key from KMS (see Step 4)
# 3. Set environment variable
export AUTOS_KEY_BACKEND="kms"

# 4. Test with new backend
python key_manager_cli.py sign test.bin --backend kms

# 5. Update production configuration
```

### Rollback to Local Keys
```bash
# 1. Restore from backup
cp ./backup_keys/* ~/.autosecurechain/keys/

# 2. Unset KMS environment
unset AUTOS_KEY_BACKEND

# 3. Verify
python key_manager_cli.py list
```

---

## Additional Resources

- [AWS KMS Documentation](https://docs.aws.amazon.com/kms/)
- [YubiHSM Documentation](https://developers.yubico.com/YubiHSM2/)
- [PKCS#11 Standard](http://docs.oasis-open.org/pkcs11/pkcs11-base/v2.40/os/)
- [NIST Key Management Guidelines](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-57Pt1r5.pdf)

---

**Last Updated:** 2026-05-09
**Maintainer:** Infrastructure Team
