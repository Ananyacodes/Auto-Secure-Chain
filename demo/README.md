# Demo Files

This directory contains sample files for testing and demonstrating the AutoSecureChain firmware scanner.

## Sample Reports

- **`sample_report.json`**: Complete scan report showing various security findings across multiple firmware files
- **`sample_mitigation_actions.json`**: Corresponding mitigation recommendations for the sample report

## Sample Firmware

- **`sample_firmware.bin`**: Firmware file containing various security issues for testing:
  - Telnet service indicators
  - Debug mode flags
  - Hardcoded credentials
  - JTAG enable flags
  - Provisioning tokens

- **`clean_sample.bin`**: Clean firmware file without security issues for comparison

## Usage

### Load Sample Report in Frontend

1. Start the Flask backend:
   ```powershell
   python AutoSecureChain/ui/app.py
   ```

2. Open http://localhost:5000 in your browser

3. Click "Load report.json" and select `demo/sample_report.json`

### Run Scanner on Demo Files

```powershell
# Scan the demo firmware
python AutoSecureChain/scanner/scanner.py -i demo/

# View results
Get-Content AutoSecureChain/reports/report.json | ConvertFrom-Json
```

### Expected Results

The `sample_firmware.bin` should trigger multiple YARA rules and show:
- Severity score: 6-8 (high risk)
- Multiple suspicious strings detected
- Recommended mitigations for telnet, debug interfaces, and credentials

The `clean_sample.bin` should show:
- Severity score: 0-2 (low risk)
- No suspicious strings
- Minimal or no mitigations needed

## Report Structure

```json
{
  "scanned_at": "ISO timestamp",
  "files": [
    {
      "file": "filename.bin",
      "size_bytes": 12345,
      "sha256": "hash...",
      "entropy": 7.234,
      "strings_count": 1247,
      "matches": [
        {
          "rule": "rule_name",
          "tags": ["tag1", "tag2"],
          "strings": [
            {
              "offset": 12345,
              "id": "$string_id",
              "data_preview": "matched text"
            }
          ]
        }
      ],
      "suspicious_strings": ["string1", "string2"],
      "signature": {
        "sig_found": true,
        "pubkey_found": true,
        "valid": true,
        "error": null
      },
      "severity_score": 7,
      "recommended_mitigations": [
        {
          "id": "mitigation_id",
          "title": "Mitigation Title",
          "description": "Detailed description"
        }
      ]
    }
  ]
}
```

## Security Findings Legend

- **Severity 0-2**: Low risk, minimal issues
- **Severity 3-6**: Medium risk, requires attention
- **Severity 7-10**: High risk, critical security issues

Common findings:
- **Telnet/Debug Services**: Cleartext protocols and debug interfaces
- **Hardcoded Credentials**: Embedded passwords and tokens
- **Unsigned Firmware**: Missing or invalid cryptographic signatures
- **High Entropy**: Potential encrypted/packed malware indicators