# AutoSecureChain - ECU firmware scanner

Purpose
- Static-only ECU firmware scanner for detection and triage. It does not modify firmware or attempt to flash devices.
- Finds insecure artifacts (hardcoded credentials, debug interfaces, cleartext services), detects PEM private keys, estimates entropy, runs YARA rules, and optionally verifies detached signatures using a PEM public key.

Files and detailed descriptions
- scanner/scanner.py
  - Implementation of the scanner logic. Computes SHA256, entropy, extracts printable strings, runs compiled YARA rules (if yara-python installed), and performs optional external signature verification using scanner/public_key.pem and a sibling .sig file.
  - Produces reports/report.json (detailed findings) and reports/mitigation_actions.json (flattened suggested actions).
  - Note: signature verification attempts RSA PKCS#1 v1.5 + SHA256 by default; adapt if vendor uses another scheme.

- scanner/rules.yar
  - YARA rule set detecting telnet/cleartext services, hardcoded credentials/provision tokens, debug/JTAG/UART indicators, and PEM private keys.

- scanner/sample.bin
  - Demo firmware blob (text) containing sample triggers (JAGUAR_PROVISION, PROVISION_TOKEN, telnetd, root:, DEBUG_MODE, PEM markers). Do not place real secrets here.

- reports/report.json
  - Human-readable scan report with timestamp and per-file details (sha256, entropy, matches, suspicious strings, signature info, severity_score, recommended_mitigations).

- reports/mitigation_actions.json
  - Machine-readable flattened list of mitigation actions derived from the report.

Usage (PowerShell)
1. Allow script activation for the session if needed:
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope Process -Force

2. Create and activate a venv; install dependencies:
   python -m venv venv
   .\venv\Scripts\Activate.ps1
   python -m pip install --upgrade pip
   pip install -r requirements.txt

3. Run scanner:
   python AutoSecureChain\scanner\scanner.py

Optional: signature verification
- Set AUTOS_PUBLIC_KEY to the PEM public key path (recommended), or place public_key.pem in a secure folder.
- Never commit private keys.

Optional: Metasploit integration (defensive only)
- Generate resource script and add notes:
  python AutoSecureChain\scripts\generate_msf_rc.py
  msfconsole -r AutoSecureChain\scripts\autosecurechain_notes.rc

- Export via RPC (requires msgrpc):
  Start Metasploit:
    msfconsole -x "load msgrpc ServerHost=0.0.0.0 User=msf Pass=pass123 SSL=false"
  Export:
    .\run-scanner.ps1 -ExportToMetasploitRpc -MsfPass "pass123"
  Options:
    -MsfHost 127.0.0.1 -MsfPort 55553 -MsfUser msf -MsfSsl
## Demo (video + notes script)
```html
<video controls width="720">
  <source src="AutoSecureChain/demo/demo.mp4" type="video/mp4">
  Your browser does not support the video tag. Download the demo at AutoSecureChain/demo/demo.mp4
</video>
```
