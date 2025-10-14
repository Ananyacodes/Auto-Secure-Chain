"""
ECU firmware static scanner with basic signature verification.
- Scans .bin/.img/.fw files in scanner/ for YARA hits, strings, entropy, and optional external .sig verification.
- If a public key is present at scanner/public_key.pem and a .sig file exists next to firmware, verify signature (RSA PKCS#1 v1.5 + SHA256).
- Produces reports in ../reports/: report.json and mitigation_actions.json.
"""
import os
import sys
import json
import math
import re
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORTS = ROOT.parent / "reports"
RULES_PATH = ROOT / "rules.yar"
PUBKEY_PATH = ROOT / "public_key.pem"

REPORTS.mkdir(parents=True, exist_ok=True)

PRINTABLE_RE = re.compile(br'[\x20-\x7E]{4,}')  # printable ascii strings length >=4

def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    freq = {}
    for b in data:
        freq[b] = freq.get(b, 0) + 1
    ent = 0.0
    length = len(data)
    for count in freq.values():
        p = count / length
        ent -= p * math.log2(p)
    return ent

def extract_strings(data: bytes, min_len=4):
    return [s.decode('latin1') for s in PRINTABLE_RE.findall(data)]

def hash_file(path: Path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def verify_external_signature(fw_path: Path):
    # Looks for fw.bin.sig alongside fw_path and a public key at PUBKEY_PATH
    sig_path = fw_path.with_suffix(fw_path.suffix + ".sig")
    if not sig_path.exists() or not PUBKEY_PATH.exists():
        return {"sig_found": sig_path.exists(), "pubkey_found": PUBKEY_PATH.exists(), "valid": None, "error": None}
    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import padding
        from cryptography.hazmat.backends import default_backend
    except Exception as e:
        return {"sig_found": True, "pubkey_found": True, "valid": None, "error": "cryptography not installed: " + str(e)}
    try:
        data = fw_path.read_bytes()
        sig = sig_path.read_bytes()
        pubpem = PUBKEY_PATH.read_bytes()
        pub = serialization.load_pem_public_key(pubpem, backend=default_backend())
        # Try PKCS#1 v1.5 verify with SHA256 (common simple scheme). If different scheme is used, verification will fail.
        pub.verify(
            sig,
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return {"sig_found": True, "pubkey_found": True, "valid": True, "error": None}
    except Exception as e:
        return {"sig_found": True, "pubkey_found": True, "valid": False, "error": str(e)}

def load_rules():
    try:
        import yara
    except Exception:
        return None
    if not RULES_PATH.exists():
        return None
    try:
        return yara.compile(str(RULES_PATH))
    except Exception:
        return None

def scan_file(path: Path, rules):
    data = path.read_bytes()
    result = {
        "file": str(path.name),
        "size_bytes": path.stat().st_size,
        "sha256": hash_file(path),
        "entropy": shannon_entropy(data),
        "strings_count": len(PRINTABLE_RE.findall(data)),
        "matches": [],
        "suspicious_strings": [],
    }

    # signature check
    sig_info = verify_external_signature(path)
    result["signature"] = sig_info

    # extract strings and find suspicious patterns
    strings = extract_strings(data)
    for s in strings:
        low = s.lower()
        if any(tok in low for tok in ("telnet", "root:", "passwd", "password", "jtag", "debug", "uart", "factory", "provision", "hardcoded", "private key", "-----begin rsa private key-----")):
            result["suspicious_strings"].append(s)

    # YARA
    if rules:
        try:
            matches = rules.match(str(path))
            for m in matches:
                result["matches"].append({
                    "rule": m.rule,
                    "tags": m.tags,
                    "strings": [{"offset": s[0], "id": s[1], "data_preview": s[2].decode('latin1', errors='replace')[:200]} for s in m.strings]
                })
        except Exception:
            pass

    # quick severity heuristic
    sev = 0
    if sig_info.get("sig_found") and sig_info.get("valid") is False:
        sev += 3
    elif not sig_info.get("sig_found"):
        sev += 2
    if result["entropy"] > 7.5:
        sev += 1
    sev += min(len(result["suspicious_strings"]), 3)
    sev += min(len(result["matches"]), 5)
    result["severity_score"] = sev

    # suggested mitigations
    mitigations = []
    if sig_info.get("valid") is not True:
        mitigations.append({
            "id": "require_fw_signing",
            "title": "Enforce signed firmware with verified public keys",
            "description": "Ensure each device verifies firmware signatures with a vetted public key and rejects unsigned or invalid updates."
        })
    if any("telnet" in s.lower() for s in result["suspicious_strings"]):
        mitigations.append({"id":"disable_telnet","title":"Disable telnet","description":"Remove telnet/cleartext shells."})
    if any(tok in s.lower() for s in result["suspicious_strings"] for tok in ("jtag","uart","debug")):
        mitigations.append({"id":"protect_debug","title":"Protect debug interfaces","description":"Disable or gate JTAG/UART in production; require physical or cryptographic attestation."})
    if any("provision" in s.lower() or "hardcoded" in s.lower() for s in result["suspicious_strings"]):
        mitigations.append({"id":"rotate_tokens","title":"Rotate hardcoded tokens","description":"Remove hardcoded provisioning tokens; issue unique per-device credentials."})

    result["recommended_mitigations"] = mitigations
    return result

def main():
    rules = load_rules()
    firmware_files = sorted([p for p in ROOT.iterdir() if p.suffix.lower() in (".bin", ".img", ".fw")])
    if not firmware_files:
        print("No firmware files found in scanner/ (looking for .bin, .img, .fw).")
        return

    full_report = {"scanned_at": __import__("datetime").datetime.utcnow().isoformat() + "Z", "files": []}
    for f in firmware_files:
        try:
            r = scan_file(f, rules)
            full_report["files"].append(r)
            print(f"Scanned {f.name}  severity={r['severity_score']}")
        except Exception as e:
            full_report["files"].append({"file": str(f.name), "error": str(e)})

    report_path = REPORTS / "report.json"
    with open(report_path, "w", encoding="utf-8") as fh:
        json.dump(full_report, fh, indent=2)

    mitigation_path = REPORTS / "mitigation_actions.json"
    actions = {"generated_at": full_report["scanned_at"], "actions": []}
    for f in full_report["files"]:
        for m in f.get("recommended_mitigations", []):
            actions["actions"].append({"file": f["file"], **m})
    with open(mitigation_path, "w", encoding="utf-8") as fh:
        json.dump(actions, fh, indent=2)

    print("Reports written to:", report_path, "and", mitigation_path)

if __name__ == "__main__":
    main()
