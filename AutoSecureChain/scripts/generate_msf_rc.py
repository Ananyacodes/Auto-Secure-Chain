from __future__ import annotations
import json
from pathlib import Path

"""
Generate a Metasploit resource script (.rc) that adds notes summarizing AutoSecureChain results.
Defensive use only. Does not run exploits.

Usage:
  python AutoSecureChain/scripts/generate_msf_rc.py
Then:
  msfconsole -r AutoSecureChain/scripts/autosecurechain_notes.rc
"""

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = PROJECT_ROOT / "reports" / "report.json"
OUT_RC = PROJECT_ROOT / "scripts" / "autosecurechain_notes.rc"


def safe(s: str) -> str:
    return (s or "").replace('"', "'").replace("\n", " ").strip()


def main() -> int:
    if not REPORT_PATH.exists():
        print(f"Report not found: {REPORT_PATH}")
        return 2

    report = json.loads(REPORT_PATH.read_text(encoding="utf-8"))
    files = report.get("files", [])

    lines = []
    lines.append("# AutoSecureChain Metasploit notes resource script")
    lines.append("# Defensive use only. Adds notes to the database with scan summaries.")
    lines.append("")
    lines.append("workspace -a AutoSecureChain")
    lines.append("workspace AutoSecureChain")
    lines.append("")

    for f in files:
        fname = f.get("file", "unknown")
        sev = f.get("severity_score", 0)
        sha256 = f.get("sha256", "")
        sig = f.get("signature", {}) or {}
        sig_found = sig.get("sig_found", False)
        sig_valid = sig.get("valid", None)
        susp = f.get("suspicious_strings", []) or []
        matches = f.get("matches", []) or []

        summary = {
            "file": fname,
            "sha256": sha256,
            "severity": sev,
            "sig_found": sig_found,
            "sig_valid": sig_valid,
            "suspicious_count": len(susp),
            "yara_matches": len(matches),
        }
        data = " ".join(f"{k}={safe(str(v))}" for k, v in summary.items())
        note_type = f"autosecurechain.{fname}".replace(" ", "_")
        lines.append(f'notes -a -t {note_type} -d "{data}" -h autosecurechain')

    OUT_RC.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote Metasploit resource script: {OUT_RC}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
