import json
from pathlib import Path

REPORT = Path(__file__).resolve().parents[1] / "reports" / "report.json"

def main() -> int:
    if not REPORT.exists():
        print(f"Report not found: {REPORT}")
        return 2
    r = json.loads(REPORT.read_text(encoding="utf-8"))
    for f in r.get("files", []):
        file = f.get("file", "unknown")
        sha = f.get("sha256", "")
        sev = f.get("severity_score", 0)
        sig = f.get("signature", {}) or {}
        sf = sig.get("sig_found", False)
        sv = sig.get("valid", None)
        susp = len(f.get("suspicious_strings", []))
        y = len(f.get("matches", []))
        data = f'file={file} sha256={sha} severity={sev} sig_found={sf} sig_valid={sv} suspicious_count={susp} yara_matches={y}'
        print(f'notes -a -t autosecurechain.{file} -d "{data}" -h autosecurechain')
    return 0

if __name__ == "__main__":
    raise SystemExit(main())