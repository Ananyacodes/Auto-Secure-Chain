"""
Export AutoSecureChain scan results to Metasploit via RPC.
Creates/selects a workspace and adds notes summarizing findings.
Defensive only. Requires authorized environment and running msgrpc.

Start msgrpc (example):
  msfconsole -x "load msgrpc ServerHost=0.0.0.0 User=msf Pass=pass123 SSL=false"

Usage:
  python AutoSecureChain/scripts/export_to_metasploit.py --password pass123
  python AutoSecureChain/scripts/export_to_metasploit.py --host 127.0.0.1 --port 55553 --user msf --password pass123 --workspace AutoSecureChain

Requires: pymetasploit3
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from pymetasploit3.msfrpc import MsfRpcClient

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_REPORT = PROJECT_ROOT / "reports" / "report.json"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Export AutoSecureChain report to Metasploit RPC as notes.")
    p.add_argument("--report", default=str(DEFAULT_REPORT), help="Path to report.json")
    p.add_argument("--host", default="127.0.0.1", help="Metasploit RPC host")
    p.add_argument("--port", type=int, default=55553, help="Metasploit RPC port")
    p.add_argument("--ssl", action="store_true", help="Use SSL for RPC")
    p.add_argument("--user", default="msf", help="Metasploit RPC username")
    p.add_argument("--password", required=True, help="Metasploit RPC password")
    p.add_argument("--workspace", default="AutoSecureChain", help="Workspace name")
    return p.parse_args()


def safe(s: str) -> str:
    return (s or "").replace('"', "'").replace("\n", " ").strip()


def main() -> int:
    args = parse_args()
    rep_path = Path(args.report)
    if not rep_path.exists():
        print(f"Report not found: {rep_path}")
        return 2

    report = json.loads(rep_path.read_text(encoding="utf-8"))
    files = report.get("files", [])

    client = MsfRpcClient(
        args.password,
        username=args.user,
        ssl=args.ssl,
        server=args.host,
        port=args.port,
    )

    cons = client.consoles.console()
    def run(cmd: str):
        cons.run_cmd(cmd)

    run(f"workspace -a {args.workspace}")
    run(f"workspace {args.workspace}")

    host_label = "autosecurechain"

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

        run(f'notes -a -t {note_type} -d "{data}" -h {host_label}')

    print(f"Exported {len(files)} file note(s) to Metasploit workspace '{args.workspace}'.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
