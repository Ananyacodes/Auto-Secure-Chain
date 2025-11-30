# filepath: AutoSecureChain\ui\app.py
from pathlib import Path
import json
from flask import Flask, render_template, abort, send_file

APP_ROOT = Path(__file__).resolve().parents[1]
REPORT_PATH = APP_ROOT / "reports" / "report.json"
SCRIPTS_DIR = APP_ROOT / "scripts"
OUT_RC = SCRIPTS_DIR / "autosecurechain_notes.rc"

app = Flask(__name__, template_folder="templates")


def load_report():
    if not REPORT_PATH.exists():
        return {"scanned_at": None, "files": []}
    return json.loads(REPORT_PATH.read_text(encoding="utf-8"))


def make_notes_lines(report):
    lines = []
    for f in report.get("files", []):
        fname = f.get("file", "unknown")
        sha = f.get("sha256", "")
        sev = f.get("severity_score", 0)
        sig = f.get("signature", {}) or {}
        sf = sig.get("sig_found", False)
        sv = sig.get("valid", None)
        susp = len(f.get("suspicious_strings", []))
        yara = len(f.get("matches", []))
        data = f'file={fname} sha256={sha} severity={sev} sig_found={sf} sig_valid={sv} suspicious_count={susp} yara_matches={yara}'
        lines.append(f'notes -a -t autosecurechain.{fname} -d "{data}" -h autosecurechain')
    return lines


@app.route("/")
def index():
    report = load_report()
    return render_template("index.html", report=report)


@app.route("/file/<path:fname>")
def file_view(fname):
    report = load_report()
    for f in report.get("files", []):
        if f.get("file") == fname:
            return render_template("file.html", file=f)
    abort(404)


@app.route("/notes")
def notes_view():
    report = load_report()
    lines = make_notes_lines(report)
    return render_template("notes.html", lines=lines)


@app.route("/download-rc")
def download_rc():
    report = load_report()
    SCRIPTS_DIR.mkdir(parents=True, exist_ok=True)
    lines = [
        "# AutoSecureChain Metasploit notes resource script",
        "# Defensive use only. Adds notes to the database with scan summaries.",
        "",
        "workspace -a AutoSecureChain",
        "workspace AutoSecureChain",
        "",
    ]
    lines += make_notes_lines(report)
    OUT_RC.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return send_file(str(OUT_RC), as_attachment=True)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
