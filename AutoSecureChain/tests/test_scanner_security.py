import json
from pathlib import Path

from AutoSecureChain.scanner import scanner


def test_resolve_public_key_path_prefers_env(monkeypatch, tmp_path):
    custom_key = tmp_path / "custom-public.pem"
    custom_key.write_text("PUBLIC KEY", encoding="utf-8")
    monkeypatch.setenv("AUTOS_PUBLIC_KEY", str(custom_key))

    key_path, source = scanner.resolve_public_key_path()

    assert key_path == custom_key
    assert source == "env"


def test_resolve_public_key_path_uses_managed_key(monkeypatch, tmp_path):
    monkeypatch.delenv("AUTOS_PUBLIC_KEY", raising=False)
    managed_dir = tmp_path / ".autosecurechain"
    managed_dir.mkdir(parents=True, exist_ok=True)
    managed_key = managed_dir / "public_key.pem"
    managed_key.write_text("PUBLIC KEY", encoding="utf-8")
    monkeypatch.setattr(scanner, "KEYS_DIR", managed_dir)

    key_path, source = scanner.resolve_public_key_path()

    assert key_path == managed_key
    assert source == "managed"


def test_append_audit_event_writes_jsonl(monkeypatch, tmp_path):
    audit_log = tmp_path / "audit.log"
    monkeypatch.setattr(scanner, "AUDIT_LOG_PATH", audit_log)

    scanner.append_audit_event("signature_verification", {"file": "sample.bin", "valid": True})

    lines = audit_log.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 1
    payload = json.loads(lines[0])
    assert payload["action"] == "signature_verification"
    assert payload["details"]["file"] == "sample.bin"
    assert payload["details"]["valid"] is True
    assert payload["timestamp"].endswith("Z")
