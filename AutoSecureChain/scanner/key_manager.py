"""
Secure key management utilities for AutoSecureChain.
Provides secure key generation, storage, and rotation capabilities.
"""
import os
import json
import hashlib
import secrets
from pathlib import Path
from typing import Optional
from datetime import datetime, timezone
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import logging

logger = logging.getLogger(__name__)

# Optional OS keyring support for passphrase storage
try:
    import keyring
    _KEYRING_AVAILABLE = True
except Exception:
    keyring = None
    _KEYRING_AVAILABLE = False

class KeyManager:
    """Secure key management for firmware signing and verification."""

    def __init__(self, key_dir: Path = None, signer=None):
        """Initialize KeyManager.

        Args:
            key_dir: Optional custom key directory.
            signer: Optional external signer implementing sign(data, key_identifier) for KMS/HSM.
        """

        default_dir = Path.home() / ".autosecurechain" / "keys"
        configured_dir = Path(os.environ["AUTOS_KEY_DIR"]) if os.environ.get("AUTOS_KEY_DIR") else None
        self.key_dir = key_dir or configured_dir or default_dir

        try:
            self.key_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            fallback_dir = Path.cwd() / ".autosecurechain" / "keys"
            if self.key_dir != fallback_dir:
                logger.warning("Falling back to workspace-local key directory: %s", fallback_dir)
                self.key_dir = fallback_dir
                self.key_dir.mkdir(parents=True, exist_ok=True)
            else:
                raise
        self.audit_log = self.key_dir / "audit.log"
        # Optional external signer (KMS/HSM adapter)
        self.signer = signer

    def generate_keypair(self, key_name: str = "production", key_size: int = 4096, passphrase: Optional[str] = None, use_keyring: bool = False) -> dict:
        """Generate a new RSA keypair for firmware signing."""
        logger.info(f"Generating new RSA keypair: {key_name} ({key_size} bits)")

        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=key_size,
            backend=default_backend()
        )

        # Generate public key
        public_key = private_key.public_key()

        # Serialize keys (optionally encrypt private key with passphrase)
        if passphrase:
            encryption = serialization.BestAvailableEncryption(passphrase.encode())
        else:
            encryption = serialization.NoEncryption()

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Create key metadata
        key_id = hashlib.sha256(public_pem).hexdigest()[:16]
        timestamp = datetime.now(timezone.utc).isoformat()

        key_info = {
            "key_id": key_id,
            "name": key_name,
            "algorithm": "RSA",
            "key_size": key_size,
            "created_at": timestamp,
            "status": "active",
            "usage_count": 0,
            "last_used": None
        }

        # Save keys securely
        private_path = self.key_dir / f"{key_name}_private.pem"
        public_path = self.key_dir / f"{key_name}_public.pem"
        info_path = self.key_dir / f"{key_name}_info.json"

        # WARNING: In production, private keys should be encrypted and stored securely
        private_path.write_bytes(private_pem)
        private_path.chmod(0o600)  # Owner read/write only

        public_path.write_bytes(public_pem)
        public_path.chmod(0o644)  # Owner read/write, others read

        info_path.write_text(json.dumps(key_info, indent=2))
        info_path.chmod(0o644)

        # Optionally store passphrase in OS keyring
        if passphrase and use_keyring and _KEYRING_AVAILABLE:
            try:
                keyring.set_password("AutoSecureChain", key_name, passphrase)
                logger.info("Stored passphrase for key %s in OS keyring", key_name)
            except Exception as e:
                logger.warning("Failed to store passphrase in keyring: %s", e)

        # Audit log
        self._audit_log("key_generated", {
            "key_id": key_id,
            "name": key_name,
            "key_size": key_size
        })

        logger.info(f"Keypair generated and saved: {key_id}")
        return {
            "key_id": key_id,
            "private_key_path": str(private_path),
            "public_key_path": str(public_path),
            "info": key_info
        }

    def sign_firmware(self, firmware_path: Path, key_name: str = "production", passphrase: Optional[str] = None, use_keyring: bool = False, backend: Optional[str] = None, kms_key_id: Optional[str] = None) -> Path:
        """Sign firmware using the specified key or an external signer (KMS/HSM).

        backend: 'local' or 'kms' (if using external signer)
        kms_key_id: explicit key identifier for KMS/HSM when backend='kms'
        """
        # Load firmware
        firmware_data = firmware_path.read_bytes()

        # If an external signer is configured and requested, use it
        use_external = False
        key_identifier = None
        if backend == 'kms' or kms_key_id or (isinstance(key_name, str) and key_name.startswith('kms:')):
            use_external = True
            if kms_key_id:
                key_identifier = kms_key_id
            elif isinstance(key_name, str) and key_name.startswith('kms:'):
                key_identifier = key_name.split(':', 1)[1]
            else:
                key_identifier = key_name

        if use_external:
            if not self.signer:
                raise RuntimeError("External signer requested but no signer configured on KeyManager")

            signature = self.signer.sign(firmware_data, key_identifier)

            # Save signature
            sig_path = firmware_path.with_suffix(firmware_path.suffix + ".sig")
            sig_path.write_bytes(signature)

            # Audit
            self._audit_log("firmware_signed", {
                "firmware": str(firmware_path),
                "key_name": key_name,
                "signature_path": str(sig_path),
                "backend": "external"
            })

            logger.info(f"Firmware signed via external signer: {firmware_path} -> {sig_path}")
            return sig_path

        # Local signing path (existing behavior)
        private_path = self.key_dir / f"{key_name}_private.pem"
        info_path = self.key_dir / f"{key_name}_info.json"

        if not private_path.exists():
            raise FileNotFoundError(f"Private key not found: {private_path}")

        # Load private key
        private_pem = private_path.read_bytes()
        # Determine password: explicit > keyring > None
        password_bytes = None
        if passphrase:
            password_bytes = passphrase.encode()
        elif use_keyring and _KEYRING_AVAILABLE:
            try:
                stored = keyring.get_password("AutoSecureChain", key_name)
                if stored:
                    password_bytes = stored.encode()
            except Exception:
                password_bytes = None

        private_key = serialization.load_pem_private_key(
            private_pem,
            password=password_bytes,
            backend=default_backend()
        )

        # Create signature
        signature = private_key.sign(
            firmware_data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )

        # Save signature
        sig_path = firmware_path.with_suffix(firmware_path.suffix + ".sig")
        sig_path.write_bytes(signature)

        # Update key usage
        if info_path.exists():
            info = json.loads(info_path.read_text())
            info["usage_count"] += 1
            info["last_used"] = datetime.now(timezone.utc).isoformat()
            info_path.write_text(json.dumps(info, indent=2))

        # Audit log
        self._audit_log("firmware_signed", {
            "firmware": str(firmware_path),
            "key_name": key_name,
            "signature_path": str(sig_path)
        })

        logger.info(f"Firmware signed: {firmware_path} -> {sig_path}")
        return sig_path

    def verify_signature(self, firmware_path: Path, key_name: str = "production") -> bool:
        """Verify firmware signature using the specified key."""
        public_path = self.key_dir / f"{key_name}_public.pem"
        sig_path = firmware_path.with_suffix(firmware_path.suffix + ".sig")

        if not public_path.exists():
            raise FileNotFoundError(f"Public key not found: {public_path}")

        if not sig_path.exists():
            raise FileNotFoundError(f"Signature not found: {sig_path}")

        # Load public key
        public_pem = public_path.read_bytes()
        public_key = serialization.load_pem_public_key(
            public_pem,
            backend=default_backend()
        )

        # Load firmware and signature
        firmware_data = firmware_path.read_bytes()
        signature = sig_path.read_bytes()

        try:
            # Verify signature
            public_key.verify(
                signature,
                firmware_data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )

            # Update key usage
            info_path = self.key_dir / f"{key_name}_info.json"
            if info_path.exists():
                info = json.loads(info_path.read_text())
                info["usage_count"] += 1
                info["last_used"] = datetime.now(timezone.utc).isoformat()
                info_path.write_text(json.dumps(info, indent=2))

            # Audit log
            self._audit_log("signature_verified", {
                "firmware": str(firmware_path),
                "key_name": key_name,
                "result": "valid"
            })

            return True

        except InvalidSignature:
            # Audit log failure
            self._audit_log("signature_verified", {
                "firmware": str(firmware_path),
                "key_name": key_name,
                "result": "invalid"
            })
            return False

    def rotate_key(self, old_key_name: str, new_key_name: str = None) -> dict:
        """Rotate to a new keypair, keeping the old one for verification."""
        if new_key_name is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            new_key_name = f"{old_key_name}_{timestamp}"

        # Generate new key
        new_key_info = self.generate_keypair(new_key_name)

        # Mark old key as rotated
        old_info_path = self.key_dir / f"{old_key_name}_info.json"
        if old_info_path.exists():
            old_info = json.loads(old_info_path.read_text())
            old_info["status"] = "rotated"
            old_info["rotated_to"] = new_key_info["key_id"]
            old_info["rotated_at"] = datetime.now(timezone.utc).isoformat()
            old_info_path.write_text(json.dumps(old_info, indent=2))

        # Audit log
        self._audit_log("key_rotated", {
            "old_key": old_key_name,
            "new_key": new_key_name,
            "new_key_id": new_key_info["key_id"]
        })

        logger.info(f"Key rotated: {old_key_name} -> {new_key_name}")
        return new_key_info

    def list_keys(self) -> list:
        """List all managed keys."""
        keys = []
        for info_file in self.key_dir.glob("*_info.json"):
            try:
                info = json.loads(info_file.read_text())
                keys.append(info)
            except Exception as e:
                logger.warning(f"Failed to read key info {info_file}: {e}")

        return sorted(keys, key=lambda x: x.get("created_at", ""), reverse=True)

    def get_key_info(self, key_name: str) -> dict:
        """Get information about a specific key."""
        info_path = self.key_dir / f"{key_name}_info.json"
        if not info_path.exists():
            raise FileNotFoundError(f"Key info not found: {key_name}")

        return json.loads(info_path.read_text())

    def _audit_log(self, action: str, details: dict):
        """Log security-relevant actions to audit trail."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "details": details,
            "user": os.environ.get("USER", "unknown"),
            "hostname": os.environ.get("COMPUTERNAME", "unknown")
        }

        # Append to audit log
        with open(self.audit_log, "a", encoding="utf-8") as f:
            json.dump(entry, f)
            f.write("\n")

    def get_audit_log(self, limit: int = 100) -> list:
        """Retrieve recent audit log entries."""
        if not self.audit_log.exists():
            return []

        entries = []
        with open(self.audit_log, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        return entries[-limit:]  # Return most recent entries

    def cleanup_expired_keys(self, max_age_days: int = 365):
        """Clean up old rotated keys (use with caution)."""
        # This is a basic implementation - in production you'd want more sophisticated
        # key lifecycle management
        pass


class AuditLogger:
    """Centralized audit logging for security events."""

    def __init__(self, log_dir: Path = None):
        default_dir = Path.home() / ".autosecurechain" / "logs"
        configured_dir = Path(os.environ["AUTOS_AUDIT_DIR"]) if os.environ.get("AUTOS_AUDIT_DIR") else None
        self.log_dir = log_dir or configured_dir or default_dir

        try:
            self.log_dir.mkdir(parents=True, exist_ok=True)
        except PermissionError:
            fallback_dir = Path.cwd() / ".autosecurechain" / "logs"
            if self.log_dir != fallback_dir:
                logger.warning("Falling back to workspace-local audit directory: %s", fallback_dir)
                self.log_dir = fallback_dir
                self.log_dir.mkdir(parents=True, exist_ok=True)
            else:
                raise
        self.current_log = self.log_dir / f"audit_{datetime.now().strftime('%Y%m%d')}.log"

    def log_event(self, event_type: str, severity: str, message: str, details: dict = None):
        """Log a security event."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "details": details or {},
            "user": os.environ.get("USER", "unknown"),
            "session_id": secrets.token_hex(8)
        }

        # Write to current day's log
        with open(self.current_log, "a", encoding="utf-8") as f:
            json.dump(entry, f)
            f.write("\n")

        # Also log to console for immediate visibility
        logger.info(f"AUDIT [{severity}] {event_type}: {message}")

    def log_scan_start(self, target: str, user: str = None):
        """Log the start of a firmware scan."""
        self.log_event(
            "scan_started",
            "info",
            f"Firmware scan initiated for: {target}",
            {"target": target, "user": user}
        )

    def log_scan_complete(self, target: str, findings: int, duration: float):
        """Log the completion of a firmware scan."""
        severity = "warning" if findings > 0 else "info"
        self.log_event(
            "scan_completed",
            severity,
            f"Firmware scan completed for: {target} ({findings} findings, {duration:.2f}s)",
            {"target": target, "findings": findings, "duration": duration}
        )

    def log_security_finding(self, file: str, finding_type: str, severity: str, details: dict = None):
        """Log a security finding."""
        self.log_event(
            "security_finding",
            severity,
            f"Security issue found in {file}: {finding_type}",
            {"file": file, "finding_type": finding_type, **(details or {})}
        )

    def log_key_operation(self, operation: str, key_id: str, success: bool, details: dict = None):
        """Log key management operations."""
        severity = "error" if not success else "info"
        status = "succeeded" if success else "failed"

        self.log_event(
            "key_operation",
            severity,
            f"Key {operation} {status}: {key_id}",
            {"operation": operation, "key_id": key_id, "success": success, **(details or {})}
        )

    def get_recent_events(self, limit: int = 50) -> list:
        """Get recent audit events."""
        if not self.current_log.exists():
            return []

        events = []
        with open(self.current_log, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    try:
                        events.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue

        return events[-limit:]

    def search_events(self, event_type: str = None, severity: str = None, limit: int = 100) -> list:
        """Search audit events by type and severity."""
        events = self.get_recent_events(1000)  # Get more to search through

        filtered = []
        for event in events:
            if event_type and event.get("event_type") != event_type:
                continue
            if severity and event.get("severity") != severity:
                continue
            filtered.append(event)

        return filtered[-limit:]