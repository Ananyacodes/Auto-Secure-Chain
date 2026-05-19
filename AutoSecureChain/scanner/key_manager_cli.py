#!/usr/bin/env python3
"""
Key Management CLI for AutoSecureChain.
Provides command-line interface for secure key operations and audit logging.
"""
import argparse
import sys
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from AutoSecureChain.scanner.key_manager import KeyManager, AuditLogger
from AutoSecureChain.scanner.cli_validators import (
    ValidationError, validate_key_name, validate_file_path, 
    validate_key_size, validate_passphrase, KeyFileLock,
    format_file_error, format_permission_error, format_key_error
)
import getpass

def main():
    parser = argparse.ArgumentParser(description="AutoSecureChain Key Management")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Generate keypair
    gen_parser = subparsers.add_parser("generate", help="Generate a new keypair")
    gen_parser.add_argument("--name", default="production", help="Key name")
    gen_parser.add_argument("--size", type=int, default=4096, choices=[2048, 3072, 4096], help="Key size in bits")
    gen_parser.add_argument("--passphrase", help="Passphrase to encrypt the private key (optional)")
    gen_parser.add_argument("--use-keyring", action="store_true", help="Store passphrase in OS keyring (optional)")

    # Sign firmware
    sign_parser = subparsers.add_parser("sign", help="Sign firmware file")
    sign_parser.add_argument("firmware", help="Path to firmware file")
    sign_parser.add_argument("--key", default="production", help="Key name to use")
    sign_parser.add_argument("--passphrase", help="Passphrase for private key (if encrypted)")
    sign_parser.add_argument("--use-keyring", action="store_true", help="Retrieve passphrase from OS keyring")
    sign_parser.add_argument("--backend", choices=["local","kms"], default="local", help="Signing backend to use (local or kms)")
    sign_parser.add_argument("--kms-key-id", help="KMS key id or ARN to use when backend=kms")

    # Verify signature
    verify_parser = subparsers.add_parser("verify", help="Verify firmware signature")
    verify_parser.add_argument("firmware", help="Path to firmware file")
    verify_parser.add_argument("--key", default="production", help="Key name to use")
    verify_parser.add_argument("--passphrase", help="Passphrase for private key (if needed)")
    verify_parser.add_argument("--use-keyring", action="store_true", help="Retrieve passphrase from OS keyring")

    # Rotate keys
    rotate_parser = subparsers.add_parser("rotate", help="Rotate to a new keypair")
    rotate_parser.add_argument("old_key", help="Name of key to rotate")
    rotate_parser.add_argument("--new-key", help="Name for new key (auto-generated if not specified)")

    # List keys
    list_parser = subparsers.add_parser("list", help="List all managed keys")
    list_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # Show key info
    info_parser = subparsers.add_parser("info", help="Show key information")
    info_parser.add_argument("key_name", help="Key name")
    info_parser.add_argument("--json", action="store_true", help="Output in JSON format")

    # Audit log commands
    audit_parser = subparsers.add_parser("audit", help="Audit log operations")
    audit_subparsers = audit_parser.add_subparsers(dest="audit_command")

    # Show recent audit events
    audit_recent = audit_subparsers.add_parser("recent", help="Show recent audit events")
    audit_recent.add_argument("--limit", type=int, default=20, help="Number of events to show")
    audit_recent.add_argument("--json", action="store_true", help="Output in JSON format")

    # Search audit events
    audit_search = audit_subparsers.add_parser("search", help="Search audit events")
    audit_search.add_argument("--type", help="Event type filter")
    audit_search.add_argument("--severity", choices=["info", "warning", "error"], help="Severity filter")
    audit_search.add_argument("--limit", type=int, default=50, help="Number of events to show")
    audit_search.add_argument("--json", action="store_true", help="Output in JSON format")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        return

    # Initialize components
    key_manager = KeyManager()
    audit_logger = AuditLogger()

    try:
        if args.command == "generate":
            # Validate key name and size
            try:
                key_name = validate_key_name(args.name)
                key_size = validate_key_size(args.size)
            except ValidationError as e:
                print(f"❌ Validation error: {e}")
                sys.exit(1)
            
            # Use file lock to prevent concurrent key generation
            with KeyFileLock(key_name):
                # Determine passphrase: use provided, else prompt if use-keyring requested or user wants encryption
                passphrase = getattr(args, "passphrase", None)
                use_keyring = getattr(args, "use_keyring", False)

                if not passphrase and use_keyring:
                    if sys.stdin.isatty():
                        p1 = getpass.getpass(prompt="Enter new passphrase to encrypt private key (leave empty for no encryption): ")
                        if p1:
                            p2 = getpass.getpass(prompt="Confirm passphrase: ")
                            if p1 != p2:
                                print("❌ Passphrases do not match")
                                sys.exit(1)
                            try:
                                passphrase = validate_passphrase(p1)
                            except ValidationError as e:
                                print(f"❌ Passphrase validation failed: {e}")
                                sys.exit(1)
                    else:
                        # Non-interactive: rely on keyring or explicit passphrase
                        pass

                result = key_manager.generate_keypair(key_name, key_size, passphrase=passphrase, use_keyring=use_keyring)
                print(f"✅ Keypair generated successfully!")
                print(f"   Key ID: {result['key_id']}")
                print(f"   Private key: {result['private_key_path']}")
                print(f"   Public key: {result['public_key_path']}")
                audit_logger.log_key_operation("generate", result['key_id'], True, {"name": key_name, "size": key_size})

        elif args.command == "sign":
            # Validate inputs
            try:
                firmware_path = validate_file_path(args.firmware, must_exist=True, writable=False)
                key_name = validate_key_name(args.key)
            except ValidationError as e:
                print(f"❌ Validation error: {e}")
                sys.exit(1)
            
            # Use file lock to prevent concurrent signing with same key
            with KeyFileLock(key_name):
                passphrase = getattr(args, "passphrase", None)
                use_keyring = getattr(args, "use_keyring", False)
                if not passphrase and not use_keyring and sys.stdin.isatty():
                    # Prompt for passphrase if user may have an encrypted key
                    p = getpass.getpass(prompt="Enter passphrase for private key (leave empty if not encrypted): ")
                    if p:
                        try:
                            passphrase = validate_passphrase(p)
                        except ValidationError as e:
                            print(f"❌ Passphrase validation failed: {e}")
                            sys.exit(1)

                backend = getattr(args, "backend", "local")
                kms_key_id = getattr(args, "kms_key_id", None)

                # If KMS requested, attempt to create an AWSKMSClient signer
                if backend == "kms":
                    try:
                        from AutoSecureChain.scanner.kms import AWSKMSClient
                        signer = AWSKMSClient()
                        key_manager.signer = signer
                    except Exception as e:
                        print(f"❌ Failed to initialize KMS signer: {e}")
                        sys.exit(1)

                sig_path = key_manager.sign_firmware(firmware_path, key_name, passphrase=passphrase, use_keyring=use_keyring, backend=backend, kms_key_id=kms_key_id)
                print(f"✅ Firmware signed successfully!")
                print(f"   Signature: {sig_path}")
                audit_logger.log_key_operation("sign", key_name, True, {"firmware": str(firmware_path), "backend": backend})

        elif args.command == "verify":
            # Validate inputs
            try:
                firmware_path = validate_file_path(args.firmware, must_exist=True, writable=False)
                key_name = validate_key_name(args.key)
            except ValidationError as e:
                print(f"❌ Validation error: {e}")
                sys.exit(1)
            
            # verify_signature does not need passphrase for public-key only verification,
            # but leave hooks in case private-key-based verification is required later.
            is_valid = key_manager.verify_signature(firmware_path, key_name)
            if is_valid:
                print("✅ Signature verification successful!")
                audit_logger.log_key_operation("verify", key_name, True, {"firmware": str(firmware_path)})
            else:
                print("❌ Signature verification failed!")
                audit_logger.log_key_operation("verify", key_name, False, {"firmware": str(firmware_path)})
                sys.exit(1)

        elif args.command == "rotate":
            # Validate key names
            try:
                old_key_name = validate_key_name(args.old_key)
                new_key_name = validate_key_name(args.new_key) if args.new_key else None
            except ValidationError as e:
                print(f"❌ Validation error: {e}")
                sys.exit(1)
            
            # Use file lock to prevent concurrent rotations
            with KeyFileLock(old_key_name):
                result = key_manager.rotate_key(old_key_name, new_key_name)
                print(f"✅ Key rotated successfully!")
                print(f"   New Key ID: {result['key_id']}")
                print(f"   New key name: {new_key_name or result['info']['name']}")
                audit_logger.log_key_operation("rotate", result['key_id'], True, {"old_key": old_key_name})

        elif args.command == "list":
            keys = key_manager.list_keys()
            if args.json:
                print(json.dumps(keys, indent=2))
            else:
                if not keys:
                    print("No keys found.")
                    return

                print("Managed Keys:")
                print("-" * 80)
                for key in keys:
                    status = key.get("status", "unknown")
                    status_icon = "✅" if status == "active" else "🔄" if status == "rotated" else "❓"
                    try:
                        key_display_name = validate_key_name(key['name'])
                    except ValidationError:
                        key_display_name = key['name']
                    print(f"{status_icon} {key_display_name} ({key['key_id']})")
                    print(f"   Algorithm: {key['algorithm']} {key['key_size']} bits")
                    print(f"   Status: {status}")
                    print(f"   Created: {key['created_at']}")
                    print(f"   Usage: {key.get('usage_count', 0)} times")
                    if key.get('last_used'):
                        print(f"   Last used: {key['last_used']}")
                    print()

        elif args.command == "info":
            # Validate key name
            try:
                key_name = validate_key_name(args.key_name)
            except ValidationError as e:
                print(f"❌ Validation error: {e}")
                sys.exit(1)
            
            info = key_manager.get_key_info(key_name)
            if args.json:
                print(json.dumps(info, indent=2))
            else:
                print(f"Key Information: {key_name}")
                print("-" * 40)
                for k, v in info.items():
                    print(f"{k}: {v}")

        elif args.command == "audit":
            if args.audit_command == "recent":
                events = audit_logger.get_recent_events(args.limit)
                if args.json:
                    print(json.dumps(events, indent=2))
                else:
                    display_audit_events(events)

            elif args.audit_command == "search":
                events = audit_logger.search_events(args.type, args.severity, args.limit)
                if args.json:
                    print(json.dumps(events, indent=2))
                else:
                    display_audit_events(events)
            else:
                audit_parser.print_help()

        else:
            parser.print_help()

    except ValidationError as e:
        print(f"❌ Validation failed: {e}")
        sys.exit(1)
    except FileNotFoundError as e:
        print(f"❌ File not found: {e}")
        sys.exit(1)
    except PermissionError as e:
        print(format_permission_error("access", Path(str(e))))
        sys.exit(1)
    except KeyError as e:
        print(f"❌ Key error: {e}")
        sys.exit(1)
    except Exception as e:
        # Format common OS errors
        if isinstance(e, OSError):
            print(f"❌ {format_file_error('operation', Path('.'), e)}")
        else:
            print(f"❌ Error: {e}")
        
        try:
            audit_logger.log_event("cli_error", "error", str(e), {"command": getattr(args, 'command', 'unknown')})
        except Exception:
            pass  # Audit logging failed, but don't crash
        
        sys.exit(1)

def display_audit_events(events):
    """Display audit events in a readable format."""
    if not events:
        print("No audit events found.")
        return

    print("Recent Audit Events:")
    print("-" * 100)

    for event in events:
        timestamp = event['timestamp'][:19]  # YYYY-MM-DDTHH:MM:SS
        severity = event['severity'].upper()
        event_type = event['event_type'].replace('_', ' ').title()

        severity_icon = {
            "INFO": "ℹ️",
            "WARNING": "⚠️",
            "ERROR": "❌"
        }.get(severity, "❓")

        print(f"{severity_icon} {timestamp} [{severity}] {event_type}")
        print(f"   {event['message']}")

        if event.get('details'):
            for k, v in event['details'].items():
                print(f"   {k}: {v}")

        print()

if __name__ == "__main__":
    main()