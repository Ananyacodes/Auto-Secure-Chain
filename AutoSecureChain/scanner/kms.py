"""
KMS/HSM signer abstractions for AutoSecureChain.
Provides a SignerBase interface and optional AWS KMS adapter.
"""
from typing import Optional
import logging

logger = logging.getLogger(__name__)


class SignerBase:
    """Abstract signer interface."""

    def sign(self, data: bytes, key_identifier: str, algorithm: Optional[str] = None) -> bytes:
        raise NotImplementedError()


# Optional AWS KMS adapter
try:
    import boto3
    from botocore.exceptions import BotoCoreError, ClientError
    _BOTO3_AVAILABLE = True
except Exception:
    boto3 = None
    _BOTO3_AVAILABLE = False


class AWSKMSClient(SignerBase):
    """Adapter for AWS KMS signing operations.

    Requires AWS credentials in environment/instance profile and a KeyId/ARN passed as key_identifier.
    """

    def __init__(self, region_name: Optional[str] = None):
        if not _BOTO3_AVAILABLE:
            raise RuntimeError("boto3 is not installed; AWS KMS client unavailable")
        self.client = boto3.client("kms", region_name=region_name)

    def sign(self, data: bytes, key_identifier: str, algorithm: Optional[str] = None) -> bytes:
        # Default to RSA PKCS1 v1.5 + SHA-256
        signing_algorithm = algorithm or "RSASSA_PKCS1_V1_5_SHA_256"
        try:
            response = self.client.sign(
                KeyId=key_identifier,
                Message=data,
                MessageType='RAW',
                SigningAlgorithm=signing_algorithm
            )
            signature = response.get('Signature')
            return signature
        except (BotoCoreError, ClientError) as e:
            logger.error("AWS KMS signing failed: %s", e)
            raise


class PKCS11HSMClient(SignerBase):
    """Placeholder adapter for PKCS#11 HSMs. Integration depends on platform libs (e.g., python-pkcs11).

    This is a stub: implementing a full PKCS#11 client is environment-specific and out of
    scope for this repository's immediate unit tests.
    """

    def __init__(self, library_path: str, slot: Optional[int] = None):
        raise NotImplementedError("PKCS#11 HSM support not implemented in this environment")
