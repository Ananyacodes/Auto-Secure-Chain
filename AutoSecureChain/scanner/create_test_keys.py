from pathlib import Path
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

ROOT = Path(__file__).resolve().parent
sample = ROOT / "sample.bin"
priv = ROOT / "test_private.pem"
pub = ROOT / "public_key.pem"
sig = ROOT / "sample.bin.sig"

# generate keypair (development/test only)
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
priv_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
pub_pem = key.public_key().public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
)

priv.write_bytes(priv_pem)
pub.write_bytes(pub_pem)
print(f"Written test private key -> {priv}\nWritten public key -> {pub}")

# sign sample.bin (detached PKCS#1 v1.5 + SHA256)
data = sample.read_bytes()
signature = key.sign(data, padding.PKCS1v15(), hashes.SHA256())
sig.write_bytes(signature)
print(f"Signed {sample.name} -> {sig}")
