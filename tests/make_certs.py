"""Create throwaway test certificates for the signature tests.

Everything is written to tests/build/ (git-ignored). The private keys are
generated fresh on every run and must never be committed.
"""
import datetime as dt
from pathlib import Path
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

OUT = Path(__file__).parent / "build"
OUT.mkdir(exist_ok=True)

def make(name, org, not_before, not_after, eku):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                         x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
                         x509.NameAttribute(NameOID.COMMON_NAME, org)])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject)      # self-signed
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(not_before).not_valid_after(not_after)
            .add_extension(x509.ExtendedKeyUsage([eku]), critical=(eku == ExtendedKeyUsageOID.TIME_STAMPING))
            .sign(key, hashes.SHA256()))
    (OUT / f"{name}.key").write_bytes(key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()))
    (OUT / f"{name}.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))

now = dt.datetime.now(dt.timezone.utc)
utc = dt.timezone.utc
make("fresh", "Evil Test LLC", now - dt.timedelta(days=2), now + dt.timedelta(days=365), ExtendedKeyUsageOID.CODE_SIGNING)
make("expired", "Old Tools Ltd", dt.datetime(2019, 1, 1, tzinfo=utc), dt.datetime(2021, 1, 1, tzinfo=utc), ExtendedKeyUsageOID.CODE_SIGNING)
make("hostile", "<img src=x onerror=window.__pwned=20>", now - dt.timedelta(days=400), now + dt.timedelta(days=400), ExtendedKeyUsageOID.CODE_SIGNING)
make("tsa", "Test Timestamp Authority", now - dt.timedelta(days=3000), now + dt.timedelta(days=3000), ExtendedKeyUsageOID.TIME_STAMPING)
print("test certificates written to", OUT)
