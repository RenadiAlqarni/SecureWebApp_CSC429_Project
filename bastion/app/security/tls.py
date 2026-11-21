"""
TLS (HTTPS) setup for local development.

A self-signed certificate for localhost / 127.0.0.1 is generated on first run
with the `cryptography` package (no openssl command needed). The server only
accepts TLS 1.2 or newer, with Python's default modern cipher list.

Browsers will warn that the certificate is self-signed - expected on a local
machine. In production you would use a certificate from a real authority
(e.g. Let's Encrypt), or run `mkcert` locally for a browser-trusted cert, and
point BASTION_TLS_CERT / BASTION_TLS_KEY at those files.
"""
import datetime
import ipaddress
import os
import ssl

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID


def ensure_self_signed_cert(folder):
    cert_path = os.environ.get("BASTION_TLS_CERT") or os.path.join(folder, "cert.pem")
    key_path = os.environ.get("BASTION_TLS_KEY") or os.path.join(folder, "key.pem")
    if os.path.exists(cert_path) and os.path.exists(key_path):
        return cert_path, key_path

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Bastion (development)"),
    ])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=365))
        .add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName("localhost"),
                x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
            ]),
            critical=False,
        )
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ))
    with open(cert_path, "wb") as fh:
        fh.write(cert.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def build_ssl_context(cert_path, key_path):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2   # no SSLv3 / TLS 1.0 / TLS 1.1
    ctx.load_cert_chain(cert_path, key_path)
    return ctx
