# Copyright (c) 2026 Plane hardened fork contributors
# SPDX-License-Identifier: AGPL-3.0-only

"""Real loopback TLS checks; no Redis service, Internet or production keys."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import socket
import ssl
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import pytest
import redis

from plane.utils.redis_tls import redis_tls_options


pytestmark = pytest.mark.unit


@pytest.fixture(scope="module")
def tls_identity(tmp_path_factory):
    directory = tmp_path_factory.mktemp("redis-tls")
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    certificate = directory / "certificate.pem"
    private_key = directory / "key.pem"
    certificate.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    private_key.write_bytes(
        key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    )
    private_key.chmod(0o600)
    return certificate, private_key


@contextmanager
def tls_server(identity):
    certificate, key = identity
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(str(certificate), str(key))
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(3)
    errors = []

    def serve():
        try:
            raw, _ = listener.accept()
            raw.settimeout(3)
            with raw:
                try:
                    with context.wrap_socket(raw, server_side=True) as connection:
                        if connection.recv(1):
                            connection.sendall(b"+")
                except ssl.SSLError:
                    # The rejected-certificate cases abort the handshake.
                    pass
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=serve, daemon=True)
    worker.start()
    try:
        yield listener.getsockname()[1]
    finally:
        worker.join(timeout=4)
        listener.close()
        assert not worker.is_alive(), "TLS fixture worker did not exit"
        assert not errors, errors


def connect(port, hostname, options):
    client = redis.Redis.from_url(
        f"rediss://{hostname}:{port}/0", socket_connect_timeout=2, socket_timeout=2, **options
    )
    connection = client.connection_pool.make_connection()
    stream = connection._connect()
    try:
        stream.sendall(b"?")
        assert stream.recv(1) == b"+"
    finally:
        stream.close()


def test_original_insecure_flags_accept_untrusted_wrong_hostname(tls_identity):
    with tls_server(tls_identity) as port:
        connect(port, "127.0.0.1", {"ssl_cert_reqs": None, "ssl_check_hostname": False})


def test_hardened_connection_accepts_valid_trusted_peer(tls_identity):
    options = {**redis_tls_options("rediss://localhost"), "ssl_ca_certs": str(tls_identity[0])}
    with tls_server(tls_identity) as port:
        connect(port, "localhost", options)


def test_hardened_connection_rejects_untrusted_certificate(tls_identity):
    with tls_server(tls_identity) as port:
        with pytest.raises(ssl.SSLCertVerificationError):
            connect(port, "localhost", redis_tls_options("rediss://localhost"))


def test_hardened_connection_rejects_wrong_hostname_even_with_trusted_ca(tls_identity):
    options = {**redis_tls_options("rediss://localhost"), "ssl_ca_certs": str(tls_identity[0])}
    with tls_server(tls_identity) as port:
        with pytest.raises(ssl.SSLCertVerificationError):
            connect(port, "127.0.0.1", options)
