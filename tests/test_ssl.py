import socket
import ssl
import threading
from datetime import datetime, timedelta, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from wp_maintenance.ssl_audit import classify_days, connect_and_inspect, hostname_matches, ssl_findings

pytestmark = pytest.mark.real_tls  # local loopback TLS servers only; never the internet


def _key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def _build(subject, issuer, key, signer, days_from, days_to, sans=None, ca=False):
    now = datetime.now(timezone.utc)
    builder = (x509.CertificateBuilder().subject_name(subject).issuer_name(issuer).public_key(key.public_key())
               .serial_number(x509.random_serial_number()).not_valid_before(now + timedelta(days=days_from))
               .not_valid_after(now + timedelta(days=days_to))
               .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    builder = builder.add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
    builder = builder.add_extension(
        x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()), critical=False)
    if ca:
        builder = builder.add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False),
                                        critical=True)
    if sans:
        builder = builder.add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in sans]), critical=False)
    return builder.sign(signer, hashes.SHA256())


class Pki:
    def __init__(self, tmp_path):
        self.tmp = tmp_path
        self.ca_key = _key()
        self.ca = _build(_name("Test CA"), _name("Test CA"), self.ca_key, self.ca_key, -1, 3650, ca=True)
        self.ca_file = tmp_path / "ca.pem"
        self.ca_file.write_bytes(self.ca.public_bytes(serialization.Encoding.PEM))

    def serve(self, names, days_from, days_to, tag="leaf"):
        key = _key()
        cert = _build(_name(names[0]), self.ca.subject, key, self.ca_key, days_from, days_to, sans=names)
        cert_file, key_file = self.tmp / f"{tag}.pem", self.tmp / f"{tag}.key"
        cert_file.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_file.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                               serialization.NoEncryption()))
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert_file, key_file)
        return _Server(ctx)


class _Server:
    def __init__(self, ctx):
        self.ctx = ctx
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        self.sock.settimeout(0.2)
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _loop(self):
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except (socket.timeout, OSError):
                continue
            try:
                if self.ctx is None:
                    conn.sendall(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                else:
                    self.ctx.wrap_socket(conn, server_side=True).close()
            except (ssl.SSLError, OSError):
                pass
            finally:
                conn.close()

    def close(self):
        self.running = False
        self.sock.close()


@pytest.fixture
def pki(tmp_path):
    servers = []
    p = Pki(tmp_path)
    original = p.serve

    def serve(*a, **k):
        server = original(*a, **k)
        servers.append(server)
        return server
    p.serve = serve
    yield p
    for server in servers:
        server.close()


def inspect(server, host="example.test", **kwargs):
    return connect_and_inspect(host, "127.0.0.1", server.port, timeout=5, **kwargs)


def test_threshold_boundaries_match_the_specification():
    assert classify_days(31) == "HEALTHY"
    assert classify_days(30) == "WARNING" and classify_days(15) == "WARNING"
    assert classify_days(14) == "HIGH" and classify_days(7) == "HIGH"
    assert classify_days(6) == "CRITICAL" and classify_days(0) == "CRITICAL" and classify_days(-3) == "CRITICAL"


def test_thresholds_are_configurable():
    assert classify_days(40, warning_days=60, high_days=30, critical_days=10) == "WARNING"
    assert classify_days(5, warning_days=60, high_days=30, critical_days=10) == "CRITICAL"


def test_wildcard_and_exact_hostname_matching():
    assert hostname_matches("www.example.com", ["*.example.com"])
    assert not hostname_matches("a.b.example.com", ["*.example.com"])
    assert not hostname_matches("example.com", ["*.example.com"])
    assert hostname_matches("example.com", ["example.com"])


def test_valid_certificate_is_trusted_and_healthy(pki):
    info = inspect(pki.serve(["example.test"], -1, 90), cafile=str(pki.ca_file))
    assert info["trusted"] is True and info["handshake_ok"] is True and info["hostname_valid"] is True
    assert info["status"] == "HEALTHY" and 88 <= info["days_remaining"] <= 90
    assert info["san"] == ["example.test"] and info["tls_version"].startswith("TLS")
    assert ssl_findings(info) == []


@pytest.mark.parametrize("days,status,severity", [(20, "WARNING", "medium"), (10, "HIGH", "high"), (3, "CRITICAL", "critical")])
def test_expiry_windows_produce_graded_findings(pki, days, status, severity):
    info = inspect(pki.serve(["example.test"], -1, days), cafile=str(pki.ca_file))
    assert info["status"] == status
    findings = ssl_findings(info)
    assert findings[0].id == "SSL-EXPIRING" and findings[0].severity == severity


def test_expired_certificate_is_critical_and_not_trusted(pki):
    info = inspect(pki.serve(["example.test"], -400, -10), cafile=str(pki.ca_file))
    assert info["error_kind"] == "EXPIRED" and info["trusted"] is False
    assert info["diagnostic_only"] is True and info["days_remaining"] < 0
    assert info["status"] == "CRITICAL"
    assert ssl_findings(info)[0].id == "SSL-EXPIRED" and ssl_findings(info)[0].severity == "critical"


def test_hostname_mismatch_is_detected_and_never_trusted(pki):
    info = inspect(pki.serve(["other.test"], -1, 90), cafile=str(pki.ca_file))
    assert info["error_kind"] == "HOSTNAME_MISMATCH" and info["trusted"] is False
    assert info["hostname_valid"] is False and info["san"] == ["other.test"]
    assert ssl_findings(info)[0].id == "SSL-HOSTNAME-MISMATCH"


def test_untrusted_issuer_is_reported_without_disabling_verification(pki):
    info = inspect(pki.serve(["example.test"], -1, 90))  # CA deliberately not trusted
    assert info["trusted"] is False
    assert info["error_kind"] in {"UNTRUSTED_ISSUER", "UNTRUSTED_SELF_SIGNED", "UNTRUSTED_SELF_SIGNED_IN_CHAIN", "INVALID_CHAIN"}
    assert info["diagnostic_only"] is True and info["subject"]
    assert ssl_findings(info)[0].severity == "high"


def test_tls_handshake_failure_on_non_tls_endpoint():
    server = _Server(None)
    try:
        info = connect_and_inspect("example.test", "127.0.0.1", server.port, timeout=5)
    finally:
        server.close()
    assert info["trusted"] is False and info["handshake_ok"] is False
    assert info["error_kind"] in {"TLS_HANDSHAKE_FAILED", "CONNECTION_FAILED"}
    assert ssl_findings(info)[0].severity == "high"


def test_connection_refused_means_https_unavailable():
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    info = connect_and_inspect("example.test", "127.0.0.1", port, timeout=2)
    assert info["error_kind"] == "CONNECTION_FAILED"
    assert ssl_findings(info)[0].id == "SSL-HTTPS-UNAVAILABLE"


def test_http_only_and_broken_redirect_findings():
    info = {"host": "example.test", "trusted": False, "error_kind": "CONNECTION_FAILED", "error": "refused"}
    ids = {f.id for f in ssl_findings(info, https_redirect={"state": "HTTP_ONLY", "evidence": "GET http://example.test/"})}
    assert "SSL-HTTP-ONLY" in ids
    healthy = {"host": "example.test", "trusted": True, "status": "HEALTHY", "days_remaining": 100}
    broken = ssl_findings(healthy, https_redirect={"state": "BROKEN", "detail": "loop", "evidence": "x"})
    assert [f.id for f in broken] == ["SSL-REDIRECT-BROKEN"]
