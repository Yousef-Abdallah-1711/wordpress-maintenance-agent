"""TLS certificate inspection. Verification is never disabled for the trust decision."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
import ssl
from datetime import datetime, timezone

from .models import Finding

VERIFY_CODES = {
    9: "NOT_YET_VALID", 10: "EXPIRED", 18: "UNTRUSTED_SELF_SIGNED", 19: "UNTRUSTED_SELF_SIGNED_IN_CHAIN",
    20: "UNTRUSTED_ISSUER", 21: "INVALID_CHAIN", 62: "HOSTNAME_MISMATCH",
}


def classify_days(days: int, *, warning_days: int = 30, high_days: int = 14, critical_days: int = 6) -> str:
    """>warning: HEALTHY, (high..warning]: WARNING, (critical..high]: HIGH, <=critical or expired: CRITICAL."""
    if days <= critical_days:
        return "CRITICAL"
    if days <= high_days:
        return "HIGH"
    if days <= warning_days:
        return "WARNING"
    return "HEALTHY"


def hostname_matches(host: str, names: list[str]) -> bool:
    host = host.rstrip(".").lower()
    for name in names:
        name = name.rstrip(".").lower()
        if name == host:
            return True
        if name.startswith("*.") and host.count(".") >= name.count(".") and host.split(".", 1)[1] == name[2:]:
            return True
    return False


def _name_to_str(parts: object) -> str:
    out = []
    for rdn in parts or ():
        for key, value in rdn:
            out.append(f"{key}={value}")
    return ", ".join(out)


def _decode_der(der: bytes) -> dict[str, object]:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID

    cert = x509.load_der_x509_certificate(der)
    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names = list(san.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        names = []
    return {"subject": cert.subject.rfc4514_string(), "issuer": cert.issuer.rfc4514_string(),
            "not_before": cert.not_valid_before_utc, "not_after": cert.not_valid_after_utc, "san": names}


def _from_peer_cert(cert: dict) -> dict[str, object]:
    return {"subject": _name_to_str(cert.get("subject")), "issuer": _name_to_str(cert.get("issuer")),
            "not_before": datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notBefore"]), timezone.utc),
            "not_after": datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc),
            "san": [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]}


def connect_and_inspect(host: str, address: str, port: int = 443, *, timeout: float = 10,
                        cafile: str | None = None, warning_days: int = 30, high_days: int = 14,
                        critical_days: int = 6) -> dict[str, object]:
    """Handshake with one already-validated address. Trust is decided by a verifying handshake only."""
    out: dict[str, object] = {"host": host, "port": port, "address": address, "trusted": False,
        "handshake_ok": False, "hostname_valid": None, "tls_version": None, "cipher": None, "subject": None,
        "issuer": None, "not_before": None, "not_after": None, "days_remaining": None, "san": [],
        "status": "UNKNOWN", "error_kind": None, "error": None, "diagnostic_only": False,
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "source": f"direct TLS handshake to {host}:{port}"}

    def apply(info: dict[str, object]) -> None:
        now = datetime.now(timezone.utc)
        days = (info["not_after"] - now).days if info["not_after"] > now else -((now - info["not_after"]).days + 1)
        out.update(subject=info["subject"], issuer=info["issuer"], not_before=info["not_before"].isoformat(),
                   not_after=info["not_after"].isoformat(), days_remaining=days, san=info["san"])
        out["status"] = classify_days(days, warning_days=warning_days, high_days=high_days,
                                      critical_days=critical_days)

    ctx = ssl.create_default_context(cafile=cafile) if cafile else ssl.create_default_context()
    try:
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                out.update(handshake_ok=True, trusted=True, hostname_valid=True, tls_version=tls.version(),
                           cipher=(tls.cipher() or (None,))[0])
                apply(_from_peer_cert(tls.getpeercert()))
        return out
    except ssl.SSLCertVerificationError as exc:
        kind = VERIFY_CODES.get(exc.verify_code, "CERTIFICATE_INVALID")
        out.update(error_kind=kind, error=f"{exc.verify_message} (code {exc.verify_code})", trusted=False,
                   hostname_valid=False if kind == "HOSTNAME_MISMATCH" else None)
    except ssl.SSLError as exc:
        out.update(error_kind="TLS_HANDSHAKE_FAILED", error=str(exc))
        return out
    except (OSError, TimeoutError) as exc:
        out.update(error_kind="CONNECTION_FAILED", error=f"{type(exc).__name__}: {exc}")
        return out
    # Diagnostic-only metadata collection after a verification failure. Never marks the peer trusted.
    try:
        diag = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        diag.check_hostname = False
        diag.verify_mode = ssl.CERT_NONE
        with socket.create_connection((address, port), timeout=timeout) as raw:
            with diag.wrap_socket(raw, server_hostname=host) as tls:
                out["tls_version"] = tls.version()
                info = _decode_der(tls.getpeercert(binary_form=True))
        out["diagnostic_only"] = True
        apply(info)
        if out["hostname_valid"] is None:
            out["hostname_valid"] = hostname_matches(host, info["san"])
    except Exception as exc:  # metadata is best effort
        out["diagnostic_error"] = f"{type(exc).__name__}: {exc}"
    return out


def _resolve_public(host: str, port: int) -> str:
    records = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addresses = list(dict.fromkeys(rec[4][0].split("%", 1)[0] for rec in records))
    if not addresses:
        raise OSError("host resolved to no addresses")
    for address in addresses:
        if not ipaddress.ip_address(address).is_global:
            raise OSError("host resolved to a non-public address; TLS inspection refused")
    return addresses[0]


async def audit_ssl(host: str, *, port: int = 443, timeout: float = 10, warning_days: int = 30,
                    high_days: int = 14, critical_days: int = 6) -> dict[str, object]:
    def run() -> dict[str, object]:
        try:
            address = _resolve_public(host, port)
        except OSError as exc:
            return {"host": host, "port": port, "status": "UNKNOWN", "trusted": False, "handshake_ok": False,
                    "error_kind": "DNS_OR_POLICY_ERROR", "error": str(exc),
                    "checked_at": datetime.now(timezone.utc).isoformat(), "source": f"TLS inspection of {host}:{port}"}
        return connect_and_inspect(host, address, port, timeout=timeout, warning_days=warning_days,
                                   high_days=high_days, critical_days=critical_days)
    return await asyncio.to_thread(run)


def ssl_findings(info: dict[str, object], *, https_redirect: dict[str, object] | None = None) -> list[Finding]:
    """Convert a TLS inspection into evidence-backed findings."""
    findings: list[Finding] = []
    evidence = [str(info.get("source", "TLS inspection")), f"checked_at={info.get('checked_at')}"]
    host = info.get("host")
    kind = info.get("error_kind")
    fix = "Renew or reissue the certificate and confirm the full chain is served, then re-run the audit."
    if kind == "CONNECTION_FAILED":
        findings.append(Finding(id="SSL-HTTPS-UNAVAILABLE", severity="high", component="ssl",
            title="HTTPS endpoint is not reachable", detail=f"TCP/TLS connection to {host}:443 failed: {info.get('error')}",
            evidence=evidence, recommendation="Confirm the host serves HTTPS on port 443 and that a certificate is installed."))
    elif kind == "TLS_HANDSHAKE_FAILED":
        findings.append(Finding(id="SSL-HANDSHAKE-FAILED", severity="high", component="ssl",
            title="TLS handshake failed", detail=str(info.get("error")), evidence=evidence,
            recommendation="Review the server's TLS protocol versions, cipher suites and certificate configuration."))
    elif kind == "EXPIRED":
        findings.append(Finding(id="SSL-EXPIRED", severity="critical", component="ssl",
            title="TLS certificate has expired", detail=f"Certificate for {host} expired {info.get('not_after')}.",
            evidence=evidence, recommendation=fix))
    elif kind == "HOSTNAME_MISMATCH":
        findings.append(Finding(id="SSL-HOSTNAME-MISMATCH", severity="high", component="ssl",
            title="Certificate does not match the hostname",
            detail=f"{host} is not covered by certificate names {info.get('san') or 'UNKNOWN'}.", evidence=evidence,
            recommendation="Issue a certificate that includes this hostname in its Subject Alternative Names."))
    elif kind in {"UNTRUSTED_SELF_SIGNED", "UNTRUSTED_SELF_SIGNED_IN_CHAIN", "UNTRUSTED_ISSUER", "INVALID_CHAIN",
                  "CERTIFICATE_INVALID", "NOT_YET_VALID"}:
        findings.append(Finding(id=f"SSL-{kind}", severity="high", component="ssl",
            title="Certificate is not trusted", detail=f"Verification failed: {info.get('error')}. Metadata shown is diagnostic only.",
            evidence=evidence, recommendation="Install a certificate from a trusted CA and serve the complete intermediate chain."))
    elif info.get("trusted") and info.get("days_remaining") is not None:
        status = info.get("status")
        days = info["days_remaining"]
        severity = {"WARNING": "medium", "HIGH": "high", "CRITICAL": "critical"}.get(str(status))
        if severity:
            findings.append(Finding(id="SSL-EXPIRING", severity=severity, component="ssl",
                title=f"TLS certificate expires in {days} days", detail=f"Certificate for {host} expires {info.get('not_after')} ({status}).",
                evidence=evidence, recommendation="Renew the certificate (or fix automatic renewal) before expiry."))
    if https_redirect is not None:
        state = https_redirect.get("state")
        evidence_r = [str(https_redirect.get("evidence"))]
        if state == "HTTP_ONLY":
            findings.append(Finding(id="SSL-HTTP-ONLY", severity="high", component="ssl", title="Site is served over HTTP only",
                detail="http:// responds without redirecting to HTTPS.", evidence=evidence_r,
                recommendation="Serve the site over HTTPS and redirect all HTTP traffic with a permanent redirect."))
        elif state == "NO_REDIRECT":
            findings.append(Finding(id="SSL-NO-HTTPS-REDIRECT", severity="medium", component="ssl",
                title="HTTP does not redirect to HTTPS", detail="http:// is served directly although HTTPS is available.",
                evidence=evidence_r, recommendation="Add a permanent HTTP to HTTPS redirect."))
        elif state == "BROKEN":
            findings.append(Finding(id="SSL-REDIRECT-BROKEN", severity="medium", component="ssl",
                title="HTTP to HTTPS redirect is broken", detail=str(https_redirect.get("detail")),
                evidence=evidence_r, recommendation="Fix the redirect chain so http:// resolves to a working https:// page."))
    return findings
