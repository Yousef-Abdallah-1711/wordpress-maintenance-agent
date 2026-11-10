import pytest


@pytest.fixture(autouse=True)
def no_real_tls(monkeypatch, request):
    """Tests must never open real TLS connections. TLS-specific tests opt out with @pytest.mark.real_tls."""
    if request.node.get_closest_marker("real_tls"):
        return

    async def fake_audit_ssl(host, **kwargs):
        return {"host": host, "port": 443, "status": "HEALTHY", "trusted": True, "handshake_ok": True,
                "hostname_valid": True, "tls_version": "TLSv1.3", "subject": f"CN={host}", "issuer": "CN=Test CA",
                "not_after": "2099-01-01T00:00:00+00:00", "days_remaining": 9999, "san": [host],
                "checked_at": "2026-11-10T00:00:00+00:00", "source": "stub"}
    monkeypatch.setattr("wp_maintenance.audit.audit_ssl", fake_audit_ssl)
