"""PHP version support evaluation based on the official PHP lifecycle."""

from __future__ import annotations

from datetime import date

# Release/support dates from https://www.php.net/supported-versions.php.
PHP_LIFECYCLE = {
    "7.0": (date(2015, 12, 3), date(2018, 12, 3), date(2018, 12, 3)),
    "7.1": (date(2016, 12, 1), date(2019, 12, 1), date(2019, 12, 1)),
    "7.2": (date(2017, 11, 30), date(2020, 11, 30), date(2020, 11, 30)),
    "7.3": (date(2018, 12, 6), date(2021, 12, 6), date(2021, 12, 6)),
    "7.4": (date(2019, 11, 28), date(2022, 11, 28), date(2022, 11, 28)),
    "8.0": (date(2020, 11, 26), date(2022, 11, 26), date(2023, 11, 26)),
    "8.1": (date(2021, 11, 25), date(2023, 11, 25), date(2025, 12, 31)),
    "8.2": (date(2022, 12, 8), date(2024, 12, 31), date(2026, 12, 31)),
    "8.3": (date(2023, 11, 23), date(2025, 12, 31), date(2027, 12, 31)),
    "8.4": (date(2024, 11, 21), date(2026, 12, 31), date(2028, 12, 31)),
    "8.5": (date(2025, 11, 20), date(2027, 12, 31), date(2029, 12, 31)),
}


def evaluate_php(version: str | None, *, today: date | None = None) -> dict[str, object]:
    today = today or date.today()
    if not version:
        return {"installed_version": None, "support_status": "NOT_VERIFIABLE_WITH_PUBLIC_ACCESS", "source": "https://www.php.net/supported-versions.php"}
    branch = ".".join(version.split(".")[:2])
    dates = PHP_LIFECYCLE.get(branch)
    if not dates:
        return {"installed_version": version, "support_status": "UNKNOWN", "source": "https://www.php.net/supported-versions.php"}
    _, active_until, security_until = dates
    status = "ACTIVE_SUPPORT" if today <= active_until else "SECURITY_FIXES_ONLY" if today <= security_until else "END_OF_LIFE"
    return {"installed_version": version, "support_status": status, "active_support_until": active_until.isoformat(),
            "security_support_until": security_until.isoformat(), "source": "https://www.php.net/supported-versions.php"}
