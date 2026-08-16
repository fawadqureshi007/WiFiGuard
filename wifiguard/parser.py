"""
WiFiGuard data parsing and normalization.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from .scanner import AccessPoint


def normalize_security(value: str) -> str:
    """Normalize common security labels."""
    security = value.strip().upper()

    if not security or security in {"--", "NONE"}:
        return "OPEN"

    if "WEP" in security:
        return "WEP"

    if "WPA3" in security:
        return "WPA3"

    if "WPA2" in security:
        return "WPA2"

    if "WPA" in security:
        return "WPA"

    return security


def normalize_access_points(
    access_points: Iterable[AccessPoint],
) -> list[AccessPoint]:
    """Return normalized access-point records."""
    normalized = []

    for ap in access_points:
        normalized.append(
            AccessPoint(
                ssid=ap.ssid.strip(),
                bssid=ap.bssid.upper(),
                signal=ap.signal,
                channel=ap.channel,
                frequency=ap.frequency,
                security=normalize_security(ap.security),
                hidden=ap.hidden,
            )
        )

    return normalized


def group_by_ssid(
    access_points: Iterable[AccessPoint],
) -> dict[str, list[AccessPoint]]:
    """Group observed access points by SSID."""
    grouped: dict[str, list[AccessPoint]] = defaultdict(list)

    for ap in access_points:
        grouped[ap.ssid].append(ap)

    return dict(grouped)


def duplicate_ssids(
    access_points: Iterable[AccessPoint],
) -> dict[str, list[AccessPoint]]:
    """
    Return SSIDs advertised by more than one BSSID.
    """
    grouped = group_by_ssid(access_points)

    return {
        ssid: aps
        for ssid, aps in grouped.items()
        if len({ap.bssid for ap in aps}) > 1
    }
