"""
WiFiGuard rogue-access-point awareness logic.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from .scanner import AccessPoint


@dataclass
class RogueIndicator:
    ssid: str
    observed_bssid: str
    expected_bssid: str
    reason: str


def compare_trusted_profile(
    access_points: Iterable[AccessPoint],
    trusted_profiles: dict[str, dict],
) -> list[RogueIndicator]:
    """
    Compare observed networks against user-defined trusted profiles.

    Example profile:

    {
        "Cafe_WiFi": {
            "bssids": ["AA:BB:CC:DD:EE:FF"],
            "security": "WPA2"
        }
    }
    """
    indicators: list[RogueIndicator] = []

    for ap in access_points:
        profile = trusted_profiles.get(ap.ssid)

        if not profile:
            continue

        expected_bssids = {
            bssid.upper()
            for bssid in profile.get("bssids", [])
        }

        expected_security = profile.get("security")

        if expected_bssids and ap.bssid not in expected_bssids:
            indicators.append(
                RogueIndicator(
                    ssid=ap.ssid,
                    observed_bssid=ap.bssid,
                    expected_bssid=", ".join(sorted(expected_bssids)),
                    reason="Observed BSSID is not present in the trusted profile.",
                )
            )

        if (
            expected_security
            and ap.security.upper() != expected_security.upper()
        ):
            indicators.append(
                RogueIndicator(
                    ssid=ap.ssid,
                    observed_bssid=ap.bssid,
                    expected_bssid=", ".join(sorted(expected_bssids)),
                    reason=(
                        "Observed security differs from the trusted "
                        "network profile."
                    ),
                )
            )

    return indicators
