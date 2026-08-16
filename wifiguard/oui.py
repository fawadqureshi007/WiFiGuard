"""
WiFiGuard MAC/OUI utilities.
"""

from __future__ import annotations

import re


def normalize_mac(mac: str) -> str:
    """Normalize a MAC address."""
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", mac)

    if len(cleaned) != 12:
        raise ValueError(f"Invalid MAC address: {mac}")

    return ":".join(
        cleaned[index:index + 2].upper()
        for index in range(0, 12, 2)
    )


def get_oui(mac: str) -> str:
    """Return the first three octets of a MAC address."""
    normalized = normalize_mac(mac)
    return normalized[:8]


def is_locally_administered(mac: str) -> bool:
    """
    Check the locally-administered bit of the first MAC octet.
    """
    normalized = normalize_mac(mac)
    first_octet = int(normalized[:2], 16)

    return bool(first_octet & 0x02)
