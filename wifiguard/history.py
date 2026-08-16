"""
WiFiGuard scan-history storage.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path

from .scanner import AccessPoint


def save_scan(
    access_points: list[AccessPoint],
    path: str | Path,
) -> None:
    """Save a scan with a UTC timestamp."""
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "networks": [asdict(ap) for ap in access_points],
    }

    destination.write_text(
        json.dumps(record, indent=2),
        encoding="utf-8",
    )


def load_scan(path: str | Path) -> dict:
    """Load a previously saved scan."""
    return json.loads(
        Path(path).read_text(encoding="utf-8")
    )
