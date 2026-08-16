"""
WiFiGuard report generation.
"""

from __future__ import annotations

import csv
import json
from dataclasses import asdict
from pathlib import Path

from .risk import assess
from .scanner import AccessPoint


def save_json(
    access_points: list[AccessPoint],
    path: str | Path,
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    data = []

    for ap in access_points:
        item = asdict(ap)
        item["risk"] = asdict(assess(ap))
        data.append(item)

    destination.write_text(
        json.dumps(data, indent=2),
        encoding="utf-8",
    )


def save_csv(
    access_points: list[AccessPoint],
    path: str | Path,
) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)

    with destination.open(
        "w",
        newline="",
        encoding="utf-8",
    ) as handle:
        writer = csv.writer(handle)

        writer.writerow(
            [
                "SSID",
                "BSSID",
                "Signal",
                "Channel",
                "Frequency",
                "Security",
                "Hidden",
                "Risk",
                "Risk Score",
            ]
        )

        for ap in access_points:
            risk = assess(ap)

            writer.writerow(
                [
                    ap.ssid,
                    ap.bssid,
                    ap.signal,
                    ap.channel,
                    ap.frequency,
                    ap.security,
                    ap.hidden,
                    risk.level,
                    risk.score,
                ]
            )
