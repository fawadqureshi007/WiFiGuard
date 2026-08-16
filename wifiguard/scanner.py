"""
WiFiGuard passive wireless scanner.

This module collects publicly advertised Wi-Fi metadata from the local
wireless interface. It does not capture payload traffic or credentials.
"""

from __future__ import annotations

import json
import platform
import re
import subprocess
from dataclasses import asdict, dataclass
from typing import Optional


@dataclass
class AccessPoint:
    ssid: str
    bssid: str
    signal: Optional[int]
    channel: Optional[int]
    frequency: Optional[int]
    security: str
    hidden: bool = False

    def to_dict(self) -> dict:
        return asdict(self)


class ScannerError(RuntimeError):
    """Raised when the wireless scanner cannot perform a scan."""


class WiFiScanner:
    """Passive Wi-Fi scanner using NetworkManager's nmcli interface."""

    def __init__(self, interface: Optional[str] = None) -> None:
        self.interface = interface

    def _check_nmcli(self) -> None:
        try:
            subprocess.run(
                ["nmcli", "--version"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=True,
            )
        except (FileNotFoundError, subprocess.CalledProcessError) as exc:
            raise ScannerError(
                "nmcli was not found. Install/enable NetworkManager."
            ) from exc

    def _run_scan(self) -> str:
        self._check_nmcli()

        command = [
            "nmcli",
            "-t",
            "-f",
            "SSID,BSSID,SIGNAL,CHAN,FREQ,SECURITY",
            "device",
            "wifi",
            "list",
        ]

        if self.interface:
            command.extend(["ifname", self.interface])

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise ScannerError(
                exc.stderr.strip() or "Wi-Fi scan failed."
            ) from exc

        return result.stdout

    @staticmethod
    def _split_nmcli_line(line: str) -> list[str]:
        """
        Split nmcli's colon-separated output while respecting escaped
        separators.
        """
        fields = []
        current = []
        escaped = False

        for char in line:
            if escaped:
                current.append(char)
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == ":":
                fields.append("".join(current))
                current = []
            else:
                current.append(char)

        if escaped:
            current.append("\\")

        fields.append("".join(current))
        return fields

    @staticmethod
    def _clean(value: str) -> str:
        value = value.replace("\\:", ":")
        value = value.replace("\\\\", "\\")
        return value.strip()

    @staticmethod
    def _integer(value: str) -> Optional[int]:
        value = value.strip()

        if not value or value == "--":
            return None

        match = re.search(r"-?\d+", value)
        return int(match.group()) if match else None

    @staticmethod
    def _security(value: str) -> str:
        value = value.strip()

        if not value or value == "--":
            return "OPEN"

        return value

    def scan(self) -> list[AccessPoint]:
        """
        Perform a passive Wi-Fi scan and return discovered access points.
        """
        if platform.system() != "Linux":
            raise ScannerError(
                "The initial WiFiGuard scanner currently targets Linux."
            )

        output = self._run_scan()
        access_points: list[AccessPoint] = []

        for raw_line in output.splitlines():
            if not raw_line.strip():
                continue

            fields = self._split_nmcli_line(raw_line)

            if len(fields) < 6:
                continue

            ssid = self._clean(fields[0])
            bssid = self._clean(fields[1]).upper()
            signal = self._integer(fields[2])
            channel = self._integer(fields[3])
            frequency = self._integer(fields[4])
            security = self._security(self._clean(fields[5]))

            hidden = not bool(ssid)

            if hidden:
                ssid = "<hidden>"

            access_points.append(
                AccessPoint(
                    ssid=ssid,
                    bssid=bssid,
                    signal=signal,
                    channel=channel,
                    frequency=frequency,
                    security=security,
                    hidden=hidden,
                )
            )

        return access_points


def scan_to_json(interface: Optional[str] = None) -> str:
    """Convenience function returning scan results as JSON."""
    scanner = WiFiScanner(interface)
    results = scanner.scan()

    return json.dumps(
        [item.to_dict() for item in results],
        indent=2,
    )
