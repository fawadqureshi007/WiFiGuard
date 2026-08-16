"""
WiFiGuard wireless security risk assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .scanner import AccessPoint


@dataclass
class RiskResult:
    score: int
    level: str
    findings: list[str] = field(default_factory=list)


def assess(ap: AccessPoint) -> RiskResult:
    """
    Assign a basic risk score based on advertised security properties.

    This is an awareness-oriented heuristic, not a vulnerability scanner.
    """
    score = 0
    findings: list[str] = []

    security = ap.security.upper()

    if security == "OPEN":
        score += 80
        findings.append(
            "Network advertises no wireless encryption."
        )

    elif "WEP" in security:
        score += 95
        findings.append(
            "Legacy WEP security detected."
        )

    elif security == "WPA":
        score += 60
        findings.append(
            "Legacy WPA security detected."
        )

    elif "WPA2" in security:
        score += 20
        findings.append(
            "WPA2 detected; review configuration and authentication mode."
        )

    elif "WPA3" in security:
        score += 5
        findings.append(
            "WPA3 detected."
        )

    else:
        score += 30
        findings.append(
            f"Unrecognized security advertisement: {ap.security}"
        )

    if ap.hidden:
        findings.append(
            "SSID is not publicly advertised."
        )

    if score >= 80:
        level = "CRITICAL"
    elif score >= 60:
        level = "HIGH"
    elif score >= 30:
        level = "MEDIUM"
    else:
        level = "LOW"

    return RiskResult(
        score=min(score, 100),
        level=level,
        findings=findings,
    )
