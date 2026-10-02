from typing import Any


def calculate_risk(vulnerabilities: list[dict[str, Any]]) -> str:
    if not vulnerabilities:
        return "LOW"

    severities = []

    for vuln in vulnerabilities:
        for severity in vuln.get("severity", []):
            severity_type = severity.get("type", "")
            severity_score = severity.get("score", "")

            if severity_type.upper() == "CVSS-V3":
                try:
                    score = float(severity_score.split("/")[0])
                    severities.append(score)
                except (ValueError, IndexError):
                    pass

    if any(score >= 9.0 for score in severities):
        return "CRITICAL"

    if any(score >= 7.0 for score in severities):
        return "HIGH"

    if any(score >= 4.0 for score in severities):
        return "MEDIUM"

    return "LOW"


def get_verdict(risk: str) -> str:
    if risk == "CRITICAL":
        return "BLOCK"

    if risk == "HIGH":
        return "BLOCK"

    if risk == "MEDIUM":
        return "REVIEW"

    return "ALLOW"
