from typing import Any


def extract_cvss_scores(
    vulnerabilities: list[dict[str, Any]]
) -> list[float]:
    scores = []

    for vulnerability in vulnerabilities:
        for severity in vulnerability.get("severity", []):
            score_string = severity.get("score")

            if not score_string:
                continue

            try:
                score = float(score_string)

                if 0 <= score <= 10:
                    scores.append(score)

            except (ValueError, TypeError):
                continue

    return scores


def calculate_risk(
    vulnerabilities: list[dict[str, Any]]
) -> str:

    if not vulnerabilities:
        return "LOW"

    scores = extract_cvss_scores(vulnerabilities)

    if any(score >= 9.0 for score in scores):
        return "CRITICAL"

    if any(score >= 7.0 for score in scores):
        return "HIGH"

    if any(score >= 4.0 for score in scores):
        return "MEDIUM"

    return "MEDIUM"


def get_verdict(risk: str) -> str:

    if risk in ("CRITICAL", "HIGH"):
        return "BLOCK"

    if risk == "MEDIUM":
        return "REVIEW"

    return "ALLOW"


def recommendation_for(
    vulnerabilities: list[dict[str, Any]],
    risk: str
) -> str:

    if not vulnerabilities:
        return (
            "No known vulnerability was returned by OSV "
            "for this version."
        )

    fixed_versions = []

    for vulnerability in vulnerabilities:

        for affected in vulnerability.get("affected", []):

            for range_data in affected.get("ranges", []):

                for event in range_data.get("events", []):

                    fixed = event.get("fixed")

                    if fixed:
                        fixed_versions.append(fixed)

    if fixed_versions:

        unique_versions = list(
            dict.fromkeys(fixed_versions)
        )

        return (
            "Upgrade to a fixed version where possible. "
            "Known fixed versions: "
            + ", ".join(unique_versions[:10])
        )

    if risk in ("CRITICAL", "HIGH"):
        return (
            "Avoid this version and investigate "
            "a patched release."
        )

    return "Review the advisory before using this dependency."
