from typing import Any


def extract_cvss_scores(
    vulnerabilities: list[dict[str, Any]]
) -> list[float]:
    scores = []

    for vulnerability in vulnerabilities:
        for severity in vulnerability.get("severity", []):
            score_value = severity.get("score")

            if not score_value:
                continue

            # Some OSV records provide a numeric score.
            try:
                score = float(score_value)

                if 0 <= score <= 10:
                    scores.append(score)

            except (ValueError, TypeError):
                # Some records provide a CVSS vector instead.
                # Vector parsing is handled below.
                score = parse_cvss_vector(str(score_value))

                if score is not None:
                    scores.append(score)

    return scores


def parse_cvss_vector(vector: str) -> float | None:
    """
    Lightweight CVSS v3 base-score calculator.

    Supports CVSS v3.0 and v3.1 base metrics.
    """

    if not vector.startswith("CVSS:3."):
        return None

    try:
        parts = vector.split("/")[1:]
        metrics = {}

        for part in parts:
            key, value = part.split(":", 1)
            metrics[key] = value

        av = {
            "N": 0.85,
            "A": 0.62,
            "L": 0.55,
            "P": 0.20,
        }[metrics["AV"]]

        ac = {
            "L": 0.77,
            "H": 0.44,
        }[metrics["AC"]]

        pr_values = {
            "U": {"N": 0.85, "L": 0.62, "H": 0.27},
            "C": {"N": 0.85, "L": 0.68, "H": 0.50},
        }

        scope = metrics["S"]

        pr = pr_values[scope][metrics["PR"]]

        ui = {
            "N": 0.85,
            "R": 0.62,
        }[metrics["UI"]]

        impact_values = {
            "N": 0.00,
            "L": 0.22,
            "H": 0.56,
        }

        c = impact_values[metrics["C"]]
        i = impact_values[metrics["I"]]
        a = impact_values[metrics["A"]]

        isc_base = 1 - ((1 - c) * (1 - i) * (1 - a))

        if scope == "U":
            impact = 6.42 * isc_base

        else:
            impact = 7.52 * (isc_base - 0.029) - (
                3.25 * ((isc_base - 0.02) ** 15)
            )

        if impact <= 0:
            return 0.0

        exploitability = (
            8.22 * av * ac * pr * ui
        )

        if scope == "U":
            score = min(impact + exploitability, 10)

        else:
            score = min(
                1.08 * (impact + exploitability),
                10
            )

        # CVSS rounds up to one decimal place.
        score = round(score + 0.000001, 1)

        return score

    except (KeyError, ValueError, TypeError):
        return None


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

    return "LOW"


def get_verdict(risk: str) -> str:

    if risk == "CRITICAL":
        return "BLOCK"

    if risk == "HIGH":
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

        for affected in vulnerability.get(
            "affected", []
        ):

            for range_data in affected.get(
                "ranges", []
            ):

                for event in range_data.get(
                    "events", []
                ):

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

    return (
        "Review the advisory before using this dependency."
    )
