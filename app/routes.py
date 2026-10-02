from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from .models import PackageResult
from .osv import query_package
from .risk import calculate_risk, get_verdict


router = APIRouter()


@router.get("/check-package", response_model=PackageResult)
async def check_package(
    package: str,
    ecosystem: str,
    version: str
):
    try:
        data = await query_package(
            package=package,
            ecosystem=ecosystem,
            version=version
        )

    except Exception as exc:
        raise HTTPException(
            status_code=502,
            detail=f"Vulnerability database request failed: {exc}"
        )

    vulnerabilities = data.get("vulns", [])

    risk = calculate_risk(vulnerabilities)
    verdict = get_verdict(risk)

    results = []

    for vuln in vulnerabilities:
        fixed_version = None

        for affected in vuln.get("affected", []):
            for range_data in affected.get("ranges", []):
                for event in range_data.get("events", []):
                    if "fixed" in event:
                        fixed_version = event["fixed"]

        results.append({
            "id": vuln.get("id", "UNKNOWN"),
            "summary": vuln.get("summary"),
            "severity": None,
            "cvss_score": None,
            "published": vuln.get("published"),
            "modified": vuln.get("modified"),
            "fixed_version": fixed_version
        })

    return PackageResult(
        package=package,
        ecosystem=ecosystem,
        version=version,
        vulnerable=len(vulnerabilities) > 0,
        vulnerability_count=len(vulnerabilities),
        risk=risk,
        verdict=verdict,
        vulnerabilities=results,
        recommendation=(
            "Upgrade to a fixed version."
            if vulnerabilities
            else "No known vulnerability found for this version."
        ),
        checked_at=datetime.now(timezone.utc).isoformat()
    )
