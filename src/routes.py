from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query

from models import (
    BatchRequest,
    Dependency,
    PackageResult,
    ProjectRequest
)

from osv import query_package, query_batch

from risk import (
    calculate_risk,
    get_verdict,
    recommendation_for,
    parse_cvss_vector
)


router = APIRouter()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def deduplicate_vulnerabilities(
    vulnerabilities: list[dict]
) -> list[dict]:

    unique = []
    seen = set()

    for vulnerability in vulnerabilities:

        identifiers = {
            vulnerability.get("id")
        }

        identifiers.update(
            vulnerability.get("aliases", [])
        )

        identifiers.discard(None)

        if seen.intersection(identifiers):
            continue

        seen.update(identifiers)
        unique.append(vulnerability)

    return unique


def format_vulnerabilities(
    vulnerabilities: list[dict]
) -> list[dict]:

    formatted = []

    for vulnerability in vulnerabilities:

        aliases = vulnerability.get(
            "aliases",
            []
        )

        fixed_versions = []

        for affected in vulnerability.get(
            "affected",
            []
        ):

            for range_data in affected.get(
                "ranges",
                []
            ):

                for event in range_data.get(
                    "events",
                    []
                ):

                    fixed = event.get("fixed")

                    if fixed:
                        fixed_versions.append(
                            fixed
                        )

        fixed_version = None

        if fixed_versions:

            fixed_version = list(
                dict.fromkeys(
                    fixed_versions
                )
            )[0]

        severity = None
        cvss_score = None

        for severity_data in vulnerability.get(
            "severity",
            []
        ):

            severity_type = severity_data.get(
                "type",
                ""
            )

            if not severity_type.upper().startswith(
                "CVSS"
            ):
                continue

            severity = severity_type

            score = severity_data.get(
                "score"
            )

            if not score:
                continue

            try:

                numeric_score = float(score)

                if 0 <= numeric_score <= 10:
                    cvss_score = numeric_score

            except (
                TypeError,
                ValueError
            ):

                parsed_score = parse_cvss_vector(
                    str(score)
                )

                if parsed_score is not None:
                    cvss_score = parsed_score

        references = []

        for reference in vulnerability.get(
            "references",
            []
        ):

            url = reference.get("url")

            if url:
                references.append(url)

        formatted.append({

            "id":
                vulnerability.get(
                    "id",
                    "UNKNOWN"
                ),

            "aliases":
                aliases,

            "summary":
                vulnerability.get(
                    "summary"
                ),

            "severity":
                severity,

            "cvss_score":
                cvss_score,

            "published":
                vulnerability.get(
                    "published"
                ),

            "modified":
                vulnerability.get(
                    "modified"
                ),

            "fixed_version":
                fixed_version,

            "references":
                references
        })

    return formatted


def prepare_vulnerabilities(
    vulnerabilities: list[dict]
) -> list[dict]:

    return deduplicate_vulnerabilities(
        vulnerabilities
    )


@router.get(
    "/check-package",
    response_model=PackageResult
)
async def check_package(

    package: str = Query(
        ...,
        min_length=1,
        max_length=200
    ),

    ecosystem: str = Query(
        ...,
        min_length=1,
        max_length=50
    ),

    version: str = Query(
        ...,
        min_length=1,
        max_length=100
    )
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
            detail=f"OSV request failed: {exc}"
        )

    vulnerabilities = prepare_vulnerabilities(
        data.get(
            "vulns",
            []
        )
    )

    risk = calculate_risk(
        vulnerabilities
    )

    verdict = get_verdict(
        risk
    )

    formatted = format_vulnerabilities(
        vulnerabilities
    )

    return PackageResult(

        package=package,

        ecosystem=ecosystem,

        version=version,

        vulnerable=bool(
            vulnerabilities
        ),

        vulnerability_count=len(
            vulnerabilities
        ),

        risk=risk,

        verdict=verdict,

        vulnerabilities=formatted,

        recommendation=recommendation_for(
            vulnerabilities,
            risk
        ),

        checked_at=utc_now()
    )


@router.post(
    "/check-dependencies"
)
async def check_dependencies(
    request: BatchRequest
):

    dependencies = [
        dependency.model_dump()
        for dependency in request.dependencies
    ]

    try:

        data = await query_batch(
            dependencies
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"OSV batch request failed: {exc}"
        )

    results = []

    for index, dependency in enumerate(
        request.dependencies
    ):

        osv_result = (
            data[index]
            if index < len(data)
            else {}
        )

        vulnerabilities = prepare_vulnerabilities(
            osv_result.get(
                "vulns",
                []
            )
        )

        risk = calculate_risk(
            vulnerabilities
        )

        verdict = get_verdict(
            risk
        )

        results.append({

            "package":
                dependency.package,

            "ecosystem":
                dependency.ecosystem,

            "version":
                dependency.version,

            "vulnerable":
                bool(vulnerabilities),

            "vulnerability_count":
                len(vulnerabilities),

            "risk":
                risk,

            "verdict":
                verdict,

            "vulnerabilities":
                format_vulnerabilities(
                    vulnerabilities
                ),

            "recommendation":
                recommendation_for(
                    vulnerabilities,
                    risk
                )
        })

    critical = sum(
        result["risk"] == "CRITICAL"
        for result in results
    )

    high = sum(
        result["risk"] == "HIGH"
        for result in results
    )

    medium = sum(
        result["risk"] == "MEDIUM"
        for result in results
    )

    vulnerable = sum(
        result["vulnerable"]
        for result in results
    )

    return {

        "checked_at":
            utc_now(),

        "summary": {

            "total_dependencies":
                len(results),

            "vulnerable_dependencies":
                vulnerable,

            "critical":
                critical,

            "high":
                high,

            "medium":
                medium
        },

        "results":
            results
    }


@router.post(
    "/analyze-project"
)
async def analyze_project(
    request: ProjectRequest
):

    dependencies = [
        dependency.model_dump()
        for dependency in request.dependencies
    ]

    try:

        data = await query_batch(
            dependencies
        )

    except Exception as exc:

        raise HTTPException(
            status_code=502,
            detail=f"OSV request failed: {exc}"
        )

    results = []

    for index, dependency in enumerate(
        request.dependencies
    ):

        osv_result = (
            data[index]
            if index < len(data)
            else {}
        )

        vulnerabilities = prepare_vulnerabilities(
            osv_result.get(
                "vulns",
                []
            )
        )

        risk = calculate_risk(
            vulnerabilities
        )

        verdict = get_verdict(
            risk
        )

        results.append({

            "package":
                dependency.package,

            "ecosystem":
                dependency.ecosystem,

            "version":
                dependency.version,

            "vulnerable":
                bool(vulnerabilities),

            "vulnerability_count":
                len(vulnerabilities),

            "risk":
                risk,

            "verdict":
                verdict,

            "vulnerabilities":
                format_vulnerabilities(
                    vulnerabilities
                ),

            "recommendation":
                recommendation_for(
                    vulnerabilities,
                    risk
                )
        })

    counts = {

        "critical": 0,

        "high": 0,

        "medium": 0,

        "low": 0
    }

    for result in results:

        risk = result["risk"].lower()

        if risk in counts:
            counts[risk] += 1

    if counts["critical"] > 0:

        project_verdict = "BLOCK"

    elif counts["high"] > 0:

        project_verdict = "BLOCK"

    elif counts["medium"] > 0:

        project_verdict = "REVIEW"

    else:

        project_verdict = "ALLOW"

    return {

        "project":
            request.project_name,

        "manifest_type":
            request.manifest_type,

        "checked_at":
            utc_now(),

        "summary": {

            "dependencies":
                len(results),

            "vulnerable":
                sum(
                    result["vulnerable"]
                    for result in results
                ),

            **counts
        },

        "verdict":
            project_verdict,

        "results":
            results
    }
