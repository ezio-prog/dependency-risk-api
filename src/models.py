from typing import Optional
from pydantic import BaseModel, Field


class Dependency(BaseModel):
    package: str = Field(..., min_length=1, max_length=200)
    ecosystem: str = Field(..., min_length=1, max_length=50)
    version: str = Field(..., min_length=1, max_length=100)


class BatchRequest(BaseModel):
    dependencies: list[Dependency] = Field(..., min_length=1, max_length=500)


class ProjectRequest(BaseModel):
    project_name: str = Field(
        default="unnamed-project",
        min_length=1,
        max_length=200
    )
    manifest_type: str = Field(
        ...,
        min_length=1,
        max_length=50
    )
    dependencies: list[Dependency] = Field(
        ...,
        min_length=1,
        max_length=500
    )


class Vulnerability(BaseModel):
    id: str
    aliases: list[str] = []
    summary: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    published: Optional[str] = None
    modified: Optional[str] = None
    fixed_version: Optional[str] = None
    references: list[str] = []


class PackageResult(BaseModel):
    package: str
    ecosystem: str
    version: str
    vulnerable: bool
    vulnerability_count: int
    risk: str
    verdict: str
    vulnerabilities: list[Vulnerability]
    recommendation: str
    checked_at: str
