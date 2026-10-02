from typing import List, Optional
from pydantic import BaseModel


class Vulnerability(BaseModel):
    id: str
    summary: Optional[str] = None
    severity: Optional[str] = None
    cvss_score: Optional[float] = None
    published: Optional[str] = None
    modified: Optional[str] = None
    fixed_version: Optional[str] = None


class PackageResult(BaseModel):
    package: str
    ecosystem: str
    version: str

    vulnerable: bool
    vulnerability_count: int

    risk: str
    verdict: str

    vulnerabilities: List[Vulnerability]

    recommendation: str
    checked_at: str


class DependencyRequest(BaseModel):
    package: str
    ecosystem: str
    version: str


class BatchRequest(BaseModel):
    dependencies: List[DependencyRequest]
