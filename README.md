# DependencyRisk API

Automated open-source dependency security intelligence for software agents.

## Features

- Package vulnerability lookup
- Batch dependency analysis
- Project-level security analysis
- CVE/GHSA/OSV identifiers
- Fixed-version detection
- CVSS information when supplied by OSV
- Machine-readable JSON responses
- Rule-based security verdicts

## Data source

DependencyRisk uses the OSV vulnerability database.

## API

### Health

GET `/health`

### Package check

GET `/check-package`

Parameters:

- `package`
- `ecosystem`
- `version`

Example:

`/check-package?package=lodash&ecosystem=npm&version=4.17.20`

### Batch analysis

POST `/check-dependencies`

### Project analysis

POST `/analyze-project`

## Security verdicts

- `ALLOW`: no known vulnerability returned
- `REVIEW`: vulnerability information requires review
- `BLOCK`: high/critical risk according to the current rule engine

These verdicts are automated indicators, not guarantees of software safety.

## Roadmap

- GitHub Advisory Database enrichment
- Malware advisory enrichment
- License intelligence
- Dependency graph analysis
- SBOM generation
- Automated remediation suggestions
- x402 USDC payments
- API marketplace discovery
