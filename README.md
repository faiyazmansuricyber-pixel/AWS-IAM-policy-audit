# AWS IAM Policy Audit

A hands-on cloud security project where I built a deliberately misconfigured
AWS IAM environment, audited it like a real engagement, and remediated every
finding using the principle of least privilege.

## What this project shows
- Identifying over-permissioned users and wildcard (`*:*`) policies
- Detecting missing MFA and unused access keys
- Using IAM Credential Report, Access Advisor, Policy Simulator and Access Analyzer
- Writing a severity-rated findings report with evidence
- Verifying fixes with before/after comparison

## Tools
AWS IAM, IAM Access Analyzer, Policy Simulator, Credential Report, Prowler (planned), Python/boto3 (planned)

## Repo structure
- `evidence/`: screenshots and credential reports (account IDs redacted)
- `report/`: findings and final audit report
- `scripts/`: custom audit script

> All work was done in an isolated personal lab account. No real data was used.
