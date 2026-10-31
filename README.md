# AWS IAM Policy Audit

A hands-on cloud security project where I built a deliberately misconfigured AWS IAM environment, audited it like a real engagement, and remediated every finding using the principle of least privilege.

## What this project shows
- Identifying over-permissioned users and wildcard (`*:*`) policies
- Detecting missing MFA and unused access keys
- Using IAM Credential Report, Access Advisor, Policy Simulator and Access Analyzer
- Writing a severity-rated findings report with evidence
- Verifying fixes with before/after comparison

## Status
- [x] Lab account secured (root MFA, budget alert, admin group, MFA on admin user)
- [x] Misconfigured lab built (4 deliberate findings)
- [x] Manual audit (Access Advisor, Policy Simulator, Access Analyzer)
- [ ] Credential report comparison (baseline vs audit)
- [ ] Remediation and verification
- [ ] Prowler cross-check
- [ ] Custom boto3 audit script

## Tools
AWS IAM, IAM Access Analyzer, Policy Simulator, Credential Report, Prowler (planned), Python/boto3 (planned)

## Repo structure
- `evidence/`: screenshots and credential reports (account IDs redacted)
- `report/`: [findings](report/findings.md) and final audit report
- `scripts/`: custom audit script

> All work was done in an isolated personal lab account. No real data was used.
