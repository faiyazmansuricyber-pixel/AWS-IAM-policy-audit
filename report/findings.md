# AWS IAM Policy Audit: Findings

Account: lab account (ID redacted) | Date: 31 Oct 2026 | Auditor: Faiyaz Mansuri

## Scope
Single AWS lab account. Baseline (clean) state was captured first, then four misconfigurations were created on purpose and audited.

## Findings

| ID | Finding | Resource | Severity | Why it matters | Evidence |
|----|---------|----------|----------|----------------|----------|
| F1 | AdministratorAccess attached directly to user; 457 services allowed, none used | lab-dev-intern | High | TODO: write in your own words | evidence/f1-permissions.png, evidence/f1-access-advisor.png |
| F2 | Console access enabled without MFA | lab-dev-intern | High | TODO: write in your own words | evidence/f2-no-mfa.png, evidence/01-audit-credential-report.csv |
| F3 | Wildcard policy (Action: *, Resource: *); IAM DeleteUser simulated as Allowed | lab-overly-permissive-policy / lab-app-service | Critical | TODO: write in your own words | evidence/f3-policy-json.png, evidence/f3-simulator.png |
| F4 | Active access key never used (age simulated) | lab-app-service | Medium | TODO: write in your own words | evidence/f4-access-key.png, evidence/01-audit-credential-report.csv |
| F5 | No external access findings (informational) | IAM Access Analyzer | Info | TODO: confirm after scan completes | evidence/f5-access-analyzer.png |

## Notes
- F4: key age is simulated; in production, rotation age (90+ days) would also be checked.
- F5: analyzer was just created; re-check findings after the first scan completes.

## Remediation (to be completed)
| ID | Planned fix | Status |
|----|-------------|--------|
| F1 | Remove direct AdministratorAccess; use group with least-privilege policy | Pending |
| F2 | Enforce MFA for console users | Pending |
| F3 | Replace wildcard policy with scoped permissions | Pending |
| F4 | Deactivate and delete unused key | Pending |
