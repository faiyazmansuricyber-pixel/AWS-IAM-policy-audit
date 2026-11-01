# Evidence

All screenshots and CSV files have the AWS account ID, access key IDs and email addresses redacted.

## Baseline (before lab)
- 00-baseline-credential-report.csv
- 00-root-mfa-no-access-keys.png
- 00-zero-spend-budget.png
- 00-admins-group.png
- 00-iam-admin-user-mfa.png

## Audit findings (before fixes)
- 01-audit-credential-report.csv
- f1-permissions.png
- f1-access-advisor.png
- f2-no-mfa.png
- f3-policy-json.png
- f3-app-service-permissions.png
- f3-access-advisor-app-service.png
- f3-simulator.png
- f4-access-key.png
- f5-access-analyzer.png

## After fixes
- 02-after-fix-credential-report.csv
- f1-after-permissions.png
- f1-after-simulator.png
- f1-after-access-advisor.png
- f2-after-mfa.png
- f3-after-permissions.png
- f3-after-simulator.png
- f3-policy-deleted.png
- f4-after-deactivate.png
- f4-after-delete.png

See [report/remediation.md](../report/remediation.md) for how each piece of evidence maps to a fix.
