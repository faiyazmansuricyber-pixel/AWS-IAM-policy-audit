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
- [x] Misconfigured lab built (5 planted problems, 6 findings)
- [x] Manual audit (Access Advisor, Policy Simulator, Access Analyzer)
- [x] Credential report comparison (baseline vs audit)
- [x] Remediation and verification
- [x] Offline audit script with tests (lab snapshots)
- [ ] run the snapshot collector against a live account
- [ ] Prowler cross-check

## Automated audit (offline, reproducible)

After the manual audit in the AWS console, I automated the same checks in Python. The script reads an IAM snapshot (a JSON file), applies rule checks, verifies expected access, and compares before and after.

**Important:** the files in `lab/snapshots/` are hand-written mock data that mirror my lab (before and after the fixes). The live lab itself was audited manually in the console (see `report/`). The script reproduces and automates those checks; it was not used on the live lab. The account ID `123456789012` in the mock data is the AWS documentation example, not a real account. AWS managed policy documents in the mock data were reproduced by hand; the collector is designed to retrieve the real ones.

### Quick start
Python 3.8 or newer, standard library only (tested on Python 3.12).

```bash
# 1. Audit a snapshot (writes findings.json and audit_report.md)
python scripts/iam_audit.py audit --input lab/snapshots/before.json --outdir report/automated/before

# 2. Audit the fixed state (exit code 1 if any open finding is High or worse, 0 otherwise)
python scripts/iam_audit.py audit --input lab/snapshots/after.json --outdir report/automated/after --fail-on high

# 3. Check that legitimate access still works and risky access is denied
python scripts/iam_audit.py verify-access --input lab/snapshots/after.json --tests lab/access_tests.json --section after

# 4. Compare before and after
python scripts/iam_audit.py compare --before lab/snapshots/before.json --after lab/snapshots/after.json --out report/automated/comparison.md

# 5. Run the tests
python -m unittest discover -s tests -v
```

### Results on the lab snapshots

| Measure | Before fixes | After fixes |
|---|---|---|
| Critical findings (open) | 1 | 0 |
| High findings (open) | 3 | 0 |
| Medium findings (open) | 1 | 0 |
| **Total open findings** | **5** | **0** |
| Accepted administrators (approved list) | 2 | 2 |
| Access checks, as expected | 3 of 3 (admin can delete IAM users) | 8 of 8 (scoped access allowed, everything else denied) |

The two accepted items are the `Admins` group and the admin user who belongs to it. They are listed in `approved_admins` and still appear in the report as "accepted", so administrator access stays visible. Without the approval, the scanner reports them as open findings.

Details: [comparison](report/automated/comparison.md), [before report](report/automated/before/audit_report.md), [after report](report/automated/after/audit_report.md), [access checks](report/automated/access_verification_after.md).

### Rules implemented

| Rule | Severity | What it flags |
|---|---|---|
| WILDCARD_ALL | Critical | Allow with Action `*` on Resource `*` |
| WILDCARD_SERVICE | High | Service wildcard (for example `s3:*`) on Resource `*` |
| PRIV_ESC | High | Single privilege-escalation actions (for example `iam:PassRole`) on Resource `*` |
| WILDCARD_ACTION | Medium | Action `*` on specific resources |
| NOT_ACTION_ALLOW | Medium | Allow statement using NotAction |
| ADMIN_ATTACHED_USER / ROLE | High | AdministratorAccess attached directly to a user or role |
| ADMIN_ATTACHED_GROUP | High | AdministratorAccess attached to a group (unless approved) |
| PRIVILEGED_GROUP_MEMBER | Medium | User inherits administrator access through a group (unless approved) |
| NO_MFA | High | Console user without MFA |
| KEY_UNUSED | Medium | Active access key with no recorded use |
| KEY_OLD | Medium | Active access key older than 90 days |
| TRUST_PUBLIC | Critical | Role trust policy that allows any principal |
| TRUST_CROSS_ACCOUNT | High | Role trust policy that allows another AWS account |
| TRUST_FEDERATED | Low | Role trusts a federated provider; review conditions |

### How the access check works and its limits
- The evaluator returns `allow`, `deny` or `indeterminate`. An explicit Deny wins. A matching statement with a **Condition** never counts as a definite result: for example, an Allow with a conditional Deny is `indeterminate`.
- An attached policy whose document is not available is **unresolved**, and the result becomes `indeterminate` unless an explicit Deny already applies.
- `NotAction` and `NotResource` are evaluated.
- Not evaluated: permission boundaries, SCPs, resource-based policies, session policies. It is not a replacement for the AWS Policy Simulator.
- A Condition on a trust policy does not lower its severity; it is noted for manual review.
- Privilege escalation is checked for single actions only, not for combinations of permissions.

### Collector status
`scripts/collect_snapshot.py` builds a snapshot from a real account with read-only IAM calls, including attached AWS managed and customer managed policy documents resolved by ARN (needs boto3, see `requirements.txt`). It is **experimental**: its mapping logic is tested with a fake client (pagination, ARNs, AccessDenied, error handling), but it has not been run against a live AWS account yet. Live snapshots are git-ignored.

### Not done yet
Prowler was not run. Not implemented: permission boundary analysis, combined privilege-escalation paths, Access Analyzer policy validation, CI.
## Tools
AWS IAM, IAM Access Analyzer, Policy Simulator, Credential Report, Python (standard library; offline audit script), boto3 (experimental snapshot collector; not run against a live account), Prowler (not run)

## Repo structure
- `evidence/`: screenshots and credential reports (account IDs redacted)
- `report/`: [findings](report/findings.md), [remediation](report/remediation.md) and final audit report
- `report/automated/`: generated offline audit reports and access verification
- `lab/`: mock IAM snapshots and access tests
- `tests/`: offline audit and snapshot collector tests
- `scripts/`: audit script and snapshot collector

> All work was done in an isolated personal lab account. No real data was used.
