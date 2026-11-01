# Remediation and Verification

Account: lab account (ID redacted) | Date: 1 Nov 2026 | Engineer: Faiyaz Mansuri

Findings F1 to F4 from [findings.md](findings.md) were fixed in this order: F1, F2, F3, F4. Each fix was verified with before/after evidence.

## Summary

| ID | Before | Fix applied | After | Evidence (before / after) |
|----|--------|-------------|-------|---------------------------|
| F1 | `lab-dev-intern` had `AdministratorAccess` attached directly; 457 services allowed | Removed the direct admin policy; created `lab-dev-intern-s3-read`, attached through group `lab-developers` | 2 allowed services (S3 read on one bucket, IAM change own password); IAM `DeleteUser` simulated as **Denied** | `f1-permissions.png`, `f1-access-advisor.png` / `f1-after-permissions.png`, `f1-after-simulator.png`, `f1-after-access-advisor.png` |
| F2 | Console access enabled without MFA | Assigned a virtual MFA device to `lab-dev-intern` | Console access "Enabled with MFA"; credential report `mfa_active = true` | `f2-no-mfa.png`, `01-audit-credential-report.csv` / `f2-after-mfa.png`, `02-after-fix-credential-report.csv` |
| F3 | `lab-overly-permissive-policy` (`Action: *`, `Resource: *`) on `lab-app-service`; IAM `DeleteUser` simulated as **Allowed** | Created `lab-app-service-s3-write`, attached it, detached and deleted the wildcard policy | Only one scoped permission left; IAM `DeleteUser` simulated as **Denied** | `f3-policy-json.png`, `f3-simulator.png` / `f3-after-permissions.png`, `f3-after-simulator.png`, `f3-policy-deleted.png` |
| F4 | Active access key, never used | Deactivated the key, then deleted it | Access keys (0); credential report `access_key_1_active = false` | `f4-access-key.png`, `01-audit-credential-report.csv` / `f4-after-deactivate.png`, `f4-after-delete.png`, `02-after-fix-credential-report.csv` |

## Policies created (least privilege)

`lab-dev-intern-s3-read` (attached via group `lab-developers`):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "ListOneBucket",
      "Effect": "Allow",
      "Action": "s3:ListBucket",
      "Resource": "arn:aws:s3:::lab-dev-data-bucket"
    },
    {
      "Sid": "ReadObjectsInOneBucket",
      "Effect": "Allow",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::lab-dev-data-bucket/*"
    }
  ]
}
```

`lab-app-service-s3-write` (attached directly to the service user):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "WriteLogsToOneBucket",
      "Effect": "Allow",
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::lab-app-logs-bucket/*"
    }
  ]
}
```
The bucket names are placeholders; the buckets do not exist in the lab. The policies show the shape of a scoped permission.

## Credential report comparison

| User | `01-audit` (before fixes) | `02-after-fix` |
|------|---------------------------|----------------|
| `lab-dev-intern` | `mfa_active = FALSE`, password enabled | `mfa_active = TRUE` |
| `lab-app-service` | `access_key_1_active = TRUE`, last used N/A | `access_key_1_active = FALSE` |
| `@Faiyaz_Mansuri` (admin user) | MFA TRUE | MFA TRUE |
| root | MFA TRUE, no access keys | MFA TRUE, no access keys |

## Notes and observations
- F1 and F3 are permission findings, so the credential report cannot prove them. The proof is the Policy Simulator result (Allowed before, Denied after) and the permissions tabs.
- `lab-app-service` shows `mfa_active = FALSE` in both reports. This is not a finding: the user has no console password, so MFA does not apply.
- `lab-dev-intern` has `password_last_used = no_information`: the console password was never used. In production this would be flagged as a dormant credential to review or remove.
- F4: the key age was simulated (the key was created hours earlier, not 90+ days). In production, key rotation age would also be checked.
- F5 (Access Analyzer): the analyzer reported no external access findings. The lab has no resources shared outside the account, so this is expected.
- The `f1-after-*` screenshots show "Enabled without MFA" because F1 was fixed before F2.

## Lessons learned
- Capturing a clean baseline first made the fixes provable. Comparing the before and after credential reports shows exactly what changed.
- The credential report is cached for up to four hours, so a report taken right after a fix can still show the old state. The Policy Simulator (Allowed before, Denied after) proved the permission fixes that the credential report cannot show.
- Writing a policy for one specific job (one bucket, one action) was easier than trimming down an admin policy. Least privilege starts from "what does this user actually need".
- Evidence must be redacted and checked at zoom level before it is published. Account IDs and key IDs can hide in places like the console sign-in link, not only in the ARN.
