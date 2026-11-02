# AWS IAM Policy Audit: Findings

Account: lab account (ID redacted) | Date: 31 Oct to 2 Nov 2026 | Auditor: Faiyaz Mansuri

## Scope
Single AWS lab account. Baseline (clean) state was captured first, then misconfigurations were created on purpose and audited: two IAM users, one wildcard policy, one access key and one IAM role. Existing roles were also reviewed: the account had only 4 AWS service-linked roles and no custom roles. Fixes and verification are in [remediation.md](remediation.md).

## Findings

| ID | Finding | Resource | Severity | Why it matters | Best practice | Evidence |
|----|---------|----------|----------|----------------|---------------|----------|
| F1 | AdministratorAccess attached directly to user; 457 services allowed, none used | lab-dev-intern | High | Admin access controls the whole account, but this user needed very little. Access Advisor showed 457 allowed services and none used, so the extra permissions added risk and no value. If this user's password leaked, the attacker would get everything. Attaching it directly to the user, instead of through a group, also makes access harder to track. | Apply least-privilege permissions | evidence/f1-permissions.png, evidence/f1-access-advisor.png |
| F2 | Console access enabled without MFA | lab-dev-intern | High | With only a password, anyone who steals or guesses it can sign in. MFA adds a second step the attacker does not have. The risk was higher because this user had admin rights at the time. | Require multi-factor authentication (MFA) | evidence/f2-no-mfa.png, evidence/01-audit-credential-report.csv |
| F3 | Wildcard policy (Action: *, Resource: *); IAM DeleteUser simulated as Allowed | lab-overly-permissive-policy / lab-app-service | Critical | `Action: *` on `Resource: *` means every action on every resource, which is the same as full admin. The Policy Simulator showed this service user could delete IAM users. Access keys of service users often end up in code or config files, so one leaked key could take over the whole account. It is critical because the permission is unlimited and the key does not expire. | Apply least-privilege permissions | evidence/f3-policy-json.png, evidence/f3-simulator.png |
| F4 | Active access key never used (age simulated) | lab-app-service | Medium | A key that is active but never used is a hidden door. Nobody watches it, and if it leaks there is no normal activity to compare against, so misuse is easy to miss. Unused keys should be deactivated and then deleted. Rated medium because on its own it needs a leak first, but combined with F3 it would have been severe. | Remove unused long-term credentials | evidence/f4-access-key.png, evidence/01-audit-credential-report.csv |
| F5 | No external access findings (informational) | IAM Access Analyzer | Info | This checks whether any resource is shared outside the account. The lab has almost no resources, so no findings is expected. The console did not show a last scan time when checked, so this is a weak check and is recorded for completeness only. | Use IAM Access Analyzer to check external access | evidence/f5-access-analyzer.png |
| F6 | IAM role with AdministratorAccess attached; role never used. Trust policy is limited to the EC2 service | lab-ec2-admin-role | High | If an EC2 instance that uses this role is compromised, for example through a flaw in the app running on it, the attacker can take the role's credentials from the instance and get admin access to the whole account. A role for a workload should only have what that workload needs. Rated high, not critical, because the trust policy is limited to EC2 and no instance used the role. | Use roles for workloads, with least-privilege permissions | evidence/f6-roles-list.png, evidence/f6-role-trust.png, evidence/f6-role-permissions.png, evidence/f6-simulator-before.png |

Best practice names follow the AWS documentation "Security best practices in IAM" (https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html).

## Notes
- F4: key age is simulated; in production, rotation age (90+ days) would also be checked.
- F5: findings were 0, but the console did not show a last scan time, so this should not be read as proof of no exposure.
- F6: when checking a role, the trust relationship (who can assume it) matters as much as the permissions. Here the trust policy only allows `ec2.amazonaws.com`.

## Limitations
The lab used IAM users to demonstrate common misconfigurations. Current AWS guidance prefers IAM Identity Center for people and IAM roles with temporary credentials for workloads, instead of long-term access keys.

## Remediation status
| ID | Fix | Status |
|----|-----|--------|
| F1 | Removed direct AdministratorAccess; scoped policy through a group | Fixed and verified |
| F2 | Assigned MFA device | Fixed and verified |
| F3 | Replaced wildcard policy with a scoped policy; deleted the wildcard policy | Fixed and verified |
| F4 | Deactivated and deleted the unused key | Fixed and verified |
| F5 | None needed (informational) | n/a |
| F6 | Removed AdministratorAccess from the role; added a scoped S3 read policy | Fixed and verified |

Details and before/after evidence: [remediation.md](remediation.md)
