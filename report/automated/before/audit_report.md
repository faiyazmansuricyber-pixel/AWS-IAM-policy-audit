# IAM Audit Report (lab-before-fix)

| Item | Count |
|---|---|
| Users | 3 |
| Groups | 1 |
| Roles | 1 |
| Policies analyzed | 3 |
| **Open findings** | **5** |
| Critical | 1 |
| High | 3 |
| Medium | 1 |
| Low | 0 |
| Info | 0 |
| Accepted (approved administrators) | 2 |

## Open findings

| # | Severity | Rule | Resource | Detail |
|---|---|---|---|---|
| 1 | Critical | WILDCARD_ALL | policy/lab-overly-permissive-policy | Statements: statement-1. Attached to: user/lab-app-service. |
| 2 | High | ADMIN_ATTACHED_ROLE | role/lab-ec2-admin-role | Policy AdministratorAccess is attached. |
| 3 | High | ADMIN_ATTACHED_USER | user/lab-dev-intern | Policy AdministratorAccess is attached directly. |
| 4 | High | NO_MFA | user/lab-dev-intern | Console access is enabled and no MFA device is registered. |
| 5 | Medium | KEY_UNUSED | user/lab-app-service/key-1 | Key is Active and has no recorded use. |

## Remediation

1. **Policy allows all actions on all resources** (policy/lab-overly-permissive-policy): Replace with the specific actions and resources the identity needs.
2. **AdministratorAccess attached to a role** (role/lab-ec2-admin-role): Replace with a scoped policy for what the workload needs.
3. **AdministratorAccess attached directly to a user** (user/lab-dev-intern): Remove it and grant a scoped policy, preferably through a group.
4. **Console user without MFA** (user/lab-dev-intern): Enable MFA for the user.
5. **Active access key that has never been used** (user/lab-app-service/key-1): Deactivate, then delete the key.

## Accepted (listed in approved_admins)

These are visible on purpose: administrator access that was reviewed and approved.

- High: group/Admins (ADMIN_ATTACHED_GROUP)
- Medium: user/admin-user (PRIVILEGED_GROUP_MEMBER)
