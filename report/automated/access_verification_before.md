# Access verification (lab-before-fix)

| Principal | Action | Resource | Expected | Got | Reason | Result |
|---|---|---|---|---|---|---|
| user/lab-dev-intern | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | allow | allow | explicit allow | PASS |
| user/lab-app-service | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | allow | allow | explicit allow | PASS |
| role/lab-ec2-admin-role | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | allow | allow | explicit allow | PASS |

3 of 3 checks passed.

Scope: identity-based policies only. Permission boundaries, SCPs and resource-based policies are not evaluated. A check is INDETERMINATE when a matching statement has a Condition or an attached policy document is unresolved.
