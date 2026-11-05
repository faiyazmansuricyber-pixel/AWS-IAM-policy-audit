# Access verification (lab-before-fix)

| Principal | Action | Resource | Expected | Got | Result |
|---|---|---|---|---|---|
| user/lab-dev-intern | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | allow | allow | PASS |
| user/lab-app-service | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | allow | allow | PASS |
| role/lab-ec2-admin-role | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | allow | allow | PASS |

3 of 3 checks passed.

Note: conditions are not evaluated; AWS managed policies other than AdministratorAccess are treated as unknown.
