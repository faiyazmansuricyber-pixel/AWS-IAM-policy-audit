# Access verification (lab-after-fix)

| Principal | Action | Resource | Expected | Got | Reason | Result |
|---|---|---|---|---|---|---|
| user/lab-dev-intern | s3:GetObject | arn:aws:s3:::lab-dev-data-bucket/report.txt | allow | allow | explicit allow | PASS |
| user/lab-dev-intern | s3:PutObject | arn:aws:s3:::lab-dev-data-bucket/report.txt | deny | deny | implicit deny | PASS |
| user/lab-dev-intern | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | deny | deny | implicit deny | PASS |
| user/lab-app-service | s3:PutObject | arn:aws:s3:::lab-app-logs-bucket/app.log | allow | allow | explicit allow | PASS |
| user/lab-app-service | s3:GetObject | arn:aws:s3:::lab-app-logs-bucket/app.log | deny | deny | implicit deny | PASS |
| user/lab-app-service | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | deny | deny | implicit deny | PASS |
| role/lab-ec2-admin-role | s3:GetObject | arn:aws:s3:::lab-dev-data-bucket/report.txt | allow | allow | explicit allow | PASS |
| role/lab-ec2-admin-role | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | deny | deny | implicit deny | PASS |

8 of 8 checks passed.

Scope: identity-based policies only. Permission boundaries, SCPs and resource-based policies are not evaluated. A check is INDETERMINATE when a matching statement has a Condition or an attached policy document is unresolved.
