# Access verification (lab-after-fix)

| Principal | Action | Resource | Expected | Got | Result |
|---|---|---|---|---|---|
| user/lab-dev-intern | s3:GetObject | arn:aws:s3:::lab-dev-data-bucket/report.txt | allow | allow | PASS |
| user/lab-dev-intern | s3:PutObject | arn:aws:s3:::lab-dev-data-bucket/report.txt | deny | deny | PASS |
| user/lab-dev-intern | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | deny | deny | PASS |
| user/lab-app-service | s3:PutObject | arn:aws:s3:::lab-app-logs-bucket/app.log | allow | allow | PASS |
| user/lab-app-service | s3:GetObject | arn:aws:s3:::lab-app-logs-bucket/app.log | deny | deny | PASS |
| user/lab-app-service | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | deny | deny | PASS |
| role/lab-ec2-admin-role | s3:GetObject | arn:aws:s3:::lab-dev-data-bucket/report.txt | allow | allow | PASS |
| role/lab-ec2-admin-role | iam:DeleteUser | arn:aws:iam::XXXXXXXXXXXX:user/example | deny | deny | PASS |

8 of 8 checks passed.

Note: conditions are not evaluated; AWS managed policies other than AdministratorAccess are treated as unknown.
