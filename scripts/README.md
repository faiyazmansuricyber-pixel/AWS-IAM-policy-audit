# Scripts

Both scripts use only the Python standard library, except `collect_snapshot.py`, which needs `boto3`.

## iam_audit.py
Reads an IAM snapshot (JSON) and works offline. No AWS credentials are needed.

| Command | What it does |
|---|---|
| `audit` | Applies the rules and writes `findings.json` and `audit_report.md`. Use `--fail-on high` to return exit code 1 when an open finding is High or worse. |
| `verify-access` | Checks expected results (allow, deny) for a user or role. The result can be `allow`, `deny` or `indeterminate`. |
| `compare` | Compares open findings before and after the fixes. |

```bash
python scripts/iam_audit.py audit --input lab/snapshots/before.json --outdir report/automated/before
python scripts/iam_audit.py verify-access --input lab/snapshots/after.json --tests lab/access_tests.json --section after
python scripts/iam_audit.py compare --before lab/snapshots/before.json --after lab/snapshots/after.json --out report/automated/comparison.md
```

Snapshot keys: `users`, `groups`, `roles`, `policies` (documents, by name or ARN), optional `approved_admins`
(for example `["group/Admins", "user/admin-user"]`). Findings for approved administrators are shown as
"accepted" and are not counted as open.

Limits: identity-based policies only. Permission boundaries, SCPs, resource-based policies and session
policies are not evaluated. A check is `indeterminate` when a matching statement has a Condition or an
attached policy document could not be resolved. Privilege escalation is checked for single actions only,
not for combinations.

## collect_snapshot.py (experimental)
Builds a snapshot from a real account with read-only IAM calls, including the documents of attached AWS
managed and customer managed policies (resolved by ARN). It has **not** been run against a live AWS
account yet; its logic is tested with a fake client. Live snapshots contain the account ID and must not
be committed (see `.gitignore`).

```bash
pip install -r requirements.txt
python scripts/collect_snapshot.py --out lab/snapshots/live.json
python scripts/iam_audit.py audit --input lab/snapshots/live.json --outdir report/live
```

## Tests
```bash
python -m unittest discover -s tests -v
```
