"""Tests for scripts/iam_audit.py. Run from the repo root:  python -m unittest discover -s tests -v
(also works with pytest)."""
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import iam_audit as ia  # noqa: E402

ACCOUNT = "123456789012"  # AWS documentation example ID, not a real account


def doc(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def allow(action, resource, **extra):
    st = {"Effect": "Allow", "Action": action, "Resource": resource}
    st.update(extra)
    return st


def rules(findings):
    return sorted(f["rule"] for f in findings)


class PolicyRuleTests(unittest.TestCase):
    def test_full_wildcard_is_critical(self):
        f = ia.check_policy_document("policy/p", doc(allow("*", "*")))
        self.assertEqual(rules(f), ["WILDCARD_ALL"])
        self.assertEqual(f[0]["severity"], "Critical")

    def test_scoped_policy_is_clean(self):
        f = ia.check_policy_document("policy/p", doc(allow("s3:GetObject", "arn:aws:s3:::b/*")))
        self.assertEqual(f, [])

    def test_service_wildcard_on_all_resources(self):
        f = ia.check_policy_document("policy/p", doc(allow("s3:*", "*")))
        self.assertEqual(rules(f), ["WILDCARD_SERVICE"])

    def test_wildcard_action_on_specific_resource_is_medium(self):
        f = ia.check_policy_document("policy/p", doc(allow("*", "arn:aws:s3:::b/*")))
        self.assertEqual(rules(f), ["WILDCARD_ACTION"])
        self.assertEqual(f[0]["severity"], "Medium")

    def test_privilege_escalation_action(self):
        f = ia.check_policy_document("policy/p", doc(allow(["iam:PassRole"], "*")))
        self.assertEqual(rules(f), ["PRIV_ESC"])

    def test_privilege_escalation_on_specific_resource_not_flagged(self):
        f = ia.check_policy_document("policy/p", doc(allow("iam:PassRole", "arn:aws:iam::%s:role/app" % ACCOUNT)))
        self.assertEqual(f, [])

    def test_deny_statement_is_ignored(self):
        f = ia.check_policy_document("policy/p", doc({"Effect": "Deny", "Action": "*", "Resource": "*"}))
        self.assertEqual(f, [])

    def test_not_action_allow_flagged(self):
        f = ia.check_policy_document("policy/p", doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
        self.assertIn("NOT_ACTION_ALLOW", rules(f))


class UserAndRoleRuleTests(unittest.TestCase):
    def test_admin_directly_on_user(self):
        f = ia.check_user({"name": "u", "attached_policies": ["AdministratorAccess"]})
        self.assertEqual(rules(f), ["ADMIN_ATTACHED_USER"])

    def test_admin_via_group_is_not_flagged(self):
        snap = {"account_id": ACCOUNT,
                "users": [{"name": "u", "console_access": True, "mfa_enabled": True, "groups": ["Admins"]}],
                "groups": [{"name": "Admins", "attached_policies": ["AdministratorAccess"]}]}
        self.assertEqual(ia.analyze(snap)["findings"], [])

    def test_missing_mfa_only_when_console_enabled(self):
        self.assertEqual(rules(ia.check_user({"name": "u", "console_access": True, "mfa_enabled": False})), ["NO_MFA"])
        self.assertEqual(ia.check_user({"name": "u", "console_access": False, "mfa_enabled": False}), [])

    def test_active_unused_key_flagged_inactive_not(self):
        active = {"name": "u", "access_keys": [{"id": "k", "status": "Active", "age_days": 1, "last_used": None}]}
        inactive = {"name": "u", "access_keys": [{"id": "k", "status": "Inactive", "age_days": 1, "last_used": None}]}
        self.assertEqual(rules(ia.check_user(active)), ["KEY_UNUSED"])
        self.assertEqual(ia.check_user(inactive), [])

    def test_old_key_flagged(self):
        user = {"name": "u", "access_keys": [{"id": "k", "status": "Active", "age_days": 200, "last_used": "2026-01-01"}]}
        self.assertEqual(rules(ia.check_user(user)), ["KEY_OLD"])

    def test_admin_on_role(self):
        snap = {"account_id": ACCOUNT, "roles": [{"name": "r", "attached_policies": ["AdministratorAccess"],
                "trust_policy": doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"})}]}
        self.assertEqual(rules(ia.analyze(snap)["findings"]), ["ADMIN_ATTACHED_ROLE"])


class TrustPolicyTests(unittest.TestCase):
    def test_service_principal_is_fine(self):
        t = doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"})
        self.assertEqual(ia.check_trust_policy("r", t, ACCOUNT), [])

    def test_public_principal_is_critical(self):
        t = doc({"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"})
        f = ia.check_trust_policy("r", t, ACCOUNT)
        self.assertEqual((rules(f), f[0]["severity"]), (["TRUST_PUBLIC"], "Critical"))

    def test_public_principal_with_condition_is_lower(self):
        t = doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                 "Condition": {"StringEquals": {"sts:ExternalId": "x"}}})
        self.assertEqual(ia.check_trust_policy("r", t, ACCOUNT)[0]["severity"], "High")

    def test_other_account_flagged_own_account_not(self):
        other = doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"})
        own = doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"})
        self.assertEqual(rules(ia.check_trust_policy("r", other, ACCOUNT)), ["TRUST_CROSS_ACCOUNT"])
        self.assertEqual(ia.check_trust_policy("r", own, ACCOUNT), [])


class EvaluatorTests(unittest.TestCase):
    def test_allow_and_implicit_deny(self):
        d = [doc(allow("s3:GetObject", "arn:aws:s3:::b/*"))]
        self.assertTrue(ia.evaluate(d, "s3:GetObject", "arn:aws:s3:::b/x"))
        self.assertFalse(ia.evaluate(d, "s3:PutObject", "arn:aws:s3:::b/x"))
        self.assertFalse(ia.evaluate(d, "s3:GetObject", "arn:aws:s3:::other/x"))

    def test_explicit_deny_wins(self):
        d = [doc(allow("*", "*"), {"Effect": "Deny", "Action": "iam:*", "Resource": "*"})]
        self.assertFalse(ia.evaluate(d, "iam:DeleteUser", "*"))
        self.assertTrue(ia.evaluate(d, "s3:GetObject", "arn:aws:s3:::b/x"))

    def test_action_match_is_case_insensitive(self):
        self.assertTrue(ia.evaluate([doc(allow("S3:getobject", "*"))], "s3:GetObject", "x"))

    def test_conditions_are_skipped(self):
        d = [doc(allow("s3:GetObject", "*", Condition={"Bool": {"aws:SecureTransport": "true"}}))]
        self.assertFalse(ia.evaluate(d, "s3:GetObject", "x"))


class LabRegressionTests(unittest.TestCase):
    """The lab snapshots must produce 5 findings before the fixes and none after."""

    @classmethod
    def setUpClass(cls):
        cls.before = ia.analyze(ia.load(ROOT / "lab/snapshots/before.json"))
        cls.after = ia.analyze(ia.load(ROOT / "lab/snapshots/after.json"))
        cls.tests = ia.load(ROOT / "lab/access_tests.json")

    def test_before_has_the_five_planted_problems(self):
        self.assertEqual(self.before["summary"]["findings_total"], 5)
        self.assertEqual(rules(self.before["findings"]),
                         sorted(["WILDCARD_ALL", "ADMIN_ATTACHED_ROLE", "ADMIN_ATTACHED_USER", "NO_MFA", "KEY_UNUSED"]))

    def test_after_has_no_findings(self):
        self.assertEqual(self.after["summary"]["findings_total"], 0)

    def test_access_checks_before_and_after(self):
        for section, snap in (("before", "before"), ("after", "after")):
            results = ia.run_access_tests(ia.load(ROOT / ("lab/snapshots/%s.json" % snap)), self.tests[section])
            self.assertTrue(all(r["passed"] for r in results), [r for r in results if not r["passed"]])

    def test_comparison_resolves_everything(self):
        text = ia.compare(self.before, self.after)
        self.assertIn("Resolved: 5 | Still present: 0 | New: 0", text)

    def test_outputs_are_redacted(self):
        self.assertNotIn("123456789012", ia.render_markdown(self.before))
        self.assertEqual(ia.redact("arn:aws:iam::123456789012:root"), "arn:aws:iam::XXXXXXXXXXXX:root")

    def test_cli_fail_on_exit_code(self):
        out = ROOT / "report" / "automated" / "_tmp_cli_test"
        try:
            self.assertEqual(ia.main(["audit", "--input", str(ROOT / "lab/snapshots/before.json"),
                                      "--outdir", str(out), "--fail-on", "high"]), 1)
            self.assertEqual(ia.main(["audit", "--input", str(ROOT / "lab/snapshots/after.json"),
                                      "--outdir", str(out), "--fail-on", "high"]), 0)
        finally:
            for p in out.glob("*"):
                p.unlink()
            if out.exists():
                out.rmdir()


if __name__ == "__main__":
    unittest.main()
