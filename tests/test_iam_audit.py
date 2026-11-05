"""Tests for scripts/iam_audit.py. Run from the repo root:  python -m unittest discover -s tests -v
(also works with pytest). The focus is on cases that could cause a wrong security conclusion."""
import copy
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


def deny(action, resource, **extra):
    st = {"Effect": "Deny", "Action": action, "Resource": resource}
    st.update(extra)
    return st


def rules(findings):
    return sorted(f["rule"] for f in findings)


def open_rules(result):
    return sorted(f["rule"] for f in result["findings"] if f["status"] == "open")


class PolicyRuleTests(unittest.TestCase):
    def test_full_wildcard_is_critical(self):
        f = ia.check_policy_document("policy/p", doc(allow("*", "*")))
        self.assertEqual((rules(f), f[0]["severity"]), (["WILDCARD_ALL"], "Critical"))

    def test_scoped_policy_is_clean(self):
        self.assertEqual(ia.check_policy_document("policy/p", doc(allow("s3:GetObject", "arn:aws:s3:::b/*"))), [])

    def test_service_wildcard_on_all_resources(self):
        self.assertEqual(rules(ia.check_policy_document("policy/p", doc(allow("s3:*", "*")))), ["WILDCARD_SERVICE"])

    def test_wildcard_action_on_specific_resource_is_medium(self):
        f = ia.check_policy_document("policy/p", doc(allow("*", "arn:aws:s3:::b/*")))
        self.assertEqual((rules(f), f[0]["severity"]), (["WILDCARD_ACTION"], "Medium"))

    def test_privilege_escalation_action_on_all_resources(self):
        self.assertEqual(rules(ia.check_policy_document("policy/p", doc(allow(["iam:PassRole"], "*")))), ["PRIV_ESC"])

    def test_privilege_escalation_action_on_specific_resource_not_flagged(self):
        f = ia.check_policy_document("policy/p", doc(allow("iam:PassRole", "arn:aws:iam::%s:role/app" % ACCOUNT)))
        self.assertEqual(f, [])

    def test_deny_statement_is_ignored(self):
        self.assertEqual(ia.check_policy_document("policy/p", doc(deny("*", "*"))), [])

    def test_not_action_allow_flagged(self):
        f = ia.check_policy_document("policy/p", doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"}))
        self.assertIn("NOT_ACTION_ALLOW", rules(f))

    def test_multiple_statements_reported_once_per_rule(self):
        f = ia.check_policy_document("policy/p", doc(allow("*", "*", Sid="a"), allow("*", "*", Sid="b")))
        self.assertEqual(len(f), 1)
        self.assertIn("a, b", f[0]["detail"])

    def test_malformed_policies_do_not_crash(self):
        for bad in (None, {}, {"Statement": "oops"}, {"Statement": ["text", 5, None]}, {"Statement": {"Effect": "Allow"}}, "x"):
            self.assertEqual(ia.check_policy_document("policy/p", bad), [])


class UserGroupRoleRuleTests(unittest.TestCase):
    def test_admin_directly_on_user(self):
        self.assertEqual(rules(ia.check_user({"name": "u", "attached_policies": ["AdministratorAccess"]})),
                         ["ADMIN_ATTACHED_USER"])

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

    def _group_admin_snapshot(self, approved=None):
        snap = {"account_id": ACCOUNT,
                "users": [{"name": "u", "console_access": True, "mfa_enabled": True, "groups": ["Admins"]}],
                "groups": [{"name": "Admins", "attached_policies": ["AdministratorAccess"]}]}
        if approved:
            snap["approved_admins"] = approved
        return snap

    def test_admin_via_group_is_flagged_when_not_approved(self):
        result = ia.analyze(self._group_admin_snapshot())
        self.assertEqual(open_rules(result), ["ADMIN_ATTACHED_GROUP", "PRIVILEGED_GROUP_MEMBER"])

    def test_admin_via_group_is_accepted_when_approved(self):
        result = ia.analyze(self._group_admin_snapshot(approved=["group/Admins", "user/u"]))
        self.assertEqual(result["summary"]["findings_total"], 0)
        self.assertEqual(result["summary"]["accepted_total"], 2)
        self.assertIn("Accepted", ia.render_markdown(result))

    def test_approval_does_not_hide_other_findings(self):
        snap = self._group_admin_snapshot(approved=["group/Admins", "user/u"])
        snap["users"][0]["mfa_enabled"] = False
        self.assertEqual(open_rules(ia.analyze(snap)), ["NO_MFA"])

    def test_admin_on_role(self):
        snap = {"account_id": ACCOUNT, "roles": [{"name": "r", "attached_policies": ["AdministratorAccess"],
                "trust_policy": doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                                     "Action": "sts:AssumeRole"})}]}
        self.assertEqual(open_rules(ia.analyze(snap)), ["ADMIN_ATTACHED_ROLE"])

    def test_aws_managed_admin_policy_not_double_flagged(self):
        arn = "arn:aws:iam::aws:policy/AdministratorAccess"
        snap = {"account_id": ACCOUNT,
                "users": [{"name": "u", "attached_policies": [{"name": "AdministratorAccess", "arn": arn}]}],
                "policies": [{"name": "AdministratorAccess", "arn": arn, "aws_managed": True,
                              "document": doc(allow("*", "*"))}]}
        self.assertEqual(open_rules(ia.analyze(snap)), ["ADMIN_ATTACHED_USER"])

    def test_customer_policy_named_like_admin_is_not_the_aws_one(self):
        ref = {"name": "AdministratorAccess", "arn": "arn:aws:iam::%s:policy/AdministratorAccess" % ACCOUNT}
        self.assertFalse(ia.is_admin(ref))

    def test_other_aws_managed_policy_documents_are_analyzed(self):
        arn = "arn:aws:iam::aws:policy/PowerUserAccess"
        snap = {"account_id": ACCOUNT,
                "users": [{"name": "u", "attached_policies": [{"name": "PowerUserAccess", "arn": arn}]}],
                "policies": [{"name": "PowerUserAccess", "arn": arn, "aws_managed": True,
                              "document": doc({"Effect": "Allow", "NotAction": ["iam:*"], "Resource": "*"})}]}
        self.assertEqual(open_rules(ia.analyze(snap)), ["NOT_ACTION_ALLOW"])


class TrustPolicyTests(unittest.TestCase):
    def test_service_principal_is_fine(self):
        t = doc({"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"})
        self.assertEqual(ia.check_trust_policy("r", t, ACCOUNT), [])

    def test_public_principal_is_critical(self):
        f = ia.check_trust_policy("r", doc({"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}), ACCOUNT)
        self.assertEqual((rules(f), f[0]["severity"]), (["TRUST_PUBLIC"], "Critical"))

    def test_condition_does_not_lower_severity(self):
        t = doc({"Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "sts:AssumeRole",
                 "Condition": {"StringEquals": {"sts:ExternalId": "x"}}})
        f = ia.check_trust_policy("r", t, ACCOUNT)
        self.assertEqual(f[0]["severity"], "Critical")
        self.assertIn("manual review", f[0]["detail"])

    def test_wildcard_service_principal_flagged(self):
        t = doc({"Effect": "Allow", "Principal": {"Service": "*"}, "Action": "sts:AssumeRole"})
        self.assertEqual(rules(ia.check_trust_policy("r", t, ACCOUNT)), ["TRUST_PUBLIC"])

    def test_other_account_flagged_own_account_not(self):
        other = doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:root"}, "Action": "sts:AssumeRole"})
        own = doc({"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::%s:root" % ACCOUNT}, "Action": "sts:AssumeRole"})
        self.assertEqual(rules(ia.check_trust_policy("r", other, ACCOUNT)), ["TRUST_CROSS_ACCOUNT"])
        self.assertEqual(ia.check_trust_policy("r", own, ACCOUNT), [])

    def test_federated_principal_flagged_for_review(self):
        t = doc({"Effect": "Allow", "Principal": {"Federated": "arn:aws:iam::%s:oidc-provider/example.com" % ACCOUNT},
                 "Action": "sts:AssumeRoleWithWebIdentity"})
        f = ia.check_trust_policy("r", t, ACCOUNT)
        self.assertEqual((rules(f), f[0]["severity"]), (["TRUST_FEDERATED"], "Low"))

    def test_malformed_trust_policy_does_not_crash(self):
        for bad in (None, {}, {"Statement": [{"Effect": "Allow", "Principal": 5}]}):
            self.assertEqual(ia.check_trust_policy("r", bad, ACCOUNT), [])


class EvaluatorTests(unittest.TestCase):
    def ev(self, docs, action, resource, unresolved=()):
        return ia.evaluate(docs, action, resource, unresolved)[0]

    def test_allow_and_implicit_deny(self):
        d = [doc(allow("s3:GetObject", "arn:aws:s3:::b/*"))]
        self.assertEqual(self.ev(d, "s3:GetObject", "arn:aws:s3:::b/x"), "allow")
        self.assertEqual(self.ev(d, "s3:PutObject", "arn:aws:s3:::b/x"), "deny")
        self.assertEqual(self.ev(d, "s3:GetObject", "arn:aws:s3:::other/x"), "deny")

    def test_explicit_deny_wins(self):
        d = [doc(allow("*", "*"), deny("iam:*", "*"))]
        self.assertEqual(self.ev(d, "iam:DeleteUser", "*"), "deny")
        self.assertEqual(self.ev(d, "s3:GetObject", "arn:aws:s3:::b/x"), "allow")

    def test_action_match_is_case_insensitive(self):
        self.assertEqual(self.ev([doc(allow("S3:getobject", "*"))], "s3:GetObject", "x"), "allow")

    def test_conditional_deny_makes_allow_indeterminate(self):
        d = [doc(allow("iam:DeleteUser", "*"),
                 deny("iam:DeleteUser", "*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "false"}}))]
        self.assertEqual(self.ev(d, "iam:DeleteUser", "*"), "indeterminate")

    def test_conditional_allow_is_indeterminate_not_deny(self):
        d = [doc(allow("s3:GetObject", "*", Condition={"Bool": {"aws:SecureTransport": "true"}}))]
        self.assertEqual(self.ev(d, "s3:GetObject", "x"), "indeterminate")

    def test_definite_deny_beats_conditional_allow(self):
        d = [doc(allow("s3:*", "*", Condition={"Bool": {"x": "y"}}), deny("s3:GetObject", "*"))]
        self.assertEqual(self.ev(d, "s3:GetObject", "x"), "deny")

    def test_not_resource_is_evaluated(self):
        d = [doc({"Effect": "Allow", "Action": "s3:GetObject", "NotResource": "arn:aws:s3:::secret/*"})]
        self.assertEqual(self.ev(d, "s3:GetObject", "arn:aws:s3:::public/x"), "allow")
        self.assertEqual(self.ev(d, "s3:GetObject", "arn:aws:s3:::secret/x"), "deny")

    def test_not_action_is_evaluated(self):
        d = [doc({"Effect": "Allow", "NotAction": "iam:*", "Resource": "*"})]
        self.assertEqual(self.ev(d, "s3:GetObject", "x"), "allow")
        self.assertEqual(self.ev(d, "iam:DeleteUser", "x"), "deny")

    def test_unresolved_policy_makes_result_indeterminate(self):
        d = [doc(allow("s3:GetObject", "*"))]
        self.assertEqual(self.ev(d, "s3:GetObject", "x", unresolved=["SomePolicy"]), "indeterminate")
        self.assertEqual(self.ev([], "iam:DeleteUser", "x", unresolved=["SomePolicy"]), "indeterminate")

    def test_explicit_deny_stands_even_with_unresolved_policy(self):
        d = [doc(deny("iam:*", "*"))]
        self.assertEqual(self.ev(d, "iam:DeleteUser", "x", unresolved=["SomePolicy"]), "deny")

    def test_policy_refs_are_matched_by_arn(self):
        aws_arn, own_arn = "arn:aws:iam::aws:policy/Same", "arn:aws:iam::%s:policy/Same" % ACCOUNT
        snap = {"users": [{"name": "u", "attached_policies": [{"name": "Same", "arn": own_arn}]}],
                "policies": [{"name": "Same", "arn": aws_arn, "aws_managed": True, "document": doc(allow("*", "*"))},
                             {"name": "Same", "arn": own_arn, "document": doc(allow("s3:GetObject", "*"))}]}
        docs, unresolved = ia.effective_docs(snap, "user/u")
        self.assertEqual(unresolved, [])
        self.assertEqual(self.ev(docs, "iam:DeleteUser", "x"), "deny")

    def test_group_policies_are_included(self):
        snap = {"users": [{"name": "u", "groups": ["g"]}],
                "groups": [{"name": "g", "attached_policies": ["p"]}],
                "policies": [{"name": "p", "document": doc(allow("s3:GetObject", "*"))}]}
        docs, _ = ia.effective_docs(snap, "user/u")
        self.assertEqual(self.ev(docs, "s3:GetObject", "x"), "allow")


class LabRegressionTests(unittest.TestCase):
    """The lab snapshots must give 5 open findings before the fixes and none after."""

    @classmethod
    def setUpClass(cls):
        cls.before_snap = ia.load(ROOT / "lab/snapshots/before.json")
        cls.after_snap = ia.load(ROOT / "lab/snapshots/after.json")
        cls.before, cls.after = ia.analyze(cls.before_snap), ia.analyze(cls.after_snap)
        cls.tests = ia.load(ROOT / "lab/access_tests.json")

    def test_before_has_the_five_planted_problems(self):
        self.assertEqual(self.before["summary"]["findings_total"], 5)
        self.assertEqual(open_rules(self.before), sorted(
            ["WILDCARD_ALL", "ADMIN_ATTACHED_ROLE", "ADMIN_ATTACHED_USER", "NO_MFA", "KEY_UNUSED"]))

    def test_after_has_no_open_findings_and_two_accepted_admins(self):
        self.assertEqual(self.after["summary"]["findings_total"], 0)
        self.assertEqual(self.after["summary"]["accepted_total"], 2)

    def test_after_without_approvals_shows_admin_group(self):
        snap = copy.deepcopy(self.after_snap)
        snap.pop("approved_admins")
        self.assertEqual(open_rules(ia.analyze(snap)), ["ADMIN_ATTACHED_GROUP", "PRIVILEGED_GROUP_MEMBER"])

    def test_access_checks_before_and_after(self):
        for section, snap in (("before", self.before_snap), ("after", self.after_snap)):
            results = ia.run_access_tests(snap, self.tests[section])
            self.assertTrue(all(r["passed"] for r in results), [r for r in results if not r["passed"]])

    def test_unresolved_managed_policy_makes_access_check_indeterminate(self):
        snap = copy.deepcopy(self.after_snap)
        snap["policies"] = [p for p in snap["policies"] if p["name"] != "IAMUserChangePassword"]
        results = ia.run_access_tests(snap, [t for t in self.tests["after"] if t["principal"] == "user/lab-dev-intern"])
        self.assertTrue(all(r["got"] == "indeterminate" for r in results))
        self.assertFalse(any(r["passed"] for r in results))

    def test_comparison_resolves_everything(self):
        text = ia.compare(self.before, self.after)
        self.assertIn("Resolved: 5 | Still present: 0 | New: 0", text)

    def test_outputs_are_redacted(self):
        self.assertNotIn(ACCOUNT, ia.render_markdown(self.before))
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
