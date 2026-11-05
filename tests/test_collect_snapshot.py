"""Tests the mapping logic of scripts/collect_snapshot.py with a fake IAM client.
These tests do not prove behaviour against real AWS; they check how API-shaped data is turned into a snapshot."""
import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
import collect_snapshot as cs  # noqa: E402
import iam_audit as ia  # noqa: E402

NOW = datetime(2026, 11, 2, tzinfo=timezone.utc)
ADMIN_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"
OWN_ARN = "arn:aws:iam::123456789012:policy/wild"
UNATTACHED_ARN = "arn:aws:iam::123456789012:policy/unattached"
DENIED_ARN = "arn:aws:iam::aws:policy/SecurityAudit"


class AwsError(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakePaginator:
    def __init__(self, pages_fn):
        self.pages_fn = pages_fn

    def paginate(self, **kw):
        return self.pages_fn(**kw)


class FakeIAM:
    """Mimics the IAM calls used by the collector. Subclass or tweak attributes to change behaviour."""

    def __init__(self):
        self.get_policy_calls = []
        self.denied_arns = set()
        self.throttle = False

    def get_paginator(self, op):
        attached = {"intern": [{"PolicyName": "AdministratorAccess", "PolicyArn": ADMIN_ARN}],
                    "svc": [{"PolicyName": "wild", "PolicyArn": OWN_ARN}],
                    "audit-user": [{"PolicyName": "SecurityAudit", "PolicyArn": DENIED_ARN}]}
        table = {
            # two pages on purpose: real list calls are paginated
            "list_users": lambda: [{"Users": [{"UserName": "intern"}, {"UserName": "svc"}]},
                                   {"Users": [{"UserName": "audit-user"}]}],
            "list_mfa_devices": lambda UserName: [{"MFADevices": []}],
            "list_access_keys": lambda UserName: [{"AccessKeyMetadata": (
                [{"AccessKeyId": "FAKEKEYIDFAKEFAKE1234", "Status": "Active",
                  "CreateDate": NOW - timedelta(days=120)}] if UserName == "svc" else [])}],
            "list_groups_for_user": lambda UserName: [{"Groups": []}],
            "list_attached_user_policies": lambda UserName: [{"AttachedPolicies": attached.get(UserName, [])}],
            "list_user_policies": lambda UserName: [{"PolicyNames": []}],
            "list_groups": lambda: [{"Groups": []}],
            "list_roles": lambda: [{"Roles": [
                {"RoleName": "app-role", "Path": "/", "AssumeRolePolicyDocument": {"Statement": []}},
                {"RoleName": "AWSServiceRoleForX", "Path": "/aws-service-role/x/", "AssumeRolePolicyDocument": {}}]}],
            "list_attached_role_policies": lambda RoleName: [{"AttachedPolicies": []}],
            "list_role_policies": lambda RoleName: [{"PolicyNames": []}],
            "list_policies": lambda Scope: [{"Policies": [
                {"PolicyName": "wild", "Arn": OWN_ARN, "DefaultVersionId": "v1"},
                {"PolicyName": "unattached", "Arn": UNATTACHED_ARN, "DefaultVersionId": "v1"}]}],
        }
        return FakePaginator(table[op])

    def get_login_profile(self, UserName):
        if UserName == "intern":
            return {"LoginProfile": {}}
        raise AwsError("NoSuchEntity")

    def get_access_key_last_used(self, AccessKeyId):
        return {"AccessKeyLastUsed": {}}

    def get_policy(self, PolicyArn):
        self.get_policy_calls.append(PolicyArn)
        if self.throttle:
            raise AwsError("Throttling")
        if PolicyArn in self.denied_arns:
            raise AwsError("AccessDenied")
        return {"Policy": {"PolicyName": PolicyArn.rsplit("/", 1)[-1], "DefaultVersionId": "v1"}}

    def get_policy_version(self, PolicyArn, VersionId):
        doc = {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]} if "wild" in PolicyArn or "Admin" in PolicyArn \
            else {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::b/*"}]}
        return {"PolicyVersion": {"Document": doc}}


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.iam = FakeIAM()
        self.snap = cs.collect_snapshot(self.iam, "123456789012", now=NOW)

    def user(self, name):
        return next(u for u in self.snap["users"] if u["name"] == name)

    def test_pagination_collects_all_pages(self):
        self.assertEqual([u["name"] for u in self.snap["users"]], ["intern", "svc", "audit-user"])

    def test_users_mapped(self):
        self.assertTrue(self.user("intern")["console_access"])
        self.assertFalse(self.user("svc")["console_access"])
        self.assertFalse(self.user("intern")["mfa_enabled"])

    def test_attached_policies_keep_their_arn(self):
        self.assertEqual(self.user("intern")["attached_policies"], [{"name": "AdministratorAccess", "arn": ADMIN_ARN}])

    def test_key_is_masked_and_aged(self):
        key = self.user("svc")["access_keys"][0]
        self.assertEqual((key["id"], key["age_days"], key["last_used"]), ("***1234", 120, None))

    def test_service_linked_roles_skipped(self):
        self.assertEqual([r["name"] for r in self.snap["roles"]], ["app-role"])

    def test_aws_managed_and_customer_policy_documents_collected(self):
        by_arn = {p["arn"]: p for p in self.snap["policies"]}
        self.assertTrue(by_arn[ADMIN_ARN]["aws_managed"])
        self.assertIsNotNone(by_arn[ADMIN_ARN]["document"])
        self.assertFalse(by_arn[OWN_ARN]["aws_managed"])
        self.assertIn(UNATTACHED_ARN, by_arn)

    def test_each_policy_is_fetched_once(self):
        self.assertEqual(len(self.iam.get_policy_calls), len(set(self.iam.get_policy_calls)))

    def test_access_denied_policy_is_stored_as_unresolved(self):
        iam = FakeIAM()
        iam.denied_arns = {DENIED_ARN}
        snap = cs.collect_snapshot(iam, "123456789012", now=NOW)
        entry = next(p for p in snap["policies"] if p["arn"] == DENIED_ARN)
        self.assertIsNone(entry["document"])
        self.assertTrue(any("AccessDenied" in w for w in snap["collector_warnings"]))
        docs, unresolved = ia.effective_docs(snap, "user/audit-user")
        self.assertEqual(unresolved, ["SecurityAudit"])
        self.assertEqual(ia.evaluate(docs, "s3:GetObject", "x", unresolved)[0], "indeterminate")

    def test_other_errors_are_not_swallowed(self):
        class Boom(FakeIAM):
            def get_login_profile(self, UserName):
                raise RuntimeError("something else")
        with self.assertRaises(RuntimeError):
            cs.collect_snapshot(Boom(), "123456789012", now=NOW)
        throttled = FakeIAM()
        throttled.throttle = True
        with self.assertRaises(AwsError):
            cs.collect_snapshot(throttled, "123456789012", now=NOW)

    def test_snapshot_flows_into_the_audit(self):
        found = sorted(f["rule"] for f in ia.analyze(self.snap)["findings"])
        self.assertEqual(found, sorted(["ADMIN_ATTACHED_USER", "NO_MFA", "WILDCARD_ALL", "KEY_UNUSED", "KEY_OLD"]))


if __name__ == "__main__":
    unittest.main()
