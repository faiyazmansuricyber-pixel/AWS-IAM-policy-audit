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


class NoSuchEntity(Exception):
    def __init__(self):
        self.response = {"Error": {"Code": "NoSuchEntity"}}


class FakePaginator:
    def __init__(self, fn):
        self.fn = fn

    def paginate(self, **kw):
        return [self.fn(**kw)]


class FakeIAM:
    """Mimics the few IAM calls used by the collector."""

    def get_paginator(self, op):
        table = {
            "list_users": lambda: {"Users": [{"UserName": "intern"}, {"UserName": "svc"}]},
            "list_mfa_devices": lambda UserName: {"MFADevices": []},
            "list_access_keys": lambda UserName: {"AccessKeyMetadata": (
                [{"AccessKeyId": "FAKEKEYIDFAKEFAKE1234", "Status": "Active", "CreateDate": NOW - timedelta(days=120)}]
                if UserName == "svc" else [])},
            "list_groups_for_user": lambda UserName: {"Groups": []},
            "list_attached_user_policies": lambda UserName: {"AttachedPolicies": (
                [{"PolicyName": "AdministratorAccess"}] if UserName == "intern" else [{"PolicyName": "wild"}])},
            "list_user_policies": lambda UserName: {"PolicyNames": []},
            "list_groups": lambda: {"Groups": []},
            "list_roles": lambda: {"Roles": [
                {"RoleName": "app-role", "Path": "/", "AssumeRolePolicyDocument": {"Statement": []}},
                {"RoleName": "AWSServiceRoleForX", "Path": "/aws-service-role/x/", "AssumeRolePolicyDocument": {}}]},
            "list_attached_role_policies": lambda RoleName: {"AttachedPolicies": []},
            "list_role_policies": lambda RoleName: {"PolicyNames": []},
            "list_policies": lambda Scope: {"Policies": [{"PolicyName": "wild", "Arn": "arn:x", "DefaultVersionId": "v1"}]},
        }
        return FakePaginator(table[op])

    def get_login_profile(self, UserName):
        if UserName == "intern":
            return {"LoginProfile": {}}
        raise NoSuchEntity()

    def get_access_key_last_used(self, AccessKeyId):
        return {"AccessKeyLastUsed": {}}

    def get_policy_version(self, PolicyArn, VersionId):
        return {"PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}}


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.snap = cs.collect_snapshot(FakeIAM(), "123456789012", now=NOW)

    def test_users_mapped(self):
        users = {u["name"]: u for u in self.snap["users"]}
        self.assertTrue(users["intern"]["console_access"])
        self.assertFalse(users["svc"]["console_access"])
        self.assertFalse(users["intern"]["mfa_enabled"])
        self.assertEqual(users["intern"]["attached_policies"], ["AdministratorAccess"])

    def test_key_is_masked_and_aged(self):
        key = self.snap["users"][1]["access_keys"][0]
        self.assertEqual(key["id"], "***1234")
        self.assertEqual(key["age_days"], 120)
        self.assertIsNone(key["last_used"])

    def test_service_linked_roles_skipped(self):
        self.assertEqual([r["name"] for r in self.snap["roles"]], ["app-role"])

    def test_customer_policy_document_collected(self):
        self.assertEqual(self.snap["policies"][0]["name"], "wild")

    def test_snapshot_flows_into_the_audit(self):
        found = sorted(f["rule"] for f in ia.analyze(self.snap)["findings"])
        self.assertEqual(found, sorted(["ADMIN_ATTACHED_USER", "NO_MFA", "WILDCARD_ALL", "KEY_UNUSED", "KEY_OLD"]))

    def test_other_errors_are_not_swallowed(self):
        class Boom(FakeIAM):
            def get_login_profile(self, UserName):
                raise RuntimeError("access denied")
        with self.assertRaises(RuntimeError):
            cs.collect_snapshot(Boom(), "123456789012", now=NOW)


if __name__ == "__main__":
    unittest.main()
