#!/usr/bin/env python3
"""Collect an IAM snapshot (JSON) from an AWS account using read-only IAM calls.

EXPERIMENTAL: the mapping logic is unit-tested with a fake client (tests/test_collect_snapshot.py),
but this script has NOT been run against a live AWS account yet.

Usage (needs boto3 and read-only credentials, for example the SecurityAudit managed policy):
    python scripts/collect_snapshot.py --out lab/snapshots/live.json

The snapshot stores only the last 4 characters of access key IDs. Never commit real snapshots.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path


def _is_no_such_entity(exc):
    resp = getattr(exc, "response", None) or {}
    return resp.get("Error", {}).get("Code") == "NoSuchEntity"


def _paginate(iam, op, key, **kwargs):
    items = []
    for page in iam.get_paginator(op).paginate(**kwargs):
        items += page.get(key, [])
    return items


def _inline_docs(iam, list_op, get_op, name_arg, name):
    docs = []
    for pname in _paginate(iam, list_op, "PolicyNames", **{name_arg: name}):
        doc = getattr(iam, get_op)(**{name_arg: name, "PolicyName": pname})["PolicyDocument"]
        docs.append({"name": pname, "document": doc})
    return docs


def _collect_user(iam, name, now):
    try:
        iam.get_login_profile(UserName=name)
        console = True
    except Exception as exc:  # NoSuchEntity means the user has no console password
        if not _is_no_such_entity(exc):
            raise
        console = False
    mfa = bool(_paginate(iam, "list_mfa_devices", "MFADevices", UserName=name))
    keys = []
    for k in _paginate(iam, "list_access_keys", "AccessKeyMetadata", UserName=name):
        last = iam.get_access_key_last_used(AccessKeyId=k["AccessKeyId"])["AccessKeyLastUsed"].get("LastUsedDate")
        keys.append({"id": "***" + k["AccessKeyId"][-4:], "status": k["Status"],
                     "age_days": (now - k["CreateDate"]).days,
                     "last_used": last.isoformat() if last else None})
    return {"name": name, "console_access": console, "mfa_enabled": mfa,
            "groups": [g["GroupName"] for g in _paginate(iam, "list_groups_for_user", "Groups", UserName=name)],
            "attached_policies": [p["PolicyName"] for p in
                                  _paginate(iam, "list_attached_user_policies", "AttachedPolicies", UserName=name)],
            "inline_policies": _inline_docs(iam, "list_user_policies", "get_user_policy", "UserName", name),
            "access_keys": keys}


def collect_snapshot(iam, account_id, label="live", now=None):
    now = now or datetime.now(timezone.utc)
    snap = {"label": label, "account_id": account_id, "users": [], "groups": [], "roles": [], "policies": []}
    for u in _paginate(iam, "list_users", "Users"):
        snap["users"].append(_collect_user(iam, u["UserName"], now))
    for g in _paginate(iam, "list_groups", "Groups"):
        name = g["GroupName"]
        snap["groups"].append({
            "name": name,
            "attached_policies": [p["PolicyName"] for p in
                                  _paginate(iam, "list_attached_group_policies", "AttachedPolicies", GroupName=name)],
            "inline_policies": _inline_docs(iam, "list_group_policies", "get_group_policy", "GroupName", name)})
    for r in _paginate(iam, "list_roles", "Roles"):
        if r.get("Path", "").startswith("/aws-service-role/"):
            continue  # service-linked roles are managed by AWS
        name = r["RoleName"]
        snap["roles"].append({
            "name": name, "trust_policy": r["AssumeRolePolicyDocument"],
            "attached_policies": [p["PolicyName"] for p in
                                  _paginate(iam, "list_attached_role_policies", "AttachedPolicies", RoleName=name)],
            "inline_policies": _inline_docs(iam, "list_role_policies", "get_role_policy", "RoleName", name)})
    for p in _paginate(iam, "list_policies", "Policies", Scope="Local"):
        doc = iam.get_policy_version(PolicyArn=p["Arn"], VersionId=p["DefaultVersionId"])["PolicyVersion"]["Document"]
        snap["policies"].append({"name": p["PolicyName"], "document": doc})
    return snap


def main(argv=None):
    ap = argparse.ArgumentParser(description="Collect an IAM snapshot with read-only calls (experimental).")
    ap.add_argument("--out", required=True)
    ap.add_argument("--label", default="live")
    args = ap.parse_args(argv)
    try:
        import boto3
    except ImportError:
        print("boto3 is required: pip install -r requirements.txt", file=sys.stderr)
        return 2
    account = boto3.client("sts").get_caller_identity()["Account"]
    snap = collect_snapshot(boto3.client("iam"), account, label=args.label)
    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(snap, indent=2) + "\n", encoding="utf-8")
    print("Snapshot written to %s (do not commit it)." % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
