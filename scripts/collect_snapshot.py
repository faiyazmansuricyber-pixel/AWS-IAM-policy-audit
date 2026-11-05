#!/usr/bin/env python3
"""Collect an IAM snapshot (JSON) from an AWS account using read-only IAM calls.

EXPERIMENTAL: the mapping logic is unit-tested with a fake client (tests/test_collect_snapshot.py),
but this script has NOT been run against a live AWS account yet.

Usage (needs boto3 and read-only credentials, for example the SecurityAudit managed policy):
    python scripts/collect_snapshot.py --out lab/snapshots/live.json

What is collected: users (console access, MFA, access keys, groups, attached and inline policies),
groups, roles (trust policy, attached and inline policies; service-linked roles are skipped), and the
documents of every attached policy (AWS managed and customer managed, resolved by ARN) plus unattached
customer managed policies. If a policy document cannot be read (for example AccessDenied), the policy is
stored with document null and the audit treats it as unresolved.

Not collected: permission boundaries, SCPs, resource-based policies, role last-used data.
The snapshot stores only the last 4 characters of access key IDs and contains the account ID: do not commit it.
"""
import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"


def _error_code(exc):
    resp = getattr(exc, "response", None) or {}
    return resp.get("Error", {}).get("Code")


def _paginate(iam, op, key, **kwargs):
    items = []
    for page in iam.get_paginator(op).paginate(**kwargs):
        items += page.get(key, [])
    return items


def _refs(items):
    return [{"name": p["PolicyName"], "arn": p["PolicyArn"]} for p in items]


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
        if _error_code(exc) != "NoSuchEntity":
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
            "attached_policies": _refs(_paginate(iam, "list_attached_user_policies", "AttachedPolicies",
                                                 UserName=name)),
            "inline_policies": _inline_docs(iam, "list_user_policies", "get_user_policy", "UserName", name),
            "access_keys": keys}


def _fetch_policy(iam, arn, warnings):
    """Return a policy entry for the audit. document is None when it cannot be read."""
    entry = {"arn": arn, "aws_managed": arn.startswith(AWS_MANAGED_PREFIX), "name": arn.rsplit("/", 1)[-1],
             "document": None}
    try:
        meta = iam.get_policy(PolicyArn=arn)["Policy"]
        entry["name"] = meta["PolicyName"]
        entry["document"] = iam.get_policy_version(PolicyArn=arn, VersionId=meta["DefaultVersionId"])[
            "PolicyVersion"]["Document"]
    except Exception as exc:
        if _error_code(exc) not in ("AccessDenied", "AccessDeniedException"):
            raise
        warnings.append("Could not read policy %s (AccessDenied); it will be treated as unresolved." % arn)
    return entry


def collect_snapshot(iam, account_id, label="live", now=None):
    now = now or datetime.now(timezone.utc)
    warnings = []
    snap = {"label": label, "account_id": account_id, "users": [], "groups": [], "roles": [], "policies": [],
            "collector_warnings": warnings}
    for u in _paginate(iam, "list_users", "Users"):
        snap["users"].append(_collect_user(iam, u["UserName"], now))
    for g in _paginate(iam, "list_groups", "Groups"):
        name = g["GroupName"]
        snap["groups"].append({
            "name": name,
            "attached_policies": _refs(_paginate(iam, "list_attached_group_policies", "AttachedPolicies",
                                                 GroupName=name)),
            "inline_policies": _inline_docs(iam, "list_group_policies", "get_group_policy", "GroupName", name)})
    for r in _paginate(iam, "list_roles", "Roles"):
        if r.get("Path", "").startswith("/aws-service-role/"):
            continue  # service-linked roles are managed by AWS
        name = r["RoleName"]
        snap["roles"].append({
            "name": name, "trust_policy": r["AssumeRolePolicyDocument"],
            "attached_policies": _refs(_paginate(iam, "list_attached_role_policies", "AttachedPolicies",
                                                 RoleName=name)),
            "inline_policies": _inline_docs(iam, "list_role_policies", "get_role_policy", "RoleName", name)})
    arns = []  # every attached policy plus all customer managed policies, each fetched once
    for kind in ("users", "groups", "roles"):
        for e in snap[kind]:
            arns += [ref["arn"] for ref in e["attached_policies"]]
    arns += [p["Arn"] for p in _paginate(iam, "list_policies", "Policies", Scope="Local")]
    cache = {}
    for arn in arns:
        if arn not in cache:
            cache[arn] = _fetch_policy(iam, arn, warnings)
    snap["policies"] = list(cache.values())
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
    for w in snap["collector_warnings"]:
        print("WARNING:", w, file=sys.stderr)
    print("Snapshot written to %s (do not commit it)." % args.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
