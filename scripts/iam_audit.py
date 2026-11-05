#!/usr/bin/env python3
"""IAM audit: rule-based checks on an IAM snapshot (JSON), access verification, and before/after comparison.

Works offline on a snapshot file, so results can be reproduced without AWS credentials.
Snapshot format: see lab/snapshots/before.json. A snapshot can be produced from a real account
with scripts/collect_snapshot.py (experimental, see README).

Commands:
  audit          Run the rules on a snapshot and write findings.json and audit_report.md
  verify-access  Check expected results with a small policy evaluator (allow / deny / indeterminate)
  compare        Compare open findings before and after fixes

Scope: identity-based policies only. Not evaluated: permission boundaries, SCPs, resource-based
policies, session policies. The evaluator returns INDETERMINATE (never a silent allow or deny) when a
matching statement has a Condition or when an attached policy document is unresolved.
"""
import argparse
import fnmatch
import json
import re
import sys
from pathlib import Path

SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]
SEV_RANK = {s: i for i, s in enumerate(SEVERITIES)}  # lower number = worse
ADMIN_POLICIES = {"AdministratorAccess"}
ADMIN_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
AWS_MANAGED_PREFIX = "arn:aws:iam::aws:policy/"
KEY_MAX_AGE_DAYS = 90
APPROVABLE = {"ADMIN_ATTACHED_USER", "ADMIN_ATTACHED_ROLE", "ADMIN_ATTACHED_GROUP", "PRIVILEGED_GROUP_MEMBER"}
PRIV_ESC = {
    "iam:passrole", "iam:createaccesskey", "iam:createloginprofile", "iam:updateloginprofile",
    "iam:attachuserpolicy", "iam:attachrolepolicy", "iam:attachgrouppolicy",
    "iam:putuserpolicy", "iam:putrolepolicy", "iam:putgrouppolicy",
    "iam:createpolicyversion", "iam:setdefaultpolicyversion", "iam:updateassumerolepolicy",
}

RULES = {
    "WILDCARD_ALL": ("Critical", "Policy allows all actions on all resources",
                     "Replace with the specific actions and resources the identity needs."),
    "WILDCARD_SERVICE": ("High", "Service-wide wildcard on all resources",
                         "Limit to the needed actions and to specific resource ARNs."),
    "WILDCARD_ACTION": ("Medium", "Wildcard action on specific resources",
                        "List only the actions that are needed."),
    "PRIV_ESC": ("High", "Permission that can be used to escalate privileges, on all resources",
                 "Remove it, or restrict it to specific resources and add conditions. "
                 "Note: only single actions are checked, not combinations."),
    "NOT_ACTION_ALLOW": ("Medium", "Allow statement uses NotAction",
                         "Rewrite as an explicit list of allowed actions."),
    "ADMIN_ATTACHED_USER": ("High", "AdministratorAccess attached directly to a user",
                            "Remove it and grant a scoped policy, preferably through a group."),
    "ADMIN_ATTACHED_ROLE": ("High", "AdministratorAccess attached to a role",
                            "Replace with a scoped policy for what the workload needs."),
    "ADMIN_ATTACHED_GROUP": ("High", "AdministratorAccess attached to a group",
                             "Confirm this is an approved admin group, keep membership minimal, require MFA, "
                             "and record the approval in approved_admins."),
    "PRIVILEGED_GROUP_MEMBER": ("Medium", "User inherits administrator access through a group",
                                "Confirm the user needs admin access, require MFA, and record the approval "
                                "in approved_admins."),
    "NO_MFA": ("High", "Console user without MFA", "Enable MFA for the user."),
    "KEY_UNUSED": ("Medium", "Active access key that has never been used",
                   "Deactivate, then delete the key."),
    "KEY_OLD": ("Medium", "Active access key older than %d days" % KEY_MAX_AGE_DAYS,
                "Rotate or delete the key."),
    "TRUST_PUBLIC": ("Critical", "Role trust policy allows any principal",
                     "Restrict the Principal to specific identities and add conditions."),
    "TRUST_CROSS_ACCOUNT": ("High", "Role trust policy allows another AWS account",
                            "Confirm the account is trusted; add an ExternalId or other conditions."),
    "TRUST_FEDERATED": ("Low", "Role trusts a federated identity provider",
                        "Review conditions such as audience and subject."),
}


# ---------- small helpers (tolerate malformed input) ----------

def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def statements(doc):
    if not isinstance(doc, dict):
        return []
    return [s for s in as_list(doc.get("Statement")) if isinstance(s, dict)]


def ref_name(ref):
    return ref["name"] if isinstance(ref, dict) else ref


def ref_arn(ref):
    return ref.get("arn") if isinstance(ref, dict) else None


def is_admin(ref):
    arn = ref_arn(ref)
    return ref_name(ref) in ADMIN_POLICIES and (arn is None or arn.startswith(AWS_MANAGED_PREFIX))


def make_finding(rule, rtype, resource, detail, severity=None):
    sev, title, fix = RULES[rule]
    return {"rule": rule, "severity": severity or sev, "status": "open", "resource_type": rtype,
            "resource": resource, "title": title, "detail": detail, "remediation": fix}


# ---------- rule checks ----------

def check_policy_document(label, doc, attached_to=None):
    """Return findings for one policy document. label is e.g. 'policy/NAME'."""
    fired = {}
    for i, st in enumerate(statements(doc)):
        if st.get("Effect") != "Allow":
            continue
        sid = st.get("Sid") or "statement-%d" % (i + 1)
        actions, resources = as_list(st.get("Action")), as_list(st.get("Resource"))
        if st.get("NotAction") is not None:
            fired.setdefault("NOT_ACTION_ALLOW", []).append(sid)
        if "*" in actions and "*" in resources:
            fired.setdefault("WILDCARD_ALL", []).append(sid)
            continue
        if "*" in actions:
            fired.setdefault("WILDCARD_ACTION", []).append(sid)
            continue
        esc = [a for a in actions if isinstance(a, str) and (a.lower() in PRIV_ESC or a.lower() == "iam:*")]
        if esc and "*" in resources:
            fired.setdefault("PRIV_ESC", []).append("%s (%s)" % (sid, ", ".join(esc)))
        elif any(isinstance(a, str) and a.endswith(":*") for a in actions) and "*" in resources:
            fired.setdefault("WILDCARD_SERVICE", []).append(sid)
    out = []
    for rule, sids in fired.items():
        detail = "Statements: %s." % ", ".join(sids)
        if attached_to:
            detail += " Attached to: %s." % ", ".join(attached_to)
        out.append(make_finding(rule, "policy", label, detail))
    return out


def check_trust_policy(role_name, doc, own_account):
    """Flag trust policies that allow any principal, another account, or a federated provider.
    The severity is NOT lowered when a Condition exists: whether a condition really restricts access
    needs manual review."""
    fired = {}
    for st in statements(doc):
        if st.get("Effect") != "Allow":
            continue
        has_cond = bool(st.get("Condition"))
        principal = st.get("Principal")
        if principal == "*":
            fired["TRUST_PUBLIC"] = has_cond
            continue
        if not isinstance(principal, dict):
            continue
        for p in as_list(principal.get("AWS")) + as_list(principal.get("Service")):
            if p == "*":
                fired["TRUST_PUBLIC"] = has_cond
                continue
            m = re.search(r"\b(\d{12})\b", p) if isinstance(p, str) else None
            if m and m.group(1) != own_account:
                fired["TRUST_CROSS_ACCOUNT"] = has_cond
        if as_list(principal.get("Federated")):
            fired.setdefault("TRUST_FEDERATED", has_cond)
    out = []
    for rule, has_cond in fired.items():
        detail = "Trust policy principal check failed."
        if has_cond:
            detail += " A Condition is present; manual review needed (severity not lowered)."
        out.append(make_finding(rule, "role", "role/" + role_name, detail))
    return out


def check_user(user):
    out = []
    name = "user/" + user["name"]
    if any(is_admin(r) for r in user.get("attached_policies", [])):
        out.append(make_finding("ADMIN_ATTACHED_USER", "user", name,
                                "Policy AdministratorAccess is attached directly."))
    if user.get("console_access") and not user.get("mfa_enabled"):
        out.append(make_finding("NO_MFA", "user", name,
                                "Console access is enabled and no MFA device is registered."))
    for k in user.get("access_keys", []):
        if k.get("status") != "Active":
            continue
        kid = k.get("id", "key")
        if not k.get("last_used"):
            out.append(make_finding("KEY_UNUSED", "access_key", "%s/%s" % (name, kid),
                                    "Key is Active and has no recorded use."))
        if (k.get("age_days") or 0) > KEY_MAX_AGE_DAYS:
            out.append(make_finding("KEY_OLD", "access_key", "%s/%s" % (name, kid),
                                    "Key age is %s days." % k.get("age_days")))
    return out


def analyze(snapshot):
    findings, analyzed = [], 0
    users, groups, roles = snapshot.get("users", []), snapshot.get("groups", []), snapshot.get("roles", [])
    attached = {}
    for kind, items in (("user", users), ("group", groups), ("role", roles)):
        for e in items:
            for ref in e.get("attached_policies", []):
                attached.setdefault(ref_name(ref), []).append("%s/%s" % (kind, e["name"]))
    for p in snapshot.get("policies", []):
        analyzed += 1
        if p.get("aws_managed") and p["name"] in ADMIN_POLICIES:
            continue  # covered by the ADMIN_ATTACHED_* rules
        findings += check_policy_document("policy/" + p["name"], p.get("document"), attached.get(p["name"]))
    for kind, items in (("user", users), ("group", groups), ("role", roles)):
        for e in items:
            for ip in e.get("inline_policies", []):
                analyzed += 1
                findings += check_policy_document("%s/%s inline:%s" % (kind, e["name"], ip["name"]),
                                                  ip.get("document"))
    for u in users:
        findings += check_user(u)
    admin_groups = {g["name"] for g in groups if any(is_admin(r) for r in g.get("attached_policies", []))}
    for gname in sorted(admin_groups):
        members = [u["name"] for u in users if gname in u.get("groups", [])]
        findings.append(make_finding("ADMIN_ATTACHED_GROUP", "group", "group/" + gname,
                                     "AdministratorAccess is attached to the group. Members: %s." %
                                     (", ".join(members) or "none")))
    for u in users:
        via = [g for g in u.get("groups", []) if g in admin_groups]
        if via:
            findings.append(make_finding("PRIVILEGED_GROUP_MEMBER", "user", "user/" + u["name"],
                                         "Inherits AdministratorAccess through group(s): %s." % ", ".join(via)))
    for r in roles:
        if any(is_admin(x) for x in r.get("attached_policies", [])):
            findings.append(make_finding("ADMIN_ATTACHED_ROLE", "role", "role/" + r["name"],
                                         "Policy AdministratorAccess is attached."))
        findings += check_trust_policy(r["name"], r.get("trust_policy"), snapshot.get("account_id", ""))
    approved = set(snapshot.get("approved_admins", []))
    for f in findings:
        if f["rule"] in APPROVABLE and f["resource"] in approved:
            f["status"] = "accepted"
    findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["resource"], f["rule"]))
    open_f = [f for f in findings if f["status"] == "open"]
    counts = {s: sum(1 for f in open_f if f["severity"] == s) for s in SEVERITIES}
    summary = {"label": snapshot.get("label", ""), "users": len(users), "groups": len(groups),
               "roles": len(roles), "policies_analyzed": analyzed, "findings_total": len(open_f),
               "accepted_total": len(findings) - len(open_f), "by_severity": counts}
    return {"summary": summary, "findings": findings}


def redact(text):
    """Replace 12-digit numbers (AWS account IDs) in any output."""
    return re.sub(r"\b\d{12}\b", "XXXXXXXXXXXX", text)


def render_markdown(result):
    s = result["summary"]
    open_f = [f for f in result["findings"] if f["status"] == "open"]
    acc_f = [f for f in result["findings"] if f["status"] == "accepted"]
    lines = ["# IAM Audit Report (%s)" % s["label"], "",
             "| Item | Count |", "|---|---|",
             "| Users | %d |" % s["users"], "| Groups | %d |" % s["groups"], "| Roles | %d |" % s["roles"],
             "| Policies analyzed | %d |" % s["policies_analyzed"],
             "| **Open findings** | **%d** |" % s["findings_total"]]
    lines += ["| %s | %d |" % (sev, s["by_severity"][sev]) for sev in SEVERITIES]
    lines += ["| Accepted (approved administrators) | %d |" % s["accepted_total"], "", "## Open findings", ""]
    if not open_f:
        lines.append("No open findings.")
    else:
        lines += ["| # | Severity | Rule | Resource | Detail |", "|---|---|---|---|---|"]
        for i, f in enumerate(open_f, 1):
            lines.append("| %d | %s | %s | %s | %s |" % (i, f["severity"], f["rule"], f["resource"], f["detail"]))
        lines += ["", "## Remediation", ""]
        for i, f in enumerate(open_f, 1):
            lines.append("%d. **%s** (%s): %s" % (i, f["title"], f["resource"], f["remediation"]))
    if acc_f:
        lines += ["", "## Accepted (listed in approved_admins)", "",
                  "These are visible on purpose: administrator access that was reviewed and approved.", ""]
        lines += ["- %s: %s (%s)" % (f["severity"], f["resource"], f["rule"]) for f in acc_f]
    return redact("\n".join(lines) + "\n")


# ---------- access verification (small policy evaluator) ----------

def find_policy(snapshot, ref):
    arn, name = ref_arn(ref), ref_name(ref)
    for p in snapshot.get("policies", []):
        if (arn and p.get("arn") == arn) or (not arn and p["name"] == name):
            return p
    return None


def policy_doc(snapshot, ref):
    p = find_policy(snapshot, ref)
    if p is not None and p.get("document"):
        return p["document"]
    if p is None and is_admin(ref):
        return ADMIN_DOC  # fallback for hand-written snapshots
    return None


def effective_docs(snapshot, principal):
    """principal is 'user/NAME' or 'role/NAME'. Returns (documents, unresolved_policy_names)."""
    kind, name = principal.split("/", 1)
    ent = next((e for e in snapshot.get(kind + "s", []) if e["name"] == name), None)
    if ent is None:
        raise KeyError("principal not found: " + principal)
    refs = list(ent.get("attached_policies", []))
    docs = [ip.get("document") for ip in ent.get("inline_policies", [])]
    if kind == "user":
        for gname in ent.get("groups", []):
            g = next((x for x in snapshot.get("groups", []) if x["name"] == gname), None)
            if g:
                refs += g.get("attached_policies", [])
                docs += [ip.get("document") for ip in g.get("inline_policies", [])]
    unresolved = []
    for r in refs:
        d = policy_doc(snapshot, r)
        if d:
            docs.append(d)
        else:
            unresolved.append(ref_name(r))
    return docs, unresolved


def _match(patterns, value, ci=False):
    for pat in patterns:
        if not isinstance(pat, str):
            continue
        if ci and fnmatch.fnmatchcase(value.lower(), pat.lower()):
            return True
        if not ci and fnmatch.fnmatchcase(value, pat):
            return True
    return False


def _statement_matches(st, action, resource):
    if st.get("NotAction") is not None:
        a = not _match(as_list(st["NotAction"]), action, ci=True)
    else:
        a = _match(as_list(st.get("Action")), action, ci=True)
    if st.get("NotResource") is not None:
        r = not _match(as_list(st["NotResource"]), resource)
    else:
        r = _match(as_list(st.get("Resource")), resource)
    return a and r


def evaluate(docs, action, resource, unresolved=()):
    """Return (result, reason). result is 'allow', 'deny' or 'indeterminate'.
    Statements with a Condition are never treated as definite: they can make the result indeterminate."""
    allow_def = allow_cond = deny_def = deny_cond = False
    for doc in docs:
        for st in statements(doc):
            if not _statement_matches(st, action, resource):
                continue
            cond = bool(st.get("Condition"))
            if st.get("Effect") == "Deny":
                deny_def, deny_cond = deny_def or not cond, deny_cond or cond
            elif st.get("Effect") == "Allow":
                allow_def, allow_cond = allow_def or not cond, allow_cond or cond
    if deny_def:
        return "deny", "explicit deny"
    if allow_def:
        if deny_cond:
            return "indeterminate", "a conditional Deny may apply"
        if unresolved:
            return "indeterminate", "unresolved policies: %s" % ", ".join(unresolved)
        return "allow", "explicit allow"
    if allow_cond:
        return "indeterminate", "a conditional Allow may apply"
    if unresolved:
        return "indeterminate", "unresolved policies: %s" % ", ".join(unresolved)
    return "deny", "implicit deny"


def run_access_tests(snapshot, tests):
    results = []
    for t in tests:
        docs, unresolved = effective_docs(snapshot, t["principal"])
        got, reason = evaluate(docs, t["action"], t["resource"], unresolved)
        r = dict(t)
        r.update({"got": got, "reason": reason, "passed": got == t["expect"], "unresolved_policies": unresolved})
        results.append(r)
    return results


def render_access_markdown(label, results):
    lines = ["# Access verification (%s)" % label, "",
             "| Principal | Action | Resource | Expected | Got | Reason | Result |", "|---|---|---|---|---|---|---|"]
    for r in results:
        verdict = "PASS" if r["passed"] else ("INDETERMINATE" if r["got"] == "indeterminate" else "FAIL")
        lines.append("| %s | %s | %s | %s | %s | %s | %s |" % (
            r["principal"], r["action"], r["resource"], r["expect"], r["got"], r["reason"], verdict))
    passed = sum(1 for r in results if r["passed"])
    lines += ["", "%d of %d checks passed." % (passed, len(results)), "",
              "Scope: identity-based policies only. Permission boundaries, SCPs and resource-based policies are "
              "not evaluated. A check is INDETERMINATE when a matching statement has a Condition or an attached "
              "policy document is unresolved."]
    return redact("\n".join(lines) + "\n")


# ---------- compare ----------

def compare(before, after):
    opened = lambda res: [f for f in res["findings"] if f["status"] == "open"]
    key = lambda f: (f["rule"], f["resource"])
    b, a = {key(f): f for f in opened(before)}, {key(f): f for f in opened(after)}
    resolved = [b[k] for k in b if k not in a]
    new = [a[k] for k in a if k not in b]
    remaining = [a[k] for k in a if k in b]
    lines = ["# Before and after comparison (open findings)", "", "| Severity | Before | After |", "|---|---|---|"]
    lines += ["| %s | %d | %d |" % (s, before["summary"]["by_severity"][s], after["summary"]["by_severity"][s])
              for s in SEVERITIES]
    lines += ["| **Total open** | **%d** | **%d** |" % (before["summary"]["findings_total"],
                                                         after["summary"]["findings_total"]),
              "| Accepted (approved administrators) | %d | %d |" % (before["summary"]["accepted_total"],
                                                                    after["summary"]["accepted_total"]),
              "", "Resolved: %d | Still present: %d | New: %d" % (len(resolved), len(remaining), len(new)), ""]
    for title, items in (("Resolved", resolved), ("Still present", remaining), ("New", new)):
        lines.append("## " + title)
        lines += ["- %s: %s (%s)" % (f["severity"], f["resource"], f["rule"]) for f in items] or ["- none"]
        lines.append("")
    return redact("\n".join(lines))


def load(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    a = sub.add_parser("audit")
    a.add_argument("--input", required=True)
    a.add_argument("--outdir", required=True)
    a.add_argument("--fail-on", choices=[s.lower() for s in SEVERITIES[:4]])
    v = sub.add_parser("verify-access")
    v.add_argument("--input", required=True)
    v.add_argument("--tests", required=True)
    v.add_argument("--section", required=True)
    v.add_argument("--out")
    c = sub.add_parser("compare")
    c.add_argument("--before", required=True)
    c.add_argument("--after", required=True)
    c.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    if args.cmd == "audit":
        result = analyze(load(args.input))
        out = Path(args.outdir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "findings.json").write_text(redact(json.dumps(result, indent=2)) + "\n", encoding="utf-8")
        (out / "audit_report.md").write_text(render_markdown(result), encoding="utf-8")
        s = result["summary"]
        print("%s: %d open findings %s, %d accepted" % (s["label"], s["findings_total"], s["by_severity"],
                                                        s["accepted_total"]))
        if args.fail_on:
            limit = SEV_RANK[args.fail_on.capitalize()]
            if any(f["status"] == "open" and SEV_RANK[f["severity"]] <= limit for f in result["findings"]):
                return 1
        return 0
    if args.cmd == "verify-access":
        snap = load(args.input)
        results = run_access_tests(snap, load(args.tests)[args.section])
        text = render_access_markdown(snap.get("label", ""), results)
        print(text)
        if args.out:
            Path(args.out).parent.mkdir(parents=True, exist_ok=True)
            Path(args.out).write_text(text, encoding="utf-8")
        return 0 if all(r["passed"] for r in results) else 1
    if args.cmd == "compare":
        text = compare(analyze(load(args.before)), analyze(load(args.after)))
        Path(args.out).parent.mkdir(parents=True, exist_ok=True)
        Path(args.out).write_text(text, encoding="utf-8")
        print(text)
        return 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
