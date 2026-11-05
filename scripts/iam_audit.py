#!/usr/bin/env python3
"""IAM audit: rule-based checks on an IAM snapshot (JSON), access verification, and before/after comparison.

Works offline on a snapshot file, so results can be reproduced without AWS credentials.
Snapshot format: see lab/snapshots/before.json. A snapshot can be produced from a real account
with scripts/collect_snapshot.py (experimental, see README).

Commands:
  audit          Run the rules on a snapshot and write findings.json and audit_report.md
  verify-access  Check that expected Allow/Deny results hold (a small policy evaluator)
  compare        Compare findings before and after fixes

Known limits: Conditions are not evaluated; NotAction/NotResource statements are skipped by the
access evaluator; AWS managed policies other than AdministratorAccess are treated as unknown.
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
KEY_MAX_AGE_DAYS = 90
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
                 "Remove it, or restrict it to specific resources and add conditions."),
    "NOT_ACTION_ALLOW": ("Medium", "Allow statement uses NotAction",
                         "Rewrite as an explicit list of allowed actions."),
    "ADMIN_ATTACHED_USER": ("High", "AdministratorAccess attached directly to a user",
                            "Remove it and grant a scoped policy, preferably through a group."),
    "ADMIN_ATTACHED_ROLE": ("High", "AdministratorAccess attached to a role",
                            "Replace with a scoped policy for what the workload needs."),
    "NO_MFA": ("High", "Console user without MFA", "Enable MFA for the user."),
    "KEY_UNUSED": ("Medium", "Active access key that has never been used",
                   "Deactivate, then delete the key."),
    "KEY_OLD": ("Medium", "Active access key older than %d days" % KEY_MAX_AGE_DAYS,
                "Rotate or delete the key."),
    "TRUST_PUBLIC": ("Critical", "Role trust policy allows any principal",
                     "Restrict the Principal to specific identities and add conditions."),
    "TRUST_CROSS_ACCOUNT": ("High", "Role trust policy allows another AWS account",
                            "Confirm the account is trusted; add an ExternalId or other conditions."),
}


def as_list(v):
    if v is None:
        return []
    return v if isinstance(v, list) else [v]


def make_finding(rule, rtype, resource, detail, severity=None):
    sev, title, fix = RULES[rule]
    return {"rule": rule, "severity": severity or sev, "resource_type": rtype, "resource": resource,
            "title": title, "detail": detail, "remediation": fix}


def check_policy_document(label, doc, attached_to=None):
    """Return findings for one policy document. label is e.g. 'policy/NAME'."""
    fired = {}
    for i, st in enumerate(as_list((doc or {}).get("Statement"))):
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
        esc = [a for a in actions if a.lower() in PRIV_ESC or a.lower() == "iam:*"]
        if esc and "*" in resources:
            fired.setdefault("PRIV_ESC", []).append("%s (%s)" % (sid, ", ".join(esc)))
        elif any(a.endswith(":*") for a in actions) and "*" in resources:
            fired.setdefault("WILDCARD_SERVICE", []).append(sid)
    out = []
    for rule, sids in fired.items():
        detail = "Statements: %s." % ", ".join(sids)
        if attached_to:
            detail += " Attached to: %s." % ", ".join(attached_to)
        out.append(make_finding(rule, "policy", label, detail))
    return out


def check_trust_policy(role_name, doc, own_account):
    """Flag trust policies that allow any principal or a different AWS account."""
    fired = {}
    for st in as_list((doc or {}).get("Statement")):
        if st.get("Effect") != "Allow":
            continue
        has_cond = bool(st.get("Condition"))
        principal = st.get("Principal")
        if principal == "*":
            values = ["*"]
        elif isinstance(principal, dict):
            values = as_list(principal.get("AWS"))
        else:
            values = []
        for p in values:
            if p == "*":
                fired["TRUST_PUBLIC"] = ("High" if has_cond else "Critical", has_cond)
                continue
            m = re.search(r"\b(\d{12})\b", p)
            if m and m.group(1) != own_account:
                fired["TRUST_CROSS_ACCOUNT"] = ("Medium" if has_cond else "High", has_cond)
    out = []
    for rule, (sev, has_cond) in fired.items():
        detail = "Trust policy principal check failed (conditions present: %s)." % ("yes" if has_cond else "no")
        out.append(make_finding(rule, "role", "role/" + role_name, detail, severity=sev))
    return out


def check_user(user):
    out = []
    name = "user/" + user["name"]
    if "AdministratorAccess" in user.get("attached_policies", []):
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
    attached = {}
    for kind in ("users", "groups", "roles"):
        for e in snapshot.get(kind, []):
            for p in e.get("attached_policies", []):
                attached.setdefault(p, []).append("%s/%s" % (kind[:-1], e["name"]))
    for p in snapshot.get("policies", []):
        analyzed += 1
        findings += check_policy_document("policy/" + p["name"], p.get("document"), attached.get(p["name"]))
    for kind in ("users", "groups", "roles"):
        for e in snapshot.get(kind, []):
            for ip in e.get("inline_policies", []):
                analyzed += 1
                findings += check_policy_document("%s/%s inline:%s" % (kind[:-1], e["name"], ip["name"]),
                                                  ip.get("document"))
    for u in snapshot.get("users", []):
        findings += check_user(u)
    for r in snapshot.get("roles", []):
        if "AdministratorAccess" in r.get("attached_policies", []):
            findings.append(make_finding("ADMIN_ATTACHED_ROLE", "role", "role/" + r["name"],
                                         "Policy AdministratorAccess is attached."))
        findings += check_trust_policy(r["name"], r.get("trust_policy"), snapshot.get("account_id", ""))
    findings.sort(key=lambda f: (SEV_RANK[f["severity"]], f["resource"], f["rule"]))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}
    summary = {"label": snapshot.get("label", ""), "users": len(snapshot.get("users", [])),
               "groups": len(snapshot.get("groups", [])), "roles": len(snapshot.get("roles", [])),
               "policies_analyzed": analyzed, "findings_total": len(findings), "by_severity": counts}
    return {"summary": summary, "findings": findings}


def redact(text):
    """Replace 12-digit numbers (AWS account IDs) in any output."""
    return re.sub(r"\b\d{12}\b", "XXXXXXXXXXXX", text)


def render_markdown(result):
    s = result["summary"]
    lines = ["# IAM Audit Report (%s)" % s["label"], "",
             "| Item | Count |", "|---|---|",
             "| Users | %d |" % s["users"], "| Groups | %d |" % s["groups"], "| Roles | %d |" % s["roles"],
             "| Policies analyzed | %d |" % s["policies_analyzed"],
             "| **Findings** | **%d** |" % s["findings_total"]]
    lines += ["| %s | %d |" % (sev, s["by_severity"][sev]) for sev in SEVERITIES]
    lines += ["", "## Findings", ""]
    if not result["findings"]:
        lines.append("No findings.")
    else:
        lines += ["| # | Severity | Rule | Resource | Detail |", "|---|---|---|---|---|"]
        for i, f in enumerate(result["findings"], 1):
            lines.append("| %d | %s | %s | %s | %s |" % (i, f["severity"], f["rule"], f["resource"], f["detail"]))
        lines += ["", "## Remediation", ""]
        for i, f in enumerate(result["findings"], 1):
            lines.append("%d. **%s** (%s): %s" % (i, f["title"], f["resource"], f["remediation"]))
    return redact("\n".join(lines) + "\n")


# ---------- access verification (small policy evaluator) ----------

def _policy_doc(snapshot, name):
    if name in ADMIN_POLICIES:
        return ADMIN_DOC
    for p in snapshot.get("policies", []):
        if p["name"] == name:
            return p.get("document")
    return None


def effective_docs(snapshot, principal):
    """principal is 'user/NAME' or 'role/NAME'. Returns (documents, unknown_policy_names)."""
    kind, name = principal.split("/", 1)
    ent = next((e for e in snapshot.get(kind + "s", []) if e["name"] == name), None)
    if ent is None:
        raise KeyError("principal not found: " + principal)
    names = list(ent.get("attached_policies", []))
    docs = [ip.get("document") for ip in ent.get("inline_policies", [])]
    if kind == "user":
        for gname in ent.get("groups", []):
            g = next((x for x in snapshot.get("groups", []) if x["name"] == gname), None)
            if g:
                names += g.get("attached_policies", [])
                docs += [ip.get("document") for ip in g.get("inline_policies", [])]
    unknown = []
    for n in names:
        d = _policy_doc(snapshot, n)
        if d:
            docs.append(d)
        else:
            unknown.append(n)
    return docs, unknown


def _match(patterns, value, ci=False):
    for pat in patterns:
        if ci and fnmatch.fnmatchcase(value.lower(), pat.lower()):
            return True
        if not ci and fnmatch.fnmatchcase(value, pat):
            return True
    return False


def evaluate(docs, action, resource):
    """Return True if allowed. Explicit Deny wins. Statements with Condition/NotAction/NotResource are skipped."""
    allowed = False
    for doc in docs:
        for st in as_list((doc or {}).get("Statement")):
            if st.get("Condition") or st.get("NotAction") is not None or st.get("NotResource") is not None:
                continue
            if _match(as_list(st.get("Action")), action, ci=True) and _match(as_list(st.get("Resource")), resource):
                if st.get("Effect") == "Deny":
                    return False
                if st.get("Effect") == "Allow":
                    allowed = True
    return allowed


def run_access_tests(snapshot, tests):
    results = []
    for t in tests:
        docs, unknown = effective_docs(snapshot, t["principal"])
        got = "allow" if evaluate(docs, t["action"], t["resource"]) else "deny"
        r = dict(t)
        r.update({"got": got, "passed": got == t["expect"], "unknown_policies": unknown})
        results.append(r)
    return results


def render_access_markdown(label, results):
    lines = ["# Access verification (%s)" % label, "",
             "| Principal | Action | Resource | Expected | Got | Result |", "|---|---|---|---|---|---|"]
    for r in results:
        lines.append("| %s | %s | %s | %s | %s | %s |" % (
            r["principal"], r["action"], r["resource"], r["expect"], r["got"], "PASS" if r["passed"] else "FAIL"))
    passed = sum(1 for r in results if r["passed"])
    lines += ["", "%d of %d checks passed." % (passed, len(results)), "",
              "Note: conditions are not evaluated; AWS managed policies other than AdministratorAccess "
              "are treated as unknown."]
    return redact("\n".join(lines) + "\n")


# ---------- compare ----------

def compare(before, after):
    key = lambda f: (f["rule"], f["resource"])
    b, a = {key(f): f for f in before["findings"]}, {key(f): f for f in after["findings"]}
    resolved = [b[k] for k in b if k not in a]
    new = [a[k] for k in a if k not in b]
    remaining = [a[k] for k in a if k in b]
    lines = ["# Before and after comparison", "", "| Severity | Before | After |", "|---|---|---|"]
    lines += ["| %s | %d | %d |" % (s, before["summary"]["by_severity"][s], after["summary"]["by_severity"][s])
              for s in SEVERITIES]
    lines += ["| **Total** | **%d** | **%d** |" % (before["summary"]["findings_total"],
                                                    after["summary"]["findings_total"]),
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
        print("%s: %d findings %s" % (s["label"], s["findings_total"], s["by_severity"]))
        if args.fail_on and any(SEV_RANK[f["severity"]] <= SEV_RANK[args.fail_on.capitalize()]
                                for f in result["findings"]):
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
