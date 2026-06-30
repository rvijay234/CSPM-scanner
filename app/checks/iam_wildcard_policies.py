"""
CIS AWS Foundations 1.16 equivalent — IAM policies should not allow
full administrative privileges via wildcards.
"""
import json


def _statement_is_wildcard(stmt):
    if stmt.get("Effect") != "Allow":
        return False
    actions = stmt.get("Action", [])
    resources = stmt.get("Resource", [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(resources, str):
        resources = [resources]
    return "*" in actions and "*" in resources


def run(session, region):
    iam = session.client("iam")
    findings = []

    try:
        policies = iam.list_policies(Scope="Local", OnlyAttached=True)["Policies"]
    except Exception as e:
        return [{
            "check": "iam_wildcard_policies",
            "resource_id": "N/A",
            "severity": "ERROR",
            "raw_finding": f"Could not list IAM policies: {e}",
        }]

    for policy in policies:
        arn = policy["Arn"]
        try:
            version_id = policy["DefaultVersionId"]
            version = iam.get_policy_version(PolicyArn=arn, VersionId=version_id)
            doc = version["PolicyVersion"]["Document"]
            statements = doc.get("Statement", [])
            if isinstance(statements, dict):
                statements = [statements]

            for stmt in statements:
                if _statement_is_wildcard(stmt):
                    findings.append({
                        "check": "iam_wildcard_policies",
                        "resource_id": policy["PolicyName"],
                        "severity": "HIGH",
                        "raw_finding": f"Policy '{policy['PolicyName']}' grants Action:* on Resource:* (full admin access)",
                    })
                    break
        except Exception:
            continue

    if not findings:
        findings.append({
            "check": "iam_wildcard_policies",
            "resource_id": "N/A",
            "severity": "PASS",
            "raw_finding": f"No wildcard admin policies found among {len(policies)} customer-managed policies.",
        })

    return findings
