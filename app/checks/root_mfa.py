"""
CIS AWS Foundations 1.5 equivalent — root account should have MFA enabled.
"""


def run(session, region):
    iam = session.client("iam")

    try:
        summary = iam.get_account_summary()["SummaryMap"]
    except Exception as e:
        return [{
            "check": "root_mfa",
            "resource_id": "N/A",
            "severity": "ERROR",
            "raw_finding": f"Could not fetch account summary: {e}",
        }]

    mfa_enabled = summary.get("AccountMFAEnabled", 0) == 1

    if mfa_enabled:
        return [{
            "check": "root_mfa",
            "resource_id": "root",
            "severity": "PASS",
            "raw_finding": "Root account has MFA enabled.",
        }]

    return [{
        "check": "root_mfa",
        "resource_id": "root",
        "severity": "CRITICAL",
        "raw_finding": "Root account does NOT have MFA enabled.",
    }]
