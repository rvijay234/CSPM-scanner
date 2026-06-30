"""
CIS AWS Foundations 3.1 equivalent — CloudTrail should be enabled in all regions.
"""


def run(session, region):
    ct = session.client("cloudtrail", region_name=region)

    try:
        trails = ct.describe_trails()["trailList"]
    except Exception as e:
        return [{
            "check": "cloudtrail_status",
            "resource_id": "N/A",
            "severity": "ERROR",
            "raw_finding": f"Could not describe trails: {e}",
        }]

    if not trails:
        return [{
            "check": "cloudtrail_status",
            "resource_id": "N/A",
            "severity": "CRITICAL",
            "raw_finding": "No CloudTrail trails configured in this account/region.",
        }]

    # Check at least one trail is multi-region and actively logging
    for trail in trails:
        name = trail["Name"]
        try:
            status = ct.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging") and trail.get("IsMultiRegionTrail"):
                return [{
                    "check": "cloudtrail_status",
                    "resource_id": name,
                    "severity": "PASS",
                    "raw_finding": f"Trail '{name}' is multi-region and actively logging.",
                }]
        except Exception:
            continue

    return [{
        "check": "cloudtrail_status",
        "resource_id": trails[0]["Name"],
        "severity": "HIGH",
        "raw_finding": "CloudTrail exists but is not multi-region and/or not actively logging.",
    }]
