"""
CIS AWS Foundations 2.1.x equivalent — S3 buckets should not be publicly accessible.
"""
import json


def run(session, region):
    s3 = session.client("s3")
    findings = []

    try:
        buckets = s3.list_buckets()["Buckets"]
    except Exception as e:
        return [{
            "check": "public_s3",
            "resource_id": "N/A",
            "severity": "ERROR",
            "raw_finding": f"Could not list buckets: {e}",
        }]

    if not buckets:
        return [{
            "check": "public_s3",
            "resource_id": "N/A",
            "severity": "PASS",
            "raw_finding": "No S3 buckets found in account.",
        }]

    for bucket in buckets:
        name = bucket["Name"]
        is_public = False
        reason = []

        # Check public access block settings
        try:
            pab = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if not all(pab.values()):
                is_public = True
                reason.append("Public Access Block is not fully enabled")
        except s3.exceptions.ClientError:
            # No public access block configured at all = treat as risk
            is_public = True
            reason.append("No Public Access Block configuration found")

        # Check bucket ACL for public grants
        try:
            acl = s3.get_bucket_acl(Bucket=name)
            for grant in acl.get("Grants", []):
                grantee = grant.get("Grantee", {})
                uri = grantee.get("URI", "")
                if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                    is_public = True
                    reason.append(f"ACL grants access to {uri}")
        except Exception:
            pass

        # Check bucket policy for public statements
        try:
            policy = s3.get_bucket_policy(Bucket=name)
            policy_doc = json.loads(policy["Policy"])
            for stmt in policy_doc.get("Statement", []):
                principal = stmt.get("Principal")
                if principal == "*" or principal == {"AWS": "*"}:
                    is_public = True
                    reason.append("Bucket policy allows Principal: *")
        except s3.exceptions.ClientError:
            pass  # no policy attached, fine

        if is_public:
            findings.append({
                "check": "public_s3",
                "resource_id": name,
                "severity": "CRITICAL",
                "raw_finding": "; ".join(reason),
            })

    if not findings:
        findings.append({
            "check": "public_s3",
            "resource_id": "N/A",
            "severity": "PASS",
            "raw_finding": f"All {len(buckets)} buckets are private.",
        })

    return findings
