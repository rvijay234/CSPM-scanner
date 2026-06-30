"""
CIS AWS Foundations 2.2.1 equivalent — EBS volumes should be encrypted at rest.
"""


def run(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []

    try:
        volumes = ec2.describe_volumes()["Volumes"]
    except Exception as e:
        return [{
            "check": "unencrypted_ebs",
            "resource_id": "N/A",
            "severity": "ERROR",
            "raw_finding": f"Could not describe volumes: {e}",
        }]

    if not volumes:
        return [{
            "check": "unencrypted_ebs",
            "resource_id": "N/A",
            "severity": "PASS",
            "raw_finding": "No EBS volumes found.",
        }]

    for vol in volumes:
        if not vol.get("Encrypted", False):
            findings.append({
                "check": "unencrypted_ebs",
                "resource_id": vol["VolumeId"],
                "severity": "MEDIUM",
                "raw_finding": f"Volume {vol['VolumeId']} ({vol.get('Size')}GB) is not encrypted",
            })

    if not findings:
        findings.append({
            "check": "unencrypted_ebs",
            "resource_id": "N/A",
            "severity": "PASS",
            "raw_finding": f"All {len(volumes)} EBS volumes are encrypted.",
        })

    return findings
