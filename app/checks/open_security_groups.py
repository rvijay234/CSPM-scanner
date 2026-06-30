"""
CIS AWS Foundations 5.2/5.3 equivalent — security groups should not allow
unrestricted inbound access on sensitive ports.
"""

SENSITIVE_PORTS = {
    22: "SSH",
    3389: "RDP",
    3306: "MySQL",
    5432: "PostgreSQL",
    27017: "MongoDB",
    6379: "Redis",
    1433: "MSSQL",
    0: "ALL_TRAFFIC",  # catches "all ports" rules (from_port=-1 sentinel handled below)
}


def run(session, region):
    ec2 = session.client("ec2", region_name=region)
    findings = []

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except Exception as e:
        return [{
            "check": "open_security_groups",
            "resource_id": "N/A",
            "severity": "ERROR",
            "raw_finding": f"Could not describe security groups: {e}",
        }]

    for sg in sgs:
        for perm in sg.get("IpPermissions", []):
            from_port = perm.get("FromPort", -1)
            to_port = perm.get("ToPort", -1)

            for ip_range in perm.get("IpRanges", []):
                cidr = ip_range.get("CidrIp", "")
                if cidr != "0.0.0.0/0":
                    continue

                # All-traffic rule (no port restriction at all)
                if from_port == -1 and to_port == -1:
                    findings.append({
                        "check": "open_security_groups",
                        "resource_id": f"{sg['GroupId']} ({sg.get('GroupName', '')})",
                        "severity": "CRITICAL",
                        "raw_finding": "Allows ALL traffic from 0.0.0.0/0 (no port restriction)",
                    })
                    continue

                for port, label in SENSITIVE_PORTS.items():
                    if port == 0:
                        continue
                    if from_port <= port <= to_port:
                        findings.append({
                            "check": "open_security_groups",
                            "resource_id": f"{sg['GroupId']} ({sg.get('GroupName', '')})",
                            "severity": "CRITICAL",
                            "raw_finding": f"Port {port} ({label}) open to 0.0.0.0/0",
                        })

    if not findings:
        findings.append({
            "check": "open_security_groups",
            "resource_id": "N/A",
            "severity": "PASS",
            "raw_finding": f"No sensitive-port exposure found across {len(sgs)} security groups.",
        })

    return findings
