# AI-Powered CSPM Scanner

Audits an AWS account against 6 high-impact, CIS AWS Foundations Benchmark-aligned
security checks, then uses Groq (Llama 3.3 70B) to explain each finding in plain
English with an exact remediation command — turning a raw findings list into
something an engineer can act on immediately.

## Checks performed

| Check | CIS Control (approx.) | Severity |
|---|---|---|
| Public S3 buckets | 2.1.x | CRITICAL |
| Security groups open to 0.0.0.0/0 on sensitive ports | 5.2 / 5.3 | CRITICAL |
| IAM policies with wildcard Action:*/Resource:* | 1.16 | HIGH |
| Unencrypted EBS volumes | 2.2.1 | MEDIUM |
| Root account without MFA | 1.5 | CRITICAL |
| CloudTrail not enabled / not multi-region | 3.1 | HIGH |

## Setup

```bash
pip install -r requirements.txt
export GROQ_API_KEY=your_key_here
uvicorn app.main:app --reload
```

## Usage

```bash
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{
    "aws_access_key_id": "AKIA...",
    "aws_secret_access_key": "...",
    "region": "us-east-1"
  }'
```

## Required IAM permissions (read-only)

Attach a policy with:
- `s3:ListAllMyBuckets`, `s3:GetBucketAcl`, `s3:GetBucketPolicy`, `s3:GetBucketPublicAccessBlock`
- `ec2:DescribeSecurityGroups`, `ec2:DescribeVolumes`
- `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:GetAccountSummary`
- `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`

Never use long-lived root credentials to run this — create a dedicated
read-only IAM user or assume a scoped role.

## Testing against a real misconfigured environment

To validate findings are accurate, this was tested against a sandbox AWS
account with deliberately introduced misconfigurations:
- One S3 bucket with public read ACL
- One security group allowing inbound SSH (port 22) from 0.0.0.0/0
- Default (unencrypted) EBS volume on a test EC2 instance

See `/docs/before-after.md` for findings output and remediation walkthrough.

## Architecture

FastAPI backend → Boto3 (read-only AWS API calls) → 6 independent check
modules → Groq for plain-English risk explanation + fix command → simple
weighted compliance score.

Frontend reuses the dashboard pattern from [AI Cloud Cost Detective], with
columns swapped from cost data to severity/resource/explanation/fix.
