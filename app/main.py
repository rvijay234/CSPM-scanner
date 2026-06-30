"""
AI-Powered CSPM Scanner — FastAPI entrypoint
Audits an AWS account against a focused set of CIS-aligned security checks,
then uses Groq to explain each finding in plain English with an exact fix.
"""
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import boto3

from app.checks import (
    public_s3,
    open_security_groups,
    iam_wildcard_policies,
    unencrypted_ebs,
    root_mfa,
    cloudtrail_status,
)
from app.services.groq_service import explain_findings
from app.services.scoring import compute_compliance_score

app = FastAPI(title="CSPM Scanner API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # tighten before sharing publicly
    allow_methods=["*"],
    allow_headers=["*"],
)

CHECKS = [
    public_s3.run,
    open_security_groups.run,
    iam_wildcard_policies.run,
    unencrypted_ebs.run,
    root_mfa.run,
    cloudtrail_status.run,
]


class ScanRequest(BaseModel):
    aws_access_key_id: str
    aws_secret_access_key: str
    region: str = "us-east-1"
    aws_session_token: str | None = None


class ScanResponse(BaseModel):
    score: float
    total_checks: int
    findings: list[dict]


@app.post("/scan", response_model=ScanResponse)
def scan_account(req: ScanRequest):
    session = boto3.Session(
        aws_access_key_id=req.aws_access_key_id,
        aws_secret_access_key=req.aws_secret_access_key,
        aws_session_token=req.aws_session_token,
        region_name=req.region,
    )

    all_findings = []
    for check_fn in CHECKS:
        try:
            findings = check_fn(session, req.region)
            all_findings.extend(findings)
        except Exception as e:
            # Don't let one failed check kill the whole scan
            all_findings.append({
                "check": check_fn.__module__.split(".")[-1],
                "resource_id": "N/A",
                "severity": "ERROR",
                "raw_finding": f"Check failed to run: {str(e)}",
            })

    # Only call Groq on actual findings (skip ERROR entries and clean checks)
    real_findings = [f for f in all_findings if f["severity"] not in ("ERROR", "PASS")]
    if real_findings:
        real_findings = explain_findings(real_findings)

    score = compute_compliance_score(all_findings, len(CHECKS))

    return {
        "score": score,
        "total_checks": len(CHECKS),
        "findings": real_findings,
    }


@app.get("/health")
def health():
    return {"status": "ok"}
