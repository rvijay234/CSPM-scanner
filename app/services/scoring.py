"""
Simple weighted compliance score. Not a substitute for a real CIS scoring
methodology, but gives a defensible single-number summary for the dashboard.
"""

SEVERITY_WEIGHTS = {
    "CRITICAL": 10,
    "HIGH": 6,
    "MEDIUM": 3,
    "LOW": 1,
    "PASS": 0,
    "ERROR": 0,
}


def compute_compliance_score(findings: list[dict], total_checks: int) -> float:
    """
    Score starts at 100 and is docked based on severity of findings.
    Floors at 0. This is intentionally simple — swap in real CIS weighting
    later if you want exact benchmark alignment.
    """
    if not findings:
        return 100.0

    penalty = sum(SEVERITY_WEIGHTS.get(f["severity"], 0) for f in findings)
    score = max(0, 100 - penalty)
    return round(score, 1)
