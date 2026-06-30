"""
Sends raw findings to Groq and gets back a plain-English risk explanation
plus an exact remediation command for each one.
"""
import os
import json
from groq import Groq

_client = None


def _get_client():
    global _client
    if _client is None:
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise RuntimeError("GROQ_API_KEY environment variable is not set.")
        _client = Groq(api_key=api_key)
    return _client

PROMPT_TEMPLATE = """You are a cloud security expert. For each finding below, respond with a JSON array
where each object has exactly these keys: "resource_id", "explanation" (2-3 plain-English sentences
on what this means and why it's risky), and "fix_command" (the exact AWS CLI command or steps to remediate).

Findings:
{findings_json}

Respond with ONLY the JSON array, no markdown formatting, no preamble.
"""


def explain_findings(findings: list[dict]) -> list[dict]:
    """
    Batches all findings into a single Groq call, merges the AI explanation
    back into each finding dict. Falls back gracefully if the API call fails.
    """
    if not findings:
        return findings

    findings_for_prompt = [
        {
            "resource_id": f["resource_id"],
            "check": f["check"],
            "severity": f["severity"],
            "raw_finding": f["raw_finding"],
        }
        for f in findings
    ]

    try:
        client = _get_client()
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {
                    "role": "user",
                    "content": PROMPT_TEMPLATE.format(
                        findings_json=json.dumps(findings_for_prompt, indent=2)
                    ),
                }
            ],
            temperature=0.2,
        )
        raw_text = response.choices[0].message.content.strip()
        # Strip accidental markdown fences
        raw_text = raw_text.replace("```json", "").replace("```", "").strip()
        explanations = json.loads(raw_text)

        explanation_map = {e["resource_id"]: e for e in explanations}

        for f in findings:
            match = explanation_map.get(f["resource_id"])
            if match:
                f["explanation"] = match.get("explanation", "")
                f["fix_command"] = match.get("fix_command", "")
            else:
                f["explanation"] = "AI explanation unavailable for this finding."
                f["fix_command"] = "See AWS documentation for remediation."

    except Exception as e:
        for f in findings:
            f["explanation"] = f"AI explanation failed: {str(e)}"
            f["fix_command"] = "See AWS documentation for remediation."

    return findings
