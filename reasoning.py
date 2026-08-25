"""
The reasoning layer: hands everything the pipeline gathered to Claude
and asks for (a) a risk verdict with justification, and (b) ready-to-use
action drafts (abuse report text, warning reply, incident summary).

This is deliberately a single structured call rather than a chatty
back-and-forth: the agent already did the investigating (parser.py,
checks.py) — Claude's job here is judgment and drafting, not fetching.
"""
import json
import os
from anthropic import Anthropic

MODEL = "claude-sonnet-4-5"

client = Anthropic(api_key=os.environ.get("ANTHROPIC_API_KEY"))

SYSTEM_PROMPT = """You are the reasoning module inside ScamShield, a phishing \
and scam investigation agent. You are given structured evidence already \
gathered by the agent (parsed message, domain WHOIS age, SSL info, live \
page fetch results, urgency-language signals). You do not browse the web \
yourself; you only reason over the evidence provided.

Return ONLY valid JSON (no markdown fences, no preamble) matching this shape:
{
  "verdict": "malicious" | "suspicious" | "likely_legitimate",
  "risk_score": <integer 0-100>,
  "justification": "<2-4 sentences citing the specific evidence>",
  "indicators": ["<short indicator>", ...],
  "recommended_action": "file_abuse_report" | "draft_warning_reply" | "no_action_needed",
  "abuse_report_draft": "<a filled-out abuse report body a user could paste into Google Safe Browsing / a hosting provider's abuse form, or empty string if not applicable>",
  "warning_reply_draft": "<a short reply a user could send back to a scam sender warning them off, or empty string if not applicable>",
  "incident_summary": "<a short shareable summary for a non-technical person, e.g. a family member>"
}
"""


def analyze(evidence: dict) -> dict:
    user_content = (
        "Evidence gathered by the agent:\n\n"
        + json.dumps(evidence, indent=2, default=str)
    )
    resp = client.messages.create(
        model=MODEL,
        max_tokens=1500,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": user_content}],
    )
    text = resp.content[0].text.strip()
    text = text.removeprefix("```json").removeprefix("```").removesuffix("```").strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return {
            "verdict": "suspicious",
            "risk_score": 50,
            "justification": "Model output could not be parsed as JSON; treating as inconclusive.",
            "indicators": [],
            "recommended_action": "no_action_needed",
            "abuse_report_draft": "",
            "warning_reply_draft": "",
            "incident_summary": text[:500],
            "raw_model_output": text,
        }
