"""
Orchestrates the full ScamShield pipeline as a sequence of step events.
Each yielded dict is one "the agent just did X" moment for the live
dashboard: {"step": ..., "status": "running"|"done", "data": {...}}
"""
from parser import parse_input
from checks import investigate_domain
from reasoning import analyze


def run_investigation(raw_text: str):
    # Step 1: parse
    yield {"step": "parse", "status": "running", "label": "Parsing input"}
    parsed = parse_input(raw_text)
    yield {"step": "parse", "status": "done", "label": "Parsed input", "data": parsed}

    # Step 2: live investigate each domain found
    domain_results = []
    if parsed["domains"]:
        for domain in parsed["domains"]:
            yield {
                "step": "investigate",
                "status": "running",
                "label": f"Investigating {domain} (WHOIS, SSL, live fetch)",
            }
            url = next((u for u in parsed["urls"] if domain in u), None)
            result = investigate_domain(domain, url)
            domain_results.append(result)
            yield {
                "step": "investigate",
                "status": "done",
                "label": f"Investigated {domain}",
                "data": result,
            }
    else:
        yield {
            "step": "investigate",
            "status": "done",
            "label": "No URLs/domains found to investigate — text-only analysis",
            "data": [],
        }

    # Step 3: reasoning
    yield {"step": "reason", "status": "running", "label": "Scoring risk and drafting actions"}
    evidence = {
        "parsed_input": parsed,
        "domain_investigations": domain_results,
    }
    verdict = analyze(evidence)
    yield {"step": "reason", "status": "done", "label": "Risk assessment complete", "data": verdict}

    # Step 4: final result
    yield {
        "step": "complete",
        "status": "done",
        "label": "Investigation complete",
        "data": {
            "parsed_input": parsed,
            "domain_investigations": domain_results,
            "verdict": verdict,
        },
    }
