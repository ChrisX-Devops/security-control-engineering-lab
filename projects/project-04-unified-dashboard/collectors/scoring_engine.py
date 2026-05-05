"""
scoring_engine.py
=================
Calculates compliance scores from unified findings.

Scoring model:
    Each finding reduces the score based on severity.
    The baseline score is 100 (fully compliant).

    Deductions:
        CRITICAL finding: -20 points each
        HIGH finding:     -10 points each
        MEDIUM finding:   -5 points each
        LOW finding:      -2 points each

    Score is floored at 0 (cannot go negative).

Why deduction-based scoring:
    It is intuitive. Everyone understands 100 = perfect.
    Each finding has a visible impact on the score.
    Clients immediately see why their score is low.
    Fixing a CRITICAL finding visibly improves the score.
"""


SEVERITY_DEDUCTIONS = {
    "CRITICAL": 20,
    "HIGH":     10,
    "MEDIUM":    5,
    "LOW":       2
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def calculate_score(findings):
    """
    Calculate overall compliance score from findings list.

    Args:
        findings: list of normalized finding dicts

    Returns:
        dict: complete scoring breakdown
    """
    score = 100
    deductions = {}

    counts = {s: 0 for s in SEVERITY_ORDER}

    for finding in findings:
        severity = finding.get("severity", "LOW")
        deduction = SEVERITY_DEDUCTIONS.get(severity, 0)
        score -= deduction
        counts[severity] = counts.get(severity, 0) + 1
        deductions[severity] = deductions.get(severity, 0) + deduction

    score = max(0, score)

    if score >= 90:
        grade = "A"
        status = "EXCELLENT"
    elif score >= 80:
        grade = "B"
        status = "GOOD"
    elif score >= 70:
        grade = "C"
        status = "FAIR"
    elif score >= 50:
        grade = "D"
        status = "POOR"
    else:
        grade = "F"
        status = "CRITICAL"

    category_scores = calculate_category_scores(findings)

    return {
        "overall_score":    score,
        "grade":            grade,
        "status":           status,
        "total_findings":   len(findings),
        "counts":           counts,
        "deductions":       deductions,
        "category_scores":  category_scores
    }


def calculate_category_scores(findings):
    """
    Calculate scores broken down by category.

    Categories:
        access_control    - who can access what
        identity          - user authentication
        data_protection   - encryption and storage
        logging           - audit trails
        cloud_security    - cloud configuration

    Args:
        findings: list of normalized finding dicts

    Returns:
        dict: score per category
    """
    categories = {}

    for finding in findings:
        cat = finding.get("category", "other")
        if cat not in categories:
            categories[cat] = {"score": 100, "findings": 0}

        severity = finding.get("severity", "LOW")
        deduction = SEVERITY_DEDUCTIONS.get(severity, 0)
        categories[cat]["score"] -= deduction
        categories[cat]["findings"] += 1

    for cat in categories:
        categories[cat]["score"] = max(0, categories[cat]["score"])

    return categories


def prioritize_findings(findings):
    """
    Sort findings by severity for remediation planning.

    Args:
        findings: list of normalized finding dicts

    Returns:
        list: findings sorted CRITICAL → HIGH → MEDIUM → LOW
    """
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    return sorted(
        findings,
        key=lambda f: order.get(f.get("severity", "LOW"), 99)
    )
