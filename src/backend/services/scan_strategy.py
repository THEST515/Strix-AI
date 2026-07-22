from __future__ import annotations


def build_effective_instruction(
    *,
    scan_mode: str,
    timeout_seconds: int | None,
    user_instruction: str | None,
) -> str:
    budget = (
        f"The platform will stop this scan after {timeout_seconds} seconds."
        if timeout_seconds is not None
        else "This scan has no platform deadline and requires manual termination."
    )
    urgency = (
        "Within the first 60 seconds, fingerprint products, versions, authentication surfaces, "
        "and high-value endpoints. Map an identified product version to applicable known CVEs and "
        "validate the highest-confidence issue first."
        if timeout_seconds is not None and timeout_seconds <= 300
        else "Fingerprint products and versions early, then prioritize high-confidence validation."
    )
    autonomous_mapping = (
        "- Infer likely CVEs from the product, version, and high-value endpoint evidence without waiting "
        "for a user-specified CVE. Keep generic vulnerability discovery active when no signature matches.\n"
        "- After any confirmed finding, spend at most three focused follow-up turns on adjacent CVE "
        "validation; then preserve concrete candidate evidence and stop expanding the attack chain.\n"
    )
    evidence_cutoff = (
        f"- Treat {max(60, timeout_seconds - 60)} seconds as the evidence cutoff: stop expanding scope "
        "and create a formal vulnerability report; if formal confirmation is not yet possible, create "
        "a findings note with the concrete sanitized evidence already obtained.\n"
        if timeout_seconds is not None and timeout_seconds <= 300
        else ""
    )
    platform_rules = (
        "Platform scan priorities:\n"
        f"- Scan mode: {scan_mode}. {budget}\n"
        f"- {urgency}\n"
        f"{autonomous_mapping}"
        f"{evidence_cutoff}"
        "- Report each confirmed finding immediately; do not wait for the complete attack chain.\n"
        "- Package existing reproducible evidence before pursuing deeper exploit chains such as "
        "webshell or broader privilege expansion.\n"
        "- Before the deadline, stop open-ended reconnaissance and preserve the best available evidence."
    )
    user_rules = (user_instruction or "").strip()
    if not user_rules:
        return platform_rules
    return f"{platform_rules}\n\nUser constraints:\n{user_rules}"
