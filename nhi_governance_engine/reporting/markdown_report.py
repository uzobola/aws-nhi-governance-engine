# ---------------------------------------------------------------------------
# Markdown reporter -- human-readable view of the same findings the JSON carries
# ---------------------------------------------------------------------------

from __future__ import annotations
from typing import Dict, Any

_SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _fmt_evidence(ev: Dict[str, Any]) -> str:
    """One-line, human-readable evidence. Scalars and short lists are shown
    inline; nested structures (e.g. a full trust statement) are elided here,
    since the JSON report carries the complete detail."""
    parts = []
    for k, v in ev.items():
        if isinstance(v, list):
            if any(isinstance(x, (dict, list)) for x in v):
                parts.append(f"{k} = [...]")          # nested detail lives in the JSON
            else:
                shown = ", ".join(str(x) for x in v[:6])
                if len(v) > 6:
                    shown += f", +{len(v) - 6} more"
                parts.append(f"{k} = {shown}")
        elif isinstance(v, dict):
            parts.append(f"{k} = {{...}}")
        else:
            parts.append(f"{k} = {v}")
    return "; ".join(parts)


def _finding_block(f: Dict[str, Any]) -> list:
    nhi = f["nhi_id"].split("/")[-1]
    block = [f"**{f['title']}** -- `{nhi}`  ",
             f"{f['owasp_nhi']} \u00b7 {f['nist_800_53']}  "]
    ev = _fmt_evidence(f.get("evidence", {}))
    if ev:
        block.append(f"Evidence: {ev}  ")
    block.append(f"Remediation: {f['remediation']}")
    block.append("")
    return block


def _accepted_block(f: Dict[str, Any]) -> list:
    nhi = f["nhi_id"].split("/")[-1]
    exc = f.get("exception", {}) or {}
    owner = exc.get("owner") or "unspecified"
    expires = exc.get("expires") or "no expiry"
    reason = exc.get("reason") or ""
    return [f"**{f['title']}** -- `{nhi}`  ",
            f"{f['owasp_nhi']} \u00b7 {f['nist_800_53']}  ",
            f"Accepted by {owner}, expires {expires} -- {reason}",
            ""]


def render_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    by_type = s["nhi_by_type"]
    net = s.get("net_residual_by_severity", s.get("findings_by_severity", {}))
    total = s["findings_total"]
    open_n = s.get("findings_open", total)
    accepted_n = s.get("findings_accepted", 0)
    out = ["# NHI Governance Report", ""]
    out.append(f"**Account:** {report['account_id']}  ")
    out.append(f"**Generated:** {report['generated_at']}  ")
    out.append(f"**Scope:** {report['scope']}")
    out += ["", "## Summary", ""]
    type_str = ", ".join(f"{k}: {v}" for k, v in by_type.items() if v)
    out.append(f"- NHIs scanned: **{s['nhi_total']}** ({type_str})")
    out.append(f"- Findings: **{total}** (open: {open_n}, accepted: {accepted_n})")
    net_str = ", ".join(f"{k} {net.get(k, 0)}" for k in _SEV_ORDER)
    out.append(f"- Net residual risk: {net_str}")
    out += [""]

    findings = report["findings"]
    open_findings = [f for f in findings if f.get("status", "open") != "accepted"]
    accepted_findings = [f for f in findings if f.get("status") == "accepted"]

    out += ["## Open findings", ""]
    if not open_findings:
        out.append("_No open findings. All scanned NHIs passed, or all findings are accepted._")
        out.append("")
    else:
        for sev in _SEV_ORDER:
            group = [f for f in open_findings if f["severity"] == sev]
            if not group:
                continue
            out.append(f"### {sev} ({len(group)})")
            out.append("")
            for f in group:
                out += _finding_block(f)

    if accepted_findings:
        out += [f"## Accepted exceptions ({len(accepted_findings)})", ""]
        for f in accepted_findings:
            out += _accepted_block(f)
    return "\n".join(out) + "\n"
