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


def render_markdown(report: Dict[str, Any]) -> str:
    s = report["summary"]
    by_sev = s["findings_by_severity"]
    by_type = s["nhi_by_type"]
    out = ["# NHI Governance Report", ""]
    out.append(f"**Account:** {report['account_id']}  ")
    out.append(f"**Generated:** {report['generated_at']}  ")
    out.append(f"**Scope:** {report['scope']}")
    out += ["", "## Summary", ""]
    type_str = ", ".join(f"{k}: {v}" for k, v in by_type.items() if v)
    out.append(f"- NHIs scanned: **{s['nhi_total']}** ({type_str})")
    sev_str = ", ".join(f"{k} {by_sev.get(k, 0)}" for k in _SEV_ORDER)
    out.append(f"- Findings: **{s['findings_total']}** ({sev_str})")
    out += ["", "## Findings", ""]

    findings = report["findings"]
    if not findings:
        out.append("_No findings. All scanned NHIs passed every detector._")
        return "\n".join(out) + "\n"

    for sev in _SEV_ORDER:
        group = [f for f in findings if f["severity"] == sev]
        if not group:
            continue
        out.append(f"### {sev} ({len(group)})")
        out.append("")
        for f in group:
            nhi = f["nhi_id"].split("/")[-1]
            out.append(f"**{f['title']}** -- `{nhi}`  ")
            out.append(f"{f['owasp_nhi']} \u00b7 {f['nist_800_53']}  ")
            ev = _fmt_evidence(f.get("evidence", {}))
            if ev:
                out.append(f"Evidence: {ev}  ")
            out.append(f"Remediation: {f['remediation']}")
            out.append("")
    return "\n".join(out) + "\n"
