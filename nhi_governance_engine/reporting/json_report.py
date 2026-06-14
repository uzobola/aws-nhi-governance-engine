# ---------------------------------------------------------------------------
# JSON reporter
# -------------------------------------------------------- -------------------

from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from ..models import NHIRecord, Finding, Severity, NHIType
from ..exceptions import match_exception

def build_report(records: List[NHIRecord], findings: List[Finding],
                 account_id: str,
                 exceptions: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    exceptions = exceptions or []
    by_sev: Dict[str, int] = {s.value: 0 for s in Severity}
    net_by_sev: Dict[str, int] = {s.value: 0 for s in Severity}
    accepted = 0
    finding_dicts: List[Dict[str, Any]] = []
    for f in findings:
        by_sev[f.severity.value] += 1
        d = _finding_to_dict(f)
        exc = match_exception(d["finding_id"], exceptions)
        if exc:
            d["status"] = "accepted"
            d["exception"] = {"reason": exc.get("reason"),
                              "owner": exc.get("owner"),
                              "expires": exc.get("expires")}
            accepted += 1
        else:
            d["status"] = "open"
            net_by_sev[f.severity.value] += 1
        finding_dicts.append(d)
    by_type: Dict[str, int] = {t.value: 0 for t in NHIType}
    for r in records:
        by_type[r.nhi_type.value] += 1
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "account_id": account_id,
        "scope": "iam_roles, iam_users+keys, secretsmanager_secrets (read-only)",
        "summary": {
            "nhi_total": len(records),
            "nhi_by_type": by_type,
            "findings_total": len(findings),
            "findings_by_severity": by_sev,
            "findings_open": len(findings) - accepted,
            "findings_accepted": accepted,
            "net_residual_by_severity": net_by_sev,
        },
        "findings": finding_dicts,
    }


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    d = asdict(f)
    d["severity"] = f.severity.value
    return d
