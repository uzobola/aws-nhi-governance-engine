# ---------------------------------------------------------------------------
# JSON reporter
# -------------------------------------------------------- -------------------

from __future__ import annotations
import json
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List, Dict, Any
from ..models import NHIRecord, Finding, Severity, NHIType

def build_report(records: List[NHIRecord], findings: List[Finding],
                 account_id: str) -> Dict[str, Any]:
    by_sev: Dict[str, int] = {s.value: 0 for s in Severity}
    for f in findings:
        by_sev[f.severity.value] += 1
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
        },
        "findings": [_finding_to_dict(f) for f in findings],
    }


def _finding_to_dict(f: Finding) -> Dict[str, Any]:
    d = asdict(f)
    d["severity"] = f.severity.value
    return d
