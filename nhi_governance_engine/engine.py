
# ---------------------------------------------------------------------------
# Engine main function
# ---------------------------------------------------------------------------

from __future__ import annotations
from typing import List
from .models import NHIRecord, Finding, Config
from .detectors import DETECTORS


def run_detectors(records: List[NHIRecord], cfg: Config) -> List[Finding]:
    findings: List[Finding] = []
    for rec in records:
        for detector in DETECTORS:
            findings.extend(detector(rec, cfg))
    return findings

