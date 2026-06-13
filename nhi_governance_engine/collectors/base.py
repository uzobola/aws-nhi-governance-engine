from __future__ import annotations
from typing import List
from ..models import NHIRecord


# ---------------------------------------------------------------------------
# Base Collector class
# ---------------------------------------------------------------------------


class BaseCollector:
    def collect(self) -> List[NHIRecord]:
        raise NotImplementedError

    def account_id(self) -> str:
        return "unknown"
