# ---------------------------------------------------------------------------
# Utility functions for the engine
# ---------------------------------------------------------------------------

from __future__ import annotations
from typing import Any, List
from .models import NHIRecord


def _as_list(x: Any) -> List[Any]:
    return x if isinstance(x, list) else [x]


def _fid(prefix: str, rec: NHIRecord) -> str:
    return f"{prefix}:{rec.name}"

