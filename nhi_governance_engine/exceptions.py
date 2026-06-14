# ---------------------------------------------------------------------------
# Exception register -- approved risk acceptances / false positives.
# A listed finding is reported as "accepted" rather than "open" and does not
# count toward net residual risk or the CI gate, until its (optional) expiry
# passes. This is time-boxed risk acceptance, the way a GRC team operates it.
# ---------------------------------------------------------------------------

from __future__ import annotations
import json
from datetime import date, datetime, timezone
from typing import List, Dict, Any, Optional


def load_exceptions(path: str) -> List[Dict[str, Any]]:
    """Load a register from YAML (.yaml/.yml) or JSON (.json). Returns the list
    under the top-level 'exceptions' key (empty if absent)."""
    with open(path) as fh:
        text = fh.read()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml
        except ImportError as e:
            raise RuntimeError("PyYAML is required to read a YAML register; "
                               "pip install pyyaml, or use a .json register.") from e
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text) if text.strip() else {}
    return list(data.get("exceptions", []))


def _today() -> date:
    return datetime.now(timezone.utc).date()


def is_active(exc: Dict[str, Any], today: Optional[date] = None) -> bool:
    """Active unless an 'expires' date has already passed."""
    today = today or _today()
    exp = exc.get("expires")
    if not exp:
        return True
    try:
        return date.fromisoformat(str(exp)) >= today
    except ValueError:
        return True   # unparseable date: do not silently drop a documented acceptance


def match_exception(finding_id: str, exceptions: List[Dict[str, Any]],
                    today: Optional[date] = None) -> Optional[Dict[str, Any]]:
    """Return the active exception matching this finding_id, or None."""
    for exc in exceptions:
        if exc.get("finding_id") == finding_id and is_active(exc, today):
            return exc
    return None
