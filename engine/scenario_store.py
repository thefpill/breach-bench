"""User-authored scenarios, persisted next to the server.

Built-in scenarios (engine/scenarios.py) are read-only documented
tradecraft. Anything created or edited in the UI's scenario editor is
stored in data/scenarios.json and merged with the built-ins by the API.
No database — one JSON file, loaded on demand, written atomically.

Validation is intentionally strict: the simulator joins steps to controls
via technique prefixes and data-source names, so a malformed step would
silently produce a meaningless simulation.
"""
from __future__ import annotations

import json
import pathlib
import re
import shutil
import tempfile

from .coverage import DATA_SOURCES
from .models import TARGETABLE_TYPES

ROOT = pathlib.Path(__file__).parent.parent
STORE = ROOT / "data" / "scenarios.json"

# ATT&CK tactics offered in the editor (free text is still allowed)
TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution",
    "persistence", "privilege-escalation", "defense-evasion", "credential-access",
    "discovery", "lateral-movement", "collection", "command-and-control",
    "exfiltration", "impact",
]

# Human labels for the target_type dropdown in the editor
TARGET_LABELS = {
    "workstation": "Workstation",
    "server_win": "Windows server",
    "server_linux": "Linux server",
    "web_server": "Web server (public-facing)",
    "idp": "IdP / SSO",
    "iam": "IAM / control plane",
    "s3": "S3 bucket",
}

_ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{2,62}$")
_TECH_RE = re.compile(r"^T\d{4}(\.\d{3})?$")


# ---------------------------------------------------------------------------
# storage
# ---------------------------------------------------------------------------
def load_custom() -> list[dict]:
    if not STORE.exists():
        return []
    try:
        data = json.loads(STORE.read_text(encoding="utf-8"))
        return data if isinstance(data, list) else []
    except (json.JSONDecodeError, OSError):
        # a corrupt file should never take the whole app down
        return []


def _save_custom(scenarios: list[dict]) -> None:
    """Atomic-ish write: dump to a temp file, then replace the target."""
    STORE.parent.mkdir(parents=True, exist_ok=True)
    fd = tempfile.NamedTemporaryFile("w", dir=STORE.parent, delete=False,
                                     suffix=".tmp", encoding="utf-8")
    try:
        json.dump(scenarios, fd, indent=2, ensure_ascii=False)
        fd.close()
        shutil.move(fd.name, STORE)
    finally:
        if pathlib.Path(fd.name).exists():
            pathlib.Path(fd.name).unlink(missing_ok=True)


def find_custom(sid: str) -> dict | None:
    return next((s for s in load_custom() if s["id"] == sid), None)


def upsert(scenario: dict, orig_id: str | None = None) -> dict:
    """Validate + insert or update a custom scenario. Returns the stored one."""
    errors = validate(scenario)
    if errors:
        raise ValueError("; ".join(errors))
    scenario = _normalize(scenario)
    items = load_custom()
    sid = scenario["id"]
    # renamed? drop the old entry first
    if orig_id and orig_id != sid:
        items = [s for s in items if s["id"] != orig_id]
    items = [s for s in items if s["id"] != sid]
    items.append(scenario)
    _save_custom(items)
    return scenario


def _normalize(s: dict) -> dict:
    """Fill defaults for optional fields the simulator expects to exist."""
    out = dict(s)
    out["blurb"] = str(s.get("blurb") or "")
    out["steps"] = [dict(st, cmd_source=str(st.get("cmd_source") or "custom scenario"))
                    for st in s["steps"]]
    return out


def delete(sid: str) -> None:
    items = load_custom()
    remaining = [s for s in items if s["id"] != sid]
    if len(remaining) == len(items):
        raise KeyError(sid)
    _save_custom(remaining)


def slugify(name: str) -> str:
    """'My Threat Actor' -> 'my-threat-actor' (+ -2, -3 ... on collision)."""
    base = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")[:63].rstrip("-")
    if not _ID_RE.match(base):
        base = "scenario"
    taken = {s["id"] for s in load_custom()}
    sid, i = base, 2
    while sid in taken:
        sid = f"{base}-{i}"
        i += 1
    return sid


# ---------------------------------------------------------------------------
# validation — returns a list of human-readable problems (empty = valid)
# ---------------------------------------------------------------------------
def _bad_step(i: int, field: str, msg: str) -> str:
    return f"step {i + 1}: {field} {msg}"


def validate(s: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(s, dict):
        return ["scenario must be a JSON object"]

    if not _ID_RE.match(s.get("id", "")):
        errors.append("id must be 3-63 chars of a-z, 0-9 and dashes")
    if not str(s.get("name", "")).strip():
        errors.append("name is required")
    if not str(s.get("group", "")).strip():
        errors.append("group (adversary name) is required")

    steps = s.get("steps")
    if not isinstance(steps, list) or not steps:
        return errors + ["at least one step is required"]
    if len(steps) > 20:
        errors.append("20 steps max — split the story into two scenarios")

    for i, st in enumerate(steps):
        if not isinstance(st, dict):
            errors.append(_bad_step(i, "body", "must be an object"))
            continue
        if not _TECH_RE.match(str(st.get("technique", ""))):
            errors.append(_bad_step(i, "technique", "must look like T1566 or T1566.001"))
        if not str(st.get("name", "")).strip():
            errors.append(_bad_step(i, "name", "is required"))
        if not str(st.get("tactic", "")).strip():
            errors.append(_bad_step(i, "tactic", "is required"))
        if not str(st.get("procedure", "")).strip():
            errors.append(_bad_step(i, "procedure", "is required — cite the documented behavior"))
        if st.get("target_type") not in TARGETABLE_TYPES:
            errors.append(_bad_step(
                i, "target_type", f"must be one of: {', '.join(sorted(TARGETABLE_TYPES))}"))
        win = st.get("window")
        if win is not None and (not isinstance(win, (int, float)) or not 10 <= win <= 3600):
            errors.append(_bad_step(i, "window", "must be a number between 10 and 3600 seconds"))

        emits = st.get("emits")
        if not isinstance(emits, list) or not emits:
            errors.append(_bad_step(i, "emits", "needs at least one ground-truth event"))
            continue
        for j, ev in enumerate(emits):
            if not isinstance(ev, dict) or ev.get("ds") not in DATA_SOURCES:
                errors.append(_bad_step(
                    i, f"event {j + 1} ds", f"must be one of: {', '.join(DATA_SOURCES)}"))
                continue
            at = ev.get("at")
            if at is not None and (not isinstance(at, (int, float)) or not 0 <= at <= 1):
                errors.append(_bad_step(i, f"event {j + 1} at", "must be between 0 and 1"))
            det = ev.get("details")
            if det is not None and not isinstance(det, dict):
                errors.append(_bad_step(i, f"event {j + 1} details", "must be a JSON object"))
    return errors
