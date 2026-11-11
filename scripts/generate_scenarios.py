"""Populate Breach Bench's scenario library from the MITRE CTI extract.

Run after scripts/extract_attack.py:

    python scripts/generate_scenarios.py [groups.json]

Target: data/scenarios.json (the custom scenario store, via
engine.scenario_store.upsert — same validation as the UI editor)

For every ATT&CK group a playable kill-chain scenario is generated:

  * steps ordered along the 14 ATT&CK tactics (recon ... impact), max 2
    techniques per tactic, 12 steps per scenario — steps with a concrete
    command are preferred so the consoles show real strings;
  * target_type heuristically derived from platforms / data sources
    (cloud platforms -> IdP / IAM / S3, Linux -> Linux server, ...);
  * ground-truth emits derived from the technique's ATT&CK data components
    (mapped onto the engine's sensor vocabulary); techniques with no
    modeled data source fall back to Process Creation (the process that
    ran the technique is the one thing that always exists);
  * id prefix "cti-" keeps the namespace separate from built-in scenarios;
    re-running the script rebuilds all cti-* entries from scratch.
"""
from __future__ import annotations

import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from engine import scenario_store as store          # noqa: E402
from engine.coverage import DATA_SOURCES            # noqa: E402

SRC_DEFAULT = HERE / "data" / "mitre-attack-groups.json"

# CTI may carry tactic names the engine does not model — fold them onto the
# closest modeled tactic ("stealth" arrived with newer ATT&CK versions).
TACTIC_MAP = {"stealth": "defense-evasion"}

MAX_STEPS = 12          # validator caps at 20; 12 keeps a replay watchable
PER_TACTIC = 2          # techniques picked per tactic stage
CMD_SOURCE = "MITRE ATT&CK CTI (Groups)"
NO_CMD = "N/A — no concrete command documented in the CTI procedure"


def primary_tactic(t: dict) -> str:
    """First of the technique's tactics in canonical chain order."""
    for tac in store.TACTICS:
        if tac in t["tactics"]:
            return tac
    mapped = [TACTIC_MAP.get(x, x) for x in t["tactics"]]
    return mapped[0] if mapped else "execution"


IDP_PLATFORMS = ("azure ad", "office 365", "saas", "google workspace")


def target_type(t: dict) -> str:
    plats = [p.lower() for p in t["platforms"]]
    ds = set(t["data_sources"] or [])
    name = t["technique_name"].lower()
    tid = t["technique_id"]
    if "cloud storage access" in ds or "cloud storage" in name:
        return "s3"
    if any(k in name for k in ("identity", "sso", "federation", "multi-factor")) \
            or "cloud logon" in ds:
        return "idp"
    if any(c in p for p in plats for c in IDP_PLATFORMS):
        return "idp"
    if any("iaas" in p or "container" in p for p in plats) or "cloud api call" in ds:
        return "iam"
    if "spearphish" in name or "phishing" in name or tid.startswith("T1566"):
        return "workstation"
    if "public-facing" in name or "web shell" in name or tid.startswith(("T1190", "T1505")):
        return "web_server"
    if any(("linux" in p or "macos" in p) for p in plats) \
            and not any("windows" in p for p in plats):
        return "server_linux"
    return "workstation"


def build_emits(t: dict, command: str) -> list[dict]:
    """Ground-truth events for a step, one per modeled ATT&CK data source."""
    dss = [d for d in (t["data_sources"] or []) if d in DATA_SOURCES]
    # phishing steps must exercise the mail path even when CTI's analytics
    # point at other components
    if (not any(d.startswith("Email") for d in dss)
            and ("spearphish" in t["technique_name"].lower()
                 or t["technique_id"].startswith("T1566"))):
        dss.insert(0, "Email Delivery")
    if not dss:
        # nothing modeled for this technique — the process that ran it is
        # the one guaranteed artifact
        dss = ["Process Creation"]
    dss = list(dict.fromkeys(dss))[:4]

    emits = []
    proc = None
    m = re.search(r"([\w\-.]+\.exe)", command, re.IGNORECASE)
    if m:
        proc = m.group(1)
    for i, ds in enumerate(dss):
        ev: dict = {"ds": ds}
        if len(dss) > 1:
            ev["at"] = round(0.2 + 0.6 * i / (len(dss) - 1), 2)
        else:
            ev["at"] = 0.4
        if ds in ("Process Creation", "Command Execution") and command != NO_CMD:
            ev["cmd"] = command[:220]
            if proc:
                ev["process"] = proc
        emits.append(ev)
    return emits


def build_scenario(g: dict) -> dict | None:
    """Turn one CTI group into a validated Breach Bench scenario."""
    by_tactic: dict[str, list[dict]] = {}
    for t in g["techniques"]:
        t = {**t, "_tac": primary_tactic(t)}
        by_tactic.setdefault(t["_tac"], []).append(t)

    picked: list[dict] = []
    for tac in store.TACTICS:                      # canonical chain order
        cands = sorted(by_tactic.get(tac, []),
                       key=lambda t: (0 if t["command"] else 1, t["technique_id"]))
        picked.extend(cands[:PER_TACTIC])
    if not picked:
        return None
    picked = picked[:MAX_STEPS]

    steps = []
    for t in picked:
        command = t["command"] or NO_CMD
        st = {
            "tactic": t["_tac"],
            "technique": t["technique_id"],
            "name": t["technique_name"],
            "procedure": t["procedure"][:500],
            "command": command,
            "cmd_source": CMD_SOURCE,
            "target_type": target_type(t),
            "emits": build_emits(t, command),
        }
        if t["_tac"] == "command-and-control":
            st["window"] = 150                     # beaconing needs a stretch
        steps.append(st)

    slug = re.sub(r"[^a-z0-9]+", "-", g["name"].lower()).strip("-")[:55].rstrip("-")
    blurb = g.get("description", "").strip()
    if len(blurb) > 280:
        blurb = blurb[:277].rstrip() + "..."
    if not blurb:
        blurb = f"Documented tradecraft of {g['name']}."
    return {
        "id": f"cti-{slug}",
        "name": f"{g['name']} — CTI chain ({len(steps)} steps)",
        "group": g["name"],
        "blurb": blurb + " [auto-built from MITRE ATT&CK CTI]",
        "steps": steps,
    }


def main() -> None:
    src = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else SRC_DEFAULT
    doc = json.load(open(src, encoding="utf-8"))

    # rebuild: drop everything previously generated, keep user-authored ones
    for s in list(store.load_custom()):
        if s["id"].startswith("cti-"):
            store.delete(s["id"])

    used: set[str] = set()
    made, skipped = 0, 0
    for g in doc["groups"]:
        if not g["techniques"]:
            skipped += 1
            continue
        sc = build_scenario(g)
        if sc is None:
            skipped += 1
            continue
        sid, i = sc["id"], 2
        while sid in used:                          # de-dupe within this run
            sid = f"{sc['id']}-{i}"
            i += 1
        sc["id"] = sid
        used.add(sid)
        errs = store.validate(sc)
        if errs:
            print(f"SKIP {g['name']}: {'; '.join(errs[:3])}")
            skipped += 1
            continue
        store.upsert(sc)
        made += 1

    print(f"generated {made} scenarios ({skipped} groups skipped) -> {store.STORE}")


if __name__ == "__main__":
    main()
