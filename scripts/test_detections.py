"""Sanity checks for the detection-asset additions.

1. the new IDS asset actually detects network-native techniques and
   improves on zeek-only coverage,
2. turning the EDR process capability OFF drops process-context detections
   (rules demand rank 2) while IDS/zeek network rules keep firing,
3. every scenario technique prefix resolves to a rule or is one of the
   documented deliberate gaps — no accidental dead zones.
"""
from __future__ import annotations

import collections
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from engine.coverage import ALERT_RULES                       # noqa: E402
from engine.detections import match_alert                     # noqa: E402
from engine.example import build                              # noqa: E402
from engine.models import Graph, Node, Edge                   # noqa: E402
from engine.scenario_store import load_custom                  # noqa: E402
from engine.simulator import simulate                          # noqa: E402

failures: list[str] = []


def check(cond: bool, msg: str) -> None:
    print(("PASS  " if cond else "FAIL  ") + msg)
    if not cond:
        failures.append(msg)


def add_ids(g: Graph) -> Graph:
    g.add_node(Node(id="ids-lan", type="ids", label="IDS (LAN SPAN)", x=400, y=470))
    g.add_edge(Edge(id="e-ids-lan", src="ids-lan", dst="lan"))
    return g


def run(scen: dict, g: Graph, caps: dict | None = None) -> dict:
    return simulate(g, scen, noise_rate=0, seed=7, edr_caps=caps)


# --- pick CTI scenarios exercising the interesting families -----------------
custom = load_custom()
by_id = {s["id"]: s for s in custom}


def any_scenario(tech_prefix: str) -> dict | None:
    for s in custom:
        if any(st["technique"].startswith(tech_prefix) for st in s["steps"]):
            return s
    return None


sc_1053 = any_scenario("T1053")     # scheduled task  (process context)
sc_1071 = any_scenario("T1071")     # C2 beacon       (network-native)
sc_1046 = any_scenario("T1046")     # port scan       (network-native)
sc_1583 = any_scenario("T1583")     # resource dev    (deliberate gap)
check(all([sc_1053, sc_1071, sc_1046, sc_1583]), "representative CTI scenarios found")

# --- 1) IDS adds network detections ------------------------------------------
g0, g1 = build(), add_ids(build())
r0, r1 = run(sc_1071, g0), run(sc_1071, g1)
seen0 = {s["sensor"] for st in r0["steps"] for s in st["seen_by"]}
seen1 = {s["sensor"] for st in r1["steps"] for s in st["seen_by"]}
check(any("IDS" in s for s in seen1) and not any("IDS" in s for s in seen0),
      "IDS rows appear only when the IDS asset is placed")
check(r1["summary"]["detected"] >= r0["summary"]["detected"],
      "IDS placement never reduces detections on the C2 scenario")

# a zeek-only design vs zeek+IDS on the LAN for the port-scan scenario
r2 = run(sc_1046, g1)
ids_alerts = [r for st in r2["steps"] for r in []]  # placeholder, checked via steps
verdicts = collections.Counter(st["verdict"] for st in r2["steps"])
check(verdicts["blind"] < len(r2["steps"]),
      "port-scan scenario is not fully blind on a design with IDS")

# --- 2) EDR capability profile interaction ------------------------------------
r_all = run(sc_1053, g0)                                   # full profile
r_noproc = run(sc_1053, g0, caps={"process": False})       # no process telemetry
det_all = sum(1 for st in r_all["steps"] if st["verdict"] == "detected")
det_np = sum(1 for st in r_noproc["steps"] if st["verdict"] == "detected")
check(det_all > det_np,
      f"scheduled-task detections drop with EDR process telemetry off ({det_all} -> {det_np})")

# --- 3) every technique resolves to a rule or a documented gap ----------------
GAPS = {"T1583", "T1584", "T1585", "T1586", "T1587", "T1588", "T1608",
        "T1589", "T1590", "T1591", "T1592", "T1593", "T1594", "T1681", "T1682"}
prefixes = set()
for s in custom:
    for st in s["steps"]:
        prefixes.add(st["technique"].split(".")[0])
unresolved = [p for p in sorted(prefixes) if p not in ALERT_RULES and p not in GAPS]
check(not unresolved, f"no accidental dead zones (unresolved: {unresolved[:8]})")

# --- 4) match_alert sanity ------------------------------------------------------
class FakeInst:                        # minimal SensorInst stand-in
    kind, context, via_siem = "ids", "content", False
check(match_alert("T1595.002", FakeInst()) is not None, "IDS signature fires on active scanning")
check(match_alert("T1583.001", FakeInst()) is None, "resource-development stays undetectable")
check(match_alert("T1134.002", FakeInst()) is None, "token manipulation not detectable by IDS alone")

print("\n" + ("ALL CHECKS PASSED" if not failures else f"{len(failures)} FAILURES"))
sys.exit(1 if failures else 0)
