"""Run every scenario against the example design and summarise verdicts.

Usage:  python scripts/verdict_stats.py [--list]

Used to verify detection-catalog changes: the verdict distribution across
all CTI scenarios is the quick health metric (how many steps can actually
be *detected* rather than merely observed).
"""
from __future__ import annotations

import collections
import pathlib
import sys

HERE = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from engine.coverage import ALERT_RULES                       # noqa: E402
from engine.example import build                              # noqa: E402
from engine.scenarios import SCENARIOS, SCENARIOS_BY_ID        # noqa: E402
from engine.simulator import simulate                          # noqa: E402
from engine import scenario_store as store                     # noqa: E402


def main() -> None:
    g = build()
    all_scen = SCENARIOS + store.load_custom()
    verdicts = collections.Counter()
    detected_techs = collections.Counter()
    for sc in all_scen:
        rec = simulate(g, sc, noise_rate=0, seed=42)
        for st in rec["steps"]:
            verdicts[st["verdict"]] += 1
            if st["verdict"] == "detected":
                detected_techs[st["technique"].split(".")[0]] += 1

    print(f"scenarios: {len(all_scen)}   alert-rule families: {len(ALERT_RULES)}")
    print("verdicts:", dict(verdicts.most_common()))
    if "--list" in sys.argv:
        print("technique families ever DETECTED:")
        for t, c in sorted(detected_techs.items()):
            print(f"  {t:7} x{c}")
    else:
        print(f"distinct technique families detected: {len(detected_techs)}/130")


if __name__ == "__main__":
    main()
