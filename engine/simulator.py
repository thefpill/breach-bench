"""The kill-chain runner.

simulate(graph, scenario, noise_rate) walks the scenario step by step:

  1. resolve the target component each step lands on (propagation through
     the drawn design, preferring the previous step's segment),
  2. find the path from the Internet entry point to that target,
  3. check blocking controls (WAF, mail gateway, firewall segmentation,
     EDR protection, MFA, bucket policy),
  4. materialise ground-truth events tagged with ATT&CK data sources and
     resolve which sensors would surface each one,
  5. grade the step: blocked / detected / observed-only / blind,
  6. mix benign noise into the defender timeline (alert fatigue),
  7. build the coverage matrix + observability summary.

The result is a self-contained "recording" the frontend plays back.
"""
from __future__ import annotations

import random
from collections import defaultdict

from .models import Graph, Node, TARGETABLE_TYPES, CLOUD_KINDS
from .coverage import (Coverage, DATA_SOURCES, KIND_TAG, SENSOR_SPECS,
                       check_blocks, match_alert, NETWORK_DS)
from .noise import generate_noise

DEFAULT_WINDOW = 75  # simulated seconds per step (steps may override)


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _resolve_target(graph: Graph, step: dict, prev: Node | None) -> Node | None:
    """Pick the node this step lands on. Prefers the previous step's subnet
    so lateral movement stays local when the design allows it."""
    t = step["target_type"]
    if t not in TARGETABLE_TYPES:
        return None
    cands = graph.by_type(t)
    if not cands:
        return None
    if prev is not None:
        # same-subnet preference: walk neighbors of prev for a subnet, then hosts
        prev_subnets = [graph.node(nb).id for nb in graph.neighbors(prev.id)
                        if graph.node(nb) and graph.node(nb).type == "subnet"]
        for c in cands:
            c_subnets = [graph.node(nb).id for nb in graph.neighbors(c.id)
                         if graph.node(nb) and graph.node(nb).type == "subnet"]
            if set(c_subnets) & set(prev_subnets):
                return c
    return cands[0]


def _fmt_sensor(inst) -> dict:
    return {"sensor": inst.siem_label if inst.via_siem else inst.label,
            "kind": inst.kind, "via_siem": inst.via_siem, "context": inst.context}


def _seen_detail(inst) -> str:
    ctx = {
        "full": "full process tree + cmdline + network w/ process attribution",
        "process_only": "process + command line (no network attribution)",
        "network_meta": "network metadata (SNI/bytes) only — no process",
        "tuple": "raw 5-tuple only",
        "content": "full payload content",
        "api": "API audit row (user, action, source IP)",
    }.get(inst.context, inst.context)
    via = " (via SIEM)" if inst.via_siem else ""
    return f"{inst.siem_label if inst.via_siem else inst.label}{via}: {ctx}"


# ---------------------------------------------------------------------------
# main entry
# ---------------------------------------------------------------------------
def simulate(graph: Graph, scenario: dict, noise_rate: int = 20,
             seed: int | None = None) -> dict:
    rng = random.Random(seed)
    coverage = Coverage(graph)
    entry = next((n for n in graph.nodes if n.type == "internet"), None)
    has_entry = entry is not None

    rec_steps: list[dict] = []
    gt_events: list[dict] = []       # ground truth (adversary view)
    defender_rows: list[dict] = []   # visible attacker rows (noise added later)

    prev_target: Node | None = None
    stopped: dict | None = None      # (reason, at_step) once the chain halts
    t0 = 0.0

    for idx, step in enumerate(scenario["steps"]):
        n = idx + 1
        window = step.get("window", DEFAULT_WINDOW)

        base = {"n": n, "tactic": step["tactic"], "technique": step["technique"],
                "name": step["name"], "group": scenario["group"],
                "procedure": step["procedure"], "command": step["command"],
                "cmd_source": step["cmd_source"], "t_start": round(t0, 1),
                "t_end": round(t0 + window, 1)}

        # ---- chain already halted? -----------------------------------------
        if stopped:
            rec_steps.append({**base, "target": "", "verdict": "not_reached",
                              "why": stopped["why"], "seen_by": [], "blocked_at": None})
            continue

        # ---- resolve target & path ------------------------------------------
        target = _resolve_target(graph, step, prev_target)
        if target is None:
            why = (f"No component of type '{step['target_type']}' exists in the design "
                   f"for this step to land on — the chain cannot proceed.")
            stopped = {"why": why, "at": n}
            rec_steps.append({**base, "target": "", "verdict": "unreachable",
                              "why": why, "seen_by": [], "blocked_at": None})
            continue

        path_ids = graph.find_path(entry.id, target.id) if entry else None
        path_note = None
        if not has_entry:
            path_note = ("no Internet entry point is drawn, so path-based controls "
                         "(WAF, mail gateway, egress firewall) were not evaluated")

        # ---- 1) blocking controls -------------------------------------------
        block = check_blocks(graph, step["technique"], target, path_ids, coverage)

        # ---- 2) ground-truth events + visibility ------------------------------
        emits = step["emits"]
        step_rows: list[dict] = []
        seen: dict[tuple, dict] = {}
        alerting: list[str] = []
        missing_ds: list[str] = []

        for i, e in enumerate(emits):
            frac = e.get("at") if e.get("at") is not None else (i + 0.5) / len(emits)
            ts = t0 + max(0.0, min(1.0, frac)) * window + rng.uniform(-1.5, 1.5)
            gtev = {"ts": round(max(0.0, ts), 1), "ds": e["ds"],
                    "process": e.get("process") or "", "cmd": e.get("cmd") or "",
                    "details": e.get("details") or {}, "host": target.label,
                    "malicious": True, "step": n}
            sensors = coverage.visible_sensors(e, target, path_ids)
            gtev["visible_to"] = sorted({
                (s.siem_label if s.via_siem else s.label) for s in sensors})
            gtev["covered"] = bool(sensors)
            gt_events.append(gtev)

            if not sensors:
                if e["ds"] not in missing_ds:
                    missing_ds.append(e["ds"])
                continue

            for inst in sensors:
                seen[(inst.siem_label if inst.via_siem else inst.label)] = _seen_detail(inst)
                reason = match_alert(step["technique"], inst)
                row = {**gtev,
                       "sensor": inst.siem_label if inst.via_siem else inst.label,
                       "kind": inst.kind,
                       "source_kind": inst.kind if inst.via_siem else None,
                       "alert": bool(reason), "alert_reason": reason}
                step_rows.append(row)
                if reason and inst.label not in alerting:
                    alerting.append(inst.label)

        # ---- 3) verdict --------------------------------------------------------
        # NOTE: a blocked step still shows whatever telemetry covered the *attempt*
        # (that's how defenders learn a control fired) — we do not clear rows here.
        blocked_at, blocked_at_id = None, None
        if block:
            label, text, ctrl_id = block
            why = f"BLOCKED — {label} ({text})."
            verdict = "blocked"
            stopped = {"why": f"The kill chain was stopped at step {n} "
                              f"({step['technique']} {step['name']}).", "at": n}
            blocked_at, blocked_at_id = label, ctrl_id
        elif alerting:
            verdict = "detected"
            why = (f"ALERT raised by {', '.join(alerting)} — "
                   f"{'; '.join(sorted({r['alert_reason'] for r in step_rows if r['alert']}, key=str))}.")
            if missing_ds:
                why += (f" Data sources with no coverage here: "
                        f"{', '.join(missing_ds)} — those rows never existed.")
            blocked_at = None
        elif step_rows:
            verdict = "observed"
            why = ("Visible in sensor logs but no detection rule fired — rows only, "
                   "no alert. Something to read, nothing that page anyone.")
            if missing_ds:
                why += (f" Data sources with no coverage here: {', '.join(missing_ds)} "
                        f"— those rows never existed.")
            blocked_at = None
        else:
            verdict = "blind"
            parts = [f"No telemetry covers {', '.join(missing_ds)} on {target.label}."]
            if path_note:
                parts.append(f"Also: {path_note}.")
            why = " ".join(parts)
            blocked_at = None

        rec_steps.append({**base, "target": target.label, "target_id": target.id,
                          "verdict": verdict, "why": why,
                          "seen_by": [{"sensor": k, "detail": v} for k, v in
                                      sorted(seen.items())],
                          "blocked_at": blocked_at, "blocked_at_id": blocked_at_id,
                          "path": list(path_ids) if path_ids else []})
        defender_rows.extend(step_rows)
        prev_target = target
        t0 += window

    total_T = t0 if t0 > 0 else 300.0

    # ---- benign noise ---------------------------------------------------------
    noise_rows = generate_noise(graph, coverage, total_T, noise_rate, seed=seed)
    defender = sorted(defender_rows + noise_rows, key=lambda r: r["ts"])

    # ---- coverage matrix --------------------------------------------------------
    matrix = _coverage_matrix(graph, coverage)

    # ---- summary ------------------------------------------------------------------
    counts = defaultdict(int)
    for s in rec_steps:
        counts[s["verdict"]] += 1
    visible_att = sum(1 for g in gt_events if g["covered"])

    return {
        "scenario": {"id": scenario["id"], "name": scenario["name"],
                     "group": scenario["group"], "blurb": scenario["blurb"]},
        "duration": round(total_T, 1),
        "steps": rec_steps,
        "events": sorted(gt_events, key=lambda e: e["ts"]),
        "defender": defender,
        "matrix": matrix,
        "summary": {
            "blocked": counts["blocked"], "detected": counts["detected"],
            "observed": counts["observed"], "blind": counts["blind"],
            "unreachable": counts["unreachable"], "not_reached": counts["not_reached"],
            "attacker_events": len(gt_events),
            "visible_events": visible_att,
            "noise_events": len(noise_rows),
            "duration": round(total_T, 1),
        },
    }


# ---------------------------------------------------------------------------
# coverage matrix: rows = data sources, columns = observable components
# ---------------------------------------------------------------------------
def _coverage_matrix(graph: Graph, coverage: Coverage) -> dict:
    columns: list[dict] = []

    def col(n: Node, group: str) -> str:
        columns.append({"id": n.id, "label": n.label, "group": group})
        return n.id

    # hosts grouped by their subnet, then freestanding observables
    seen_subnets: set[str] = set()
    for h in graph.hosts():
        sub = coverage.host_subnet.get(h.id)
        group = graph.node(sub).label if sub and graph.node(sub) else ""
        col(h, group)
        if sub:
            seen_subnets.add(sub)
    for n in graph.nodes:
        if n.type in CLOUD_KINDS or n.type in ("waf", "firewall", "mail_gateway"):
            col(n, "cloud" if n.type in CLOUD_KINDS else "perimeter")

    rows = []
    for ds in DATA_SOURCES:
        cells: dict[str, list[str]] = {}
        for c in columns:
            n = graph.node(c["id"])
            tags: list[str] = []
            if n:
                if n.type in CLOUD_KINDS:
                    tags += [KIND_TAG["cloud_audit"]] if ds in SENSOR_SPECS["cloud_audit"]["sources"] else []
                elif n.type in ("waf", "firewall", "mail_gateway"):
                    tags += [KIND_TAG[n.type]] if ds in SENSOR_SPECS[n.type]["sources"] else []
                else:  # a host
                    for inst in coverage.host_sensors.get(n.id, []):
                        if inst.via_siem:
                            continue
                        if ds in SENSOR_SPECS[inst.kind]["sources"]:
                            tag = KIND_TAG[inst.kind]
                            if tag not in tags:
                                tags.append(tag)
            cells[c["id"]] = tags
        rows.append({"ds": ds, "cells": cells})
    return {"columns": columns, "rows": rows}
