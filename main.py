"""FastAPI server for the security architecture playground.

Serves:
  GET    /                     the canvas UI (static/index.html)
  GET    /static/...           css + js
  GET    /api/scenarios        scenario list for the picker (builtin + custom)
  GET    /api/scenarios/{id}   one full scenario (for the editor)
  POST   /api/scenarios        create / update a custom scenario
  DELETE /api/scenarios/{id}   delete a custom scenario
  GET    /api/meta             vocabularies for the scenario editor
  GET    /api/edr/caps         EDR capability catalog for the profile page
  GET    /api/example          the bundled example graph
  POST   /api/simulate         run a kill chain against a drawn design
                               (accepts the `edr_caps` telemetry profile)

Run standalone:   python main.py                     (http://localhost/ — port 80)
Run in sandbox:   uvicorn main:app --host 0.0.0.0 --port 3000
"""
from __future__ import annotations

import argparse
import os
import pathlib
import socket
import sys

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from engine import example, scenario_store, scenarios
from engine.coverage import DEFAULT_EDR_CAPS, EDR_CAPABILITIES
from engine.models import Graph
from engine.simulator import simulate

ROOT = pathlib.Path(__file__).parent
app = FastAPI(title="Security Architecture Playground")

app.mount("/static", StaticFiles(directory=ROOT / "static"), name="static")


# ---------------------------------------------------------------------------
# UI entry point — injects the gateway query string when running behind the
# sandbox proxy (XTransformPort), so the same files work locally and hosted.
# ---------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    xtp = request.query_params.get("XTransformPort")
    qs = f"?XTransformPort={xtp}" if xtp else ""
    return HTMLResponse(html.replace("__XTPQ__", qs))


# ---------------------------------------------------------------------------
# Scenario API (read-only built-ins + editable custom scenarios)
# ---------------------------------------------------------------------------
@app.get("/api/scenarios")
def list_scenarios():
    out = []
    for s in scenarios.SCENARIOS:
        out.append({"id": s["id"], "name": s["name"], "group": s["group"],
                    "blurb": s["blurb"], "builtin": True,
                    "steps": [{"technique": st["technique"], "name": st["name"],
                               "tactic": st["tactic"]} for st in s["steps"]]})
    for s in scenario_store.load_custom():
        out.append({"id": s["id"], "name": s["name"], "group": s["group"],
                    "blurb": s.get("blurb", ""), "builtin": False,
                    "steps": [{"technique": st["technique"], "name": st["name"],
                               "tactic": st["tactic"]} for st in s["steps"]]})
    return out


def _find_scenario(sid: str) -> dict | None:
    """Built-ins take precedence; custom scenarios share the namespace."""
    if sid in scenarios.SCENARIOS_BY_ID:
        return {**scenarios.SCENARIOS_BY_ID[sid], "builtin": True}
    custom = scenario_store.find_custom(sid)
    return {**custom, "builtin": False} if custom else None


@app.get("/api/scenarios/{sid}")
def get_scenario(sid: str):
    s = _find_scenario(sid)
    if s is None:
        return JSONResponse({"error": "unknown scenario id"}, status_code=404)
    return s


@app.post("/api/scenarios")
async def save_scenario(request: Request):
    body = await request.json()
    scenario = body.get("scenario") or {}
    orig_id = body.get("orig_id")          # set when the editor renamed a copy
    builtin_ids = set(scenarios.SCENARIOS_BY_ID)
    try:
        # auto-id for new scenarios drafted in the editor
        if not scenario.get("id") and not orig_id:
            scenario["id"] = scenario_store.slugify(scenario.get("name", ""))
        if scenario.get("id") in builtin_ids and scenario.get("id") != orig_id:
            return JSONResponse({"error": "that id belongs to a built-in scenario — "
                                          "duplicate it under a new name instead"},
                                status_code=400)
        stored = scenario_store.upsert(scenario, orig_id=orig_id)
        return {"id": stored["id"]}
    except ValueError as exc:
        return JSONResponse({"error": str(exc)}, status_code=400)
    except Exception as exc:  # noqa: BLE001
        return JSONResponse({"error": f"could not save scenario: {exc}"}, status_code=500)


@app.delete("/api/scenarios/{sid}")
def delete_scenario(sid: str):
    if sid in scenarios.SCENARIOS_BY_ID:
        return JSONResponse({"error": "built-in scenarios cannot be deleted — "
                                      "duplicate one and edit the copy"},
                            status_code=400)
    try:
        scenario_store.delete(sid)
        return {"ok": True}
    except KeyError:
        return JSONResponse({"error": "unknown scenario id"}, status_code=404)


@app.get("/api/meta")
def editor_meta():
    """Vocabularies the scenario editor needs for its dropdowns."""
    return {
        "data_sources": scenario_store.DATA_SOURCES,
        "target_types": sorted(scenario_store.TARGETABLE_TYPES),
        "target_labels": scenario_store.TARGET_LABELS,
        "tactics": scenario_store.TACTICS,
    }


@app.get("/api/edr/caps")
def edr_caps_meta():
    """The EDR capability catalog for the 'EDR profile' page: what an agent
    can report, what each stream feeds, and the default policy."""
    return {
        "capabilities": [
            {"key": c["key"], "label": c["label"], "desc": c["desc"],
             "ds": c.get("ds", []), "protect": bool(c.get("protect")),
             "default": DEFAULT_EDR_CAPS[c["key"]]}
            for c in EDR_CAPABILITIES
        ],
        "defaults": DEFAULT_EDR_CAPS,
    }


@app.get("/api/example")
def example_graph():
    return example.build().to_dict()


@app.post("/api/simulate")
async def run_simulation(request: Request):
    body = await request.json()
    try:
        graph = Graph.from_dict(body.get("graph", {}))
        scenario = _find_scenario(body.get("scenario_id"))
        if scenario is None:
            return JSONResponse({"error": "unknown scenario_id"}, status_code=400)
        noise_rate = max(0, min(200, int(body.get("noise_rate", 20))))
        # the EDR telemetry profile toggled on the "EDR profile" page
        edr_caps = body.get("edr_caps")
        edr_caps = edr_caps if isinstance(edr_caps, dict) else None
        recording = simulate(graph, scenario, noise_rate=noise_rate,
                             edr_caps=edr_caps)
        return recording
    except Exception as exc:  # noqa: BLE001 — surface engine errors to the UI
        return JSONResponse({"error": f"simulation failed: {exc}"}, status_code=500)


if __name__ == "__main__":
    # ------------------------------------------------------------------
    # Port 80 by default (plain http://localhost/). Override with
    # --port N or the PORT env var. Ports below 1024 need extra rights
    # on Linux, so we probe the bind first and give an actionable hint
    # instead of uvicorn's bare "[Errno 13]" line.
    # ------------------------------------------------------------------
    ap = argparse.ArgumentParser(description="Security Architecture Playground")
    ap.add_argument("--host", default="0.0.0.0",
                    help="bind address (default: all interfaces; "
                         "use 127.0.0.1 for localhost only)")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("PORT", "80")),
                    help="TCP port (default: 80, or $PORT)")
    args = ap.parse_args()

    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        probe.bind((args.host, args.port))
    except PermissionError:
        print(f"cannot bind port {args.port}: permission denied.\n"
              "Ports below 1024 need extra rights on Linux. Pick one:\n"
              f"  1. run again with sudo:      sudo {sys.executable} main.py"
              f" --host {args.host} --port {args.port}\n"
              "  2. allow python to use low ports once:\n"
              "       sudo setcap 'cap_net_bind_service=+ep' "
              "$(readlink -f $(which python3))\n"
              "  3. or use an unprivileged port:  python main.py --port 8000")
        raise SystemExit(1)
    except OSError as exc:
        print(f"cannot bind {args.host}:{args.port}: {exc} "
              "(is another server already listening there? "
              "try --port 8000)")
        raise SystemExit(1)
    finally:
        probe.close()

    uvicorn.run(app, host=args.host, port=args.port)
