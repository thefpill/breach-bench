"""FastAPI server for the security architecture playground.

Serves:
  GET    /                     the canvas UI (static/index.html)
  GET    /static/...           css + js
  GET    /api/scenarios        scenario list for the picker (builtin + custom)
  GET    /api/scenarios/{id}   one full scenario (for the editor)
  POST   /api/scenarios        create / update a custom scenario
  DELETE /api/scenarios/{id}   delete a custom scenario
  GET    /api/meta             vocabularies for the scenario editor
  GET    /api/example          the bundled example graph
  POST   /api/simulate         run a kill chain against a drawn design

Run standalone:   python main.py                     (http://localhost:8000)
Run in sandbox:   uvicorn main:app --host 0.0.0.0 --port 3000
"""
from __future__ import annotations

import pathlib

import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from engine import example, scenario_store, scenarios
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
        recording = simulate(graph, scenario, noise_rate=noise_rate)
        return recording
    except Exception as exc:  # noqa: BLE001 — surface engine errors to the UI
        return JSONResponse({"error": f"simulation failed: {exc}"}, status_code=500)


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
