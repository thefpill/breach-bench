# Security Architecture Playground

Draw a security architecture → pick an adversary scenario → watch the kill chain
propagate through **your** design → read what your sensors actually saw.

The core idea: **observability, not percentages.** Verdicts are never "87% blocked".
A step is *blocked* if a control stops it, *detected* if an alert fired, *observed*
if rows exist but nobody pages anyone, and *blind* if no telemetry covered it at
all — blind spots are experienced, not reported.

Built with Python (FastAPI) + a small dependency-free JavaScript frontend.

## Quick start

```bash
pip install -r requirements.txt
python main.py            # → http://localhost/  (port 80)
```

## How to play

1. **Draw a design.** Drag components from the palette onto the canvas (or click
   a palette item, then click the canvas). Link components with the *Link /
   unlink* tool (click node A, then node B — same gesture toggles a connection),
   or select any wire and press Del. Every connection also has an *unlink*
   button in the inspector. For big designs: **the mouse wheel zooms** (and the
   `− / 100% / +` controls), hold **Space and drag to pan** (grab cursor),
   the canvas **grows as you drag an asset toward its
   edge** (there is no fixed size — scrollbars pan the expanded world),
   **dragging on empty canvas
   rubber-band selects** several assets (shift-click adds) so you can move or
   delete them as one, and the **◉ on any node hides just that asset's
   connection lines** — a SIEM wired to six places stops drawing six wires;
   *unhide lines* brings everything back. Hidden lines are view-only: the
   simulation is unaffected, and the preference survives export/import.
2. **Configure hosts directly on the asset.** Select any host and toggle its
   own telemetry in the inspector:
   * **EDR agent** — full process tree, command lines, network with process
     attribution; can block some techniques (e.g. credential dumping).
   * **Sysmon / Windows event log** — process creation, logons (4624); Windows
     hosts only, no network attribution. Linux servers show it disabled —
     a deliberate blind spot.
   Active toggles appear as small badges (EDR / SYS) under the node label, just
   like DENY / SEG / MFA / LOCK badges for firewall, IdP and bucket settings.
3. **Pick a scenario and Run.** The kill chain replays documented tradecraft
   (ATT&CK Groups procedure examples + Atomic Red Team style command snippets)
   step by step against your design.
4. **Read both views.**
   * *Defender console* — only what your sensors actually produced, mixed with
     benign noise (alert fatigue is part of the game). Steps without sensor
     coverage never appear at all. Toggle *show unseen activity* to compare
     with the ground truth.
   * *Adversary view* — the full kill chain with per-step verdicts
     (blocked / detected / observed / blind) and who saw what.
   * *Coverage matrix* — which data source is observable on which component.
   * *Summary* — observability accounting and concrete things to try.

## Scenario editor

Click **Scenarios** in the top bar to open the full-screen editor:

* create new scenarios from scratch (steps, ATT&CK technique IDs, data-source
  tagged ground-truth events, target component, timing windows),
* **duplicate a built-in** scenario to make an editable copy (built-ins document
  real tradecraft and stay read-only),
* edit and delete your own scenarios — they persist in `data/scenarios.json`
  and appear in the top-bar picker immediately.

Validation runs server-side: technique IDs must look like `T1566.001`, every
step needs at least one ground-truth event with a real ATT&CK data source, and
targets must be components that can actually exist in a design.

## CTI scenario library (auto-generated)

The picker also carries a generated scenario per ATT&CK group (ids prefixed
`cti-`, shown as *custom*, editable like any user scenario). Each is a 1–12
step kill chain built from the group's documented procedures in the MITRE
CTI bundle:

```bash
# one-time: fetch the CTI bundle (~50 MB)
curl -L -o scripts/data/enterprise-attack.json \
  https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

python scripts/extract_attack.py      # CTI bundle -> scripts/data/mitre-attack-groups.json
python scripts/generate_scenarios.py  # that JSON  -> data/scenarios.json
```

`extract_attack.py` pulls every group → technique pair with its tactics,
procedure text and the best concrete command/API call found in the procedure
(e.g. Lazarus + T1134.002 → `CreateProcessAsUserA`), and maps ATT&CK data
components onto the engine's sensor vocabulary. `generate_scenarios.py`
converts it into validated kill chains ordered along the 14 tactics.
Re-running rebuilds all `cti-*` scenarios; user-authored ones are never
touched. The app ships with the library already generated.

## EDR telemetry profile

Click **EDR profile** in the top bar to control what the EDR product actually
reports — one policy applied to every host with the EDR toggle:

* **process & command line** — the anchor sense; off, the agent degrades to a
  dumb 5-tuple logger and context-hungry alerts stop firing,
* **file writes & access**, **process access / injection**, **network
  connections with process attribution**, **logon sessions (4624/4625)** —
  each toggles its data sources out of the EDR subscription,
* **credential-theft prevention** — a *protection*, not telemetry: off means
  LSASS dumping (T1003) succeeds even on EDR hosts.

The profile persists in the browser and is sent with every `/api/simulate`
request; the coverage matrix and both consoles reflect it on the next run.

## Design → engine join model

Every scenario step emits ground-truth events tagged with ATT&CK **data
sources** (Process Creation, Network Connection Creation, Cloud Logon, …).
Sensors subscribe to data sources *and* only cover their location:

| sensor | subscribes to | context |
| --- | --- | --- |
| EDR (host toggle) | capability profile (process / file / injection / net attribution; logon optional) | full — degrades to 5-tuple when process telemetry is off |
| Sysmon (host toggle, Win only) | process / command / file / process access / logon | process-only |
| Zeek (SPAN on a segment) | net connections, traffic content | network metadata |
| IDS / NDR (SPAN on a segment) | net connections, traffic content | payload signatures — detects, rarely explains |
| NetFlow (segment or firewall) | net connections | 5-tuple |
| Firewall / WAF / Mail GW (in path) | connections / payloads / email | own logs |
| Cloud services | cloud logon / API / storage | API audit rows — visible **only** via a SIEM link |
| SIEM | whatever is shipped to it | mirrors its inputs |

Detection rules require enough *context* (a bare 5-tuple cannot attribute a C2
beacon to a process; an EDR can). Blocking rules check the drawn path (WAF,
mail gateway, egress/segmentation) or asset properties (MFA, hardened bucket).

## Detection catalog

The alert rules for every ATT&CK technique family used by the scenario
library live in `engine/detections.py` — one annotated, greppable table:
technique prefix → which sensor kinds carry analytics for it and the minimum
context rank they need (e.g. scheduled tasks: EDR/SIEM with process context;
internal port scan: EDR, IDS or Zeek; cloud policy change: SIEM at any rank).
A visible row without a matching rule stays verdict *observed* — rows are not
detections. Reconnaissance/resource-development techniques (T1583–T1595)
have **no** rule on purpose: that activity happens in attacker-owned space,
outside anything you can draw.

## File guide (small, single-purpose, commented)

```
main.py                  FastAPI server + REST API (scenarios CRUD, EDR caps, simulate)
engine/
  models.py              Node / Edge / Graph + BFS path finding
  scenarios.py           the three built-in ATT&CK-mapped scenarios
  scenario_store.py      custom scenario persistence + validation (data/)
  coverage.py            data sources × sensor subscriptions, EDR capability
                         profile, block rules
  detections.py          the detection catalog: technique family → sensor
                         analytics + minimum context ("detection assets")
  simulator.py           the kill-chain runner → playback "recording"
  noise.py               benign background noise (alert fatigue)
  example.py             the bundled example architecture
static/
  index.html             shell: topbar, canvas, panels, overlays
  style.css              dark SOC theme
  js/canvas.js           interactive editor (drag & drop, toggles, unlink)
  js/player.js           playback engine (seek, speed, step reveal)
  js/editor.js           the scenario editor overlay
  js/edr.js              the EDR telemetry profile overlay
  js/app.js              glue: API calls, tabs, console rendering
scripts/
  extract_attack.py      MITRE CTI bundle -> group/technique/command JSON
  generate_scenarios.py  that JSON -> cti-* scenarios in the store
  data/                  the CTI bundle + generated JSON (not shipped)
```
