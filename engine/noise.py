"""Benign background noise — alert fatigue as a game mechanic.

The defender console is NOT a clean list of attacker events: it is a log
stream in which ~dozens of harmless events arrive per simulated minute.
Noise rows are emitted by sensors that actually exist in the design (you
cannot get Sysmon noise from a host without Sysmon), which makes the mix
feel like a real console.

Rows carry `malicious: False` and never trigger alerts; attacker rows that
merely got *observed* (no detection rule fired) are formatted identically,
so the analyst has to actually read them.
"""
from __future__ import annotations

import random

from .models import Graph, HOST_TYPES, WINDOWS_TYPES
from .coverage import Coverage

# Template pool. `kind` = sensor kind that produces the row; `pool` restricts
# the host pick (windows / linux / any / cloud / appliance-with-that-kind).
TEMPLATES: list[dict] = [
    # --- Sysmon / Windows event log noise -----------------------------------
    {"kind": "sysmon", "pool": "windows", "ds": "Logon Session Creation",
     "process": "", "cmd": "", "details": {"event": "4624", "logon_type": "2 (interactive)",
                                           "user": "j.smith", "result": "success"}},
    {"kind": "sysmon", "pool": "windows", "ds": "Process Creation",
     "process": "explorer.exe → chrome.exe",
     "cmd": "\"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\""},
    {"kind": "sysmon", "pool": "windows", "ds": "Process Creation",
     "process": "explorer.exe → Teams.exe", "cmd": "Teams.exe --background"},
    {"kind": "sysmon", "pool": "windows", "ds": "Process Creation",
     "process": "services.exe → MsMpEng.exe",
     "cmd": "MsMpEng.exe -Scan -ScanType 1 (scheduled, clean)"},
    {"kind": "sysmon", "pool": "windows", "ds": "Logon Session Creation",
     "process": "", "cmd": "", "details": {"event": "4624", "logon_type": "3 (network)",
                                           "user": "CORP\\svc_backup", "result": "success"}},
    # --- EDR noise -----------------------------------------------------------
    {"kind": "edr", "pool": "any", "ds": "Process Creation",
     "process": "explorer.exe → OneDrive.exe", "cmd": "OneDrive.exe /background"},
    {"kind": "edr", "pool": "any", "ds": "File Creation",
     "process": "chrome.exe", "cmd": "write %TEMP%\\tmp7A3F.tmp (2 KB)"},
    {"kind": "edr", "pool": "any", "ds": "Process Creation",
     "process": "services.exe → svchost.exe (-k netsvcs)", "cmd": "routine service start"},
    # --- Zeek (network metadata) noise ---------------------------------------
    {"kind": "zeek", "pool": "any", "ds": "Network Connection Creation",
     "process": "", "cmd": "",
     "details": {"dst": "151.101.1.67:443", "sni": "cdn.jsdelivr.net", "bytes_out": "210 KB"}},
    {"kind": "zeek", "pool": "any", "ds": "Network Connection Creation",
     "process": "", "cmd": "",
     "details": {"dst": "52.113.194.132:443", "sni": "teams.microsoft.com", "bytes_out": "88 KB"}},
    {"kind": "zeek", "pool": "any", "ds": "Network Traffic Content",
     "process": "", "cmd": "",
     "details": {"method": "GET", "path": "/assets/app.3f2a.js", "status": 200}},
    # --- IDS (signature engine) noise -----------------------------------------
    {"kind": "ids", "pool": "any", "ds": "Network Traffic Content",
     "process": "", "cmd": "",
     "details": {"signature": "ET INFO Observed DNS Query to CDN Domain",
                 "category": "info", "priority": 3}},
    {"kind": "ids", "pool": "any", "ds": "Network Traffic Content",
     "process": "", "cmd": "",
     "details": {"signature": "ET POLICY HTTP GET to known software-update host",
                 "category": "policy", "priority": 3}},
    # --- NetFlow noise ---------------------------------------------------------
    {"kind": "netflow", "pool": "any", "ds": "Network Connection Creation",
     "process": "", "cmd": "",
     "details": {"src": "10.0.20.11:52100", "dst": "13.107.4.50:443", "bytes_out": "12 KB"}},
    {"kind": "netflow", "pool": "any", "ds": "Network Connection Creation",
     "process": "", "cmd": "",
     "details": {"src": "10.0.20.12:51404", "dst": "40.126.6.74:443", "bytes_out": "9 KB"}},
    # --- appliance noise (only if such an appliance exists) --------------------
    {"kind": "firewall", "pool": "appliance", "ds": "Network Connection Creation",
     "process": "", "cmd": "", "details": {"action": "ALLOW", "rule": "corp→any:443"}},
    {"kind": "waf", "pool": "appliance", "ds": "Network Traffic Content",
     "process": "", "cmd": "",
     "details": {"method": "GET", "path": "/health", "status": 200}},
    {"kind": "mail_gateway", "pool": "appliance", "ds": "Email Delivery",
     "process": "", "cmd": "",
     "details": {"subject": "Weekly newsletter", "verdict": "clean"}},
    # --- cloud audit noise (only surfaces if a SIEM is linked) ------------------
    {"kind": "cloud_audit", "pool": "cloud", "ds": "Cloud API Call",
     "process": "", "cmd": "", "details": {"api": "iam:ListRoles", "result": "success",
                                           "note": "config-sync job"}},
    {"kind": "cloud_audit", "pool": "cloud", "ds": "Cloud API Call",
     "process": "", "cmd": "", "details": {"api": "s3:ListBuckets", "result": "success",
                                           "note": "backup monitor"}},
]


def _candidate_hosts(graph: Graph, coverage: Coverage, tpl: dict) -> list[str]:
    """Hosts (or appliance/cloud ids) a given noise template can come from."""
    kind = tpl["kind"]
    pool = tpl["pool"]
    if pool == "appliance":
        return [n.id for n in graph.nodes
                if n.type == kind and kind in ("firewall", "waf", "mail_gateway")]
    if pool == "cloud":
        # cloud audit rows only surface when a SIEM ingests that service
        return [nid for nid in coverage.cloud_sensors
                if coverage.siem_links.get(coverage.cloud_sensors[nid][0].sid)]
    # host pools: windows / linux / any — restricted to hosts with that sensor
    hosts = graph.hosts()
    if pool == "windows":
        hosts = [h for h in hosts if h.type in WINDOWS_TYPES]
    out = []
    for h in hosts:
        for inst in coverage.host_sensors.get(h.id, []):
            if inst.kind == kind and not inst.via_siem:
                out.append(h.id)
                break
    return out


def generate_noise(graph: Graph, coverage: Coverage, t_end: float,
                   rate_per_min: int, seed: int | None = None) -> list[dict]:
    """Fill [0, t_end] with benign rows at `rate_per_min` rows per sim-minute."""
    rng = random.Random(seed)
    rows: list[dict] = []

    # precompute per-template candidate lists
    candidates = []
    for i, tpl in enumerate(TEMPLATES):
        hosts = _candidate_hosts(graph, coverage, tpl)
        if hosts:
            candidates.append((i, hosts))

    if not candidates or rate_per_min <= 0:
        return rows

    total = int(rate_per_min * t_end / 60)
    for _ in range(total):
        i, hosts = rng.choice(candidates)
        tpl = TEMPLATES[i]
        host_node = graph.node(rng.choice(hosts))
        label = host_node.label if host_node else "sensor"
        # find a concrete sensor instance label for that kind on that host
        sensor_label = label
        if tpl["pool"] == "appliance":
            sensor_label = host_node.label
        elif tpl["pool"] == "cloud":
            sensor_label = coverage.cloud_sensors[host_node.id][0].label
        else:
            for inst in coverage.host_sensors.get(host_node.id, []):
                if inst.kind == tpl["kind"]:
                    sensor_label = inst.label
                    break

        rows.append({
            "ts": round(rng.uniform(0, t_end), 1),
            "host": sensor_label.replace(" audit log", ""),
            "ds": tpl["ds"],
            "process": tpl["process"],
            "cmd": tpl["cmd"],
            "details": dict(tpl.get("details", {})),
            "sensor": sensor_label,
            "kind": tpl["kind"],
            "source_kind": None,
            "alert": False,
            "alert_reason": None,
            "malicious": False,
            "step": None,
        })
    rows.sort(key=lambda r: r["ts"])
    return rows
