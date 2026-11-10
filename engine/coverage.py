"""Sensor coverage, detection rules and blocking rules.

This is the join key of the whole system, following MITRE's model:

  * every scenario step emits ground-truth events tagged with an ATT&CK
    *data source* (Process Creation, Network Connection Creation, ...);
  * every sensor subscribes to a set of data sources, and only covers the
    location it is deployed on (its host, subnet or path);
  * an event that is not covered by any sensor simply never reaches the
    defender console — the blind spot is *experienced*, not told.

Context quality model (what a sensor can actually see):
    api          cloud audit log row (API call, no host process context)
    tuple        network 5-tuple only (NetFlow, firewall log)
    network_meta network metadata with SNI/bytes (Zeek)
    process_only process + command line (Sysmon / Windows Event Log)
    full         process tree + command line + network with process
                 attribution (EDR)
    content      payload content (WAF, mail gateway)
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass

from .models import Graph, Node, CLOUD_KINDS, HOST_TYPES, SUBNET_TYPES, WINDOWS_TYPES

# The detection catalog lives in detections.py (technique -> which sensor
# kind has analytics, minimum context rank, alert text). Re-exported here
# so the rest of the engine keeps a single import point.
from .detections import ALERT_RULES, ALERT_TEXT, match_alert  # noqa: F401

# ---------------------------------------------------------------------------
# ATT&CK data sources used by the scenarios (component names, shortened)
# ---------------------------------------------------------------------------
DATA_SOURCES = [
    "Process Creation", "Command Execution", "File Creation", "File Access",
    "Process Access", "Logon Session Creation", "Network Connection Creation",
    "Network Traffic Content", "Email Delivery",
    "Cloud Logon", "Cloud API Call", "Cloud Storage Access",
]
CLOUD_DS = {"Cloud Logon", "Cloud API Call", "Cloud Storage Access"}
NETWORK_DS = {"Network Connection Creation", "Network Traffic Content"}

CONTEXT_RANK = {"api": 0, "tuple": 1, "network_meta": 1,
                "process_only": 2, "full": 3, "content": 3}

# ---------------------------------------------------------------------------
# What each sensor kind subscribes to
# ---------------------------------------------------------------------------
SENSOR_SPECS: dict[str, dict] = {
    # --- deployable endpoint sensors (link onto a host) ---
    "edr":    {"sources": ["Process Creation", "Command Execution", "File Creation",
                           "File Access", "Process Access", "Network Connection Creation"],
               "context": "full", "scope": "host"},
    "sysmon": {"sources": ["Process Creation", "Command Execution", "File Creation",
                           "Process Access", "Logon Session Creation"],
               "context": "process_only", "scope": "host", "os": "windows"},
    # --- network sensors ---
    "zeek":    {"sources": ["Network Connection Creation", "Network Traffic Content"],
                "context": "network_meta", "scope": "subnet"},
    "ids":     {"sources": ["Network Connection Creation", "Network Traffic Content"],
                "context": "content", "scope": "subnet"},
    "netflow": {"sources": ["Network Connection Creation"],
                "context": "tuple", "scope": "subnet_or_firewall"},
    "siem":    {"sources": [], "context": "inherited", "scope": "ingested"},
    # --- appliances with their own native logs (they *are* sensors) ---
    "waf":          {"sources": ["Network Traffic Content"], "context": "content", "scope": "self"},
    "firewall":     {"sources": ["Network Connection Creation"], "context": "tuple", "scope": "self"},
    "mail_gateway": {"sources": ["Email Delivery"], "context": "content", "scope": "self"},
    # --- cloud services keep their own audit logs; rows only reach the
    #     SOC console when a SIEM is linked to the service ---
    "cloud_audit":  {"sources": list(CLOUD_DS), "context": "api", "scope": "self"},
}

# Short tags used in the coverage matrix on the UI
KIND_TAG = {"edr": "EDR", "sysmon": "SYS", "zeek": "ZK", "netflow": "NF",
            "siem": "SIEM", "waf": "WAF", "firewall": "FW",
            "mail_gateway": "MGW", "cloud_audit": "AUD", "ids": "IDS"}

# ---------------------------------------------------------------------------
# EDR capability profile — what the EDR product actually reports.
#
# One profile for the whole design (one EDR product, one policy) applied to
# every host whose per-host EDR toggle is on. Toggled from the "EDR profile"
# page in the UI and passed through /api/simulate as `edr_caps`.
#
#   "ds"      data sources the capability feeds into the EDR subscription
#   "protect" capability gates a BLOCK_RULES prevention instead of telemetry
# ---------------------------------------------------------------------------
EDR_CAPABILITIES = [
    {"key": "process", "label": "Process & command-line telemetry",
     "ds": ["Process Creation", "Command Execution"],
     "desc": ("The EDR's anchor sense: every process spawn with full command "
              "line and parent. Without it the agent degrades to a dumb "
              "5-tuple network logger — no attribution, no context, no "
              "analytics that need process context.")},
    {"key": "file", "label": "File writes & file access",
     "ds": ["File Creation", "File Access"],
     "desc": ("Dropped payloads, staged archives, bulk reads of user data. "
              "The difference between seeing a dropper land and seeing only "
              "the process that later ran it.")},
    {"key": "injection", "label": "Process access & injection monitoring",
     "ds": ["Process Access"],
     "desc": ("LSASS handle requests and cross-process memory access — the "
              "raw feed credential-dumping analytics live on.")},
    {"key": "net_attr", "label": "Network connections with process attribution",
     "ds": ["Network Connection Creation"],
     "desc": ("Per-process connection events (which process talked to whom). "
              "Without it, beaconing is just firewall noise with no owning "
              "process.")},
    {"key": "logon", "label": "Logon session tracking (4624/4625)",
     "ds": ["Logon Session Creation"], "default": False,
     "desc": ("Interactive / remote logon sessions on the host. Many agents "
              "leave this to Windows Event Log — enable it only if yours "
              "actually ingests 4624/4625.")},
    {"key": "cred_protect", "label": "Credential-theft prevention (auto-kill)",
     "protect": True, "default": True,
     "desc": ("Behavioral prevention: terminate processes touching LSASS "
              "memory (T1003). A protection decision, not telemetry — off "
              "means dumping succeeds even on EDR-instrumented hosts.")},
]
DEFAULT_EDR_CAPS: dict[str, bool] = {c["key"]: c.get("default", True)
                                     for c in EDR_CAPABILITIES}

# technique prefix -> capability that must be ON for the prevention to fire
BLOCK_CAPS = {"T1003": "cred_protect"}


@dataclass
class SensorInst:
    """One concrete sensor instance that can cover an event."""
    sid: str            # id of the sensor node (or emitter for cloud_audit)
    kind: str           # edr | sysmon | zeek | netflow | waf | firewall | ...
    label: str
    context: str        # see CONTEXT_RANK
    via_siem: bool = False      # True when the row reached you through a SIEM
    siem_label: str = ""


def _expand_via_siem(inst: SensorInst, siem_links: dict) -> list[SensorInst]:
    """A sensor's row exists for the analyst in two places: the device's own
    console, and the SIEM (if the sensor ships its logs there)."""
    out = [inst]
    for siem_label in siem_links.get(inst.sid, []):
        out.append(SensorInst(inst.sid, "siem", siem_label, inst.context,
                              via_siem=True, siem_label=siem_label))
    return out


class Coverage:
    """Precomputed placement map: which sensor instances can see what."""

    def __init__(self, graph: Graph, edr_caps: dict | None = None):
        self.graph = graph
        # effective EDR capability profile: defaults overridden by whatever
        # the UI sent (unknown keys and non-bools are ignored)
        self.edr_caps = dict(DEFAULT_EDR_CAPS)
        for k, v in (edr_caps or {}).items():
            if k in self.edr_caps and isinstance(v, bool):
                self.edr_caps[k] = v
        # data sources the EDR subscription carries under this profile
        self._edr_sources = {ds for c in EDR_CAPABILITIES
                             if self.edr_caps.get(c["key"])
                             for ds in c.get("ds", [])}
        self.host_sensors: dict[str, list[SensorInst]] = defaultdict(list)
        self.cloud_sensors: dict[str, list[SensorInst]] = {}
        self.siem_links: dict[str, list[str]] = defaultdict(list)
        self.host_subnet: dict[str, str] = {}
        self.subnet_hosts: dict[str, list[str]] = defaultdict(list)
        self._build()

    # -- placement -----------------------------------------------------------
    def _build(self) -> None:
        g = self.graph

        # which SIEM nodes is each sensor wired to?
        for e in g.edges:
            for s in g.by_type("siem"):
                other = e.dst if e.src == s.id else (e.src if e.dst == s.id else None)
                if other:
                    self.siem_links[other].append(s.label)

        # host <-> subnet membership
        for h in g.hosts():
            for nb in g.neighbors(h.id):
                n = g.node(nb)
                if n and n.type in SUBNET_TYPES:
                    self.host_subnet[h.id] = n.id
                    self.subnet_hosts[n.id].append(h.id)

        # deployable sensors
        #
        # Endpoint telemetry lives as TOGGLES on the host itself since the
        # UI change ("the asset has an EDR/Sysmon switch"): a host with
        # props.edr / props.sysmon carries that sensor directly.
        for h in g.hosts():
            if h.props.get("edr"):
                # context quality tracks the profile: without process
                # telemetry the agent degrades to a 5-tuple network logger
                edr_ctx = "full" if self.edr_caps.get("process") else "tuple"
                self.host_sensors[h.id].append(
                    SensorInst(h.id, "edr", f"EDR \u00b7 {h.label}", edr_ctx))
            # Sysmon is Windows-only — a deliberate blind spot on Linux
            if h.props.get("sysmon") and h.type in WINDOWS_TYPES:
                self.host_sensors[h.id].append(
                    SensorInst(h.id, "sysmon", f"Sysmon \u00b7 {h.label}",
                               SENSOR_SPECS["sysmon"]["context"]))

        # Legacy layout: standalone EDR / Sysmon *nodes* linked to a host
        # (older saved designs). Kept so imported designs still simulate.
        for n in g.nodes:
            if n.type in ("edr", "sysmon"):
                for nb in g.neighbors(n.id):
                    m = g.node(nb)
                    if not m or m.type not in HOST_TYPES:
                        continue
                    if n.type == "sysmon" and m.type not in WINDOWS_TYPES:
                        continue
                    self.host_sensors[m.id].append(
                        SensorInst(n.id, n.type, n.label, SENSOR_SPECS[n.type]["context"]))
                continue

            if n.type in ("zeek", "ids"):
                # Zeek (metadata) and IDS (payload signatures) both monitor
                # the segment their SPAN port is plugged into
                for nb in g.neighbors(n.id):
                    m = g.node(nb)
                    if m and m.type in SUBNET_TYPES:
                        for h_id in self.subnet_hosts[m.id]:
                            self.host_sensors[h_id].append(
                                SensorInst(n.id, n.type, n.label,
                                           SENSOR_SPECS[n.type]["context"]))
                    elif m and m.type in HOST_TYPES:
                        self.host_sensors[m.id].append(
                            SensorInst(n.id, n.type, n.label,
                                       SENSOR_SPECS[n.type]["context"]))
            elif n.type == "netflow":
                for nb in g.neighbors(n.id):
                    m = g.node(nb)
                    if m and m.type in SUBNET_TYPES:
                        for h_id in self.subnet_hosts[m.id]:
                            self.host_sensors[h_id].append(
                                SensorInst(n.id, "netflow", n.label, "tuple"))
                    elif m and m.type == "firewall":
                        # NetFlow on the backbone firewall approximates
                        # "sees the 5-tuples of everything that transits"
                        for h in g.hosts():
                            self.host_sensors[h.id].append(
                                SensorInst(n.id, "netflow", n.label, "tuple"))  # h is a Node here

        # cloud services always produce their own audit rows (context: api);
        # whether you ever see them depends on SIEM wiring
        for n in g.nodes:
            if n.type in CLOUD_KINDS:
                self.cloud_sensors[n.id] = [
                    SensorInst(n.id, "cloud_audit", f"{n.label} audit log", "api")]

    def sources_for(self, kind: str) -> list[str]:
        """Data sources a sensor kind subscribes to, honoring the EDR profile."""
        if kind == "edr":
            return sorted(self._edr_sources)
        return SENSOR_SPECS[kind]["sources"]

    # -- event visibility ------------------------------------------------------
    def visible_sensors(self, ev: dict, target: Node,
                        path_ids: list[str] | None) -> list[SensorInst]:
        """Return every sensor instance (incl. SIEM relays) that would show
        this ground-truth event. `path_ids` is the entry->target path or None."""
        g = self.graph
        ds = ev["ds"]
        raw: list[SensorInst] = []

        if ds == "Email Delivery":
            # mail transits the gateway wherever it sits in the design
            raw = [SensorInst(n.id, "mail_gateway", n.label, "content")
                   for n in g.by_type("mail_gateway")]

        elif ds in CLOUD_DS:
            # cloud services log their own API activity, but those rows live in
            # the provider's console — the SOC only sees them if a SIEM is
            # wired to the service. No SIEM link = blind spot, experienced.
            raw = []
            for inst in self.cloud_sensors.get(target.id, []):
                for siem_label in self.siem_links.get(inst.sid, []):
                    raw.append(SensorInst(inst.sid, "siem", siem_label, inst.context,
                                          via_siem=True, siem_label=siem_label))

        elif ds in NETWORK_DS:
            # host-attached sensors that include network telemetry
            for inst in self.host_sensors.get(target.id, []):
                if ds in self.sources_for(inst.kind):
                    raw.append(inst)
            # appliances on the path log what transits them
            if path_ids:
                for pid in path_ids:
                    n = g.node(pid)
                    if n and n.type == "firewall" and ds == "Network Connection Creation":
                        raw.append(SensorInst(n.id, "firewall", n.label, "tuple"))
                    if n and n.type == "waf" and ds == "Network Traffic Content":
                        raw.append(SensorInst(n.id, "waf", n.label, "content"))

        else:  # host-local telemetry (process, file, logon, ...)
            for inst in self.host_sensors.get(target.id, []):
                if ds in self.sources_for(inst.kind):
                    raw.append(inst)

        # expand each raw sensor through the SIEMs it ships to
        out: list[SensorInst] = []
        for inst in raw:
            out.extend(_expand_via_siem(inst, self.siem_links))
        return out


# ---------------------------------------------------------------------------
# Blocking rules: technique prefix -> list of (control, condition, prop, text)
#   conditions:  in_path      control lies on the entry->target path
#                on_host      control is deployed on the target host
#                target_prop  the target component itself has a property set
# ---------------------------------------------------------------------------
BLOCK_RULES: dict[str, list[tuple[str, str, str | None, str]]] = {
    "T1566": [("mail_gateway", "in_path", None,
               "quarantined the spearphishing attachment before delivery")],
    "T1190": [("waf", "in_path", None,
               "inspected and blocked the exploit payload at the edge")],
    "T1021": [("firewall", "in_path", "segmentation",
               "east-west segmentation denied the remote-service session")],
    "T1071": [("firewall", "in_path", "egress_deny",
               "default-deny egress dropped the C2 beacon")],
    "T1041": [("firewall", "in_path", "egress_deny",
               "default-deny egress dropped the bulk upload")],
    "T1003": [("edr", "on_host", None,
               "EDR credential-theft protection terminated the dumper")],
    "T1078": [("idp", "in_path", "mfa",
               "stolen credentials alone cannot satisfy the MFA challenge")],
    "T1530": [("s3", "target_prop", "block_public",
               "bucket policy + least-privilege IAM denied GetObject")],
}

# Property name -> predicate over the control node's props
_PROP_CHECK = {
    "segmentation": lambda n: bool(n.props.get("segmentation")),
    "egress_deny":  lambda n: n.props.get("egress") == "default-deny",
    "mfa":          lambda n: bool(n.props.get("mfa")),
}


def check_blocks(graph: Graph, technique: str, target: Node,
                 path_ids: list[str] | None,
                 coverage: Coverage) -> tuple[str, str, str] | None:
    """Return (control label, explanation, control node id) if blocked."""
    prefix = None
    for p in BLOCK_RULES:
        if technique.startswith(p) and (prefix is None or len(p) > len(prefix)):
            prefix = p
    if prefix is None:
        return None

    for kind, cond, prop, text in BLOCK_RULES[prefix]:
        # preventions can be switched off per capability profile (e.g. the
        # EDR credential-theft protection toggle)
        cap = BLOCK_CAPS.get(prefix)
        if (cap and cond == "on_host" and kind == "edr"
                and not coverage.edr_caps.get(cap, True)):
            continue
        if cond == "in_path":
            if not path_ids:
                continue  # no drawn path from an Internet entry point
            for pid in path_ids:
                n = graph.node(pid)
                if n and n.type == kind:
                    if prop and not _PROP_CHECK[prop](n):
                        continue
                    return n.label, text, n.id
        elif cond == "on_host":
            insts = coverage.host_sensors.get(target.id, [])
            if any(i.kind == kind for i in insts):
                match = next(i for i in insts if i.kind == kind)
                return match.label, text, match.sid
        elif cond == "target_prop":
            if target.type == kind and prop and target.props.get(prop):
                return target.label, text, target.id
    return None
