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
            "mail_gateway": "MGW", "cloud_audit": "AUD"}


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

    def __init__(self, graph: Graph):
        self.graph = graph
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
                self.host_sensors[h.id].append(
                    SensorInst(h.id, "edr", f"EDR \u00b7 {h.label}",
                               SENSOR_SPECS["edr"]["context"]))
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

            if n.type == "zeek":
                # Zeek sees network metadata for the segment its SPAN port is on
                for nb in g.neighbors(n.id):
                    m = g.node(nb)
                    if m and m.type in SUBNET_TYPES:
                        for h_id in self.subnet_hosts[m.id]:
                            self.host_sensors[h_id].append(
                                SensorInst(n.id, "zeek", n.label, "network_meta"))
                    elif m and m.type in HOST_TYPES:
                        self.host_sensors[m.id].append(
                            SensorInst(n.id, "zeek", n.label, "network_meta"))
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
                if ds in SENSOR_SPECS[inst.kind]["sources"]:
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
                if ds in SENSOR_SPECS[inst.kind]["sources"]:
                    raw.append(inst)

        # expand each raw sensor through the SIEMs it ships to
        out: list[SensorInst] = []
        for inst in raw:
            out.extend(_expand_via_siem(inst, self.siem_links))
        return out


# ---------------------------------------------------------------------------
# Detection rules: technique prefix -> [(sensor kinds, min context rank)]
# A visible event raises an ALERT only if a sensor with sufficient context
# has analytics for the technique. Rows without analytics are just rows.
# ---------------------------------------------------------------------------
ALERT_RULES: dict[str, list[tuple[str, int]]] = {
    "T1566": [("mail_gateway", 0), ("siem", 0)],       # phishing alerts from mail gw / SIEM
    "T1204": [("edr", 2), ("siem", 2)],                # user execution w/ process context
    "T1059": [("edr", 2), ("siem", 2)],                # script interpreter
    "T1071": [("edr", 2), ("siem", 2)],                # C2 needs process attribution
    "T1003": [("edr", 2), ("siem", 2)],                # credential dumping
    "T1021": [("edr", 2), ("siem", 2)],                # remote services / lateral movement
    "T1190": [("waf", 0), ("siem", 1), ("edr", 2)],    # exploit: WAF sees payload, else process
    "T1505": [("edr", 2), ("siem", 2)],                # web shell persistence
    "T1036": [("edr", 2), ("siem", 3)],                # masquerading needs EDR-grade context
    "T1005": [("edr", 3), ("siem", 3)],                # file access needs EDR-grade telemetry
    "T1041": [("edr", 2), ("siem", 2)],                # exfil over C2 needs attribution
    "T1078": [("siem", 0)],                            # valid accounts (cloud logon analytics)
    "T1580": [("siem", 0)],                            # cloud infrastructure discovery
    "T1530": [("siem", 0)],                            # data from cloud storage
    "T1567": [("edr", 2), ("siem", 0)],                # exfil to cloud storage
}

# Human-readable alert reasons per technique prefix (shown on alert rows)
ALERT_TEXT = {
    "T1566": "Phishing: malicious attachment flagged",
    "T1204": "Suspicious Office/document child process",
    "T1059": "Suspicious scripted interpreter execution",
    "T1071": "Possible C2 beacon (periodic egress w/ process attribution)",
    "T1003": "Credential dumping: LSASS access",
    "T1021": "Suspicious remote service logon/execution",
    "T1190": "Web exploit attempt / shell spawned by web server",
    "T1505": "Web shell drop or spawn under web server process",
    "T1036": "Masquerading: system binary name outside system path",
    "T1005": "Bulk file access by untrusted process",
    "T1041": "Large outbound transfer from suspicious process",
    "T1078": "Anomalous cloud console logon (new geo/device)",
    "T1580": "Cloud infra enumeration (Describe/List burst)",
    "T1530": "Bulk GetObject from cloud storage",
    "T1567": "Upload to external file-sharing / cloud storage",
}


def match_alert(technique: str, inst: SensorInst) -> str | None:
    """Return an alert reason if this sensor instance would alert, else None."""
    prefix = None
    for p in ALERT_RULES:
        if technique.startswith(p) and (prefix is None or len(p) > len(prefix)):
            prefix = p
    if prefix is None:
        return None
    rank = CONTEXT_RANK.get(inst.context, 0)
    for kind, min_rank in ALERT_RULES[prefix]:
        eff_kind = "siem" if inst.via_siem else inst.kind
        if eff_kind == kind and rank >= min_rank:
            return f"{ALERT_TEXT[prefix]} ({technique})"
    return None


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
