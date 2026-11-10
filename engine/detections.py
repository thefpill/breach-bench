"""The detection catalog — which sensor has analytics for which technique.

This is the "detection asset" layer for the scenario library: the CTI
import (scripts/generate_scenarios.py) brought in ~130 technique families,
and every one of them needs an answer to "who would notice this?".

Model
-----
    ALERT_RULES: technique prefix -> [(sensor kind, min context rank), ...]
    ALERT_TEXT:  technique prefix -> human alert reason (shown on rows)

`match_alert()` walks a visible sensor row and returns an alert reason only
if the sensor kind carries analytics for the technique AND the sensor's
context quality meets the minimum rank (see coverage.CONTEXT_RANK:

    api 0 < tuple 1 / network_meta 1 < process_only 2 < full 3 / content 3).

So a Zeek 5-tuple will not "detect" process injection no matter how many
rows it sees — rows are not detections. A visible row without a rule here
stays verdict "observed": something to read, nothing that pages anyone.

Deliberate gaps
---------------
Reconnaissance / resource-development techniques (T1583-T1595 OSINT and
infrastructure work) happen in attacker-owned space: no sensor in the
design can see a domain being registered. Those prefixes have NO rule on
purpose — the corresponding steps play out as observed-at-best, which is
the honest answer, not a modeling omission.
"""
from __future__ import annotations

ALERT_RULES: dict[str, list[tuple[str, int]]] = {}
ALERT_TEXT: dict[str, str] = {}


def _add(prefix: str, kinds: list[tuple[str, int]], text: str) -> None:
    """Register one technique family's detection rule + alert reason."""
    ALERT_RULES[prefix] = kinds
    ALERT_TEXT[prefix] = text


# Sensor shorthands — the context ranks each argument demands:
#   edr 2 = EDR with process telemetry ON (profile toggle "process")
#   edr 3 = EDR-grade behavioral analytics only (full process attribution)
#   siem N = any row relayed through a SIEM with context rank >= N
#   zeek 1 / ids 0 / firewall 1 = network-layer analytics of that appliance

# ---------------------------------------------------------------------------
# initial access
# ---------------------------------------------------------------------------
_add("T1566", [("mail_gateway", 0), ("siem", 0)],
     "Phishing: malicious attachment flagged")
_add("T1078", [("siem", 0)],
     "Anomalous cloud console logon (new geo/device)")
_add("T1190", [("waf", 0), ("ids", 0), ("siem", 1), ("edr", 2)],
     "Web exploit attempt / shell spawned by web server")
_add("T1189", [("waf", 0), ("ids", 0), ("edr", 2), ("siem", 2)],
     "Drive-by: exploit-kit pattern on a browsing session")
_add("T1133", [("ids", 1), ("edr", 2), ("siem", 2)],
     "External remote service (VPN/RDP) session from unexpected source")
_add("T1195", [("edr", 2), ("siem", 2)],
     "Supply-chain: trusted updater spawning a suspicious child")
_add("T1199", [("ids", 1), ("edr", 2), ("siem", 2)],
     "Trusted-relationship access from an unusual network")
_add("T1200", [("edr", 2), ("siem", 2)],
     "New storage device attached + driver loaded on endpoint")
_add("T1091", [("edr", 2), ("siem", 2)],
     "Executable written from removable media and executed")
_add("T1203", [("edr", 2), ("siem", 2)],
     "Exploited document/application spawning a child process")
_add("T1659", [("waf", 0), ("ids", 0), ("edr", 2), ("siem", 2)],
     "Content injection: script payload inside a trusted page")
_add("T1684", [("edr", 2), ("siem", 2)],
     "Impersonation attempt (typosquatted identity/domain)")

# ---------------------------------------------------------------------------
# execution
# ---------------------------------------------------------------------------
_add("T1053", [("edr", 2), ("siem", 2)],
     "Scheduled task created outside the change window")
_add("T1047", [("edr", 2), ("siem", 2)],
     "WMI process spawn (odd parent / remote command)")
_add("T1059", [("edr", 2), ("siem", 2)],
     "Suspicious scripted interpreter execution")
_add("T1204", [("edr", 2), ("siem", 2)],
     "Suspicious Office/document child process")
_add("T1072", [("edr", 2), ("siem", 2)],
     "Admin/deployment tool pushing execution onto a server")
_add("T1106", [("edr", 3), ("siem", 3)],
     "Suspicious direct API call pattern (no interpreter involved)")
_add("T1569", [("edr", 2), ("siem", 2)],
     "Service created and started by a suspicious parent")
_add("T1610", [("edr", 2), ("siem", 2)],
     "Container image deployed outside the build pipeline")
_add("T1675", [("edr", 2), ("siem", 2)],
     "Hypervisor/ESXi administration command")

# ---------------------------------------------------------------------------
# persistence
# ---------------------------------------------------------------------------
_add("T1037", [("edr", 2), ("siem", 2)],
     "Logon script modified by a non-GPO process")
_add("T1080", [("edr", 2), ("siem", 2)],
     "Executable written to a shared folder by an unusual writer")
_add("T1098", [("edr", 2), ("siem", 0)],
     "Account/permission manipulation (delegate added, admin granted)")
_add("T1112", [("edr", 2), ("siem", 2)],
     "Persistence registry key written by an untrusted process")
_add("T1136", [("edr", 2), ("siem", 0)],
     "New local/domain account created (4720/4732)")
_add("T1137", [("edr", 2), ("siem", 2)],
     "Office add-in/template persistence installed")
_add("T1176", [("edr", 2), ("siem", 2)],
     "Browser/IDE extension dropped and registered")
_add("T1205", [("ids", 1), ("zeek", 1)],
     "Port-knock sequence preceding service activation")
_add("T1505", [("edr", 2), ("siem", 2)],
     "Web shell drop or spawn under web server process")
_add("T1542", [("edr", 3), ("siem", 3)],
     "Firmware / boot-image write on an endpoint")
_add("T1543", [("edr", 2), ("siem", 2)],
     "New service installed pointing outside system paths")
_add("T1546", [("edr", 2), ("siem", 2)],
     "Event-triggered persistence (accessibility/debugger key)")
_add("T1547", [("edr", 2), ("siem", 2)],
     "Autostart entry (run key / startup folder) modified")
_add("T1548", [("edr", 2), ("siem", 2)],
     "Elevation abuse: UAC bypass / unexpected sudo")
_add("T1556", [("edr", 3), ("siem", 3)],
     "Authentication package / security provider modified")
_add("T1574", [("edr", 2), ("siem", 2)],
     "DLL hijack: library load from a writable path")

# ---------------------------------------------------------------------------
# privilege escalation
# ---------------------------------------------------------------------------
_add("T1055", [("edr", 3), ("siem", 3)],
     "Cross-process memory injection")
_add("T1068", [("edr", 2), ("siem", 2)],
     "Exploit attempt against a privileged service")
_add("T1134", [("edr", 3), ("siem", 3)],
     "Token theft/impersonation API (CreateProcessAsUserA)")
_add("T1484", [("edr", 2), ("siem", 0)],
     "Group/tenant policy modified by an unexpected principal")
_add("T1611", [("edr", 3), ("siem", 3)],
     "Container escape toward the host runtime")

# ---------------------------------------------------------------------------
# defense evasion
# ---------------------------------------------------------------------------
_add("T1006", [("edr", 2), ("siem", 2)],
     "Raw volume handle opened by a user process")
_add("T1014", [("edr", 3), ("siem", 3)],
     "Kernel driver / rootkit indicator")
_add("T1027", [("edr", 2), ("siem", 2)],
     "Encoded/high-entropy payload executed")
_add("T1036", [("edr", 2), ("siem", 3)],
     "Masquerading: system binary name outside system path")
_add("T1070", [("edr", 2), ("siem", 0)],
     "Log/indicator purge (event log cleared, delete burst)")
_add("T1140", [("edr", 2), ("siem", 2)],
     "Decoder utility spawned right after a file drop")
_add("T1211", [("edr", 2), ("siem", 2)],
     "Stealth exploit attempt against security tooling")
_add("T1218", [("edr", 2), ("siem", 2)],
     "LOLBin proxy execution (rundll32/regsvr32 from odd paths)")
_add("T1219", [("edr", 2), ("siem", 2)],
     "Remote-access tool (AnyDesk/TeamViewer-class) installed")
_add("T1221", [("edr", 2), ("siem", 2)],
     "Document template injection fetching a remote macro")
_add("T1480", [("edr", 2), ("siem", 2)],
     "Execution guardrails: sandbox/VM checks before detonation")
_add("T1518", [("edr", 2), ("siem", 2)],
     "Security-software enumeration")
_add("T1564", [("edr", 2), ("siem", 2)],
     "Hidden artifact: hidden window / file attributes")

# ---------------------------------------------------------------------------
# credential access
# ---------------------------------------------------------------------------
_add("T1003", [("edr", 2), ("siem", 2)],
     "Credential dumping: LSASS access")
_add("T1040", [("edr", 3), ("siem", 3)],
     "Promiscuous packet capture started on an endpoint")
_add("T1056", [("edr", 3), ("siem", 3)],
     "Keylogger: low-level input hooks installed")
_add("T1110", [("siem", 0), ("edr", 2)],
     "Password spray / brute-force burst")
_add("T1187", [("ids", 1), ("edr", 2), ("siem", 2)],
     "Coerced authentication (SpoolSample-style callback)")
_add("T1528", [("edr", 2), ("siem", 0)],
     "OAuth/application token stolen from a store or API")
_add("T1539", [("edr", 3), ("siem", 3)],
     "Web-session cookie store read by an untrusted process")
_add("T1552", [("edr", 2), ("siem", 2)],
     "Credential material read from insecure locations")
_add("T1555", [("edr", 3), ("siem", 3)],
     "Browser/DPAPI password store access")
_add("T1557", [("ids", 1), ("zeek", 1)],
     "ARP poisoning / spoofed identity on the segment")
_add("T1558", [("edr", 2), ("siem", 0)],
     "Kerberoasting / anomalous ticket requests")

# ---------------------------------------------------------------------------
# discovery — uniform process-context analytics (EDR + SIEM correlation)
# ---------------------------------------------------------------------------
_DISCOVERY = {
    "T1007": "system service enumeration",
    "T1012": "registry query burst",
    "T1016": "network configuration enumeration",
    "T1033": "user/account enumeration",
    "T1049": "network connection enumeration",
    "T1057": "process enumeration burst",
    "T1069": "permission/group enumeration",
    "T1082": "system information enumeration",
    "T1083": "file/directory enumeration burst",
    "T1087": "account discovery sweep",
    "T1135": "network share enumeration",
    "T1482": "domain trust discovery (nltest/dsquery)",
    "T1120": "peripheral/device enumeration",
    "T1124": "system time discovery",
    "T1680": "local storage enumeration",
    "T1497": "sandbox/VM evasion checks",
}
for _t, _what in _DISCOVERY.items():
    _add(_t, [("edr", 2), ("siem", 2)], f"Discovery burst: {_what}")

# discovery that also crosses the wire — network-layer analytics see it too
_add("T1018", [("edr", 2), ("siem", 2), ("ids", 1)],
     "Remote system sweep (arp/net-view pattern)")
_add("T1046", [("edr", 2), ("siem", 2), ("ids", 1), ("zeek", 1)],
     "Internal port scan")

# ---------------------------------------------------------------------------
# lateral movement
# ---------------------------------------------------------------------------
_add("T1021", [("edr", 2), ("siem", 2)],
     "Suspicious remote service logon/execution")
_add("T1210", [("edr", 2), ("siem", 2), ("ids", 1)],
     "Remote service exploitation attempt (SMB/RPC pattern)")
_add("T1534", [("mail_gateway", 0), ("siem", 0), ("edr", 2)],
     "Internal spearphishing from a compromised mailbox")
_add("T1550", [("siem", 0), ("edr", 2)],
     "Pass-the-hash: NTLM logon with reused credentials")
_add("T1563", [("edr", 2), ("siem", 2)],
     "RDP session hijack (tscon) usage")
_add("T1570", [("edr", 2), ("siem", 2), ("ids", 1)],
     "Tool staging over SMB/RPC between hosts")

# ---------------------------------------------------------------------------
# collection
# ---------------------------------------------------------------------------
_add("T1005", [("edr", 3), ("siem", 3)],
     "Bulk file access by untrusted process")
_add("T1039", [("edr", 3), ("siem", 3)],
     "Bulk read from a network share by an untrusted process")
_add("T1074", [("edr", 2), ("siem", 2)],
     "Data staged into an archive area")
_add("T1113", [("edr", 3), ("siem", 3)],
     "Screen capture API usage")
_add("T1114", [("edr", 2), ("siem", 0)],
     "Mailbox export / cloud mail collection")
_add("T1119", [("edr", 2), ("siem", 2)],
     "Automated collection script burst")
_add("T1213", [("edr", 2), ("siem", 0)],
     "Bulk export from an information repository")
_add("T1560", [("edr", 2), ("siem", 2)],
     "Archive utility compressing user data")

# ---------------------------------------------------------------------------
# command and control — the network sensors earn their keep here
# ---------------------------------------------------------------------------
_add("T1001", [("edr", 2), ("siem", 2)],
     "Encoded/steganographic payload staged for C2")
_add("T1071", [("edr", 2), ("siem", 2), ("zeek", 1), ("ids", 0)],
     "Possible C2 beacon (periodic egress w/ process attribution)")
_add("T1090", [("edr", 2), ("siem", 2), ("zeek", 1)],
     "Traffic via known proxy/relay infrastructure")
_add("T1095", [("ids", 0), ("zeek", 1), ("edr", 2), ("siem", 2)],
     "Raw non-HTTP protocol on an unusual egress")
_add("T1102", [("edr", 2), ("siem", 2), ("zeek", 1), ("ids", 0)],
     "C2 via legitimate web service (paste/social site)")
_add("T1105", [("edr", 2), ("siem", 2), ("ids", 1)],
     "Tool download by a suspicious process")
_add("T1568", [("ids", 0), ("zeek", 1), ("edr", 2), ("siem", 2)],
     "Algorithmic DNS (high-entropy NXDOMAIN burst)")
_add("T1571", [("ids", 0), ("zeek", 1), ("firewall", 1), ("edr", 2), ("siem", 2)],
     "C2 on a non-standard port")
_add("T1573", [("edr", 2), ("siem", 2), ("zeek", 1), ("ids", 1)],
     "Encrypted channel with fingerprint/flow anomalies")

# ---------------------------------------------------------------------------
# exfiltration
# ---------------------------------------------------------------------------
_add("T1029", [("edr", 2), ("siem", 2), ("zeek", 1)],
     "Periodic/scheduled outbound transfer pattern")
_add("T1041", [("edr", 2), ("siem", 2)],
     "Large outbound transfer from suspicious process")
_add("T1048", [("ids", 0), ("zeek", 1), ("firewall", 1), ("edr", 2), ("siem", 2)],
     "Bulk egress over an alternative protocol/port")
_add("T1567", [("edr", 2), ("siem", 0)],
     "Upload to external file-sharing / cloud storage")

# ---------------------------------------------------------------------------
# impact
# ---------------------------------------------------------------------------
_add("T1486", [("edr", 2), ("siem", 0)],
     "Mass file encryption (ransomware behavior)")
_add("T1657", [("edr", 2), ("siem", 2)],
     "Suspicious financial transaction pattern")

# ---------------------------------------------------------------------------
# reconnaissance — only the probes that actually touch the design
# ---------------------------------------------------------------------------
_add("T1595", [("waf", 0), ("ids", 0), ("zeek", 1), ("firewall", 1), ("siem", 1)],
     "Vulnerability scan: probe burst against public services")
_add("T1598", [("mail_gateway", 0), ("siem", 0)],
     "Recon phishing: credential-harvesting link")

# NOT modeled on purpose (attacker-side, invisible to any design):
#   resource development  T1583 T1584 T1585 T1586 T1587 T1588 T1608
#   OSINT recon           T1589 T1590 T1591 T1592 T1593 T1594 T1681 T1682


# ---------------------------------------------------------------------------
# matcher
# ---------------------------------------------------------------------------
def match_alert(technique: str, inst) -> str | None:
    """Return an alert reason if this sensor instance would alert, else None.

    `inst` is a coverage.SensorInst; longest matching technique prefix wins
    (a T1071.001 row is judged by the T1071 family rule unless a more
    specific rule exists).
    """
    prefix = None
    for p in ALERT_RULES:
        if technique.startswith(p) and (prefix is None or len(p) > len(prefix)):
            prefix = p
    if prefix is None:
        return None
    from .coverage import CONTEXT_RANK           # late import: no cycle at load
    rank = CONTEXT_RANK.get(inst.context, 0)
    for kind, min_rank in ALERT_RULES[prefix]:
        eff_kind = "siem" if inst.via_siem else inst.kind
        if eff_kind == kind and rank >= min_rank:
            return f"{ALERT_TEXT[prefix]} ({technique})"
    return None
