"""Extract group -> technique -> tactic/procedure/command JSON from MITRE CTI.

Fetch the CTI bundle once, then run:

    curl -L -o scripts/data/enterprise-attack.json \
      https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json
    python scripts/extract_attack.py [output.json]      # default: scripts/data/mitre-attack-groups.json
    python scripts/generate_scenarios.py                # turns it into playable scenarios

Output JSON (default scripts/data/mitre-attack-groups.json): every ATT&CK
*group* (intrusion-set) with every documented technique it uses:

  * technique id + name (T1134.002 / "Access Token Manipulation: ...")
  * tactics (from the technique's kill-chain phases)
  * ATT&CK data components the technique would touch, mapped onto the
    the app's shortened data-source names (the simulator's join key)
  * the procedure description verbatim (cleaned of citations)
  * a *concrete command* extracted from the procedure where one is
    documented (WinAPI call, shell command, tool invocation, URL...)

    "Lazarus Group keylogger KiloAlfa obtains user tokens ... with API
     call CreateProcessAsUserA under that user's context"
      -> command: "CreateProcessAsUserA"
"""
from __future__ import annotations

import json
import re
import sys
import datetime
import pathlib

HERE = pathlib.Path(__file__).resolve().parent
CTI = HERE / "data" / "enterprise-attack.json"
OUT_DEFAULT = HERE / "data" / "mitre-attack-groups.json"

sys.path.insert(0, str(HERE.parent))
from engine.coverage import DATA_SOURCES  # the engine's shortened vocabulary

# ---------------------------------------------------------------------------
# ATT&CK data-component name -> app data source (the simulator's join
# key). Components the engine does not model (registry, AD, firmware, ...)
# are deliberately unmapped: no modeled telemetry means no invented rows.
# ---------------------------------------------------------------------------
DC_MAP = {
    # exact matches with the engine vocabulary
    "Process Creation": "Process Creation",
    "Command Execution": "Command Execution",
    "File Creation": "File Creation",
    "File Access": "File Access",
    "Process Access": "Process Access",
    "Logon Session Creation": "Logon Session Creation",
    "Network Connection Creation": "Network Connection Creation",
    "Network Traffic Content": "Network Traffic Content",
    "Email Delivery": "Email Delivery",
    "Cloud Logon": "Cloud Logon",
    "Cloud API Call": "Cloud API Call",
    "Cloud Storage Access": "Cloud Storage Access",
    # near-synonyms folded onto the closest modeled source
    "File Modification": "File Creation",
    "File Deletion": "File Creation",
    "File Metadata": "File Access",
    "Process Metadata": "Process Creation",
    "Process Termination": "Process Creation",
    "Process Modification": "Process Access",
    "Module Load": "Process Creation",
    "Script Execution": "Command Execution",
    "WMI Operation": "Command Execution",
    "Service Creation": "Process Creation",
    "Service Modification": "Process Creation",
    "Scheduled Job Creation": "Process Creation",
    "Scheduled Job Modification": "Process Creation",
    "User Account Creation": "Logon Session Creation",
    "User Account Modification": "Logon Session Creation",
    "Active Directory Credential Request": "Logon Session Creation",
    "Network Share Access": "Network Connection Creation",
    "Cloud Service Metadata": "Cloud API Call",
    "Cloud Storage Modification": "Cloud Storage Access",
    "Cloud Storage Metadata": "Cloud Storage Access",
    "Cloud Storage Object Access": "Cloud Storage Access",
}

# ---------------------------------------------------------------------------
# concrete-command extraction
# ---------------------------------------------------------------------------
CITATION_RE = re.compile(r"\(Citation:[^)]*\)")
MDLINK_RE = re.compile(r"\[([^\]]+)\]\(([^)]*)\)")

API_PREFIXES = (
    "Create", "Open", "Set", "Get", "Find", "Enum", "Load", "Read", "Write",
    "Virtual", "Map", "Unmap", "Heap", "Allocate", "Free", "Shell", "Reg",
    "Nt", "Zw", "Rtl", "Lsa", "Ldr", "Crypt", "Hash", "BCrypt", "NCrypt",
    "WSA", "Win", "Internet", "Http", "Url", "IsWow64", "Adjust", "Lookup",
    "Impersonate", "Duplicate", "Revert", "CoCreate", "SysAlloc", "GlobalAlloc",
    "LocalAlloc", "WideChar", "MultiByte", "Send", "Recv", "Connect", "Bind",
    "Listen", "Accept", "QueueUser", "SetThread", "Resume", "Suspend",
    "Terminate", "CheckRemote", "Debug", "WriteProcess", "ReadProcess",
    "Mini", "NetApi", "StartService", "ControlService", "DeleteFile",
    "MoveFile", "CopyFile", "CreateRemote", "GetToken", "SetToken",
)

TOOL_RE = re.compile(
    r"\b(schtasks(?:\.exe)?\s+[^\n\.\)\"]{0,120}|net(?:\.exe)?\s+(?:user|group|"
    r"localgroup|use|share|session)[^\n\.\)\"]{0,100}|wmic\s+[^\n\.\)\"]{0,120}|"
    r"certutil\s+[^\n\.\)\"]{0,120}|bitsadmin\s+[^\n\.\)\"]{0,120}|"
    r"reg(?:\.exe)?\s+(?:add|query|save)[^\n\.\)\"]{0,100}|sc(?:\.exe)?\s+"
    r"(?:create|config|start)[^\n\.\)\"]{0,100}|powershell(?:\.exe)?\s+[^\n\.\)\"]{0,160}|"
    r"rundll32(?:\.exe)?\s+[^\n\.\)\"]{0,140}|mshta\s+[^\n\.\)\"]{0,100}|"
    r"at\s+\d{1,2}[:\.]\d{2}[^\n\.\)\"]{0,80}|whoami\s*/[a-z]+|nltest\s+[^\n\.\)\"]{0,80})",
    re.IGNORECASE)

EXE_RE = re.compile(r"\b((?:[A-Za-z]:\\[^\s\"';,]*|[\w\-.]+)\.exe)\b")
QUOTED_RE = re.compile(r'"([^"\n]{6,250})"')
URL_RE = re.compile(r"(https?://[^\s\)\]\"<>]{6,150})")
API_MENTION_RE = re.compile(r"API (?:function |call |calls |command )?\(?([A-Z][A-Za-z0-9_]{3,})")
CAMEL_RE = re.compile(r"\b([A-Z][a-z0-9]+(?:[A-Z][A-Za-z0-9_]*)+)\b")
CALL_PAREN_RE = re.compile(r"\b([A-Z][A-Za-z0-9_]{4,})\s*\(")


CODE_TAG_RE = re.compile(r"<code>(.*?)</code>", re.IGNORECASE | re.DOTALL)
HTML_TAG_RE = re.compile(r"</?[a-z][^>]*>", re.IGNORECASE)


def clean_procedure(text: str) -> str:
    """Drop STIX citations, keep markdown link labels, unwrap <code> tags
    into backticks (they feed the command extractor), squash whitespace."""
    text = CITATION_RE.sub("", text or "")
    text = MDLINK_RE.sub(lambda m: m.group(1), text)
    text = CODE_TAG_RE.sub(lambda m: f"`{m.group(1)}`", text)
    text = HTML_TAG_RE.sub("", text)
    return re.sub(r"\s+", " ", text).strip()


def _is_api_word(w: str) -> bool:
    return w.startswith(API_PREFIXES) or re.search(r"(A|W|Ex)$", w) is not None


def _looks_like_command(s: str) -> bool:
    """Reject sentence fragments that merely mention a tool: a real captured
    command usually carries a flag (-x /x), a path, a script/exe extension
    or an assignment."""
    if re.search(r"(?:^|\s)-\w|(?:^|\s)/\w|\.exe|\.dll|\.ps1|\.vbs|\.bat|\\|"
                 r"https?:|%[A-Za-z]%|\b\d{1,3}(?:\.\d{1,3}){3}\b", s, re.IGNORECASE):
        return True
    return " " not in s.strip()          # single token, e.g. whoami


def extract_commands(text: str) -> list[str]:
    """Ordered, de-duplicated candidates, best first."""
    out: list[str] = []

    def add(c: str | None, check: bool = False):
        if not c:
            return
        c = re.sub(r"\s+", " ", c).strip().rstrip(".;,")
        if check and not _looks_like_command(c):
            return
        if 2 <= len(c) <= 250 and c.lower() not in {o.lower() for o in out}:
            out.append(c)

    # 1) markdown/backtick code blocks
    for c in re.findall(r"`([^`\n]{3,200})`", text):
        add(c)
    # 2) explicit "API call CreateProcessAsUserA" phrasing
    for m in API_MENTION_RE.finditer(text):
        if _is_api_word(m.group(1)):
            add(m.group(1))
    # 3) CamelCase WinAPI-looking identifiers
    for w in CAMEL_RE.findall(text):
        if _is_api_word(w):
            add(w)
    # 4) anything invoked with parentheses
    for m in CALL_PAREN_RE.finditer(text):
        if _is_api_word(m.group(1)):
            add(m.group(1))
    # 5) tool invocations and executables (command-likeness checked)
    for m in TOOL_RE.finditer(text):
        add(m.group(0), check=True)
    for m in EXE_RE.finditer(text):
        add(m.group(1))
    # 6) shell one-liners inside quotes
    for m in QUOTED_RE.finditer(text):
        q = m.group(1)
        if any(k in q.lower() for k in ("-", "/", ":", "exe", "http", "powershell", "cmd")):
            add(q)
    # 7) URLs (C2 / payload locations)
    for m in URL_RE.finditer(text):
        add(m.group(1))
    return out


# ---------------------------------------------------------------------------
# bundle parsing
# ---------------------------------------------------------------------------
def load_objects():
    with open(CTI, encoding="utf-8") as f:
        return json.load(f)["objects"]


def main() -> None:
    out_path = pathlib.Path(sys.argv[1]) if len(sys.argv) > 1 else OUT_DEFAULT
    objs = load_objects()

    aps, groups, dcs, strategies, analytics = {}, {}, {}, {}, {}
    for o in objs:
        if o.get("revoked") or o.get("x_mitre_deprecated"):
            continue
        if o["type"] == "attack-pattern":
            ext = next((r for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack" and
                        re.fullmatch(r"T\d{4}(\.\d{3})?", r.get("external_id", ""))), None)
            if ext:
                aps[o["id"]] = {
                    "stix": o["id"],
                    "tid": ext["external_id"],
                    "name": o["name"],
                    "url": ext.get("url", ""),
                    "tactics": [p["phase_name"] for p in o.get("kill_chain_phases", [])
                                if p.get("kill_chain_name") == "mitre-attack"],
                    "platforms": o.get("x_mitre_platforms", []),
                    "components": set(),   # ATT&CK data-component names
                }
        elif o["type"] == "x-mitre-detection-strategy":
            strategies[o["id"]] = {"analytics": o.get("x_mitre_analytic_refs", []),
                                    "tid": None}
        elif o["type"] == "x-mitre-analytic":
            comps = {r["x_mitre_data_component_ref"]
                     for r in o.get("x_mitre_log_source_references", [])
                     if r.get("x_mitre_data_component_ref")}
            analytics[o["id"]] = comps
        elif o["type"] == "intrusion-set":
            ext = next((r for r in o.get("external_references", [])
                        if r.get("source_name") == "mitre-attack"), None)
            if ext:
                groups[o["id"]] = {
                    "gid": ext.get("external_id", ""),
                    "name": o["name"],
                    "url": ext.get("url", ""),
                    "aliases": sorted({r["source_name"] for r in o.get("external_references", [])
                                       if r.get("source_name") not in ("mitre-attack",)}),
                    "description": clean_procedure(o.get("description", "")),
                    "techniques": {},
                }
        elif o["type"] == "x-mitre-data-component":
            dcs[o["id"]] = o.get("name", "")

    # technique <-> data component.
    # CTI v17 chain: detection-strategy --detects--> attack-pattern, and the
    # strategy's analytics carry x_mitre_data_component_ref pointers.
    for r in objs:
        if r["type"] != "relationship" or r.get("relationship_type") != "detects":
            continue
        s, t = r.get("source_ref"), r.get("target_ref")
        if s in strategies and t in aps:
            strategies[s]["tid"] = t
        elif t in aps and s in dcs:          # legacy direct DC linkage
            aps[t]["components"].add(dcs[s])
        elif s in aps and t in dcs:
            aps[s]["components"].add(dcs[t])
    for st in strategies.values():
        if st["tid"] and st["tid"] in aps:
            for an in st["analytics"]:
                for dc_ref in analytics.get(an, ()):  # stix id -> DC stix id
                    if dc_ref in dcs:
                        aps[st["tid"]]["components"].add(dcs[dc_ref])

    # sub-technique display name: "Parent: Child" (T1134.002 etc.)
    for r in objs:
        if r["type"] == "relationship" and r.get("relationship_type") == "subtechnique-of":
            child, parent = r.get("source_ref"), r.get("target_ref")
            if child in aps and parent in aps and "." in aps[child]["tid"]:
                aps[child]["name"] = f"{aps[parent]['name']}: {aps[child]['name']}"

    # group -> technique ("uses" relationships carry the procedure text)
    for r in objs:
        if (r["type"] == "relationship" and r.get("relationship_type") == "uses"
                and r.get("source_ref") in groups and r.get("target_ref") in aps):
            proc = clean_procedure(r.get("description", ""))
            if not proc:
                continue
            ap = aps[r["target_ref"]]
            g = groups[r["source_ref"]]
            entry = g["techniques"].setdefault(ap["tid"], {
                "technique_id": ap["tid"],
                "technique_name": ap["name"],   # 'Parent: Child' for sub-techniques
                "tactics": ap["tactics"], "platforms": ap["platforms"],
                "url": ap["url"],
                "attack_data_components": sorted(ap["components"]),
                "data_sources": sorted({DC_MAP[c] for c in ap["components"]
                                        if c in DC_MAP}),
                "procedures": [],
            })
            entry["procedures"].append(proc)

    # assemble + extract commands
    out_groups = []
    n_tech = 0
    for g in groups.values():
        techs = []
        for t in g["techniques"].values():
            t["procedure"] = t["procedures"][0]
            cmds: list[str] = []
            for p in t["procedures"]:
                for c in extract_commands(p):
                    if c not in cmds:
                        cmds.append(c)
            t["commands"] = cmds[:5]
            t["command"] = cmds[0] if cmds else None
            t.pop("procedures")  # keep the first only, as 'procedure'
            techs.append(t)
        techs.sort(key=lambda t: t["technique_id"])
        n_tech += len(techs)
        out_groups.append({
            "id": g["gid"], "name": g["name"], "aliases": g["aliases"],
            "description": g["description"], "url": g["url"],
            "techniques": techs,
        })
    out_groups.sort(key=lambda g: g["name"].lower())

    doc = {
        "meta": {
            "source": "https://attack.mitre.org/ (MITRE ATT&CK CTI, enterprise-attack.json)",
            "generated": datetime.date.today().isoformat(),
            "groups": len(out_groups),
            "group_technique_pairs": n_tech,
            "note": ("procedures are quoted verbatim from the ATT&CK Groups objects; "
                     "'command' is the best concrete command/API call extracted from "
                     "the procedure text, 'commands' lists up to 5 candidates; "
                     "'data_sources' maps ATT&CK data components onto the app's "
                     "modeled sensor vocabulary (unmodeled components are omitted)."),
        },
        "groups": out_groups,
    }
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=1, ensure_ascii=False)

    print(f"groups: {len(out_groups)}  technique pairs: {n_tech}")
    print(f"written: {out_path}")


if __name__ == "__main__":
    main()
