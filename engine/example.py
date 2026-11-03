"""Bundled example architecture — a small but realistic corporate design
with *deliberate* observability gaps:

  * no mail gateway          → the phishing email is never seen
  * no WAF                   → web exploits only show up as process spawns
  * EDR toggle ON on WS-001  → WS-002 stays a blind host
  * FILE-01 carries no agent → lateral movement is invisible
  * Zeek only on the DMZ     → LAN network traffic unseen
  * SIEM wired to some, not all sensors
  * cloud audit logs NOT shipped to the SIEM → the cloud is a black box
  * firewall egress = default-allow → C2 and exfil flow freely (toggle it!)

Endpoint telemetry (EDR / Sysmon) is configured as toggles on the host
itself; a host only ships those rows to the SIEM if it is wired to one.
Draw your own design or tweak this one, then re-run a scenario and compare.
"""
from __future__ import annotations

from .models import Graph, Node, Edge


def build() -> Graph:
    g = Graph()
    n = lambda id_, type_, label, x, y, **props: g.add_node(
        Node(id=id_, type=type_, label=label, x=x, y=y, props=props))

    # --- perimeter -----------------------------------------------------------
    n("internet", "internet", "Internet", 55, 250)
    n("fw-core", "firewall", "fw-core", 175, 250, egress="default-allow", segmentation=False)

    # --- DMZ ------------------------------------------------------------------
    n("dmz", "subnet", "DMZ", 335, 105)
    n("zeek", "zeek", "Zeek (DMZ SPAN)", 335, 30)
    n("app01", "web_server", "APP-01 (IIS)", 505, 105, sysmon=True)

    # --- corporate LAN ---------------------------------------------------------
    n("lan", "subnet", "Corp LAN", 335, 375)
    n("ws001", "workstation", "WS-001", 505, 300, edr=True)
    n("ws002", "workstation", "WS-002", 505, 375)
    n("file01", "server_win", "FILE-01", 505, 450)

    # --- security tooling -------------------------------------------------------
    n("siem", "siem", "SIEM", 780, 140)

    # --- cloud -------------------------------------------------------------------
    n("idp", "idp", "SSO / IdP", 610, 440, mfa=False)
    n("vpc", "subnet", "Cloud VPC", 730, 440)
    n("iam", "iam", "IAM / Control Plane", 845, 380)
    n("s3", "s3", "S3: customer-backups", 845, 465, block_public=False)

    e = lambda a, b: g.add_edge(Edge(id=f"e-{a}-{b}", src=a, dst=b))
    # perimeter & segments
    e("internet", "fw-core"); e("fw-core", "dmz"); e("dmz", "lan")
    e("dmz", "app01"); e("zeek", "dmz")
    e("lan", "ws001"); e("lan", "ws002"); e("lan", "file01")
    # SIEM ingest (only some sensors ship logs!) — hosts with an agent
    # toggle forward their telemetry when wired to the SIEM
    e("ws001", "siem"); e("app01", "siem"); e("zeek", "siem")
    # cloud hangs off the LAN via the IdP
    e("lan", "idp"); e("idp", "vpc"); e("vpc", "iam"); e("vpc", "s3")
    return g
