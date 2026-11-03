"""Graph data model for the security architecture playground.

A *design* is a graph of components (nodes) and connections (edges) drawn on
the canvas. Everything else in the engine consumes this object:
sensor coverage, kill-chain path-finding and the simulation itself.

Deliberately tiny: one Node dataclass, one Edge dataclass, one Graph class
with the handful of helpers the engine needs.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field, asdict

# ---------------------------------------------------------------------------
# Component taxonomy — the types the canvas palette can place.
# ---------------------------------------------------------------------------
HOST_TYPES      = {"workstation", "server_win", "server_linux", "web_server"}
WINDOWS_TYPES   = {"workstation", "server_win", "web_server"}   # Sysmon-capable
SENSOR_KINDS    = {"edr", "sysmon", "zeek", "netflow", "siem"}
APPLIANCE_KINDS = {"waf", "firewall", "mail_gateway"}
CLOUD_KINDS     = {"idp", "iam", "s3"}                          # own audit logs
SUBNET_TYPES    = {"subnet"}
ALL_TYPES       = HOST_TYPES | SENSOR_KINDS | APPLIANCE_KINDS | CLOUD_KINDS | SUBNET_TYPES | {"internet"}

# Component types that are "places where attack steps land" (simulation targets)
TARGETABLE_TYPES = HOST_TYPES | CLOUD_KINDS


@dataclass
class Node:
    """A component on the canvas (host, sensor, appliance, cloud service...)."""
    id: str
    type: str
    label: str
    x: float = 0.0
    y: float = 0.0
    # Free-form per-type configuration, e.g. {"mfa": true} on an IdP or
    # {"egress": "default-deny"} on a firewall. Inspected by coverage.py.
    props: dict = field(default_factory=dict)


@dataclass
class Edge:
    """A connection between two components. Direction is only cosmetic
    (arrow rendering); the engine treats the graph as undirected."""
    id: str
    src: str
    dst: str


@dataclass
class Graph:
    nodes: list[Node] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)

    # -- lookups ------------------------------------------------------------
    def node(self, node_id: str) -> Node | None:
        idx = {n.id: n for n in self.nodes}
        return idx.get(node_id)

    def by_type(self, t: str) -> list[Node]:
        return [n for n in self.nodes if n.type == t]

    def hosts(self) -> list[Node]:
        return [n for n in self.nodes if n.type in HOST_TYPES]

    def neighbors(self, node_id: str) -> list[str]:
        out = []
        for e in self.edges:
            if e.src == node_id:
                out.append(e.dst)
            elif e.dst == node_id:
                out.append(e.src)
        return out

    # -- mutation ------------------------------------------------------------
    def add_node(self, node: Node) -> None:
        self.nodes.append(node)

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def remove_node(self, node_id: str) -> None:
        self.nodes = [n for n in self.nodes if n.id != node_id]
        self.edges = [e for e in self.edges if e.src != node_id and e.dst != node_id]

    # -- graph algorithms ----------------------------------------------------
    def find_path(self, src: str, dst: str) -> list[str] | None:
        """BFS shortest path as a list of node ids (inclusive), or None."""
        if src == dst:
            return [src]
        prev = {src: None}
        q = deque([src])
        while q:
            cur = q.popleft()
            for nb in self.neighbors(cur):
                if nb in prev:
                    continue
                prev[nb] = cur
                if nb == dst:
                    path = [dst]
                    while prev[path[-1]] is not None:
                        path.append(prev[path[-1]])
                    return list(reversed(path))
                q.append(nb)
        return None

    # -- (de)serialisation ----------------------------------------------------
    def to_dict(self) -> dict:
        return {"nodes": [asdict(n) for n in self.nodes],
                "edges": [asdict(e) for e in self.edges]}

    @staticmethod
    def from_dict(d: dict) -> "Graph":
        g = Graph(
            nodes=[Node(**n) for n in d.get("nodes", [])],
            edges=[Edge(**e) for e in d.get("edges", [])],
        )
        return g
