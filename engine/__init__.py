"""Security architecture playground — simulation engine.

Package layout (each file has one job):
    models.py     graph data model (components + connections)
    coverage.py   sensor specs, data-source coverage, alert & block rules
    scenarios.py  ATT&CK-mapped adversary scenarios with documented tradecraft
    noise.py      benign background events (alert fatigue)
    simulator.py  kill-chain runner: coverage resolution + verdicts + recording
    example.py    the bundled example architecture graph
"""
