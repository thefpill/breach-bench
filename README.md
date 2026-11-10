# Security Architecture Playground

**See your blind spots before an attacker does.**

Draw a security architecture, pick an adversary, replay the kill chain against
your design, and read what your sensors actually saw. Every attacker step gets
an honest verdict: blocked, detected, observed, or blind. No percentages, no
scores. Blind spots are something you walk into and feel, not a number in a
report.

## Quick start

```bash
pip install -r requirements.txt
python main.py           
```
Port 80 needs extra rights on Linux but you can overwrite default port with `--port 8000`.

## The 30-second tour

1. **Draw.** Drag subnets, firewalls, WAF, mail gateway, hosts, Zeek, IDS,
   NetFlow, SIEM, IdP, IAM and S3 onto the canvas and wire them up.
2. **Instrument.** Hosts carry EDR / Sysmon toggles. Firewalls get egress
   policy and segmentation. IdP gets MFA. Sensors only see what they are
   wired to.
3. **Run an adversary.** 170+ scenarios built from documented ATT&CK
   tradecraft: phishing, lateral movement, cloud attacks, C2, exfil.
4. **Read both sides.** The defender console shows only what your sensors
   produced, mixed with benign noise. The adversary view shows the ground
   truth and who saw what.
5. **Redesign and run again.** Watch alerts appear, disappear, and mislead.

## Honest modeling

- Sensors only know what their data source carries. Zeek sees the network,
  never the process. EDR sees the process, not the wire. IDS matches
  signatures but cannot explain them.
- A SIEM shows only what is shipped to it. Cloud audit rows are invisible
  until something links the cloud to your SIEM.
- Recon and resource development happen on the attacker's side, so nothing
  in your design sees them. That blind spot is a fact, not a bug.
- Benign noise per minute is adjustable. Alert fatigue is part of the game.

## Canvas controls

Mouse wheel zooms. Space plus drag pans. Drag on empty canvas to
rubber-band select. The dot on each asset hides just that asset's
connection lines. The canvas grows as you drag toward its edge.

## Stack

FastAPI backend, vanilla JS + SVG frontend, zero frontend frameworks.
Everything runs locally, nothing phones home.

## Full guide

Sensors, detection catalog, scenario editor, and the design-to-engine join
model: [docs/GUIDE.md](docs/GUIDE.md)
