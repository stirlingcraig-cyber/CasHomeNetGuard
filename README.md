# CAS HomeNet Guard
*CAS Solutions — home network & IoT protection for Windows 10/11*

A desktop security console that watches every device on your home network, detects trojans, botnets, data exfiltration and exploit attempts, and blocks bad actors through Windows Defender Firewall.

## Protection layers

| Layer | What it does | Needs Npcap? |
|---|---|---|
| **Threat intelligence** | Checks every connection against abuse.ch Feodo Tracker (botnet C2), Spamhaus DROP and your own blocklist. Auto-updates every 6 h. | No (connections) / Yes (all packets) |
| **Packet inspection (DPI)** | 13 targeted signatures: Mirai/Gafgyt BusyBox commands, wget-pipe-to-shell droppers, Mozi, `/bins/<arch>` downloads, GPON, Netgear, D-Link HNAP, Realtek UPnP exploits, Log4Shell, Shellshock, path traversal. | Yes |
| **Behavioural AI** | Learns each device's normal upload volume (EWMA mean/variance per 10 s) and flags exfiltration bursts, port scans, worm-style sweeps (e.g. a camera hitting 40+ hosts on Telnet) and machine-regular C2 beaconing. | Yes |
| **Connection monitor** | Maps every TCP connection on this PC to its program; flags threat-list IPs, backdoor ports and programs running from Temp. End or locate the program with one click. | No |
| **Device audit (IoT)** | Ping sweep + ARP + UPnP/SSDP discovery, vendor ID, and probes ports that IoT malware abuses (Telnet, ADB, DVR backdoors, RTSP, MQTT, TR-069…). Rates each device and gives fix-it steps. New-device alerts. | No |
| **Firewall response** | Creates paired in/out block rules (`CAS-HNG Block <ip>`), keeps a register, re-applies rules after a firewall reset. | No |

## Changes from the original HomeNetGuard brief (deliberate)
- **No automatic process killing.** Killing by remote IP can terminate browsers or Windows services on a false positive. Ending a program is a confirmed one-click action on the Connections page.
- **Signatures tightened.** Generic words such as `exec`, `mips`, `arm7` matched ordinary web traffic and would have blocked legitimate sites. Every rule now targets a specific, documented attack artefact.
- **LAN devices and the router are never auto-blocked** — doing so can knock you offline. You get an alert and isolation guidance instead.
- **Anomaly model fixed.** The per-packet list grew unbounded and judged single packet sizes; it now models per-device traffic per time window with bounded memory and a 5-minute warm-up.
- **Three response modes** (Settings): Alert only · Recommended (auto-block confirmed threats) · Strict.
- **Start-up via Scheduled Task with highest privileges** rather than a Run key (an admin app launched from the Run key prompts UAC every boot).

## Build
1. Install the [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).
2. Double-click `build.bat` → produces `publish\CasHomeNetGuard.exe` (single self-contained file, no .NET needed on target PCs).

Or push the folder to GitHub — `.github/workflows/build.yml` builds the exe on a Windows runner and attaches it as a downloadable artifact.

## Install & first run
1. Install **Npcap** from https://npcap.com (tick *“Install Npcap in WinPcap API-compatible mode”*). Without it the app still runs connection monitoring, threat intel and device audits.
2. Run `CasHomeNetGuard.exe` (it asks for administrator rights — required for firewall rules and packet capture).
3. Settings → tick *Start protection automatically when I sign in*.
4. Devices → **Scan network now**, then name and mark trusted the devices you recognise.

## Seeing IoT traffic, not just this PC's
On Wi-Fi, Windows only sees its own traffic. To inspect every smart device:
- connect this PC by Ethernet to a managed switch with **port mirroring** of the router uplink, enable *Promiscuous mode* in Settings; or
- run the device audit only (works on any network) and put IoT gadgets on a separate guest/IoT Wi-Fi.

Blocking a compromised IoT device from the internet must be done on the router — the Devices page shows the steps.

## Data
`C:\ProgramData\CAS Solutions\HomeNetGuard\` — settings.json, alerts.jsonl, devices.json, blocked.json, blocklist.txt (edit freely), feed-cache.txt, engine.log.

## Uninstall
Settings → untick start-up · Firewall → **Unblock all** · delete the exe and the data folder.

## Project layout
```
Program.cs                single-instance entry point
Core/GuardEngine.cs       orchestrator: capture → intel → DPI → anomaly → response
Core/ThreatIntel.cs       IP/CIDR reputation store + feed updater
Core/Signatures.cs        DPI rules
Core/AnomalyEngine.cs     behavioural detection
Core/DeviceScanner.cs     LAN/IoT discovery and risk audit
Core/ConnectionMonitor.cs TCP table → process mapping
Core/FirewallManager.cs   Windows Firewall rules
Core/AlertStore.cs, Settings.cs, AutoStart.cs, Models.cs, IpUtil.cs, AppPaths.cs
UI/                       themed WinForms console (Overview, Devices, Alerts, Connections, Firewall, Activity, Settings) + tray
```
