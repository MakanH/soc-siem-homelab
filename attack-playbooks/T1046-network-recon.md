# T1046 - Network Service Scanning

Incident-report-style writeup of network reconnaissance run from the Kali
attacker against the corporate LAN, the telemetry it produced, and the
defensive findings it surfaced.

| | |
|---|---|
| **MITRE technique** | T1046 - Network Service Scanning |
| **Tactic** | Discovery |
| **Attacker** | Kali, 10.10.10.50 (corporate LAN) |
| **Targets** | 10.10.10.0/24 - pfSense gateway (10.10.10.1) and the DC (10.10.10.10) |
| **Log source** | pfSense firewall logs / host connection telemetry |

## Objective
Enumerate live hosts and open services on the corporate LAN - the first move an
attacker makes after gaining a foothold, to find what can be attacked next.

## Attacker actions
A full-port SYN scan of the corporate subnet from the Kali attacker:

```bash
sudo nmap -sS -p- --min-rate 1000 10.10.10.0/24
```

`-sS` is a half-open SYN scan (stealthier than a full connect), `-p-` covers all
65,535 TCP ports, and `--min-rate 1000` pushes packets fast enough to finish the
sweep in a couple of minutes.

## What was logged / observed
The scan returned two live hosts and, importantly, revealed each host's exposure:

```
Nmap scan report for pfsense.lab.local (10.10.10.1)
PORT    STATE SERVICE
53/tcp  open  domain
80/tcp  open  http
443/tcp open  https

Nmap scan report for 10.10.10.10        # the Domain Controller
All 65535 scanned ports are in ignored states (filtered).
```

Two defensive findings fell out of the recon itself:
- **pfSense** exposed DNS (53) and its web GUI (80/443) to the LAN.
- **The DC initially showed every port filtered** - its Windows host firewall was
  dropping all inbound probes, including SMB (445). This is a genuinely good
  posture: even from inside the LAN, the DC's services were not casually
  reachable. (For the follow-on T1110 brute-force test, the host firewall was
  deliberately relaxed to allow the attack to land - see that playbook.)

## Detection logic
A `-p-` SYN scan generates a large fan-out of connection attempts from one source
to many ports/hosts in a short window - a pattern distinct from normal traffic.
The signals available to correlate it:
- pfSense logs the connection attempts crossing/hitting its interfaces.
- The volume + fan-out from a single internal source is the tell: hundreds of
  distinct destination ports from `10.10.10.50` within seconds is not something a
  legitimate workstation does.

<!-- If you enable pfSense log forwarding to Wazuh later, add the specific rule
     ID that flags the scan here and a screenshot of the alert. -->

## Analyst notes (triage & response)
**Triage**
- Identify the source. Internal recon from a workstation IP that has no business
  port-scanning is a strong indicator of a compromised host or an insider.
- Scope the scan: a single-host probe is low concern; a full `/24`, all-ports
  sweep is deliberate discovery activity and should raise priority.

**Containment**
- Isolate the scanning host pending investigation; block it at pfSense if it is
  not an authorized scanner.
- Correlate timing: recon is usually the precursor to an attack. Check what the
  same source did *next* (here, it pivoted to an SMB brute-force against the DC).

**Hardening**
- The DC's default-deny host firewall is exactly what limited what the recon
  could find - keep host firewalls restrictive even on internal segments.
- Network segmentation already limits blast radius; ensure only required
  management hosts can reach infrastructure like pfSense's GUI (80/443).

**Detection improvement**
- Forward pfSense firewall logs into Wazuh and add a rule that flags a single
  source hitting a high number of distinct destination ports within a short
  timeframe - this turns "noise in the firewall log" into an actionable
  scan-detected alert.
