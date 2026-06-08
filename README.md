# SOC Detection Lab — Segmented Network, Wazuh SIEM & Custom Detections

> 🚧 **Work in progress.** Building this lab out phase by phase — see the commit history.

Building a security operations lab from scratch: a **pfSense-segmented network**
(Corporate LAN / DMZ / SIEM subnet), centralized detection with **Wazuh** across
**Windows (Active Directory)** and **Linux** endpoints, **custom decoders and
correlation rules**, and detections validated against **simulated attacks** and
mapped to **MITRE ATT&CK**.

## Planned architecture

```mermaid
graph TD
  NET((Internet)) --> WAN[pfSense WAN / NAT]
  WAN --> FW{{pfSense<br/>Segmentation + Firewall Rules}}
  FW -->|10.10.10.0/24| LAN[Corporate LAN]
  FW -->|10.10.20.0/24| DMZ[DMZ]
  FW -->|10.10.30.0/24| SIEM[SIEM Subnet]
  LAN --- DC[Windows Server<br/>AD / DC<br/>Sysmon + Wazuh agent]
  LAN --- WIN[Windows Client<br/>Sysmon + Wazuh agent]
  DMZ --- LIN[Linux Endpoint<br/>Wazuh agent + CustomApp]
  SIEM --- WZ[Wazuh Manager<br/>Indexer + Dashboard]
  LAN -. simulated attacks .-> ATT[Kali Attacker]
```

## Goals
- **Network segmentation & firewall policy design** — isolated LAN / DMZ / SIEM zones (pfSense)
- **SIEM operations** — centralized log collection and triage across Windows + Linux (Wazuh)
- **Detection engineering** — hand-written XML decoders and multi-stage correlation rules
- **Adversary emulation** — simulated attacks, each validated against a detection and mapped to MITRE ATT&CK

## Stack
Kali Linux (host) · VirtualBox · pfSense · Wazuh 4.14 · Windows Server (Active
Directory) · Sysmon · Ubuntu · Kali (attacker) · C# / .NET 8

## Status
Build in progress. Documentation, custom detections, and attack writeups are added
to this repo as each phase is completed.
