# 05 — Endpoints & Agents

Endpoints are onboarded to Wazuh so their telemetry is collected and analysed centrally.
Each endpoint runs a Wazuh agent that reports to the manager on the SIEM segment
(`10.10.30.10`) over ports 1514–1515.

## Onboarded endpoints

| Host | Segment | IP | OS | Telemetry |
|---|---|---|---|---|
| Domain controller | LAN | `10.10.10.10` | Windows Server 2022 | Windows Security log + Sysmon |
| DMZ endpoint | DMZ | `10.10.20.10` | Ubuntu Server 22.04 | syslog + CustomApp application log |

The DMZ endpoint is a single-homed Linux host on the semi-exposed segment. It intentionally
has no management interface — it is reached only through its console — which mirrors how a
real DMZ asset would be isolated from the workstation network. It is also the host that runs
the custom application whose authentication events feed the detection rules (see
`06-detections.md`).

## Linux agent install (DMZ endpoint)

```bash
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo gpg --no-default-keyring \
  --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
sudo chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
  | sudo tee /etc/apt/sources.list.d/wazuh.list
sudo apt update
sudo WAZUH_MANAGER="10.10.30.10" WAZUH_AGENT_NAME="dmz-endpoint" apt install wazuh-agent -y
sudo systemctl enable --now wazuh-agent
```

## Segmentation validation

Agent enrollment exercises the firewall policy from real hosts, not just on paper:

- The **DC** (LAN) reaches the manager because the LAN rule permits LAN → `10.10.30.10`.
- The **DMZ endpoint** reaches the manager because the DMZ rule permits DMZ → `10.10.30.10`
  on 1514–1515, while DMZ → LAN remains blocked.

Both agents showing **Active** in the dashboard therefore confirms the allow-paths work while
the isolation rules stay in force. The dashboard view with the DC active is captured in
`screenshots/05-wazuh-agent-dc01.png`.

## Future addition

A domain-joined Windows 10/11 client on the LAN is a natural next endpoint (a realistic
"employee workstation" and secondary Windows telemetry source). It is deferred because the
domain controller already provides Windows + Sysmon telemetry, and the primary credential
attack is observed at the DC regardless. Agent config snippets for reuse are in
`../config-reference/`.
