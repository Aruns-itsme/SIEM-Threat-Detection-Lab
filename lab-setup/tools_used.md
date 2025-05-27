# Tools Used in SIEM Threat Detection Lab

This document outlines the tools, platforms, and technologies used across the lab environment for MITRE ATT&CK simulations, detection rules, and log aggregation.

---

## Virtualization Platform

| Tool             | Purpose                                    | Notes                             |
|------------------|--------------------------------------------|-----------------------------------|
| VirtualBox / VMware | Host the lab virtual machines           | Required for isolated environment  |
| Vagrant (Optional) | Automate VM provisioning (optional)      | For advanced users                |

---

## Security Information & Event Management (SIEM)

| Tool        | Role                        | Host                  | Notes                                |
|-------------|-----------------------------|-----------------------|--------------------------------------|
| Wazuh       | SIEM & host-based IDS       | Ubuntu Server (Wazuh) | Detection rules via `wazuh_detection_rules.xml` |
| Splunk      | Log aggregation & detection | Ubuntu Server (Splunk) | Detection rules via `splunk_detection_rules.md` |

---

## Windows Client (Attack Simulation Host)

| Tool          | Purpose                              | Notes                                |
|---------------|---------------------------------------|--------------------------------------|
| Sysmon        | System event logging (process, file, network) | Logs forwarded to Wazuh/Splunk      |
| Winlogbeat    | Forward Windows event logs            | Connects Windows VM to SIEM solutions |
| Mimikatz      | Credential dumping simulation         | For T1003.001 Credential Access tests |
| PowerShell    | Command-line scripting for attack simulations | Used for many MITRE techniques      |
| Atomic Red Team Simulations | MITRE ATT&CK scenario execution | Refer to `atomic_red_team_simulations.md` |

---

## Optional Tools (Advanced Attack Simulation)

| Tool            | Purpose                           | Host           | Notes                        |
|-----------------|------------------------------------|----------------|------------------------------|
| Kali Linux      | Advanced attacker VM (optional)    | Kali VM        | For penetration testing      |
| Metasploit      | Post-exploitation & lateral movement | Kali VM        | Optional for advanced tests  |
| Hydra           | Brute-force simulation            | Kali VM        | For T1021.001 (RDP brute force) |

---

## Visualization & Dashboards

| Tool          | Purpose                               | Notes                                |
|---------------|----------------------------------------|--------------------------------------|
| Kibana        | Visualize Wazuh alerts & logs          | Integrated with Wazuh                |
| Splunk Search UI | Visualize logs, search, create dashboards | Via Splunk web interface             |

---

## Documentation & Resources

| File                            | Purpose                                          |
|---------------------------------|--------------------------------------------------|
| `atomic_red_team_simulations.md`| MITRE attack scenarios for Windows Client       |
| `wazuh_detection_rules.xml`     | Wazuh detection rules for 80 MITRE techniques   |
| `splunk_detection_rules.md`     | Splunk detection rules for 80 MITRE techniques  |
| `network_topology.png`          | Visual diagram of lab environment              |
| `vm_config.md`                  | VM specifications and deployment info          |
| `README.md`                     | Project overview, setup, and deployment guide  |

---

## Important Notes

- All tools are for **educational and lab use only**.  
- Never deploy offensive tools like Mimikatz or Metasploit on production systems.  
- Ensure the lab is **isolated from your main network** to prevent unintended impacts.

---
