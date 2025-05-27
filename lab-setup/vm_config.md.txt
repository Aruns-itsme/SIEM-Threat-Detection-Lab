# Lab VM Configuration – SIEM Threat Detection Project

This document outlines the virtual machine configurations for the lab environment. The setup includes:

Wazuh SIEM server  
Splunk instance  
Windows 10 client (for simulations)  
(Optional) Kali Linux for advanced testing

---

## Virtual Machines Overview

| VM Name         | OS                 | vCPU  | RAM    | Disk   | Network        | Role / Purpose                           |
|-----------------|--------------------|-------|--------|--------|----------------|------------------------------------------|
| **Wazuh-SIEM**  | Ubuntu 22.04 LTS   | 2     | 4 GB   | 40 GB  | Host-Only/NAT  | Wazuh Manager, Kibana Dashboard          |
| **Splunk-Server**| Ubuntu 22.04 LTS  | 2     | 4 GB   | 40 GB  | Host-Only/NAT  | Splunk Search Head & Indexer             |
| **Windows-Client**| Windows 10 Pro   | 2     | 4 GB   | 50 GB  | Host-Only/NAT  | Sysmon + Winlogbeat + Attack Simulations |
| **Kali-Linux** (Optional) | Kali Rolling | 1     | 2 GB   | 30 GB  | Host-Only/NAT  | Advanced attacks (e.g., Metasploit)  |

---

## Tools & Software Required

### **Wazuh-SIEM** (Ubuntu)
- Wazuh Manager (4.x)
- Kibana / Elasticsearch
- Filebeat (if required)

### **Splunk-Server** (Ubuntu)
- Splunk Enterprise (Free for testing)
- Forwarder/Receiver for logs

### **Windows-Client** (Windows 10)
- Sysmon (from Sysinternals Suite)
- Winlogbeat (configured for Wazuh/Splunk)
- PowerShell 5.1+
- Mimikatz (for lab testing)
- Atomic Red Team simulations from `atomic_red_team_simulations.md`

### **Kali-Linux** (Optional)
- Metasploit Framework
- Nmap, Hydra (optional)

---

## Network Configuration

| Network Adapter | Type        | Notes                                 |
|-----------------|-------------|---------------------------------------|
| Adapter 1       | Host-Only   | Internal lab communication             |
| Adapter 2       | NAT         | For internet access (updates, tools)   |

> Adjust IP addresses statically or use DHCP, ensuring all VMs are reachable.

---

## Security Notes

- **Isolate the lab from your production network.**
- **Use NAT for internet access only if required for updates.**
- **Never run attack tools like Mimikatz on production systems.**

---

## Deployment Steps

1. **Install VMs** with the specs above.
2. **Install required software** on each system.
3. **Configure logging agents** (Winlogbeat, Sysmon, Filebeat).
4. **Import detection rules** into Wazuh and Splunk.
5. **Execute attack simulations** from the Windows VM.
6. **Validate detections** in Wazuh and Splunk dashboards.

---
