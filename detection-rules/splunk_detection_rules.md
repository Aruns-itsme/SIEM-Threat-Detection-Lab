# 📦 Splunk Detection Rules with Descriptions for 30 Atomic Red Team Techniques

## 🔍 T1003.001

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1059.001

### Description
Detects suspicious PowerShell activity commonly used for script execution and downloading malicious code.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell* EventCode=4104 Message="*Invoke-Expression*" OR Message="*DownloadString*"
```

---

## 🔍 T1071.001

### Description
Detects HTTP-based exfiltration attempts using PowerShell and non-standard network ports.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=3 Image="*powershell.exe" DestinationPort!=80 DestinationPort!=443
```

---

## 🔍 T1086

### Description
Detects the use of Windows command-line interface for creating user accounts or privilege escalation.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security (EventCode=4720 OR (EventCode=4688 AND CommandLine="*net user* /add*"))
```

---

## 🔍 T1021.001

### Description
Detects RDP brute-force login attempts through repeated failed login logs (Event ID 4625).

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4625 LogonType=10 | stats count by Account_Name, Source_Network_Address | where count > 5
```

---

## 🔍 T1033

### Description
Detects enumeration of the current user context using 'whoami' or similar utilities.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*whoami*"
```

---

## 🔍 T1057

### Description
Detects usage of 'tasklist' to enumerate running processes, which could be reconnaissance.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*tasklist.exe"
```

---

## 🔍 T1016

### Description
Detects execution of 'ipconfig' to gather local network configuration details.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*ipconfig.exe"
```

---

## 🔍 T1082

### Description
Detects the use of 'systeminfo' to enumerate system details like patch level and hostname.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*systeminfo.exe"
```

---

## 🔍 T1049

### Description
Detects the use of 'netstat' to check active network connections, ports, and listeners.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*netstat.exe"
```

---

## 🔍 T1005

### Description
Detects access to sensitive files on disk, indicating possible data staging or theft.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4663 Object_Name="C:\\sensitive_data.txt"
```

---

## 🔍 T1218.005

### Description
Detects use of regsvr32 to execute remote scripts as a LOLBin technique.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*regsvr32.exe" CommandLine="*scrobj.dll*"
```

---

## 🔍 T1055.001

### Description
Detects suspicious DLL injection via rundll32 into target processes.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*rundll32.exe" CommandLine="*evil.dll*"
```

---

## 🔍 T1562.001

### Description
Detects attempts to disable Windows Defender real-time protection via PowerShell.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*Set-MpPreference*"
```

---

## 🔍 T1036.005

### Description
Detects a renamed executable mimicking svchost.exe for masquerading and evasion.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*svchost.exe" AND ParentProcessName!="C:\\Windows\\System32\\services.exe"
```

---

## 🔍 T1003.0016

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0017

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0018

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0019

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0020

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0021

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0022

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0023

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0024

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0025

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0026

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0027

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0028

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0029

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1003.0030

### Description
Detects unauthorized memory access to LSASS.exe for credential dumping, typically via Mimikatz.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe" NOT (Image="C:\\Windows\\System32\\taskmgr.exe")
```

---

## 🔍 T1131

### Description
Detects creation of scheduled tasks which may indicate persistence techniques.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4698 TaskName="*Updater*"
```

---

## 🔍 T1132

### Description
Detects querying privilege information via whoami.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*whoami*" CommandLine="*/priv*"
```

---

## 🔍 T1133

### Description
Detects obfuscated PowerShell command execution.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell* EventCode=4104 Message="*-EncodedCommand*"
```

---

## 🔍 T1134

### Description
Detects Mimikatz-style credential harvesting from memory.

### SPL Query
```spl
index=windows sourcetype=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational EventCode=10 TargetImage="*lsass.exe"
```

---

## 🔍 T1135

### Description
Detects execution of network enumeration commands like net view and net user.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 (CommandLine="*net view*" OR CommandLine="*net user*")
```

---

## 🔍 T1136

### Description
Detects execution of PsExec, often used for lateral movement.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*PsExec.exe*"
```

---

## 🔍 T1137

### Description
Detects staging of document files in unusual directories.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4663 Object_Name="*\Staged\*.docx"
```

---

## 🔍 T1138

### Description
Detects PowerShell beaconing to external C2 servers.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Microsoft-Windows-PowerShell* EventCode=4104 Message="*DownloadString*"
```

---

## 🔍 T1139

### Description
Detects file copy to network shares, indicating data exfiltration.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=5145 ShareName="\\10.10.10.10\share"
```

---

## 🔍 T1140

### Description
Detects renamed tool execution such as renamed PowerShell.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*notepad.exe"
```

---

## 🔍 T1141

### Description
Detects behavior associated with MITRE tactic credential access, mapped to technique T1141.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*mimikatz*" OR TargetImage="*lsass.exe"
```

---
## 🔍 T1142

### Description
Detects behavior associated with MITRE tactic command and control, mapped to technique T1142.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*"
```

---
## 🔍 T1143

### Description
Detects behavior associated with MITRE tactic command and control, mapped to technique T1143.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*"
```

---
## 🔍 T1144

### Description
Detects behavior associated with MITRE tactic execution, mapped to technique T1144.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell.exe*" CommandLine="*-EncodedCommand*"
```

---
## 🔍 T1145

### Description
Detects behavior associated with MITRE tactic exfiltration, mapped to technique T1145.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*Out-File*" AND CommandLine="\\10.10.10.10\*"
```

---
## 🔍 T1146

### Description
Detects behavior associated with MITRE tactic execution, mapped to technique T1146.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell.exe*" CommandLine="*-EncodedCommand*"
```

---
## 🔍 T1147

### Description
Detects behavior associated with MITRE tactic command and control, mapped to technique T1147.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*"
```

---
## 🔍 T1148

### Description
Detects behavior associated with MITRE tactic defense evasion, mapped to technique T1148.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*attrib +h*" OR CommandLine="*icacls*"
```

---
## 🔍 T1149

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1149.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1150

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1150.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1151

### Description
Detects behavior associated with MITRE tactic privilege escalation, mapped to technique T1151.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*bypassuac*" OR CommandLine="*token*"
```

---
## 🔍 T1152

### Description
Detects behavior associated with MITRE tactic collection, mapped to technique T1152.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*copy*" AND CommandLine="*.docx"
```

---
## 🔍 T1153

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1153.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1154

### Description
Detects behavior associated with MITRE tactic exfiltration, mapped to technique T1154.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*Out-File*" AND CommandLine="\\10.10.10.10\*"
```

---
## 🔍 T1155

### Description
Detects behavior associated with MITRE tactic collection, mapped to technique T1155.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*copy*" AND CommandLine="*.docx"
```

---
## 🔍 T1156

### Description
Detects behavior associated with MITRE tactic exfiltration, mapped to technique T1156.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*Out-File*" AND CommandLine="\\10.10.10.10\*"
```

---
## 🔍 T1157

### Description
Detects behavior associated with MITRE tactic execution, mapped to technique T1157.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell.exe*" CommandLine="*-EncodedCommand*"
```

---
## 🔍 T1158

### Description
Detects behavior associated with MITRE tactic lateral movement, mapped to technique T1158.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*PsExec.exe*"
```

---
## 🔍 T1159

### Description
Detects behavior associated with MITRE tactic collection, mapped to technique T1159.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*copy*" AND CommandLine="*.docx"
```

---
## 🔍 T1160

### Description
Detects behavior associated with MITRE tactic execution, mapped to technique T1160.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell.exe*" CommandLine="*-EncodedCommand*"
```

---
## 🔍 T1161

### Description
Detects behavior associated with MITRE tactic execution, mapped to technique T1161.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell.exe*" CommandLine="*-EncodedCommand*"
```

---
## 🔍 T1162

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1162.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1163

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1163.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1164

### Description
Detects behavior associated with MITRE tactic privilege escalation, mapped to technique T1164.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*bypassuac*" OR CommandLine="*token*"
```

---
## 🔍 T1165

### Description
Detects behavior associated with MITRE tactic command and control, mapped to technique T1165.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*"
```

---
## 🔍 T1166

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1166.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1167

### Description
Detects behavior associated with MITRE tactic defense evasion, mapped to technique T1167.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*attrib +h*" OR CommandLine="*icacls*"
```

---
## 🔍 T1168

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1168.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1169

### Description
Detects behavior associated with MITRE tactic command and control, mapped to technique T1169.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*"
```

---
## 🔍 T1170

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1170.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1171

### Description
Detects behavior associated with MITRE tactic credential access, mapped to technique T1171.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*mimikatz*" OR TargetImage="*lsass.exe"
```

---
## 🔍 T1172

### Description
Detects behavior associated with MITRE tactic credential access, mapped to technique T1172.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*mimikatz*" OR TargetImage="*lsass.exe"
```

---
## 🔍 T1173

### Description
Detects behavior associated with MITRE tactic privilege escalation, mapped to technique T1173.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*bypassuac*" OR CommandLine="*token*"
```

---
## 🔍 T1174

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1174.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1175

### Description
Detects behavior associated with MITRE tactic lateral movement, mapped to technique T1175.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*PsExec.exe*"
```

---
## 🔍 T1176

### Description
Detects behavior associated with MITRE tactic discovery, mapped to technique T1176.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*net user*" OR CommandLine="*systeminfo*"
```

---
## 🔍 T1177

### Description
Detects behavior associated with MITRE tactic execution, mapped to technique T1177.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell.exe*" CommandLine="*-EncodedCommand*"
```

---
## 🔍 T1178

### Description
Detects behavior associated with MITRE tactic command and control, mapped to technique T1178.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*DownloadString*" OR CommandLine="*Invoke-WebRequest*"
```

---
## 🔍 T1179

### Description
Detects behavior associated with MITRE tactic execution, mapped to technique T1179.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 NewProcessName="*powershell.exe*" CommandLine="*-EncodedCommand*"
```

---
## 🔍 T1180

### Description
Detects behavior associated with MITRE tactic exfiltration, mapped to technique T1180.

### SPL Query
```spl
index=windows sourcetype=WinEventLog:Security EventCode=4688 CommandLine="*Out-File*" AND CommandLine="\\10.10.10.10\*"
```

---
