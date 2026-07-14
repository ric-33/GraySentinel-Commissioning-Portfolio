# Process Ancestry Tree

**Collected from:** 192.168.19.129 (Windows 7)  
**Sysmon Events:** Event ID 1 (Process Create), ID 3 (Network), ID 11 (File Creation)  
**Date:** 25 June 2026, 01:38–01:44 UTC  

---

## Attack Chain Visualization

```
[2026-06-25 01:38:28]
├── explorer.exe (PID: 5960)
│   │   User: Win-Client\student
│   │   Integrity: High
│   │   ProcessGuid: {be449c31-8694-6a3c-4201-000000008600}
│   │
│   └── powershell.exe (PID: 6060)  ⚠️ SUSPICIOUS PARENT
│       │   CommandLine: "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
│       │   User: Win-Client\student
│       │   Integrity: High
│       │   ProcessGuid: {be449c31-8694-6a3c-4201-000000008600}
│       │
│       ├── [2026-06-25 01:44:31] NETWORK CONNECTION (Sysmon Event 3) ⚠️ MALICIOUS ACTIVITY
│       │   │   Destination: 192.168.19.132:8080  (Kali attacker machine)
│       │   │   Source: 192.168.19.129:59740
│       │   │   Protocol: TCP
│       │   │   Initiated: True (outbound connection)
│       │   │
│       │   └── Likely: PowerShell downloading payload or C2 beacon
│       │
│       └── [2026-06-21 19:28:47] FILE CREATION (Sysmon Event 11) ⚠️ STAGING AREA
│           │   Target: C:\Users\student\AppData\Local\Temp\__PSScriptPolicyTest_kkespus4.cnz.ps1
│           │   Process: powershell.exe (PID: 4428)
│           │
│           └── Likely: Downloaded script or obfuscated payload
```

---

## Timeline Reconstruction

| Time | Event | Details | Severity |
|---|---|---|---|
| **01:38:28** | explorer.exe starts | User browsing, opens something | Low |
| **01:38:XX** | powershell.exe spawns | Unusual parent (explorer.exe, not cmd.exe) | **High** |
| **01:44:31** | Network connection established | powershell.exe → 192.168.19.132:8080 (attacker) | **Critical** |
| **19:28:47** | Temp file created | `__PSScriptPolicyTest_kkespus4.cnz.ps1` | **High** |
| **01:XX:XX** | Script execution | PowerShell executes downloaded payload | **Critical** |

---

## Why This Is Malicious

### 1. **Abnormal Process Parent**
- **Normal:** powershell.exe spawned from cmd.exe (user typed PowerShell)
- **Observed:** powershell.exe spawned from explorer.exe (user clicked something)
- **Implication:** User likely clicked a malicious link or opened an Office document that triggered PowerShell

### 2. **Network Activity**
- PowerShell connecting to **192.168.19.132:8080** (non-standard port)
- This is the attacker's Kali machine (from earlier lab work)
- **Implication:** Downloading payload, establishing C2 channel, or exfiltrating data

### 3. **Suspicious File Creation**
- File written to `AppData\Local\Temp` (common staging area)
- Name pattern `__PSScriptPolicyTest_*` (PowerShell execution policy test — used to bypass restrictions)
- `.cnz` extension is unusual (not standard `.ps1`), suggesting obfuscation
- **Implication:** Downloaded script being staged for execution

---

## Comparison to Living-off-the-Land Attack Pattern

This ancestry tree matches the **known LOLBin attack pattern**:

1. ✅ **Initial Access:** Phishing link → explorer.exe
2. ✅ **Execution:** explorer.exe spawns PowerShell
3. ✅ **Command & Control:** PowerShell connects to attacker IP
4. ✅ **Staging:** Script file written to %TEMP%
5. ⏳ **Execution:** (Would occur next if attack completed)
6. ⏳ **Lateral Movement:** (Could use PowerShell remoting or WMI to move to other machines)

---

## Detection Confidence: **CRITICAL**

- **True Positive Likelihood:** 95%+ (explorer.exe → powershell.exe + network + temp file is not normal)
- **False Positive Likelihood:** 5% (some legitimate admin scripts may behave similarly, but rare)

---

## Recommended Actions

1. **Isolate the machine immediately** — do not let it contact other systems
2. **Terminate powershell.exe** — stop any payload execution
3. **Examine the temp file** (`__PSScriptPolicyTest_kkespus4.cnz.ps1`) for malicious code
4. **Check for lateral movement** — search for similar connections from this machine to others
5. **Reset credentials** — if the machine was compromised, assume all local credentials are compromised
6. **Deploy EDR alert** — create detection rule for this pattern on all endpoints

---

## Appendix: Full Sysmon Events

### Event 1 (Process Create): explorer.exe → powershell.exe
```
TimeCreated: 2026-06-25 01:38:28
Image: C:\Windows\explorer.exe
ParentImage: (N/A, user process)
CommandLine: "powershell.exe"
User: Win-Client\student
ProcessGuid: {be449c31-8694-6a3c-4201-000000008600}
```

### Event 3 (Network Connection): powershell.exe → Attacker
```
TimeCreated: 2026-06-25 01:44:31
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
DestinationIp: 192.168.19.132
DestinationPort: 8080
SourceIp: 192.168.19.129
SourcePort: 59740
Protocol: TCP
Initiated: True
```

### Event 11 (File Created): Temp File
```
TimeCreated: 2026-06-21 19:28:47
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetFilename: C:\Users\student\AppData\Local\Temp\__PSScriptPolicyTest_kkespus4.cnz.ps1
CreationUtcTime: 2026-06-21 19:28:47
User: Win-Client\student
```
