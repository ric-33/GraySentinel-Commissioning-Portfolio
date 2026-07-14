# Attack Timeline

**Incident:** Living-off-the-Land PowerShell Download Cradle  
**Target:** 192.168.19.129 (Windows 7)  
**Analyst:** Ritesh Gupta  
**Timeline Window:** 21–25 June 2026  

---

## Chronological Reconstruction

### **Phase 1: Initial Compromise (2026-06-25 ~01:30–01:40)**

| Time | Source | Event | Evidence | TTPs |
|---|---|---|---|---|
| **01:30** | explorer.exe | User activity begins | Process list shows explorer running normally | Initial access (phishing link?) |
| **01:38:28** | explorer.exe | PowerShell spawns unexpectedly | Sysmon Event 1: explorer.exe → powershell.exe | **T1086 (PowerShell)** + **T1028 (Scheduled Task)** |
| **01:38:35** | powershell.exe | PowerShell runs with no visible window | Process properties: Hidden execution | **T1564 (Hide Artifacts)** |

**Interpretation:**
User (or malware on behalf of user) browsed to a malicious link or opened a document that triggered PowerShell execution. Explorer.exe spawning PowerShell is unusual — this is typically done only by attackers.

---

### **Phase 2: Payload Delivery / C2 Callback (2026-06-25 ~01:44)**

| Time | Source | Event | Evidence | TTPs |
|---|---|---|---|---|
| **01:44:31** | powershell.exe | Outbound network connection | Sysmon Event 3: TCP 192.168.19.129:59740 → 192.168.19.132:8080 | **T1071 (Application Layer Protocol)** + **T1105 (Ingress Tool Transfer)** |
| **01:44:32–01:44:45** | Network (8080 server) | PowerShell downloads payload | Suricata/Firewall logs (not captured here, but implied) | **T1105 (Ingress Tool Transfer)** |

**Interpretation:**
PowerShell connects to an external attacker-controlled server on port 8080. This is not a standard Windows service port — it's typically used by web servers. The attacker sends a malicious script or executable to the target machine.

---

### **Phase 3: Staging & Obfuscation (2026-06-21 ~19:28)**

| Time | Source | Event | Evidence | TTPs |
|---|---|---|---|---|
| **19:28:47** | powershell.exe (PID: 4428) | File written to %TEMP% | Sysmon Event 11: File Created at `C:\Users\student\AppData\Local\Temp\__PSScriptPolicyTest_kkespus4.cnz.ps1` | **T1086 (PowerShell)** + **T1027 (Obfuscation)** |

**Interpretation:**
The downloaded payload is written to the user's temp directory with an obfuscated name. The `__PSScriptPolicyTest` prefix mimics a legitimate PowerShell execution policy test — a known evasion technique. The `.cnz` extension (instead of `.ps1`) further obfuscates the file type.

---

### **Phase 4: Potential Execution (Inferred)**

| Time | Source | Event | Evidence | TTPs |
|---|---|---|---|---|
| **~19:30–02:00** | powershell.exe | Script execution | **Not directly observed in provided logs**, but would be logged in: Event ID 4104 (PowerShell Script Block Logging) if enabled | **T1086 (PowerShell)** + **T1059 (Command Line Interface)** |

**Interpretation:**
If script block logging is enabled, we would see the actual PowerShell commands executed. Without this, we must infer execution based on file creation + network activity + subsequent system changes.

---

### **Phase 5: Lateral Movement (Suspected)**

Based on the earlier exploitation work in this portfolio, once PowerShell has execution, the attacker would:

| Time | Source | Event | Suspected Action | TTPs |
|---|---|---|---|---|
| **~02:XX** | powershell.exe | Enumerate network | `Get-ADComputer`, `Get-NetAdapter` | **T1018 (Remote System Discovery)** |
| **~03:XX** | powershell.exe | Dump credentials from memory | `mimikatz` or PowerShell credential theft | **T1003 (Credential Dumping)** |
| **~04:XX** | powershell.exe → SMB (445) | Lateral movement via PSExec or WMI | `Invoke-WmiMethod`, `PsExec` | **T1021 (Remote Service Execution)** |

**Interpretation:**
This phase was not directly captured in the provided Sysmon logs, but based on the earlier lateral movement report in this portfolio, we know this is the likely next step.

---

## Attack Kill Chain (MITRE ATT&CK)

```
Reconnaissance
    ↓
Initial Access (T1189: Phishing link)
    ↓
Execution (T1086: PowerShell)
    ↓
Persistence (T1547: Registry run key modification — if enabled)
    ↓
Privilege Escalation (None observed — already running as user/admin)
    ↓
Defense Evasion (T1027: Obfuscated filename + T1564: Hidden execution)
    ↓
Credential Access (T1003: Dumping if next stage executed)
    ↓
Discovery (T1018: Network enumeration)
    ↓
Lateral Movement (T1021: PSExec/WMI to other machines)
    ↓
Collection (T1119: Data staging)
    ↓
Exfiltration (T1030: Data transfer over C2 channel)
    ↓
Impact (Ransomware, data destruction, or persistence)
```

---

## Timeline Gaps & Questions

1. **Initial Access:** How did PowerShell get spawned from explorer.exe? 
   - Possibilities: Malicious link, Office macro, browser plugin, or file handler
   - **Investigation needed:** Browser history, recent file access, email logs

2. **File Creation Timing:** Why does the temp file show creation time 19:28:47 on 2026-06-21 but PowerShell spawned on 2026-06-25?
   - Possibilities: File was staged earlier, timestamp is misleading, or two separate incidents
   - **Investigation needed:** Compare file timestamps with Sysmon logs for accuracy

3. **Payload Content:** What was actually in `__PSScriptPolicyTest_kkespus4.cnz.ps1`?
   - **Investigation needed:** Extract and analyze file contents (if available)

4. **Success/Failure:** Did the attack succeed or fail after Phase 2?
   - Evidence: No subsequent service creation, no WMI activity observed
   - Possible conclusion: Attacker was interrupted or payload failed to execute

---

## Forensic Indicators Summary

| Indicator | Value | Severity |
|---|---|---|
| Process Parent Anomaly (explorer → powershell) | Detected | High |
| Network Connection to Non-standard Port | Detected (8080) | Critical |
| Temp File with Obfuscated Name | Detected | High |
| Script Block Logging | Not captured | Missing |
| Lateral Movement Attempts | Not detected (yet) | Low |
| Credential Dumping | Not detected | Low |
| Service Installation | Not detected | Low |

---

## Lessons from This Timeline

1. **Early Detection is Critical:** The explorer.exe → powershell.exe spawning is the earliest indicator. If detected within minutes, the attack chain stops here.

2. **Behavior-Based Detection Works:** Static signatures would miss this attack because all components (explorer, PowerShell, network connection) are legitimate. Behavior correlation is essential.

3. **Logging Depth Matters:** Without Sysmon Event ID 1/3/11, we would have no visibility into this attack. Windows Event Logs alone would miss it.

4. **File Integrity Matters:** Monitoring %TEMP% for new `.ps1`, `.exe`, or obfuscated files catches staging activity.

---

## Recommended Detection Rules

### Rule 1: Explorer Spawning PowerShell
```
Alert on: explorer.exe → powershell.exe
Severity: High
False Positive Rate: Low (rare legitimate scenario)
```

### Rule 2: PowerShell Network Activity
```
Alert on: powershell.exe making outbound connection to non-standard port (>1024)
Exclude: port 443, 80, 53 (common/legitimate)
Severity: High
False Positive Rate: Medium (legitimate admin scripts may trigger)
```

### Rule 3: File Creation in %TEMP% from PowerShell
```
Alert on: powershell.exe writing to C:\Users\*\AppData\Local\Temp\ with .ps1 or obfuscated extension
Severity: Medium
False Positive Rate: Low (script staging is suspicious)
```

### Combined Rule: 3-Event Correlation
```
Alert on: (Process Create + Network Connection + File Creation) all from PowerShell within 60 seconds
Severity: Critical
False Positive Rate: Very Low
Confidence: 95%+
```
