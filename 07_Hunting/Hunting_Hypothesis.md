# Threat Hunting Hypothesis

**Hypothesis Name:** PowerShell-based Download Cradle & Lateral Movement Hunt

**Date:** 24–25 June 2026

**Analyst:** Ritesh Gupta

---

## 1. Hunting Question

**Can we detect PowerShell processes spawning from non-shell parents (explorer.exe, winlogon.exe) that establish network connections and create suspicious temporary files?**

This hunting hypothesis is designed to catch a common attack pattern:
1. User clicks a link or opens a document (explorer.exe)
2. PowerShell spawns silently
3. PowerShell downloads a payload from the network
4. PowerShell creates a temporary script file in %TEMP%
5. Payload executes, potentially executing code for lateral movement

---

## 2. Why This Matters

**Attack Context:**
- Living-off-the-land attacks (LOLBins) avoid traditional malware by using built-in Windows tools like PowerShell
- PowerShell is legitimate, but spawning it from explorer.exe with network activity is suspicious
- Temporary script files in %TEMP% with obfuscated names are a known malware staging area

**Detection Gap:**
- Static signatures may not catch this because PowerShell itself is signed by Microsoft
- Behavior-based detection is more reliable

---

## 3. Hypothesis Validation Criteria

**If true (hypothesis confirmed), we should observe:**
- Sysmon Event ID 1: powershell.exe with parent process explorer.exe (or other unusual parent)
- Sysmon Event ID 3: Network connection from powershell.exe to external IP:port
- Sysmon Event ID 11: File creation in C:\Users\*\AppData\Local\Temp\ with .ps1 or obfuscated extension
- Timing: All three events within 60 seconds of each other
- Command line: PowerShell with flags like `-NoProfile`, `-Executionpolicy Bypass`, etc.

**If false (hypothesis rejected), we should find:**
- No powershell.exe processes with suspicious parents
- No file writes to %TEMP% associated with PowerShell
- Network connections from PowerShell only to trusted internal services (SCCM, WSUS, etc.)

---

## 4. Data Sources & Collection Strategy

**Primary:**
- Sysmon logs (Microsoft-Windows-Sysmon/Operational)
  - Event ID 1 (Process Create)
  - Event ID 3 (Network Connection)
  - Event ID 11 (File Created)

**Secondary:**
- Windows Event Logs (Security)
  - Event ID 4688 (Process Creation) — less detailed than Sysmon, but useful for correlation
  - Event ID 4104 (PowerShell Script Block Logging)

**Tertiary:**
- Proxy/firewall logs — if available, to correlate with network connections from PowerShell

---

## 5. Expected Findings

Based on lab testing and threat intel, we expect to find:
- At least one instance of explorer.exe → powershell.exe → network activity → file creation
- Temp files with names matching patterns like `__PSScriptPolicyTest_*`, `Temp*`, or random hex strings
- Network connections to non-standard ports (8080, 8443, custom C2 ports)
- Potential lateral movement indicators (service creation, admin share access)

---

## 6. Scope & Limitations

**Scope:**
- Single target machine (192.168.19.129, Windows 7)
- Sysmon logs from 21–25 June 2026
- One-week hunting window

**Limitations:**
- Lab environment; real-world networks may have more noise
- PowerShell logging must be enabled (not always default)
- Network connection logging may not show DNS queries unless Sysmon DNS monitoring is enabled
-
