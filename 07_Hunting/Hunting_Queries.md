# Threat Hunting Queries

Reusable PowerShell and KQL queries for detecting suspicious PowerShell activity via Sysmon.

---

## Query 1: PowerShell Spawned from Unusual Parents

**Goal:** Find powershell.exe processes whose parent is NOT cmd.exe or explorer.exe (but explorer is still suspicious)

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} | Where-Object {
    $_.Message -match "powershell.exe" -and 
    $_.Message -match "ParentImage.*explorer|winlogon|svchost"
} | Select-Object TimeCreated, Message
```

**What it detects:**
- PowerShell spawned from explorer.exe (user clicked link)
- PowerShell spawned from winlogon.exe (logged-in user)
- PowerShell spawned from svchost.exe (system service, very suspicious)

**Real-world usage:** Run this weekly to catch living-off-the-land attacks early.

---

## Query 2: PowerShell + Network Connection (Lateral Movement Hunt)

**Goal:** Correlate powershell.exe process creation with subsequent network connections

```powershell
$PowerShellProcesses = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} | Where-Object {$_.Message -match "powershell.exe"} | 
    Select-Object @{N='TimeCreated'; E={$_.TimeCreated}}, 
                  @{N='ProcessId'; E={$_.Properties[3].Value}}

$NetworkConnections = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 3
} | Where-Object {$_.Message -match "powershell"} |
    Select-Object TimeCreated, Message

# Correlate: PowerShell started, then made network connection within 60 seconds
foreach ($ps in $PowerShellProcesses) {
    $Connections = $NetworkConnections | Where-Object {
        $_.TimeCreated -gt $ps.TimeCreated -and 
        $_.TimeCreated -lt $ps.TimeCreated.AddSeconds(60)
    }
    if ($Connections) {
        Write-Host "SUSPICIOUS: PowerShell $($ps.ProcessId) made network connection(s)"
        $Connections | ForEach-Object { Write-Host "  → $_" }
    }
}
```

**What it detects:**
- PowerShell downloading payloads (reverse shell, C2 beaconing)
- Lateral movement via WMI/PSRemoting

---

## Query 3: PowerShell + File Creation in %TEMP%

**Goal:** Find PowerShell writing suspicious files to AppData\Local\Temp

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 11  # File Created
} | Where-Object {
    $_.Message -match "\\Temp\\" -and 
    ($_.Message -match "\.ps1" -or $_.Message -match "\.psm1" -or $_.Message -match "PSScript")
} | Select-Object TimeCreated, Message
```

**What it detects:**
- Malware staging files
- Downloaded scripts executed from temp
- Pattern: `__PSScriptPolicyTest_*.ps1` (PowerShell execution policy testing)

---

## Query 4: PowerShell Script Block Logging (Advanced)

**Goal:** Detect obfuscated or suspicious PowerShell commands at execution time

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    Id = 4104  # ScriptBlock
} | Where-Object {
    $_.Message -match "DownloadString|Invoke-WebRequest|New-Object.*WebClient|BitsTransfer" -or
    $_.Message -match "\[Convert\]::FromBase64String" -or
    $_.Message -match "IEX|Invoke-Expression"
} | Select-Object TimeCreated, Message
```

**What it detects:**
- Download cradles (DownloadString, IWR)
- Obfuscation attempts (base64 decoding)
- Code injection (IEX - Invoke-Expression)

---

## Query 5: Process Ancestry Chain

**Goal:** Build a parent→child→grandchild process tree for visualization

```powershell
function Get-ProcessAncestry {
    param([string]$ProcessName = "powershell.exe")
    
    $Ancestry = @()
    
    # Get the parent process
    $Parent = Get-WinEvent -FilterHashtable @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Id = 1
    } | Where-Object {$_.Message -match $ProcessName} | 
        Select-Object -First 1
    
    if ($Parent) {
        $Ancestry += "Parent: $($Parent.Properties[20].Value)"  # ParentImage
        $Ancestry += "  → $ProcessName"
        
        # Get child processes spawned by PowerShell
        $Children = Get-WinEvent -FilterHashtable @{
            LogName = 'Microsoft-Windows-Sysmon/Operational'
            Id = 1
        } | Where-Object {$_.Message -match "cmd.exe|notepad|regedit|net.exe"} |
            Select-Object TimeCreated, Message
        
        foreach ($Child in $Children) {
            $Ancestry += "      → $($Child.Properties[20].Value)"
        }
    }
    
    return $Ancestry
}

Get-ProcessAncestry
```

---

## Query 6: Registry Modifications + PowerShell

**Goal:** Detect PowerShell modifying registry (persistence, credential theft, etc.)

```powershell
$PSProcesses = Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 1
} | Where-Object {$_.Message -match "powershell.exe"} | 
    Select-Object @{N='PID'; E={$_.Properties[3].Value}}

Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    Id = 13  # Registry object set
} | Where-Object {
    $_ | Where-Object {
        $_.Properties[2].Value -match "HKLM.*Run|HKCU.*Run|Software.*Policies|CurrentVersion\\App Paths"
    }
} | Select-Object TimeCreated, @{N='RegistryPath'; E={$_.Properties[4].Value}}
```

**What it detects:**
- Registry run keys being added (persistence)
- AppInit_DLLs (DLL injection)
- PowerShell execution policies being modified

---

## KQL Equivalent (for Azure Sentinel / Log Analytics)

```kusto
// Query 1: PowerShell from suspicious parents
Event
| where EventLog == "Microsoft-Windows-Sysmon/Operational"
| where EventID == 1
| where EventData contains "powershell.exe"
| where EventData contains "ParentImage" and (EventData contains "explorer.exe" or EventData contains "winlogon.exe")
| project TimeGenerated, Computer, EventData
```

---

## Usage Notes

- **Frequency:** Run these queries **daily** or on-demand during investigations
- **Correlation:** Combine Query 1 + Query 2 + Query 3 for highest confidence
- **False Positives:** Legitimate admin scripts may trigger these; baseline your environment first
- **Tuning:** Whitelist known good PowerShell processes (e.g., Windows Update, ConfigMgr) to reduce noise
-
