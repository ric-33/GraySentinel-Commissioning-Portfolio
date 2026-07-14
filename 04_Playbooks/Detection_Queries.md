
# Detection Queries

Supporting queries for `RDP_Brute_Force_Playbook.md` and `Malware_Download_Playbook.md`.

---

## RDP Brute Force Detection

Detects more than 10 failed logon attempts (Event ID 4625) from the same source IP within a 5-minute window.

```powershell
$TimeWindow = (Get-Date).AddMinutes(-5)

$FailedLogons = Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    ID        = 4625
    StartTime = $TimeWindow
} | Group-Object { $_.Properties[19].Value }   # Source Network Address

$FailedLogons | Where-Object Count -gt 10 | ForEach-Object {
    Write-Host "ALERT: RDP brute force from $($_.Name) with $($_.Count) attempts"
}
```

**Note:** the property index for source IP can vary slightly by Windows version/build — verify against a real 4625 event (see `windows_event_4625_detail.png` in `03_Detection/`) before relying on this in production, since the "Network Information" block's field order determines the correct index.

---

## Malware Download Cradle Detection

Detects PowerShell script block logs (Event ID 4104) containing common download-cradle indicators.

```powershell
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-PowerShell/Operational'
    ID      = 4104
} | Where-Object {
    $_.Message -match "DownloadString|Invoke-WebRequest|New-Object Net.WebClient|BitsTransfer"
} | Select-Object TimeCreated, Message
```

---

## Sysmon-Based PowerShell Activity Query

Used during lab testing to correlate PowerShell process creation with the malware download playbook's detection indicators.

```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Sysmon/Operational'} |
    Where-Object {$_.Message -match "powershell.exe"} |
    Select-Object -First 5 | Format-List TimeCreated, Message
```

This is the exact query used to produce `sysmon_powershell_logs.png` in the `03_Detection` folder — included here to show the direct link between the detection engineering work and the playbook it supports.
