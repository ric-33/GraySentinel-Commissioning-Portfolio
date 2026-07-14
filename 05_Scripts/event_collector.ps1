# event_collector.ps1 - GraySentinel Windows Event Collector

$OutputDir = "C:\GraySentinel_Commissioning\1_Portfolio\Reports"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$OutputFile = "$OutputDir\security_events_$Timestamp.csv"

Write-Host "[+] Collecting security events..."

# Collect successful logons (4624)
$SuccessLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 10

# Collect failed logons (4625)
$FailedLogons = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 10

# Combine events
$Events = $SuccessLogons + $FailedLogons

# Export to CSV
$Events | Select-Object TimeCreated, Id, MachineName, Message |
Export-Csv -Path $OutputFile -NoTypeInformation

# Display summary
Write-Host "[+] Export complete: $OutputFile"
Write-Host "[+] Success logons: $($SuccessLogons.Count)"
Write-Host "[+] Failed logons: $($FailedLogons.Count)"
