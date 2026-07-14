# sysmon_collector.ps1 - GraySentinel Sysmon Event Collector

param(
    [int]$Hours = 24,
    [string]$OutputPath = "C:\Reports"
)

$StartTime = (Get-Date).AddHours(-$Hours)
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if (!(Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath | Out-Null
}

$OutputFile = "$OutputPath\sysmon_events_$Timestamp.csv"

Write-Host "[+] Collecting Sysmon events from last $Hours hour(s)..."

$Events = Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    StartTime = $StartTime
    Id        = 1,3,7,10
} -ErrorAction SilentlyContinue

$Results = foreach ($Event in $Events) {
    [PSCustomObject]@{
        TimeCreated   = $Event.TimeCreated
        EventID       = $Event.Id
        HasPowerShell = ($Event.Message -match "powershell")
        Message       = $Event.Message
    }
}

$Results | Export-Csv -Path $OutputFile -NoTypeInformation

$PowerShellCount = ($Results | Where-Object {$_.HasPowerShell -eq $true}).Count

Write-Host "[+] Total Events Collected: $($Results.Count)"
Write-Host "[+] PowerShell Related Events: $PowerShellCount"
Write-Host "[+] Report Saved: $OutputFile"
