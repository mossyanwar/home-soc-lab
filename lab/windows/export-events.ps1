<#
.SYNOPSIS
    Exports Windows event log records to JSON lines in the flat format the
    soclab engine reads.

.DESCRIPTION
    Each output line is one event with the System fields the engine's logsource
    mapping needs (Channel, EventID, Hostname, TimeCreated in UTC) and every
    named EventData field at the top level, for example Image, CommandLine,
    ParentImage, TargetObject, Details. That is the same shape as the OTRF
    Security-Datasets JSON files the rules were tested against.

    Not tested in this repo (it was written without a Windows host).

.EXAMPLE
    .\export-events.ps1 -Since (Get-Date).AddMinutes(-30) -OutFile C:\lab\run1.jsonl
    Then on the analysis machine:  soclab run --rules detections C:\lab\run1.jsonl
#>
param(
    [datetime]$Since = (Get-Date).AddHours(-1),
    [string[]]$Channels = @(
        'Microsoft-Windows-Sysmon/Operational',
        'Security',
        'System',
        'Microsoft-Windows-PowerShell/Operational'
    ),
    [string]$OutFile = (Join-Path $env:USERPROFILE ("events-{0}.jsonl" -f (Get-Date -Format 'yyyyMMdd-HHmmss')))
)

$ErrorActionPreference = 'Stop'
$utf8 = New-Object System.Text.UTF8Encoding($false)
$writer = New-Object System.IO.StreamWriter($OutFile, $false, $utf8)
$count = 0
try {
    foreach ($channel in $Channels) {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $channel; StartTime = $Since } -ErrorAction SilentlyContinue
        foreach ($e in $events) {
            $xml = [xml]$e.ToXml()
            $record = [ordered]@{
                Channel      = $e.LogName
                EventID      = $e.Id
                Hostname     = $e.MachineName
                TimeCreated  = $e.TimeCreated.ToUniversalTime().ToString('o')
                RecordNumber = $e.RecordId
                SourceName   = $e.ProviderName
            }
            foreach ($d in $xml.Event.EventData.Data) {
                if ($d.Name) { $record[$d.Name] = $d.'#text' }
            }
            $writer.WriteLine(($record | ConvertTo-Json -Compress -Depth 3))
            $count++
        }
    }
}
finally {
    $writer.Close()
}
Write-Host "Wrote $count events to $OutFile"
