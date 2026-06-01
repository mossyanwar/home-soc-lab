#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Produces benign Windows telemetry for testing the rules in detections/.

.DESCRIPTION
    This script only covers the rows in attacks/README.md that can be emulated
    with a harmless action: encoded-but-benign PowerShell, a Run key, a UAC
    bypass registry layout (keys only, the trigger binary is never launched), a
    WMI subscription, a service and a scheduled task, each running a harmless
    command (calc or a marker file) and each cleaned up afterwards.

    It deliberately does NOT emulate the credential-access rows (W1 LSASS,
    W2 NTDS, W3 SAM) or the proxy-execution rows (W4 mshta, W5 regsvr32). For
    those, run the matching Atomic Red Team test by GUID in a reverted snapshot:
      Invoke-AtomicTest T1003.001 -TestGuids 2536dee2-12fb-459a-8c37-971844fa73be
      Invoke-AtomicTest T1003.003 -TestGuids dcebead7-6c28-4b4b-bf3c-79deb1b1fc7f
      Invoke-AtomicTest T1003.002 -TestGuids 5c2571d0-1572-416d-9676-812e64ca9f44
      Invoke-AtomicTest T1218.005 -TestGuids 1483fab9-4f52-4217-a9ce-daa9d7747cae
      Invoke-AtomicTest T1218.010 -TestGuids 449aa403-6aba-47ce-8a37-247d21ef0306
    Atomic Red Team runs those in a controlled way and cleans up after itself.

    Run only on WIN-EP01 in the lab, from a snapshot. Not tested in this repo
    (written without a Windows host).

.PARAMETER Step
    One or more of W6,W7,W8,W9,W10,W11. Default: all of them.
#>
param(
    [ValidateSet('W6','W7','W8','W9','W10','W11')]
    [string[]]$Step = @('W6','W7','W8','W9','W10','W11')
)

$ErrorActionPreference = 'Stop'
$marker = Join-Path $env:TEMP 'soclab-marker.txt'

function Write-Step($id, $text) {
    Write-Host ("[{0}] {1:u} {2}" -f $id, (Get-Date).ToUniversalTime(), $text)
}

# W6, T1059.001: an encoded PowerShell command that only prints a string. Same
# "-EncodedCommand <base64>" shape the rule keys on, benign payload.
function Step-W6 {
    Write-Step 'W6' 'encoded PowerShell command (prints a string)'
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'soclab W6'"))
    powershell.exe -NoProfile -EncodedCommand $enc
}

# W7, T1547.001: a Run key value pointing at the calculator, then removed.
function Step-W7 {
    Write-Step 'W7' 'add and remove a Run key value'
    $key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    New-ItemProperty -Path $key -Name 'SocLabTest' -Value 'C:\Windows\System32\calc.exe' -PropertyType String -Force | Out-Null
    Start-Sleep -Seconds 1
    Remove-ItemProperty -Path $key -Name 'SocLabTest' -Force
}

# W8, T1548.002: build the ms-settings\shell\open\command + DelegateExecute
# layout the UAC-bypass rule detects, with a harmless value, then remove it.
# The elevation trigger (fodhelper.exe) is never launched, so no bypass happens.
function Step-W8 {
    Write-Step 'W8' 'create and remove the ms-settings shell open command keys (trigger NOT launched)'
    $base = 'HKCU:\Software\Classes\ms-settings\shell\open\command'
    New-Item -Path $base -Force | Out-Null
    New-ItemProperty -Path $base -Name '(default)' -Value 'C:\Windows\System32\calc.exe' -PropertyType String -Force | Out-Null
    New-ItemProperty -Path $base -Name 'DelegateExecute' -Value '' -PropertyType String -Force | Out-Null
    Start-Sleep -Seconds 1
    Remove-Item -Path 'HKCU:\Software\Classes\ms-settings' -Recurse -Force
}

# W9, T1546.003: a WMI CommandLineEventConsumer and filter binding that would
# run a harmless command, then removed. Follows Atomic Red Team T1546.003 #1,
# with the payload replaced by a marker-file write.
function Step-W9 {
    Write-Step 'W9' 'create and remove a WMI event subscription (benign consumer command)'
    $name = 'SocLabTest'
    $filterArgs = @{ Name = $name; EventNameSpace = 'root\CimV2'; QueryLanguage = 'WQL';
        Query = "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'" }
    $filter = New-CimInstance -Namespace root/subscription -ClassName __EventFilter -Property $filterArgs
    $consumerArgs = @{ Name = $name; CommandLineTemplate = "cmd.exe /c echo soclab-W9 > `"$marker`"" }
    $consumer = New-CimInstance -Namespace root/subscription -ClassName CommandLineEventConsumer -Property $consumerArgs
    $binding = New-CimInstance -Namespace root/subscription -ClassName __FilterToConsumerBinding -Property @{ Filter = [ref]$filter; Consumer = [ref]$consumer }
    Start-Sleep -Seconds 2
    Remove-CimInstance -InputObject $binding
    Remove-CimInstance -InputObject $consumer
    Remove-CimInstance -InputObject $filter
}

# W10, T1543.003 / T1569.002: install a service whose ImagePath is a cmd.exe
# one-liner (the shape the rule detects), start, stop and delete it.
function Step-W10 {
    Write-Step 'W10' 'create, start and delete a service with a cmd.exe ImagePath'
    & sc.exe create SocLabSvc binPath= "cmd.exe /c echo soclab-W10 > `"$marker`"" start= demand | Out-Null
    & sc.exe start SocLabSvc | Out-Null   # fails to stay running, which is fine
    Start-Sleep -Seconds 1
    & sc.exe delete SocLabSvc | Out-Null
}

# W11, T1053.005: create a scheduled task that runs an encoded-but-benign
# PowerShell command via a script host, then delete it.
function Step-W11 {
    Write-Step 'W11' 'create and delete a scheduled task that runs a script host'
    $enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes("Write-Host 'soclab W11'"))
    & schtasks.exe /Create /F /TN SocLabTask /SC ONCE /ST 23:59 /TR "powershell.exe -NonInteractive -WindowStyle Hidden -EncodedCommand $enc" | Out-Null
    Start-Sleep -Seconds 1
    & schtasks.exe /Delete /F /TN SocLabTask | Out-Null
}

foreach ($s in $Step) { & "Step-$s" }
if (Test-Path $marker) { Remove-Item $marker -Force }
Write-Host 'Done. Export the events for this window and run: soclab run --rules detections <export.jsonl>'
