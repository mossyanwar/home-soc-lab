#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Sets the audit policy and logging options the lab expects on WIN-EP01.

.DESCRIPTION
    - advanced audit policy subcategories (process creation, logons, account
      and group changes, scheduled tasks, audit policy changes)
    - command line included in Security event 4688
    - PowerShell script block and module logging
    - larger maximum sizes for the logs the lab ships

    Not tested in this repo (it was written without a Windows host).
    Subcategory names are the English ones; on a non-English install use
    `auditpol /list /subcategory:* /v` to get the GUIDs and swap them in.
#>
$ErrorActionPreference = 'Stop'

# Make advanced (subcategory) audit settings win over the legacy category ones.
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' `
    -Name 'SCENoApplyLegacyAuditPolicy' -PropertyType DWord -Value 1 -Force | Out-Null

$subcategories = @(
    @{ Name = 'Process Creation';           Success = $true; Failure = $false },
    @{ Name = 'Logon';                      Success = $true; Failure = $true  },
    @{ Name = 'Special Logon';              Success = $true; Failure = $false },
    @{ Name = 'Credential Validation';      Success = $true; Failure = $true  },
    @{ Name = 'User Account Management';    Success = $true; Failure = $true  },
    @{ Name = 'Security Group Management';  Success = $true; Failure = $false },
    @{ Name = 'Security System Extension';  Success = $true; Failure = $false },
    @{ Name = 'Other Object Access Events'; Success = $true; Failure = $false },  # 4698 scheduled task created
    @{ Name = 'Audit Policy Change';        Success = $true; Failure = $false }
)

foreach ($s in $subcategories) {
    $succ = if ($s.Success) { 'enable' } else { 'disable' }
    $fail = if ($s.Failure) { 'enable' } else { 'disable' }
    auditpol /set /subcategory:"$($s.Name)" /success:$succ /failure:$fail | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "auditpol failed for '$($s.Name)'" }
}

# Command line in 4688.
$auditKey = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
New-Item -Path $auditKey -Force | Out-Null
New-ItemProperty -Path $auditKey -Name 'ProcessCreationIncludeCmdLine_Enabled' `
    -PropertyType DWord -Value 1 -Force | Out-Null

# PowerShell script block logging (4104) and module logging (4103).
$psKey = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell'
New-Item -Path "$psKey\ScriptBlockLogging" -Force | Out-Null
New-ItemProperty -Path "$psKey\ScriptBlockLogging" -Name 'EnableScriptBlockLogging' `
    -PropertyType DWord -Value 1 -Force | Out-Null
New-Item -Path "$psKey\ModuleLogging\ModuleNames" -Force | Out-Null
New-ItemProperty -Path "$psKey\ModuleLogging" -Name 'EnableModuleLogging' `
    -PropertyType DWord -Value 1 -Force | Out-Null
New-ItemProperty -Path "$psKey\ModuleLogging\ModuleNames" -Name '*' `
    -PropertyType String -Value '*' -Force | Out-Null

# Log sizes in bytes. The defaults (20 MB for Security) roll over within hours
# once process creation auditing is on.
wevtutil sl Security /ms:1073741824
wevtutil sl System /ms:268435456
wevtutil sl 'Microsoft-Windows-PowerShell/Operational' /ms:268435456
wevtutil sl 'Microsoft-Windows-Sysmon/Operational' /ms:1073741824

auditpol /get /category:* | Select-String -Pattern 'Process Creation|Logon|Account Management|Group Management|Other Object Access|Audit Policy Change'
Write-Host 'Audit policy applied. Reboot is not required, but run gpupdate /force if a domain GPO also sets audit policy.'
