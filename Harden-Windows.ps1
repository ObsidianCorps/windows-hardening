#Requires -Version 5.1
<#
.SYNOPSIS
    Audit, preview, apply, verify and selectively restore Windows security settings.
.DESCRIPTION
    Audit is read-only and is the default. Download the complete release, including src and catalog.
    Apply and Restore require elevation. Use -WhatIf to preview without writing settings or reports.
.EXAMPLE
    .\Harden-Windows.ps1 -Action Plan -Profile Gaming
.EXAMPLE
    .\Harden-Windows.ps1 -Action Apply -RuleId security.enablelua -WhatIf
#>
[CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
param(
    [ValidateSet('Audit','Plan','Apply','Restore','Network','Doctor','Compare','CompareCatalog','Monitor','RegisterMonitor','RemoveMonitor','AppControl')]
    [string]$Action='Audit',
    [ValidateSet('Everyday','Gaming','Developer','ManagedWorkstation')][string]$Profile='Everyday',
    [string[]]$RuleId=@(),[string[]]$Categories=@(),[switch]$IncludeOptional,
    [ValidateSet('Audit','Block','Warn')][string]$ASRMode='Audit',
    [string]$StorePath=(Join-Path $env:LOCALAPPDATA 'WindowsHardening'),
    [string]$ReportPath,[switch]$Redact,[string]$BaselinePath,[string]$ComparePath,
    [string]$JournalPath,[string]$ExceptionsPath,[switch]$AllowManaged,
    [ValidateSet('Recovery','Camera','Microphone','NetworkShare','Gaming','Application','All')][string]$Symptom='All',
    [ValidateSet('New','Audit','Review','EnforceCandidate','Enforce','Remove')][string]$AppControlOperation='New',
    [string]$PolicyPath,[string]$ReviewPath,[switch]$CompatibilityReviewed,[string]$EncryptionCertificatePath,
    [switch]$Interactive,[switch]$Silent,[switch]$All
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
Import-Module (Join-Path $PSScriptRoot 'src\WindowsHardening.psm1') -Force -ErrorAction Stop
$mutation=@{WhatIf=$WhatIfPreference}
if ($PSBoundParameters.ContainsKey('Confirm')) { $mutation.Confirm=$PSBoundParameters['Confirm'] }
try {
    foreach ($parameter in @('StorePath','ReportPath','BaselinePath','ComparePath','JournalPath','ExceptionsPath','PolicyPath','ReviewPath','EncryptionCertificatePath')) {
        $value=Get-Variable -Name $parameter -ValueOnly
        if ($value) { Set-Variable -Name $parameter -Value (Resolve-HWFilePath $value) }
    }
    if ($Interactive) {
        if ($Silent -or [Console]::IsInputRedirected) { throw 'Interactive mode requires an interactive console.' }
        while ($true) {
            Write-Host ''
            Write-Host 'Windows Hardening v2 - Audit > Preview > Apply > Verify > Restore'
            Write-Host '[1] Audit  [2] Preview profile  [3] Apply profile  [4] Network  [5] Troubleshoot'
            Write-Host '[6] Choose profile  [7] Custom categories  [8] Restore a journal  [Q] Quit'
            $choice=Read-Host 'Choose'
            if ($choice -eq 'Q') { break }
            if ($choice -eq '6') {
                $answer=Read-Host 'Profile: Everyday, Gaming, Developer, ManagedWorkstation'
                if ($answer -in @('Everyday','Gaming','Developer','ManagedWorkstation')) { $Profile=$answer }
                else { Write-Host 'Unknown profile.' }
                continue
            }
            if ($choice -eq '7') {
                $available=@((Import-HWCatalog).Rules.Category | Sort-Object -Unique)
                Write-Host ('Available categories: '+($available -join ', '))
                Write-Host 'Custom categories include optional settings and may remove apps or disable functionality. Inspect the preview.'
                $answer=Read-Host 'Comma-separated categories, or blank to cancel'
                if (-not $answer) { continue }
                $custom=@($answer.Split(',') | ForEach-Object Trim)
                if (@($custom | Where-Object { $_ -notin $available }).Count) { Write-Host 'Unknown category.';continue }
                & $PSCommandPath -Action Plan -Categories $custom -IncludeOptional -StorePath $StorePath @mutation
                $answer=Read-Host 'Apply this selection? Type APPLY to continue'
                if ($answer -ceq 'APPLY') { & $PSCommandPath -Action Apply -Categories $custom -IncludeOptional -StorePath $StorePath @mutation }
                continue
            }
            if ($choice -eq '8') {
                $answer=Read-Host 'Journal path, or blank to cancel'
                if ($answer) { & $PSCommandPath -Action Restore -JournalPath $answer -StorePath $StorePath @mutation }
                continue
            }
            $selectedAction=switch ($choice) {'1'{'Audit'}'2'{'Plan'}'3'{'Apply'}'4'{'Network'}'5'{'Doctor'}default{$null}}
            if ($selectedAction) { & $PSCommandPath -Action $selectedAction -Profile $Profile -StorePath $StorePath @mutation }
        }
        return
    }
    if ($Silent -and $Action -eq 'Audit' -and ($All -or $Categories.Count -gt 0)) {
        throw 'Legacy -Silent no longer implies Apply. Review -Action Plan, then explicitly select -Action Apply.'
    }
    if ($All -and -not $IncludeOptional) { throw '-All requires -IncludeOptional to acknowledge compatibility-sensitive and irreversible changes. Prefer selecting rule IDs.' }
    if ($Action -eq 'CompareCatalog') {
        if (-not $BaselinePath -or -not $ComparePath) { throw 'Provide old and new catalog paths with -BaselinePath and -ComparePath.' }
        Compare-HWCatalog (Import-HWCatalog $BaselinePath) (Import-HWCatalog $ComparePath); return
    }
    if ($Action -eq 'Compare') {
        if (-not $BaselinePath -or -not $ComparePath) { throw 'Provide snapshot paths with -BaselinePath and -ComparePath.' }
        Compare-HWSnapshot (Read-HWJson $BaselinePath) (Read-HWJson $ComparePath); return
    }
    if ($Action -eq 'Restore') {
        if (-not $JournalPath) { throw '-JournalPath is required.' }
        $result=Restore-HWRun -JournalPath $JournalPath -StorePath $StorePath -RuleId $RuleId -AllowManaged:$AllowManaged @mutation
        $result; if ($result.Failed -gt 0) { exit 2 }; return
    }
    if ($Action -eq 'AppControl') {
        Invoke-HWAppControl -Operation $AppControlOperation -PolicyPath $PolicyPath -StorePath $StorePath -ReviewPath $ReviewPath -CompatibilityReviewed:$CompatibilityReviewed -AllowManaged:$AllowManaged @mutation; return
    }
    if ($Action -eq 'RegisterMonitor') {
        if (-not $BaselinePath) { throw '-BaselinePath is required; accept a private audit snapshot first.' }
        Register-HWMonitor -ScriptPath $PSCommandPath -BaselinePath $BaselinePath -StorePath $StorePath -Profile $Profile @mutation; return
    }
    if ($Action -eq 'RemoveMonitor') { Remove-HWMonitor @mutation; return }
    if ($Action -eq 'Network') {
        $network=Get-HWNetwork
        $network.Listeners | Format-Table Protocol,LocalAddress,LocalPort,Scope,ProcessName,OwningProcess
        Write-Output $network; return
    }
    if ($Action -eq 'Doctor') { Get-HWDiagnostics -Symptom $Symptom -JournalPath $JournalPath; return }
    if ($Action -eq 'Monitor' -and -not $BaselinePath) { throw 'Monitor requires an explicitly accepted -BaselinePath.' }
    $catalog=Import-HWCatalog
    if ($EncryptionCertificatePath) {
        $public=Read-HWEncryptionCertificate $EncryptionCertificatePath
        ($catalog.Rules | Where-Object Id -eq 'logging.encryptioncertificate').Desired=$public
        if ($RuleId.Count -gt 0) { $RuleId=@(@($RuleId)+@('logging.encryptioncertificate','logging.enableprotectedeventlogging') | Select-Object -Unique) }
    }
    $context=Get-HWContext
    $mode=@{Audit=2;Block=1;Warn=6}[$ASRMode]
    $exceptions=@(Get-HWExceptions -Path $ExceptionsPath -Catalog $catalog)
    if ($Action -eq 'Monitor' -and -not $ExceptionsPath) {
        $accepted=Read-HWJson $BaselinePath
        $exceptions=@(Get-HWProperty $accepted.Plan 'Exceptions' @() | Where-Object {
            -not $_.ExpiresUtc -or [DateTimeOffset]::Parse($_.ExpiresUtc) -gt [DateTimeOffset]::UtcNow
        })
    }
    $plan=New-HWPlan -Catalog $catalog -Context $context -Profile $Profile -RuleId $RuleId -Categories $Categories -IncludeOptional:$IncludeOptional -ASRMode $mode -Exceptions $exceptions
    $snapshot=[pscustomobject]@{SchemaVersion=1;CreatedUtc=[DateTime]::UtcNow.ToString('o');Plan=$plan;Network=$null;Diagnostics=$null;Diff=$null;Apply=$null}
    if ($Action -eq 'Plan') {
        $plan.Items | Select-Object Id,Status,Selected,@{n='Target';e={ConvertTo-HWCanonical $_.Rule.Desired}},@{n='Impact';e={$_.Rule.Impact}} | Format-Table -Wrap
    } elseif ($Action -eq 'Apply') {
        $plan.Items | Where-Object Selected | Select-Object Id,Status,@{n='Impact';e={$_.Rule.Impact}} | Format-Table -Wrap
        $result=Invoke-HWApply -Plan $plan -StorePath $StorePath -AllowManaged:$AllowManaged @mutation
        $snapshot.Apply=$result; $result
        $snapshot.Plan=New-HWPlan -Catalog $catalog -Context (Get-HWContext) -Profile $Profile -RuleId $RuleId -Categories $Categories -IncludeOptional:$IncludeOptional -ASRMode $mode -Exceptions $exceptions
    } else {
        $snapshot.Network=Get-HWNetwork
        Get-HWSummary $plan | Format-Table
        Get-HWSoftwareContext
    }
    if ($BaselinePath) {
        $baseline=Read-HWJson $BaselinePath
        if (Get-HWProperty $baseline 'Redacted' $false) { throw 'A redacted report cannot serve as a monitoring baseline.' }
        $snapshot.Diff=Compare-HWSnapshot $baseline $snapshot
        $snapshot.Diff
    }
    if ($Action -eq 'Monitor' -and -not $ReportPath) { $ReportPath=Join-Path $StorePath 'monitor' }
    if ($ReportPath -and -not $WhatIfPreference) { Export-HWReport -Snapshot $snapshot -Directory $ReportPath -Redact:$Redact }
    if ($null -ne $snapshot.Apply -and ($snapshot.Apply.Failed -gt 0 -or $snapshot.Apply.Blocked.Count -gt 0)) { exit 2 }
    if ($Action -eq 'Monitor' -and $null -ne $snapshot.Diff -and ($snapshot.Diff.Changes.Count -gt 0 -or $snapshot.Diff.ListenerChanges.Count -gt 0)) { exit 3 }
} catch {
    Write-Error $_ -ErrorAction Continue
    exit 1
}


