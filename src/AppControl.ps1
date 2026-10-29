function Read-HWPolicyXml {
    param([string]$Path)
    $settings=New-Object Xml.XmlReaderSettings
    $settings.DtdProcessing=[Xml.DtdProcessing]::Prohibit
    $settings.XmlResolver=$null
    $settings.MaxCharactersInDocument=10MB
    $reader=[Xml.XmlReader]::Create([IO.Path]::GetFullPath($Path),$settings)
    try {
        $doc=New-Object Xml.XmlDocument
        $doc.XmlResolver=$null; $doc.Load($reader)
        return ,$doc
    } finally { $reader.Dispose() }
}

function Get-HWPolicyInfo {
    param([string]$Path)
    $doc=Read-HWPolicyXml $Path
    $idNode=$doc.SelectSingleNode('/*[local-name()="SiPolicy"]/*[local-name()="PolicyID"]')
    $baseNode=$doc.SelectSingleNode('/*[local-name()="SiPolicy"]/*[local-name()="BasePolicyID"]')
    if ($null -eq $idNode -or $null -eq $baseNode) { throw 'Policy must use multiple-policy format.' }
    $id=[guid]$idNode.InnerText
    if ($id -eq [guid]::Empty -or $id -ne [guid]$baseNode.InnerText) { throw 'Only an independent base policy is supported.' }
    $options=@($doc.SelectNodes('//*[local-name()="Rules"]/*[local-name()="Rule"]/*[local-name()="Option"]') | ForEach-Object InnerText)
    if ('Enabled:Unsigned System Integrity Policy' -notin $options) { throw 'Signed or locked App Control policies are not supported by this recovery workflow.' }
    [pscustomobject]@{Id=$id.ToString('B').ToUpperInvariant();Audit=('Enabled:Audit Mode' -in $options);Options=$options
        Hash=(Get-FileHash -LiteralPath $Path -Algorithm SHA256 -ErrorAction Stop).Hash}
}

function New-HWAppControlAudit {
    [CmdletBinding(SupportsShouldProcess)]
    param([Parameter(Mandatory)][string]$Directory)
    if (-not $PSCmdlet.ShouldProcess($Directory,'Create an audit-only App Control policy from the Windows template')) { return }
    Initialize-HWStore $Directory | Out-Null
    $source=Join-Path $env:SystemRoot 'schemas\CodeIntegrity\ExamplePolicies\DefaultWindows_Audit.xml'
    if (-not (Test-Path -LiteralPath $source)) { throw 'Windows audit policy template is unavailable.' }
    $destination=Join-Path $Directory ("appcontrol-audit-$([guid]::NewGuid().ToString('N')).xml")
    Copy-Item -LiteralPath $source -Destination $destination -ErrorAction Stop
    Set-CIPolicyIdInfo -FilePath $destination -PolicyName 'WindowsHardening reviewed audit policy' -ResetPolicyID -ErrorAction Stop | Out-Null
    foreach ($option in @(3,6,9,10)) { Set-RuleOption -FilePath $destination -Option $option -ErrorAction Stop }
    $info=Get-HWPolicyInfo $destination
    if (-not $info.Audit) { throw 'Generated policy is not in audit mode.' }
    [pscustomobject]@{Xml=$destination;Policy=$info
        Next='Review this XML, deploy Audit explicitly, exercise applications, collect Review evidence, then create and review an Enforce candidate. Audit mode can still change script-host behavior.'}
}

function Get-HWAppControlEvents {
    param([DateTime]$Since=(Get-Date).AddDays(-7))
    $events=@();$errors=@()
    foreach ($log in @('Microsoft-Windows-CodeIntegrity/Operational','Microsoft-Windows-AppLocker/MSI and Script')) {
        try {
            $events+=@(Get-WinEvent -FilterHashtable @{LogName=$log;StartTime=$Since} -MaxEvents 500 -ErrorAction Stop |
                Select-Object TimeCreated,Id,ProviderName,Message)
        } catch { $errors+="$log : $($_.Exception.Message)" }
    }
    [pscustomobject]@{Events=@($events);Errors=@($errors);TruncatedMayBe=$events.Count -ge 500
        Advice='Review all affected applications, drivers, scripts and MSI installers. Events may be absent, inaccessible, overwritten or truncated; this report is not a compatibility certification.'}
}

function Invoke-HWAppControl {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param([ValidateSet('New','Audit','Review','EnforceCandidate','Enforce','Remove')][string]$Operation,
        [string]$PolicyPath,[Parameter(Mandatory)][string]$StorePath,[string]$ReviewPath,
        [switch]$CompatibilityReviewed,[switch]$AllowManaged)
    $context=Get-HWContext
    if ($Operation -eq 'New') { return New-HWAppControlAudit -Directory $StorePath -WhatIf:$WhatIfPreference -Confirm:$false }
    if ($context.Build -lt 22621) { throw 'This lifecycle requires Windows 11 22H2 or newer and CiTool.' }
    if (-not $PolicyPath) { throw '-PolicyPath is required.' }
    $info=Get-HWPolicyInfo $PolicyPath
    $recordPath=Join-Path $StorePath ("appcontrol-"+$info.Id.Trim('{}')+'.json')
    if ($Operation -eq 'Review') {
        $record=Read-HWJson $recordPath
        if ($record.Computer -ne $context.Computer -or $record.UserSid -ne $context.UserSid) { throw 'Policy record belongs to another computer or user.' }
        if ($record.Status -ne 'DeployedAudit' -or $record.PolicyHash -ne $info.Hash) { throw 'Review requires this exact audit policy to have been deployed by this tool.' }
        if (-not $PSCmdlet.ShouldProcess($StorePath,'Save App Control audit evidence')) { return }
        Initialize-HWStore $StorePath | Out-Null
        $review=[pscustomobject]@{SchemaVersion=1;PolicyId=$info.Id;PolicyHash=$info.Hash;Computer=$context.Computer;UserSid=$context.UserSid
            AuditDeployedUtc=$record.DeployedUtc;ReviewedUtc=[DateTime]::UtcNow.ToString('o')
            Evidence=Get-HWAppControlEvents -Since ([DateTime]::Parse($record.DeployedUtc))}
        $path=Join-Path $StorePath ("appcontrol-review-$([guid]::NewGuid().ToString('N')).json")
        Write-HWJson $review $path
        return [pscustomobject]@{ReviewPath=$path;Review=$review}
    }
    Assert-HWApplyContext $context -AllowManaged:$AllowManaged
    if ($Operation -eq 'EnforceCandidate') {
        if (-not $info.Audit -or -not $ReviewPath -or -not $CompatibilityReviewed) { throw 'Provide an audit policy, -ReviewPath and explicit -CompatibilityReviewed after testing applications.' }
        $review=Read-HWJson $ReviewPath
        if ($review.PolicyId -ne $info.Id -or $review.PolicyHash -ne $info.Hash -or $review.Computer -ne $context.Computer -or $review.UserSid -ne $context.UserSid) { throw 'Review does not match this exact audit policy and machine.' }
        $record=Read-HWJson $recordPath
        if ($record.Status -ne 'DeployedAudit' -or $record.PolicyHash -ne $info.Hash) { throw 'An intact audit deployment record is required.' }
        if (([DateTime]::UtcNow - [DateTime]::Parse($record.DeployedUtc).ToUniversalTime()).TotalDays -lt 7) { throw 'Exercise the audit policy for at least seven days before preparing enforcement.' }
        if (-not $PSCmdlet.ShouldProcess($PolicyPath,'Create an enforcement candidate after compatibility review')) { return }
        $destination=Join-Path $StorePath ("appcontrol-enforce-$([guid]::NewGuid().ToString('N')).xml")
        Copy-Item -LiteralPath $PolicyPath -Destination $destination -ErrorAction Stop
        Set-RuleOption -FilePath $destination -Option 3 -Delete -ErrorAction Stop
        $candidate=Get-HWPolicyInfo $destination
        $record.CandidateHash=$candidate.Hash; $record.ReviewPath=$ReviewPath
        Write-HWJson $record $recordPath
        return [pscustomobject]@{Xml=$destination;Policy=$candidate;Advice='Inspect the candidate. Explicit Enforce is a separate action; restrictive policy can prevent tools from running.'}
    }
    if ($Operation -eq 'Audit' -and -not $info.Audit) { throw 'Audit requires an audit-mode policy.' }
    if ($Operation -eq 'Enforce' -and $info.Audit) { throw 'Enforce requires an enforcement candidate.' }
    if ($Operation -in @('Enforce','Remove')) {
        $record=Read-HWJson $recordPath
        if ($record.Computer -ne $context.Computer -or $record.UserSid -ne $context.UserSid) { throw 'Deployment belongs to another machine or user.' }
        if ($Operation -eq 'Enforce' -and (-not $CompatibilityReviewed -or $record.CandidateHash -ne $info.Hash)) { throw 'Enforcement requires the reviewed candidate and -CompatibilityReviewed.' }
    }
    if (-not $PSCmdlet.ShouldProcess($info.Id,"App Control $Operation")) { return }
    Initialize-HWStore $StorePath | Out-Null
    $lock=$null
    try {
        $lock=[IO.File]::Open((Join-Path $StorePath 'mutation.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        if ($Operation -eq 'Audit' -and (Test-Path -LiteralPath $recordPath)) { throw 'A record already exists for this policy ID. Do not replace existing policies.' }
        $existing=Invoke-HWNative 'CiTool.exe' @('--list-policies','-json')
        $policyList=$existing.Output | ConvertFrom-Json -ErrorAction Stop
        $installed=@($policyList.Policies | Where-Object { ([string]$_.PolicyID).Trim('{}') -eq $info.Id.Trim('{}') })
        if ($Operation -eq 'Audit' -and $installed.Count -gt 0) { throw 'Policy ID already exists on this machine.' }
        if ($Operation -ne 'Audit' -and $installed.Count -ne 1) { throw 'Expected one existing policy for this lifecycle operation.' }
        if ($Operation -eq 'Remove') {
            # Only policy IDs recorded as created by this tool are removable here.
            $record.Status='PreparedRemove';Write-HWJson $record $recordPath
            Invoke-HWNative 'CiTool.exe' @('--remove-policy',$info.Id) | Out-Null
            $record.Status='RemovalRequestedRestartRequired';Write-HWJson $record $recordPath
            return $record
        }
        $binary=Join-Path $StorePath ($info.Id+'.cip')
        ConvertFrom-CIPolicy -XmlFilePath $PolicyPath -BinaryFilePath $binary -ErrorAction Stop | Out-Null
        $record=[pscustomobject]@{SchemaVersion=1;PolicyId=$info.Id;Computer=$context.Computer;UserSid=$context.UserSid;PolicyHash=$info.Hash
            CandidateHash=$null;ReviewPath=$ReviewPath;DeployedUtc=[DateTime]::UtcNow.ToString('o');Status="Prepared$Operation"}
        Write-HWJson $record $recordPath
        Invoke-HWNative 'CiTool.exe' @('--update-policy',$binary) | Out-Null
        $record.Status=if ($Operation -eq 'Audit') {'DeployedAudit'} else {'EnforcementRequestedRestartRequired'}
        Write-HWJson $record $recordPath
        return $record
    } finally { if ($null -ne $lock) { $lock.Dispose() } }
}

