#Requires -Version 5.1
Set-StrictMode -Version Latest
$script:ToolVersion = '2.0.0'
$script:ModuleRoot = $PSScriptRoot
$script:AllowedKinds = @('Registry','Service','Task','ASR','Defender','Feature','Firewall','Package','Observation','NetBIOS')

function Get-HWProperty {
    param($Object, [string]$Name, $Default = $null)
    if ($null -ne $Object -and $null -ne $Object.PSObject.Properties[$Name]) { return $Object.$Name }
    return $Default
}

function Resolve-HWFilePath {
    param([Parameter(Mandatory)][string]$Path)
    if ($Path -match '::' -or ($Path -match '^[^\\/:]+:' -and $Path -notmatch '^[A-Za-z]:[\\/]')) { throw 'Use a filesystem path, not a provider or drive-relative path.' }
    return $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
}

function ConvertTo-HWCanonical {
    param($Value)
    if ($null -eq $Value) { return 'null' }
    if ($Value -is [string] -or $Value -is [ValueType]) { return (ConvertTo-Json -InputObject $Value -Compress) }
    if ($Value -is [System.Collections.IDictionary]) {
        $parts = foreach ($key in @($Value.Keys | Sort-Object)) {
            (ConvertTo-Json -InputObject ([string]$key) -Compress) + ':' + (ConvertTo-HWCanonical $Value[$key])
        }
        return '{' + ($parts -join ',') + '}'
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $parts = foreach ($v in $Value) { ConvertTo-HWCanonical $v }
        return '[' + ($parts -join ',') + ']'
    }
    $map = @{}
    foreach ($p in $Value.PSObject.Properties) { $map[$p.Name] = $p.Value }
    return ConvertTo-HWCanonical $map
}

function Test-HWEqual {
    param($Left, $Right)
    return (ConvertTo-HWCanonical $Left) -ceq (ConvertTo-HWCanonical $Right)
}

function Get-HWHash {
    param([string]$Text)
    $sha = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-','').ToLowerInvariant() }
    finally { $sha.Dispose() }
}

function Read-HWJson {
    param([Parameter(Mandatory)][string]$Path)
    $Path=Resolve-HWFilePath $Path
    $file = Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -gt 20MB) { throw 'JSON input exceeds the 20 MB limit.' }
    return Get-Content -LiteralPath $file.FullName -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
}

function Import-HWCatalog {
    param([string]$Path = (Join-Path $script:ModuleRoot '..\catalog\rules.json'))
    $catalog = Read-HWJson $Path
    if ($catalog.SchemaVersion -ne 1) { throw 'Unsupported catalog schema.' }
    $ids = @{}; $targets = @{}
    foreach ($r in $catalog.Rules) {
        foreach ($name in @('Id','Name','Category','Domain','Kind','Target','Desired','RegistryType','MinBuild','MaxBuild','Editions','Profiles','Automatic','Reversible','Restart','Severity','Description','Impact','Source','Reviewed','Deprecated')) {
            if ($null -eq $r.PSObject.Properties[$name]) { throw "Rule is missing $name." }
        }
        if ($r.Id -notmatch '^[a-z0-9][a-z0-9.*-]+$' -or $ids.ContainsKey($r.Id)) { throw "Invalid or duplicate rule ID: $($r.Id)" }
        if ($r.Kind -notin $script:AllowedKinds) { throw "Unsupported provider: $($r.Kind)" }
        if ($r.Domain -notin @('Security','Privacy','Preference')) { throw 'Invalid rule domain.' }
        if ($r.Source -notmatch '^https://') { throw 'Every rule must have an HTTPS source.' }
        if ($r.Kind -eq 'Registry') {
            if ($r.Target.Path -notmatch '^HK(LM|CU):\\' -or $r.RegistryType -notin @('DWord','QWord','String','ExpandString','MultiString','Binary')) { throw "Invalid registry target: $($r.Id)" }
        }
        $target = $r.Kind + ':' + (ConvertTo-HWCanonical $r.Target)
        if ($targets.ContainsKey($target)) { throw "Duplicate target: $($r.Id)" }
        $targets[$target] = $true; $ids[$r.Id] = $true
    }
    return $catalog
}

function Get-HWContext {
    if (-not [Environment]::Is64BitProcess) { throw 'Use 64-bit Windows PowerShell.' }
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
    $os=$null;$evidenceErrors=@()
    try { $os=Get-CimInstance Win32_OperatingSystem -ErrorAction Stop }
    catch { $evidenceErrors+='OS CIM query unavailable; registry build information used.' }
    if (($null -ne $os -and [int]$os.ProductType -ne 1) -or ($null -eq $os -and (Get-HWProperty $cv 'InstallationType') -ne 'Client')) { throw 'Only Windows client operating systems are supported.' }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $admin = ([Security.Principal.WindowsPrincipal]$identity).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    $managed = $null
    try {
        $cs = Get-CimInstance Win32_ComputerSystem -ErrorAction Stop
        $managed = [bool]($cs.PartOfDomain -or (Test-Path 'HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo') -or
            @(Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Enrollments' -ErrorAction Stop | Where-Object { $_.PSChildName -match '^[{]?[0-9a-f-]{36}[}]?$' }).Count -gt 0)
    } catch { $managed = $null }
    [pscustomobject]@{
        Build = if ($null -ne $os) {[int]$os.BuildNumber} else {[int]$cv.CurrentBuildNumber}; Edition = $cv.EditionID
        DisplayVersion = Get-HWProperty $cv 'DisplayVersion' 'Unknown'
        LastBoot = if ($null -ne $os) {$os.LastBootUpTime.ToUniversalTime().ToString('o')} else {$null}
        Computer = $env:COMPUTERNAME; UserSid = $identity.User.Value; Admin = $admin; Managed = $managed
        CollectedAt = [DateTime]::UtcNow.ToString('o');EvidenceErrors=@($evidenceErrors)
    }
}

function Initialize-HWStore {
    param([Parameter(Mandatory)][string]$Path)
    $full = Resolve-HWFilePath $Path
    if ($full.StartsWith('\\')) { throw 'State must be stored on a local filesystem.' }
    # Inspect existing ancestors before creating any output directory.
    $probe=$full
    while ($probe) {
        if (Test-Path -LiteralPath $probe -ErrorAction Stop) {
            $item=Get-Item -LiteralPath $probe -Force -ErrorAction Stop
            if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'State directory and its ancestors must be real directories, not links or files.' }
        }
        $parent=[IO.Directory]::GetParent($probe)
        $probe=if ($null -ne $parent) {$parent.FullName} else {$null}
    }
    if (-not (Test-Path -LiteralPath $full)) { New-Item -ItemType Directory -Path $full -ErrorAction Stop | Out-Null }
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($identity in @($sid, [Security.Principal.SecurityIdentifier]'S-1-5-18', [Security.Principal.SecurityIdentifier]'S-1-5-32-544')) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $full -AclObject $acl -ErrorAction Stop
    return $full
}

function Write-HWJson {
    param([Parameter(Mandatory)]$Data, [Parameter(Mandatory)][string]$Path)
    $Path=Resolve-HWFilePath $Path
    if ((Test-Path -LiteralPath $Path) -and ((Get-Item -LiteralPath $Path -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Output file cannot be a reparse point.' }
    $tmp = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try {
        $json = ConvertTo-Json -InputObject $Data -Depth 32
        $stream=New-Object IO.FileStream($tmp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
        try {
            $bytes=(New-Object Text.UTF8Encoding($true)).GetPreamble() + [Text.Encoding]::UTF8.GetBytes($json)
            $stream.Write($bytes,0,$bytes.Length)
            $stream.Flush($true)
        } finally { $stream.Dispose() }
        if (Test-Path -LiteralPath $Path) {
            $previous=$Path+'.previous'
            if ((Test-Path -LiteralPath $previous) -and ((Get-Item -LiteralPath $previous -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Backup checkpoint cannot be a reparse point.' }
            [IO.File]::Replace($tmp,$Path,$previous,$true)
        } else { [IO.File]::Move($tmp,$Path) }
    } finally { if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue } }
}

function Test-HWCompliant {
    param($Rule, $State)
    if (-not $State.Known) { return $false }
    if ($Rule.Kind -eq 'Registry') {
        if (-not $State.Exists) { return [bool](Get-HWProperty $Rule 'DefaultSecure' $false) }
        if ($Rule.Target.Name -eq 'RunAsPPL' -and $State.Value -eq 1 -and $Rule.Desired -eq 2) { return $true }
        return ($State.Type -eq $Rule.RegistryType -and (Test-HWEqual $State.Value $Rule.Desired))
    }
    # Never downgrade existing ASR Block/Warn protection when the selected target is Audit.
    if ($Rule.Kind -eq 'ASR' -and (($Rule.Desired -eq 2 -and $State.Value -in @(1,6)) -or ($Rule.Desired -eq 6 -and $State.Value -eq 1))) { return $true }
    if ($Rule.Kind -eq 'NetBIOS') {
        return (@($State.Value).Count -gt 0 -and @($State.Value | Where-Object Options -ne $Rule.Desired).Count -eq 0)
    }
    if ($Rule.Kind -eq 'Feature' -and $Rule.Desired -eq 'Disabled' -and $State.Value -eq 'DisabledWithPayloadRemoved') { return $true }
    if ($Rule.Kind -eq 'Service') {
        return (-not $State.Exists -or ($State.Value.StartMode -eq $Rule.Desired.StartMode -and $State.Value.Running -eq $Rule.Desired.Running))
    }
    if (-not $State.Exists -and $Rule.Kind -in @('Task','Package','Feature')) { return $true }
    return Test-HWEqual $State.Value $Rule.Desired
}

function Get-HWExceptions {
    param([string]$Path, $Catalog)
    if (-not $Path) { return @() }
    $doc = Read-HWJson $Path
    if ($doc.SchemaVersion -ne 1) { throw 'Unsupported exceptions schema.' }
    $seen = @{}
    foreach ($e in @($doc.Exceptions)) {
        if ($e.RuleId -notin @($Catalog.Rules.Id) -or [string]::IsNullOrWhiteSpace($e.Reason) -or $seen.ContainsKey($e.RuleId)) { throw 'Exception requires a unique known rule ID and a reason.' }
        $seen[$e.RuleId] = $true
        if ($e.ExpiresUtc) {
            $expiry = [DateTimeOffset]::Parse($e.ExpiresUtc,[Globalization.CultureInfo]::InvariantCulture)
            if ($expiry -le [DateTimeOffset]::UtcNow) { continue }
        }
        $e
    }
}

function New-HWPlan {
    param($Catalog, $Context, [string]$Profile = 'Everyday', [string[]]$RuleId = @(),
        [string[]]$Categories = @(), [switch]$IncludeOptional, [int]$ASRMode = -1, [array]$Exceptions = @())
    $knownIds = @($Catalog.Rules.Id)
    foreach ($id in $RuleId) { if ($id -notin $knownIds) { throw "Unknown rule: $id" } }
    foreach ($cat in $Categories) { if ($cat -notin @($Catalog.Rules.Category)) { throw "Unknown category: $cat" } }
    $results = @()
    foreach ($sourceRule in $Catalog.Rules) {
        $r = $sourceRule | ConvertTo-Json -Depth 12 | ConvertFrom-Json
        if ($RuleId.Count -gt 0 -and $r.Id -notin $RuleId) { continue }
        if ($Categories.Count -gt 0 -and $r.Category -notin $Categories) { continue }
        if ($r.Kind -eq 'ASR' -and $ASRMode -ge 0) { $r.Desired = $ASRMode }
        $selected = ($r.Automatic -and $Profile -in @($r.Profiles)) -or $IncludeOptional -or $r.Id -in $RuleId
        $status = 'NotConfigured'; $state = $null; $errorText = $null
        $exception = @($Exceptions | Where-Object RuleId -eq $r.Id | Select-Object -First 1)
        if ($Context.Build -lt $r.MinBuild -or ($r.MaxBuild -gt 0 -and $Context.Build -gt $r.MaxBuild) -or
            (@($r.Editions).Count -gt 0 -and $Context.Edition -notin @($r.Editions))) { $status = 'Unsupported'; $selected = $false }
        elseif ($r.Deprecated) { $status = 'Unsupported'; $selected = $false }
        else {
            try {
                $state = Get-HWState $r
                if (-not $state.Known) { $status = 'Unknown' }
                elseif (Test-HWCompliant $r $state) { $status = 'Configured' }
                elseif (-not $state.Exists -and $r.Kind -ne 'Registry' -and $r.Kind -ne 'ASR') { $status = 'NotApplicable' }
            } catch { $status = 'Unknown'; $errorText = $_.Exception.Message }
        }
        if ($r.Id -eq 'logging.encryptioncertificate' -and [string]::IsNullOrWhiteSpace([string]$r.Desired)) {
            $selected=$false
        }
        if ($null -ne $state -and $r.Kind -eq 'Feature' -and $state.Value -in @('EnablePending','DisablePending')) { $status='PendingReboot';$selected=$false }
        if ($r.Kind -eq 'Observation') {
            $selected = $false
            if ($status -eq 'Configured' -and (Get-HWProperty $r 'EvidenceType' 'Runtime') -eq 'Runtime') { $status = 'Active' }
        }
        if ($exception.Count -gt 0) { $status = 'Excepted'; $selected = $false }
        $results += [pscustomobject]@{
            Id = $r.Id; Name = $r.Name; Category = $r.Category; Domain = $r.Domain; Severity = $r.Severity
            Status = $status; Selected = [bool]$selected; Explicit = ($r.Id -in $RuleId); Rule = $r; Before = $state
            Reason = if ($exception.Count) { $exception[0].Reason } else { $null }
            Error = $errorText
        }
    }
    [pscustomobject]@{ SchemaVersion=1; ToolVersion=$script:ToolVersion; CatalogVersion=$Catalog.Version
        CatalogHash=(Get-HWHash (ConvertTo-HWCanonical $Catalog)); Profile=$Profile; Context=$Context; Exceptions=@($Exceptions);Items=@($results) }
}

function Assert-HWApplyContext {
    param($Context, [switch]$AllowManaged)
    if (-not $Context.Admin) { throw 'Applying or restoring changes requires Administrator privileges.' }
    if ($Context.Build -lt 19045) { throw 'This Windows build is too old for mutation support.' }
    if ($Context.Managed -ne $false -and -not $AllowManaged) { throw 'Device is managed, or management status is unknown. Review organization policy and explicitly use -AllowManaged.' }
}

function Invoke-HWApply {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param([Parameter(Mandatory)]$Plan,[Parameter(Mandatory)][string]$StorePath,[switch]$AllowManaged)
    Assert-HWApplyContext $Plan.Context -AllowManaged:$AllowManaged
    $StorePath=Resolve-HWFilePath $StorePath
    $journal = [pscustomobject]@{ SchemaVersion=1; RunId=[guid]::NewGuid().ToString(); Action='Apply'; CreatedUtc=[DateTime]::UtcNow.ToString('o')
        Context=$Plan.Context; CatalogVersion=$Plan.CatalogVersion; Items=@(); Completed=$false }
    $path = Join-Path $StorePath ("run-$($journal.RunId).json")
    $initialized = $false
    foreach ($p in @($Plan.Items | Where-Object { $_.Selected -and $_.Status -eq 'NotConfigured' })) {
        if (-not $PSCmdlet.ShouldProcess("$($p.Id): $($p.Name)",'Apply and journal security configuration')) { continue }
        if (-not $initialized) {
            Initialize-HWStore $StorePath | Out-Null
            $lockPath = Join-Path $StorePath 'mutation.lock'
            try { $lock = [IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None) }
            catch { throw 'Another hardening or restore operation is running.' }
            $initialized = $true
        }
        try {
            # Re-read immediately before mutation, rejecting stale previews.
            $current = Get-HWState $p.Rule
            if (-not (Test-HWEqual $current $p.Before)) { throw "State changed since preview: $($p.Id). Create a new plan." }
            $entry = [pscustomobject]@{ Id=$p.Id; Name=$p.Name; Rule=$p.Rule; Before=$current; After=$null
                Status='Prepared'; Error=$null; Reversible=$p.Rule.Reversible; TimestampUtc=[DateTime]::UtcNow.ToString('o') }
            $journal.Items += $entry
            # Write-ahead journal: a failed backup aborts before the first setting is touched.
            Write-HWJson $journal $path
            try {
                foreach ($dependencyId in @(Get-HWProperty $p.Rule 'Requires' @())) {
                    if ($dependencyId -eq 'logging.encryptioncertificate') {
                        $certState=Get-HWRegistryState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' 'EncryptionCertificate'
                        if (-not $certState.Exists -or -not $certState.Value) { throw 'Protected Event Logging requires an encryption certificate.' }
                        Test-HWEncryptionCertificateText $certState.Value | Out-Null
                    } elseif ($dependencyId -eq 'logging.enableprotectedeventlogging') {
                        $logging=Get-HWObservation 'ProtectedLogging'
                        if (-not $logging.Known -or -not $logging.Value) { throw 'Configure Protected Event Logging before enabling sensitive script logging.' }
                    } else { throw "Unsupported dependency: $dependencyId" }
                }
                Set-HWState $p.Rule (New-HWDesiredState $p.Rule $current) | Out-Null
                $entry.After = Get-HWState $p.Rule
                if (-not (Test-HWCompliant $p.Rule $entry.After)) {
                    if ($p.Rule.Kind -eq 'Feature' -and $entry.After.Value -eq 'DisablePending') { $entry.Status='PendingReboot' }
                    else { throw 'Post-change verification failed.' }
                } else { $entry.Status = if ($p.Rule.Restart) { 'ConfiguredRestartRequired' } else { 'Verified' } }
            } catch {
                $entry.Status = 'Failed'; $entry.Error = $_.Exception.Message
                try { $entry.After = Get-HWState $p.Rule } catch { $entry.After=$null }
            }
            Write-HWJson $journal $path
        } catch {
            # Stale state or journal failure is fatal; never continue without durable evidence.
            if ($initialized) { $lock.Dispose() }
            throw
        }
    }
    if ($initialized) {
        try { $journal.Completed=$true; Write-HWJson $journal $path }
        finally { $lock.Dispose() }
    } else { $path = $null }
    $blocked=@($Plan.Items | Where-Object { ($_.Selected -and $_.Status -eq 'Unknown') -or
        ((Get-HWProperty $_ 'Explicit' $false) -and $_.Status -in @('Unsupported','Unknown','PendingReboot','NotApplicable')) })
    [pscustomobject]@{ Journal=$journal; Path=$path; Failed=@($journal.Items | Where-Object Status -eq 'Failed').Count;Blocked=@($blocked | Select-Object Id,Status,Error) }
}

function Restore-HWRun {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact='High')]
    param([Parameter(Mandatory)][string]$JournalPath,[Parameter(Mandatory)][string]$StorePath,
        [string[]]$RuleId=@(),[switch]$AllowManaged)
    $context = Get-HWContext
    $StorePath=Resolve-HWFilePath $StorePath
    Assert-HWApplyContext $context -AllowManaged:$AllowManaged
    $source = Read-HWJson $JournalPath
    if ($source.SchemaVersion -ne 1 -or $source.Action -ne 'Apply') { throw 'Only version 2 apply journals can be restored. Legacy .reg files are not complete backups.' }
    if ($source.Context.Computer -ne $context.Computer -or $source.Context.UserSid -ne $context.UserSid) { throw 'Journal belongs to another computer or user.' }
    $catalog = Import-HWCatalog
    foreach ($id in $RuleId) { if ($id -notin @($source.Items.Id)) { throw "Rule is not in this run: $id" } }
    $results=@(); $lock=$null; $path=$null
    $entries=@($source.Items); [array]::Reverse($entries)
    try {
        foreach ($entry in $entries) {
            if ($RuleId.Count -gt 0 -and $entry.Id -notin $RuleId) { continue }
            $trusted = @($catalog.Rules | Where-Object Id -eq $entry.Id)
            # Never trust a journal as a source of arbitrary registry paths or commands.
            if ($trusted.Count -ne 1 -or -not (Test-HWEqual $trusted[0].Target $entry.Rule.Target) -or $trusted[0].Kind -ne $entry.Rule.Kind) { throw "Journal rule target is not in the installed catalog: $($entry.Id)" }
            if (-not $trusted[0].Reversible) { $results += [pscustomobject]@{Id=$entry.Id;Status='ManualRecoveryRequired';Error='Reinstall removed apps from Microsoft Store.'}; continue }
            if (-not $PSCmdlet.ShouldProcess($entry.Id,'Restore original state from journal')) { continue }
            if ($null -eq $lock) {
                Initialize-HWStore $StorePath | Out-Null
                $lock=[IO.File]::Open((Join-Path $StorePath 'mutation.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
                $path=Join-Path $StorePath ("restore-$([guid]::NewGuid()).json")
            }
            $r=[pscustomobject]@{Id=$entry.Id;Status='Prepared';Error=$null}
            $results += $r
            Write-HWJson ([pscustomobject]@{SchemaVersion=1;Action='Restore';SourceRun=$source.RunId;Items=@($results)}) $path
            try {
                $current=Get-HWState $trusted[0]
                if (Test-HWEqual $current $entry.Before) { $r.Status='AlreadyRestored' }
                elseif (($null -eq $entry.After -or -not (Test-HWEqual $current $entry.After)) -and
                    -not ($trusted[0].Kind -eq 'Feature' -and $entry.Status -eq 'PendingReboot' -and
                        $null -ne $entry.After -and $entry.After.Value -eq 'DisablePending' -and $current.Value -eq 'Disabled')) {
                    $r.Status='Conflict'; $r.Error='State changed after this run, or the interrupted run has no verified after-state. Review manually.'
                } else {
                    Set-HWState $trusted[0] $entry.Before | Out-Null
                    $restored=Get-HWState $trusted[0]
                    if ($trusted[0].Kind -eq 'Feature' -and
                        (($entry.Before.Value -eq 'Enabled' -and $restored.Value -eq 'EnablePending') -or
                         ($entry.Before.Value -eq 'Disabled' -and $restored.Value -eq 'DisablePending'))) {
                        $r.Status='RestorePendingReboot'
                    } else {
                        if (-not (Test-HWEqual $restored $entry.Before)) { throw 'Restore verification failed; a restart may be required.' }
                        $r.Status=if ($trusted[0].Restart) {'RestoredRestartRequired'} else {'Restored'}
                    }
                }
            } catch { $r.Status='Failed'; $r.Error=$_.Exception.Message }
            Write-HWJson ([pscustomobject]@{SchemaVersion=1;Action='Restore';SourceRun=$source.RunId;Items=@($results)}) $path
        }
    } finally { if ($null -ne $lock) { $lock.Dispose() } }
    [pscustomobject]@{Path=$path;Items=@($results);Failed=@($results | Where-Object Status -in @('Failed','Conflict','ManualRecoveryRequired')).Count}
}

foreach ($file in @('Providers.ps1','Inspection.ps1','Reports.ps1','AppControl.ps1','Automation.ps1')) {
    . (Join-Path $PSScriptRoot $file)
}
Export-ModuleMember -Function *-HW*

