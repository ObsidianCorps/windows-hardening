#Requires -Version 5.1
[CmdletBinding()]
param([string]$ResultPath)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
$parseErrors=@()
foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File | Where-Object Extension -in @('.ps1','.psm1','.psd1')) {
    $tokens=$null;$errors=$null
    [Management.Automation.Language.Parser]::ParseFile($file.FullName,[ref]$tokens,[ref]$errors) | Out-Null
    $parseErrors+=@($errors)
}
if ($parseErrors.Count) { throw (($parseErrors | ForEach-Object { "$($_.Extent.File):$($_.Extent.StartLineNumber) $($_.Message)" }) -join [Environment]::NewLine) }
$module=Import-Module (Join-Path $root 'src\WindowsHardening.psm1') -Force -PassThru
$testRoot=Join-Path ([IO.Path]::GetTempPath()) ('windows-hardening-tests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot | Out-Null
$results=& $module {
    param($testRoot,$root)
    $script:TestResults=New-Object Collections.Generic.List[object]
    function Assert([bool]$Condition,[string]$Message='Assertion failed') { if (-not $Condition) { throw $Message } }
    function Expect-Throw([scriptblock]$Body,[string]$Pattern='*') {
        $caught=$null
        try { & $Body | Out-Null } catch { $caught=$_.Exception.Message }
        Assert ($null -ne $caught) 'Expected an exception.'
        Assert ($caught -like $Pattern) "Unexpected exception: $caught"
    }
    function Test([string]$Name,[scriptblock]$Body) {
        try { & $Body; $script:TestResults.Add([pscustomobject]@{Name=$Name;Passed=$true;Error=$null}) }
        catch { $script:TestResults.Add([pscustomobject]@{Name=$Name;Passed=$false;Error=($_ | Out-String)}) }
    }
    $catalog=Import-HWCatalog
    $context=[pscustomobject]@{Build=26100;Edition='Professional';Computer='TEST-PC';UserSid='TEST-SID';Admin=$true;Managed=$false;LastBoot='2026-01-01T00:00:00Z'}
    $rule=$catalog.Rules | Where-Object Id -eq 'security.enablelua'
    $one=[pscustomobject]@{SchemaVersion=1;Version='test';Rules=@($rule)}
    $script:Memory=@{}
    $script:Memory[$rule.Id]=New-HWState -Exists $false
    $script:Writes=0;$script:FailWrite=$false;$script:NoOp=$false
    $script:RealState=(Get-Item Function:Get-HWState).ScriptBlock
    $script:RealSet=(Get-Item Function:Set-HWState).ScriptBlock
    $script:RealStore=(Get-Item Function:Initialize-HWStore).ScriptBlock
    $script:RealWrite=(Get-Item Function:Write-HWJson).ScriptBlock
    function script:Get-HWState { param($Rule)
        if ($script:Memory.ContainsKey($Rule.Id)) { return $script:Memory[$Rule.Id] | ConvertTo-Json -Depth 20 | ConvertFrom-Json }
        return New-HWState -Known $false
    }
    function script:Set-HWState { param($Rule,$State)
        $script:Writes++
        if ($script:FailWrite) { throw 'Simulated provider failure' }
        if (-not $script:NoOp) { $script:Memory[$Rule.Id]=$State | ConvertTo-Json -Depth 20 | ConvertFrom-Json }
    }
    function script:Initialize-HWStore { param($Path)
        if (-not (Test-Path -LiteralPath $Path)) { New-Item -ItemType Directory -Path $Path | Out-Null }; return $Path
    }
    function script:Get-HWContext { return $script:TestContext }
    $script:TestContext=$context
    Test 'Catalog has unique IDs, unique targets and versioned metadata' {
        Assert ($catalog.Rules.Count -ge 170)
        Assert (@($catalog.Rules.Id | Sort-Object -Unique).Count -eq $catalog.Rules.Count)
        Assert (@($catalog.Rules | Where-Object { -not $_.Source -or -not $_.Reviewed -or -not $_.Impact }).Count -eq 0)
    }
    Test 'Delivery Optimization has exactly one owner and one desired value' {
        $delivery=@($catalog.Rules | Where-Object { (Get-HWProperty $_.Target 'Name') -eq 'DODownloadMode' })
        Assert ($delivery.Count -eq 1); Assert ($delivery[0].Desired -eq 0)
    }
    Test 'LSA default does not request firmware locking and is build gated' {
        $lsa=$catalog.Rules | Where-Object { (Get-HWProperty $_.Target 'Name') -eq 'RunAsPPL' }
        Assert ($lsa.Desired -eq 2 -and $lsa.MinBuild -ge 22621 -and -not $lsa.Automatic)
    }
    Test 'Legacy and irreversible rules are excluded from default profiles' {
        Assert (@($catalog.Rules | Where-Object { ($_.Deprecated -or -not $_.Reversible) -and $_.Automatic }).Count -eq 0)
    }
    Test 'Planning reads state without mutations or files' {
        $script:Writes=0
        $plan=New-HWPlan $one $context
        Assert ($plan.Items[0].Status -eq 'NotConfigured'); Assert ($script:Writes -eq 0)
    }
    Test 'Unknown evidence is excluded from apply' {
        $script:Memory[$rule.Id]=New-HWState -Known $false
        $plan=New-HWPlan $one $context
        $r=Invoke-HWApply $plan (Join-Path $testRoot 'unknown') -Confirm:$false
        Assert ($r.Journal.Items.Count -eq 0 -and $null -eq $r.Path)
        $script:Memory[$rule.Id]=New-HWState -Exists $false
    }
    Test 'WhatIf does not create a state directory or call a provider' {
        $plan=New-HWPlan $one $context;$script:Writes=0
        $path=Join-Path $testRoot 'whatif'
        $r=Invoke-HWApply $plan $path -WhatIf -Confirm:$false
        Assert ($script:Writes -eq 0 -and -not (Test-Path $path))
    }
    Test 'Write-ahead journal precedes mutation and restore removes an originally absent value' {
        $script:Memory[$rule.Id]=New-HWState -Exists $false;$script:Writes=0
        $plan=New-HWPlan $one $context
        $run=Invoke-HWApply $plan (Join-Path $testRoot 'roundtrip') -Confirm:$false
        Assert ($run.Failed -eq 0 -and $run.Journal.Items[0].After.Value -eq 1)
        Assert ((Read-HWJson $run.Path).Completed)
        $restore=Restore-HWRun $run.Path (Join-Path $testRoot 'roundtrip') -Confirm:$false
        Assert ($restore.Failed -eq 0 -and -not $script:Memory[$rule.Id].Exists)
        $script:RoundtripPath=$run.Path
    }
    Test 'Restoring an already restored value is idempotent' {
        $script:Writes=0
        $r=Restore-HWRun $script:RoundtripPath (Join-Path $testRoot 'roundtrip') -Confirm:$false
        Assert ($r.Items[0].Status -eq 'AlreadyRestored' -and $script:Writes -eq 0)
    }
    Test 'Post-run configuration changes are preserved as restore conflicts' {
        $script:Memory[$rule.Id]=New-HWState -Exists $false
        $run=Invoke-HWApply (New-HWPlan $one $context) (Join-Path $testRoot 'conflict') -Confirm:$false
        $script:Memory[$rule.Id]=New-HWState -Value 9 -Type DWord
        $r=Restore-HWRun $run.Path (Join-Path $testRoot 'conflict') -Confirm:$false
        Assert ($r.Failed -eq 1 -and $r.Items[0].Status -eq 'Conflict' -and $script:Memory[$rule.Id].Value -eq 9)
    }
    Test 'Stale previews abort before mutation' {
        $script:Memory[$rule.Id]=New-HWState -Exists $false
        $plan=New-HWPlan $one $context
        $script:Memory[$rule.Id]=New-HWState -Value 8 -Type DWord;$script:Writes=0
        Expect-Throw { Invoke-HWApply $plan (Join-Path $testRoot 'stale') -Confirm:$false } '*State changed*'
        Assert ($script:Writes -eq 0)
    }
    Test 'Provider failures are recorded and returned as failures' {
        $script:Memory[$rule.Id]=New-HWState -Exists $false;$script:FailWrite=$true
        try {
            $run=Invoke-HWApply (New-HWPlan $one $context) (Join-Path $testRoot 'failure') -Confirm:$false
            Assert ($run.Failed -eq 1 -and $run.Journal.Items[0].Status -eq 'Failed')
            Assert ((Read-HWJson $run.Path).Items[0].Error -like '*Simulated*')
        } finally { $script:FailWrite=$false }
    }
    Test 'A successful command without a state change fails verification' {
        $script:Memory[$rule.Id]=New-HWState -Exists $false;$script:NoOp=$true
        try {
            $run=Invoke-HWApply (New-HWPlan $one $context) (Join-Path $testRoot 'noop') -Confirm:$false
            Assert ($run.Failed -eq 1 -and $run.Journal.Items[0].Error -like '*verification*')
        } finally { $script:NoOp=$false }
    }
    Test 'Failure to persist backup aborts before mutation and releases the lock' {
        $script:Memory[$rule.Id]=New-HWState -Exists $false;$script:Writes=0
        function script:Write-HWJson { param($Data,$Path) throw 'Simulated disk full' }
        try { Expect-Throw { Invoke-HWApply (New-HWPlan $one $context) (Join-Path $testRoot 'diskfull') -Confirm:$false } '*disk full*'; Assert ($script:Writes -eq 0) }
        finally { Set-Item Function:script:Write-HWJson $script:RealWrite }
        $lock=[IO.File]::Open((Join-Path $testRoot 'diskfull\mutation.lock'),[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None);$lock.Dispose()
    }
    Test 'Concurrent mutation is rejected' {
        $path=Join-Path $testRoot 'concurrent';New-Item -ItemType Directory -Path $path | Out-Null
        $lock=[IO.File]::Open((Join-Path $path 'mutation.lock'),[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        try { Expect-Throw { Invoke-HWApply (New-HWPlan $one $context) $path -Confirm:$false } '*Another hardening*' }
        finally { $lock.Dispose() }
    }
    Test 'Managed and unknown management states require explicit override' {
        foreach ($managed in @($true,$null)) {
            $c=$context | ConvertTo-Json | ConvertFrom-Json;$c.Managed=$managed
            Expect-Throw { Assert-HWApplyContext $c } '*managed*'
            Assert-HWApplyContext $c -AllowManaged
        }
    }
    Test 'Non-admin apply is rejected' {
        $c=$context | ConvertTo-Json | ConvertFrom-Json;$c.Admin=$false
        Expect-Throw { Assert-HWApplyContext $c } '*Administrator*'
    }
    Test 'Existing ASR Block and Warn are never downgraded by Audit' {
        $r=$catalog.Rules | Where-Object Kind -eq 'ASR' | Select-Object -First 1
        foreach ($action in @(1,2,6)) { Assert (Test-HWCompliant $r (New-HWState -Value $action)) }
        Assert (-not (Test-HWCompliant $r (New-HWState -Value 0)))
    }
    Test 'Existing LSA firmware protection is preserved' {
        $r=$catalog.Rules | Where-Object { (Get-HWProperty $_.Target 'Name') -eq 'RunAsPPL' }
        Assert (Test-HWCompliant $r (New-HWState -Value 1 -Type DWord))
    }
    Test 'Default secure values and registry types are handled distinctly' {
        $r=$catalog.Rules | Where-Object { (Get-HWProperty $_.Target 'Name') -eq 'UseLogonCredential' }
        Assert (Test-HWCompliant $r (New-HWState -Exists $false))
        Assert (-not (Test-HWCompliant $r (New-HWState -Value 0 -Type String)))
    }
    Test 'Unsupported and deprecated rules remain unselected even with IncludeOptional' {
        $c=$context | ConvertTo-Json | ConvertFrom-Json;$c.Build=19045
        $p=New-HWPlan $catalog $c -IncludeOptional
        Assert (-not ($p.Items | Where-Object { (Get-HWProperty $_.Rule.Target 'Name') -eq 'RunAsPPL' }).Selected)
        Assert (@($p.Items | Where-Object { $_.Rule.Deprecated -and $_.Selected }).Count -eq 0)
    }
    Test 'Exceptions suppress changes and preserve their reason' {
        $script:Memory[$rule.Id]=New-HWState -Exists $false
        $p=New-HWPlan $one $context -Exceptions @([pscustomobject]@{RuleId=$rule.Id;Reason='Approved compatibility exception';ExpiresUtc=$null})
        Assert ($p.Items[0].Status -eq 'Excepted' -and -not $p.Items[0].Selected)
    }
    Test 'Expired exceptions no longer suppress findings' {
        $path=Join-Path $testRoot 'exceptions.json'
        Write-HWJson ([pscustomobject]@{SchemaVersion=1;Exceptions=@([pscustomobject]@{RuleId=$rule.Id;Reason='Temporary';ExpiresUtc='2000-01-01T00:00:00Z'})}) $path
        Assert (@(Get-HWExceptions $path $one).Count -eq 0)
    }
    Test 'Invalid IDs, categories and duplicate targets are rejected' {
        Expect-Throw { New-HWPlan $one $context -RuleId does.not.exist } '*Unknown rule*'
        Expect-Throw { New-HWPlan $one $context -Categories DoesNotExist } '*Unknown category*'
        $bad=$one | ConvertTo-Json -Depth 20 | ConvertFrom-Json
        $copy=$rule | ConvertTo-Json -Depth 20 | ConvertFrom-Json;$copy.Id='duplicate.target';$bad.Rules+=@($copy)
        $path=Join-Path $testRoot 'badcatalog.json';Write-HWJson $bad $path
        Expect-Throw { Import-HWCatalog $path } '*Duplicate target*'
    }
    Test 'Tampered journal targets cannot redirect restore writes' {
        $j=Read-HWJson $script:RoundtripPath;$j.Items[0].Rule.Target.Path='HKLM:\SOFTWARE\Other'
        $path=Join-Path $testRoot 'tampered.json';Write-HWJson $j $path
        Expect-Throw { Restore-HWRun $path (Join-Path $testRoot 'restorebad') -Confirm:$false } '*not in the installed catalog*'
    }
    Test 'Cross-user restore is rejected' {
        $j=Read-HWJson $script:RoundtripPath;$j.Context.UserSid='ANOTHER-USER'
        $path=Join-Path $testRoot 'otheruser.json';Write-HWJson $j $path
        Expect-Throw { Restore-HWRun $path $testRoot -Confirm:$false } '*another computer or user*'
    }
    Test 'Snapshots distinguish observed drift and listener appearances without PID noise' {
        $script:Memory[$rule.Id]=New-HWState -Exists $false
        $a=[pscustomobject]@{SchemaVersion=1;CreatedUtc='now';Plan=New-HWPlan $one $context;Network=[pscustomobject]@{
            Listeners=@([pscustomobject]@{Protocol='TCP';LocalAddress='127.0.0.1';LocalPort=80;Scope='Loopback';ProcessName='demo';OwningProcess=1});Interpretation='No reachability claim'}}
        $b=$a | ConvertTo-Json -Depth 24 | ConvertFrom-Json
        $b.Network.Listeners[0].OwningProcess=2
        $d=Compare-HWSnapshot $a $b;Assert ($d.Changes.Count -eq 0 -and $d.ListenerChanges.Count -eq 0)
        $b.Network.Listeners[0].LocalPort=81;$b.Plan.Items[0].Before=New-HWState -Value 1 -Type DWord
        $d=Compare-HWSnapshot $a $b;Assert ($d.Changes.Count -eq 1 -and $d.ListenerChanges.Count -eq 2)
        $script:Fixture=$a
    }
    Test 'Reports redact sensitive fields and escape HTML' {
        $s=$script:Fixture | ConvertTo-Json -Depth 24 | ConvertFrom-Json
        $s.Plan.Context.Computer='SECRET-HOST';$s.Plan.Context.UserSid='SECRET-SID'
        $s.Plan.Items[0].Before.Value='<script>alert(1)</script>SECRET'
        $s.Plan.Items[0].Name='<script>evil</script>'
        $s | Add-Member NoteProperty Diagnostics ([pscustomobject]@{Message='SECRET-LOG'})
        $red=ConvertTo-HWRedacted $s | ConvertTo-Json -Depth 24
        Assert ($red -notmatch 'SECRET|127.0.0.1')
        $out=Export-HWReport $s (Join-Path $testRoot 'reports')
        $html=Get-Content -LiteralPath $out.Html -Raw
        Assert ($html -notmatch '<script>' -and $html -match '&lt;script&gt;')
    }
    Test 'Catalog comparison detects recommendation changes' {
        $changed=$one | ConvertTo-Json -Depth 20 | ConvertFrom-Json;$changed.Rules[0].Desired=7
        Assert ((Compare-HWCatalog $one $changed).Changes.Count -eq 1)
    }
    Test 'Policy XML parser prohibits external entities and locked policies' {
        $path=Join-Path $testRoot 'policy.xml'
        [IO.File]::WriteAllText($path,'<!DOCTYPE x [<!ENTITY xxe SYSTEM "file:///C:/Windows/win.ini">]><SiPolicy>&xxe;</SiPolicy>')
        Expect-Throw { Read-HWPolicyXml $path }
        [IO.File]::WriteAllText($path,'<SiPolicy><PolicyID>{11111111-1111-1111-1111-111111111111}</PolicyID><BasePolicyID>{11111111-1111-1111-1111-111111111111}</BasePolicyID><Rules /></SiPolicy>')
        Expect-Throw { Get-HWPolicyInfo $path } '*locked*'
    }
    Test 'Invalid encryption certificates are rejected' {
        Expect-Throw { Test-HWEncryptionCertificateText 'not a certificate' }
    }
    Test 'Array, boolean and object state comparison survives JSON roundtrips' {
        foreach ($value in @([pscustomobject]@{B=2;A=1},@(),@(0,1,2),$false,0,'')) {
            $state=New-HWState -Value $value
            Assert (Test-HWEqual $state ($state | ConvertTo-Json -Depth 20 | ConvertFrom-Json))
        }
    }
    Test 'Selected unknown evidence produces an incomplete apply result' {
        $script:Memory[$rule.Id]=New-HWState -Known $false
        $r=Invoke-HWApply (New-HWPlan $one $context -RuleId $rule.Id) (Join-Path $testRoot 'blocked') -Confirm:$false
        Assert ($r.Blocked.Count -eq 1 -and $r.Blocked[0].Status -eq 'Unknown')
    }
    Test 'A prior irreversible operation requires manual recovery' {
        $app=$catalog.Rules | Where-Object Kind -eq 'Package' | Select-Object -First 1
        $j=[pscustomobject]@{SchemaVersion=1;Action='Apply';RunId='app-fixture';Context=$context;Items=@(
            [pscustomobject]@{Id=$app.Id;Rule=$app;Before=New-HWState -Value $true;After=New-HWState -Exists $false;Reversible=$false})}
        $path=Join-Path $testRoot 'app-journal.json';Write-HWJson $j $path
        $r=Restore-HWRun $path $testRoot -Confirm:$false
        Assert ($r.Failed -eq 1 -and $r.Items[0].Status -eq 'ManualRecoveryRequired')
    }
    Test 'Configuration observations do not claim verified runtime protection' {
        $r=$catalog.Rules | Where-Object Id -eq 'runtime.smartscreen'
        $script:Memory[$r.Id]=New-HWState -Value $true
        $p=New-HWPlan ([pscustomobject]@{Version='test';Rules=@($r)}) $context
        Assert ($p.Items[0].Status -eq 'Configured')
    }
    Test 'Cross-machine snapshot comparisons are rejected' {
        $b=$script:Fixture | ConvertTo-Json -Depth 24 | ConvertFrom-Json;$b.Plan.Context.Computer='OTHER'
        Expect-Throw { Compare-HWSnapshot $script:Fixture $b } '*same computer*'
    }
    Test 'An unchanged catalog produces no recommendation diff' {
        Assert ((Compare-HWCatalog $one $one).Changes.Count -eq 0)
    }
    Test 'Relative filesystem paths follow the PowerShell working directory' {
        $path=Resolve-HWFilePath '.\README.md'
        Assert ($path -eq (Join-Path (Get-Location).Path 'README.md'))
        Expect-Throw { Resolve-HWFilePath 'Registry::HKEY_LOCAL_MACHINE\SOFTWARE' } '*filesystem*'
    }
    # Restore production provider functions before provider-specific tests.
    Set-Item Function:script:Get-HWState $script:RealState
    Set-Item Function:script:Set-HWState $script:RealSet
    Test 'Provider restores an absent ASR entry by removing only that rule' {
        function script:Get-MpComputerStatus { [pscustomobject]@{AntivirusEnabled=$true;AMRunningMode='Normal'} }
        function script:Remove-MpPreference { [CmdletBinding()]param($AttackSurfaceReductionRules_Ids) $script:RemovedASR=$AttackSurfaceReductionRules_Ids }
        $r=$catalog.Rules | Where-Object Kind -eq 'ASR' | Select-Object -First 1
        Set-HWState $r (New-HWState -Exists $false -Value 5)
        Assert ($script:RemovedASR -eq $r.Target.Id)
    }
    Test 'ASR mutation refuses passive antivirus' {
        function script:Get-MpComputerStatus { [pscustomobject]@{AntivirusEnabled=$true;AMRunningMode='Passive'} }
        $r=$catalog.Rules | Where-Object Kind -eq 'ASR' | Select-Object -First 1
        Expect-Throw { Set-HWState $r (New-HWState -Value 1) } '*Normal mode*'
    }
    Test 'ASR state query matches GUIDs without case sensitivity' {
        $script:ASRRule=$catalog.Rules | Where-Object Kind -eq 'ASR' | Select-Object -First 1
        function script:Get-MpPreference { [pscustomobject]@{AttackSurfaceReductionRules_Ids=@($script:ASRRule.Target.Id.ToLowerInvariant());AttackSurfaceReductionRules_Actions=@(1)} }
        Assert ((Get-HWState $script:ASRRule).Value -eq 1)
    }
    Test 'Firewall restores NotConfigured without coercing it to False' {
        function script:Get-NetFirewallProfile { [CmdletBinding()]param($PolicyStore,$Name) [pscustomobject]@{Enabled='NotConfigured'} }
        function script:Set-NetFirewallProfile { [CmdletBinding()]param($PolicyStore,$Name,$Enabled) $script:FirewallRestore=$Enabled }
        $r=$catalog.Rules | Where-Object Kind -eq 'Firewall' | Select-Object -First 1
        $state=Get-HWState $r;Set-HWState $r $state
        Assert ($state.Value -eq 'NotConfigured' -and $script:FirewallRestore -eq 'NotConfigured')
    }
    Test 'Adapter NetBIOS changes record and preserve individual adapter identities' {
        function script:Get-CimInstance { [CmdletBinding()]param($ClassName,$Filter)
            [pscustomobject]@{SettingID='adapter-a';TcpipNetbiosOptions=0}
            [pscustomobject]@{SettingID='adapter-b';TcpipNetbiosOptions=1}
        }
        $script:AdapterCalls=@()
        function script:Invoke-CimMethod { [CmdletBinding()]param($InputObject,$MethodName,$Arguments)
            $script:AdapterCalls+=($InputObject.SettingID+':'+$Arguments.TcpipNetbiosOptions)
            [pscustomobject]@{ReturnValue=0}
        }
        $r=$catalog.Rules | Where-Object Kind -eq 'NetBIOS'
        $original=Get-HWState $r
        Set-HWState $r (New-HWDesiredState $r $original)
        Assert (($script:AdapterCalls -join ',') -eq 'adapter-a:2,adapter-b:2')
        $script:AdapterCalls=@();Set-HWState $r $original
        Assert (($script:AdapterCalls -join ',') -eq 'adapter-a:0,adapter-b:1')
    }
    Test 'Adapter method error codes fail the operation' {
        function script:Invoke-CimMethod { [CmdletBinding()]param($InputObject,$MethodName,$Arguments) [pscustomobject]@{ReturnValue=91} }
        $r=$catalog.Rules | Where-Object Kind -eq 'NetBIOS'
        Expect-Throw { Set-HWState $r (Get-HWState $r) } '*returned 91*'
    }
    Test 'Feature disabling preserves payload and requests no automatic restart' {
        function script:Disable-WindowsOptionalFeature { [CmdletBinding()]param([switch]$Online,$FeatureName,[switch]$NoRestart)
            $script:FeatureNoRestart=[bool]$NoRestart;$script:FeatureName=$FeatureName
        }
        $r=$catalog.Rules | Where-Object Kind -eq 'Feature'
        Set-HWState $r (New-HWState -Value 'Disabled')
        Assert ($script:FeatureNoRestart -and $script:FeatureName -eq 'SMB1Protocol')
    }
    Test 'App removal does not deprovision applications for future users' {
        $script:RemovedPackage=$false
        function script:Get-AppxPackage { [CmdletBinding()]param($Name) [pscustomobject]@{Name='Fixture.App'} }
        function script:Remove-AppxPackage { [CmdletBinding()]param([Parameter(ValueFromPipeline)]$Package) process {$script:RemovedPackage=$true} }
        function script:Remove-AppxProvisionedPackage { throw 'Provisioning must never be touched.' }
        $r=$catalog.Rules | Where-Object Kind -eq 'Package' | Select-Object -First 1
        Set-HWState $r (New-HWState -Value $false)
        Assert $script:RemovedPackage
    }
    Test 'Provider rejects mutation of observation-only rules' {
        Expect-Throw { Set-HWState ([pscustomobject]@{Kind='Observation'}) (New-HWState -Value $true) } '*read-only*'
    }
    Test 'Native command runner rejects PATH-injected executable names' {
        Expect-Throw { Invoke-HWNative 'evil.exe' @() } '*not allowlisted*'
    }
    $script:TestResults.ToArray()
} $testRoot $root
$failures=@($results | Where-Object { -not $_.Passed })
$results | Select-Object Name,Passed | Format-Table -AutoSize
if ($ResultPath) {
    [IO.File]::WriteAllText([IO.Path]::GetFullPath($ResultPath),($results | ConvertTo-Json -Depth 10),(New-Object Text.UTF8Encoding($true)))
}
Write-Host ("Passed {0}/{1}; fixtures: {2}" -f ($results.Count-$failures.Count),$results.Count,$testRoot)
if ($failures.Count) { $failures | ForEach-Object { Write-Host $_.Name;Write-Host $_.Error };exit 1 }

