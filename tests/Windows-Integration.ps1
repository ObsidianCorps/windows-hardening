#Requires -Version 5.1
[CmdletBinding()]
param([switch]$DisposableClientVm)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
if ($env:GITHUB_ACTIONS -ne 'true' -and -not $DisposableClientVm) { throw 'Run only on a disposable CI runner or explicitly designated disposable client VM.' }
$root=Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src\WindowsHardening.psm1') -Force
$fixture='HKCU:\SOFTWARE\WindowsHardening\Tests\'+[guid]::NewGuid().ToString('N')
$store=Join-Path ([IO.Path]::GetTempPath()) ('hw-integration-'+[guid]::NewGuid().ToString('N'))
New-Item -Path $fixture -Force | Out-Null
try {
    # Only this unique test key is mutated; no production policy is applied.
    $r=[pscustomobject]@{Kind='Registry';Target=[pscustomobject]@{Path=$fixture;Name='Fixture'};Desired=1;RegistryType='DWord'}
    $original=Get-HWState $r
    if ($original.Exists) { throw 'Fixture unexpectedly exists.' }
    Set-HWState $r (New-HWState -Value 1 -Type DWord)
    $written=Get-HWState $r
    if (-not $written.Exists -or $written.Value -ne 1 -or $written.Type -ne 'DWord') { throw 'Registry apply failed.' }
    Set-HWState $r $original
    if ((Get-HWState $r).Exists) { throw 'Originally absent registry value was not removed.' }
    foreach ($case in @(
        [pscustomobject]@{Type='String';Value='text'},
        [pscustomobject]@{Type='ExpandString';Value='%SystemRoot%\Fixture'},
        [pscustomobject]@{Type='DWord';Value=17},
        [pscustomobject]@{Type='QWord';Value=[long]4294967296},
        [pscustomobject]@{Type='Binary';Value=[byte[]]@(0,127,255)},
        [pscustomobject]@{Type='MultiString';Value=[string[]]@('one','two')}
    )) {
        Set-HWState $r (New-HWState -Value $case.Value -Type $case.Type)
        $before=Get-HWState $r
        Set-HWState $r (New-HWState -Value 2 -Type DWord)
        Set-HWState $r ($before | ConvertTo-Json -Depth 12 | ConvertFrom-Json)
        if (-not (Test-HWEqual (Get-HWState $r) $before)) { throw "Typed restore failed: $($case.Type)" }
    }
    Initialize-HWStore $store | Out-Null
    $acl=Get-Acl -LiteralPath $store
    if (-not $acl.AreAccessRulesProtected) { throw 'State directory still inherits access.' }
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    foreach ($ace in $acl.Access) {
        if ($ace.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin $allowed) { throw 'Unexpected principal can access state.' }
    }
    Write-HWJson ([pscustomobject]@{Sequence=1}) (Join-Path $store 'checkpoint.json')
    Write-HWJson ([pscustomobject]@{Sequence=2}) (Join-Path $store 'checkpoint.json')
    if ((Read-HWJson (Join-Path $store 'checkpoint.json')).Sequence -ne 2 -or
        (Read-HWJson (Join-Path $store 'checkpoint.json.previous')).Sequence -ne 1) { throw 'Atomic checkpoint persistence failed.' }
    Write-Host 'PASS: registry absence/type roundtrips, restrictive ACLs, atomic journal checkpoints.'
} finally {
    # Only the literal GUID test key created above is removed.
    Remove-Item -LiteralPath $fixture -Recurse -Force -ErrorAction Stop
}

