#Requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory)][string]$Directory,[string]$ExpectedSignerThumbprint,[switch]$AllowUnsignedDevelopment)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=(Get-Item -LiteralPath $Directory -ErrorAction Stop).FullName
$manifestPath=Join-Path $root 'release-manifest.psd1'
$signature=Get-AuthenticodeSignature -LiteralPath $manifestPath
if ($signature.Status -eq 'NotSigned' -and $AllowUnsignedDevelopment) { }
elseif ($signature.Status -ne 'Valid') { throw 'Release manifest signature is not valid.' }
elseif (-not $ExpectedSignerThumbprint -or $signature.SignerCertificate.Thumbprint -ne $ExpectedSignerThumbprint.Replace(' ','')) { throw 'Manifest publisher does not match the independently trusted certificate thumbprint.' }
$data=Import-PowerShellDataFile -LiteralPath $manifestPath
if ($data.SchemaVersion -ne 1) { throw 'Unsupported release manifest.' }
if ($signature.Status -eq 'NotSigned' -and -not $data.Development) { throw 'Unsigned production releases are rejected.' }
$expected=@{}
foreach ($entry in $data.Files.GetEnumerator()) {
    $relative=[string]$entry.Key
    if ([IO.Path]::IsPathRooted($relative) -or $relative -match '(^|[\\/])\.\.([\\/]|$)|[:\x00-\x1f]' -or [string]$entry.Value -notmatch '^[A-Fa-f0-9]{64}$') { throw 'Invalid manifest path or digest.' }
    $full=[IO.Path]::GetFullPath((Join-Path $root $relative))
    if (-not $full.StartsWith($root+[IO.Path]::DirectorySeparatorChar,[StringComparison]::OrdinalIgnoreCase)) { throw 'Manifest path escapes release directory.' }
    $file=Get-Item -LiteralPath $full -ErrorAction Stop
    if ($file.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Release files cannot be links or junctions.' }
    if ((Get-FileHash -LiteralPath $full -Algorithm SHA256).Hash -ne $entry.Value) { throw "Checksum mismatch: $relative" }
    $expected[$full]=$true
}
foreach ($file in Get-ChildItem -LiteralPath $root -Recurse -File) {
    if (-not $expected.ContainsKey($file.FullName) -and $file.Name -notin @('release-manifest.psd1','SHA256SUMS.txt')) { throw "Unexpected file in release: $($file.Name)" }
}
[pscustomobject]@{Version=$data.Version;VerifiedFiles=$expected.Count;Publisher=$ExpectedSignerThumbprint;Development=[bool]$data.Development}

