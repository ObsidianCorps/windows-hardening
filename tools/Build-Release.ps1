#Requires -Version 5.1
[CmdletBinding(SupportsShouldProcess)]
param([Parameter(Mandatory)][string]$OutputDirectory,[string]$SigningThumbprint,[string]$TimestampServer,[switch]$Development)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$root=Split-Path $PSScriptRoot -Parent
$version=(Get-Content -LiteralPath (Join-Path $root 'catalog\rules.json') -Raw | ConvertFrom-Json).Version
if (-not $Development -and (-not $SigningThumbprint -or -not $TimestampServer)) { throw 'Production release requires a code-signing certificate thumbprint and timestamp server. Use -Development for an explicitly unsigned test bundle.' }
$destination=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath $destination) { throw 'OutputDirectory must not already exist; builds never delete or overwrite a release.' }
if (-not $PSCmdlet.ShouldProcess($destination,'Build versioned release bundle')) { return }
New-Item -ItemType Directory -Path $destination | Out-Null
$bundle=Join-Path $destination "windows-hardening-$version"
New-Item -ItemType Directory -Path $bundle | Out-Null
foreach ($name in @('Harden-Windows.ps1','README.md','LICENSE','SECURITY.md','CHANGELOG.md','src','catalog','docs','tools')) {
    Copy-Item -LiteralPath (Join-Path $root $name) -Destination $bundle -Recurse -ErrorAction Stop
}
$cert=$null
if (-not $Development) {
    $matches=@(Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Where-Object Thumbprint -eq $SigningThumbprint)
    if ($matches.Count -ne 1 -or -not $matches[0].HasPrivateKey -or $matches[0].NotAfter -le (Get-Date)) { throw 'A valid code-signing certificate with its private key is required.' }
    $cert=$matches[0]
    foreach ($file in Get-ChildItem -LiteralPath $bundle -Recurse -File | Where-Object Extension -in @('.ps1','.psm1','.psd1')) {
        $signature=Set-AuthenticodeSignature -LiteralPath $file.FullName -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer
        if ($signature.Status -ne 'Valid') { throw "Signing failed: $($file.Name)" }
    }
}
$lines=@('@{',"SchemaVersion = 1","Version = '$version'",('Development = $'+$Development.ToString().ToLowerInvariant()),"Files = @{")
$hashLines=@()
foreach ($file in Get-ChildItem -LiteralPath $bundle -Recurse -File | Sort-Object FullName) {
    $relative=$file.FullName.Substring($bundle.Length+1).Replace('\','/')
    $hash=(Get-FileHash -LiteralPath $file.FullName -Algorithm SHA256).Hash
    $lines+="'$($relative.Replace("'","''"))' = '$hash'"
    $hashLines+="$hash  $relative"
}
$lines+=@('}','}')
$manifest=Join-Path $bundle 'release-manifest.psd1'
[IO.File]::WriteAllLines($manifest,$lines,(New-Object Text.UTF8Encoding($true)))
if ($null -ne $cert) {
    $signature=Set-AuthenticodeSignature -LiteralPath $manifest -Certificate $cert -HashAlgorithm SHA256 -TimestampServer $TimestampServer
    if ($signature.Status -ne 'Valid') { throw 'Manifest signing failed.' }
}
[IO.File]::WriteAllLines((Join-Path $bundle 'SHA256SUMS.txt'),$hashLines,(New-Object Text.UTF8Encoding($false)))
$archive=Join-Path $destination ("windows-hardening-$version"+$(if ($Development) {'-development'} else {''})+'.zip')
Compress-Archive -LiteralPath $bundle -DestinationPath $archive -CompressionLevel Optimal
Get-FileHash -LiteralPath $archive -Algorithm SHA256
Write-Host "Bundle: $bundle"

