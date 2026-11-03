# Provider states contain configuration only: no timestamps or volatile diagnostic text.
function New-HWState {
    param([bool]$Known=$true,[bool]$Exists=$true,$Value=$null,[string]$Type='', $Extra=$null)
    [pscustomobject]@{Known=$Known;Exists=$Exists;Value=$Value;Type=$Type;Extra=$Extra}
}

function Get-HWRegistryState {
    param([string]$Path,[string]$Name)
    if (-not (Test-Path -LiteralPath $Path -ErrorAction Stop)) { return New-HWState -Exists $false }
    $key=Get-Item -LiteralPath $Path -ErrorAction Stop
    try {
        if ($Name -notin $key.GetValueNames()) { return New-HWState -Exists $false }
        $kind=$key.GetValueKind($Name).ToString()
        $value=$key.GetValue($Name,$null,[Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
        return New-HWState -Value $value -Type $kind
    } finally { $key.Close() }
}

function Get-HWState {
    param([Parameter(Mandatory)]$Rule)
    switch ($Rule.Kind) {
        'Registry' { return Get-HWRegistryState $Rule.Target.Path $Rule.Target.Name }
        'Service' {
            $name=$Rule.Target.Name
            if ($name -notmatch '^[a-zA-Z0-9_.-]+$') { throw 'Invalid service name.' }
            $service=Get-CimInstance Win32_Service -Filter "Name='$name'" -ErrorAction Stop
            if ($null -eq $service) { return New-HWState -Exists $false }
            $delay=Get-HWRegistryState "HKLM:\SYSTEM\CurrentControlSet\Services\$name" 'DelayedAutoStart'
            return New-HWState -Value ([pscustomobject]@{StartMode=$service.StartMode;Running=[bool]$service.Started}) -Extra $delay
        }
        'Task' {
            $tasks=@(Get-ScheduledTask -TaskPath $Rule.Target.Path -ErrorAction Stop | Where-Object TaskName -eq $Rule.Target.Name)
            if ($tasks.Count -eq 0) { return New-HWState -Exists $false }
            return New-HWState -Value ([bool]$tasks[0].Settings.Enabled)
        }
        'ASR' {
            $pref=Get-MpPreference -ErrorAction Stop
            $ids=@($pref.AttackSurfaceReductionRules_Ids)
            $actions=@($pref.AttackSurfaceReductionRules_Actions)
            $idx=[array]::IndexOf($ids,[string]$Rule.Target.Id)
            if ($idx -lt 0) {
                # GUID comparison must be case insensitive.
                for ($i=0;$i -lt $ids.Count;$i++) { if ($ids[$i] -eq $Rule.Target.Id) { $idx=$i;break } }
            }
            if ($idx -lt 0) { return New-HWState -Exists $false -Value 5 }
            if ($idx -ge $actions.Count) { return New-HWState -Known $false }
            return New-HWState -Value ([int]$actions[$idx])
        }
        'Defender' {
            $pref=Get-MpPreference -ErrorAction Stop
            $value=Get-HWProperty $pref $Rule.Target.Name
            if ($null -eq $value) { return New-HWState -Known $false }
            return New-HWState -Value ([int]$value)
        }
        'Feature' {
            $f=Get-WindowsOptionalFeature -Online -FeatureName $Rule.Target.Name -ErrorAction Stop
            if ($null -eq $f) { return New-HWState -Known $false }
            return New-HWState -Value ($f.State.ToString())
        }
        'Firewall' {
            $p=Get-NetFirewallProfile -PolicyStore PersistentStore -Name $Rule.Target.Name -ErrorAction Stop
            return New-HWState -Value ($p.Enabled.ToString())
        }
        'NetBIOS' {
            $adapters=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop |
                Sort-Object SettingID | Select-Object @{n='Id';e={$_.SettingID}},@{n='Options';e={[int]$_.TcpipNetbiosOptions}})
            return New-HWState -Exists ($adapters.Count -gt 0) -Value @($adapters)
        }
        'Package' {
            $packages=@(Get-AppxPackage -Name $Rule.Target.Name -ErrorAction Stop | Sort-Object PackageFullName | Select-Object Name,PackageFullName)
            return New-HWState -Exists ($packages.Count -gt 0) -Value ($packages.Count -gt 0) -Extra @($packages)
        }
        'Observation' { return Get-HWObservation $Rule.Target.Name }
        default { throw "Unsupported provider: $($Rule.Kind)" }
    }
}

function New-HWDesiredState {
    param($Rule,$Before=$null)
    if ($Rule.Kind -eq 'Registry') { return New-HWState -Value $Rule.Desired -Type $Rule.RegistryType }
    if ($Rule.Kind -eq 'NetBIOS') {
        return New-HWState -Value @($Before.Value | ForEach-Object { [pscustomobject]@{Id=$_.Id;Options=[int]$Rule.Desired} })
    }
    return New-HWState -Value $Rule.Desired
}

function Set-HWState {
    param([Parameter(Mandatory)]$Rule,[Parameter(Mandatory)]$State)
    if (-not $State.Known) { throw 'Cannot apply an unknown state.' }
    switch ($Rule.Kind) {
        'Registry' {
            if (-not $State.Exists) {
                if (Test-Path -LiteralPath $Rule.Target.Path -ErrorAction Stop) {
                    $existing=Get-HWRegistryState $Rule.Target.Path $Rule.Target.Name
                    if ($existing.Exists) { Remove-ItemProperty -LiteralPath $Rule.Target.Path -Name $Rule.Target.Name -ErrorAction Stop }
                }
                # Do not delete parent keys: another process may have added unrelated values.
            } else {
                if (-not (Test-Path -LiteralPath $Rule.Target.Path -ErrorAction Stop)) { New-Item -Path $Rule.Target.Path -Force -ErrorAction Stop | Out-Null }
                $value=$State.Value
                switch ($State.Type) {
                    'DWord' { $value=[int]$value }
                    'QWord' { $value=[long]$value }
                    'Binary' { $value=[byte[]]$value }
                    'MultiString' { $value=[string[]]$value }
                    {$_ -in @('String','ExpandString')} { $value=[string]$value }
                    default { throw 'Unsupported registry type.' }
                }
                New-ItemProperty -LiteralPath $Rule.Target.Path -Name $Rule.Target.Name -Value $value -PropertyType $State.Type -Force -ErrorAction Stop | Out-Null
            }
        }
        'Service' {
            if (-not $State.Exists) { throw 'Cannot recreate a missing service.' }
            $startup=switch ($State.Value.StartMode) { 'Auto' {'Automatic'} 'Manual' {'Manual'} 'Disabled' {'Disabled'} default {throw 'Unsupported service start mode.'} }
            if (-not $State.Value.Running) {
                $svc=Get-Service -Name $Rule.Target.Name -ErrorAction Stop
                if ($svc.Status -ne 'Stopped') { Stop-Service -Name $Rule.Target.Name -ErrorAction Stop }
            }
            Set-Service -Name $Rule.Target.Name -StartupType $startup -ErrorAction Stop
            if ($null -ne $State.Extra) {
                $delayRule=[pscustomobject]@{Kind='Registry';Target=[pscustomobject]@{Path="HKLM:\SYSTEM\CurrentControlSet\Services\$($Rule.Target.Name)";Name='DelayedAutoStart'}}
                Set-HWState $delayRule $State.Extra
            }
            if ($State.Value.Running) { Start-Service -Name $Rule.Target.Name -ErrorAction Stop }
        }
        'Task' {
            if ($State.Value) { Enable-ScheduledTask -TaskPath $Rule.Target.Path -TaskName $Rule.Target.Name -ErrorAction Stop | Out-Null }
            else { Disable-ScheduledTask -TaskPath $Rule.Target.Path -TaskName $Rule.Target.Name -ErrorAction Stop | Out-Null }
        }
        'ASR' {
            $status=Get-MpComputerStatus -ErrorAction Stop
            if (-not $status.AntivirusEnabled -or $status.AMRunningMode -ne 'Normal') { throw 'Defender Antivirus must be active in Normal mode.' }
            if (-not $State.Exists) { Remove-MpPreference -AttackSurfaceReductionRules_Ids $Rule.Target.Id -ErrorAction Stop }
            else { Add-MpPreference -AttackSurfaceReductionRules_Ids $Rule.Target.Id -AttackSurfaceReductionRules_Actions ([int]$State.Value) -ErrorAction Stop }
        }
        'Defender' {
            $status=Get-MpComputerStatus -ErrorAction Stop
            if (-not $status.AntivirusEnabled -or $status.AMRunningMode -ne 'Normal') { throw 'Defender Antivirus must be active in Normal mode.' }
            $parameters=@{ErrorAction='Stop'}
            if ($Rule.Target.Name -notin @('PUAProtection','EnableNetworkProtection')) { throw 'Unsupported Defender preference.' }
            $parameters[$Rule.Target.Name]=[int]$State.Value
            Set-MpPreference @parameters
        }
        'Feature' {
            if ($State.Value -eq 'Disabled') { Disable-WindowsOptionalFeature -Online -FeatureName $Rule.Target.Name -NoRestart -ErrorAction Stop | Out-Null }
            elseif ($State.Value -eq 'Enabled') { Enable-WindowsOptionalFeature -Online -FeatureName $Rule.Target.Name -All -NoRestart -ErrorAction Stop | Out-Null }
            else { throw 'Feature is in a pending or unsupported state. Restart and audit before changing it.' }
        }
        'Firewall' {
            if ($State.Value -notin @('True','False','NotConfigured')) { throw 'Invalid firewall profile state.' }
            Set-NetFirewallProfile -Name $Rule.Target.Name -PolicyStore PersistentStore -Enabled $State.Value -ErrorAction Stop
        }
        'NetBIOS' {
            $adapters=@(Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=True' -ErrorAction Stop)
            foreach ($saved in @($State.Value)) {
                $match=@($adapters | Where-Object SettingID -eq $saved.Id)
                if ($match.Count -ne 1) { throw "Adapter is no longer present: $($saved.Id)" }
                if ([int]$saved.Options -notin @(0,1,2)) { throw 'Invalid NetBIOS adapter option.' }
                $result=Invoke-CimMethod -InputObject $match[0] -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=[uint32]$saved.Options} -ErrorAction Stop
                if ($result.ReturnValue -notin @(0,1)) { throw "Adapter configuration returned $($result.ReturnValue)." }
            }
        }
        'Package' {
            if ($State.Value) { throw 'App removal requires manual reinstallation; original package payload is not backed up.' }
            Get-AppxPackage -Name $Rule.Target.Name -ErrorAction Stop | Remove-AppxPackage -ErrorAction Stop
        }
        default { throw 'This provider is read-only.' }
    }
}

function Get-HWObservation {
    param([string]$Name)
    switch ($Name) {
        {$_ -in @('DefenderActive','Realtime','Signatures','Tamper')} {
            $s=Get-MpComputerStatus -ErrorAction Stop
            $value=switch ($Name) {
                'DefenderActive' { [bool]($s.AntivirusEnabled -and $s.AMRunningMode -eq 'Normal') }
                'Realtime' { [bool]$s.RealTimeProtectionEnabled }
                'Signatures' { [bool]($s.AntivirusSignatureAge -le 7) }
                'Tamper' { Get-HWProperty $s 'IsTamperProtected' }
            }
            if ($null -eq $value) { return New-HWState -Known $false }
            return New-HWState -Value $value
        }
        'SecureBoot' { return New-HWState -Value ([bool](Confirm-SecureBootUEFI -ErrorAction Stop)) }
        'TPM' { $t=Get-Tpm -ErrorAction Stop; return New-HWState -Value ([bool]($t.TpmPresent -and $t.TpmReady)) }
        'Encryption' {
            $v=Get-BitLockerVolume -MountPoint $env:SystemDrive -ErrorAction Stop
            return New-HWState -Value ([bool]($v.ProtectionStatus -eq 'On' -and $v.VolumeStatus -eq 'FullyEncrypted'))
        }
        {$_ -in @('CredentialGuard','MemoryIntegrity')} {
            $d=Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
            $id=if ($Name -eq 'CredentialGuard') {1} else {2}
            return New-HWState -Value ([bool]($d.SecurityServicesRunning -contains $id))
        }
        'WinRE' {
            # REAgentC output is localized. Preserve evidence; never guess health from an English string.
            $r=Invoke-HWNative 'reagentc.exe' @('/info')
            return New-HWState -Known $false -Value $r.Output
        }
        'SmartScreen' {
            $v=Get-HWRegistryState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' 'EnableSmartScreen'
            if (-not $v.Exists) { return New-HWState -Known $false }
            return New-HWState -Value ([bool]($v.Value -eq 1))
        }
        'DriverBlocklist' {
            $v=Get-HWRegistryState 'HKLM:\SYSTEM\CurrentControlSet\Control\CI\Config' 'VulnerableDriverBlocklistEnable'
            if (-not $v.Exists) { return New-HWState -Known $false }
            return New-HWState -Value ([bool]($v.Value -eq 1))
        }
        'ProtectedLogging' {
            $enabled=Get-HWRegistryState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' 'EnableProtectedEventLogging'
            $cert=Get-HWRegistryState 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\ProtectedEventLogging' 'EncryptionCertificate'
            return New-HWState -Value ([bool]($enabled.Exists -and $enabled.Value -eq 1 -and $cert.Exists -and $cert.Value))
        }
        'Servicing' { return New-HWState -Known $false -Value 'Review OS edition, servicing channel, ESU entitlement and update history; build alone does not prove security-update support.' }
        default { return New-HWState -Known $false }
    }
}

function Test-HWEncryptionCertificateText {
    param([Parameter(Mandatory)][string]$Text)
    try {
        $clean=$Text.Replace('-----BEGIN CERTIFICATE-----','').Replace('-----END CERTIFICATE-----','') -replace '\s',''
        $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2(,[Convert]::FromBase64String($clean))
        if ($cert.HasPrivateKey) { throw 'Provide only a public certificate.' }
        if ($cert.NotAfter.ToUniversalTime() -le [DateTime]::UtcNow -or $cert.NotBefore.ToUniversalTime() -gt [DateTime]::UtcNow) { throw 'Certificate is expired or not yet valid.' }
        $eku=@($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.37' })
        if ($eku.Count -ne 1 -or '1.3.6.1.4.1.311.80.1' -notin @($eku[0].EnhancedKeyUsages.Value)) { throw 'Certificate requires Document Encryption enhanced key usage.' }
        $usage=@($cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.15' })
        $validUsage=[Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment -bor [Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DataEncipherment
        if ($usage.Count -ne 1 -or -not ($usage[0].KeyUsages -band $validUsage)) { throw 'Certificate requires key or data encipherment usage.' }
        return $true
    } finally { if ($null -ne (Get-Variable cert -ValueOnly -ErrorAction SilentlyContinue)) { $cert.Dispose() } }
}
function Read-HWEncryptionCertificate {
    param([Parameter(Mandatory)][string]$Path)
    $file=Get-Item -LiteralPath $Path -ErrorAction Stop
    if ($file.Length -gt 64KB -or $file.Extension -notin @('.cer','.crt','.pem')) { throw 'Provide a public .cer, .crt or .pem certificate no larger than 64 KB.' }
    $cert=New-Object Security.Cryptography.X509Certificates.X509Certificate2($file.FullName)
    try {
        $text=[Convert]::ToBase64String($cert.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
        Test-HWEncryptionCertificateText $text | Out-Null
        return $text
    } finally { $cert.Dispose() }
}
function Invoke-HWNative {
    param([string]$Name,[string[]]$Arguments)
    # Resolve only Windows system binaries; do not execute PATH-shadowed helpers.
    if ($Name -notin @('reagentc.exe','CiTool.exe')) { throw 'Native executable is not allowlisted.' }
    $executable=Join-Path $env:SystemRoot "System32\$Name"
    if (-not (Test-Path -LiteralPath $executable)) { throw "$Name is unavailable on this build." }
    $output=& $executable @Arguments 2>&1 | Out-String
    $code=$LASTEXITCODE
    if ($code -ne 0) { throw "$Name exited with code $code. $output" }
    [pscustomobject]@{ExitCode=$code;Output=$output.Trim()}
}

