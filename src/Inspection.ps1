function Get-HWNetwork {
    $errors=@(); $listeners=@(); $processes=@{}; $services=@{}
    try { foreach ($p in @(Get-CimInstance Win32_Process -ErrorAction Stop)) { $processes[[int]$p.ProcessId]=$p } }
    catch { $errors += "Process inventory: $($_.Exception.Message)" }
    try { foreach ($s in @(Get-CimInstance Win32_Service -ErrorAction Stop | Where-Object ProcessId -gt 0)) {
        $key=[int]$s.ProcessId
        if (-not $services.ContainsKey($key)) { $services[$key]=@() }
        $services[$key]+=$s.Name
    } } catch { $errors += "Service inventory: $($_.Exception.Message)" }
    foreach ($protocol in @('TCP','UDP')) {
        try {
            $endpoints=if ($protocol -eq 'TCP') { @(Get-NetTCPConnection -State Listen -ErrorAction Stop) } else { @(Get-NetUDPEndpoint -ErrorAction Stop) }
            foreach ($e in $endpoints) {
                $ip=$null; $scope='Unknown'
                if ([Net.IPAddress]::TryParse([string]$e.LocalAddress,[ref]$ip)) {
                    $scope=if ([Net.IPAddress]::IsLoopback($ip)) {'Loopback'} elseif ($ip.Equals([Net.IPAddress]::Any) -or $ip.Equals([Net.IPAddress]::IPv6Any)) {'AllInterfaces'} else {'InterfaceAddress'}
                }
                $ownerId=[int]$e.OwningProcess; $process=$null
                if ($processes.ContainsKey($ownerId)) { $process=$processes[$ownerId] }
                $listeners += [pscustomobject]@{Protocol=$protocol;LocalAddress=[string]$e.LocalAddress;LocalPort=[int]$e.LocalPort
                    Scope=$scope;OwningProcess=$ownerId;ProcessName=Get-HWProperty $process 'Name' 'Unavailable'
                    ExecutablePath=Get-HWProperty $process 'ExecutablePath';Services=if ($services.ContainsKey($ownerId)) {@($services[$ownerId])} else {@()}
                    Reachability='Not tested'}
            }
        } catch { $errors += "$protocol inventory: $($_.Exception.Message)" }
    }
    $profiles=@(); $firewall=@()
    try {
        $profiles=@(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop |
            Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction,AllowLocalFirewallRules)
        foreach ($rule in @(Get-NetFirewallRule -PolicyStore ActiveStore -Enabled True -Direction Inbound -ErrorAction Stop)) {
            try {
                $port=@($rule | Get-NetFirewallPortFilter -ErrorAction Stop | Select-Object Protocol,LocalPort,RemotePort)
                $address=@($rule | Get-NetFirewallAddressFilter -ErrorAction Stop | Select-Object LocalAddress,RemoteAddress)
                $app=@($rule | Get-NetFirewallApplicationFilter -ErrorAction Stop | Select-Object Program,Package)
                $svc=@($rule | Get-NetFirewallServiceFilter -ErrorAction Stop | Select-Object Service)
                $firewall += [pscustomobject]@{Name=$rule.Name;DisplayName=$rule.DisplayName;Action=[string]$rule.Action;Profile=[string]$rule.Profile
                    Port=@($port);Address=@($address);Application=@($app);Service=@($svc);PolicyStoreSource=Get-HWProperty $rule 'PolicyStoreSource'}
            } catch { $errors += "Firewall filters unavailable for $($rule.Name)." }
        }
    } catch { $errors += "Firewall inventory: $($_.Exception.Message)" }
    [pscustomobject]@{CollectedAt=[DateTime]::UtcNow.ToString('o');Listeners=@($listeners | Sort-Object Protocol,LocalAddress,LocalPort)
        Profiles=@($profiles);InboundRules=@($firewall);Errors=@($errors)
        Interpretation='Bound sockets and active firewall evidence only. UDP endpoints are not proof of a server. Internet/LAN reachability is not inferred; upstream firewalls and routing also matter.'}
}

function Get-HWDiagnostics {
    param([ValidateSet('Recovery','Camera','Microphone','NetworkShare','Gaming','Application','All')][string]$Symptom='All',
        [string]$JournalPath)
    $categories=switch ($Symptom) {
        'Recovery' {@('Security','Tasks','Services','Bloatware','Updates','AI')}
        'Camera' {@('Privacy','Services')}
        'Microphone' {@('Privacy','Services')}
        'NetworkShare' {@('Network','Security','Services')}
        'Gaming' {@('Services','Bloatware','Defender','Misc')}
        'Application' {@('Defender','Security')}
        default {@('Security','Tasks','Services','Privacy','Network','Bloatware','Updates','AI','Defender','Misc')}
    }
    $related=@()
    if ($JournalPath) {
        $j=Read-HWJson $JournalPath
        foreach ($e in @($j.Items)) {
            if ($e.Rule.Category -in $categories) {
                $related += [pscustomobject]@{Id=$e.Id;Name=$e.Name;Status=$e.Status;Reversible=$e.Reversible
                    Explanation='Potentially related change. Timing/category correlation does not establish causation.'}
            }
        }
    }
    $events=@(); $errors=@()
    foreach ($log in @('Microsoft-Windows-CodeIntegrity/Operational','Microsoft-Windows-Windows Defender/Operational','System')) {
        try {
            $filter=@{LogName=$log;StartTime=(Get-Date).AddDays(-7)}
            if ($log -eq 'System') { $filter.Id=@(12,7000,7001,7023,7024,7031) }
            else { $filter.Id=if ($log -like '*CodeIntegrity*') {@(3033,3063,3065,3066,3076,3077,3089)} else {@(1121,1122,1123,1124,5007)} }
            $events += @(Get-WinEvent -FilterHashtable $filter -MaxEvents 50 -ErrorAction Stop |
                Select-Object TimeCreated,Id,ProviderName,@{n='Message';e={ $m=[string]$_.Message; $m.Substring(0,[Math]::Min(4096,$m.Length)) }})
        } catch { $errors += "$log : $($_.Exception.Message)" }
    }
    $logs=@()
    foreach ($path in @((Join-Path $env:SystemDrive '$SysReset\Logs\setupact.log'),
        (Join-Path $env:SystemDrive '$SysReset\Logs\setuperr.log'),
        (Join-Path $env:SystemRoot 'Logs\ReAgent\ReAgent.log'),
        (Join-Path $env:SystemRoot 'Logs\CBS\CBS.log'),(Join-Path $env:SystemRoot 'Logs\DISM\dism.log'),
        (Join-Path $env:SystemRoot 'Panther\setuperr.log'))) {
        if (Test-Path -LiteralPath $path) { $logs += Get-Item -LiteralPath $path | Select-Object FullName,Length,LastWriteTimeUtc }
    }
    $recovery=$null
    try { $recovery=Invoke-HWNative 'reagentc.exe' @('/info') } catch { $errors += $_.Exception.Message }
    $pending=[pscustomobject]@{
        ComponentServicing=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending'
        WindowsUpdate=Test-Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired'
    }
    [pscustomobject]@{Symptom=$Symptom;CollectedAt=[DateTime]::UtcNow.ToString('o');RelatedChanges=@($related);Events=@($events)
        LogLocations=@($logs);Recovery=$recovery;PendingReboot=$pending;Errors=@($errors)
        Advice='Review error codes and the affected change. Use selective Restore only after review. WinRE status alone does not guarantee reset success. No repair or reset has been attempted.'}
}

function Get-HWSoftwareContext {
    $observations=@()
    foreach ($name in @('GamingServices','vmcompute','WslService','LxssManager')) {
        try { if (Get-Service $name -ErrorAction SilentlyContinue) { $observations += $name } } catch {}
    }
    [pscustomobject]@{Signals=@($observations)
        Advice='GamingServices suggests reviewing Gaming. WSL/virtualization suggests reviewing Developer. These are hints, not a complete compatibility assessment. A managed device requires administrator policy review.'}
}

