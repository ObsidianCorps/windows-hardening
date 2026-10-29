function Compare-HWSnapshot {
    param($Before,$After)
    if ($Before.SchemaVersion -ne 1 -or $After.SchemaVersion -ne 1) { throw 'Unsupported snapshot schema.' }
    if ($Before.Plan.Context.Computer -ne $After.Plan.Context.Computer -or $Before.Plan.Context.UserSid -ne $After.Plan.Context.UserSid) { throw 'Snapshots must belong to the same computer and user.' }
    $changes=@()
    $old=@{}; $new=@{}
    foreach ($i in $Before.Plan.Items) { $old[$i.Id]=$i }
    foreach ($i in $After.Plan.Items) { $new[$i.Id]=$i }
    foreach ($id in @(@($old.Keys)+@($new.Keys) | Sort-Object -Unique)) {
        if (-not $old.ContainsKey($id)) { $changes += [pscustomobject]@{Id=$id;Change='RuleAdded';Before=$null;After=$new[$id].Before};continue }
        if (-not $new.ContainsKey($id)) { $changes += [pscustomobject]@{Id=$id;Change='RuleRemoved';Before=$old[$id].Before;After=$null};continue }
        if (-not (Test-HWEqual $old[$id].Before $new[$id].Before) -or $old[$id].Status -ne $new[$id].Status) {
            $changes += [pscustomobject]@{Id=$id;Change='ObservedStateChanged';Before=$old[$id].Before;After=$new[$id].Before}
        }
    }
    $listeners=@();$quality=@()
    if ($null -ne $Before.Network -and $null -ne $After.Network) {
        if (@(Get-HWProperty $Before.Network 'Errors' @()).Count -gt 0 -or @(Get-HWProperty $After.Network 'Errors' @()).Count -gt 0) {
            $quality+='Listener comparison skipped because one network inventory is incomplete.'
        } else {
        $oldEndpoints=@{}; $newEndpoints=@{}
        foreach ($e in $Before.Network.Listeners) { $oldEndpoints["$($e.Protocol)|$($e.LocalAddress)|$($e.LocalPort)|$($e.ProcessName)"]=$e }
        foreach ($e in $After.Network.Listeners) { $newEndpoints["$($e.Protocol)|$($e.LocalAddress)|$($e.LocalPort)|$($e.ProcessName)"]=$e }
        foreach ($key in @(@($oldEndpoints.Keys)+@($newEndpoints.Keys) | Sort-Object -Unique)) {
            if (-not $oldEndpoints.ContainsKey($key)) { $listeners += [pscustomobject]@{Change='Appeared';Endpoint=$newEndpoints[$key]} }
            elseif (-not $newEndpoints.ContainsKey($key)) { $listeners += [pscustomobject]@{Change='Disappeared';Endpoint=$oldEndpoints[$key]} }
        }
        }
    }
    [pscustomobject]@{SchemaVersion=1;CatalogChanged=($Before.Plan.CatalogHash -ne $After.Plan.CatalogHash)
        Changes=@($changes);ListenerChanges=@($listeners);DataQualityWarnings=@($quality);Interpretation='Observed changes since baseline. Attribution to this tool requires a matching apply journal; process IDs are intentionally excluded from listener identity.'}
}

function Compare-HWCatalog {
    param($Before,$After)
    $changes=@();$old=@{};$new=@{}
    foreach ($r in $Before.Rules) { $old[$r.Id]=$r }
    foreach ($r in $After.Rules) { $new[$r.Id]=$r }
    foreach ($id in @(@($old.Keys)+@($new.Keys) | Sort-Object -Unique)) {
        $a=if ($old.ContainsKey($id)) {$old[$id]} else {$null}
        $b=if ($new.ContainsKey($id)) {$new[$id]} else {$null}
        if (-not (Test-HWEqual $a $b)) { $changes += [pscustomobject]@{Id=$id;Before=$a;After=$b} }
    }
    [pscustomobject]@{SchemaVersion=1;From=$Before.Version;To=$After.Version;Changes=@($changes);Advice='Review added, removed and changed recommendations. Catalog comparison never applies changes or executes downloaded code.'}
}

function Get-HWSummary {
    param($Plan)
    foreach ($domain in @('Security','Privacy','Preference')) {
        $items=@($Plan.Items | Where-Object Domain -eq $domain)
        [pscustomobject]@{Domain=$domain;Active=@($items | Where-Object Status -eq 'Active').Count
            Configured=@($items | Where-Object Status -eq 'Configured').Count
            Gaps=@($items | Where-Object Status -eq 'NotConfigured').Count
            Unknown=@($items | Where-Object Status -eq 'Unknown').Count
            Unsupported=@($items | Where-Object Status -in @('Unsupported','NotApplicable')).Count
            Exceptions=@($items | Where-Object Status -eq 'Excepted').Count}
    }
}

function ConvertTo-HWRedacted {
    param($Snapshot)
    # Export a strict allowlist. Do not try to scrub free-form events and paths with regexes.
    $items=@()
    foreach ($p in $Snapshot.Plan.Items) {
        $items += [pscustomobject]@{Id=$p.Id;Name=$p.Name;Category=$p.Category;Domain=$p.Domain;Status=$p.Status;Selected=$p.Selected
            Before=[pscustomobject]@{Known=Get-HWProperty $p.Before 'Known' $false;Exists=Get-HWProperty $p.Before 'Exists' $false
                Value='[redacted]';Type=Get-HWProperty $p.Before 'Type' ''};Rule=[pscustomobject]@{
                Description=$p.Rule.Description;Impact=$p.Rule.Impact;Source=$p.Rule.Source;Reversible=$p.Rule.Reversible;Restart=$p.Rule.Restart;Desired='[redacted]'}}
    }
    $network=$null
    if ($null -ne $Snapshot.Network) {
        $network=[pscustomobject]@{Listeners=@($Snapshot.Network.Listeners | ForEach-Object {
            [pscustomobject]@{Protocol=$_.Protocol;LocalAddress='[redacted]';LocalPort=$_.LocalPort;Scope=$_.Scope
                ProcessName='[redacted]';Reachability='Not tested'}
        });Profiles=@();InboundRules=@();Interpretation=$Snapshot.Network.Interpretation}
    }
    $apply=$null
    $sourceApply=Get-HWProperty $Snapshot 'Apply'
    if ($null -ne $sourceApply) {
        $apply=[pscustomobject]@{Journal=[pscustomobject]@{Items=@($sourceApply.Journal.Items | ForEach-Object {
            [pscustomobject]@{Id=$_.Id;Name=$_.Name;Status=$_.Status;Reversible=$_.Reversible;Before='[redacted]';After='[redacted]'}
        })}}
    }
    [pscustomobject]@{SchemaVersion=1;Redacted=$true;CreatedUtc=$Snapshot.CreatedUtc
        Plan=[pscustomobject]@{ToolVersion=$Snapshot.Plan.ToolVersion;CatalogVersion=$Snapshot.Plan.CatalogVersion
            Profile=$Snapshot.Plan.Profile;Context=[pscustomobject]@{Computer='[redacted]';UserSid='[redacted]';Build=$Snapshot.Plan.Context.Build;Edition=$Snapshot.Plan.Context.Edition};Items=@($items)}
        Network=$network;Diagnostics=$null;Diff=$null;Apply=$apply}
}

function Export-HWReport {
    param([Parameter(Mandatory)]$Snapshot,[Parameter(Mandatory)][string]$Directory,[switch]$Redact)
    Initialize-HWStore $Directory | Out-Null
    $report=if ($Redact) {ConvertTo-HWRedacted $Snapshot} else {$Snapshot}
    $prefix=Join-Path $Directory ("report-"+[DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N'))
    Write-HWJson $report ($prefix+'.json')
    $encode={param($v) [Net.WebUtility]::HtmlEncode([string]$v)}
    $rows=foreach ($p in $report.Plan.Items) {
        $before=if ($null -ne $p.Before) {ConvertTo-HWCanonical $p.Before.Value} else {'Unavailable'}
        '<tr><td>'+(& $encode $p.Id)+'<br>'+(& $encode $p.Name)+'</td><td>'+(& $encode $p.Status)+'</td><td>'+(& $encode $before)+'</td><td>'+(& $encode (ConvertTo-HWCanonical $p.Rule.Desired))+'</td><td>'+(& $encode $p.Rule.Impact)+'</td></tr>'
    }
    $summary=Get-HWSummary $report.Plan | ConvertTo-Html -Fragment | Out-String
    $changeTable=''
    $apply=Get-HWProperty $report 'Apply'
    if ($null -ne $apply) {
        $changeRows=foreach ($entry in $apply.Journal.Items) {
            '<tr><td>'+(& $encode $entry.Id)+'</td><td>'+(& $encode (ConvertTo-HWCanonical $entry.Before))+'</td><td>'+(& $encode (ConvertTo-HWCanonical $entry.After))+'</td><td>'+(& $encode $entry.Status)+'</td><td>'+(& $encode $(if ($entry.Reversible) {'Selective restore available'} else {'Manual recovery required'}))+'</td></tr>'
        }
        $changeTable='<h2>Changes attempted by this run</h2><table><thead><tr><th>Rule</th><th>Before</th><th>After</th><th>Result</th><th>Recovery</th></tr></thead><tbody>'+($changeRows -join '')+'</tbody></table>'
    }
    $diff=Get-HWProperty $report 'Diff'
    if ($null -ne $diff) {
        $diffRows=foreach ($entry in $diff.Changes) {
            '<tr><td>'+(& $encode $entry.Id)+'</td><td>'+(& $encode $entry.Change)+'</td><td>'+(& $encode (ConvertTo-HWCanonical $entry.Before))+'</td><td>'+(& $encode (ConvertTo-HWCanonical $entry.After))+'</td></tr>'
        }
        $changeTable+='<h2>Differences from the accepted snapshot</h2><p>Observed differences do not establish which application made a change.</p><table><thead><tr><th>Rule</th><th>Difference</th><th>Before</th><th>After</th></tr></thead><tbody>'+($diffRows -join '')+'</tbody></table>'
    }
    $details=(& $encode ($report | ConvertTo-Json -Depth 32))
    $html='<!doctype html><html lang="en"><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src ''none''; style-src ''unsafe-inline''"><title>Windows Hardening report</title><style>body{font:16px system-ui;margin:2rem;line-height:1.5;color:#17212b}table{border-collapse:collapse;width:100%}td,th{padding:.6rem;border:1px solid #ccd;text-align:left}pre{white-space:pre-wrap;overflow-wrap:anywhere}th{background:#eef3f8}</style><h1>Windows Hardening report</h1><p>Configured policy is distinct from verified runtime protection. Unknown results require review. Privacy and preference items are counted separately.</p>'+ $summary +'<table><thead><tr><th>Rule</th><th>Status</th><th>Observed</th><th>Target</th><th>Compatibility impact</th></tr></thead><tbody>'+($rows -join '')+'</tbody></table><h2>Evidence, network inventory and differences</h2><pre>'+$details+'</pre></html>'
    $htmlPath=$prefix+'.html'
    $html=$html.Replace('<h2>Evidence, network inventory and differences</h2>',$changeTable+'<h2>Evidence, network inventory and differences</h2>')
    [IO.File]::WriteAllText($htmlPath,$html,(New-Object Text.UTF8Encoding($true)))
    [pscustomobject]@{Json=$prefix+'.json';Html=$htmlPath;Redacted=[bool]$Redact}
}

