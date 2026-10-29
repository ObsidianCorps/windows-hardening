function Get-HWMonitorName {
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    'WindowsHardening-Monitor-'+$sid
}
function Register-HWMonitor {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param([Parameter(Mandatory)][string]$ScriptPath,[Parameter(Mandatory)][string]$BaselinePath,
        [Parameter(Mandatory)][string]$StorePath,[ValidateSet('Everyday','Gaming','Developer','ManagedWorkstation')][string]$Profile='Everyday')
    $scriptFile=(Get-Item -LiteralPath $ScriptPath -ErrorAction Stop).FullName
    $baseline=(Get-Item -LiteralPath $BaselinePath -ErrorAction Stop).FullName
    $snapshot=Read-HWJson $baseline
    if ($snapshot.SchemaVersion -ne 1 -or (Get-HWProperty $snapshot 'Redacted' $false)) { throw 'Monitoring needs an original private snapshot.' }
    $context=Get-HWContext
    if ($snapshot.Plan.Context.Computer -ne $context.Computer -or $snapshot.Plan.Context.UserSid -ne $context.UserSid) { throw 'Baseline belongs to another computer or user.' }
    $name=Get-HWMonitorName
    if (@(Get-ScheduledTask -ErrorAction Stop | Where-Object TaskName -eq $name).Count -gt 0) { throw 'Monitor already exists. Remove it explicitly before replacing it.' }
    if (-not $PSCmdlet.ShouldProcess($name,'Register daily and logon read-only checks as the current limited user')) { return }
    Initialize-HWStore $StorePath | Out-Null
    # Proper PowerShell single-quoted literals are encoded; no shell interpolation of paths.
    $quote={param($value) "'"+([string]$value).Replace("'","''")+"'"}
    $command='& '+(& $quote $scriptFile)+' -Action Monitor -BaselinePath '+(& $quote $baseline)+' -StorePath '+(& $quote ([IO.Path]::GetFullPath($StorePath)))+' -Profile '+(& $quote $Profile)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
    $exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $action=New-ScheduledTaskAction -Execute $exe -Argument "-NoProfile -NonInteractive -EncodedCommand $encoded"
    $user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
    $principal=New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
    $triggers=@((New-ScheduledTaskTrigger -Daily -At '12:00'),(New-ScheduledTaskTrigger -AtLogOn -User $user))
    $settings=New-ScheduledTaskSettingsSet -StartWhenAvailable -MultipleInstances IgnoreNew -ExecutionTimeLimit (New-TimeSpan -Minutes 15)
    Register-ScheduledTask -TaskName $name -Action $action -Principal $principal -Trigger $triggers -Settings $settings -Description 'WindowsHardening owned read-only monitor. Never applies or restores settings.' -ErrorAction Stop | Out-Null
    [pscustomobject]@{TaskName=$name;Mode='Read-only, current user, limited token';Baseline=$baseline}
}
function Remove-HWMonitor {
    [CmdletBinding(SupportsShouldProcess,ConfirmImpact='High')]
    param()
    $name=Get-HWMonitorName
    $task=Get-ScheduledTask -TaskName $name -ErrorAction Stop
    if ($task.Description -ne 'WindowsHardening owned read-only monitor. Never applies or restores settings.') { throw 'Task does not have the expected ownership marker.' }
    if ($PSCmdlet.ShouldProcess($name,'Remove this user''s WindowsHardening monitor')) {
        Unregister-ScheduledTask -TaskName $name -Confirm:$false -ErrorAction Stop
    }
}

