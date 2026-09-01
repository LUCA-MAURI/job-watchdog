# Windows: register a supervised job as a scheduled task.
# Run as Administrator. Pure ASCII - PowerShell 5.1 reads .ps1 as ANSI.
#
# For always-on services rather than periodic jobs, use winservice-kit instead:
# https://github.com/LUCA-MAURI/winservice-kit

$Python  = "C:\Python312\python.exe"
$Tool    = "C:\Tools\job_watchdog.py"
$JobName = "sync"

# SYSTEM has no user environment, so the alert routing goes in machine scope.
[Environment]::SetEnvironmentVariable("ALERT_TELEGRAM_TOKEN", "your-token", "Machine")
[Environment]::SetEnvironmentVariable("ALERT_TELEGRAM_CHAT", "your-chat-id", "Machine")

$action = New-ScheduledTaskAction -Execute $Python `
    -Argument "`"$Tool`" $JobName --timeout 600 -- C:\App\sync.cmd"

$trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 15)

$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -Hidden `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" `
    -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "Supervised $JobName" -Action $action `
    -Trigger $trigger -Settings $settings -Principal $principal
