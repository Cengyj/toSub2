param(
    [ValidateRange(1, 65535)]
    [int]$Port = 4399
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$nodePath = (Get-Command node.exe -ErrorAction Stop).Source
$pythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $pythonPath)) {
    throw 'Create .venv and install requirements.txt before installing autostart.'
}
# Launch the base executable directly so Task Scheduler owns the supervisor,
# without a virtual-environment redirector process in between.
$basePythonPath = (& $pythonPath -c 'import sys; print(sys._base_executable or sys.executable)').Trim()
if ($LASTEXITCODE -ne 0) { throw 'Could not resolve the base Python executable.' }
$pythonWindowlessPath = Join-Path (Split-Path -Parent $basePythonPath) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonWindowlessPath)) {
    throw 'The base Python installation must include pythonw.exe for windowless autostart.'
}
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot 'node_modules\vite'))) {
    throw 'Run npm.cmd ci before installing autostart.'
}
$taskName = 'toSub2 Persistent Server'
$existing = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
if ($existing) {
    throw "Task '$taskName' already exists. Use the documented start/stop commands to manage it."
}
if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
    throw "Port $Port is already in use; stop that server or select another port."
}

$deploymentRoot = Join-Path $env:LOCALAPPDATA 'toSub2'
New-Item -ItemType Directory -Path $deploymentRoot -Force | Out-Null
$configPath = Join-Path $deploymentRoot 'deployment.json'
$config = [ordered]@{
    ProjectRoot = $projectRoot
    NodePath = $nodePath
    PythonPath = $pythonPath
    SupervisorPythonPath = $pythonWindowlessPath
    OutputRoot = Join-Path $projectRoot 'tmp\chatgpt-onboarding-console'
    LogRoot = Join-Path $deploymentRoot 'logs'
    Host = '127.0.0.1'
    Port = $Port
}
$config | ConvertTo-Json | Set-Content -LiteralPath $configPath -Encoding UTF8

# pythonw is a GUI-subsystem executable: it never creates a console window.
$runnerPath = Join-Path $PSScriptRoot 'windows-daemon.py'
$arguments = '"{0}" --config "{1}"' -f $runnerPath, $configPath
$action = New-ScheduledTaskAction -Execute $pythonWindowlessPath -Argument $arguments -WorkingDirectory $projectRoot
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$triggers = @(
    (New-ScheduledTaskTrigger -AtLogOn -User $user),
    (New-ScheduledTaskTrigger -Once -At (Get-Date).AddMinutes(1) -RepetitionInterval (New-TimeSpan -Minutes 1))
)
$settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable `
    -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
$task = New-ScheduledTask -Action $action -Principal $principal -Trigger $triggers -Settings $settings `
    -Description 'Runs toSub2 independently of Codex; restarts failed node processes and starts at user logon.'
Register-ScheduledTask -TaskName $taskName -InputObject $task | Out-Null
Start-ScheduledTask -TaskName $taskName
[pscustomobject]@{ Task = $taskName; Url = "http://127.0.0.1:$Port/"; Config = $configPath; Logs = $config.LogRoot } | Format-List
