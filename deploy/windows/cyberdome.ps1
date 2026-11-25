<#
.SYNOPSIS
  Controls CyberDome on a Windows host: start, stop, restart, status, check.

.DESCRIPTION
  start    starts the scheduled task(s) \CyberDome\API (and \CyberDome\Scheduler when registered)
  stop     asks each launcher to stop (DataDir\run\<role>.stop), ends the platform's process tree by its recorded
           process id (uvicorn's worker processes outlive their parent otherwise), then ends the task
  restart  stop, then start
  status   each task's state and process, and the platform's /health/live and /health/ready answers
  check    "python -m soc_platform config check" with the settings file loaded (every problem with its fix)
  Run from an elevated PowerShell. Values from the settings file are never printed.
#>
[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true)][ValidateSet("start", "stop", "restart", "status", "check")][string]$Command,
    [string]$InstallDir = (Join-Path $env:ProgramFiles "CyberDome"),
    [string]$DataDir = (Join-Path $env:ProgramData "CyberDome"),
    [int]$StopTimeoutSeconds = 60
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
$L = Get-CyberDomeLayout -InstallDir $InstallDir -DataDir $DataDir

function Get-RoleTasks {
    foreach ($role in @("api", "scheduler")) {
        $t = Get-ScheduledTask -TaskPath $script:TaskPath -TaskName $script:Roles[$role] -ErrorAction SilentlyContinue
        if ($t) { [pscustomobject]@{ Role = $role; Task = $t } }
    }
}

function Get-RolePid([string]$Role) {
    $f = Join-Path $L.Run "$Role.pid"
    if (-not (Test-Path -LiteralPath $f)) { return $null }
    $id = [int](Get-Content -LiteralPath $f -Raw).Trim()
    if (Get-Process -Id $id -ErrorAction SilentlyContinue) { return $id }
    return $null
}

function Stop-Roles {
    $tasks = @(Get-RoleTasks)
    if (-not $tasks) { throw "No CyberDome scheduled tasks are registered (run install.ps1)." }
    foreach ($t in $tasks) {
        New-Item -ItemType File -Force -Path (Join-Path $L.Run "$($t.Role).stop") | Out-Null
        $id = Get-RolePid $t.Role
        if ($id) {
            & (Join-Path $env:SystemRoot "System32\taskkill.exe") /PID $id /T /F | Out-Null
            Write-Host "$($t.Role): stopped process tree $id"
        }
    }
    $deadline = (Get-Date).AddSeconds($StopTimeoutSeconds)
    foreach ($t in $tasks) {
        while ((Get-ScheduledTask -TaskPath $script:TaskPath -TaskName $t.Task.TaskName).State -eq "Running" -and (Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 500
        }
        if ((Get-ScheduledTask -TaskPath $script:TaskPath -TaskName $t.Task.TaskName).State -eq "Running") {
            Stop-ScheduledTask -TaskPath $script:TaskPath -TaskName $t.Task.TaskName
        }
        Write-Host "$($t.Role): $((Get-ScheduledTask -TaskPath $script:TaskPath -TaskName $t.Task.TaskName).State)"
    }
}

function Start-Roles {
    $tasks = @(Get-RoleTasks)
    if (-not $tasks) { throw "No CyberDome scheduled tasks are registered (run install.ps1)." }
    foreach ($t in $tasks) {
        Remove-Item -LiteralPath (Join-Path $L.Run "$($t.Role).stop") -Force -ErrorAction SilentlyContinue
        Start-ScheduledTask -TaskPath $script:TaskPath -TaskName $t.Task.TaskName
        Write-Host "$($t.Role): started"
    }
}

function Show-Status {
    foreach ($t in @(Get-RoleTasks)) {
        $info = Get-ScheduledTaskInfo -TaskPath $script:TaskPath -TaskName $t.Task.TaskName
        $id = Get-RolePid $t.Role
        $proc = "no process"
        if ($id) { $proc = "process $id" }
        Write-Host ("{0}: task {1}, {2}, last result {3}" -f $t.Role, $t.Task.State, $proc, $info.LastTaskResult)
    }
    $null = Import-CyberDomeSettings -Path $L.Settings
    $port = $env:SOC_PORT
    if (-not $port) { $port = "8080" }
    foreach ($path in @("/health/live", "/health/ready")) {
        try {
            $r = Invoke-WebRequest -UseBasicParsing -TimeoutSec 10 -Uri "http://127.0.0.1:$port$path"
            Write-Host "${path}: $($r.StatusCode)"
        } catch {
            $code = $null
            if ($_.Exception.Response) { $code = [int]$_.Exception.Response.StatusCode }
            if ($code) { Write-Host "${path}: $code" } else { Write-Host "${path}: no answer" }
        }
    }
}

switch ($Command) {
    "start" { Start-Roles }
    "stop" { Stop-Roles }
    "restart" { Stop-Roles; Start-Roles }
    "status" { Show-Status }
    "check" {
        & (Join-Path $PSHOME "powershell.exe") -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "run.ps1") `
            -InstallDir $InstallDir -DataDir $DataDir -CheckOnly
        exit $LASTEXITCODE
    }
}
