<#
.SYNOPSIS
  Runs one CyberDome process on a Windows host and keeps it running (the scheduled tasks install.ps1 registers call
  this at start-up, as the service account).

.DESCRIPTION
  Loads the settings file (DataDir\config\cyberdome.env) into the process environment, fills the same production
  defaults the container image sets, then starts "python -m soc_platform serve" (role api) or "... scheduler" (role
  scheduler) and restarts it when it exits, with a growing pause (5 s doubling to 5 min; reset after 10 minutes of
  running). Each start writes its own log files under DataDir\logs; logs older than -LogDays are removed. The process
  id is written to DataDir\run\<role>.pid. cyberdome.ps1 stop writes DataDir\run\<role>.stop and ends the process tree:
  the loop then exits instead of restarting.

  -CheckOnly loads the settings and runs "python -m soc_platform config check" (every configuration problem with its
  fix), exiting with its code. Values are never printed.
#>
[CmdletBinding()]
param(
    [ValidateSet("api", "scheduler")][string]$Role = "api",
    [string]$InstallDir = (Join-Path $env:ProgramFiles "CyberDome"),
    [string]$DataDir = (Join-Path $env:ProgramData "CyberDome"),
    [string]$Python,                 # default: InstallDir\venv\Scripts\python.exe
    [string]$AppDir,                 # default: InstallDir\app
    [string]$Code,                   # tests only: run this Python code instead of the platform
    [switch]$SeparateScheduler,      # role api without the built-in scheduler (a scheduler task runs it)
    [switch]$CheckOnly,
    [int]$MaxRestarts = 0,           # 0 = restart for ever
    [int]$BackoffSeconds = 5,
    [int]$LogDays = 30
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")

$L = Get-CyberDomeLayout -InstallDir $InstallDir -DataDir $DataDir
if (-not $Python) { $Python = $L.Python }
if (-not $AppDir) { $AppDir = $L.App }
if (-not (Test-Path -LiteralPath $Python)) { throw "Python not found: $Python (run install.ps1)" }

$names = Import-CyberDomeSettings -Path $L.Settings
# The container image's defaults (deploy/Dockerfile), with this host's folders. The settings file wins.
Set-DefaultSetting "SOC_ENVIRONMENT" "prod"
Set-DefaultSetting "SOC_AUTH_MODE" "entra"
Set-DefaultSetting "SOC_BLOB_STORE" "database"
Set-DefaultSetting "SOC_HOST" "127.0.0.1"          # only the reverse proxy on this host reaches the platform
Set-DefaultSetting "SOC_PORT" "8080"
Set-DefaultSetting "SOC_API_WORKERS" ([string][Math]::Max(1, [Environment]::ProcessorCount))
# every process calling the tools gets 1/N of a tool's rate budget: the workers plus the scheduler
$workers = 0
if ([int]::TryParse("$env:SOC_API_WORKERS", [ref]$workers) -and $workers -gt 0) {   # a mistyped value: config check names it
    Set-DefaultSetting "SOC_CONNECTOR_RATE_SHARE" ([string]($workers + 1))
}
Set-DefaultSetting "SOC_CONNECTORS_CONFIG" (Join-Path $L.Config "connectors.yaml")
Set-DefaultSetting "SOC_SUPPLIERS_FILE" (Join-Path $L.Config "suppliers.yaml")
Set-DefaultSetting "SOC_RAW_PAYLOAD_DIR" (Join-Path $L.Data "raw")
Set-DefaultSetting "SOC_REPORT_OUTPUT_DIR" (Join-Path $L.Data "reports")
Set-DefaultSetting "SOC_PHISHING_HOME" (Join-Path $AppDir "artifacts\phishing")
Set-DefaultSetting "PYTHONUNBUFFERED" "1"
Set-DefaultSetting "PYTHONDONTWRITEBYTECODE" "1"
$keyFile = Join-Path $L.Secrets "data_key"
if (-not $env:SOC_DATA_KEY -and -not $env:SOC_DATA_KEY_FILE -and (Test-Path -LiteralPath $keyFile)) {
    $env:SOC_DATA_KEY_FILE = $keyFile
}
if ($Role -eq "api" -and $SeparateScheduler) { $env:SOC_EMBEDDED_SCHEDULER = "0" }

if ($CheckOnly) {
    Push-Location $AppDir
    try { & $Python -m soc_platform config check; exit $LASTEXITCODE } finally { Pop-Location }
}

foreach ($d in @($L.Logs, $L.Run)) { New-Item -ItemType Directory -Force -Path $d | Out-Null }
if ($Code) { $Arguments = @("-c", $Code) }
elseif ($Role -eq "api") { $Arguments = @("-m", "soc_platform", "serve") }
else { $Arguments = @("-m", "soc_platform", "scheduler") }
$argString = ConvertTo-ArgumentString $Arguments
$stopFlag = Join-Path $L.Run "$Role.stop"
$pidFile = Join-Path $L.Run "$Role.pid"
$supervisorLog = Join-Path $L.Logs "$Role-supervisor.log"
Remove-Item -LiteralPath $stopFlag -Force -ErrorAction SilentlyContinue

function Write-Supervisor([string]$Message) {
    $line = "{0} {1} {2}" -f (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ"), $Role, $Message
    Add-Content -LiteralPath $supervisorLog -Value $line -Encoding UTF8
}

Write-Supervisor ("starting with {0} setting(s) from the settings file" -f $names.Count)
$restarts = 0
$failures = 0
while ($true) {
    Get-ChildItem -LiteralPath $L.Logs -File -Filter "*.log" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$LogDays) } | Remove-Item -Force -ErrorAction SilentlyContinue
    $stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss")
    $out = Join-Path $L.Logs "$Role-$stamp.log"
    $err = Join-Path $L.Logs "$Role-$stamp.err.log"
    $proc = Start-Process -FilePath $Python -ArgumentList $argString -WorkingDirectory $AppDir -NoNewWindow -PassThru `
        -RedirectStandardOutput $out -RedirectStandardError $err
    $null = $proc.Handle              # keep the handle: without it ExitCode is empty once the process has gone
    Set-Content -LiteralPath $pidFile -Value $proc.Id -Encoding Ascii
    Write-Supervisor "process $($proc.Id) started"
    $started = Get-Date
    $proc.WaitForExit()
    $code = $proc.ExitCode
    Remove-Item -LiteralPath $pidFile -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $stopFlag) {
        Write-Supervisor "process $($proc.Id) ended (exit $code) after a stop request"
        Remove-Item -LiteralPath $stopFlag -Force -ErrorAction SilentlyContinue
        exit 0
    }
    if (((Get-Date) - $started).TotalMinutes -ge 10) { $failures = 0 }
    $restarts++
    if ($MaxRestarts -gt 0 -and $restarts -gt $MaxRestarts) {
        Write-Supervisor "process $($proc.Id) exited (exit $code); restart limit $MaxRestarts reached, giving up"
        exit 1
    }
    $pause = [Math]::Min(300, $BackoffSeconds * [Math]::Pow(2, $failures))
    $failures++
    Write-Supervisor ("process {0} exited (exit {1}); restart {2} in {3} s" -f $proc.Id, $code, $restarts, $pause)
    Start-Sleep -Seconds $pause
    if (Test-Path -LiteralPath $stopFlag) { Remove-Item -LiteralPath $stopFlag -Force; exit 0 }
}
