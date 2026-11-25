<#
.SYNOPSIS
  Dumps the CyberDome database (pg_dump, custom format) to DataDir\backups and removes dumps older than -KeepDays.
  With -Register it schedules itself daily (\CyberDome\Backup, as SYSTEM) instead of running now.

.DESCRIPTION
  Connects with the owner connection (DataDir\admin\database_owner_url by default): host, port, user, database and
  TLS settings are passed to pg_dump separately and the password through the environment, never on a command line.
  A dump alone is not a restore: keep DataDir\secrets\data_key with it (protected columns are encrypted with it), and
  copy the backups folder off the host (the organisation's backup agent). Managed PostgreSQL brings its own
  point-in-time recovery; this script is for a database on the same host.
  Restore: pg_restore --clean --if-exists -d <database> <file> as the owner, with the platform stopped.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PgBin,
    [string]$InstallDir = (Join-Path $env:ProgramFiles "CyberDome"),
    [string]$DataDir = (Join-Path $env:ProgramData "CyberDome"),
    [string]$DatabaseUrlFile,
    [string]$BackupDir,
    [int]$KeepDays = 14,
    [switch]$Register,
    [string]$At = "02:00"
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
$L = Get-CyberDomeLayout -InstallDir $InstallDir -DataDir $DataDir
if (-not $DatabaseUrlFile) { $DatabaseUrlFile = Join-Path $L.Admin "database_owner_url" }
if (-not $BackupDir) { $BackupDir = $L.Backups }

if ($Register) {
    if (-not (Test-Elevated)) { throw "Run from an elevated PowerShell to register the backup task." }
    $argList = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", (Join-Path $L.App "deploy\windows\backup.ps1"),
                 "-PgBin", $PgBin, "-InstallDir", $InstallDir, "-DataDir", $DataDir, "-DatabaseUrlFile", $DatabaseUrlFile,
                 "-BackupDir", $BackupDir, "-KeepDays", $KeepDays)
    $action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME "powershell.exe") -Argument (ConvertTo-ArgumentString $argList)
    $trigger = New-ScheduledTaskTrigger -Daily -At $At
    $principal = New-ScheduledTaskPrincipal -UserId "S-1-5-18" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Hours 4) -StartWhenAvailable -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskPath $script:TaskPath -TaskName "Backup" -Action $action -Trigger $trigger -Principal $principal `
        -Settings $settings -Description "CyberDome database dump (deploy\windows\backup.ps1)" -Force | Out-Null
    Write-Host "Registered $($script:TaskPath)Backup daily at $At"
    exit 0
}

$raw = (Get-Content -LiteralPath $DatabaseUrlFile -Raw).Trim()
$uri = [Uri]($raw -replace '^postgresql(\+[a-z0-9]+)?://', 'postgresql://')
$user, $pw = $uri.UserInfo.Split(":", 2)
$query = @{}
foreach ($pair in $uri.Query.TrimStart("?").Split("&")) {
    if ($pair -match '^([^=]+)=(.*)$') { $query[$Matches[1]] = [Uri]::UnescapeDataString($Matches[2]) }
}
New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null
$port = $uri.Port
if ($port -lt 0) { $port = 5432 }
$db = $uri.AbsolutePath.TrimStart("/")
$file = Join-Path $BackupDir ("{0}-{1}.dump" -f $db, (Get-Date).ToUniversalTime().ToString("yyyyMMdd-HHmmss"))
$saved = @{ PGPASSWORD = $env:PGPASSWORD; PGSSLMODE = $env:PGSSLMODE; PGSSLROOTCERT = $env:PGSSLROOTCERT }
try {
    $env:PGPASSWORD = [Uri]::UnescapeDataString($pw)
    if ($query["sslmode"]) { $env:PGSSLMODE = $query["sslmode"] }
    if ($query["sslrootcert"]) { $env:PGSSLROOTCERT = $query["sslrootcert"] }
    Invoke-Checked (Join-Path $PgBin "pg_dump.exe") @("-h", $uri.Host, "-p", "$port", "-U", [Uri]::UnescapeDataString($user),
        "-d", $db, "-Fc", "--no-password", "-f", $file)
} finally {
    foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], "Process") }
}
$size = (Get-Item -LiteralPath $file).Length
Write-Host ("Backup written: {0} ({1:N1} MB)" -f $file, ($size / 1MB))
Get-ChildItem -LiteralPath $BackupDir -File -Filter "*.dump" | Where-Object { $_.LastWriteTime -lt (Get-Date).AddDays(-$KeepDays) } |
    ForEach-Object { Remove-Item -LiteralPath $_.FullName -Force; Write-Host "removed old backup $($_.Name)" }
