<#
.SYNOPSIS
  Prepares a PostgreSQL (16 or later) on the same Windows host for CyberDome: least-privilege roles, TLS with
  certificate verification, local connections only. Run after install.ps1, from an elevated PowerShell.

.DESCRIPTION
  - Roles: the schema owner (only init-db signs in with it) and the runtime role the platform uses (read / write,
    append-only audit log, no schema changes - granted by init-db). Random passwords, kept from a previous run unless
    -RotatePasswords. Database owned by the owner role; CONNECT revoked from PUBLIC; CREATE on schema public revoked.
  - TLS: a private CA and a server certificate for "localhost" (scripts\gen_db_certs.py) in PgData\certs; ssl on;
    scram-sha-256 passwords; with -LocalOnly (default) PostgreSQL listens on localhost only.
  - pg_hba.conf: a marked block at the top allows the two roles to this database only over TLS from 127.0.0.1 / ::1
    and rejects every other connection for them. Re-running replaces the block.
  - Restarts PostgreSQL (the Windows service -ServiceName, else pg_ctl), then writes
      DataDir\secrets\database_url        runtime connection (service account can read)
      DataDir\admin\database_owner_url    owner connection (administrators only)
      DataDir\certs\db-ca.crt             the CA the platform verifies the server with (sslmode=verify-full)
    and runs init-db as the owner. Passwords are never printed.
  The settings file needs SOC_DATABASE_URL_FILE, SOC_DB_RUNTIME_ROLE and SOC_SCHEMA_MANAGE=0 (the template has them).
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$PgBin,         # e.g. C:\Program Files\PostgreSQL\16\bin
    [Parameter(Mandatory = $true)][string]$PgData,        # e.g. C:\Program Files\PostgreSQL\16\data
    [string]$ServiceName,                                  # e.g. postgresql-x64-16; without it pg_ctl restarts
    [int]$Port = 5432,
    [string]$Superuser = "postgres",
    [string]$SuperuserPasswordFile,                        # else psql asks (or local trust applies)
    [string]$Database = "soc_platform",
    [string]$OwnerRole = "soc_owner",
    [string]$AppRole = "soc_app",
    [string]$InstallDir = (Join-Path $env:ProgramFiles "CyberDome"),
    [string]$DataDir = (Join-Path $env:ProgramData "CyberDome"),
    [switch]$RotatePasswords,
    [bool]$LocalOnly = $true,
    [switch]$NoInitDb
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
$L = Get-CyberDomeLayout -InstallDir $InstallDir -DataDir $DataDir
foreach ($n in @($Database, $OwnerRole, $AppRole)) {
    if ($n -notmatch '^[a-z_][a-z0-9_]{0,62}$') { throw "'$n' is not a plain PostgreSQL name (lower-case letters, digits, _)" }
}
$psql = Join-Path $PgBin "psql.exe"
$pgctl = Join-Path $PgBin "pg_ctl.exe"
foreach ($f in @($psql, $L.Python)) { if (-not (Test-Path -LiteralPath $f)) { throw "Not found: $f" } }
$hba = Join-Path $PgData "pg_hba.conf"
if (-not (Test-Path -LiteralPath $hba)) { throw "Not a PostgreSQL data folder (no pg_hba.conf): $PgData" }

$runtimeFile = Join-Path $L.Secrets "database_url"
$ownerFile = Join-Path $L.Admin "database_owner_url"
foreach ($d in @($L.Secrets, $L.Admin, $L.Certs)) { if (-not (Test-Path -LiteralPath $d)) { throw "Run install.ps1 first ($d is missing)" } }

function Get-UrlPassword([string]$File) {
    if (-not (Test-Path -LiteralPath $File)) { return $null }
    $m = [regex]::Match((Get-Content -LiteralPath $File -Raw), '^[^:]+://[^:]+:([^@]+)@')
    if ($m.Success) { return $m.Groups[1].Value }
    return $null
}
$ownerPw = $null
$appPw = $null
if (-not $RotatePasswords) { $ownerPw = Get-UrlPassword $ownerFile; $appPw = Get-UrlPassword $runtimeFile }
if (-not $ownerPw) { $ownerPw = New-RandomSecret }
if (-not $appPw) { $appPw = New-RandomSecret }

$oldPw = $env:PGPASSWORD
if ($SuperuserPasswordFile) { $env:PGPASSWORD = (Get-Content -LiteralPath $SuperuserPasswordFile -Raw).Trim() }
function Invoke-Psql([string]$Sql, [string]$Db = "postgres") {
    # SQL goes in on standard input, so no password appears on a command line
    $Sql | & $psql -X -q -v ON_ERROR_STOP=1 -h localhost -p $Port -U $Superuser -d $Db -f - | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "psql failed (exit $LASTEXITCODE)" }
}

try {
    Write-Host "==> TLS certificates"
    $pgCerts = Join-Path $PgData "certs"
    Invoke-Checked $L.Python @((Join-Path $L.App "scripts\gen_db_certs.py"), $pgCerts, "--host", "localhost")
    Copy-Item -LiteralPath (Join-Path $pgCerts "ca.crt") -Destination (Join-Path $L.Certs "db-ca.crt") -Force
    $crt = (Join-Path $pgCerts "server.crt") -replace '\\', '/'
    $key = (Join-Path $pgCerts "server.key") -replace '\\', '/'

    Write-Host "==> Roles and database"
    Invoke-Psql @"
SET password_encryption = 'scram-sha-256';
SELECT 'CREATE ROLE $OwnerRole' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$OwnerRole')\gexec
SELECT 'CREATE ROLE $AppRole' WHERE NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$AppRole')\gexec
ALTER ROLE $OwnerRole LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$ownerPw';
ALTER ROLE $AppRole LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE PASSWORD '$appPw';
SELECT 'CREATE DATABASE $Database OWNER $OwnerRole' WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$Database')\gexec
REVOKE ALL ON DATABASE $Database FROM PUBLIC;
GRANT CONNECT ON DATABASE $Database TO $AppRole;
ALTER SYSTEM SET ssl = 'on';
ALTER SYSTEM SET ssl_cert_file = '$crt';
ALTER SYSTEM SET ssl_key_file = '$key';
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
"@
    Invoke-Psql "REVOKE CREATE ON SCHEMA public FROM PUBLIC;" $Database
    if ($LocalOnly) { Invoke-Psql "ALTER SYSTEM SET listen_addresses = 'localhost';" }

    Write-Host "==> pg_hba.conf"
    $begin = "# BEGIN CyberDome (deploy/windows/setup_postgres.ps1)"
    $end = "# END CyberDome"
    $lines = Get-Content -LiteralPath $hba
    $kept = New-Object System.Collections.Generic.List[string]
    $skip = $false
    foreach ($ln in $lines) {
        if ($ln -eq $begin) { $skip = $true; continue }
        if ($ln -eq $end) { $skip = $false; continue }
        if (-not $skip) { $kept.Add($ln) }
    }
    $block = @(
        $begin,
        "hostssl  $Database  $OwnerRole,$AppRole  127.0.0.1/32  scram-sha-256",
        "hostssl  $Database  $OwnerRole,$AppRole  ::1/128       scram-sha-256",
        "host     all        $OwnerRole,$AppRole  all           reject",
        $end
    )
    Copy-Item -LiteralPath $hba -Destination "$hba.before-cyberdome" -Force
    Set-Content -LiteralPath $hba -Value ($block + $kept) -Encoding Ascii

    Write-Host "==> Restarting PostgreSQL"
    if ($ServiceName) { Restart-Service -Name $ServiceName -Force }
    else { Invoke-Starter $pgctl @("restart", "-D", $PgData, "-w", "-m", "fast", "-t", "120") }
} finally {
    $env:PGPASSWORD = $oldPw
}

$ca = (Join-Path $L.Certs "db-ca.crt") -replace '\\', '/'
$query = "sslmode=verify-full&sslrootcert=$ca"
Write-SecretFile -Path $runtimeFile -Value "postgresql+psycopg2://${AppRole}:${appPw}@localhost:$Port/${Database}?$query"
Write-SecretFile -Path $ownerFile -Value "postgresql+psycopg2://${OwnerRole}:${ownerPw}@localhost:$Port/${Database}?$query"
Write-Host "    $runtimeFile (runtime), $ownerFile (owner, administrators only)"

if (-not $NoInitDb) {
    Write-Host "==> Creating the schema (init-db as $OwnerRole)"
    Invoke-SchemaInit -Layout $L -OwnerDatabaseUrlFile $ownerFile
}
Write-Host "Done. The settings file needs: SOC_DATABASE_URL_FILE=$runtimeFile, SOC_DB_RUNTIME_ROLE=$AppRole, SOC_SCHEMA_MANAGE=0"
