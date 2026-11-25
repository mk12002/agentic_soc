<#
.SYNOPSIS
  Installs or upgrades CyberDome on a Windows host (run from an elevated PowerShell, from the release folder).

.DESCRIPTION
  1. Checks the Python interpreter: 64-bit, 3.11 to 3.13 (3.13 recommended), installed for all users.
  2. Copies the release into InstallDir\app (code, configuration templates, models) and creates InstallDir\venv.
  3. Installs every package from the hash-pinned Windows lock (requirements\windows-engine.lock, or
     requirements\windows.lock with -NoEngine) with --require-hashes: a file that changed on the index fails the
     install. Optionally adds the in-house LLM gateway SDK from its own hashed lock (-GatewaySdkLock with
     -GatewaySdkLockSha256, and -PipConfig for the internal index).
  4. Creates DataDir: config (settings file from the template, connectors.yaml, suppliers.yaml; never overwritten),
     secrets (a new data-encryption key if none), admin, certs, data, logs, run, backups - with NTFS permissions:
     administrators and SYSTEM full control, the service account only what it needs.
  5. With -OwnerDatabaseUrlFile: creates / extends the database schema as its owner (init-db) and grants the runtime
     role (SOC_DB_RUNTIME_ROLE in the settings file). The owner connection is read here and never stored elsewhere.
  6. Registers the scheduled tasks \CyberDome\API (and \CyberDome\Scheduler with -SeparateScheduler): at start-up, as
     the service account, restarted on failure, no time limit. Runs "config check" and starts them only if it passes.

  Re-running it upgrades in place: settings, secrets and data are kept.

.EXAMPLE
  .\deploy\windows\install.ps1 -Python "C:\Program Files\Python313\python.exe"
.EXAMPLE
  .\deploy\windows\install.ps1 -Python "C:\Program Files\Python313\python.exe" -ServiceAccount "CORP\svc-cyberdome$" `
      -OwnerDatabaseUrlFile C:\ProgramData\CyberDome\admin\database_owner_url
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Python,
    [string]$InstallDir = (Join-Path $env:ProgramFiles "CyberDome"),
    [string]$DataDir = (Join-Path $env:ProgramData "CyberDome"),
    # LOCAL SERVICE (default: no password, no network identity), a group managed service account ("DOMAIN\name$"),
    # or a user account with -ServiceCredential
    [string]$ServiceAccount = "NT AUTHORITY\LOCAL SERVICE",
    [pscredential]$ServiceCredential,
    [string]$AdminPrincipal = "BUILTIN\Administrators",
    [switch]$NoEngine,
    [string]$GatewaySdkLock,
    [string]$GatewaySdkLockSha256,
    [string]$PipConfig,
    [string]$OwnerDatabaseUrlFile,
    [switch]$SeparateScheduler,
    [switch]$NoTasks,
    [switch]$NoStart,
    [string]$Source                  # the release folder; default: two levels above this script
)
$ErrorActionPreference = "Stop"
# Windows PowerShell 5.1 does not set $PSScriptRoot while it evaluates parameter defaults
if (-not $Source) { $Source = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
. (Join-Path $PSScriptRoot "common.ps1")
function Step([string]$Text) { Write-Host "==> $Text" }

if (-not $NoTasks -and -not (Test-Elevated)) { throw "Run install.ps1 from an elevated PowerShell (or pass -NoTasks)." }
$L = Get-CyberDomeLayout -InstallDir $InstallDir -DataDir $DataDir
$adminSid = Resolve-AccountSid $AdminPrincipal
$svcSid = Resolve-AccountSid $ServiceAccount

# 1. the interpreter --------------------------------------------------------------------------------------------
Step "Checking Python"
if (-not (Test-Path -LiteralPath $Python)) { throw "Python not found: $Python" }
$info = & $Python -c "import struct, sys; print('%d.%d.%d %d' % (sys.version_info[:3] + (struct.calcsize('P') * 8,)))"
if ($LASTEXITCODE -ne 0 -or -not $info) { throw "$Python did not run" }
$ver, $bits = "$info".Trim().Split(" ")
$mm = [version]($ver.Split(".")[0..1] -join ".")
if ($bits -ne "64") { throw "Python $ver is $bits-bit: install the 64-bit (x86-64) build" }
if ($mm -lt [version]"3.11" -or $mm -gt [version]"3.13") { throw "Python $ver is not supported: use 3.11 to 3.13 (3.13 recommended)" }
$pyFull = (Resolve-Path -LiteralPath $Python).Path
if (-not $NoTasks -and $pyFull -like "$env:SystemDrive\Users\*") {
    throw "Python $pyFull is installed for one user; the service account cannot run it. Install Python for all users."
}
Write-Host "    Python $ver (64-bit)"

# 2. the code ---------------------------------------------------------------------------------------------------
Step "Copying the release to $($L.App)"
New-Item -ItemType Directory -Force -Path $L.App | Out-Null
$robocopy = Join-Path $env:SystemRoot "System32\robocopy.exe"
$exclude = @("/XD", "__pycache__", ".pytest_cache", "node_modules", "/XF", "*.pyc")
foreach ($d in @("soc_platform", "config", "scripts", "artifacts", "requirements", "deploy\windows")) {
    Invoke-Checked $robocopy (@((Join-Path $Source $d), (Join-Path $L.App $d), "/MIR", "/NFL", "/NDL", "/NJH", "/NJS", "/NP") + $exclude) -OkCodes @(0, 1, 2, 3)
}
foreach ($f in @("pyproject.toml", "README.md")) { Copy-Item -LiteralPath (Join-Path $Source $f) -Destination $L.App -Force }

Step "Creating the Python environment"
$cfg = Join-Path $L.Venv "pyvenv.cfg"
if (Test-Path -LiteralPath $cfg) {
    $home_ = (Get-Content -LiteralPath $cfg | Where-Object { $_ -like "home*=*" }) -replace '^home\s*=\s*', ''
    if ($home_.Trim().TrimEnd("\") -ne (Split-Path $pyFull -Parent).TrimEnd("\")) {
        Write-Host "    the interpreter changed: recreating the environment"
        Remove-Item -LiteralPath $L.Venv -Recurse -Force
    }
}
if (-not (Test-Path -LiteralPath $L.Python)) { Invoke-Checked $pyFull @("-m", "venv", $L.Venv) }

$lockName = "windows-engine.lock"
if ($NoEngine) { $lockName = "windows.lock" }
$lock = Join-Path $L.App "requirements\$lockName"
Step "Installing packages from $lockName (hash-checked)"
Invoke-Checked $L.Python @("-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--require-hashes", "--no-deps", "-q", "-r", $lock)
# the platform itself runs from InstallDir\app (it reads its static files, fixtures and models there), like the
# image's editable install - without build tools in the runtime environment
$site = & $L.Python -c "import sysconfig; print(sysconfig.get_paths()['purelib'])"
Write-SecretFile -Path (Join-Path "$site".Trim() "cyberdome.pth") -Value $L.App

if ($GatewaySdkLock) {
    Step "Adding the in-house LLM gateway SDK (hash-checked)"
    if (-not $GatewaySdkLockSha256) { throw "-GatewaySdkLock needs -GatewaySdkLockSha256 (the lock file's SHA-256)" }
    $actual = (Get-FileHash -LiteralPath $GatewaySdkLock -Algorithm SHA256).Hash
    if ($actual -ne $GatewaySdkLockSha256.ToUpperInvariant()) { throw "the gateway SDK lock's SHA-256 does not match -GatewaySdkLockSha256" }
    $old = $env:PIP_CONFIG_FILE
    try {
        if ($PipConfig) { $env:PIP_CONFIG_FILE = $PipConfig }
        Invoke-Checked $L.Python @("-m", "pip", "install", "--disable-pip-version-check", "--no-input", "--require-hashes", "-q", "-r", $GatewaySdkLock)
    } finally { $env:PIP_CONFIG_FILE = $old }
}

# 4. data, settings, secrets, permissions -----------------------------------------------------------------------
Step "Preparing $($L.DataDir)"
Set-FolderAccess -Path $L.InstallDir -AdminSid $adminSid -ServiceSid $svcSid -Right "RX"
Set-FolderAccess -Path $L.DataDir -AdminSid $adminSid -ServiceSid $svcSid -Right "RX"
foreach ($d in @($L.Config, $L.Secrets, $L.Certs)) { Set-FolderAccess -Path $d -AdminSid $adminSid -ServiceSid $svcSid -Right "R" }
foreach ($d in @($L.Data, $L.Logs, $L.Run)) { Set-FolderAccess -Path $d -AdminSid $adminSid -ServiceSid $svcSid -Right "M" }
foreach ($d in @($L.Admin, $L.Backups)) { Set-FolderAccess -Path $d -AdminSid $adminSid }
foreach ($d in @((Join-Path $L.Data "raw"), (Join-Path $L.Data "reports"))) { New-Item -ItemType Directory -Force -Path $d | Out-Null }

if (-not (Test-Path -LiteralPath $L.Settings)) {
    Copy-Item -LiteralPath (Join-Path $L.App "deploy\windows\cyberdome.env.example") -Destination $L.Settings
    Write-Host "    settings file created from the template: edit $($L.Settings)"
}
foreach ($f in @("connectors.yaml", "suppliers.yaml")) {
    $target = Join-Path $L.Config $f
    if (-not (Test-Path -LiteralPath $target)) { Copy-Item -LiteralPath (Join-Path $L.App "config\$f") -Destination $target }
}
$keyFile = Join-Path $L.Secrets "data_key"
if (-not (Test-Path -LiteralPath $keyFile)) {
    Invoke-Checked $L.Python @("-c", "import sys; from cryptography.fernet import Fernet; open(sys.argv[1], 'wb').write(Fernet.generate_key())", $keyFile)
    Write-Host "    new data-encryption key written to $keyFile (back it up with the database: without it stored data cannot be read)"
}

# 5. schema ------------------------------------------------------------------------------------------------------
if ($OwnerDatabaseUrlFile) {
    Step "Creating / extending the database schema as its owner"
    Invoke-SchemaInit -Layout $L -OwnerDatabaseUrlFile $OwnerDatabaseUrlFile
}

# 6. scheduled tasks ---------------------------------------------------------------------------------------------
if ($NoTasks) { Write-Host "Installed (no scheduled tasks: -NoTasks)."; exit 0 }
Step "Registering the scheduled tasks under $script:TaskPath"
$runPs1 = Join-Path $L.App "deploy\windows\run.ps1"
$roles = @("api")
if ($SeparateScheduler) { $roles += "scheduler" }
$settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 `
    -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -MultipleInstances IgnoreNew
$trigger = New-ScheduledTaskTrigger -AtStartup
foreach ($role in @("api", "scheduler")) {
    $existing = Get-ScheduledTask -TaskPath $script:TaskPath -TaskName $script:Roles[$role] -ErrorAction SilentlyContinue
    if ($existing) { Unregister-ScheduledTask -TaskPath $script:TaskPath -TaskName $script:Roles[$role] -Confirm:$false }
}
foreach ($role in $roles) {
    $argList = @("-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-File", $runPs1, "-Role", $role,
                 "-InstallDir", $L.InstallDir, "-DataDir", $L.DataDir)
    if ($role -eq "api" -and $SeparateScheduler) { $argList += "-SeparateScheduler" }
    $action = New-ScheduledTaskAction -Execute (Join-Path $PSHOME "powershell.exe") -Argument (ConvertTo-ArgumentString $argList) -WorkingDirectory $L.App
    $name = $script:Roles[$role]
    $desc = "CyberDome $role (deploy\windows\run.ps1): restarts the process if it stops"
    if ($svcSid -in @("S-1-5-19", "S-1-5-20")) {
        $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType ServiceAccount -RunLevel Limited
        Register-ScheduledTask -TaskPath $script:TaskPath -TaskName $name -Description $desc -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
    } elseif ($ServiceAccount.EndsWith('$')) {
        $principal = New-ScheduledTaskPrincipal -UserId $ServiceAccount -LogonType Password -RunLevel Limited
        Register-ScheduledTask -TaskPath $script:TaskPath -TaskName $name -Description $desc -Action $action -Trigger $trigger -Settings $settings -Principal $principal | Out-Null
    } else {
        if (-not $ServiceCredential) { throw "-ServiceAccount $ServiceAccount is a user account: pass -ServiceCredential" }
        Register-ScheduledTask -TaskPath $script:TaskPath -TaskName $name -Description $desc -Action $action -Trigger $trigger -Settings $settings `
            -User $ServiceCredential.UserName -Password $ServiceCredential.GetNetworkCredential().Password -RunLevel Limited | Out-Null
    }
    Write-Host "    $script:TaskPath$name as $ServiceAccount"
}

Step "Checking the configuration"
& (Join-Path $PSHOME "powershell.exe") -NoProfile -ExecutionPolicy Bypass -File $runPs1 -Role api -InstallDir $L.InstallDir -DataDir $L.DataDir -CheckOnly
if ($LASTEXITCODE -ne 0) {
    Write-Warning "The configuration has errors (listed above, each with its fix). Edit $($L.Settings), then run: .\deploy\windows\cyberdome.ps1 check; .\deploy\windows\cyberdome.ps1 start"
    exit 1
}
if (-not $NoStart) {
    foreach ($role in $roles) { Start-ScheduledTask -TaskPath $script:TaskPath -TaskName $script:Roles[$role] }
    Write-Host "Started. Status: .\deploy\windows\cyberdome.ps1 status"
}
