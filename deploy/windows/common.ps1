# Shared by install.ps1, run.ps1, cyberdome.ps1, setup_postgres.ps1 and backup.ps1 (dot-sourced). PowerShell 5.1.
# Nothing here prints a setting's value: settings files hold connection strings and, by mistake, sometimes secrets.

$script:TaskPath = "\CyberDome\"
$script:Roles = @{ api = "API"; scheduler = "Scheduler" }

function Get-CyberDomeLayout {
    # Every folder the platform uses on a Windows host, from the two roots the installer was given.
    param([Parameter(Mandatory = $true)][string]$InstallDir, [Parameter(Mandatory = $true)][string]$DataDir)
    [pscustomobject]@{
        InstallDir = $InstallDir
        App        = Join-Path $InstallDir "app"
        Venv       = Join-Path $InstallDir "venv"
        Python     = Join-Path $InstallDir "venv\Scripts\python.exe"
        DataDir    = $DataDir
        Config     = Join-Path $DataDir "config"
        Settings   = Join-Path $DataDir "config\cyberdome.env"
        Secrets    = Join-Path $DataDir "secrets"     # read by the service account
        Admin      = Join-Path $DataDir "admin"       # administrators only (schema owner connection)
        Certs      = Join-Path $DataDir "certs"
        Data       = Join-Path $DataDir "data"
        Logs       = Join-Path $DataDir "logs"
        Run        = Join-Path $DataDir "run"
        Backups    = Join-Path $DataDir "backups"
    }
}

function Import-CyberDomeSettings {
    # Load NAME=value lines into this process's environment (the platform reads settings only from the
    # environment). Same rules as scripts/load_env.ps1: blank lines and comments skipped, an inline "  # comment"
    # removed, surrounding quotes stripped, an empty value means "use the default". Returns the names set.
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) { throw "Settings file not found: $Path" }
    $names = @()
    $n = 0
    foreach ($line in Get-Content -LiteralPath $Path -Encoding UTF8) {
        $n++
        $t = $line.Trim()
        if ($t -eq "" -or $t.StartsWith("#")) { continue }
        $i = $t.IndexOf("=")
        if ($i -lt 1) { throw "Settings file ${Path}, line ${n}: expected NAME=value" }
        $k = $t.Substring(0, $i).Trim()
        if ($k -notmatch '^[A-Za-z_][A-Za-z0-9_]*$') { throw "Settings file ${Path}, line ${n}: '$k' is not a setting name" }
        $v = ($t.Substring($i + 1) -replace '\s+#.*$', "").Trim()
        if ($v.Length -ge 2 -and (($v.StartsWith('"') -and $v.EndsWith('"')) -or ($v.StartsWith("'") -and $v.EndsWith("'")))) {
            $v = $v.Substring(1, $v.Length - 2)
        }
        if ($v -eq "") { continue }
        [Environment]::SetEnvironmentVariable($k, $v, "Process")
        $names += $k
    }
    return , $names
}

function Set-DefaultSetting {
    # Set a setting only when the settings file did not.
    param([string]$Name, [string]$Value)
    if (-not [Environment]::GetEnvironmentVariable($Name, "Process")) {
        [Environment]::SetEnvironmentVariable($Name, $Value, "Process")
    }
}

function ConvertTo-ArgumentString {
    # One command line for Start-Process: arguments with spaces or quotes are quoted (Windows C runtime rules).
    param([string[]]$Arguments)
    $parts = foreach ($a in $Arguments) {
        if ($a -eq "") { '""' }
        elseif ($a -notmatch '[\s"]') { $a }
        else {
            $escaped = $a -replace '(\\*)"', '$1$1\"'
            $escaped = $escaped -replace '(\\+)$', '$1$1'
            '"' + $escaped + '"'
        }
    }
    return ($parts -join " ")
}

function Invoke-Checked {
    # Run a native program; throw with its name when it fails (PowerShell 5.1 does not stop on a native exit code).
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$Arguments = @(), [int[]]$OkCodes = @(0))
    & $FilePath @Arguments
    if ($OkCodes -notcontains $LASTEXITCODE) { throw "$([IO.Path]::GetFileName($FilePath)) failed (exit $LASTEXITCODE)" }
}

function Invoke-Starter {
    # Run a program that starts a long-lived child (pg_ctl start / restart) and wait for that program only. Piping its
    # output would wait for ever: the server it starts inherits the pipe and keeps it open.
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$Arguments = @(), [int]$TimeoutSeconds = 180)
    $log = [IO.Path]::GetTempFileName()
    try {
        $p = Start-Process -FilePath $FilePath -ArgumentList (ConvertTo-ArgumentString $Arguments) -NoNewWindow -PassThru `
            -RedirectStandardOutput $log -RedirectStandardError "$log.err"
        $null = $p.Handle
        if (-not $p.WaitForExit($TimeoutSeconds * 1000)) { throw "$([IO.Path]::GetFileName($FilePath)) did not finish in $TimeoutSeconds s" }
        if ($p.ExitCode -ne 0) {
            $detail = (Get-Content -LiteralPath "$log.err" -ErrorAction SilentlyContinue | Select-Object -First 5) -join " "
            throw "$([IO.Path]::GetFileName($FilePath)) failed (exit $($p.ExitCode)): $detail"
        }
    } finally {
        Remove-Item -LiteralPath $log, "$log.err" -Force -ErrorAction SilentlyContinue
    }
}

function Resolve-AccountSid {
    param([Parameter(Mandatory = $true)][string]$Account)
    if ($Account -match '^S-1-') { return $Account }
    return (New-Object System.Security.Principal.NTAccount($Account)).Translate([System.Security.Principal.SecurityIdentifier]).Value
}

function Set-FolderAccess {
    # Replace a folder's permissions: inheritance from the parent removed, full control for the administrators
    # principal and SYSTEM, and the given right for the service account (R read, RX read+run, M modify).
    # Child items inherit, so files the platform writes later get the same protection (os.chmod is a no-op on NTFS).
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$AdminSid,
          [string]$ServiceSid, [ValidateSet("R", "RX", "M", "")][string]$Right = "")
    New-Item -ItemType Directory -Force -Path $Path | Out-Null
    # an account that is also the administrators principal keeps full control (a grant would replace it)
    if ($ServiceSid -eq $AdminSid -or $ServiceSid -eq "S-1-5-18") { $ServiceSid = $null }
    $grants = @("*${AdminSid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
    if ($ServiceSid -and $Right) { $grants += "*${ServiceSid}:(OI)(CI)$Right" }
    $icacls = Join-Path $env:SystemRoot "System32\icacls.exe"
    $icArgs = @($Path, "/inheritance:r", "/Q")
    foreach ($g in $grants) { $icArgs += @("/grant:r", $g) }
    & $icacls @icArgs | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls could not set the permissions of $Path (exit $LASTEXITCODE)" }
    # drop explicit entries of anyone else (for example the creator of an existing folder)
    $keep = @($AdminSid, "S-1-5-18") + @($ServiceSid | Where-Object { $_ -and $Right })
    $acl = Get-Acl -LiteralPath $Path
    foreach ($rule in @($acl.Access)) {
        if ($rule.IsInherited) { continue }
        $sid = $rule.IdentityReference.Translate([System.Security.Principal.SecurityIdentifier]).Value
        if ($keep -notcontains $sid) {
            & $icacls $Path /remove:g "*$sid" /Q | Out-Null
        }
    }
}

function Test-Elevated {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function New-RandomSecret {
    # URL-safe random text (letters and digits only, so it needs no quoting in a URL or in SQL).
    param([int]$Length = 40)
    $alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"
    $rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
    $bytes = New-Object byte[] ($Length * 2)
    $rng.GetBytes($bytes)
    $out = New-Object System.Text.StringBuilder
    foreach ($b in $bytes) {
        if ($b -lt (256 - (256 % $alphabet.Length))) { [void]$out.Append($alphabet[$b % $alphabet.Length]) }
        if ($out.Length -ge $Length) { break }
    }
    if ($out.Length -lt $Length) { return New-RandomSecret -Length $Length }
    return $out.ToString()
}

function Invoke-SchemaInit {
    # "python -m soc_platform init-db" as the schema owner: creates / extends the tables and grants the runtime role
    # (SOC_DB_RUNTIME_ROLE from the settings file). The owner connection comes from a file only administrators can
    # read; the process environment is restored afterwards.
    param([Parameter(Mandatory = $true)]$Layout, [Parameter(Mandatory = $true)][string]$OwnerDatabaseUrlFile)
    $names = @("SOC_DATABASE_URL", "SOC_DATABASE_URL_FILE", "SOC_SCHEMA_MANAGE", "SOC_DATA_KEY_FILE")
    $saved = @{}
    foreach ($n in $names) { $saved[$n] = [Environment]::GetEnvironmentVariable($n, "Process") }
    try {
        $null = Import-CyberDomeSettings -Path $Layout.Settings
        [Environment]::SetEnvironmentVariable("SOC_DATABASE_URL", $null, "Process")
        $env:SOC_DATABASE_URL_FILE = (Resolve-Path -LiteralPath $OwnerDatabaseUrlFile).Path
        $env:SOC_SCHEMA_MANAGE = "1"
        $key = Join-Path $Layout.Secrets "data_key"
        if (-not $env:SOC_DATA_KEY -and -not $env:SOC_DATA_KEY_FILE -and (Test-Path -LiteralPath $key)) { $env:SOC_DATA_KEY_FILE = $key }
        Push-Location $Layout.App
        try { Invoke-Checked $Layout.Python @("-m", "soc_platform", "init-db") } finally { Pop-Location }
    } finally {
        foreach ($n in $names) { [Environment]::SetEnvironmentVariable($n, $saved[$n], "Process") }
    }
}

function Write-SecretFile {
    # Write a secret without a trailing newline (the platform strips it anyway) and without echoing it.
    param([Parameter(Mandatory = $true)][string]$Path, [Parameter(Mandatory = $true)][string]$Value)
    [IO.File]::WriteAllText($Path, $Value, (New-Object System.Text.UTF8Encoding($false)))
}
