# Load a .env file into the CURRENT PowerShell session (the platform reads settings from the environment only).
#   . .\scripts\load_env.ps1              # loads .\.env
#   . .\scripts\load_env.ps1 other.env    # loads another file
# Note the leading dot: without it the variables vanish when the script ends.
# Blank lines and comments are skipped, inline "  # comment" text is removed, surrounding quotes are stripped.
# Values are never printed - only the names that were set.
param([string]$Path = ".env")

if (-not (Test-Path $Path)) { Write-Error "No $Path file here. Copy .env.example to .env and fill it in."; return }
$names = @()
foreach ($line in Get-Content $Path) {
    $t = $line.Trim()
    if ($t -eq "" -or $t.StartsWith("#") -or -not $t.Contains("=")) { continue }
    $k, $v = $t -split "=", 2
    $k = $k.Trim()
    $v = ($v -replace "\s+#.*$", "").Trim().Trim('"').Trim("'")
    if ($v -eq "") { continue }                      # an empty value means "use the default"
    [Environment]::SetEnvironmentVariable($k, $v, "Process")
    $names += $k
}
Write-Host ("Loaded {0} setting(s): {1}" -f $names.Count, ($names -join ", "))
