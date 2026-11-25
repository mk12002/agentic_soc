<#
.SYNOPSIS
  Removes CyberDome's scheduled tasks and, with -RemoveProgram, InstallDir. Data is kept unless -RemoveData is given
  (DataDir holds the settings, the data-encryption key and stored files: without the key the database's protected
  columns cannot be read). The database itself is never touched.
#>
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = "High")]
param(
    [string]$InstallDir = (Join-Path $env:ProgramFiles "CyberDome"),
    [string]$DataDir = (Join-Path $env:ProgramData "CyberDome"),
    [switch]$RemoveProgram,
    [switch]$RemoveData
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
if (-not (Test-Elevated)) { throw "Run uninstall.ps1 from an elevated PowerShell." }

$registered = @(foreach ($n in $script:Roles.Values) { Get-ScheduledTask -TaskPath $script:TaskPath -TaskName $n -ErrorAction SilentlyContinue })
if ($registered) {
    & (Join-Path $PSScriptRoot "cyberdome.ps1") stop -InstallDir $InstallDir -DataDir $DataDir
    foreach ($t in $registered) {
        Unregister-ScheduledTask -TaskPath $script:TaskPath -TaskName $t.TaskName -Confirm:$false
        Write-Host "removed task $script:TaskPath$($t.TaskName)"
    }
}
if ($RemoveProgram -and (Test-Path -LiteralPath $InstallDir) -and $PSCmdlet.ShouldProcess($InstallDir, "delete the program folder")) {
    Remove-Item -LiteralPath $InstallDir -Recurse -Force
    Write-Host "removed $InstallDir"
}
if ($RemoveData -and (Test-Path -LiteralPath $DataDir) -and $PSCmdlet.ShouldProcess($DataDir, "delete settings, secrets and stored files")) {
    Remove-Item -LiteralPath $DataDir -Recurse -Force
    Write-Host "removed $DataDir"
}
