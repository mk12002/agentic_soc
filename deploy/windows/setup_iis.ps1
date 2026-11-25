<#
.SYNOPSIS
  Puts IIS in front of CyberDome on the same Windows host: an HTTPS site that passes every request to the platform on
  127.0.0.1:8080. Run from an elevated PowerShell after installing IIS, URL Rewrite and Application Request Routing.

.DESCRIPTION
  - Enables ARR's proxy server-wide (preserving the Host header, 300 s timeout: report building and model calls can
    take longer than ARR's 30 s default; no response caching).
  - Creates the site (default "CyberDome") with its own folder holding deploy\windows\iis\web.config, bound to
    HTTPS on -Port with the certificate whose thumbprint is given (LocalMachine\My), and requires SNI if -HostName.
  - HTTP is not bound: there is nothing to redirect (add a redirect site only if the organisation needs one).
  The certificate comes from the organisation's PKI; its private key stays in the machine store.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$CertificateThumbprint,
    [string]$HostName = "",
    [int]$Port = 443,
    [string]$SiteName = "CyberDome",
    [string]$SiteDir = (Join-Path $env:SystemDrive "inetpub\cyberdome"),
    [int]$ProxyTimeoutSeconds = 300
)
$ErrorActionPreference = "Stop"
. (Join-Path $PSScriptRoot "common.ps1")
if (-not (Test-Elevated)) { throw "Run setup_iis.ps1 from an elevated PowerShell." }
$appcmd = Join-Path $env:SystemRoot "System32\inetsrv\appcmd.exe"
if (-not (Test-Path -LiteralPath $appcmd)) { throw "IIS is not installed (no appcmd.exe)." }
$modules = (& $appcmd list modules) -join "`n"
if ($modules -notmatch "RewriteModule") { throw "The IIS URL Rewrite module is not installed." }
if ($modules -notmatch "ApplicationRequestRouting") { throw "IIS Application Request Routing (ARR) is not installed." }
$thumb = $CertificateThumbprint -replace '\s', ''
if (-not (Get-Item -LiteralPath "Cert:\LocalMachine\My\$thumb" -ErrorAction SilentlyContinue)) {
    throw "No certificate $thumb in LocalMachine\My"
}

Write-Host "==> ARR proxy"
$timeout = [TimeSpan]::FromSeconds($ProxyTimeoutSeconds).ToString()
Invoke-Checked $appcmd @("set", "config", "-section:system.webServer/proxy", "/enabled:True", "/preserveHostHeader:True",
    "/reverseRewriteHostInResponseHeaders:False", "/timeout:$timeout", "/commit:apphost")
Invoke-Checked $appcmd @("set", "config", "-section:system.webServer/proxy", "/cache.enabled:False", "/commit:apphost")

Write-Host "==> Site $SiteName"
New-Item -ItemType Directory -Force -Path $SiteDir | Out-Null
Copy-Item -LiteralPath (Join-Path $PSScriptRoot "iis\web.config") -Destination (Join-Path $SiteDir "web.config") -Force
Import-Module WebAdministration
if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) { Remove-Website -Name $SiteName }
$sslFlags = 0
if ($HostName) { $sslFlags = 1 }
New-Website -Name $SiteName -PhysicalPath $SiteDir -Port $Port -HostHeader $HostName -Ssl -SslFlags $sslFlags | Out-Null
$binding = Get-WebBinding -Name $SiteName -Protocol https
$binding.AddSslCertificate($thumb, "My")
Write-Host "Done: https://$(if ($HostName) { $HostName } else { 'localhost' }):$Port -> http://127.0.0.1:8080"
