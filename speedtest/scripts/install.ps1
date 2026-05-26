# mmwx-speedtester Windows install & run script
# Usage: .\install.ps1 -Master https://your-master-url -Token <token>
param(
    [Parameter(Mandatory=$true)][string]$Master,
    [Parameter(Mandatory=$true)][string]$Token
)

$ErrorActionPreference = "Stop"
$Repo = "MMWOrg/mmwX-plugins"
$BinaryName = "mmwx-speedtester"

# Detect architecture
$Arch = if ([Environment]::Is64BitOperatingSystem) {
    if ($env:PROCESSOR_ARCHITECTURE -eq "ARM64") { "arm64" } else { "amd64" }
} else {
    Write-Error "32-bit systems are not supported"; exit 1
}

$AssetName = "${BinaryName}-windows-${Arch}.exe"
Write-Host "Platform: windows/${Arch}"

# Get latest release
Write-Host "Fetching latest release..."
$ReleaseUrl = "https://api.github.com/repos/${Repo}/releases/latest"
$Release = Invoke-RestMethod -Uri $ReleaseUrl -Headers @{ "User-Agent" = "mmwx-installer" }
Write-Host "Latest version: $($Release.tag_name)"

$Asset = $Release.assets | Where-Object { $_.name -eq $AssetName } | Select-Object -First 1
if (-not $Asset) {
    Write-Error "Asset ${AssetName} not found. Visit https://github.com/${Repo}/releases/latest to download manually."
    exit 1
}

# Download
$OutputPath = Join-Path $PWD "${BinaryName}.exe"
Write-Host "Downloading ${AssetName}..."
Invoke-WebRequest -Uri $Asset.browser_download_url -OutFile $OutputPath
Write-Host "Saved to: ${OutputPath}"

# Run
Write-Host ""
Write-Host "========================================"
Write-Host "Master: ${Master}"
Write-Host "========================================"
Write-Host ""
& $OutputPath -master $Master -token $Token
