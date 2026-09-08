# Universal installer for secfoo (Windows). Usage:
#   irm https://raw.githubusercontent.com/rakfortltd/secfoo/main/install.ps1 | iex
#
# Downloads the latest secfoo-win32-x64.exe from GitHub Releases, verifies
# its checksum, and installs it to $env:LOCALAPPDATA\secfoo\secfoo.exe,
# adding that directory to the user PATH if it isn't there already.

$ErrorActionPreference = "Stop"

$Repo = "rakfortltd/secfoo"
$InstallDir = Join-Path $env:LOCALAPPDATA "secfoo"
$Asset = "secfoo-win32-x64.exe"

Write-Host "Fetching latest release info..."
$Release = Invoke-RestMethod -Uri "https://api.github.com/repos/$Repo/releases/latest"
$Tag = $Release.tag_name
if (-not $Tag) {
    Write-Error "Could not determine the latest release tag from the GitHub API"
    exit 1
}
Write-Host "Latest release: $Tag"

$BaseUrl = "https://github.com/$Repo/releases/download/$Tag"
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ([System.Guid]::NewGuid())
New-Item -ItemType Directory -Path $TmpDir | Out-Null

try {
    $ExePath = Join-Path $TmpDir $Asset
    $SumsPath = Join-Path $TmpDir "SHA256SUMS"

    Invoke-WebRequest -Uri "$BaseUrl/$Asset" -OutFile $ExePath
    Invoke-WebRequest -Uri "$BaseUrl/SHA256SUMS" -OutFile $SumsPath

    Write-Host "Verifying checksum..."
    $ExpectedLine = Select-String -Path $SumsPath -Pattern " $Asset$" | Select-Object -First 1
    if (-not $ExpectedLine) {
        Write-Error "No checksum entry found for $Asset in SHA256SUMS"
        exit 1
    }
    $Expected = ($ExpectedLine -split "\s+")[0]
    $Actual = (Get-FileHash -Path $ExePath -Algorithm SHA256).Hash.ToLower()
    if ($Expected -ne $Actual) {
        Write-Error "Checksum mismatch for $Asset (expected $Expected, got $Actual) -- aborting install"
        exit 1
    }
    Write-Host "Checksum OK."

    New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
    Move-Item -Path $ExePath -Destination (Join-Path $InstallDir "secfoo.exe") -Force

    Write-Host "Installed secfoo $Tag to $InstallDir\secfoo.exe"

    $UserPath = [Environment]::GetEnvironmentVariable("Path", "User")
    if ($UserPath -notlike "*$InstallDir*") {
        [Environment]::SetEnvironmentVariable("Path", "$UserPath;$InstallDir", "User")
        Write-Host "Added $InstallDir to your user PATH. Restart your terminal for it to take effect."
    }
}
finally {
    Remove-Item -Recurse -Force $TmpDir -ErrorAction SilentlyContinue
}
