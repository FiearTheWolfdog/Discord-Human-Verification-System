param(
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$projectRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $projectRoot

if ($Clean) {
    Write-Host "Cleaning dist/ and build/ folders..."
    Remove-Item -Path (Join-Path $projectRoot "dist") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $projectRoot "build") -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path (Join-Path $projectRoot "DiscordHVS.spec") -Force -ErrorAction SilentlyContinue
}

$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    $python = "python"
}

Write-Host "Ensuring PyInstaller is available..."
& $python -m pip install --upgrade pyinstaller | Out-Null

$pyinstallerArgs = @(
    "--onefile",
    "--windowed",
    "--name", "DiscordHVS",
    "--log-level", "WARN",
    "main.py"
)

Write-Host "Building one-file executable..."
& $python -m PyInstaller @pyinstallerArgs

Write-Host "Build complete. Executable is located in: " (Join-Path $projectRoot "dist")

$sourceExe = Join-Path $projectRoot "dist/DiscordHVS.exe"
if (Test-Path $sourceExe) {
    $targetExe = Join-Path $projectRoot "DiscordHVS.exe"
    Copy-Item -Path $sourceExe -Destination $targetExe -Force
    Write-Host "Copied executable to" $targetExe
} else {
    Write-Warning "Expected executable not found at $sourceExe"
}
