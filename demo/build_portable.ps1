param(
    [string]$ExeName = "archipel"
)

$ErrorActionPreference = "Stop"

Write-Host "[build] Installing PyInstaller if needed..."
python -m pip install --disable-pip-version-check -q pyinstaller

Write-Host "[build] Building single-file executable..."
pyinstaller --onefile main.py --name $ExeName

if (!(Test-Path "dist\\$ExeName.exe")) {
    throw "Executable not found: dist\\$ExeName.exe"
}

Write-Host "[ok] Built: dist\\$ExeName.exe"
Write-Host "[next] Copy this file to machine B and run commands there."

