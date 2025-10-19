<#
.SYNOPSIS
    Initial setup for AutoSecureChain
.DESCRIPTION
    Creates virtual environment, installs dependencies, and configures key paths
#>
param(
    [switch]$SkipKeySetup
)

Write-Host "AutoSecureChain Setup" -ForegroundColor Cyan
Write-Host "=====================" -ForegroundColor Cyan

# Create venv
if (-not (Test-Path "venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Yellow
    python -m venv venv
}

# Activate and install
Write-Host "Installing dependencies..." -ForegroundColor Yellow
& .\venv\Scripts\Activate.ps1
python -m pip install --upgrade pip -q
pip install -r requirements.txt

# Key setup
if (-not $SkipKeySetup) {
    $secureDir = Join-Path $env:USERPROFILE ".autosecurechain"
    try {
        if (-not (Test-Path $secureDir)) {
            New-Item -ItemType Directory -Path $secureDir -Force -ErrorAction Stop | Out-Null
            Write-Host "Created secure key directory" -ForegroundColor Green
        }
    } catch {
        Write-Host "Could not create $secureDir (using workspace .keys)" -ForegroundColor Yellow
        $secureDir = Join-Path (Get-Location) ".keys"
        New-Item -ItemType Directory -Path $secureDir -Force | Out-Null
    }

    Write-Host ""
    Write-Host "Key Configuration:" -ForegroundColor Cyan
    Write-Host "  Public key location: $secureDir\public_key.pem" -ForegroundColor Gray

    $oldKeyPath = "AutoSecureChain\scanner\public_key.pem"
    if (Test-Path $oldKeyPath) {
        try {
            Write-Host "  Moving public_key.pem to secure location..." -ForegroundColor Yellow
            Copy-Item -Path $oldKeyPath -Destination "$secureDir\public_key.pem" -Force
            Remove-Item -Path $oldKeyPath -Force
        } catch {
            Write-Host "  Could not move key file (will use workspace location)" -ForegroundColor Yellow
        }
    }

    Write-Host "  Setting environment variable..." -ForegroundColor Yellow
    try {
        [System.Environment]::SetEnvironmentVariable("AUTOS_PUBLIC_KEY", "$secureDir\public_key.pem", "User")
        $env:AUTOS_PUBLIC_KEY = "$secureDir\public_key.pem"
        Write-Host "  AUTOS_PUBLIC_KEY = $secureDir\public_key.pem" -ForegroundColor Green
    } catch {
        Write-Host "  Could not set persistent env var (set manually if needed)" -ForegroundColor Yellow
    }
}

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Place firmware files in .\firmware\" -ForegroundColor Gray
Write-Host "  2. Run: .\run-scanner.ps1" -ForegroundColor Gray
