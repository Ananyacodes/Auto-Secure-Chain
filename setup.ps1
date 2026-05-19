<#
.SYNOPSIS
    Initial setup for AutoSecureChain
.DESCRIPTION
    Creates virtual environment, installs dependencies, and configures key paths
#>
param(
    [switch]$SkipKeySetup,
    [switch]$GenerateSampleKeypair
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

    try {
        [System.Environment]::SetEnvironmentVariable("AUTOS_KEY_DIR", $secureDir, "User")
        $env:AUTOS_KEY_DIR = $secureDir
        Write-Host "  AUTOS_KEY_DIR = $secureDir" -ForegroundColor Green
    } catch {
        Write-Host "  Could not set persistent key dir env var (set manually if needed)" -ForegroundColor Yellow
    }

    if ($GenerateSampleKeypair) {
        $keyManagerScript = Join-Path (Get-Location) "key-manager.ps1"
        if (Test-Path $keyManagerScript) {
            Write-Host "  Generating a sample production keypair for local testing..." -ForegroundColor Yellow
            # Offer optional encryption and keyring storage
            $encryptAnswer = Read-Host "  Encrypt private key? (y/N)"
            $passphrase = $null
            $useKeyring = $false
            if ($encryptAnswer -and $encryptAnswer.ToLower().StartsWith('y')) {
                $secure = Read-Host -AsSecureString "  Enter passphrase to encrypt private key"
                $confirm = Read-Host -AsSecureString "  Confirm passphrase"
                $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
                $plain = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr)
                $bstr2 = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm)
                $plain2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr2)
                [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr2)
                if ($plain -ne $plain2) {
                    Write-Host "  Passphrases did not match; aborting sample key generation." -ForegroundColor Red
                } else {
                    $passphrase = $plain
                    $krAnswer = Read-Host "  Store passphrase in OS keyring? (y/N)"
                    if ($krAnswer -and $krAnswer.ToLower().StartsWith('y')) { $useKeyring = $true }
                }
            }

            $args = @("-Command", "generate", "-Name", "production", "-KeySize", "2048")
            if ($passphrase) { $args += @("-Passphrase", $passphrase) }
            if ($useKeyring) { $args += "-UseKeyring" }

            & $keyManagerScript @args
            Write-Host "  Sample keypair generated. Review files under $secureDir before using in production." -ForegroundColor Gray
        } else {
            Write-Host "  key-manager.ps1 not found; skipping sample key generation" -ForegroundColor Yellow
        }
    }
}

Write-Host ""
Write-Host "Setup complete." -ForegroundColor Green
Write-Host ""
Write-Host "Next steps:" -ForegroundColor Cyan
Write-Host "  1. Place firmware files in .\firmware\" -ForegroundColor Gray
Write-Host "  2. Run: .\run-scanner.ps1" -ForegroundColor Gray
Write-Host "  3. Manage keys: .\run-scanner.ps1 -KeyCommand list" -ForegroundColor Gray
