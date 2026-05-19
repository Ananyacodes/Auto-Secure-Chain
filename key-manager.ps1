# AutoSecureChain Key Management Script
# Provides PowerShell interface for secure key operations

param(
    [Parameter(Mandatory=$false)]
    [ValidateSet("generate", "sign", "verify", "rotate", "list", "info", "audit")]
    [string]$Command,

    [Parameter(Mandatory=$false)]
    [string]$Name = "production",

    [Parameter(Mandatory=$false)]
    [int]$KeySize = 4096,

    [Parameter(Mandatory=$false)]
    [string]$Firmware,

    [Parameter(Mandatory=$false)]
    [string]$Key,
    [Parameter(Mandatory=$false)]
    [string]$Passphrase,
    [Parameter(Mandatory=$false)]
    [switch]$UseKeyring,
    [Parameter(Mandatory=$false)]
    [ValidateSet("local","kms")]
    [string]$Backend = "local",
    [Parameter(Mandatory=$false)]
    [string]$KmsKeyId,

    [Parameter(Mandatory=$false)]
    [string]$OldKey,

    [Parameter(Mandatory=$false)]
    [string]$NewKey,

    [Parameter(Mandatory=$false)]
    [switch]$Json,

    [Parameter(Mandatory=$false)]
    [int]$Limit = 20,

    [Parameter(Mandatory=$false)]
    [string]$Type,

    [Parameter(Mandatory=$false)]
    [ValidateSet("info", "warning", "error")]
    [string]$Severity
)

$ErrorActionPreference = "Stop"

# Get the script directory and project root
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = $ScriptDir
$ScannerDir = Join-Path $ProjectRoot "AutoSecureChain\scanner"
$PythonExe = "python"

# Check if Python is available
try {
    & $PythonExe --version | Out-Null
} catch {
    Write-Error "Python is not available. Please ensure Python 3.8+ is installed and in PATH."
    exit 1
}

# Function to run key manager CLI
function Invoke-KeyManager {
    param([string[]]$CliArgs)

    $cliPath = Join-Path $ScannerDir "key_manager_cli.py"
    if (!(Test-Path $cliPath)) {
        Write-Error "Key manager CLI not found at: $cliPath"
        exit 1
    }

    try {
        & $PythonExe $cliPath @CliArgs
    } catch {
        Write-Error "Failed to execute key manager: $_"
        exit 1
    }
}

# Function to generate a new keypair
function New-KeyPair {
    param([string]$KeyName = "production", [int]$Size = 4096, [string]$Passphrase = $null, [switch]$UseKeyring)

    Write-Host "Generating new RSA keypair: $KeyName ($Size bits)" -ForegroundColor Cyan
    $args = @("generate", "--name", $KeyName, "--size", $Size.ToString())
    if ($Passphrase) { $args += @("--passphrase", $Passphrase) }
    if ($UseKeyring) { $args += "--use-keyring" }

    Invoke-KeyManager $args
}

# Function to sign firmware
function Sign-Firmware {
    param([string]$FirmwarePath, [string]$KeyName = "production", [string]$Passphrase = $null, [switch]$UseKeyring)

    if (!(Test-Path $FirmwarePath)) {
        Write-Error "Firmware file not found: $FirmwarePath"
        exit 1
    }

    Write-Host "Signing firmware: $FirmwarePath" -ForegroundColor Cyan
    $args = @("sign", $FirmwarePath, "--key", $KeyName)
    if ($Passphrase) { $args += @("--passphrase", $Passphrase) }
    if ($UseKeyring) { $args += "--use-keyring" }
    if ($PSBoundParameters.ContainsKey('Backend') -and $Backend) { $args += @("--backend", $Backend) }
    if ($PSBoundParameters.ContainsKey('KmsKeyId') -and $KmsKeyId) { $args += @("--kms-key-id", $KmsKeyId) }
    Invoke-KeyManager $args
}

# Function to verify firmware signature
function Test-FirmwareSignature {
    param([string]$FirmwarePath, [string]$KeyName = "production")

    if (!(Test-Path $FirmwarePath)) {
        Write-Error "Firmware file not found: $FirmwarePath"
        exit 1
    }

    Write-Host "Verifying firmware signature: $FirmwarePath" -ForegroundColor Cyan
    Invoke-KeyManager @("verify", $FirmwarePath, "--key", $KeyName)
}

# Function to rotate keys
function Update-KeyRotation {
    param([string]$OldKeyName, [string]$NewKeyName)

    Write-Host "Rotating key: $OldKeyName -> $NewKeyName" -ForegroundColor Cyan
    $args = @("rotate", $OldKeyName)
    if ($NewKeyName) {
        $args += @("--new-key", $NewKeyName)
    }
    Invoke-KeyManager $args
}

# Function to list keys
function Get-Keys {
    param([switch]$AsJson)

    Write-Host "Listing managed keys:" -ForegroundColor Cyan
    if ($AsJson) {
        Invoke-KeyManager @("list", "--json")
    } else {
        Invoke-KeyManager @("list")
    }
}

# Function to get key info
function Get-KeyInfo {
    param([string]$KeyName, [switch]$AsJson)

    Write-Host "Getting key information: $KeyName" -ForegroundColor Cyan
    if ($AsJson) {
        Invoke-KeyManager @("info", $KeyName, "--json")
    } else {
        Invoke-KeyManager @("info", $KeyName)
    }
}

# Function to show audit logs
function Get-AuditLogs {
    param([int]$LogLimit = 20, [switch]$AsJson)

    Write-Host "Showing recent audit events:" -ForegroundColor Cyan
    if ($AsJson) {
        Invoke-KeyManager @("audit", "recent", "--limit", $LogLimit.ToString(), "--json")
    } else {
        Invoke-KeyManager @("audit", "recent", "--limit", $LogLimit.ToString())
    }
}

# Function to search audit logs
function Search-AuditLogs {
    param([string]$EventType, [string]$LogSeverity, [int]$LogLimit = 50, [switch]$AsJson)

    Write-Host "Searching audit events:" -ForegroundColor Cyan
    $args = @("audit", "search", "--limit", $LogLimit.ToString())
    if ($EventType) { $args += @("--type", $EventType) }
    if ($LogSeverity) { $args += @("--severity", $LogSeverity) }
    if ($AsJson) { $args += "--json" }

    Invoke-KeyManager $args
}

# Main command processing
switch ($Command) {
    "generate" {
        New-KeyPair -KeyName $Name -Size $KeySize
    }
    "sign" {
        if (!$Firmware) {
            Write-Error "Firmware path is required for signing"
            exit 1
        }
        Sign-Firmware -FirmwarePath $Firmware -KeyName $Key
    }
    "verify" {
        if (!$Firmware) {
            Write-Error "Firmware path is required for verification"
            exit 1
        }
        Test-FirmwareSignature -FirmwarePath $Firmware -KeyName $Key
    }
    "rotate" {
        if (!$OldKey) {
            Write-Error "Old key name is required for rotation"
            exit 1
        }
        Update-KeyRotation -OldKeyName $OldKey -NewKeyName $NewKey
    }
    "list" {
        Get-Keys -AsJson:$Json
    }
    "info" {
        if (!$Name) {
            Write-Error "Key name is required for info command"
            exit 1
        }
        Get-KeyInfo -KeyName $Name -AsJson:$Json
    }
    "audit" {
        if ($Type -or $Severity) {
            Search-AuditLogs -EventType $Type -LogSeverity $Severity -LogLimit $Limit -AsJson:$Json
        } else {
            Get-AuditLogs -LogLimit $Limit -AsJson:$Json
        }
    }
    default {
        Write-Host "AutoSecureChain Key Management Tool" -ForegroundColor Green
        Write-Host ""
        Write-Host "USAGE: .\key-manager.ps1 -Command <command> [parameters]" -ForegroundColor Yellow
        Write-Host ""
        Write-Host "COMMANDS:" -ForegroundColor Yellow
        Write-Host "  generate    Generate a new RSA keypair"
        Write-Host "  sign        Sign firmware file"
        Write-Host "  verify      Verify firmware signature"
        Write-Host "  rotate      Rotate to a new keypair"
        Write-Host "  list        List all managed keys"
        Write-Host "  info        Show key information"
        Write-Host "  audit       Show/search audit logs"
        Write-Host ""
        Write-Host "EXAMPLES:" -ForegroundColor Yellow
        Write-Host "  .\key-manager.ps1 -Command generate -Name testkey -KeySize 2048"
        Write-Host "  .\key-manager.ps1 -Command sign -Firmware firmware.bin -Key production"
        Write-Host "  .\key-manager.ps1 -Command verify -Firmware firmware.bin"
        Write-Host "  .\key-manager.ps1 -Command list"
        Write-Host "  .\key-manager.ps1 -Command audit -Limit 50"
        Write-Host "  .\key-manager.ps1 -Command audit -Type signature_check -Severity warning"
        Write-Host ""
        exit 0
    }
}