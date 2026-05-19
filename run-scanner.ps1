<#
.SYNOPSIS
    AutoSecureChain - ECU Firmware Security Scanner
.DESCRIPTION
    Scans firmware files for vulnerabilities, suspicious patterns, and signature validation
.PARAMETER FirmwareDir
    Directory containing firmware files (default: ./firmware)
.PARAMETER ExportToMetasploit
    Generate a Metasploit resource script (.rc) with notes
.PARAMETER ExportToMetasploitRpc
    Export notes via Metasploit RPC (msgrpc)
#>
param(
    [string]$FirmwareDir = "firmware",
    [switch]$ExportToMetasploit,
    [switch]$ExportToMetasploitRpc,
    [string]$MsfHost = "127.0.0.1",
    [int]$MsfPort = 55553,
    [switch]$MsfSsl = $false,
    [string]$MsfUser = "msf",
    [string]$MsfPass = "",
    [ValidateSet("scan", "generate", "sign", "verify", "rotate", "list", "info", "audit")]
    [string]$KeyCommand = "scan",
    [string]$KeyName = "production",
    [int]$KeySize = 4096,
    [string]$FirmwarePath = "",
    [string]$OldKeyName = "",
    [string]$NewKeyName = "",
    [string]$AuditType = "",
    [ValidateSet("info", "warning", "error")]
    [string]$AuditSeverity = "",
    [int]$AuditLimit = 20,
    [switch]$Json
)

$ErrorActionPreference = "Stop"

Write-Host "AutoSecureChain - ECU Firmware Scanner" -ForegroundColor Cyan
Write-Host "=====================================" -ForegroundColor Cyan

function Invoke-KeyManager {
    param(
        [string]$Command,
        [string[]]$ExtraArgs
    )

    $keyManagerScript = Join-Path $PSScriptRoot "key-manager.ps1"
    if (-not (Test-Path $keyManagerScript)) {
        throw "Key manager script not found: $keyManagerScript"
    }

    & $keyManagerScript -Command $Command @ExtraArgs
}

function Invoke-KeyManagementMode {
    Write-Host "Running key management command: $KeyCommand" -ForegroundColor Cyan

    switch ($KeyCommand) {
        "generate" {
            Invoke-KeyManager -Command $KeyCommand -ExtraArgs @("-Name", $KeyName, "-KeySize", $KeySize.ToString())
        }
        "sign" {
            if (-not $FirmwarePath) { throw "-FirmwarePath is required for sign" }
            Invoke-KeyManager -Command $KeyCommand -ExtraArgs @("-Firmware", $FirmwarePath, "-Key", $KeyName)
        }
        "verify" {
            if (-not $FirmwarePath) { throw "-FirmwarePath is required for verify" }
            Invoke-KeyManager -Command $KeyCommand -ExtraArgs @("-Firmware", $FirmwarePath, "-Key", $KeyName)
        }
        "rotate" {
            if (-not $OldKeyName) { throw "-OldKeyName is required for rotate" }
            $extraArgs = @("-OldKey", $OldKeyName)
            if ($NewKeyName) { $extraArgs += @("-NewKey", $NewKeyName) }
            Invoke-KeyManager -Command $KeyCommand -ExtraArgs $extraArgs
        }
        "list" {
            $extraArgs = @()
            if ($Json) { $extraArgs += "-Json" }
            Invoke-KeyManager -Command $KeyCommand -ExtraArgs $extraArgs
        }
        "info" {
            $extraArgs = @("-Name", $KeyName)
            if ($Json) { $extraArgs += "-Json" }
            Invoke-KeyManager -Command $KeyCommand -ExtraArgs $extraArgs
        }
        "audit" {
            $extraArgs = @("-Limit", $AuditLimit.ToString())
            if ($AuditType) { $extraArgs += @("-Type", $AuditType) }
            if ($AuditSeverity) { $extraArgs += @("-Severity", $AuditSeverity) }
            if ($Json) { $extraArgs += "-Json" }
            Invoke-KeyManager -Command $KeyCommand -ExtraArgs $extraArgs
        }
    }
}

if ($KeyCommand -ne "scan") {
    Invoke-KeyManagementMode
    return
}

# Activate venv
if (Test-Path "venv\Scripts\Activate.ps1") {
    Write-Host "Activating virtual environment..." -ForegroundColor Green
    & .\venv\Scripts\Activate.ps1
} else {
    Write-Host "Virtual environment not found. Creating..." -ForegroundColor Yellow
    python -m venv venv
    & .\venv\Scripts\Activate.ps1
}

# Install/update dependencies
Write-Host "Checking dependencies..." -ForegroundColor Green
pip install -q --upgrade pip
pip install -q -r requirements.txt

# Copy firmware files to scanner directory
if (Test-Path $FirmwareDir) {
    $firmwareFiles = Get-ChildItem -Path $FirmwareDir -Include *.bin,*.img,*.fw -Recurse
    if ($firmwareFiles) {
        Write-Host "Found $($firmwareFiles.Count) firmware file(s)" -ForegroundColor Green
        foreach ($file in $firmwareFiles) {
            Copy-Item -Path $file.FullName -Destination "AutoSecureChain\scanner\" -Force
        }
    } else {
        Write-Host "No firmware files found in $FirmwareDir" -ForegroundColor Yellow
        Write-Host "Scanning default sample.bin..." -ForegroundColor Gray
    }
}

# Run scanner
Write-Host ""
Write-Host "Running security scan..." -ForegroundColor Cyan
python AutoSecureChain\scanner\scanner.py

# Optional: export notes to Metasploit via .rc
if ($ExportToMetasploit) {
    Write-Host ""
    Write-Host "Generating Metasploit resource script from report..." -ForegroundColor Cyan
    try {
        python AutoSecureChain\scripts\generate_msf_rc.py
        Write-Host "To apply notes in an authorized environment:" -ForegroundColor Yellow
        Write-Host "  msfconsole -r AutoSecureChain\scripts\autosecurechain_notes.rc" -ForegroundColor Gray
    } catch {
        Write-Host "Failed to generate Metasploit resource script: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Optional: export notes to Metasploit via RPC
if ($ExportToMetasploitRpc) {
    if (-not $MsfPass) {
        Write-Host "Metasploit RPC password is required. Provide -MsfPass." -ForegroundColor Red
    } else {
        Write-Host ""
        Write-Host "Exporting findings to Metasploit via RPC..." -ForegroundColor Cyan
        $sslFlag = ""
        if ($MsfSsl) { $sslFlag = "--ssl" }
        try {
            python AutoSecureChain\scripts\export_to_metasploit.py `
                --host $MsfHost --port $MsfPort $sslFlag `
                --user $MsfUser --password $MsfPass --workspace "AutoSecureChain"
        } catch {
            Write-Host "Failed to export via RPC: $($_.Exception.Message)" -ForegroundColor Red
        }
    }
}

# Display results
if (Test-Path "AutoSecureChain\reports\report.json") {
    Write-Host ""
    Write-Host "Scan Results" -ForegroundColor Cyan
    Write-Host "===========" -ForegroundColor Cyan

    $report = Get-Content -Raw "AutoSecureChain\reports\report.json" | ConvertFrom-Json

    foreach ($file in $report.files) {
        $color = "Green"
        if ($file.severity_score -gt 5) { $color = "Red" }
        elseif ($file.severity_score -gt 2) { $color = "Yellow" }

        Write-Host "File: $($file.file)" -ForegroundColor White
        Write-Host "  SHA-256: $($file.sha256)" -ForegroundColor Gray
        Write-Host "  Severity: $($file.severity_score)" -ForegroundColor $color
        Write-Host "  Entropy: $([math]::Round($file.entropy, 2))" -ForegroundColor Gray

        if ($file.signature.sig_found) {
            $sigStatus = if ($file.signature.valid) { "Valid" } else { "Invalid" }
            $sigColor = if ($file.signature.valid) { "Green" } else { "Red" }
            Write-Host "  Signature: $sigStatus" -ForegroundColor $sigColor
        } else {
            Write-Host "  Signature: Not found" -ForegroundColor Yellow
        }

        if ($file.suspicious_strings.Count -gt 0) {
            Write-Host "  Suspicious findings: $($file.suspicious_strings.Count)" -ForegroundColor Yellow
        }

        if ($file.recommended_mitigations.Count -gt 0) {
            Write-Host ""
            Write-Host "  Recommended Actions:" -ForegroundColor Yellow
            foreach ($mitigation in $file.recommended_mitigations) {
                Write-Host "    - $($mitigation.title)" -ForegroundColor Yellow
            }
        }
        Write-Host ""
    }

    Write-Host "Reports saved to:" -ForegroundColor Cyan
    Write-Host "  - AutoSecureChain\reports\report.json" -ForegroundColor Gray
    Write-Host "  - AutoSecureChain\reports\mitigation_actions.json" -ForegroundColor Gray
} else {
    Write-Host "No report generated" -ForegroundColor Red
}

Write-Host ""
Write-Host "Key management commands are available via -KeyCommand generate|sign|verify|rotate|list|info|audit" -ForegroundColor Cyan
