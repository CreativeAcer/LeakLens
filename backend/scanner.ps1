<#
.SYNOPSIS
    LeakLens PowerShell Backend Scanner
    Outputs NDJSON lines for real-time streaming to the Node.js server.

.PARAMETER ScanPath
    The file share path to scan.

.PARAMETER MaxFileSizeMB
    Maximum file size to content-scan (default: 10).

.PARAMETER JsonOutput
    Switch: output NDJSON instead of human-readable text.

.PARAMETER ReportsDir
    Directory to save JSON report. Defaults to ../reports relative to script.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory)]
    [string]$ScanPath,

    [int]$MaxFileSizeMB = 10,

    [switch]$JsonOutput,

    [string]$ReportsDir = ""
)

Set-StrictMode -Off
$ErrorActionPreference = "SilentlyContinue"

# ─── Output helpers ───────────────────────────────────────────────────────────

function Out-Json($obj) {
    Write-Output ($obj | ConvertTo-Json -Compress -Depth 5)
}

function Emit-Progress($scanned, $hits, $current) {
    Out-Json @{ type = "progress"; scanned = $scanned; hits = $hits; current = $current }
}

function Emit-Finding($finding) {
    $finding["type"] = "finding"
    Out-Json $finding
}

function Emit-Summary($scanned, $hits, $reportFile) {
    Out-Json @{ type = "summary"; scanned = $scanned; hits = $hits; reportFile = $reportFile }
}

function Emit-Log($msg) {
    Out-Json @{ type = "log"; message = $msg }
}

# ─── Configuration ────────────────────────────────────────────────────────────

$TargetExtensions = @(
    ".ps1", ".psm1", ".psd1",
    ".bat", ".cmd",
    ".sh",
    ".txt", ".log",
    ".xml", ".config", ".conf",
    ".json", ".yaml", ".yml",
    ".ini", ".env",
    ".csv",
    ".sql",
    ".py", ".rb", ".php",
    ".md",
    ".htm", ".html"
)

$BinaryRiskExtensions = @(
    ".kdbx", ".kdb",
    ".pfx", ".p12",
    ".ppk",
    ".pem", ".key",
    ".jks",
    ".wallet"
)

$RiskyFilenames = @(
    "password", "passwords", "passwd", "credentials", "creds",
    "secrets", "secret", "apikey", "api_key", "token",
    "serviceaccount", "svc_account", ".env", "wallet",
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"
)

$ContentPatterns = [ordered]@{
    "Plaintext Password"      = '(?i)(password|passwd|pwd)\s*[=:]\s*\S+'
    "Connection String"       = '(?i)(connectionstring|data source|initial catalog).*password\s*='
    "NTLM Hash"               = '\b[a-fA-F0-9]{32}:[a-fA-F0-9]{32}\b'
    "MD5 Hash"                = '\b[a-fA-F0-9]{32}\b'
    "SHA1 Hash"               = '\b[a-fA-F0-9]{40}\b'
    "SHA256 Hash"             = '\b[a-fA-F0-9]{64}\b'
    "SHA512 Hash"             = '\b[a-fA-F0-9]{128}\b'
    "Bcrypt Hash"             = '\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}'
    "Base64 Credential"       = '(?i)(password|secret|token|key)\s*[=:]\s*[A-Za-z0-9+/]{20,}={0,2}'
    "AWS Access Key"          = '\bAKIA[0-9A-Z]{16}\b'
    "Generic API Key/Token"   = '(?i)(api[_-]?key|bearer|access[_-]?token)\s*[=:]\s*\S{10,}'
    "Private Key Header"      = '-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'
    "Net Use Credential"      = '(?i)net use.*\/user:.*\S+'
    "PowerShell SecureString" = '(?i)ConvertTo-SecureString|ConvertFrom-SecureString'
    "Hardcoded PSCredential"  = '(?i)PSCredential\s*\('
    "SQL sa Password"         = '(?i)(sa|sysadmin)\s*password\s*[=:]\s*\S+'
}

# ─── Risk level ───────────────────────────────────────────────────────────────

function Get-RiskLevel($matchedPatterns, $riskyName, $binaryRisk) {
    if ($binaryRisk -or ($matchedPatterns -match "Private Key|NTLM|Plaintext Password")) { return "HIGH" }
    if ($matchedPatterns.Count -ge 2 -or $riskyName) { return "MEDIUM" }
    return "LOW"
}

# ─── Reports directory ────────────────────────────────────────────────────────

if (-not $ReportsDir) {
    $ReportsDir = Join-Path (Split-Path $PSScriptRoot -Parent) "reports"
}
if (-not (Test-Path $ReportsDir)) {
    New-Item -ItemType Directory -Path $ReportsDir -Force | Out-Null
}

# ─── Main scan ────────────────────────────────────────────────────────────────

Emit-Log "Starting scan of: $ScanPath"

if (-not (Test-Path $ScanPath)) {
    Emit-Log "ERROR: Path does not exist or is not accessible: $ScanPath"
    exit 1
}

$MaxBytes  = $MaxFileSizeMB * 1MB
$FileCount = 0
$HitCount  = 0
$Results   = [System.Collections.Generic.List[hashtable]]::new()

$AllFiles = @(Get-ChildItem -Path $ScanPath -Recurse -File -ErrorAction SilentlyContinue)
$TotalFiles = $AllFiles.Count

Emit-Log "Found $TotalFiles files to evaluate"

foreach ($File in $AllFiles) {
    $FileCount++

    # Emit progress every 10 files
    if ($FileCount % 10 -eq 0 -or $FileCount -eq 1) {
        Emit-Progress -scanned $FileCount -hits $HitCount -current $File.FullName
    }

    $ext       = $File.Extension.ToLower()
    $nameBase  = $File.BaseName.ToLower()
    $findings  = [System.Collections.Generic.List[string]]::new()
    $isBinary  = $false
    $riskyName = ($RiskyFilenames | Where-Object { $nameBase -like "*$_*" }).Count -gt 0

    if ($BinaryRiskExtensions -contains $ext) {
        $isBinary = $true
        $findings.Add("Sensitive file type ($ext)")
    }
    elseif ($TargetExtensions -contains $ext) {
        if ($File.Length -gt $MaxBytes) {
            $findings.Add("File too large to scan ($([math]::Round($File.Length/1MB,1)) MB)")
        } else {
            try {
                $content = [System.IO.File]::ReadAllText($File.FullName)
                foreach ($pattern in $ContentPatterns.GetEnumerator()) {
                    if ($content -match $pattern.Value) {
                        $findings.Add($pattern.Key)
                    }
                }
            } catch {
                $findings.Add("Read error: $_")
            }
        }
    }
    elseif ($riskyName) {
        $findings.Add("Suspicious filename")
    } else {
        continue
    }

    if ($findings.Count -gt 0 -or $riskyName -or $isBinary) {
        $HitCount++

        $riskLevel = Get-RiskLevel -matchedPatterns $findings.ToArray() -riskyName $riskyName -binaryRisk $isBinary

        $owner = ""
        try { $owner = (Get-Acl $File.FullName).Owner } catch {}

        $finding = @{
            riskLevel     = $riskLevel
            fileName      = $File.Name
            fullPath      = $File.FullName
            extension     = $ext
            sizeKB        = [math]::Round($File.Length / 1KB, 1)
            lastModified  = $File.LastWriteTime.ToString("yyyy-MM-dd HH:mm")
            owner         = $owner
            riskyFilename = $riskyName
            findings      = ($findings -join " | ")
            findingsList  = $findings.ToArray()
        }

        $Results.Add($finding)
        Emit-Finding $finding
    }
}

# Final progress
Emit-Progress -scanned $FileCount -hits $HitCount -current ""

# ─── Save JSON report ─────────────────────────────────────────────────────────

$Timestamp  = Get-Date -Format "yyyyMMdd_HHmmss"
$ReportFile = Join-Path $ReportsDir "LeakLens_$Timestamp.json"

$Report = @{
    scanPath   = $ScanPath
    scanDate   = (Get-Date -Format "yyyy-MM-dd HH:mm:ss")
    scanned    = $FileCount
    hits       = $HitCount
    findings   = $Results.ToArray()
}

$Report | ConvertTo-Json -Depth 10 | Out-File -FilePath $ReportFile -Encoding UTF8

Emit-Log "Report saved: $ReportFile"
Emit-Summary -scanned $FileCount -hits $HitCount -reportFile $ReportFile
