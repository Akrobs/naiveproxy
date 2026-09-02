[CmdletBinding()]
param(
    [string]$ScriptPath = "",
    [string]$ExpectedVersion = "5.8.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
if (-not $ScriptPath) {
    $ScriptPath = Join-Path $repositoryRoot "naiveproxy.sh"
}
$ScriptPath = [IO.Path]::GetFullPath($ScriptPath)
$source = Get-Content -LiteralPath $ScriptPath -Raw

function Assert-Contains {
    param([string]$Pattern, [string]$Message)
    if ($source -notmatch $Pattern) {
        throw $Message
    }
}

function Assert-NotContains {
    param([string]$Pattern, [string]$Message)
    if ($source -match $Pattern) {
        throw $Message
    }
}

Assert-Contains ('VERSION="' + [regex]::Escape($ExpectedVersion) + '"') "Expected Yurich Panel v$ExpectedVersion"
Assert-Contains 'credential_set_user\(\)' "Protected credential writer is missing"
Assert-Contains 'hash_proxy_password' "bcrypt generation is missing"
Assert-Contains 'rsa_padding_mode:oaep' "RSA-OAEP encryption is missing"
Assert-Contains 'rsa_oaep_md:sha256' "RSA-OAEP SHA-256 is missing"
Assert-Contains 'basic_auth bcrypt' "Caddy bcrypt authentication is missing"
Assert-Contains 'type: command' "Hysteria command authentication is missing"
Assert-Contains 'credentials-migrate\|credential-migrate' "Credential migration CLI is missing"
Assert-Contains 'credential_state_restore' "Credential rollback is missing"
Assert-Contains 'sanitize_imported_credentials_dir' "Credential import validation is missing"
Assert-NotContains 'basic_auth\s+\$\{?u\}?\s+\$\{?p\}?' "Legacy plaintext Caddy auth is still generated"
Assert-NotContains 'printf\s+''%s:%s\\n''\s+"\$[^\"]+"\s+"\$[^\"]*(pass|password)[^\"]*"\s*>>\s*"\$USERS_FILE"' "A plaintext password is appended to users.conf"

$requiredDocs = @(
    "README.md",
    "README_EN.md",
    "SECURITY.md",
    "MULTISERVER_GUIDE_RU.md",
    "CREDENTIALS_MIGRATION_RU.md"
)
foreach ($relativePath in $requiredDocs) {
    $path = Join-Path $repositoryRoot $relativePath
    if (-not (Test-Path -LiteralPath $path)) {
        throw "Required documentation is missing: $relativePath"
    }
}

Write-Host "CREDENTIAL_STORAGE_STATIC=ok script=$ScriptPath"
