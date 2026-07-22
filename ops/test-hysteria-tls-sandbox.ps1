[CmdletBinding()]
param(
    [string]$ScriptPath = ""
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

Assert-Contains 'HYSTERIA_TLS_DIR="\$\{CONFIG_DIR\}/hysteria-tls"' "Dedicated Hysteria TLS directory is missing"
Assert-Contains 'install_hysteria_tls_sync\(\)' "Hysteria TLS sync installer is missing"
Assert-Contains 'openssl x509 .* -checkend 86400' "Certificate expiry validation is missing"
Assert-Contains 'certificate and private key do not match' "Certificate/key matching validation is missing"
Assert-Contains 'ProtectHome=true' "Hysteria home isolation is missing"
Assert-Contains 'ReadOnlyPaths=\$\{HYSTERIA_TLS_DIR\}' "Hysteria service does not use the isolated TLS directory"
Assert-Contains 'OnUnitActiveSec=6h' "Hysteria TLS renewal timer is missing"
Assert-Contains 'hysteria-repair\|hy2-repair' "Hysteria repair CLI is missing"
Assert-Contains 'cmd_post_update\(\)' "Post-update migration hook is missing"
Assert-Contains 'run_startup_migrations\(\)' "First-start migration fallback is missing"
Assert-Contains 'check_os\s+run_startup_migrations \|\| true' "First-start migration is not wired into main"
Assert-NotContains '^[ \t]*cert: \$\{cert_file\}[ \t]*$' "Hysteria config still references the Caddy certificate directly"
Assert-NotContains '^[ \t]*key: \$\{key_file\}[ \t]*$' "Hysteria config still references the Caddy key directly"

Write-Host "HYSTERIA_TLS_SANDBOX_STATIC=ok script=$ScriptPath"
