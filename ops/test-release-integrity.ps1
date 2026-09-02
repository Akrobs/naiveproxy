[CmdletBinding()]
param(
    [string]$RepositoryRoot = "",
    [string]$ExpectedVersion = "5.8.0"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if (-not $RepositoryRoot) {
    $RepositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
}
$RepositoryRoot = [IO.Path]::GetFullPath($RepositoryRoot)

function Require-File {
    param([string]$RelativePath)
    $path = Join-Path $RepositoryRoot $RelativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required release file is missing: $RelativePath"
    }
    return $path
}

function Read-ShaSidecar {
    param([string]$Path, [string]$ExpectedFileName)
    $line = (Get-Content -LiteralPath $Path -Raw).Trim()
    if ($line -notmatch '^([a-fA-F0-9]{64})  (.+)$') {
        throw "Invalid SHA256 sidecar format: $Path"
    }
    if ($Matches[2] -ne $ExpectedFileName) {
        throw "SHA256 sidecar names $($Matches[2]), expected $ExpectedFileName"
    }
    return $Matches[1].ToLowerInvariant()
}

$canonicalPath = Require-File "yurich-panel.sh"
$legacyPath = Require-File "naiveproxy.sh"
$canonicalHash = (Get-FileHash -LiteralPath $canonicalPath -Algorithm SHA256).Hash.ToLowerInvariant()
$legacyHash = (Get-FileHash -LiteralPath $legacyPath -Algorithm SHA256).Hash.ToLowerInvariant()
if ($canonicalHash -ne $legacyHash) {
    throw "yurich-panel.sh and naiveproxy.sh are not byte-identical"
}

$canonicalSidecar = Read-ShaSidecar (Require-File "yurich-panel.sh.sha256") "yurich-panel.sh"
$legacySidecar = Read-ShaSidecar (Require-File "naiveproxy.sh.sha256") "naiveproxy.sh"
if ($canonicalSidecar -ne $canonicalHash -or $legacySidecar -ne $legacyHash) {
    throw "A SHA256 sidecar does not match its script"
}

$source = Get-Content -LiteralPath $canonicalPath -Raw
$escapedVersion = [regex]::Escape($ExpectedVersion)
if ($source -notmatch "VERSION=`"$escapedVersion`"") {
    throw "Expected Yurich Panel v$ExpectedVersion"
}
if ($source -match 'x25519\s+-i') {
    throw "A REALITY private key can still reach Xray through argv"
}
if ($source -notmatch 'openssl pkey -inform DER -pubout -outform DER') {
    throw "Safe OpenSSL REALITY public-key derivation is missing"
}
if ($source -notmatch 'xray_local_dns_ready') {
    throw "Conditional Xray DNS fallback is missing"
}
if ($source -notmatch 'local_tcp_endpoint_ready "\$browser_backend_port"') {
    throw "Browser SNI backend preflight is missing"
}
if ($source -notmatch 'domain_in_space_list_ci "\$caddy_sni_domains" "\$browser_sni_domain"') {
    throw "Case-insensitive Browser SNI collision guard is missing"
}
if ($source -notmatch 'Ротация отменена: некорректный BROWSER_SUBSCRIPTION_PROFILES') {
    throw "Credential rotation subscription preflight is missing"
}
if ($source -match '(?i)(go-it\.tech|net-it\.pro|plus-dns\.tech|dns-ai\.online|n8n-cloud\.online)') {
    throw "A production infrastructure domain is hardcoded in the public script"
}

$rolloutSource = Get-Content -LiteralPath (Require-File "ops/security-hardening-rollout.sh") -Raw
if ($rolloutSource -match 'HYSTERIA_STAGED\s*=|/tmp/yurich-hysteria-') {
    throw "Privileged rollout still trusts a predictable shared Hysteria staging path"
}
if ($rolloutSource -notmatch '-o "\$temp_dir/hysteria"' -or
    $rolloutSource -notmatch 'hysteria_size >= 1048576 && hysteria_size <= 67108864') {
    throw "Hysteria rollout must download into its private temp directory with a size bound"
}

$browserValidation = $source.IndexOf('browser_links=$(browser_subscription_links_for_user')
$subscriptionWrite = $source.IndexOf('printf ''%s\n'' "$active_links" > "$links_file"')
if ($browserValidation -lt 0 -or $subscriptionWrite -lt 0 -or $browserValidation -gt $subscriptionWrite) {
    throw "Browser subscription validation must happen before publication"
}
if ($source -match 'subscription_vless_relay_links_for_user[^\r\n]*\|\| true') {
    throw "VLESS relay validation errors are still suppressed"
}

$publicTextExtensions = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
@(
    ".conf", ".json", ".md", ".ps1", ".sh", ".sha256", ".toml", ".txt", ".yaml", ".yml"
) | ForEach-Object { [void]$publicTextExtensions.Add($_) }
$publicTextNames = [Collections.Generic.HashSet[string]]::new(
    [StringComparer]::OrdinalIgnoreCase
)
@(".gitattributes", ".gitignore") | ForEach-Object { [void]$publicTextNames.Add($_) }

$publicTextFiles = @(
    Get-ChildItem -LiteralPath $RepositoryRoot -Recurse -File -Force |
        Where-Object {
            $_.FullName -notlike "*$([IO.Path]::DirectorySeparatorChar).git$([IO.Path]::DirectorySeparatorChar)*" -and
            ($publicTextExtensions.Contains($_.Extension) -or $publicTextNames.Contains($_.Name))
        } |
        ForEach-Object { [IO.Path]::GetRelativePath($RepositoryRoot, $_.FullName) } |
        Sort-Object -Unique
)
if ($publicTextFiles.Count -eq 0) {
    throw "No public text files found for secret scanning"
}
$secretPatterns = @(
    '\b[0-9]{8,12}:[A-Za-z0-9_-]{30,}\b',
    '-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----',
    '(?i)/s/[a-f0-9]{40,}/',
    '\bAKIA[0-9A-Z]{16}\b',
    '\bgh[pousr]_[A-Za-z0-9]{36,}\b',
    '\bsk-[A-Za-z0-9_-]{20,}\b',
    '(?im)^\s*(?:TELEGRAM_(?:BOT_)?TOKEN|BOT_TOKEN|API_TOKEN|CLOUDFLARE_API_TOKEN|SSH_PASSWORD|ROOT_PASSWORD)\s*=\s*["'']?[A-Za-z0-9_+/@.,:-]{16,}["'']?\s*$'
)
foreach ($relativePath in $publicTextFiles) {
    $path = Join-Path $RepositoryRoot $relativePath
    $text = Get-Content -LiteralPath $path -Raw
    foreach ($pattern in $secretPatterns) {
        if ($text -match $pattern) {
            throw "Potential secret detected in public file: $relativePath"
        }
    }
}

Write-Host "RELEASE_INTEGRITY=ok version=$ExpectedVersion sha256=$canonicalHash scanned_text_files=$($publicTextFiles.Count)"
