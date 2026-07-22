[CmdletBinding()]
param(
    [string]$CaddyPath = "",
    [string]$NaiveVersion = "v148.0.7778.96-5",
    [string]$NaiveArchiveSha256 = "54c7918557a7bd694f86ec7942b85d88b3623b21514ac3160c1e9e0e63175e8e"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

if ($NaiveVersion -notmatch '\Av[0-9][0-9A-Za-z._+-]{0,95}\z') {
    throw "Unsafe Naive version: $NaiveVersion"
}
if ($NaiveArchiveSha256 -notmatch '\A[a-fA-F0-9]{64}\z') {
    throw "Naive archive SHA256 must contain exactly 64 hexadecimal characters"
}
$NaiveArchiveSha256 = $NaiveArchiveSha256.ToLowerInvariant()

function Get-FreeTcpPort {
    $listener = [Net.Sockets.TcpListener]::new([Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        return ([Net.IPEndPoint]$listener.LocalEndpoint).Port
    }
    finally {
        $listener.Stop()
    }
}

function Wait-TcpPort {
    param(
        [Parameter(Mandatory)] [int]$Port,
        [Parameter(Mandatory)] [System.Diagnostics.Process]$Process,
        [int]$Attempts = 80
    )

    for ($attempt = 0; $attempt -lt $Attempts; $attempt++) {
        if ($Process.HasExited) {
            return $false
        }
        try {
            $client = [Net.Sockets.TcpClient]::new()
            $connect = $client.ConnectAsync("127.0.0.1", $Port)
            if ($connect.Wait(250) -and $client.Connected) {
                $client.Dispose()
                return $true
            }
            $client.Dispose()
        }
        catch {
        }
        Start-Sleep -Milliseconds 250
    }
    return $false
}

function Remove-TestRootCertificate {
    param([Parameter(Mandatory)] [string]$Thumbprint)

    $registryKey = "Registry::HKEY_CURRENT_USER\Software\Microsoft\SystemCertificates\Root\Certificates\$Thumbprint"
    if (Test-Path -LiteralPath $registryKey) {
        Remove-Item -LiteralPath $registryKey -Recurse -Force
    }

    Start-Sleep -Milliseconds 300
    $exists = (& pwsh -NoLogo -NoProfile -Command "[bool](Get-ChildItem Cert:\CurrentUser\Root\$Thumbprint -ErrorAction SilentlyContinue)").Trim()
    if ($exists -ne "False") {
        throw "Temporary Caddy root remains in CurrentUser certificate store: $Thumbprint"
    }
}

function Add-TestRootCertificate {
    param(
        [Parameter(Mandatory)]
        [Security.Cryptography.X509Certificates.X509Certificate2]$Certificate
    )

    $store = [Security.Cryptography.X509Certificates.X509Store]::new(
        [Security.Cryptography.X509Certificates.StoreName]::Root,
        [Security.Cryptography.X509Certificates.StoreLocation]::CurrentUser
    )
    try {
        $store.Open([Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite)
        $store.Add($Certificate)
    }
    finally {
        $store.Close()
    }
}

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $scriptDirectory "..\.."))
if (-not $CaddyPath) {
    $CaddyPath = Join-Path $repositoryRoot "dist\caddy\v2.11.4\caddy-windows-amd64.exe"
}
$CaddyPath = [IO.Path]::GetFullPath($CaddyPath)
if (-not (Test-Path -LiteralPath $CaddyPath)) {
    throw "Caddy candidate not found: $CaddyPath"
}

$tempRoot = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$cacheRoot = [IO.Path]::GetFullPath((Join-Path $tempRoot "yurich-naive-client-cache"))
$naiveCache = [IO.Path]::GetFullPath((Join-Path $cacheRoot $NaiveVersion))
$cachePrefix = $cacheRoot.TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar) + [IO.Path]::DirectorySeparatorChar
if (-not $naiveCache.StartsWith($cachePrefix, [StringComparison]::OrdinalIgnoreCase)) {
    throw "Refusing to use unsafe Naive cache path: $naiveCache"
}
$testRoot = Join-Path $tempRoot ("yurich-naive-e2e-" + [Guid]::NewGuid().ToString("N"))
$naiveArchive = Join-Path $naiveCache "naiveproxy.zip"
$naiveExtract = Join-Path $testRoot "naive-extract"
$naiveArchiveName = "naiveproxy-$NaiveVersion-win-x64.zip"
$naiveUrl = "https://github.com/klzgrad/naiveproxy/releases/download/$NaiveVersion/$naiveArchiveName"

New-Item -ItemType Directory -Force -Path $naiveCache | Out-Null
$archiveValid = $false
if (Test-Path -LiteralPath $naiveArchive) {
    $archiveValid = (Get-FileHash -Algorithm SHA256 -LiteralPath $naiveArchive).Hash.ToLowerInvariant() -eq $NaiveArchiveSha256
}
if (-not $archiveValid) {
    Remove-Item -LiteralPath $naiveArchive -Force -ErrorAction SilentlyContinue
    & curl.exe -fL --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 20 --max-time 300 -o $naiveArchive $naiveUrl
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to download official Naive client: $naiveUrl"
    }
}

$actualNaiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $naiveArchive).Hash.ToLowerInvariant()
if ($actualNaiveHash -ne $NaiveArchiveSha256) {
    throw "Naive archive hash mismatch. Expected $NaiveArchiveSha256, got $actualNaiveHash"
}

New-Item -ItemType Directory -Force -Path $testRoot | Out-Null
try {
    Expand-Archive -LiteralPath $naiveArchive -DestinationPath $naiveExtract
    $naiveExe = Get-ChildItem -LiteralPath $naiveExtract -Recurse -Filter "naive.exe" | Select-Object -First 1 -ExpandProperty FullName
    if (-not $naiveExe) {
        throw "naive.exe is missing from verified archive"
    }
}
catch {
    Remove-Item -LiteralPath $testRoot -Recurse -Force -ErrorAction SilentlyContinue
    throw
}

$caddyPort = Get-FreeTcpPort
$socksPort = Get-FreeTcpPort
$badSocksPort = Get-FreeTcpPort
$appData = Join-Path $testRoot "AppData\Roaming"
$localAppData = Join-Path $testRoot "AppData\Local"
New-Item -ItemType Directory -Force -Path $appData, $localAppData | Out-Null

$caddyfile = Join-Path $testRoot "Caddyfile"
$caddyStdout = Join-Path $testRoot "caddy.stdout.log"
$caddyStderr = Join-Path $testRoot "caddy.stderr.log"
$naiveConfig = Join-Path $testRoot "naive.json"
$badNaiveConfig = Join-Path $testRoot "naive-bad-auth.json"
$naiveStdout = Join-Path $testRoot "naive.stdout.log"
$naiveStderr = Join-Path $testRoot "naive.stderr.log"
$webRoot = Join-Path $testRoot "www"
New-Item -ItemType Directory -Force -Path $webRoot | Out-Null
"caddy candidate" | Set-Content -LiteralPath (Join-Path $webRoot "index.html") -Encoding utf8
$caddyWebRoot = $webRoot.Replace('\', '/')
$authHash = (& $CaddyPath hash-password --plaintext "build-check").Trim()
if ($LASTEXITCODE -ne 0 -or $authHash -notmatch '^\$2[aby]\$') {
    throw "Caddy failed to generate a bcrypt test credential"
}
# Apache htpasswd emits $2y$ on Ubuntu; exercise the exact migration format.
$authHash = '$2y$' + $authHash.Substring(4)

@"
{
    admin off
    skip_install_trust
    auto_https disable_redirects
    order forward_proxy before file_server
    servers {
        protocols h1 h2
    }
}

:$caddyPort, localhost:$caddyPort {
    bind 127.0.0.1
    tls internal
    @naive_proxy method CONNECT
    route @naive_proxy {
        request_header Authorization "{http.request.header.Proxy-Authorization}"
        basic_auth bcrypt {
            build-check $authHash
        }
        request_header -Authorization
        forward_proxy {
            hide_ip
            hide_via
        }
    }
    file_server {
        root $caddyWebRoot
    }
    handle_errors {
        @proxy_auth_error expression {http.error.status_code} == 401
        handle @proxy_auth_error {
            log_append yurich_auth_failure "1"
            header -WWW-Authenticate
            respond "Not Found" 404
        }
    }
}
"@ | Set-Content -LiteralPath $caddyfile -Encoding utf8

@{
    listen = "socks://127.0.0.1:$socksPort"
    proxy = "https://build-check:build-check@localhost:$caddyPort"
    "host-resolver-rules" = "MAP localhost 127.0.0.1"
    log = ""
} | ConvertTo-Json | Set-Content -LiteralPath $naiveConfig -Encoding utf8

@{
    listen = "socks://127.0.0.1:$badSocksPort"
    proxy = "https://build-check:wrong-password@localhost:$caddyPort"
    "host-resolver-rules" = "MAP localhost 127.0.0.1"
    log = ""
} | ConvertTo-Json | Set-Content -LiteralPath $badNaiveConfig -Encoding utf8

$caddyProcess = $null
$naiveProcess = $null
$badNaiveProcess = $null
$rootThumbprint = $null
$success = $false
$failureMessage = ""
$cleanupError = ""

try {
    & $CaddyPath validate --config $caddyfile --adapter caddyfile | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "Candidate rejected E2E Caddyfile"
    }

    $childEnvironment = @{
        APPDATA = $appData
        LOCALAPPDATA = $localAppData
        USERPROFILE = $testRoot
    }
    $previousChildEnvironment = @{}
    foreach ($entry in $childEnvironment.GetEnumerator()) {
        $previousChildEnvironment[$entry.Key] = [Environment]::GetEnvironmentVariable($entry.Key, "Process")
        [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
    }
    try {
        $caddyProcess = Start-Process -FilePath $CaddyPath -ArgumentList @(
            "run", "--config", $caddyfile, "--adapter", "caddyfile"
        ) -WorkingDirectory $testRoot -WindowStyle Hidden -RedirectStandardOutput $caddyStdout -RedirectStandardError $caddyStderr -PassThru
    }
    finally {
        foreach ($entry in $previousChildEnvironment.GetEnumerator()) {
            [Environment]::SetEnvironmentVariable($entry.Key, $entry.Value, "Process")
        }
    }

    $rootCertificatePath = Join-Path $appData "Caddy\pki\authorities\local\root.crt"
    if (-not (Wait-TcpPort -Port $caddyPort -Process $caddyProcess)) {
        throw "Caddy TLS listener did not start"
    }
    for ($attempt = 0; $attempt -lt 40 -and -not (Test-Path -LiteralPath $rootCertificatePath); $attempt++) {
        Start-Sleep -Milliseconds 250
    }
    if (-not (Test-Path -LiteralPath $rootCertificatePath)) {
        throw "Caddy internal root was not generated"
    }

    $rootCertificate = [Security.Cryptography.X509Certificates.X509Certificate2]::new($rootCertificatePath)
    $rootThumbprint = $rootCertificate.Thumbprint
    if (Test-Path "Cert:\CurrentUser\Root\$rootThumbprint") {
        throw "Generated test root already exists unexpectedly: $rootThumbprint"
    }

    Add-TestRootCertificate -Certificate $rootCertificate
    if (-not (Test-Path "Cert:\CurrentUser\Root\$rootThumbprint")) {
        throw "Unable to trust temporary Caddy root"
    }

    $naiveProcess = Start-Process -FilePath $naiveExe -ArgumentList @($naiveConfig, "--log") -WorkingDirectory $testRoot -WindowStyle Hidden -RedirectStandardOutput $naiveStdout -RedirectStandardError $naiveStderr -PassThru
    if (-not (Wait-TcpPort -Port $socksPort -Process $naiveProcess)) {
        throw "Naive SOCKS listener did not start"
    }

    $httpCode = & curl.exe -sS --max-time 30 --socks5-hostname "127.0.0.1:$socksPort" -o NUL -w "%{http_code}" "https://example.com/"
    if ($LASTEXITCODE -ne 0 -or $httpCode -ne "200") {
        throw "Naive request failed: curl=$LASTEXITCODE http=$httpCode"
    }

    $badNaiveProcess = Start-Process -FilePath $naiveExe -ArgumentList @($badNaiveConfig, "--log") -WorkingDirectory $testRoot -WindowStyle Hidden -PassThru
    if (-not (Wait-TcpPort -Port $badSocksPort -Process $badNaiveProcess)) {
        throw "Bad-auth Naive SOCKS listener did not start"
    }
    $previousErrorPreference = $ErrorActionPreference
    try {
        # A TLS failure is the expected result for rejected proxy credentials.
        $ErrorActionPreference = "Continue"
        $badHttpCode = & curl.exe -sS --max-time 8 --socks5-hostname "127.0.0.1:$badSocksPort" -o NUL -w "%{http_code}" "https://example.com/" 2>$null
        $badCurlExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorPreference
    }
    if ($badCurlExitCode -eq 0 -and $badHttpCode -eq "200") {
        throw "Caddy accepted an invalid proxy credential"
    }

    Start-Sleep -Milliseconds 700
    $naiveLog = (Get-Content -LiteralPath $naiveStdout -Raw -ErrorAction SilentlyContinue) + (Get-Content -LiteralPath $naiveStderr -Raw -ErrorAction SilentlyContinue)
    $paddingMatch = [regex]::Match($naiveLog, "negotiated padding type:\s*([^\r\n]+)")
    if (-not $paddingMatch.Success) {
        throw "Naive did not report padding negotiation"
    }
    $paddingType = $paddingMatch.Groups[1].Value.Trim()
    if ($paddingType -eq "None") {
        throw "Naive padding was not negotiated"
    }

    $success = $true
    Write-Host "NAIVE_E2E=ok caddy=$((& $CaddyPath version).Split(' ')[0]) naive=$NaiveVersion http=200 padding=$paddingType"
}
catch {
    $failureMessage = $_.Exception.Message
    throw
}
finally {
    if ($naiveProcess -and -not $naiveProcess.HasExited) {
        Stop-Process -Id $naiveProcess.Id -Force
        Wait-Process -Id $naiveProcess.Id -ErrorAction SilentlyContinue
    }
    if ($badNaiveProcess -and -not $badNaiveProcess.HasExited) {
        Stop-Process -Id $badNaiveProcess.Id -Force
        Wait-Process -Id $badNaiveProcess.Id -ErrorAction SilentlyContinue
    }
    if ($caddyProcess -and -not $caddyProcess.HasExited) {
        Stop-Process -Id $caddyProcess.Id -Force
        Wait-Process -Id $caddyProcess.Id -ErrorAction SilentlyContinue
    }

    if ($rootThumbprint -and (Test-Path "Cert:\CurrentUser\Root\$rootThumbprint")) {
        try {
            Remove-TestRootCertificate -Thumbprint $rootThumbprint
        }
        catch {
            $cleanupError = $_.Exception.Message
        }
    }

    if (-not $success) {
        Write-Host "NAIVE_E2E=failed reason=$failureMessage"
        Write-Host "NAIVE_LOG"
        Get-Content -LiteralPath $naiveStdout -ErrorAction SilentlyContinue
        Get-Content -LiteralPath $naiveStderr -ErrorAction SilentlyContinue
        Write-Host "CADDY_LOG"
        Get-Content -LiteralPath $caddyStderr -ErrorAction SilentlyContinue
    }

    if (Test-Path -LiteralPath $testRoot) {
        $resolvedTestRoot = [IO.Path]::GetFullPath($testRoot)
        $resolvedTemp = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
        if (-not $resolvedTestRoot.StartsWith($resolvedTemp, [StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove unsafe E2E directory: $resolvedTestRoot"
        }
        Remove-Item -LiteralPath $resolvedTestRoot -Recurse -Force
    }

    if ($cleanupError) {
        throw "E2E cleanup failed: $cleanupError"
    }
}
