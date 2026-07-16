[CmdletBinding()]
param(
    [string]$CaddyVersion = "v2.11.4",
    [string]$XcaddyVersion = "v0.4.6",
    [string]$ForwardProxyRef = "d62c80d3dd2c706b6b87579844d2397bddd18317",
    [string]$GoVersion = "1.26.5",
    [string]$GoWindowsAmd64Sha256 = "97e6b2a833b6d89f9ff17d25419ac0a7e3b482a044e9ab18cdef834bd834fd38",
    [string]$OutputDirectory = "",
    [switch]$KeepWorkDirectory
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

function Invoke-Native {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [string]$WorkingDirectory = ""
    )

    if ($WorkingDirectory) {
        Push-Location -LiteralPath $WorkingDirectory
    }

    try {
        & $FilePath @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "Command failed with exit code ${LASTEXITCODE}: $FilePath $($Arguments -join ' ')"
        }
    }
    finally {
        if ($WorkingDirectory) {
            Pop-Location
        }
    }
}

function Invoke-NativeWithRetry {
    param(
        [Parameter(Mandatory)] [string]$FilePath,
        [Parameter(Mandatory)] [string[]]$Arguments,
        [string]$WorkingDirectory = "",
        [ValidateRange(1, 10)] [int]$Attempts = 3,
        [ValidateRange(1, 60)] [int]$DelaySeconds = 5
    )

    for ($attempt = 1; $attempt -le $Attempts; $attempt++) {
        try {
            Invoke-Native -FilePath $FilePath -Arguments $Arguments -WorkingDirectory $WorkingDirectory
            return
        }
        catch {
            if ($attempt -eq $Attempts) {
                throw
            }
            Write-Warning "Attempt $attempt/$Attempts failed: $($_.Exception.Message)"
            Start-Sleep -Seconds $DelaySeconds
        }
    }
}

function Get-SafeVersionName {
    param([Parameter(Mandatory)] [string]$Version)
    return ($Version -replace '[^A-Za-z0-9._-]', '_')
}

function Get-ContainedPath {
    param(
        [Parameter(Mandatory)] [string]$Parent,
        [Parameter(Mandatory)] [string]$Child,
        [Parameter(Mandatory)] [string]$Label
    )

    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd(
        [IO.Path]::DirectorySeparatorChar,
        [IO.Path]::AltDirectorySeparatorChar
    )
    $childFull = [IO.Path]::GetFullPath($Child)
    $parentPrefix = $parentFull + [IO.Path]::DirectorySeparatorChar
    if (-not $childFull.StartsWith($parentPrefix, [StringComparison]::OrdinalIgnoreCase)) {
        throw "Unsafe $Label path: $childFull"
    }
    return $childFull
}

function Assert-LinuxAmd64Elf {
    param([Parameter(Mandatory)] [string]$Path)

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $header = New-Object byte[] 20
        if ($stream.Read($header, 0, $header.Length) -ne $header.Length) {
            throw "Candidate is too small to be an ELF binary: $Path"
        }
    }
    finally {
        $stream.Dispose()
    }

    $isElf = $header[0] -eq 0x7f -and $header[1] -eq 0x45 -and $header[2] -eq 0x4c -and $header[3] -eq 0x46
    $is64Bit = $header[4] -eq 2
    $isLittleEndian = $header[5] -eq 1
    $machine = [BitConverter]::ToUInt16($header, 18)

    if (-not ($isElf -and $is64Bit -and $isLittleEndian -and $machine -eq 0x3e)) {
        throw "Candidate is not a Linux amd64 ELF binary: $Path"
    }
}

if ($CaddyVersion -notmatch '\Av[0-9]+\.[0-9]+\.[0-9]+\z') {
    throw "Invalid Caddy version: $CaddyVersion"
}
if ($XcaddyVersion -notmatch '\Av[0-9]+\.[0-9]+\.[0-9]+\z') {
    throw "Invalid xcaddy version: $XcaddyVersion"
}
if ($GoVersion -notmatch '\A[0-9]+\.[0-9]+\.[0-9]+\z') {
    throw "Invalid Go version: $GoVersion"
}
if ($ForwardProxyRef -notmatch '\A[a-fA-F0-9]{40}\z') {
    throw "Forwardproxy ref must be a full 40-character commit SHA"
}
if ($GoWindowsAmd64Sha256 -notmatch '\A[a-fA-F0-9]{64}\z') {
    throw "Go SDK SHA256 must contain exactly 64 hexadecimal characters"
}
$ForwardProxyRef = $ForwardProxyRef.ToLowerInvariant()
$GoWindowsAmd64Sha256 = $GoWindowsAmd64Sha256.ToLowerInvariant()

$scriptDirectory = Split-Path -Parent $PSCommandPath
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptDirectory "..\.."))

if (-not $OutputDirectory) {
    $OutputDirectory = Join-Path $repositoryRoot "dist\caddy\$CaddyVersion"
}
$OutputDirectory = [System.IO.Path]::GetFullPath($OutputDirectory)

$safeCaddyVersion = Get-SafeVersionName -Version $CaddyVersion
$tempRoot = [System.IO.Path]::GetFullPath((Join-Path ([System.IO.Path]::GetTempPath()) "yurich-caddy-build"))
New-Item -ItemType Directory -Force -Path $tempRoot | Out-Null
$buildLockPath = Join-Path $tempRoot "build.lock"
try {
    $buildLock = [IO.File]::Open($buildLockPath, [IO.FileMode]::OpenOrCreate, [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
}
catch {
    throw "Another Caddy build is already running: $buildLockPath"
}
$workDirectory = Get-ContainedPath -Parent $tempRoot -Child (Join-Path $tempRoot $safeCaddyVersion) -Label "work directory"

if (Test-Path -LiteralPath $workDirectory) {
    Remove-Item -LiteralPath $workDirectory -Recurse -Force
}

$toolDirectory = Join-Path $workDirectory "tools"
$forwardProxyDirectory = Join-Path $workDirectory "forwardproxy"
$candidateDirectory = Join-Path $workDirectory "candidate"
$testCaddyfile = Join-Path $workDirectory "Caddyfile.test"
$windowsCandidate = Join-Path $candidateDirectory "caddy-windows-amd64.exe"
$linuxCandidate = Join-Path $candidateDirectory "caddy-linux-amd64"

New-Item -ItemType Directory -Force -Path $toolDirectory, $candidateDirectory, $OutputDirectory | Out-Null

$requiredCommands = @("git", "curl.exe")
foreach ($commandName in $requiredCommands) {
    if (-not (Get-Command $commandName -ErrorAction SilentlyContinue)) {
        throw "Required command is missing: $commandName"
    }
}

$goSdkRoot = [IO.Path]::GetFullPath((Join-Path ([IO.Path]::GetTempPath()) "yurich-go-sdk"))
$goInstallRoot = Get-ContainedPath -Parent $goSdkRoot -Child (Join-Path $goSdkRoot "go$GoVersion-windows-amd64") -Label "Go SDK"
$goArchive = Get-ContainedPath -Parent $goSdkRoot -Child (Join-Path $goSdkRoot "go$GoVersion.windows-amd64.zip") -Label "Go archive"
$goExe = Join-Path $goInstallRoot "go\bin\go.exe"
$goDownloadUrl = "https://go.dev/dl/go$GoVersion.windows-amd64.zip"
New-Item -ItemType Directory -Force -Path $goSdkRoot | Out-Null

$goArchiveValid = $false
if (Test-Path -LiteralPath $goArchive) {
    $goArchiveValid = (Get-FileHash -Algorithm SHA256 -LiteralPath $goArchive).Hash.ToLowerInvariant() -eq $GoWindowsAmd64Sha256
}
if (-not $goArchiveValid) {
    Remove-Item -LiteralPath $goArchive -Force -ErrorAction SilentlyContinue
    & curl.exe -fL --retry 5 --retry-all-errors --retry-delay 3 --connect-timeout 20 --max-time 600 -o $goArchive $goDownloadUrl
    if ($LASTEXITCODE -ne 0) {
        throw "Unable to download pinned Go SDK: $goDownloadUrl"
    }
}

$actualGoArchiveHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $goArchive).Hash.ToLowerInvariant()
if ($actualGoArchiveHash -ne $GoWindowsAmd64Sha256) {
    throw "Go SDK hash mismatch. Expected $GoWindowsAmd64Sha256, got $actualGoArchiveHash"
}

$goSdkReady = $false
if (Test-Path -LiteralPath $goExe) {
    $existingGoVersion = (& $goExe version).Trim()
    $goSdkReady = $LASTEXITCODE -eq 0 -and $existingGoVersion -match "go$([regex]::Escape($GoVersion))\s"
}
if (-not $goSdkReady) {
    $goStagingRoot = [IO.Path]::GetFullPath((Join-Path $goSdkRoot ("staging-" + [Guid]::NewGuid().ToString("N"))))
    try {
        New-Item -ItemType Directory -Force -Path $goStagingRoot | Out-Null
        Expand-Archive -LiteralPath $goArchive -DestinationPath $goStagingRoot
        $stagedGoExe = Join-Path $goStagingRoot "go\bin\go.exe"
        if (-not (Test-Path -LiteralPath $stagedGoExe)) {
            throw "Pinned Go archive does not contain go/bin/go.exe"
        }
        if (Test-Path -LiteralPath $goInstallRoot) {
            $null = Get-ContainedPath -Parent $goSdkRoot -Child $goInstallRoot -Label "Go SDK replacement"
            Remove-Item -LiteralPath $goInstallRoot -Recurse -Force
        }
        Move-Item -LiteralPath $goStagingRoot -Destination $goInstallRoot
    }
    finally {
        if (Test-Path -LiteralPath $goStagingRoot) {
            Remove-Item -LiteralPath $goStagingRoot -Recurse -Force
        }
    }
}

$goVersionOutput = (& $goExe version).Trim()
$goVersionMatch = [regex]::Match($goVersionOutput, 'go([0-9]+)\.([0-9]+)(?:\.([0-9]+))?')
if ($LASTEXITCODE -ne 0 -or -not $goVersionMatch.Success) {
    throw "Unable to parse Go version: $goVersionOutput"
}

$goMajor = [int]$goVersionMatch.Groups[1].Value
$goMinor = [int]$goVersionMatch.Groups[2].Value
if ($goMajor -lt 1 -or ($goMajor -eq 1 -and $goMinor -lt 25)) {
    throw "Caddy $CaddyVersion requires Go 1.25.1 or newer; found $goVersionOutput"
}
if ($goVersionOutput -notmatch "go$([regex]::Escape($GoVersion))\s") {
    throw "Pinned Go SDK mismatch. Expected go$GoVersion, got $goVersionOutput"
}

$savedEnvironment = @{
    GOBIN = $env:GOBIN
    GOOS = $env:GOOS
    GOARCH = $env:GOARCH
    CGO_ENABLED = $env:CGO_ENABLED
    XCADDY_GO_BUILD_FLAGS = $env:XCADDY_GO_BUILD_FLAGS
    XCADDY_WHICH_GO = $env:XCADDY_WHICH_GO
    GOPROXY = $env:GOPROXY
    GOSUMDB = $env:GOSUMDB
    GONOSUMDB = $env:GONOSUMDB
    GONOPROXY = $env:GONOPROXY
    GOPRIVATE = $env:GOPRIVATE
    GOINSECURE = $env:GOINSECURE
    GOENV = $env:GOENV
    GOFLAGS = $env:GOFLAGS
    PATH = $env:PATH
}
$env:PATH = "$(Split-Path -Parent $goExe);$($env:PATH)"
$env:XCADDY_WHICH_GO = $goExe
$env:GOPROXY = "https://proxy.golang.org,direct"
$env:GOSUMDB = "sum.golang.org"
$env:GONOSUMDB = ""
$env:GONOPROXY = ""
$env:GOPRIVATE = ""
$env:GOINSECURE = ""
$env:GOENV = "off"
$env:GOFLAGS = ""

try {
    Write-Host "[1/7] Cloning pinned Naive forwardproxy source..."
    $cloneArguments = @(
        "clone", "--branch", "naive", "--single-branch", "--filter=blob:none",
        "https://github.com/klzgrad/forwardproxy.git", $forwardProxyDirectory
    )
    for ($cloneAttempt = 1; $cloneAttempt -le 3; $cloneAttempt++) {
        if (Test-Path -LiteralPath $forwardProxyDirectory) {
            if (-not $forwardProxyDirectory.StartsWith($workDirectory, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Refusing to clean unsafe clone directory: $forwardProxyDirectory"
            }
            Remove-Item -LiteralPath $forwardProxyDirectory -Recurse -Force
        }
        try {
            Invoke-Native -FilePath "git" -Arguments $cloneArguments
            break
        }
        catch {
            if ($cloneAttempt -eq 3) {
                throw
            }
            Write-Warning "Clone attempt $cloneAttempt/3 failed: $($_.Exception.Message)"
            Start-Sleep -Seconds 5
        }
    }
    Invoke-NativeWithRetry -FilePath "git" -Arguments @(
        "fetch", "--depth", "1", "origin", $ForwardProxyRef
    ) -WorkingDirectory $forwardProxyDirectory
    Invoke-Native -FilePath "git" -Arguments @("checkout", "--detach", "FETCH_HEAD") -WorkingDirectory $forwardProxyDirectory

    $resolvedForwardProxyRef = (& git -C $forwardProxyDirectory rev-parse HEAD).Trim()
    if ($LASTEXITCODE -ne 0 -or $resolvedForwardProxyRef -ne $ForwardProxyRef) {
        throw "Forwardproxy ref mismatch. Expected $ForwardProxyRef, got $resolvedForwardProxyRef"
    }

    Write-Host "[2/7] Testing forwardproxy against $CaddyVersion..."
    Invoke-Native -FilePath $goExe -Arguments @(
        "mod", "edit", "-require=github.com/caddyserver/caddy/v2@$CaddyVersion"
    ) -WorkingDirectory $forwardProxyDirectory
    Invoke-Native -FilePath $goExe -Arguments @("mod", "tidy") -WorkingDirectory $forwardProxyDirectory
    Invoke-Native -FilePath $goExe -Arguments @("mod", "verify") -WorkingDirectory $forwardProxyDirectory
    Invoke-Native -FilePath $goExe -Arguments @("test", "./...") -WorkingDirectory $forwardProxyDirectory

    $dependencyFile = Join-Path $candidateDirectory "go-modules.txt"
    Push-Location -LiteralPath $forwardProxyDirectory
    try {
        & $goExe list -m all | Set-Content -LiteralPath $dependencyFile -Encoding utf8
        if ($LASTEXITCODE -ne 0) {
            throw "Unable to record Go module list"
        }
    }
    finally {
        Pop-Location
    }

    Write-Host "[3/7] Installing pinned xcaddy $XcaddyVersion locally..."
    $env:GOBIN = $toolDirectory
    $env:GOOS = ""
    $env:GOARCH = ""
    $env:CGO_ENABLED = "0"
    Invoke-Native -FilePath $goExe -Arguments @(
        "install", "github.com/caddyserver/xcaddy/cmd/xcaddy@$XcaddyVersion"
    )

    $xcaddy = Join-Path $toolDirectory "xcaddy.exe"
    if (-not (Test-Path -LiteralPath $xcaddy)) {
        throw "xcaddy executable was not produced: $xcaddy"
    }

    # Build from the immutable remote commit. The local clone above is only
    # used for compatibility tests; remote replacement keeps source provenance
    # in Go build metadata and avoids embedding a temporary Windows path.
    $forwardProxyReplacement = "github.com/klzgrad/forwardproxy@$ForwardProxyRef"
    $env:XCADDY_GO_BUILD_FLAGS = "-trimpath -buildvcs=false"

    Write-Host "[4/7] Building Windows verification candidate..."
    $env:GOOS = "windows"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    Invoke-Native -FilePath $xcaddy -Arguments @(
        "build", $CaddyVersion,
        "--with", "github.com/caddyserver/forwardproxy=$forwardProxyReplacement",
        "--output", $windowsCandidate
    ) -WorkingDirectory $candidateDirectory

    $versionOutput = (& $windowsCandidate version).Trim()
    if ($LASTEXITCODE -ne 0 -or $versionOutput -notmatch [regex]::Escape($CaddyVersion.TrimStart('v'))) {
        throw "Unexpected Caddy version output: $versionOutput"
    }

    $moduleFile = Join-Path $candidateDirectory "caddy-modules.txt"
    $modules = & $windowsCandidate list-modules
    if ($LASTEXITCODE -ne 0) {
        throw "caddy list-modules failed"
    }
    $modules | Set-Content -LiteralPath $moduleFile -Encoding utf8
    if ($modules -notcontains "http.handlers.forward_proxy") {
        throw "Required module is missing: http.handlers.forward_proxy"
    }

    @'
{
    auto_https off
    order forward_proxy before file_server
}

http://127.0.0.1:18080 {
    forward_proxy {
        basic_auth build-check build-check
        hide_ip
        hide_via
        probe_resistance
    }
    respond "caddy candidate"
}
'@ | Set-Content -LiteralPath $testCaddyfile -Encoding utf8

    Invoke-Native -FilePath $windowsCandidate -Arguments @(
        "validate", "--config", $testCaddyfile, "--adapter", "caddyfile"
    )

    Write-Host "[5/7] Building Linux amd64 production candidate..."
    $env:GOOS = "linux"
    $env:GOARCH = "amd64"
    $env:CGO_ENABLED = "0"
    Invoke-Native -FilePath $xcaddy -Arguments @(
        "build", $CaddyVersion,
        "--with", "github.com/caddyserver/forwardproxy=$forwardProxyReplacement",
        "--output", $linuxCandidate
    ) -WorkingDirectory $candidateDirectory

    Assert-LinuxAmd64Elf -Path $linuxCandidate

    Write-Host "[6/7] Verifying Linux build metadata..."
    $buildMetadataFile = Join-Path $candidateDirectory "caddy-linux-buildinfo.txt"
    $buildMetadata = & $goExe version -m $linuxCandidate
    if ($LASTEXITCODE -ne 0) {
        throw "go version -m failed for Linux candidate"
    }
    $buildMetadata | Set-Content -LiteralPath $buildMetadataFile -Encoding utf8
    $buildMetadataText = $buildMetadata -join "`n"
    $buildMetadataBody = ($buildMetadata | Select-Object -Skip 1) -join "`n"
    if ($buildMetadataText -notmatch "github\.com/caddyserver/caddy/v2\s+$([regex]::Escape($CaddyVersion))") {
        throw "Linux candidate does not contain Caddy $CaddyVersion"
    }
    if ($buildMetadataText -notmatch "github\.com/caddyserver/forwardproxy") {
        throw "Linux candidate does not contain forwardproxy build metadata"
    }
    $forwardProxyShortRef = $ForwardProxyRef.Substring(0, [Math]::Min(12, $ForwardProxyRef.Length))
    if ($buildMetadataText -notmatch "github\.com/klzgrad/forwardproxy\s+v[0-9A-Za-z.+_-]*$([regex]::Escape($forwardProxyShortRef))") {
        throw "Linux candidate does not record pinned klzgrad/forwardproxy ref $ForwardProxyRef"
    }
    if ($buildMetadataBody -match "yurich-caddy-build") {
        throw "Linux candidate unexpectedly contains a temporary build path"
    }

    Write-Host "[7/7] Publishing local artifacts and checksums..."
    $publishedLinux = Join-Path $OutputDirectory "caddy-linux-amd64"
    $publishedWindows = Join-Path $OutputDirectory "caddy-windows-amd64.exe"
    Copy-Item -LiteralPath $linuxCandidate -Destination $publishedLinux -Force
    Copy-Item -LiteralPath $windowsCandidate -Destination $publishedWindows -Force
    Copy-Item -LiteralPath $moduleFile, $dependencyFile, $buildMetadataFile -Destination $OutputDirectory -Force

    $linuxHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $publishedLinux).Hash.ToLowerInvariant()
    $windowsHash = (Get-FileHash -Algorithm SHA256 -LiteralPath $publishedWindows).Hash.ToLowerInvariant()

    $checksumText = @(
        "# Generated with LF line endings for sha256sum compatibility.",
        "$linuxHash  caddy-linux-amd64",
        "$windowsHash  caddy-windows-amd64.exe"
    ) -join "`n"
    [IO.File]::WriteAllText(
        (Join-Path $OutputDirectory "SHA256SUMS.txt"),
        "$checksumText`n",
        [Text.Encoding]::ASCII
    )

    $manifest = [ordered]@{
        schemaVersion = 1
        builtAtUtc = [DateTime]::UtcNow.ToString("o")
        caddyVersion = $CaddyVersion
        xcaddyVersion = $XcaddyVersion
        forwardProxyRepository = "https://github.com/klzgrad/forwardproxy.git"
        forwardProxyRef = $resolvedForwardProxyRef
        goVersion = $goVersionOutput
        goArchiveSha256 = $actualGoArchiveHash
        target = "linux/amd64"
        caddyVersionOutput = $versionOutput
        requiredModule = "http.handlers.forward_proxy"
        forwardProxyProvenanceVerifiedInLinuxMetadata = $true
        moduleVerifiedWithWindowsCandidate = $true
        configValidatedWithWindowsCandidate = $true
        linuxElfVerified = $true
        linuxSha256 = $linuxHash
        windowsVerifierSha256 = $windowsHash
    }
    $manifest | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath (Join-Path $OutputDirectory "manifest.json") -Encoding utf8

    Write-Host "Build completed successfully."
    Write-Host "Artifacts: $OutputDirectory"
    Write-Host "Linux SHA256: $linuxHash"
}
finally {
    $env:GOBIN = $savedEnvironment.GOBIN
    $env:GOOS = $savedEnvironment.GOOS
    $env:GOARCH = $savedEnvironment.GOARCH
    $env:CGO_ENABLED = $savedEnvironment.CGO_ENABLED
    $env:XCADDY_GO_BUILD_FLAGS = $savedEnvironment.XCADDY_GO_BUILD_FLAGS
    $env:XCADDY_WHICH_GO = $savedEnvironment.XCADDY_WHICH_GO
    $env:GOPROXY = $savedEnvironment.GOPROXY
    $env:GOSUMDB = $savedEnvironment.GOSUMDB
    $env:GONOSUMDB = $savedEnvironment.GONOSUMDB
    $env:GONOPROXY = $savedEnvironment.GONOPROXY
    $env:GOPRIVATE = $savedEnvironment.GOPRIVATE
    $env:GOINSECURE = $savedEnvironment.GOINSECURE
    $env:GOENV = $savedEnvironment.GOENV
    $env:GOFLAGS = $savedEnvironment.GOFLAGS
    $env:PATH = $savedEnvironment.PATH

    if (-not $KeepWorkDirectory -and (Test-Path -LiteralPath $workDirectory)) {
        if (-not $workDirectory.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing to remove unsafe work directory: $workDirectory"
        }
        Remove-Item -LiteralPath $workDirectory -Recurse -Force
    }
    elseif ($KeepWorkDirectory) {
        Write-Host "Work directory kept at: $workDirectory"
    }
    if ($buildLock) {
        $buildLock.Dispose()
    }
}
