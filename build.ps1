$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot

# Auto-detect Pico SDK
if (-not $env:PICO_SDK_PATH) {
    $sdkCandidates = @(
        "$env:USERPROFILE\.pico-sdk\sdk\*",
        "C:\pico\pico-sdk"
    )
    $foundSdk = Get-Item $sdkCandidates -ErrorAction SilentlyContinue |
        Where-Object { Test-Path "$_\pico_sdk_init.cmake" } |
        Select-Object -First 1
    if ($foundSdk) { $env:PICO_SDK_PATH = $foundSdk.FullName }
}

# Auto-detect ARM GNU Toolchain
if (-not $env:PICO_TOOLCHAIN_PATH) {
    $toolchainCandidates = @(
        "$env:APPDATA\xPacks\@xpack-dev-tools\arm-none-eabi-gcc\*\.content\bin",
        "$env:USERPROFILE\.pico-sdk\toolchain\*\bin"
    )
    $foundToolchain = Get-Item $toolchainCandidates -ErrorAction SilentlyContinue |
        Where-Object { Test-Path "$_\arm-none-eabi-gcc.exe" } |
        Select-Object -First 1
    if ($foundToolchain) { $env:PICO_TOOLCHAIN_PATH = $foundToolchain.FullName }
}

if ($env:PICO_TOOLCHAIN_PATH -and ($env:PATH -notlike "*$env:PICO_TOOLCHAIN_PATH*")) {
    $env:PATH = "$env:PICO_TOOLCHAIN_PATH;$env:PATH"
}

# Auto-detect Ninja
$ninjaCandidates = @(
    "$env:APPDATA\xPacks\@xpack-dev-tools\ninja-build\*\.content\bin",
    "$env:USERPROFILE\.pico-sdk\ninja\*"
)
$foundNinja = Get-Item $ninjaCandidates -ErrorAction SilentlyContinue |
    Where-Object { Test-Path "$_\ninja.exe" } |
    Select-Object -First 1
if ($foundNinja -and ($env:PATH -notlike "*$($foundNinja.FullName)*")) {
    $env:PATH = "$($foundNinja.FullName);$env:PATH"
}

# Auto-detect picotool
if (-not $env:picotool_DIR) {
    $picotoolCandidates = @(
        "$env:USERPROFILE\Desktop\pico\tools\picotool-sdk\picotool",
        "$env:USERPROFILE\.pico-sdk\picotool\*"
    )
    $foundPicotool = Get-Item $picotoolCandidates -ErrorAction SilentlyContinue |
        Where-Object { Test-Path "$_\picotoolConfig.cmake" } |
        Select-Object -First 1
    if ($foundPicotool) { $env:picotool_DIR = $foundPicotool.FullName }
}

$buildDir = Join-Path $PSScriptRoot "build-pico"

$cmakeArgs = @(
    "-S", $PSScriptRoot,
    "-B", $buildDir,
    "-G", "Ninja",
    "-DCMAKE_BUILD_TYPE=Release",
    "-DQSAC_TARGET_PICO=ON",
    "-DQSAC_BUILD_TESTS=ON"
)

if ($env:PICO_SDK_PATH) {
    $cmakeArgs += "-DPICO_SDK_PATH=$($env:PICO_SDK_PATH.Replace('\', '/'))"
}
if ($env:PICO_TOOLCHAIN_PATH) {
    $cmakeArgs += "-DPICO_TOOLCHAIN_PATH=$($env:PICO_TOOLCHAIN_PATH.Replace('\', '/'))"
}
if ($env:picotool_DIR) {
    $cmakeArgs += "-Dpicotool_DIR=$($env:picotool_DIR.Replace('\', '/'))"
}

Write-Host "Configuring build-pico..." -ForegroundColor Cyan
cmake @cmakeArgs
if ($LASTEXITCODE -ne 0) {
    Write-Host "CMake configuration failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "Building build-pico..." -ForegroundColor Cyan
cmake --build $buildDir
if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed!" -ForegroundColor Red
    exit $LASTEXITCODE
}

Write-Host "`nbuild-pico is ready!" -ForegroundColor Green
