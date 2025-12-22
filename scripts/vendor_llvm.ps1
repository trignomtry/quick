$ErrorActionPreference = 'Stop'

$tag = if ($env:LLVM_TAG) { $env:LLVM_TAG } else { 'llvmorg-18.1.4' }
$version = $tag -replace '^llvmorg-'
$prefix = if ($env:LLVM_PREFIX) { $env:LLVM_PREFIX } else { Join-Path -Path (Get-Location) -ChildPath 'llvm/install' }
$prefix = [IO.Path]::GetFullPath($prefix)

$archive = if ($env:LLVM_ARCHIVE) { $env:LLVM_ARCHIVE } else { "clang+llvm-$version-x86_64-pc-windows-msvc.tar.xz" }
$url = "https://github.com/llvm/llvm-project/releases/download/$tag/$archive"

$tmp = New-Item -ItemType Directory -Path ([IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName()))
try {
    $archivePath = Join-Path $tmp $archive
    Write-Host "Downloading LLVM $version from $url"
    Invoke-WebRequest -Uri $url -OutFile $archivePath

    if (Test-Path $prefix) {
        Remove-Item -Recurse -Force $prefix
    }
    New-Item -ItemType Directory -Force -Path $prefix | Out-Null

    & tar -xf $archivePath -C $tmp
    $extracted = Get-ChildItem -Directory -Path $tmp -Filter "clang+llvm-*" | Select-Object -First 1
    if (-not $extracted) {
        throw "Extracted LLVM directory not found in $tmp"
    }

    Copy-Item -Path (Join-Path $extracted.FullName '*') -Destination $prefix -Recurse

    $llvmConfig = Join-Path (Join-Path $prefix 'bin') 'llvm-config.exe'
    if (-not (Test-Path $llvmConfig)) {
        throw "llvm-config.exe not found under $prefix"
    }

    Write-Host "LLVM installed to $prefix"
}
finally {
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
}
