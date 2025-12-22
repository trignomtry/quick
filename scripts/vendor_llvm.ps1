$ErrorActionPreference = 'Stop'

$tag = if ($env:LLVM_TAG) { $env:LLVM_TAG } else { 'llvmorg-18.1.8' }
$version = $tag -replace '^llvmorg-'
$prefix = if ($env:LLVM_PREFIX) { $env:LLVM_PREFIX } else { Join-Path -Path (Get-Location) -ChildPath 'llvm/install' }
$prefix = [IO.Path]::GetFullPath($prefix)

$archive = "LLVM-$version-win64.exe"
$url = "https://github.com/llvm/llvm-project/releases/download/$tag/$archive"

$tmp = New-Item -ItemType Directory -Path ([IO.Path]::Combine([IO.Path]::GetTempPath(), [IO.Path]::GetRandomFileName()))
try {
    $installer = Join-Path $tmp $archive
    Write-Host "Downloading LLVM $version from $url"
    Invoke-WebRequest -Uri $url -OutFile $installer

    if (Test-Path $prefix) {
        Remove-Item -Recurse -Force $prefix
    }
    New-Item -ItemType Directory -Force -Path $prefix | Out-Null

    $args = @('/S', "/D=$prefix")
    $proc = Start-Process -FilePath $installer -ArgumentList $args -Wait -PassThru -NoNewWindow
    if ($proc.ExitCode -ne 0) {
        throw "LLVM installer exited with code $($proc.ExitCode)"
    }

    $llvmConfig = Join-Path (Join-Path $prefix 'bin') 'llvm-config.exe'
    if (-not (Test-Path $llvmConfig)) {
        throw "llvm-config.exe not found under $prefix"
    }

    Write-Host "LLVM installed to $prefix"
}
finally {
    if (Test-Path $tmp) { Remove-Item -Recurse -Force $tmp }
}
