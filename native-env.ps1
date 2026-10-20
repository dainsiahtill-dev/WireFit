$ErrorActionPreference = 'Stop'
$WirefitNativeConfig = Join-Path $PSScriptRoot '.local/native-installation.json'
$WirefitNativeRuntime = [System.IO.File]::ReadAllText($WirefitNativeConfig, [System.Text.UTF8Encoding]::new($false)) | ConvertFrom-Json
if (-not (Test-Path -LiteralPath (Join-Path $WirefitNativeRuntime.java_home 'bin/java.exe') -PathType Leaf)) {
    throw 'The configured Wirefit JDK is missing.'
}
if (-not (Test-Path -LiteralPath (Join-Path $WirefitNativeRuntime.ghidra_install_dir 'support/analyzeHeadless.bat') -PathType Leaf)) {
    throw 'The configured Wirefit Ghidra installation is missing.'
}
$env:JAVA_HOME = $WirefitNativeRuntime.java_home
$env:GHIDRA_INSTALL_DIR = $WirefitNativeRuntime.ghidra_install_dir
$WirefitNativeJavaBin = Join-Path $env:JAVA_HOME 'bin'
if (-not (($env:Path -split ';') -contains $WirefitNativeJavaBin)) {
    $env:Path = $WirefitNativeJavaBin + ';' + $env:Path
}
Write-Output "JAVA_HOME=$env:JAVA_HOME"
Write-Output "GHIDRA_INSTALL_DIR=$env:GHIDRA_INSTALL_DIR"
