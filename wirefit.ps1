$WirefitRuntime = Join-Path $PSScriptRoot '.tools/runtime/node_modules/node-win-x64/bin/node.exe'
if (-not (Test-Path -LiteralPath $WirefitRuntime -PathType Leaf)) {
    $WirefitRuntime = (Get-Command node -ErrorAction Stop).Source
}
& $WirefitRuntime (Join-Path $PSScriptRoot 'apps/cli/bin/wirefit.js') @args
exit $LASTEXITCODE
