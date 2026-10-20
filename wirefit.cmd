@echo off
setlocal
set "WIREFIT_NODE=%~dp0.tools\runtime\node_modules\node-win-x64\bin\node.exe"
if not exist "%WIREFIT_NODE%" set "WIREFIT_NODE=node"
"%WIREFIT_NODE%" "%~dp0apps\cli\bin\wirefit.js" %*
exit /b %errorlevel%
