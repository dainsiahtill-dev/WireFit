@echo off
setlocal
set "WIREFIT_WEB_NODE=%~dp0.tools\runtime\node_modules\node-win-x64\bin\node.exe"
if not exist "%WIREFIT_WEB_NODE%" set "WIREFIT_WEB_NODE=node"
"%WIREFIT_WEB_NODE%" "%~dp0apps\cli\bin\wirefit.js" web %*
exit /b %errorlevel%
