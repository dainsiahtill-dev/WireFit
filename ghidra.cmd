@echo off
setlocal
set "JAVA_HOME=%~dp0.tools\native\jdk-21.0.12.1+1"
set "GHIDRA_INSTALL_DIR=%~dp0.tools\native\ghidra_12.1.4_PUBLIC"
if not exist "%JAVA_HOME%\bin\java.exe" (
  echo Wirefit JDK installation is missing. 1>&2
  exit /b 1
)
if not exist "%GHIDRA_INSTALL_DIR%\ghidraRun.bat" (
  echo Wirefit Ghidra installation is missing. 1>&2
  exit /b 1
)
set "PATH=%JAVA_HOME%\bin;%PATH%"
call "%GHIDRA_INSTALL_DIR%\ghidraRun.bat" %*
exit /b %errorlevel%
