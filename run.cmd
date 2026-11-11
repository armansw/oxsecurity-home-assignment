@echo off
rem Code Guardian launcher for cmd.exe and PowerShell: same commands as ./run.sh (run.cmd, run.cmd test, run.cmd doctor, ...).
setlocal
rem Started from PowerShell 7, Windows PowerShell would inherit its module path and fail to load built-in modules.
set "PSModulePath="
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
exit /b %ERRORLEVEL%
