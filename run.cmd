@echo off
rem Code Guardian launcher for cmd.exe: same commands as ./run.sh (run, run docker, run test, run doctor, ...).
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
exit /b %ERRORLEVEL%
