@echo off
setlocal
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0asl-bootstrap-windows-x86_64.ps1" %*
exit /b %ERRORLEVEL%
