@echo off
rem SOInsight Web console launcher - double-click to start the local server.
setlocal
cd /d %~dp0..
where python >nul 2>nul
if errorlevel 1 (
  echo Python was not found on PATH. Install Python 3.10+ and retry.
  pause
  exit /b 1
)
python web\server.py %*
if errorlevel 1 pause
endlocal
