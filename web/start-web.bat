@echo off
rem SOInsight Web console launcher - double-click to start the local server.
rem Prefers the "py -3" launcher: on machines with several Python installs the
rem bare "python" may be a version without PyYAML, which breaks the catalog.
setlocal
cd /d %~dp0..

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python was not found on PATH. Install Python 3.10+ and retry.
  pause
  exit /b 1
)

%PY% web\server.py %*
if errorlevel 1 pause
endlocal
