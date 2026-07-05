@echo off
setlocal

cd /d "%~dp0"

set "HOST=127.0.0.1"
set "PORT=4321"
set "URL=http://%HOST%:%PORT%/"
set "RUNNER="

title dear-nikki local dev server

echo.
echo Starting dear-nikki locally...
echo Project: %CD%
echo URL:     %URL%
echo.
echo Keep this window open while using the site.
echo Press Ctrl+C in this window to stop the server.
echo.

where node >nul 2>nul
if errorlevel 1 goto node_missing

where corepack >nul 2>nul
if not errorlevel 1 (
    set "RUNNER=corepack pnpm"
) else (
    where pnpm >nul 2>nul
    if errorlevel 1 goto pnpm_missing
    set "RUNNER=pnpm"
)

if not exist "node_modules\" (
    echo Installing dependencies...
    %RUNNER% install
    if errorlevel 1 goto install_failed
    echo.
)

echo Opening browser shortly...
start "dear-nikki browser opener" powershell -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Sleep -Seconds 3; Start-Process '%URL%'"

%RUNNER% dev --host %HOST% --port %PORT%
set "EXIT_CODE=%ERRORLEVEL%"
echo.
echo Server stopped with exit code %EXIT_CODE%.
pause
exit /b %EXIT_CODE%

:node_missing
echo Node.js was not found.
echo Install Node.js first, then double-click this script again.
pause
exit /b 1

:pnpm_missing
echo pnpm was not found, and Corepack is unavailable.
echo Install pnpm or enable Corepack first, then double-click this script again.
pause
exit /b 1

:install_failed
echo Dependency installation failed.
pause
exit /b 1
