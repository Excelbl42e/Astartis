@echo off
:: install-protect-service.bat
:: Installs astartis_bridge as a Windows service that runs on boot.
:: Must be run as Administrator.
::
:: The service starts with: astartis_bridge.exe --protect --dashboard --daemon
:: so the dashboard is always accessible at http://127.0.0.1:9876/
::
:: Usage:
::   install-protect-service.bat          — install and start
::   install-protect-service.bat remove   — stop and remove

setlocal
set SERVICE_NAME=AstartisProtect
set SERVICE_DISPLAY=Astartis Real-Time Protection
set SERVICE_DESC=Astartis v3.1 - 77-agent AI cybersecurity protection. Monitors Event Log, file system, and network entropy. Powered by IBM Granite.
set EXE_PATH=%~dp0..\build\Release\astartis_bridge.exe

:: Resolve to absolute path
for %%F in ("%EXE_PATH%") do set EXE_PATH=%%~fF

if /i "%1"=="remove" goto :remove

:: ---- INSTALL ----
echo.
echo  Astartis Protection Service Installer
echo  ======================================
echo  Service : %SERVICE_NAME%
echo  Binary  : %EXE_PATH%
echo.

if not exist "%EXE_PATH%" (
    echo ERROR: Binary not found at:
    echo   %EXE_PATH%
    echo Please build first:
    echo   cmake --build build --config Release --target astartis_bridge
    exit /b 1
)

:: Check for admin
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo ERROR: This script must be run as Administrator.
    echo Right-click and select "Run as administrator".
    exit /b 1
)

:: Remove existing service if present
sc query %SERVICE_NAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo Removing existing service...
    sc stop %SERVICE_NAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    sc delete %SERVICE_NAME% >nul 2>&1
    timeout /t 1 /nobreak >nul
)

:: Create service — binPath includes all flags
sc create %SERVICE_NAME% ^
    binPath= "\"%EXE_PATH%\" --protect --dashboard --daemon" ^
    start= auto ^
    DisplayName= "%SERVICE_DISPLAY%"

if %errorlevel% neq 0 (
    echo ERROR: sc create failed.
    exit /b 1
)

:: Set description
sc description %SERVICE_NAME% "%SERVICE_DESC%"

:: Configure recovery: restart on failure (3 attempts, 60s delay)
sc failure %SERVICE_NAME% reset= 86400 actions= restart/60000/restart/60000/restart/120000

:: Start immediately
echo Starting service...
sc start %SERVICE_NAME%

if %errorlevel% equ 0 (
    echo.
    echo  SUCCESS: Astartis Protection Service is running.
    echo.
    echo  Dashboard : http://127.0.0.1:9876/
    echo  Logs      : %%TEMP%%\astartis_bridge.log
    echo  PID file  : %%TEMP%%\astartis_bridge.pid
    echo.
    echo  The service will restart automatically on reboot and after crashes.
    echo  To stop: sc stop %SERVICE_NAME%
    echo  To uninstall: %~nx0 remove
) else (
    echo WARNING: Service installed but failed to start immediately.
    echo Check: %%TEMP%%\astartis_bridge.log
)
goto :eof

:: ---- REMOVE ----
:remove
echo Stopping and removing %SERVICE_NAME%...
sc stop %SERVICE_NAME% >nul 2>&1
timeout /t 3 /nobreak >nul
sc delete %SERVICE_NAME%
if %errorlevel% equ 0 (
    echo Service removed.
) else (
    echo ERROR: Could not remove service. Check it exists: sc query %SERVICE_NAME%
)
