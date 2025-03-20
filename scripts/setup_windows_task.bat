@echo off
REM Setup GateKeeper Scheduler as a Windows Scheduled Task
REM Run this script as Administrator

echo Setting up GateKeeper Scheduler Task...

REM Get the current directory
set "SCRIPT_DIR=%~dp0"
set "GATEKEEPER_DIR=%SCRIPT_DIR%.."
cd %GATEKEEPER_DIR%

REM Create the scheduled task
schtasks /Create /SC DAILY /TN "GateKeeper/ScheduledScanner" /TR "python %GATEKEEPER_DIR%\scheduled_scan.py run" /ST 00:00 /RU "SYSTEM" /RL HIGHEST /F

echo.
echo Task creation complete.
echo To view the task, open Task Scheduler and look for "GateKeeper/ScheduledScanner"
echo.
echo You can modify the task settings in Task Scheduler if needed.
pause 