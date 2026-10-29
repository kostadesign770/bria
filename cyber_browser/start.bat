@echo off
REM Cyber Browser launcher for Windows
cd /d "%~dp0.."
python -m cyber_browser %*
if errorlevel 1 pause
