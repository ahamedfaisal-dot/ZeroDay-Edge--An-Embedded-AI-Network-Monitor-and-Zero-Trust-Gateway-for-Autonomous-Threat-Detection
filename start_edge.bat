@echo off
title ZeroDay-Edge Server
echo ========================================================
echo   Starting ZeroDay-Edge Server on Windows Laptop...
echo   Dashboard URL: http://localhost:5000
echo ========================================================
cd /d "%~dp0"
python app.py
pause
