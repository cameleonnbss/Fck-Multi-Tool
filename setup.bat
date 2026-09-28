@echo off
chcp 65001 >nul 2>&1
title FCK MULTI TOOL - SETUP
cd /d "%~dp0"

echo.
echo   =============================================
echo      FCK MULTI TOOL - Installation
echo   =============================================
echo.

where python >nul 2>nul
if errorlevel 1 (
    echo   [x] Python introuvable. Installez Python 3.8+ :
    echo       https://www.python.org/downloads/
    pause
    exit /b 1
)

echo   [~] Mise a jour de pip...
python -m pip install --upgrade pip --quiet

echo   [~] Installation des dependances...
python -m pip install -r requirements.txt --quiet

echo   [~] Verification des modules...
python main.py --selftest

echo.
echo   [+] Setup termine. Lancez start.bat pour ouvrir le tool.
echo.
pause
