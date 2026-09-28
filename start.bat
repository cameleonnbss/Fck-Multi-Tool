@echo off
chcp 65001 >nul 2>&1
title FCK MULTI TOOL
cd /d "%~dp0"

start "" "https://github.com/cameleonnbss"
start "" "https://github.com/cameleonnbss/Fck-Multi-Tool"

where python >nul 2>nul
if errorlevel 1 (
    echo   [x] Python introuvable. Lancez d'abord setup.bat
    pause
    exit /b 1
)

python main.py %*
if errorlevel 1 (
    echo.
    echo   [x] Le tool s'est arrete avec une erreur.
    pause
)
