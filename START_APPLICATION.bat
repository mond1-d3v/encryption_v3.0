@echo off
title Unbreakable Encryption - Interface
echo.
echo 🛡️ Lancement de l'interface...
echo ⚡ Unbreakable Encryption System v3.0
echo.
cd /d "%~dp0"
python GUI.py
if errorlevel 1 (
    echo.
    echo ❌ Erreur de lancement.
    echo 🔍 Vérifications:
    echo    - Python 3.6+ installé
    echo    - Fichiers présents dans le dossier
    echo    - Permissions d'exécution
    echo.
    pause
)
