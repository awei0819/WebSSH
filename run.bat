@echo off
rem WebSSH portable launcher (Windows): auto-install deps on first run
cd /d "%~dp0"
python -c "import fastapi, uvicorn, paramiko" >nul 2>nul
if errorlevel 1 (
  echo [run.bat] Installing dependencies, please wait...
  pip install -r requirements.txt
)
python WebSSH.py
pause
