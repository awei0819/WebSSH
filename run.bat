@echo off
rem WebSSH 便携启动脚本（Windows）：首次运行自动安装依赖
cd /d "%~dp0"

rem ==== 地址绑定与端口（按需修改）====
set WEBSSH_HOST=0.0.0.0
set WEBSSH_PORT=8089
rem ==================================

python -c "import fastapi, uvicorn, paramiko" >nul 2>nul
if errorlevel 1 (
  echo [run.bat] Installing dependencies, please wait...
  pip install -r requirements.txt
)
python src\main.py %*
pause
