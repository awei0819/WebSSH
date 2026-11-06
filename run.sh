#!/bin/sh
# WebSSH 便携启动脚本（Linux / macOS）：venv 隔离 + 首次自动装依赖
cd "$(dirname "$0")"

# ==== 地址绑定与端口（按需修改）====
WEBSSH_HOST=0.0.0.0
WEBSSH_PORT=8089
export WEBSSH_HOST WEBSSH_PORT
# ==================================

PY=python3
command -v python3 >/dev/null 2>&1 || PY=python

# 优先使用独立虚拟环境，不污染系统 Python（规避麒麟/UOS 的版本冲突）
if [ ! -x .venv/bin/python ]; then
  "$PY" -m venv .venv 2>/dev/null || rm -rf .venv
fi
[ -x .venv/bin/python ] && PY=.venv/bin/python

if ! "$PY" -c "import fastapi, uvicorn, paramiko" 2>/dev/null; then
  echo "[run.sh] 正在安装依赖，请稍候..."
  "$PY" -m pip install -r requirements.txt || exit 1
fi
exec "$PY" src/main.py "$@"
