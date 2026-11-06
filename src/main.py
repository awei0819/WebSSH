#!/usr/bin/env python3
"""
WebSSH —— 好用且安全的网页版 Shell 连接工具

入口：装配应用（路由/中间件/页面），业务实现见 src/ 下各模块。
    src/core.py   配置、凭据加密、认证/用户体系、主机资产存储
    src/ssh.py    asyncssh 连接、会话管理、WebSocket 终端
    src/files.py  SFTP 文件接口
    src/page.py   前端页面

依赖：
    pip install -r requirements.txt
运行：
    python src/main.py            # 默认 https://0.0.0.0:8089
    python src/main.py --no-tls   # 回退 http
    绑定地址/端口：环境变量 WEBSSH_HOST / WEBSSH_PORT（run.bat / run.sh 已内置可改）
"""
import os
import sys
import threading
import webbrowser

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from core import VERSION, install_security_headers
from core import router as core_router
from ssh import router as ssh_router
from files import router as files_router
from page import HTML
import core    # 启动横幅打印 core.DATA_DIR

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
install_security_headers(app)
app.include_router(core_router)
app.include_router(ssh_router)
app.include_router(files_router)


@app.get("/")
async def index():
    return HTMLResponse(HTML)


def _build_id() -> str:
    """构建标识（送审/排障用）：包内 build_id.txt 优先（发布包自证，避免解压进
    某个 git 仓库时误报仓库 id）→ git describe（源码运行）→ 空"""
    import subprocess
    here = os.path.dirname(os.path.abspath(__file__))
    try:
        with open(os.path.join(here, "build_id.txt"), encoding="ascii") as f:
            return f.read().strip()
    except OSError:
        pass
    try:
        r = subprocess.run(["git", "describe", "--always", "--dirty"],
                           capture_output=True, text=True, timeout=5, cwd=here)
        if r.returncode == 0 and r.stdout.strip():
            return r.stdout.strip()
    except Exception:
        pass
    return ""


if __name__ == "__main__":
    # 地址与端口由启动脚本（run.bat / run.sh）经环境变量下发，便于按机调整；
    # 直接 python src/main.py 运行时取默认 0.0.0.0:8089
    HOST = os.environ.get("WEBSSH_HOST", "0.0.0.0")
    try:
        PORT = int(os.environ.get("WEBSSH_PORT", "8089"))
    except ValueError:
        PORT = 8089
    USE_TLS = "--no-tls" not in sys.argv   # 默认 HTTPS，加 --no-tls 回退 HTTP
    ssl_kw = {}
    if USE_TLS:
        from ssh import ensure_selfsigned_cert
        cert_p, key_p = ensure_selfsigned_cert()
        ssl_kw = {"ssl_certfile": cert_p, "ssl_keyfile": key_p}
        print(f"HTTPS 证书： {cert_p}（自签，浏览器首次访问需手动信任）")
    scheme = "https" if USE_TLS else "http"
    threading.Timer(1.2, lambda: webbrowser.open(f"{scheme}://127.0.0.1:{PORT}/")).start()
    bid = _build_id()
    tag_txt = f"（build {bid}）" if bid else ""
    print(f"WebSSH {VERSION}{tag_txt} 启动中： {scheme}://127.0.0.1:{PORT}/（已监听 {HOST}，局域网可通过 {scheme}://<本机IP>:{PORT} 访问）")
    print(f"默认管理员： admin / Admin#1234（加盐哈希存于 data/auth.json，用户管理在设置里）")
    print(f"数据目录： {core.DATA_DIR}   启动参数： --no-tls 可回退 HTTP")
    print("若浏览器未自动打开，请手动访问上面的地址。按 Ctrl+C 退出。")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning", server_header=False, **ssl_kw)
