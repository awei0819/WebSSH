#!/usr/bin/env python3
"""
WebSSH —— 好用且安全的网页版 Shell 连接工具

入口：装配应用（路由/中间件/页面），业务实现见 webssh/ 包各模块。
    webssh/core.py   配置、凭据加密、认证/用户体系、主机资产存储
    webssh/ssh.py    asyncssh 连接、会话管理、WebSocket 终端
    webssh/files.py  SFTP 文件接口
    webssh/page.py   前端页面

依赖：
    pip install fastapi "uvicorn[standard]" asyncssh
运行：
    python WebSSH.py            # 默认 https://0.0.0.0:8080
    python WebSSH.py --no-tls   # 回退 http
"""
import os
import sys
import threading
import webbrowser

import uvicorn
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from core import VERSION, install_security_headers  # noqa: F401 （测试引用）
from core import router as core_router
from ssh import router as ssh_router
from files import router as files_router
from page import HTML
import core, ssh, files as files_mod  # noqa: F401 （测试经 WebSSH.* 访问内部）

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
install_security_headers(app)
app.include_router(core_router)
app.include_router(ssh_router)
app.include_router(files_router)


@app.get("/")
async def index():
    return HTMLResponse(HTML)


if __name__ == "__main__":
    HOST = "0.0.0.0"     # 仅本机使用改成 "127.0.0.1"
    PORT = 8080
    USE_TLS = "--no-tls" not in sys.argv   # 默认 HTTPS，加 --no-tls 回退 HTTP
    ssl_kw = {}
    if USE_TLS:
        from ssh import ensure_selfsigned_cert
        cert_p, key_p = ensure_selfsigned_cert()
        ssl_kw = {"ssl_certfile": cert_p, "ssl_keyfile": key_p}
        print(f"HTTPS 证书： {cert_p}（自签，浏览器首次访问需手动信任）")
    scheme = "https" if USE_TLS else "http"
    threading.Timer(1.2, lambda: webbrowser.open(f"{scheme}://127.0.0.1:{PORT}/")).start()
    print(f"WebSSH {VERSION} 启动中： {scheme}://127.0.0.1:{PORT}/（已监听 0.0.0.0，局域网可通过 {scheme}://<本机IP>:{PORT} 访问）")
    print(f"默认管理员： admin / Admin#1234（加盐哈希存于 data/auth.json，用户管理在设置里）")
    print(f"数据目录： {core.DATA_DIR}   启动参数： --no-tls 可回退 HTTP")
    print("若浏览器未自动打开，请手动访问上面的地址。按 Ctrl+C 退出。")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning", server_header=False, **ssl_kw)
