#!/usr/bin/env python3
"""
端到端测试：内置一个临时 paramiko SSH/SFTP 服务器（回显 shell + 临时目录 SFTP），
验证：手动连接终端、主机资产快捷连接、SFTP 列目录/上传/下载/删除、会话隔离。

运行： python test_e2e.py
"""
import asyncio
import json
import os
import socket
import sys
import tempfile
import threading
import time
from urllib.parse import quote

import httpx
import paramiko
import uvicorn
import websockets.sync.client as wsclient
from websockets.exceptions import ConnectionClosed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sys as _sys
_sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
# 数据目录隔离必须在 import main/core 之前：core 在导入时就读取 secret.key/auth.json。
# e2e 绝不触碰真实 data/（历史上测试后 rm -rf 清理曾误删用户真实主机数据）
os.environ["WEBSSH_DATA_DIR"] = tempfile.mkdtemp(prefix="webssh_e2e_data_")
import main as WebSSH      # 入口模块（src/main.py）
import core

PORT = 2222
USER, PASS = "tester", "secret"


# ---------------- SFTP 后端：映射到本地临时目录 ----------------
class DummySFTP(paramiko.SFTPServerInterface):
    root = None
    _open_lock = threading.Lock()   # 串行化 os.open（Windows 句柄竞争）

    def _real(self, path):
        root = os.path.realpath(self.root)
        real = os.path.realpath(os.path.join(root, path.lstrip("/")))
        if not (real == root or real.startswith(root + os.sep)):
            raise OSError(13, "permission denied")
        return real

    def _deny_check(self, path):
        """模拟 root 专属目录：路径中含 secret 段则返回权限不足（普通用户视角）"""
        if "secret" in path.replace("\\", "/").split("/"):
            raise OSError(13, "permission denied")

    def realpath(self, path):
        root = os.path.realpath(self.root)
        rel = os.path.relpath(self._real(path), root).replace(os.sep, "/")
        return "/" if rel == "." else "/" + rel

    def list_folder(self, path):
        try:
            self._deny_check(path)
            names = os.listdir(self._real(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        out = []
        for n in names:
            attr = paramiko.SFTPAttributes.from_stat(os.stat(os.path.join(self._real(path), n)))
            attr.filename = n
            out.append(attr)
        return out

    def stat(self, path):
        try:
            self._deny_check(path)
            return paramiko.SFTPAttributes.from_stat(os.stat(self._real(path)))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)

    def lstat(self, path):
        return self.stat(path)

    def open(self, path, flags, attr):
        try:
            self._deny_check(path)
            flags |= getattr(os, "O_BINARY", 0)
            mode = getattr(attr, "st_mode", None) or 0o666
            with DummySFTP._open_lock:
                fd = os.open(self._real(path), flags, mode)
        except OSError as e:
            # 注意：paramiko 5.x 已移除 SFTPServer.from_oserror，这里用 convert_errno
            return paramiko.SFTPServer.convert_errno(e.errno)
        if flags & os.O_WRONLY:
            s = "ab" if flags & os.O_APPEND else "wb"
        elif flags & os.O_RDWR:
            s = "a+b" if flags & os.O_APPEND else "r+b"
        else:
            s = "rb"
        try:
            f = os.fdopen(fd, s)
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        h = paramiko.SFTPHandle(flags)
        h.readfile = f
        h.writefile = f
        return h

    def remove(self, path):
        try:
            os.remove(self._real(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK

    def rmdir(self, path):
        try:
            os.rmdir(self._real(path))
        except OSError as e:
            return paramiko.SFTPServer.convert_errno(e.errno)
        return paramiko.SFTP_OK


class EchoSSHServer(paramiko.ServerInterface):
    """回显 shell：终端交互测试用"""

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        return (paramiko.AUTH_SUCCESSFUL
                if (username == USER and password == PASS) else paramiko.AUTH_FAILED)

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_pty_request(self, *a):
        return True

    def check_channel_shell_request(self, channel):
        def run():
            channel.send("welcome to test\r\n$ ")
            while True:
                if channel.recv_ready():
                    d = channel.recv(4096)
                    if not d or b"exit" in d.lower():
                        break
                    if b"die" in d.lower():
                        channel.get_transport().close()   # 模拟远端异常掉线（直接断 TCP，无优雅关闭）
                        return
                    channel.send(d)
                else:
                    time.sleep(0.03)
            channel.close()
        threading.Thread(target=run, daemon=True).start()
        return True


def start_test_ssh_server(tmpdir):
    DummySFTP.root = tmpdir
    host_key = paramiko.RSAKey.generate(2048)
    ls = socket.socket()
    ls.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    ls.bind(("127.0.0.1", PORT))
    ls.listen(5)

    def handle(conn):
        t = paramiko.Transport(conn)
        t.add_server_key(host_key)
        t.set_subsystem_handler("sftp", paramiko.SFTPServer, DummySFTP)
        try:
            t.start_server(server=EchoSSHServer())
        except Exception:
            t.close()
            return
        chan = t.accept(30)
        if chan is not None:
            while t.is_active():
                time.sleep(0.1)
        t.close()

    def loop():
        while True:
            conn, _ = ls.accept()
            threading.Thread(target=handle, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return host_key



# ---------------- 应用测试服务器（单事件循环，与生产一致） ----------------
APP_PORT = 8123
WS_BASE = f"ws://127.0.0.1:{APP_PORT}"


def start_app_server():
    config = uvicorn.Config(WebSSH.app, host="127.0.0.1", port=APP_PORT, log_level="error")
    server = uvicorn.Server(config)
    threading.Thread(target=server.run, daemon=True).start()
    for _ in range(60):
        if server.started:
            return
        time.sleep(0.1)
    raise RuntimeError("应用服务器启动失败")


def ws_open(cookie, origin=None):
    headers = {"Cookie": cookie} if cookie else {}
    if origin:
        headers["Origin"] = origin
    try:
        return wsclient.connect(WS_BASE + "/ws", additional_headers=headers)
    except TypeError:
        return wsclient.connect(WS_BASE + "/ws", extra_headers=headers)


def ws_close_code(cookie, origin=None):
    """连接后等服务器主动关闭，返回关闭码（连接未被关闭/异常断开则断言失败）"""
    w = ws_open(cookie, origin)
    try:
        try:
            m = w.recv(timeout=5)
            raise AssertionError(f"ws 应被关闭，却收到消息: {m}")
        except ConnectionClosed as e:
            assert e.rcvd is not None, f"异常断开（无关闭帧，浏览器视角 1006）: {e}"
            return e.rcvd.code
    finally:
        try:
            w.close()
        except Exception:
            pass


def recv_until(ws, typ, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        try:
            m = json.loads(ws.recv(timeout=max(0.1, end - time.time())))
        except TimeoutError:
            break
        if m.get("type") == typ:
            return m
        if m.get("type") == "error":
            raise AssertionError("ws error: " + m.get("message", ""))
    raise AssertionError("未等到消息类型 " + typ)


def collect_data(ws, needle, timeout=10):
    end = time.time() + timeout
    buf = ""
    while time.time() < end:
        try:
            m = json.loads(ws.recv(timeout=max(0.1, end - time.time())))
        except TimeoutError:
            break
        if m.get("type") == "data":
            buf += m.get("data", "")
            if needle in buf:
                return buf
        if m.get("type") in ("closed", "error"):
            break
    return buf


def login(base, user, password):
    with httpx.Client(base_url=base, verify=False, timeout=15) as cl:
        r = cl.post("/api/login", json={"user": user, "password": password})
        assert r.status_code == 200, (user, r.text)
        return "webssh_session=" + cl.cookies.get("webssh_session", "")


def assert_no_await_inside_sync_with():
    """静态守护：async 函数内，同步 with 块（threading.Lock 等）不得跨 await 持有。
    async with（asyncio.Lock/Semaphore）不受限；嵌套函数体内的 await 不属于本层执行流。
    与 ruff 互补：F821 抓未定义名称（stat_path 类事故），本条抓持锁跨 await（N1 类事故）。"""
    import ast
    here = os.path.dirname(os.path.abspath(__file__))
    mods = []
    for name in ("core.py", "ssh.py", "files.py", "main.py"):
        for rel in (name, os.path.join("src", name)):   # 兼容仓库布局与发布包平铺布局
            p = os.path.join(here, rel)
            if os.path.exists(p):
                mods.append((name, p))
                break

    def direct_awaits(with_node):          # 收集 with 块执行流上的 await（跳过嵌套函数）
        found, stack = [], list(ast.iter_child_nodes(with_node))
        while stack:
            n = stack.pop()
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(n, ast.Await):
                found.append(n.lineno)
            stack.extend(ast.iter_child_nodes(n))
        return found

    offenders = []
    for name, path in mods:
        tree = ast.parse(open(path, encoding="utf-8").read())
        for fn in ast.walk(tree):
            if not isinstance(fn, ast.AsyncFunctionDef):
                continue
            for node in ast.walk(fn):
                if isinstance(node, ast.With):        # 只限同步 with；ast.AsyncWith 合法
                    lines = direct_awaits(node)
                    for ln in lines:
                        offenders.append(f"{name} {fn.name}() 行{ln}")
    assert not offenders, "同步 with 块内跨 await 持锁: " + "; ".join(offenders)


def main():
    def watchdog():
        time.sleep(120)
        print("TIMEOUT: 测试卡死")
        os._exit(1)
    threading.Thread(target=watchdog, daemon=True).start()

    assert_no_await_inside_sync_with()
    print("0) 静态守护：无跨 await 持锁     OK")
    # 隔离守护：数据目录必须落在临时区（防止未来改动让 e2e 又碰真实 data/）
    assert core.DATA_DIR == os.environ["WEBSSH_DATA_DIR"] and "webssh_e2e_data_" in core.DATA_DIR
    print("0) 数据目录隔离               OK")

    tmpdir = tempfile.mkdtemp(prefix="webssh_e2e_")
    os.makedirs(os.path.join(tmpdir, "子目录"))
    start_test_ssh_server(tmpdir)
    start_app_server()
    time.sleep(0.3)
    BASE = f"http://127.0.0.1:{APP_PORT}"
    admin_ck = login(BASE, "admin", "Admin#1234")
    hid = None
    c = httpx.Client(base_url=BASE, verify=False, timeout=60, headers={"Cookie": admin_ck})

    try:
        # ===== 0) 登录认证 =====
        with httpx.Client(base_url=BASE, verify=False) as c0:
            assert c0.get("/api/hosts").status_code == 401
            assert c0.get("/api/files?token=x").status_code == 401
            assert c0.post("/api/login", json={"user": "admin", "password": "wrong"}).status_code == 401
        assert c.get("/api/hosts").status_code == 200
        print("0) 登录认证 OK")

        # ===== 1) 手动连接 + 终端回显 =====
        with ws_open(admin_ck) as ws:
            ws.send(json.dumps({"type": "connect", "host": "127.0.0.1", "port": PORT,
                                "username": USER, "password": PASS, "trust_host_key": True}))
            m = recv_until(ws, "connected")
            tk1 = m["token"]
            assert f"{USER}@127.0.0.1" in m["label"]
            ws.send(json.dumps({"type": "input", "data": "hello-e2e"}))
            seen = collect_data(ws, "hello-e2e")
            assert "hello-e2e" in seen and "welcome" in seen, seen[:80]
            print("1) 手动连接 + 终端回显        OK")
        assert c.get(f"/api/files?token={tk1}&path=.").status_code == 409
        print("   断开后 token 失效(409)       OK")

        # ===== 2) 主机快捷连接 =====
        r = c.post("/api/hosts", json={"name": "e2e测试机", "host": "127.0.0.1", "port": PORT,
                                       "username": USER, "password": PASS, "trust": True})
        assert r.status_code == 201, r.text
        hid = r.json()["id"]
        with ws_open(admin_ck) as ws:
            ws.send(json.dumps({"type": "connect", "host_id": hid}))
            m = recv_until(ws, "connected")
            tk = m["token"]
            assert "e2e测试机" in m["label"]
            print("2) 主机快捷连接(仅传 host_id) OK")

            # ===== 3) SFTP：列目录 / 上传 / 下载 / 删除 =====
            q = f"token={tk}"
            r = c.get(f"/api/files?{q}&path=.")
            assert r.status_code == 200, r.text
            base = r.json()["path"]
            names = [e["name"] for e in r.json()["entries"]]
            assert "子目录" in names
            assert any(e["is_dir"] and e["name"] == "子目录" for e in r.json()["entries"])

            content = "你好 webssh，e2e 上传内容 12345"
            r = c.put(f"/api/upload?{q}&path={quote(base)}&name=demo.txt", content=content.encode())
            assert r.status_code == 200 and r.json()["written"] == len(content.encode()), r.text

            r = c.get(f"/api/files?{q}&path={quote(base)}")
            entry = next(e for e in r.json()["entries"] if e["name"] == "demo.txt")
            assert entry["size"] == len(content.encode())

            # 下载预检：存在（回大小）/ 不存在（不报错）
            r = c.get(f"/api/stat?{q}&path={quote(base + '/demo.txt')}")
            assert r.status_code == 200 and r.json()["exists"] is True, r.text
            assert r.json()["size"] == len(content.encode())
            r = c.get(f"/api/stat?{q}&path={quote(base + '/no_such_file')}")
            assert r.status_code == 200 and r.json()["exists"] is False

            r = c.get(f"/api/download?{q}&path={quote(base + '/demo.txt')}")
            assert r.status_code == 200 and r.content.decode() == content
            assert "demo.txt" in r.headers["content-disposition"]

            r = c.delete(f"/api/files?{q}&path={quote(base + '/demo.txt')}")
            assert r.status_code == 200
            r = c.get(f"/api/files?{q}&path={quote(base)}")
            assert all(e["name"] != "demo.txt" for e in r.json()["entries"])

            r = c.put(f"/api/upload?{q}&path={quote(base)}&name=../evil", content=b"x")
            assert r.status_code == 400
            # 目标无写权限（路径含 secret 段）：必须 403，且绝不能走"创建"分支清空文件
            r = c.put(f"/api/upload?{q}&path={quote(base)}&name=secret", content=b"x")
            assert r.status_code == 403, r.text
            print("3) SFTP 列表/上传/下载/删除   OK")

            # ===== 3.5) 分片乱序上传 + 下载完整性 =====
            import hashlib
            data = os.urandom(3 * 1024 * 1024)
            part = 1 << 20
            for off in (2 * part, part, 0):
                r = c.put(f"/api/upload?{q}&path={quote(base)}&name=big.bin&offset={off}",
                          content=data[off:off + part])
                assert r.status_code == 200, (off, r.text)
            r = c.get(f"/api/download?{q}&path={quote(base + '/big.bin')}")
            assert r.status_code == 200 and len(r.content) == len(data)
            assert hashlib.sha256(r.content).digest() == hashlib.sha256(data).digest()
            r = c.put(f"/api/upload?{q}&path={quote(base)}&name=empty.txt&offset=0", content=b"")
            assert r.status_code == 200
            r = c.get(f"/api/download?{q}&path={quote(base + '/empty.txt')}")
            assert r.status_code == 200 and r.content == b""
            small = os.urandom(2 * 256 * 1024)
            errs = []

            def up_part(off, chunk):
                try:
                    rr = c.put(f"/api/upload?{q}&path={quote(base)}&name=conc.bin&offset={off}",
                               content=chunk)
                    if rr.status_code != 200:
                        errs.append((off, rr.status_code, rr.text))
                except Exception as e:
                    errs.append((off, repr(e)))

            ths = [threading.Thread(target=up_part, args=(o, small[o:o + 256 * 1024]))
                   for o in (0, 256 * 1024)]
            [t.start() for t in ths]
            [t.join() for t in ths]
            assert not errs, errs
            r = c.get(f"/api/download?{q}&path={quote(base + '/conc.bin')}")
            assert r.status_code == 200 and r.content == small
            print("3.5) 分片乱序/并发上传+下载完整性 OK")

        # ===== 4) 认证失败错误回传 =====
        with ws_open(admin_ck) as ws:
            ws.send(json.dumps({"type": "connect", "host": "127.0.0.1", "port": PORT,
                                "username": USER, "password": "wrong", "trust_host_key": True}))
            m = recv_until(ws, "error")
            assert "Auth" in m.get("message", ""), m
            print("4) 认证失败错误回传          OK")

        # ===== 5) 多用户 =====
        assert c.post("/api/users", json={"user": "u1", "password": "User#12345"}).status_code == 201
        u1_ck = login(BASE, "u1", "User#12345")
        cu = httpx.Client(base_url=BASE, verify=False, timeout=60,
                          headers={"Cookie": u1_ck})
        assert cu.get("/api/me").json() == {"user": "u1", "admin": False}
        assert cu.get("/api/users").status_code == 403
        assert cu.get("/api/hosts").json() == []
        with ws_open(u1_ck) as ws:
            ws.send(json.dumps({"type": "connect", "host_id": hid}))
            m = recv_until(ws, "error")
            assert "不存在" in m.get("message", ""), m
        r = cu.post("/api/hosts",
                    json={"name": "u1机", "host": "127.0.0.1", "port": PORT,
                    "username": USER, "password": PASS})
        assert r.status_code == 201, r.text
        u1hid = r.json()["id"]
        assert "u1机" not in [h["name"] for h in c.get("/api/hosts").json()]
        with ws_open(u1_ck) as ws:
            ws.send(json.dumps({"type": "connect", "host_id": u1hid}))
            recv_until(ws, "connected")
            print("5) 多用户隔离/越权防护        OK")

            # ===== 5.5) 删除用户 → 其活跃终端被强制断开 + 登录态作废 =====
            # （回归：Session.close 曾是 async def 被同步调用，连接实际关不掉）
            assert c.delete("/api/users/u1").status_code == 200
            recv_until(ws, "closed")
            assert cu.get("/api/me").status_code == 401    # 该用户全部 Cookie 立即作废
            print("5.5) 删除用户踢线+登录态作废  OK")

        # ===== 5.7) 改密×应急重置竞态：管理员的重置不能被持旧密码者覆盖 =====
        # （回归：is not rec 身份检查对"原地改 dict"失明——用可控窗口把改密请求
        #   按在旧密码哈希阶段，期间管理员重置，断言改密 409 且重置密码生效）
        assert c.post("/api/users", json={"user": "u2", "password": "RaceOld#123"}).status_code == 201
        u2_ck = login(BASE, "u2", "RaceOld#123")
        _orig_hash, _entered, _release = core._hash_pw_async, threading.Event(), threading.Event()

        async def _slow_hash(password, salt):
            if password == "RaceOld#123":        # 只拦攻击者的旧密码校验哈希
                _entered.set()
                while not _release.is_set():
                    await asyncio.sleep(0.02)
            return await _orig_hash(password, salt)

        core._hash_pw_async = _slow_hash
        try:
            result = {}

            def _change():
                with httpx.Client(base_url=BASE, timeout=30, headers={"Cookie": u2_ck}) as cl:
                    result["r"] = cl.put("/api/me/password", json={
                        "old_password": "RaceOld#123", "new_password": "Evil#Attacker9"})

            th = threading.Thread(target=_change)
            th.start()
            assert _entered.wait(5), "改密请求未进入哈希阶段"
            assert c.put("/api/users/u2/password",
                         json={"new_password": "AdminReset#777"}).status_code == 200
            _release.set()
            th.join(20)
            assert result["r"].status_code == 409, result["r"].text
        finally:
            core._hash_pw_async = _orig_hash
            _release.set()
        login(BASE, "u2", "AdminReset#777")               # 重置的密码生效
        with httpx.Client(base_url=BASE, timeout=15) as cl:
            assert cl.post("/api/login", json={"user": "u2",
                            "password": "Evil#Attacker9"}).status_code == 401
        c.delete("/api/users/u2")
        print("5.7) 改密×应急重置竞态守卫     OK")

        # ===== 6) WS 关闭码：未登录 4401 / 跨站 Origin 4403 =====
        # （accept 后 close 才能把码送到浏览器；握手前 close 会被转成 HTTP 403 → 1006）
        assert ws_close_code(None) == 4401
        assert ws_close_code(admin_ck, origin="http://evil.example") == 4403
        print("6) 未登录/跨站 WS 关闭码 4401/4403 OK")

        # ===== 7) 远端断开通知：优雅退出 / TCP 直接断都应送达 closed =====
        # （回归：asyncssh 的会话关闭钩子是 connection_lost；此前误用 paramiko 时代的
        #   session_closed(status, msg)——asyncssh 从不调用该名字，断连后终端无提示冻结）
        for cmd, desc in (("exit", "优雅退出"), ("die", "异常掉线")):
            with ws_open(admin_ck) as ws:
                ws.send(json.dumps({"type": "connect", "host": "127.0.0.1", "port": PORT,
                                    "username": USER, "password": PASS, "trust_host_key": True}))
                recv_until(ws, "connected")
                ws.send(json.dumps({"type": "input", "data": cmd}))
                recv_until(ws, "closed")
            print(f"7) 远端{desc}送达 closed        OK")

        print("")
        print("全部 E2E 测试通过 ✅")
    finally:
        if hid:
            try:
                c.delete(f"/api/hosts/{hid}")
            except Exception:
                pass
        try:
            c.delete("/api/users/u1")
        except Exception:
            pass
        with core._STORE_LOCK:
            core._save_hosts([h for h in core._load_hosts() if h.get("owner") != "u1"])


if __name__ == "__main__":
    main()
