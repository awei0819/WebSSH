#!/usr/bin/env python3
"""
端到端测试：内置一个临时 paramiko SSH/SFTP 服务器（回显 shell + 临时目录 SFTP），
验证：手动连接终端、主机资产快捷连接、SFTP 列目录/上传/下载/删除、会话隔离。

运行： python test_e2e.py
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
from urllib.parse import quote

import paramiko
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import WebSSH

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
            flags |= getattr(os, "O_BINARY", 0)
            mode = getattr(attr, "st_mode", None) or 0o666
            with DummySFTP._open_lock:
                fd = os.open(self._real(path), flags, mode)
        except OSError as e:
            return paramiko.SFTPServer.from_oserror(e)
        if flags & os.O_WRONLY:
            s = "ab" if flags & os.O_APPEND else "wb"
        elif flags & os.O_RDWR:
            s = "a+b" if flags & os.O_APPEND else "r+b"
        else:
            s = "rb"
        try:
            f = os.fdopen(fd, s)
        except OSError as e:
            return paramiko.SFTPServer.from_oserror(e)
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


def main():
    # 看门狗：卡死则退出而非永久阻塞
    def watchdog():
        time.sleep(90)
        print("TIMEOUT: 测试卡死")
        os._exit(1)
    threading.Thread(target=watchdog, daemon=True).start()

    tmpdir = tempfile.mkdtemp(prefix="webssh_e2e_")
    os.makedirs(os.path.join(tmpdir, "子目录"))
    # 测试用临时 known_hosts，避免污染正式数据
    WebSSH.KNOWN_HOSTS = os.path.join(tmpdir, "known_hosts")
    start_test_ssh_server(tmpdir)
    time.sleep(0.3)

    c = TestClient(WebSSH.app)
    # ===== 0) 登录认证 =====
    c0 = TestClient(WebSSH.app)          # 未登录客户端
    assert c0.get('/api/hosts').status_code == 401
    assert c0.get('/api/files?token=x').status_code == 401
    assert c0.post('/api/login', json={'user': 'admin', 'password': 'wrong'}).status_code == 401
    assert c.post('/api/login', json={'user': 'admin', 'password': 'Admin#1234'}).status_code == 200
    assert c.get('/api/hosts').status_code == 200
    # 密码按需下发接口已彻底移除（F12 不可见明文）
    assert c.post('/api/hosts/xx/password').status_code == 404
    assert c.get('/api/hosts/xx/password').status_code == 404
    print('0) 登录认证（未登录401/密码错401/登录成功/密码接口已移除） OK')
    WS_HEADERS = {'Cookie': 'webssh_session=' + (c.cookies.get('webssh_session') or '')}
    hid = None
    try:
        # ===== 1) 手动连接 + 终端回显 =====
        with c.websocket_connect("/ws", headers=WS_HEADERS) as ws:
            ws.send_text(json.dumps({"type": "connect", "host": "127.0.0.1", "port": PORT,
                                     "username": USER, "password": PASS, "trust_host_key": True}))
            token1 = None
            seen = ""
            for _ in range(30):
                msg = json.loads(ws.receive_text())
                if msg.get("type") == "connected":
                    token1 = msg["token"]
                    assert "tester@127.0.0.1" in msg["label"], msg
                    ws.send_text(json.dumps({"type": "input", "data": "hello-e2e"}))
                elif msg.get("type") == "data":
                    seen += msg["data"]
                elif msg.get("type") == "error":
                    raise AssertionError("连接失败: " + msg.get("message", ""))
                if token1 and "hello-e2e" in seen:
                    break
            assert token1 and "hello-e2e" in seen, f"终端回显失败 token={token1} seen={seen!r}"
            assert "welcome" in seen, seen
            print("1) 手动连接 + 终端回显        OK")

        # 会话已断开，token 应失效
        r = c.get(f"/api/files?token={token1}&path=.")
        assert r.status_code == 401, r.status_code
        print("   断开后 token 失效           OK")

        # ===== 2) 主机资产 + 快捷连接 =====
        r = c.post("/api/hosts", json={"name": "e2e测试机", "host": "127.0.0.1", "port": PORT,
                                       "username": USER, "password": PASS, "trust": True})
        assert r.status_code == 201, r.text
        hid = r.json()["id"]

        with c.websocket_connect("/ws", headers=WS_HEADERS) as ws:
            ws.send_text(json.dumps({"type": "connect", "host_id": hid}))
            token = None
            for _ in range(10):
                msg = json.loads(ws.receive_text())
                if msg.get("type") == "connected":
                    token = msg["token"]
                    assert "e2e测试机" in msg["label"], msg
                    break
                if msg.get("type") == "error":
                    raise AssertionError("快捷连接失败: " + msg.get("message", ""))
            assert token, "未收到 connected"
            print("2) 主机快捷连接(仅传 host_id) OK")

            # ===== 3) SFTP：列目录 / 上传 / 下载 / 删除 =====
            q = f"token={quote(token)}"
            r = c.get(f"/api/files?{q}&path=.")
            assert r.status_code == 200, r.text
            base = r.json()["path"]
            names = [e["name"] for e in r.json()["entries"]]
            assert "子目录" in names, names
            assert any(e["is_dir"] and e["name"] == "子目录" for e in r.json()["entries"])

            content = "你好 webssh，e2e 上传内容 12345"
            r = c.put(f"/api/upload?{q}&path={quote(base)}&name=demo.txt", content=content.encode())
            assert r.status_code == 200 and r.json()["written"] == len(content.encode()), r.text

            r = c.get(f"/api/files?{q}&path={quote(base)}")
            entry = next(e for e in r.json()["entries"] if e["name"] == "demo.txt")
            assert entry["size"] == len(content.encode()), entry

            r = c.get(f"/api/download?{q}&path={quote(base + '/demo.txt')}")
            assert r.status_code == 200, r.text
            assert r.content.decode() == content, r.content
            assert "demo.txt" in r.headers["content-disposition"]

            r = c.delete(f"/api/files?{q}&path={quote(base + '/demo.txt')}")
            assert r.status_code == 200, r.text
            r = c.get(f"/api/files?{q}&path={quote(base)}")
            assert all(e["name"] != "demo.txt" for e in r.json()["entries"])

            # 非法文件名
            r = c.put(f"/api/upload?{q}&path={quote(base)}&name=../evil", content=b"x")
            assert r.status_code == 400, r.status_code
            print("3) SFTP 列表/上传/下载/删除   OK")

            # ===== 3.5) 分片乱序上传 + 并行下载完整性 =====
            import hashlib
            data = os.urandom(3 * 1024 * 1024)          # 3MB 随机数据
            part = 1 << 20
            # 乱序分片：先传后面的分片再传第 0 片（offset 随机写）
            for off in (2 * part, part, 0):
                r = c.put(f"/api/upload?{q}&path={quote(base)}&name=big.bin&offset={off}",
                          content=data[off:off + part])
                assert r.status_code == 200, (off, r.text)
            r = c.get(f"/api/download?{q}&path={quote(base + '/big.bin')}")
            assert r.status_code == 200 and len(r.content) == len(data)
            assert hashlib.sha256(r.content).digest() == hashlib.sha256(data).digest()
            # 空文件
            r = c.put(f"/api/upload?{q}&path={quote(base)}&name=empty.txt&offset=0", content=b"")
            assert r.status_code == 200, r.text
            r = c.get(f"/api/download?{q}&path={quote(base + '/empty.txt')}")
            assert r.status_code == 200 and r.content == b""
            # 同一文件多分片并发写（后端 upload_lock 保证建文件不互删）
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
            print("3.5) 分片乱序/并发上传+并行下载完整性 OK")

        # ===== 4) 密码错误应回传明确错误 =====
        with c.websocket_connect("/ws", headers=WS_HEADERS) as ws:
            ws.send_text(json.dumps({"type": "connect", "host": "127.0.0.1", "port": PORT,
                                     "username": USER, "password": "wrong", "trust_host_key": True}))
            msg = json.loads(ws.receive_text())
            assert msg.get("type") == "error" and "Auth" in msg.get("message", ""), msg
            print("4) 认证失败错误回传          OK")

        # ===== 5) 多用户：用户管理 / 资产隔离 / 改密规则 =====
        # 自清理：移除历史失败运行残留的 u1 用户与其资产
        if "u1" in WebSSH.AUTH["users"]:
            WebSSH.AUTH["users"].pop("u1")
            WebSSH._save_auth()
        with WebSSH._STORE_LOCK:
            WebSSH._save_hosts([h for h in WebSSH._load_hosts()
                                   if h.get("owner") != "u1"])
        r = c.post("/api/users", json={"user": "u1", "password": "User#12345"})
        assert r.status_code == 201, r.text
        assert c.post("/api/users", json={"user": "u1", "password": "User#12345"}).status_code == 400
        assert c.post("/api/users", json={"user": "x", "password": "123"}).status_code == 400

        cu = TestClient(WebSSH.app)
        assert cu.post("/api/login", json={"user": "u1", "password": "User#12345"}).status_code == 200
        assert cu.get("/api/me").json() == {"user": "u1", "admin": False}
        assert cu.get("/api/users").status_code == 403          # 普通用户无权用户管理
        assert cu.get("/api/hosts").json() == []                # 资产隔离：看不到 admin 的
        with cu.websocket_connect("/ws", headers={"Cookie": "webssh_session=" +
                (cu.cookies.get("webssh_session") or "")}) as w5:
            w5.send_text(json.dumps({"type": "connect", "host_id": hid}))   # 越权连接
            m = json.loads(w5.receive_text())
            assert m.get("type") == "error" and "不存在" in m.get("message", ""), m
        r = cu.post("/api/hosts", json={"name": "u1机", "host": "127.0.0.1",
                                        "username": "u1u", "password": "p"})
        assert r.status_code == 201, r.text
        assert "u1机" not in [h["name"] for h in c.get("/api/hosts").json()]
        assert [h["name"] for h in cu.get("/api/hosts").json()] == ["u1机"]
        assert cu.put("/api/me/password",
                      json={"old_password": "WRONG", "new_password": "New#12345"}).status_code == 403
        # 改密后旧 Cookie 立即作废（密码版本号机制）
        old_u1 = cu.cookies.get("webssh_session")
        assert cu.put("/api/me/password",
                      json={"old_password": "User#12345", "new_password": "New#12345"}).status_code == 200
        assert cu.get("/api/hosts",
                      headers={"Cookie": f"webssh_session={old_u1}"}).status_code == 401
        cu2 = TestClient(WebSSH.app)
        assert cu2.post("/api/login", json={"user": "u1", "password": "User#12345"}).status_code == 401
        assert cu2.post("/api/login", json={"user": "u1", "password": "New#12345"}).status_code == 200
        # admin 改自己密码：admin 旧 Cookie 作废，重登后继续
        assert c.put("/api/me/password", json={"old_password": "", "new_password": "Tmp#12345"}).status_code == 200
        assert c.get("/api/hosts").status_code == 401
        assert c.post("/api/login", json={"user": "admin", "password": "Tmp#12345"}).status_code == 200
        assert c.put("/api/me/password", json={"old_password": "", "new_password": "Admin#1234"}).status_code == 200
        assert c.post("/api/login", json={"user": "admin", "password": "Admin#1234"}).status_code == 200
        # admin 重置 u1 密码：u1 旧 Cookie 作废，admin 自身不受影响
        u1_old = cu2.cookies.get("webssh_session")
        assert c.put("/api/users/u1/password", json={"new_password": "Reset#12345"}).status_code == 200
        assert cu2.get("/api/hosts",
                       headers={"Cookie": f"webssh_session={u1_old}"}).status_code == 401
        assert c.get("/api/hosts").status_code == 200
        cu3 = TestClient(WebSSH.app)
        assert cu3.post("/api/login", json={"user": "u1", "password": "Reset#12345"}).status_code == 200
        # 删除保护 & 删除用户连带清理其资产
        assert c.delete("/api/users/admin").status_code == 400  # admin 不允许删除
        assert cu3.get("/api/hosts").status_code == 200         # 签名 Cookie 持续有效（刷新不掉线机制）
        assert c.delete("/api/users/u1").status_code == 200
        assert cu3.get("/api/hosts").status_code == 401         # 用户删除后 Cookie 立即失效
        assert all(h.get("owner") != "u1" for h in WebSSH._load_hosts())  # 资产已连带删除
        # 回归：用户名含点也能正常登录（token 从右侧解析固定段）
        assert c.post("/api/users", json={"user": "a.b", "password": "Dot#12345"}).status_code == 201
        cd = TestClient(WebSSH.app)
        assert cd.post("/api/login", json={"user": "a.b", "password": "Dot#12345"}).status_code == 200
        assert cd.get("/api/me").json()["user"] == "a.b"
        assert c.delete("/api/users/a.b").status_code == 200
        print("5) 多用户（隔离/越权/改密规则/删除保护） OK")

        print("\n全部 E2E 测试通过 ✅")
    finally:
        if hid:
            try:
                c.delete(f"/api/hosts/{hid}")
            except Exception:
                pass


if __name__ == "__main__":
    main()
