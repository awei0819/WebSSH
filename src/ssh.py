"""SSH 连接、会话管理与 WebSocket 终端（asyncssh 全异步）"""
import asyncio
import codecs
import json
import os
import secrets
import threading

import asyncssh
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect

import core
from core import (
    DATA_DIR, _load_hosts, dec, _cur_user, _STORE_LOCK)
# KNOWN_HOSTS 经 core 模块属性动态取用（test_e2e 会重定向到临时文件隔离 TOFU 状态）

router = APIRouter()

# SSH 会话（asyncssh 全异步：每会话零线程，终端与 SFTP 共用一条连接）
# ============================================================
class Session:
    def __init__(self, conn, owner: str = ""):
        self.conn = conn
        self.owner = owner                # 绑定创建者（防其他用户盗用 token）
        self.sftp = None                  # 惰性创建的 SFTP 客户端（原生异步流水线）
        self.sftp_lock = asyncio.Lock()
        self.upload_locks = {}            # 目标文件名 -> asyncio.Lock（多分片并发建文件用）

    def upload_lock(self, target: str) -> asyncio.Lock:
        lk = self.upload_locks.get(target)
        if lk is None:
            lk = asyncio.Lock()
            self.upload_locks[target] = lk
        return lk
        # 注意：不做"单个分片传完即释放"——分片 PUT 相互独立，提前释放会破坏
        # 并发分片建文件的互斥；条目随会话在 close() 里统一 clear（会话级泄漏边界）

    async def get_sftp(self):
        async with self.sftp_lock:
            if self.sftp is None:
                self.sftp = await self.conn.start_sftp_client()
            return self.sftp

    def close(self):
        # 故意不用 async：清理回调（delete_user → _cleanup_user_sessions）在同步上下文调用，
        # 若是 async def，不加 await 的调用只会创建协程对象、函数体从不执行（连接关不掉）。
        # 仅强杀路径调用本方法；正常断开由 ws 处理器 finally 走优雅的 conn.close()，
        # Session 随 SESSIONS.pop 失去引用交由 GC——不要把 abort 混进优雅路径。
        # abort() 强断后由会话钩子 connection_lost 兜底通知（实测：优雅退出/网络断开/abort
        # 三种场景都触发它）→ 给 pump 投哨兵 → 前端收到 {"type":"closed"}
        self.sftp = None
        self.upload_locks.clear()        # 清理锁字典（泄漏边界从进程级缩到会话级）
        self.conn.abort()


SESSIONS: dict = {}  # token -> Session

# 注册会话清理回调（delete_user 时关闭该用户全部 SSH 连接）
from core import register_session_cleanup

def _cleanup_user_sessions(username: str):
    for tok, s in list(SESSIONS.items()):
        if s.owner == username:
            SESSIONS.pop(tok, None)
            try:
                s.close()
            except Exception:
                pass

register_session_cleanup(_cleanup_user_sessions)


_TOFU_LOCK = threading.Lock()       # known_hosts 追加写入串行化（防多连接首次并发交错）

# 反向代理（Nginx 等）转发后 Host 头可能变成内部地址，导致 Origin 校验误拒：
# 可用环境变量放行外部来源，逗号分隔，如 WEBSSH_ALLOWED_ORIGINS=https://webssh.example.com
_EXTRA_ORIGINS = {o.strip() for o in os.environ.get("WEBSSH_ALLOWED_ORIGINS", "").split(",")
                  if o.strip()}


class _TofuClient(asyncssh.SSHClient):
    """主机密钥 TOFU：已知且一致放行 / 已知但变更拒绝 / 未知按 trust 记录或拒绝。
    写入格式与 OpenSSH known_hosts 兼容（paramiko 时期的历史档案可直接沿用）。"""

    def __init__(self, kh_file: str, trust: bool):
        self._kh, self._trust = kh_file, trust

    def validate_host_public_key(self, host, addr, port, key) -> bool:
        hostline = host if port == 22 else "[" + host + "]:" + str(port)
        want = " ".join(key.export_public_key("openssh").decode().split()[:2])
        try:
            with open(self._kh, encoding="utf-8") as f:
                lines = [l.split() for l in f if l.strip() and not l.startswith("#")]
        except OSError:
            lines = []
        for parts in lines:
            if hostline in parts[0].split(","):
                return " ".join(parts[1:3]) == want     # 指纹变更 → 拒绝
        if self._trust:                                 # 首次：记录
            with _TOFU_LOCK:
                with open(self._kh, "a", encoding="utf-8") as f:
                    f.write(hostline + " " + want + chr(10))
            return True
        return False                                    # 未知且不信任 → 拒绝


def _import_key(key_str: str, passphrase: str):
    try:
        return asyncssh.import_private_key(key_str.strip() + chr(10), passphrase or None)
    except Exception as e:
        raise ValueError("无法解析私钥：" + str(e)
                         + "（可尝试 ssh-keygen -p -m PEM -f 私钥文件 转换格式后再粘贴）")


_CONNECT_SEM = asyncio.Semaphore(64)       # 全局并发建连上限（防 fd/远端 MaxStartups 打爆）
_MAX_SESSIONS_PER_USER = 30                # 每用户最多活跃终端会话数


async def _ssh_connect(hostname, port, username, password="", key="", key_passphrase="", trust=False):
    if not os.path.exists(core.KNOWN_HOSTS):
        open(core.KNOWN_HOSTS, "a").close()
    async with _CONNECT_SEM:
        return await _do_connect(hostname, port, username, password, key, key_passphrase, trust)


async def _do_connect(hostname, port, username, password, key, key_passphrase, trust):
    kwargs = {}
    if key:
        kwargs["client_keys"] = [_import_key(key, key_passphrase)]
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("请填写密码或私钥")
    try:
        conn, _ = await asyncio.wait_for(asyncssh.create_connection(
            lambda: _TofuClient(core.KNOWN_HOSTS, trust),
            hostname, port=int(port), username=username,
            known_hosts=core.KNOWN_HOSTS, keepalive_interval=30,
            connect_timeout=15, compression_algs=[], **kwargs), timeout=20)
    except asyncio.TimeoutError:
        raise ValueError("连接超时")
    except asyncssh.HostKeyNotVerifiable:
        raise ValueError("主机密钥校验失败：未知主机需勾选信任，或服务器密钥已变更")
    except asyncssh.PermissionDenied as e:
        raise ValueError("Authentication failed: " + str(e.reason))
    except asyncssh.KeyExchangeFailed as e:
        raise ValueError("密钥协商失败（服务器算法过旧或不兼容）: " + str(e))
    except (OSError, asyncssh.Error) as e:
        raise ValueError("连接失败: " + str(e))
    return conn


def _resolve_connect_cfg(cfg: dict, user: str = ""):
    """快捷连接（host_id，服务端取凭据）或手动连接（前端传参）。"""
    hid = cfg.get("host_id")
    if hid:
        with _STORE_LOCK:
            rec = next((h for h in _load_hosts()
                        if h["id"] == hid and h.get("owner") == user), None)
        if not rec:
            raise ValueError("主机不存在（可能已被删除）")
        label = f"{rec['name']}  ({rec['username']}@{rec['host']}:{rec['port']})"
        return dict(
            hostname=rec["host"], port=rec["port"], username=rec["username"],
            password=dec(rec.get("password_enc", "")),
            key=dec(rec.get("key_enc", "")),
            key_passphrase=dec(rec.get("key_passphrase_enc", "")),
            trust=bool(rec.get("trust")),
        ), label, rec["name"]
    # 手动连接
    hostname = str(cfg.get("host") or "").strip()
    username = str(cfg.get("username") or "").strip()
    if not hostname or not username:
        raise ValueError("请填写主机和用户名")
    try:
        port = int(cfg.get("port") or 22)
    except (TypeError, ValueError):
        raise ValueError("端口不正确")
    label = f"{username}@{hostname}:{port}"
    return dict(
        hostname=hostname, port=port, username=username,
        password=str(cfg.get("password") or ""),
        key=str(cfg.get("key") or "").strip(),
        key_passphrase=str(cfg.get("key_passphrase") or ""),
        trust=bool(cfg.get("trust_host_key")),
    ), label, f"{username}@{hostname}"


# ============================================================
# SFTP 文件接口（凭 token 访问当前终端会话）
# ============================================================
def _get_session(token: str, user: str) -> Session:
    sess = SESSIONS.get(token or "")
    if sess is None:
        # 409 而非 401：会话死亡不是"登录过期"。前端把一切 401 视为登录过期并弹
        # 登录框——混用会让网络闪断后的文件操作凭空要求重新登录（登录态仍有效）
        raise HTTPException(409, "会话不存在或已断开")
    if user and sess.owner and sess.owner != user:
        raise HTTPException(403, "无权访问该会话")   # token 属于其他用户
    return sess


def _sanitize_name(name: str) -> str:
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name or len(name) > 255:
        raise HTTPException(400, "文件名不合法")
    return name


@router.websocket("/ws")
async def ssh_ws(ws: WebSocket):
    # 必须先 accept 再校验关闭：握手前的 close 会被 uvicorn 转成 HTTP 403 拒绝握手，
    # 浏览器只能收到 1006，自定义关闭码（4401/4403）送不到前端（前端按码引导重登录）
    await ws.accept()
    # Origin 校验：防跨站 WebSocket 劫持（CSWSH）——连上即关，不处理任何消息
    origin = ws.headers.get("origin", "")
    host = ws.headers.get("host", "")
    if (origin and host and origin not in (f"http://{host}", f"https://{host}")
            and origin not in _EXTRA_ORIGINS):
        await ws.close(code=4403)
        return
    ws_user = _cur_user(ws.cookies)         # 登录过期：4401 关闭，前端引导重新登录
    if not ws_user:
        await ws.close(code=4401)
        return
    # 每用户活跃会话上限（防单人占满全部资源）
    _user_count = sum(1 for v in SESSIONS.values() if v.owner == ws_user)
    if _user_count >= _MAX_SESSIONS_PER_USER:
        await ws.send_text(json.dumps({"type": "error", "message":
            f"已达会话上限（{_MAX_SESSIONS_PER_USER}），请先关闭部分标签页再连接"}))
        await ws.close(code=4400)
        return

    conn = None
    chan = None
    token = None
    pump_task = None

    async def send(obj):
        try:
            await ws.send_text(json.dumps(obj))
        except Exception:
            pass

    try:
        raw = await ws.receive_text()
        cfg = json.loads(raw)
        cfg_conn, label, name = _resolve_connect_cfg(cfg, ws_user)
        conn = await _ssh_connect(**cfg_conn)

        out_q: asyncio.Queue = asyncio.Queue(maxsize=128)
        chan_ref = {}

        class _Term(asyncssh.SSHClientSession):
            """终端输出 → 有界队列 + 背压（慢客户端时暂停远端发送，防 OOM）。
            回调与 pump 同跑在一个事件循环上，天然无并发竞态。
            状态一律挂实例 self——挂类属性的话，日后若把类提出函数外，
            paused/closed 会变成全体会话共享，跨连接串数据。"""
            def __init__(self):
                self.paused = False
                self.closed = False
            def connection_made(self, chan):
                chan_ref['chan'] = chan
            def data_received(self, data, datatype):
                try:
                    out_q.put_nowait(bytes(data))
                except asyncio.QueueFull:          # 消费不动：暂停远端，等 pump 追平
                    if not self.paused:
                        self.paused = True
                        chan_ref['chan'].pause()
            def eof_received(self):
                self.closed = True
                try:
                    out_q.put_nowait(None)
                except asyncio.QueueFull:     # 队列满（慢客户端）：标记由 pump 兜底
                    pass
            def connection_lost(self, exc):
                # asyncssh 的会话关闭钩子是 connection_lost（没有 session_closed 这个钩子——
                # 那是 paramiko 时代残留，asyncssh 从不调用）。优雅退出/网络断开/本地 abort
                # 三种断连场景实测都会走到这里
                self.closed = True
                try:
                    out_q.put_nowait(None)
                except asyncio.QueueFull:
                    pass

        chan, term = await conn.create_session(
            _Term, term_type="xterm-256color", term_size=(120, 30), encoding=None)

        token = secrets.token_hex(16)
        SESSIONS[token] = Session(conn, owner=ws_user)
        await send({"type": "connected", "token": token, "label": label, "name": name})

        async def pump():
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            try:
                while True:
                    if out_q.empty() and term.closed:
                        break                # 关闭哨兵可能因队列满被丢，靠 closed 标记兜底
                    item = await out_q.get()
                    if item is None:
                        break
                    if term.paused and out_q.qsize() < 32:       # 背压恢复（只在 paused 时调）
                        term.paused = False
                        try:
                            chan_ref['chan'].resume()
                        except Exception:
                            pass
                    text = decoder.decode(item)
                    if text:
                        await ws.send_text(json.dumps({"type": "data", "data": text}))
            except Exception:
                pass
            finally:
                # 远端已断：SFTP 接口即刻失效（幂等——正常关闭时 ws 处理器 finally 也会 pop）
                SESSIONS.pop(token, None)
                try:
                    await ws.send_text(json.dumps({"type": "closed"}))
                except Exception:
                    pass

        pump_task = asyncio.create_task(pump())

        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            t = msg.get("type")
            if t == "input":
                try:
                    chan.write(msg.get("data", "").encode("utf-8"))
                except Exception:
                    break                   # 远端已断：退出收发循环
            elif t == "resize":
                try:
                    chan.change_terminal_size(int(msg["cols"]), int(msg["rows"]))
                except (KeyError, ValueError, TypeError):
                    pass                     # 畸形 resize 消息不杀连接
    except WebSocketDisconnect:
        pass
    except Exception as e:
        await send({"type": "error", "message": str(e)})
    finally:
        if pump_task:
            pump_task.cancel()
        if token:
            SESSIONS.pop(token, None)
        if chan:
            chan.close()
        if conn:
            conn.close()


# ============================================================

def ensure_selfsigned_cert():
    """首次生成自签证书（含本机局域网 IP 的 SAN，尽力而为）；返回 (cert, key)"""
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import socket

    cert_p = os.path.join(DATA_DIR, "webssh_cert.pem")
    key_p = os.path.join(DATA_DIR, "webssh_key.pem")
    if os.path.exists(cert_p) and os.path.exists(key_p):
        return cert_p, key_p
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "WebSSH Self-Signed")])
    sans = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
    try:                                   # 尽力把本机局域网 IP 加进 SAN（他机访问少一层警告）
        lan_ip = socket.gethostbyname(socket.gethostname())
        if lan_ip and lan_ip != "127.0.0.1":
            sans.append(x509.IPAddress(ipaddress.ip_address(lan_ip)))
    except Exception:
        pass
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=3650))
        .add_extension(x509.SubjectAlternativeName(sans), critical=False)
        .sign(key, hashes.SHA256())
    )
    with open(cert_p, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(key_p, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.TraditionalOpenSSL,
                                  serialization.NoEncryption()))
    try:
        os.chmod(key_p, 0o600)           # Linux 多用户下防其他用户读取 TLS 私钥
    except OSError:
        pass                             # Windows
    return cert_p, key_p
