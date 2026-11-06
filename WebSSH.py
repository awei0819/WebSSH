#!/usr/bin/env python3
"""
WebSSH —— 轻量级浏览器 SSH 堡垒机（对标 JumpServer 核心功能的极简实现）

功能：
    1. 主机资产管理：新增/编辑/删除主机（名称、IP、端口、用户名、密码/私钥），列表一键快捷连接
    2. 网页终端（xterm.js）
    3. 文件管理：SFTP 浏览目录、上传（带进度）、下载、删除

安全设计：
    - 默认只监听 127.0.0.1；需要局域网访问自行改为 0.0.0.0
    - 主机密码/私钥用 Fernet 加密落盘，密钥为本机生成的 data/secret.key
    - 密码永不下发浏览器：快捷连接只传 host_id，凭据仅在服务端解密使用
    - 文件接口与终端会话绑定（随机 token，终端断开即失效）
    - 默认拒绝未知主机密钥；勾选"信任"则 TOFU：首次记录指纹到 data/known_hosts，指纹变更即拒绝

依赖：
    pip install fastapi "uvicorn[standard]" paramiko
    （cryptography 随 paramiko 自动安装）

运行：
    python WebSSH.py
    数据文件：./data/{hosts.json, secret.key, known_hosts}
"""
import asyncio
import codecs
import errno
import hashlib
import hmac
import io
import json
import os
import posixpath
import queue
import re
import secrets
import sys
import socket
import stat as stat_mod
import threading
import time
import webbrowser
from datetime import datetime
from urllib.parse import quote

import paramiko
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, HTTPException, Request, Response, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, StreamingResponse

VERSION = "v1.0.0"

if not hasattr(asyncio, "to_thread"):        # Python 3.7/3.8 兼容（麒麟 V10 / UOS 系统自带 3.7）
    import functools as _ft

    async def _to_thread(func, *args, **kwargs):
        return await asyncio.get_running_loop().run_in_executor(
            None, _ft.partial(func, *args, **kwargs))
    asyncio.to_thread = _to_thread

app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """安全响应头：防嗅探/防点击劫持/禁缓存；HTTPS 时附加 HSTS"""
    resp = await call_next(request)
    resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    resp.headers.setdefault("X-Frame-Options", "DENY")
    resp.headers.setdefault("Referrer-Policy", "no-referrer")
    resp.headers.setdefault("Cache-Control", "no-store")
    resp.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "connect-src 'self' ws: wss:; img-src 'self' data:; object-src 'none'; "
        "frame-ancestors 'none'; base-uri 'self'")
    if request.url.scheme == "https":
        resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return resp

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
HOSTS_FILE = os.path.join(DATA_DIR, "hosts.json")
KEY_FILE = os.path.join(DATA_DIR, "secret.key")
KNOWN_HOSTS = os.path.join(DATA_DIR, "known_hosts")


# ============================================================
# 凭据加密（Fernet，密钥为本机随机生成，仅保护落盘数据）
# ============================================================
def _load_fernet() -> Fernet:
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(KEY_FILE):
        key = open(KEY_FILE, "rb").read().strip()
    else:
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as f:
            f.write(key)
        try:
            os.chmod(KEY_FILE, 0o600)
        except OSError:
            pass  # Windows
    return Fernet(key)


FERNET = _load_fernet()


def enc(s: str) -> str:
    return FERNET.encrypt(s.encode("utf-8")).decode("ascii") if s else ""


def dec(s: str) -> str:
    if not s:
        return ""
    try:
        return FERNET.decrypt(s.encode("ascii")).decode("utf-8")
    except InvalidToken:
        raise ValueError("凭据解密失败：data/secret.key 与 hosts.json 不匹配")


# ============================================================
# 登录认证（多用户；PBKDF2 加盐哈希落盘；签名 Cookie 无服务端会话，刷新/重启不掉线）
# ============================================================
AUTH_FILE = os.path.join(DATA_DIR, "auth.json")
SESSION_HOURS = 12
PBKDF2_ROUNDS = 200_000
DEFAULT_ADMIN_USER = "admin"
DEFAULT_ADMIN_PASS = "Admin#1234"
_SIGN_KEY = open(KEY_FILE, "rb").read().strip()      # 复用本机密钥给 Cookie 签名


def _hash_pw(password: str, salt: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), PBKDF2_ROUNDS).hex()


def _load_auth() -> dict:
    """格式：{"users": {名字: {salt, hash, admin}}}；兼容迁移旧版单用户文件"""
    data = None
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, encoding="utf-8") as f:
                data = json.load(f)
        except ValueError:
            data = None
    if not data or "users" not in data:
        if data and "salt" in data:      # 旧版 {user,salt,hash} → admin 用户
            users = {data["user"]: {"salt": data["salt"], "hash": data["hash"], "admin": True}}
        else:                            # 首次运行：默认管理员
            salt = secrets.token_hex(16)
            users = {DEFAULT_ADMIN_USER: {"salt": salt,
                                          "hash": _hash_pw(DEFAULT_ADMIN_PASS, salt),
                                          "admin": True}}
        data = {"users": users}
        with open(AUTH_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    for rec in data["users"].values():          # 迁移：旧记录补密码版本号
        rec.setdefault("pwver", 1)
    return data


AUTH = _load_auth()
_AUTH_LOCK = threading.Lock()       # auth.json 修改串行化
_DUMMY_SALT = "0" * 32              # 恒时登录：用户不存在时也做同代价哈希


def _save_auth():
    with open(AUTH_FILE, "w", encoding="utf-8") as f:
        json.dump(AUTH, f, ensure_ascii=False, indent=2)


def _sign(payload: str) -> str:
    return hmac.new(_SIGN_KEY, payload.encode(), hashlib.sha256).hexdigest()


def _issue_login_token(user: str) -> str:
    exp = int(time.time() + SESSION_HOURS * 3600)
    ver = AUTH["users"][user].get("pwver", 1)
    body = f"{user}.{exp}.{ver}"
    return f"{body}.{_sign(body)}"


def _cur_user(cookies):
    """从 Cookie 解析当前登录用户名；无效/过期/密码已变更（版本不符）返回 None。
    token 结构：用户名(可含点).过期时间.密码版本.签名 —— 从右侧解析固定段。"""
    tok = cookies.get("webssh_session") if cookies else None
    if not tok:
        return None
    parts = tok.split(".")
    if len(parts) < 4:
        return None
    sig, ver, exp = parts[-1], parts[-2], parts[-3]
    user = ".".join(parts[:-3])
    try:
        if int(exp) < time.time():
            return None
        if int(ver) < 1:
            return None
    except ValueError:
        return None
    if not hmac.compare_digest(sig, _sign(f"{user}.{exp}.{ver}")):
        return None
    rec = AUTH["users"].get(user)
    if rec is None or rec.get("pwver", 1) != int(ver):   # 已改密/重置 → 旧凭证作废
        return None
    return user


def _is_admin(user: str) -> bool:
    rec = AUTH["users"].get(user)
    return bool(rec and rec.get("admin"))


def _need_user(request: Request) -> str:
    u = _cur_user(request.cookies)
    if not u:
        raise HTTPException(401, "未登录或登录已过期")
    return u


def _need_admin(request: Request) -> str:
    u = _need_user(request)
    if not _is_admin(u):
        raise HTTPException(403, "仅管理员可操作")
    return u


async def require_auth(request: Request):
    if not _cur_user(request.cookies):
        raise HTTPException(401, "未登录或登录已过期")


_LOGIN_FAILS: dict = {}        # 用户名 -> [连续失败次数, 锁定截止时间戳]
_FAIL_LIMIT = 5
_LOCK_SECONDS = 300


def _login_guard(user: str):
    """登录限速：连续错 5 次锁定 5 分钟"""
    rec = _LOGIN_FAILS.get(user)
    if rec:
        if rec[1] and rec[1] > time.time():
            left = int(rec[1] - time.time()) + 1
            raise HTTPException(429, f"失败次数过多，请 {left // 60} 分 {left % 60} 秒后再试")
        if rec[1] and rec[1] <= time.time():    # 锁过期，清零重新计
            _LOGIN_FAILS.pop(user, None)


def _login_fail(user: str):
    rec = _LOGIN_FAILS.setdefault(user, [0, 0.0])
    rec[0] += 1
    if rec[0] >= _FAIL_LIMIT:
        rec[1] = time.time() + _LOCK_SECONDS
        rec[0] = 0


@app.post("/api/login")
async def login(body: dict, response: Response):
    user = str(body.get("user") or "").strip()
    password = str(body.get("password") or "")
    _login_guard(user)
    rec = AUTH["users"].get(user)
    if not rec:
        _hash_pw(password, _DUMMY_SALT)     # 恒时：不存在的用户也做同代价计算，防用户名枚举
        _login_fail(user)                   # 不存在的用户同样计数（防借锁定行为探测用户名）
        raise HTTPException(401, "账号或密码错误")
    if not hmac.compare_digest(rec["hash"], _hash_pw(password, rec["salt"])):
        _login_fail(user)
        raise HTTPException(401, "账号或密码错误")
    _LOGIN_FAILS.pop(user, None)            # 成功即清零
    response.set_cookie("webssh_session", _issue_login_token(user),
                        httponly=True, samesite="strict",
                        max_age=SESSION_HOURS * 3600)
    return {"ok": True, "user": user, "admin": bool(rec.get("admin"))}


@app.get("/api/me")
async def whoami(request: Request, _: None = Depends(require_auth)):
    u = _need_user(request)
    return {"user": u, "admin": _is_admin(u)}


@app.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("webssh_session")
    return {"ok": True}


@app.put("/api/me/password")
async def change_my_password(request: Request, body: dict, _: None = Depends(require_auth)):
    u = _need_user(request)
    old = str(body.get("old_password") or "")
    new = str(body.get("new_password") or "")
    if len(new) < 8:
        raise HTTPException(400, "新密码至少 8 位")
    with _AUTH_LOCK:
        rec = AUTH["users"][u]
        if not _is_admin(u):                # 管理员改自己免验旧密码
            if not hmac.compare_digest(rec["hash"], _hash_pw(old, rec["salt"])):
                raise HTTPException(403, "旧密码不正确")
        rec["salt"] = secrets.token_hex(16)
        rec["hash"] = _hash_pw(new, rec["salt"])
        rec["pwver"] = rec.get("pwver", 1) + 1   # 版本+1：该用户所有旧 Cookie 立即作废
        _save_auth()
    return {"ok": True}


# ---------- 用户管理（仅 admin） ----------
@app.get("/api/users")
async def list_users(request: Request, _: None = Depends(require_auth)):
    _need_admin(request)
    return [{"user": n, "admin": bool(r.get("admin"))}
            for n, r in sorted(AUTH["users"].items())]


@app.post("/api/users", status_code=201)
async def create_user(request: Request, body: dict, _: None = Depends(require_auth)):
    _need_admin(request)
    name = str(body.get("user") or "").strip()
    pwd = str(body.get("password") or "")
    if not re.fullmatch(r"[A-Za-z0-9_.\-]{2,32}", name):
        raise HTTPException(400, "用户名需为 2-32 位字母/数字/_.-")
    if name in AUTH["users"]:
        raise HTTPException(400, "用户已存在")
    if len(pwd) < 8:
        raise HTTPException(400, "密码至少 8 位")
    with _AUTH_LOCK:
        salt = secrets.token_hex(16)
        AUTH["users"][name] = {"salt": salt, "hash": _hash_pw(pwd, salt),
                               "admin": bool(body.get("admin")), "pwver": 1}
        _save_auth()
    return {"ok": True}


@app.delete("/api/users/{name}")
async def delete_user(request: Request, name: str, _: None = Depends(require_auth)):
    cur = _need_admin(request)
    if name == DEFAULT_ADMIN_USER:
        raise HTTPException(400, "admin 用户不允许删除")
    if name == cur:
        raise HTTPException(400, "不能删除当前登录用户")
    if name not in AUTH["users"]:
        raise HTTPException(404, "用户不存在")
    if AUTH["users"][name].get("admin") and             sum(1 for r in AUTH["users"].values() if r.get("admin")) <= 1:
        raise HTTPException(400, "至少保留一个管理员")
    with _AUTH_LOCK:
        AUTH["users"].pop(name)
        _save_auth()
    with _STORE_LOCK:                      # 该用户名下资产一并删除（否则成无人可见的孤儿数据）
        _save_hosts([h for h in _load_hosts() if h.get("owner") != name])
    return {"ok": True}


@app.put("/api/users/{name}/password")
async def reset_user_password(request: Request, name: str, body: dict, _: None = Depends(require_auth)):
    _need_admin(request)
    if name not in AUTH["users"]:
        raise HTTPException(404, "用户不存在")
    new = str(body.get("new_password") or "")
    if len(new) < 8:
        raise HTTPException(400, "密码至少 8 位")
    with _AUTH_LOCK:
        rec = AUTH["users"][name]
        rec["salt"] = secrets.token_hex(16)
        rec["hash"] = _hash_pw(new, rec["salt"])
        rec["pwver"] = rec.get("pwver", 1) + 1   # 被重置用户的所有旧 Cookie 立即作废
        _save_auth()
    return {"ok": True}


# ============================================================
# 主机资产存储
# ============================================================
_STORE_LOCK = threading.Lock()


def _load_hosts() -> list:
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        hosts = data.get("hosts", [])
    except (OSError, ValueError):
        hosts = []
    for h in hosts:                       # 兼容旧数据：未绑定归属的资产划给 admin
        h.setdefault("owner", "admin")
    return hosts


def _save_hosts(hosts: list):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = HOSTS_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"hosts": hosts}, f, ensure_ascii=False, indent=2)
    os.replace(tmp, HOSTS_FILE)


def _host_public(h: dict) -> dict:
    """返回给前端的字段——绝不包含密码/私钥（含密文）。"""
    auth = []
    if h.get("password_enc"):
        auth.append("密码")
    if h.get("key_enc"):
        auth.append("私钥")
    return {
        "id": h["id"],
        "name": h["name"],
        "host": h["host"],
        "port": h["port"],
        "username": h["username"],
        "auth": "+".join(auth) or "未设置",
        "trust": bool(h.get("trust")),
        "remark": h.get("remark", ""),
        "created_at": h.get("created_at", ""),
    }


def _validate_host_body(body: dict, creating: bool):
    name = str(body.get("name") or "").strip()
    host = str(body.get("host") or "").strip()
    username = str(body.get("username") or "").strip()
    remark = str(body.get("remark") or "").strip()
    if not (1 <= len(name) <= 64):
        raise HTTPException(400, "名称必填（1-64 字符）")
    if not re.fullmatch(r"[A-Za-z0-9_.:\-]+", host) or len(host) > 255:
        raise HTTPException(400, "主机格式不正确")
    if not (1 <= len(username) <= 64) or any(c.isspace() for c in username):
        raise HTTPException(400, "用户名不正确")
    try:
        port = int(body.get("port") or 22)
        assert 1 <= port <= 65535
    except Exception:
        raise HTTPException(400, "端口必须在 1-65535 之间")
    password = str(body.get("password") or "")
    key = str(body.get("key") or "").strip()
    key_passphrase = str(body.get("key_passphrase") or "")
    if creating and not password and not key:
        raise HTTPException(400, "密码与私钥至少填一项")
    return name, host, port, username, password, key, key_passphrase, bool(body.get("trust")), remark[:128]


@app.get("/api/hosts")
async def list_hosts(request: Request, _: None = Depends(require_auth)):
    user = _need_user(request)
    with _STORE_LOCK:
        return [_host_public(h) for h in _load_hosts() if h.get("owner") == user]


@app.post("/api/hosts", status_code=201)
async def create_host(request: Request, body: dict, _: None = Depends(require_auth)):
    name, host, port, username, password, key, key_pass, trust, remark = _validate_host_body(body, True)
    rec = {
        "id": secrets.token_hex(4), "owner": _need_user(request),
        "name": name, "host": host, "port": port, "username": username,
        "password_enc": enc(password), "key_enc": enc(key), "key_passphrase_enc": enc(key_pass),
        "trust": trust, "remark": remark,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    with _STORE_LOCK:
        hosts = _load_hosts()
        hosts.append(rec)
        _save_hosts(hosts)
    return _host_public(rec)


@app.put("/api/hosts/{hid}")
async def update_host(request: Request, hid: str, body: dict, _: None = Depends(require_auth)):
    name, host, port, username, password, key, key_pass, trust, remark = _validate_host_body(body, False)
    with _STORE_LOCK:
        user = _need_user(request)
        hosts = _load_hosts()
        for h in hosts:
            if h["id"] == hid and h.get("owner") == user:
                h.update({
                    "name": name, "host": host, "port": port, "username": username,
                    "trust": trust, "remark": remark,
                    # 编辑时留空 = 保持原凭据不变
                    "password_enc": enc(password) if password else h.get("password_enc", ""),
                    "key_enc": enc(key) if key else h.get("key_enc", ""),
                    "key_passphrase_enc": enc(key_pass) if key_pass else h.get("key_passphrase_enc", ""),
                })
                _save_hosts(hosts)
                return _host_public(h)
    raise HTTPException(404, "主机不存在")


@app.delete("/api/hosts/{hid}")
async def delete_host(request: Request, hid: str, _: None = Depends(require_auth)):
    with _STORE_LOCK:
        user = _need_user(request)
        hosts = _load_hosts()
        left = [h for h in hosts if not (h["id"] == hid and h.get("owner") == user)]
        if len(left) == len(hosts):
            raise HTTPException(404, "主机不存在")
        _save_hosts(left)
    return {"ok": True}


# ============================================================
# SSH 会话（终端与 SFTP 共用一条连接，随 WebSocket 生命周期）
# ============================================================
class Session:
    def __init__(self, client: paramiko.SSHClient):
        self.client = client
        self.sftp = None
        self.lock = threading.RLock()     # 共享 SFTP 通道串行化（可重入）
        self.upload_locks = {}            # 目标文件名 -> Lock（多分片并发建文件用）

    def upload_lock(self, target: str) -> threading.Lock:
        with self.lock:
            lk = self.upload_locks.get(target)
            if lk is None:
                lk = threading.Lock()
                self.upload_locks[target] = lk
            return lk

    def get_sftp(self):
        """共享 SFTP 通道：只用于列表/删除/stat 等短操作（须持有 self.lock）"""
        if self.sftp is None:
            self.sftp = self.client.open_sftp()
        return self.sftp

    def reset_sftp(self):
        with self.lock:
            if self.sftp is not None:
                try:
                    self.sftp.close()
                except Exception:
                    pass
                self.sftp = None

    def close(self):
        self.reset_sftp()
        try:
            self.client.close()
        except Exception:
            pass


SESSIONS: dict = {}  # token -> Session


def _load_pkey(key_str: str, passphrase: str):
    key_str = key_str.strip() + "\n"
    last_err = None
    for name in ("Ed25519Key", "ECDSAKey", "RSAKey", "DSSKey"):
        cls = getattr(paramiko, name, None)
        if cls is None:
            continue
        try:
            return cls.from_private_key(io.StringIO(key_str), password=passphrase or None)
        except Exception as e:
            last_err = e
    raise ValueError(f"无法解析私钥：{last_err}")


def _ssh_connect(hostname, port, username, password="", key="", key_passphrase="", trust=False):
    client = paramiko.SSHClient()
    # TOFU：首次自动记录指纹，之后指纹变更会被拒绝
    if not os.path.exists(KNOWN_HOSTS):
        open(KNOWN_HOSTS, "a").close()
    client.load_host_keys(KNOWN_HOSTS)
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy() if trust else paramiko.RejectPolicy())

    kwargs = dict(
        hostname=hostname, port=int(port), username=username,
        timeout=15, banner_timeout=15, auth_timeout=15,
        allow_agent=False, look_for_keys=False,
    )
    if key:
        kwargs["pkey"] = _load_pkey(key, key_passphrase)
    elif password:
        kwargs["password"] = password
    else:
        raise ValueError("请填写密码或私钥")

    client.connect(**kwargs)
    transport = client.get_transport()
    if transport:
        transport.set_keepalive(30)
    return client


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
def _get_session(token: str) -> Session:
    sess = SESSIONS.get(token or "")
    if sess is None:
        raise HTTPException(401, "会话不存在或已断开")
    return sess


def _sftp_call(sess: Session, fn):
    """在共享 SFTP 通道上执行短操作（列表/stat/删除）。
    注意：paramiko 的 SFTPClient 不允许跨线程并发请求（会错读响应包导致死锁），
    因此共享通道必须串行；大文件传输走独立通道，不受此限制。"""
    with sess.lock:
        try:
            return fn(sess.get_sftp())
        except HTTPException:
            raise
        except Exception:
            sess.reset_sftp()
            return fn(sess.get_sftp())


def _sanitize_name(name: str) -> str:
    if not name or name in (".", "..") or "/" in name or "\\" in name or "\x00" in name or len(name) > 255:
        raise HTTPException(400, "文件名不合法")
    return name


@app.get("/api/files")
async def list_files(token: str, path: str = ".", _: None = Depends(require_auth)):
    sess = _get_session(token)

    def op(sftp):
        try:
            p = sftp.normalize(path or ".")
            attrs = sftp.listdir_attr(p)
        except OSError as e:
            if e.errno == errno.EACCES:            # 与"路径不存在"区分开
                raise HTTPException(403, "权限不足")
            raise HTTPException(404, "路径不存在")
        entries = []
        for a in attrs:
            if a.filename in (".", ".."):
                continue
            entries.append({
                "name": a.filename,
                "is_dir": stat_mod.S_ISDIR(a.st_mode or 0),
                "size": int(getattr(a, "st_size", 0) or 0),
                "mtime": int(getattr(a, "st_mtime", 0) or 0),
            })
        entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
        # 当前路径所在文件系统的空间状态（statvfs 扩展，服务器不支持则为 null）
        vfs = None
        try:
            v = sftp.statvfs(p)
            unit = (v.f_frsize or v.f_bsize or 1)
            total = v.f_blocks * unit
            free = v.f_bfree * unit
            vfs = {"total": total, "free": free, "used": total - free,
                   "percent": round((total - free) / total * 100, 1) if total else 0.0}
        except Exception:
            pass
        return {"path": p, "entries": entries, "vfs": vfs}

    return await asyncio.to_thread(_sftp_call, sess, op)


@app.get("/api/stat")
async def stat_path(token: str, path: str, _: None = Depends(require_auth)):
    """下载前预检：文件是否还存在（服务器上可能已被删除）"""
    sess = _get_session(token)

    def op(sftp):
        try:
            st = sftp.stat(path)
        except OSError:
            return {"exists": False}
        return {"exists": True, "is_dir": stat_mod.S_ISDIR(st.st_mode or 0),
                "size": int(getattr(st, "st_size", 0) or 0)}

    return await asyncio.to_thread(_sftp_call, sess, op)


# ---------- 大文件传输调优参数 ----------
DL_BLOCK = 1 << 20        # 每个读线程单块 1MB
DL_READERS = 6            # 并行读线程数（多路 SFTP 读流水线，隐藏 RTT）
DL_REQ = 1 << 18          # 单个 SFTP 读请求 256KB（旧服务器短读时自动补齐）
UP_REQ = 192 * 1024       # 单个 SFTP 写请求 192KB（低于协议包上限，兼容旧服务器）
UP_BUF = 1 << 20          # 上传聚合写缓冲 1MB（配合 pipelined 深度流水线写）


@app.get("/api/download")
async def download_file(token: str, path: str, _: None = Depends(require_auth)):
    sess = _get_session(token)

    def op(sftp):
        st = sftp.stat(path)
        if stat_mod.S_ISDIR(st.st_mode or 0):
            raise HTTPException(400, "目录不能下载，请进入目录后下载文件")
        return st.st_size

    size = await asyncio.to_thread(_sftp_call, sess, op)

    stop = threading.Event()
    q: "queue.Queue" = queue.Queue(maxsize=DL_READERS * 4)

    def put_q(item):
        while not stop.is_set():
            try:
                q.put(item, timeout=5)
                return True
            except queue.Full:
                continue
        return False

    def reader(idx):
        f = None
        sftp = None
        try:
            sftp = sess.client.open_sftp()    # 每个读线程独立 SFTP 通道（Transport 多路复用，线程安全）
            f = sftp.open(path, "rb")
            f.MAX_REQUEST_SIZE = DL_REQ      # 提高 paramiko 默认 32KB 的单请求上限
            pos = idx * DL_BLOCK
            while pos < size and not stop.is_set():
                remain = min(DL_BLOCK, size - pos)
                f.seek(pos)
                buf = bytearray()
                while len(buf) < remain and not stop.is_set():
                    d = f.read(remain - len(buf))
                    if not d:
                        break
                    buf.extend(d)
                if len(buf) != remain:
                    put_q((None, IOError(f"读取不完整 @{pos}")))
                    return
                if not put_q((pos, bytes(buf))):
                    return
                pos += DL_BLOCK * DL_READERS
        except Exception as e:
            put_q((None, e))
        finally:
            if f:
                try:
                    f.close()
                except Exception:
                    pass
            if sftp:
                try:
                    sftp.close()
                except Exception:
                    pass

    def start_readers():
        for i in range(DL_READERS):
            threading.Thread(target=reader, args=(i,), daemon=True).start()

    await asyncio.to_thread(start_readers)

    def pump():
        """按 offset 排序输出各线程读到的块（并行读、顺序写流）"""
        out = {}
        next_pos = 0
        first_err = None
        try:
            while next_pos < size:
                try:
                    pos, item = q.get(timeout=120)
                except queue.Empty:
                    first_err = TimeoutError("下载超时")
                    break
                if isinstance(item, Exception):
                    first_err = item
                    break
                out[pos] = item
                while next_pos in out:
                    data = out.pop(next_pos)
                    yield data
                    next_pos += len(data)
        finally:
            stop.set()
            try:                            # 清空队列，让读线程尽快退出
                while True:
                    q.get_nowait()
            except queue.Empty:
                pass
        if first_err:
            raise first_err

    name = posixpath.basename(posixpath.normpath(path)) or "file"
    ascii_name = name if name.isascii() else "file"
    return StreamingResponse(
        pump(),
        media_type="application/octet-stream",
        headers={
            "Content-Length": str(size),
            "Content-Disposition": f"attachment; filename=\"{ascii_name}\"; filename*=UTF-8''{quote(name)}",
        },
    )


@app.put("/api/upload")
async def upload_file(request: Request, token: str, path: str, name: str, offset: int = 0, _: None = Depends(require_auth)):
    """分片并行上传：前端把大文件切成多段，各带 offset 并发 PUT，
    后端各自 seek 到 offset 写入（SFTP 随机写），互不干扰。offset 缺省=0 兼容单流上传。"""
    sess = _get_session(token)
    name = _sanitize_name(name)
    if offset < 0:
        raise HTTPException(400, "offset 不合法")
    target = posixpath.join(path, name)
    written = 0

    def open_rw():
        # 每个分片请求独享一条 SFTP 通道（paramiko 单通道不支持跨线程并发请求）
        sftp = sess.client.open_sftp()
        try:
            # 首个到达的分片建文件，其余 r+b 随机写（per-target 锁避免并发建文件互删）
            with sess.upload_lock(target):
                try:
                    f = sftp.open(target, "r+b")
                except OSError:
                    f = sftp.open(target, "wb")
                    f.close()
                    f = sftp.open(target, "r+b")
        except Exception:
            try:
                sftp.close()
            except Exception:
                pass
            raise
        f.MAX_REQUEST_SIZE = UP_REQ          # 提高单写请求上限
        try:
            f.set_pipelined(True)            # 异步流水线写，深度隐藏 RTT
        except Exception:
            pass
        f.seek(offset)
        return f, sftp

    f, sftp = await asyncio.to_thread(open_rw)
    try:
        buf = bytearray()
        async for chunk in request.stream():
            buf.extend(chunk)
            if len(buf) >= UP_BUF:
                data = bytes(buf)
                await asyncio.to_thread(f.write, data)
                written += len(data)
                buf.clear()
        if buf:
            data = bytes(buf)
            await asyncio.to_thread(f.write, data)
            written += len(data)
    except OSError as e:
        if e.errno == errno.EACCES:
            raise HTTPException(403, "权限不足")
        raise HTTPException(500, "上传中断")
    except Exception:
        raise HTTPException(500, "上传中断")
    finally:
        try:
            await asyncio.to_thread(f.close)
        except Exception:
            pass
        try:
            await asyncio.to_thread(sftp.close)
        except Exception:
            pass
    return {"written": written}


@app.delete("/api/files")
async def delete_file(token: str, path: str, _: None = Depends(require_auth)):
    sess = _get_session(token)

    def op(sftp):
        try:
            st = sftp.stat(path)
            (sftp.rmdir if stat_mod.S_ISDIR(st.st_mode or 0) else sftp.remove)(path)
        except OSError as e:
            if e.errno == errno.EACCES:
                raise HTTPException(403, "权限不足")
            raise HTTPException(404, "文件不存在")

    await asyncio.to_thread(_sftp_call, sess, op)
    return {"ok": True}


# ============================================================
# 终端 WebSocket
# ============================================================
@app.websocket("/ws")
async def ssh_ws(ws: WebSocket):
    await ws.accept()
    ws_user = _cur_user(ws.cookies)         # 登录过期：4401 关闭，前端引导重新登录
    if not ws_user:
        await ws.close(code=4401)
        return
    loop = asyncio.get_running_loop()

    client = None
    chan = None
    token = None
    stop = threading.Event()

    async def send(obj):
        try:
            await ws.send_text(json.dumps(obj))
        except Exception:
            pass

    try:
        raw = await ws.receive_text()
        cfg = json.loads(raw)

        conn, label, name = _resolve_connect_cfg(cfg, ws_user)
        client = await asyncio.to_thread(_ssh_connect, **conn)

        chan = client.invoke_shell(term="xterm-256color", width=120, height=30)
        chan.settimeout(0.5)

        token = secrets.token_hex(16)
        SESSIONS[token] = Session(client)
        await send({"type": "connected", "token": token, "label": label, "name": name})

        decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")

        def reader():
            try:
                while not stop.is_set():
                    try:
                        data = chan.recv(65536)
                    except socket.timeout:
                        continue
                    except Exception:
                        break
                    if not data:
                        break
                    text = decoder.decode(data)
                    if text:
                        asyncio.run_coroutine_threadsafe(
                            ws.send_text(json.dumps({"type": "data", "data": text})), loop)
            finally:
                try:
                    asyncio.run_coroutine_threadsafe(
                        ws.send_text(json.dumps({"type": "closed"})), loop)
                except Exception:
                    pass

        threading.Thread(target=reader, daemon=True).start()

        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            t = msg.get("type")
            if t == "input":
                try:
                    chan.send(msg.get("data", ""))
                except Exception:
                    break
            elif t == "resize":
                try:
                    chan.resize_pty(width=int(msg["cols"]), height=int(msg["rows"]))
                except Exception:
                    pass

    except WebSocketDisconnect:
        pass
    except Exception as e:
        await send({"type": "error", "message": str(e)})
    finally:
        stop.set()
        if token:
            SESSIONS.pop(token, None)
        if chan:
            try:
                chan.close()
            except Exception:
                pass
        if client:
            try:
                client.close()
            except Exception:
                pass


# ============================================================
# 前端页面
# ============================================================
HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>WebSSH</title>
<link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/css/xterm.min.css">
<style>
  * { box-sizing: border-box; }
  html, body { margin: 0; height: 100%; background: #1e1e1e; color: #ddd;
               font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
  .hidden { display: none !important; }

  /* ---------- 半透明滚动条（无白色底） ---------- */
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: rgba(255, 255, 255, .16); border-radius: 4px; }
  ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, .32); }
  html { scrollbar-width: thin; scrollbar-color: rgba(255,255,255,.16) transparent; }

  #app { display: flex; height: 100%; position: relative; }

  /* ---------- 侧边栏 ---------- */
  #sidebar { width: 250px; flex: none; background: #191919; border-right: 1px solid #2d2d2d;
             display: flex; flex-direction: column; position: relative; }
  #sidebar.collapsed { display: none; }
  /* 拖拽调宽手柄 */
  #sb-resize { position: absolute; top: 0; right: -3px; width: 6px; height: 100%;
               cursor: col-resize; z-index: 41; }
  #sb-resize:hover, #sb-resize.drag { background: rgba(14, 99, 156, .55); }
  body.resizing { cursor: col-resize; user-select: none; }
  /* 侧边栏收起后的浮出按钮 */
  #sidebar-fab { position: absolute; top: 10px; left: 10px; z-index: 30; padding: 6px 12px; }
  /* ---------- 侧边栏用户栏 ---------- */
  #user-bar { display: flex; align-items: center; gap: 8px; margin-top: 8px;
              font-size: 12px; color: #9cdcfe;
              padding: 2px 14px 6px 16px; }   /* 左/右留白：绿点与两侧边框保持距离 */
  #btn-settings { font-size: 16px; padding: 5px 10px; }
  #ub-dot { width: 7px; height: 7px; border-radius: 50%; background: #4ec9b0; flex: none; }
  #ub-name { max-width: 110px; overflow: hidden; text-overflow: ellipsis;
             white-space: nowrap; }

  /* ---------- 设置中心 ---------- */
  .set-tabs { display: flex; gap: 4px; border-bottom: 1px solid #3c3c3c;
              margin-bottom: 14px; }
  .set-tab { background: none; border: none; border-bottom: 2px solid transparent;
             color: #888; padding: 8px 14px; font-size: 13px; border-radius: 0; }
  .set-tab.active { color: #9cdcfe; border-bottom-color: #9cdcfe; }
  #settings-overlay .card { width: 800px; height: 640px; max-height: 90vh;
                            display: flex; flex-direction: column; }  /* 尺寸锁死 */
  #settings-overlay h1 { flex: none; }
  #set-hosts, #set-users { flex: 1; min-height: 0; display: flex; flex-direction: column; }
  #set-passwd { flex: 1; min-height: 0; overflow-y: auto; }
  .set-toolbar { display: flex; align-items: center; gap: 8px; margin-bottom: 10px; flex: none; }
  .set-toolbar input { background: #1e1e1e; border: 1px solid #3c3c3c; color: #ddd;
                       border-radius: 4px; padding: 6px 8px; font-size: 12px; outline: none; }
  .set-search { flex: 1; min-width: 120px; }
  .set-count { color: #777; font-size: 11px; flex: none; }
  .set-list { flex: 1; min-height: 0; overflow-y: auto; }
  .set-pager { display: flex; align-items: center; justify-content: center; gap: 12px;
               padding-top: 10px; border-top: 1px solid #2d2d2d; font-size: 12px;
               color: #888; flex: none; }
  .set-pager .text-btn { padding: 3px 8px; }
  .text-btn:disabled { color: #555; cursor: default; background: none; border: none; }
  .text-btn:disabled:hover { color: #555; background: none; }
  .page-jump { width: 44px; text-align: center; background: #1e1e1e;
               border: 1px solid #3c3c3c; color: #ddd; border-radius: 4px;
               padding: 2px 4px; font-size: 12px; outline: none; }
  .page-jump:focus { border-color: #0e639c; }
  .set-row { display: flex; align-items: center; gap: 8px; padding: 8px 10px;
             border-radius: 6px; font-size: 13px; }
  .set-row:hover { background: #242424; }
  .set-row .sr-main { flex: 1; min-width: 0; }
  .set-row .sr-sub { color: #777; font-size: 11px; margin-top: 2px;
                     white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .tag { font-size: 10px; color: #4ec9b0; border: 1px solid #2d5f57; border-radius: 3px;
         padding: 0 4px; flex: none; }
  .set-empty { color: #666; font-size: 12px; text-align: center; padding: 24px 0; }

  /* ---------- 密码框自绘小眼睛（隐藏 Edge 原生黑色眼睛） ---------- */
  input[type="password"]::-ms-reveal, input[type="password"]::-ms-clear { display: none; }
  .pw-wrap { position: relative; }
  .pw-wrap input { padding-right: 36px; }
  .pw-eye { position: absolute; right: 6px; top: 50%; transform: translateY(-50%);
            background: none; border: none; color: #9a9a9a; cursor: pointer;
            padding: 4px; display: flex; border-radius: 4px; }
  .pw-eye:hover { color: #ffffff; }

  /* ---------- 登录页 ---------- */
  #login-overlay { background: #141414; }          /* 纯色，完全遮住后面的应用 */
  #login-overlay .card { box-shadow: 0 14px 44px rgba(0,0,0,.65); text-align: center; }
  #login-overlay h1 { justify-content: center; display: flex; align-items: center; gap: 8px;
                      font-size: 20px; }
  .login-sub { color: #777; font-size: 12px; margin: 0 0 18px; }
  #login-overlay form { text-align: left; }

  .side-head-btns { display: flex; align-items: center; gap: 10px; margin-left: auto; }
  .side-head { display: flex; align-items: center; padding: 12px; border-bottom: 1px solid #2d2d2d; }
  .logo { font-weight: 600; font-size: 15px; color: #9cdcfe; flex: none; white-space: nowrap; }
  #host-list { flex: 1; overflow-y: auto; padding: 8px; }
  .host-empty { color: #666; font-size: 12px; text-align: center; margin-top: 40px; line-height: 2; }
  #host-title { display: flex; align-items: center; justify-content: space-between;
               padding: 8px 12px 4px; font-size: 12px; color: #888; }
  #host-count { font-size: 11px; color: #666; }
  .host-item { display: flex; align-items: center; gap: 4px; padding: 5px 10px; border-radius: 6px;
               cursor: pointer; margin-bottom: 2px; border: 1px solid transparent; }
  .host-item:hover { background: #242424; border-color: #2f2f2f; }
  .host-item.active { background: #094771; border-color: #0e639c; }
  .host-name { font-size: 13px; flex: 1; min-width: 0; white-space: nowrap; overflow: hidden;
               text-overflow: ellipsis; }
  .host-actions { display: none; gap: 2px; }
  .host-item:hover .host-actions { display: flex; }
  .icon-btn { background: none; border: none; color: #9cdcfe; cursor: pointer; font-size: 13px;
              padding: 3px 5px; border-radius: 4px; line-height: 1; text-decoration: none; }
  .icon-btn:hover { background: #333; color: #fff; }
  .icon-btn.danger:hover { color: #f48771; }
  .icon-btn.flip-x { transform: scaleX(-1); }   // 铅笔笔尖朝左下（✎ 原本朝右下，水平镜像）
  .side-foot { padding: 10px; border-top: 1px solid #2d2d2d; }

  /* ---------- 主区域 ---------- */
  #main { flex: 1; min-width: 0; display: flex; flex-direction: column; }
  #empty-state { flex: 1; display: flex; align-items: center; justify-content: center; }
  .empty-card { text-align: center; color: #aaa; }
  .empty-card h1 { font-size: 26px; color: #ddd; margin: 0 0 6px; }
  .empty-card p { margin: 0 0 18px; font-size: 13px; color: #777; }
  .empty-card ol { text-align: left; display: inline-block; font-size: 13px; line-height: 2.1;
                   color: #999; margin: 0 0 20px; }
  .empty-actions { display: flex; gap: 10px; justify-content: center; }

  #session-view { flex: 1; display: flex; flex-direction: column; min-height: 0; }
  #session-body { flex: 1; display: flex; min-height: 0; }
  #term-stack { flex: 1; min-width: 0; position: relative; }
  .term-box { position: absolute; inset: 4px; display: none; }
  .term-box.active { display: block; }

  /* ---------- 终端标签栏 ---------- */
  #tabbar { display: flex; align-items: center; gap: 4px; background: #181818;
            border-bottom: 1px solid #2d2d2d; padding: 4px 6px; flex: none; }
  #tabs { display: flex; gap: 4px; flex: 1; min-width: 0; overflow-x: auto; }
  .chev-btn { flex: none; font-size: 14px; padding: 4px 8px; color: #9cdcfe; }
  .tab { display: flex; align-items: center; gap: 6px; padding: 5px 8px 5px 10px; font-size: 12px;
         background: #222; border: 1px solid #2f2f2f; border-radius: 6px 6px 0 0;
         cursor: pointer; color: #aaa; max-width: 190px; user-select: none; flex: none; }
  .tab.active { background: #0e639c; color: #fff; border-color: #0e639c; }
  .tab.dragging { opacity: .4; }
  .tab-name { max-width: 130px; overflow: hidden; text-overflow: ellipsis;
              white-space: nowrap; }
  .tab-x { opacity: 0; padding: 0 2px; border-radius: 3px; }
  .tab:hover .tab-x { opacity: .8; }
  .tab-x:hover { color: #f48771; opacity: 1; }
  .tab-dot { width: 7px; height: 7px; border-radius: 50%; flex: none; }
  .tab-dot.on { background: #4ec9b0; }
  .tab-dot.off { background: #f48771; }

  /* ---------- 标签右键菜单 ---------- */
  #ctx-menu { position: fixed; z-index: 200; background: #2a2a2a; border: 1px solid #454545;
              border-radius: 6px; box-shadow: 0 6px 18px rgba(0,0,0,.5); padding: 4px;
              min-width: 160px; font-size: 13px; }
  .ctx-item { padding: 6px 14px; border-radius: 4px; cursor: pointer; color: #ddd; }
  .ctx-item:hover { background: #094771; color: #fff; }
  .ctx-item.danger:hover { background: #7a2e2e; }
  .ctx-sep { height: 1px; background: #454545; margin: 4px 8px; }

  /* ---------- 文件面板 ---------- */
  #file-panel { width: 320px; flex: none; border-left: 1px solid #333; background: #212121;
                display: flex; flex-direction: column; min-height: 0; position: relative; }
  /* 文件面板左缘拖拽调宽手柄 */
  #fp-resize { position: absolute; top: 0; left: -3px; width: 6px; height: 100%;
               cursor: col-resize; z-index: 45; }
  #fp-resize:hover, #fp-resize.drag { background: rgba(14, 99, 156, .55); }
  .fp-head { display: flex; align-items: center; gap: 6px; padding: 8px; border-bottom: 1px solid #333; }
  #fp-path { flex: 1; min-width: 0; background: #1a1a1a; border: 1px solid #333; color: #9cdcfe;
             border-radius: 4px; padding: 4px 8px; font-size: 12px;
             font-family: Consolas, "Courier New", monospace; outline: none; }
  #fp-path:focus { border-color: #0e639c; }
  #fp-path.invalid { color: #f48771; }
  #fp-status { font-size: 11px; color: #888; padding: 4px 8px; min-height: 22px;
               white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  #fp-status.err { color: #f48771; }
  #fp-list { flex: 1; overflow-y: auto; padding: 4px 0; }
  .fp-row { display: flex; align-items: center; gap: 6px; padding: 5px 10px; font-size: 13px;
            cursor: pointer; }
  .fp-row:hover { background: #2a2a2a; }
  .fp-name { flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .fp-name.dir { color: #dcdcaa; }
  .fp-meta { font-size: 11px; color: #777; flex: none; }
  .fp-acts { display: none; gap: 2px; flex: none; }
  .fp-row:hover .fp-acts { display: flex; }
  .fp-empty { color: #666; font-size: 12px; text-align: center; margin-top: 30px; }
  #fp-footer { padding: 8px; border-top: 1px solid #333; flex: none; }
  #task-badge { color: #4ec9b0; margin-left: 4px; }

  /* ---------- 传输任务 ---------- */
  .task-row { padding: 8px 2px; border-bottom: 1px solid #2d2d2d; }
  .task-row:last-child { border-bottom: none; }
  .task-head { display: flex; align-items: center; gap: 6px; font-size: 13px; }
  .task-kind { flex: none; width: 18px; text-align: center; }
  .task-name { flex: 1; min-width: 0; white-space: nowrap; overflow: hidden;
               text-overflow: ellipsis; }
  .task-sess { color: #777; font-size: 11px; flex: none; }
  .task-bar { height: 4px; background: #333; border-radius: 2px; margin: 6px 0 4px; overflow: hidden; }
  .task-fill { height: 100%; background: #0e639c; border-radius: 2px; transition: width .2s; }
  .task-fill.done { background: #4ec9b0; }
  .task-fill.err { background: #f48771; }
  .task-meta { display: flex; align-items: center; justify-content: space-between;
               font-size: 11px; color: #888; }
  .task-cancel { background: none; border: 1px solid #555; color: #bbb; border-radius: 3px;
                 padding: 1px 8px; font-size: 11px; cursor: pointer; }
  .task-cancel:hover { border-color: #f48771; color: #f48771; }
  .text-btn, .text-btn:hover,
  .text-btn.danger, .text-btn.danger:hover {
    background: none; border: none; }   /* 覆盖全局 button/button:hover 的填充 */
  .text-btn { color: #9cdcfe; padding: 3px 8px; font-size: 12px;
              cursor: pointer; flex: none; }
  .text-btn:hover { color: #4ec9b0; }
  .text-btn.danger { color: #f48771; }
  .text-btn.danger:hover { color: #ff9d9d; }
  #task-list { max-height: 50vh; overflow-y: auto; }
  .task-empty { color: #666; font-size: 12px; text-align: center; padding: 30px 0; }

  /* ---------- 按钮 ---------- */
  button { border: none; border-radius: 4px; cursor: pointer; font-size: 13px;
           padding: 8px 14px; background: #0e639c; color: #fff; }
  button:hover { background: #1177bb; }
  button:disabled { background: #555; cursor: not-allowed; }
  button.small { padding: 4px 10px; font-size: 12px; }
  button.ghost { background: transparent; color: #bbb; border: 1px solid #444; }
  button.ghost:hover { background: #2a2a2a; color: #fff; }
  button.danger { background: #7a2e2e; }
  button.danger:hover { background: #a13d3d; }
  label.upload-btn { background: #0e639c; color: #fff; border-radius: 4px; cursor: pointer;
                     padding: 4px 10px; font-size: 12px; }
  label.upload-btn:hover { background: #1177bb; }

  /* ---------- 弹窗 ---------- */
  .overlay { position: fixed; inset: 0; background: rgba(0,0,0,.55); display: flex;
             align-items: center; justify-content: center; z-index: 50; }
  .card { background: #252526; border: 1px solid #3c3c3c; border-radius: 8px;
          padding: 22px; width: 440px; max-width: 92vw; max-height: 90vh; overflow-y: auto; }
  .card h1 { margin: 0 0 16px; font-size: 17px; font-weight: 600; }
  .field { margin-bottom: 12px; }
  .field label { display: block; font-size: 12px; color: #9cdcfe; margin-bottom: 4px; }
  .field input, .field textarea {
    width: 100%; background: #1e1e1e; border: 1px solid #3c3c3c; color: #ddd;
    padding: 8px; border-radius: 4px; font-size: 13px; font-family: inherit; outline: none; }
  .field input:focus, .field textarea:focus { border-color: #0e639c; }
  .field textarea { resize: vertical; min-height: 70px; font-family: monospace; }
  .row { display: flex; gap: 10px; }
  .row .field { flex: 1; }
  .checkbox-field { display: flex; align-items: center; gap: 8px; margin: 4px 0 12px; }
  .checkbox-field input { width: auto; }
  .checkbox-field label { margin: 0; color: #9cdcfe; font-size: 12px; cursor: pointer; }
  .modal-actions { display: flex; justify-content: flex-end; gap: 10px; margin-top: 6px; }
  /* 从设置中心里弹出的二级弹窗，需盖在设置之上 */
  #host-overlay, #user-overlay { z-index: 60; }
  details { margin-bottom: 10px; }
  details summary { cursor: pointer; font-size: 12px; color: #9cdcfe; margin-bottom: 8px;
                    user-select: none; }

  /* ---------- Toast ---------- */
  #toast { position: fixed; top: 14px; left: 50%; transform: translateX(-50%);
           background: #333; color: #fff; border: 1px solid #555; padding: 9px 16px;
           border-radius: 6px; font-size: 13px; z-index: 100; max-width: 80vw;
           opacity: 0; transition: opacity .2s; pointer-events: none; }
  #toast.show { opacity: 1; }
  #toast.err { background: #5a2323; border-color: #8a3535; }
</style>
</head>
<body>
<div id="app">
  <!-- 侧边栏：主机资产列表 -->
  <aside id="sidebar">
    <div class="side-head">
      <span class="logo">⌨ WebSSH</span>
      <span class="side-head-btns">
        <button id="btn-new-host" class="small" title="新增主机">＋</button>
        <button id="btn-hide-sb" type="button" class="icon-btn chev-btn" title="隐藏侧边栏">«</button>
      </span>
    </div>
    <div id="host-title"><span>主机列表</span><span id="host-count">数量 0</span></div>
    <div id="host-list"></div>
    <div class="side-foot">
      <button id="btn-manual" class="ghost small" style="width:100%">手动连接（不保存）</button>
      <div id="user-bar">
        <span id="ub-dot"></span>
        <span id="ub-name">-</span>
        <span style="flex:1"></span>
        <button id="btn-logout" type="button" class="icon-btn" title="退出登录">退出</button>
        <button id="btn-settings" type="button" class="icon-btn" title="设置">⚙</button>
      </div>
    </div>
    <div id="sb-resize" title="拖拽调整宽度"></div>
  </aside>

  <!-- 侧边栏隐藏后的显示按钮 -->
  <button id="sidebar-fab" class="hidden" title="显示资产列表">☰ 资产</button>

  <!-- 主区域 -->
  <main id="main">
    <div id="empty-state">
      <div class="empty-card">
        <h1>WebSSH</h1>
        <p>轻量堡垒机 · 网页终端 · 文件传输</p>
        <ol>
          <li>点击左上「＋ 主机」添加服务器（IP / 端口 / 用户 / 密码）</li>
          <li>点击主机名称即可打开终端标签页，可同时开多个</li>
          <li>标签页右键：复制窗口 / 重新连接 / 关闭</li>
          <li>点右上角「«»」展开文件管理，可上传 / 下载文件</li>
        </ol>
        <div class="empty-actions">
          <button id="btn-new-host2">新增主机</button>
          <button id="btn-manual2" class="ghost">手动连接</button>
        </div>
      </div>
    </div>

    <div id="session-view" class="hidden">
      <div id="tabbar">
        <button id="sb-expand" type="button" class="icon-btn chev-btn hidden" title="显示资产列表">»</button>
        <div id="tabs"></div>
        <button id="btn-files" type="button" class="icon-btn chev-btn" title="展开文件管理">«</button>
      </div>
      <div id="session-body">
        <div id="term-stack"></div>
        <div id="file-panel" class="hidden">
          <div id="fp-resize" title="拖拽调整宽度"></div>
          <div class="fp-head">
            <button id="fp-up" class="small ghost" title="上级目录">↑</button>
            <input id="fp-path" placeholder="输入路径，回车跳转" spellcheck="false" autocomplete="off">
            <label class="upload-btn">上传<input type="file" id="fp-input" multiple hidden></label>
            <button id="fp-refresh" type="button" class="icon-btn" title="刷新">↻</button>
          </div>
          <div id="fp-status"></div>
          <div id="fp-list"></div>
          <div id="fp-footer">
            <button id="btn-tasks" class="small ghost" style="width:100%">传输详情<span id="task-badge"></span></button>
          </div>
        </div>
      </div>
    </div>
  </main>
</div>

<!-- 主机 新增/编辑 弹窗 -->
<div class="overlay hidden" id="host-overlay">
  <div class="card">
    <h1 id="host-modal-title">新增主机</h1>
    <form id="host-form">
      <div class="field">
        <label>名称</label>
        <input id="hf-name" required maxlength="64" placeholder="如：生产-web01" autocomplete="off">
      </div>
      <div class="row">
        <div class="field" style="flex:2">
          <label>主机 IP / 域名</label>
          <input id="hf-host" required placeholder="192.168.1.10" autocomplete="off">
        </div>
        <div class="field" style="flex:1">
          <label>端口</label>
          <input id="hf-port" type="number" value="22" min="1" max="65535">
        </div>
      </div>
      <div class="field">
        <label>用户名</label>
        <input id="hf-user" required autocomplete="off">
      </div>
      <div class="field">
        <label>密码</label>
        <input id="hf-pass" type="password" autocomplete="new-password" placeholder="">
      </div>
      <details>
        <summary>私钥认证（可选，与密码二选一）</summary>
        <div class="field">
          <label>私钥内容（OpenSSH 格式）</label>
          <textarea id="hf-key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
        </div>
        <div class="field">
          <label>私钥口令（如无可留空）</label>
          <input id="hf-keypass" type="password" autocomplete="new-password">
        </div>
      </details>
      <div class="field">
        <label>备注（可选）</label>
        <input id="hf-remark" maxlength="128" autocomplete="off">
      </div>
      <div class="checkbox-field">
        <input id="hf-trust" type="checkbox">
        <label for="hf-trust">信任主机密钥（TOFU：首次记录指纹，变更即拒绝）</label>
      </div>
      <div class="modal-actions">
        <button type="button" class="ghost" data-close>取消</button>
        <button type="submit" id="host-submit">保 存</button>
      </div>
    </form>
  </div>
</div>

<!-- 手动连接 弹窗 -->
<div class="overlay hidden" id="manual-overlay">
  <div class="card">
    <h1>手动连接</h1>
    <form id="manual-form">
      <div class="row">
        <div class="field" style="flex:2">
          <label>主机 IP / 域名</label>
          <input id="mf-host" required placeholder="192.168.1.10" autocomplete="off">
        </div>
        <div class="field" style="flex:1">
          <label>端口</label>
          <input id="mf-port" type="number" value="22" min="1" max="65535">
        </div>
      </div>
      <div class="field">
        <label>用户名</label>
        <input id="mf-user" required autocomplete="off">
      </div>
      <div class="field">
        <label>密码</label>
        <input id="mf-pass" type="password" autocomplete="off">
      </div>
      <details>
        <summary>私钥认证（可选）</summary>
        <div class="field">
          <label>私钥内容（OpenSSH 格式）</label>
          <textarea id="mf-key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----"></textarea>
        </div>
        <div class="field">
          <label>私钥口令（如无可留空）</label>
          <input id="mf-keypass" type="password" autocomplete="off">
        </div>
      </details>
      <div class="checkbox-field">
        <input id="mf-trust" type="checkbox">
        <label for="mf-trust">信任此主机密钥（仅内网/可信网络勾选）</label>
      </div>
      <div class="modal-actions">
        <button type="button" class="ghost" data-close>取消</button>
        <button type="submit" id="manual-submit">连 接</button>
      </div>
      <div class="hint" style="font-size:11px;color:#777;margin-top:10px">
        提示：连接后同样可使用文件上传下载；主机信息不会保存。
      </div>
    </form>
  </div>
</div>

<!-- 标签页右键菜单 -->
<div id="ctx-menu" class="hidden">
  <div class="ctx-item" data-act="dup">复制窗口</div>
  <div class="ctx-item" data-act="reconn">重新连接</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-act="close">关闭当前</div>
  <div class="ctx-item danger" data-act="closeAll">关闭所有</div>
</div>

<!-- 登录页 -->
<div class="overlay hidden" id="login-overlay">
  <div class="card" style="width:360px">
    <h1>⌨ WebSSH</h1>
    <p class="login-sub">轻量堡垒机 v1.0.0 · 请登录</p>
    <form id="login-form">
      <div class="field">
        <label>账号</label>
        <input id="lg-user" required autocomplete="username" placeholder="用户名">
      </div>
      <div class="field">
        <label>密码</label>
        <div class="pw-wrap">
          <input id="lg-pass" type="password" required autocomplete="current-password">
          <button type="button" id="lg-eye" class="pw-eye" title="显示/隐藏密码" tabindex="-1">
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
          </button>
        </div>
      </div>
      <button type="submit" id="login-btn" style="width:100%">登 录</button>
      <div id="login-error" style="color:#f48771;font-size:12px;margin-top:10px;min-height:16px"></div>
    </form>
  </div>
</div>

<!-- 设置中心 -->
<div class="overlay hidden" id="settings-overlay">
  <div class="card" style="width:660px">
    <h1>设置</h1>
    <div class="set-tabs">
      <button type="button" class="set-tab active" data-tab="hosts">主机管理</button>
      <button type="button" class="set-tab" data-tab="passwd">修改密码</button>
      <button type="button" class="set-tab hidden" data-tab="users" id="tab-users">用户管理</button>
    </div>

    <div id="set-hosts">
      <div class="set-toolbar">
        <input id="sh-search" class="set-search" placeholder="搜索名称 / IP / 用户名 / 备注">
        <button id="btn-add-host2" class="small">＋ 新增主机</button>
      </div>
      <div id="set-host-list" class="set-list"></div>
      <div class="set-pager" id="sh-pager"></div>
    </div>

    <div id="set-passwd" class="hidden">
      <form id="pw-form">
        <div class="field" id="pw-old-row">
          <label>旧密码</label>
          <input id="pw-old" type="password" autocomplete="off">
        </div>
        <div id="pw-admin-hint" class="hidden" style="color:#777;font-size:11px;margin-bottom:12px">
          管理员修改密码无需验证旧密码
        </div>
        <div class="field">
          <label>新密码（至少 8 位）</label>
          <input id="pw-new" type="password" autocomplete="new-password" required minlength="8">
        </div>
        <div class="field">
          <label>确认新密码</label>
          <input id="pw-new2" type="password" autocomplete="new-password" required minlength="8">
        </div>
        <button type="submit">保存新密码</button>
      </form>
    </div>

    <div id="set-users" class="hidden">
      <div class="set-toolbar">
        <input id="su-search" class="set-search" placeholder="搜索用户名">
        <button id="btn-add-user" class="small">＋ 新增用户</button>
      </div>
      <div id="user-list" class="set-list"></div>
      <div class="set-pager" id="su-pager"></div>
    </div>

    <div class="modal-actions"><button type="button" class="ghost" data-close>关 闭</button></div>
  </div>
</div>

<!-- 新增用户 弹窗 -->
<div class="overlay hidden" id="user-overlay">
  <div class="card" style="width:400px">
    <h1>新增用户</h1>
    <form id="user-form">
      <div class="field">
        <label>用户名（2-32 位字母/数字/_.-）</label>
        <input id="nu-user" required maxlength="32" autocomplete="off">
      </div>
      <div class="field">
        <label>密码（至少 8 位）</label>
        <input id="nu-pass" type="password" required minlength="8" autocomplete="new-password">
      </div>
      <div class="checkbox-field">
        <input id="nu-admin" type="checkbox">
        <label for="nu-admin">管理员（可管理用户、免旧密码修改密码）</label>
      </div>
      <div class="modal-actions">
        <button type="button" class="ghost" data-close>取 消</button>
        <button type="submit">保 存</button>
      </div>
    </form>
  </div>
</div>

<!-- 通用输入弹窗 -->
<div class="overlay hidden" id="prompt-overlay">
  <div class="card" style="width:360px">
    <h1 id="pt-title">输入</h1>
    <div class="field" style="margin-top:4px">
      <input id="pt-input" autocomplete="off">
    </div>
    <div class="modal-actions">
      <button type="button" class="ghost" id="pt-no">取 消</button>
      <button type="button" id="pt-yes">确 定</button>
    </div>
  </div>
</div>

<!-- 通用确认弹窗（替代浏览器原生 confirm） -->
<div class="overlay hidden" id="confirm-overlay">
  <div class="card" style="width:380px">
    <h1 id="cf-title">确认操作</h1>
    <p id="cf-msg" style="font-size:13px;color:#ccc;white-space:pre-wrap;margin:0 0 16px;line-height:1.7"></p>
    <div class="modal-actions">
      <button type="button" class="ghost" id="cf-no">取 消</button>
      <button type="button" class="danger" id="cf-yes">确 定</button>
    </div>
  </div>
</div>

<!-- 传输详情 弹窗 -->
<div class="overlay hidden" id="tasks-overlay">
  <div class="card" style="width:540px">
    <h1>传输详情<span id="tasks-count" style="color:#888;font-size:12px;font-weight:400"></span></h1>
    <div id="task-list"></div>
    <div class="modal-actions">
      <button class="ghost small" id="btn-clear-done">清除已完成</button>
      <button class="ghost" data-close>关闭</button>
    </div>
  </div>
</div>

<div id="toast"></div>

<script src="https://cdn.jsdelivr.net/npm/@xterm/xterm@5.5.0/lib/xterm.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/@xterm/addon-fit@0.10.0/lib/addon-fit.min.js"></script>
<script>
(function () {
  const $ = (id) => document.getElementById(id);

  // ==================== 多标签终端会话 ====================
  const sessions = new Map();   // id -> {id,cfg,ws,term,fit,box,tab,token,label,name,status,pending}
  let activeId = null;
  let seq = 0;
  let curPath = null;           // 文件面板当前目录
  let dragTabId = null;         // 正在拖拽排序的标签
  const activeS = () => sessions.get(activeId);

  function fitActive() {
    const s = activeS();
    if (s && s.fit) { try { s.fit.fit(); } catch (e) {} }
  }

  // ==================== 工具 ====================
  let toastTimer = null;
  function toast(msg, isErr) {
    const t = $('toast');
    t.textContent = msg;
    t.className = 'show' + (isErr ? ' err' : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.className = ''; }, 3200);
  }

  $('lg-eye').onclick = () => {
    const i = $('lg-pass');
    i.type = i.type === 'password' ? 'text' : 'password';
  };

  function showLogin() {
    ME = null;
    updateUserBar();
    $('login-overlay').classList.remove('hidden');
    $('login-error').textContent = '';
    setTimeout(() => $('lg-pass').focus(), 0);
  }

  function updateUserBar() {
    $('ub-name').textContent = ME ? ME.user : '-';
    $('ub-dot').style.background = ME ? '#4ec9b0' : '#f48771';
  }
  function applyMe() {                    // 登录成功/静默恢复后统一刷新身份相关 UI
    updateUserBar();
    $('tab-users').classList.toggle('hidden', !(ME && ME.admin));
  }
  $('login-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const btn = $('login-btn');
    btn.disabled = true;
    $('login-error').textContent = '';
    try {
      const login_res = await api('/api/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: $('lg-user').value.trim(), password: $('lg-pass').value }),
      });
      ME = login_res;
      applyMe();
      $('login-overlay').classList.add('hidden');
      $('lg-pass').value = '';
      updateUserBar();
      loadHosts();
    } catch (e) {
      // 401 账密错误 / 429 限速锁定（透传服务端提示）
      $('login-error').textContent = (e && e.status === 429) ? e.message : '账号或密码错误';
    } finally {
      btn.disabled = false;
    }
  });

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).catch(() => legacyCopy(text));
      return;
    }
    legacyCopy(text);
  }
  function legacyCopy(text) {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    try { document.execCommand('copy'); } catch (e) {}
    document.body.removeChild(ta);
  }

  let ME = null;   // 当前登录用户 {user, admin}

  async function api(path, opts) {
    const r = await fetch(path, opts);
    if (r.status === 401 && !path.startsWith('/api/login')) {
      showLogin();                          // 登录过期：任何接口统一引导重新登录
      throw Object.assign(new Error('未登录或登录已过期'), { status: 401 });
    }
    if (!r.ok) {
      let msg = '请求失败 (' + r.status + ')';
      try { msg = (await r.json()).detail || msg; } catch (e) {}
      const err = new Error(msg);
      err.status = r.status;               // 供调用方区分 403 权限不足 / 404 无效路径 等
      throw err;
    }
    return r.json();
  }

  function humanSize(n) {
    if (n < 1024) return n + ' B';
    const u = ['KB', 'MB', 'GB', 'TB'];
    let i = -1;
    do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1);
    return n.toFixed(n >= 100 ? 0 : 1) + ' ' + u[i];
  }

  // ==================== 侧边栏：宽度 / 隐藏 显示 ====================
  const SB_KEY = 'webssh_sidebar';
  const SB_MIN = 180, SB_MAX = 480;
  let sb = { width: 250, hidden: false };
  try { Object.assign(sb, JSON.parse(localStorage.getItem(SB_KEY) || '{}')); } catch (e) {}
  sb.width = Math.min(SB_MAX, Math.max(SB_MIN, Number(sb.width) || 250));

  function saveSb() { localStorage.setItem(SB_KEY, JSON.stringify(sb)); }

  function applySidebar() {
    const el = $('sidebar');
    el.classList.toggle('collapsed', sb.hidden);
    el.style.width = sb.width + 'px';
    updateSbExpand();
    saveSb();
    fitActive();
  }

  // 侧边栏收起时的展开入口：有标签页 → 标签栏最左「»」；无标签页 → 左上角「☰ 资产」
  function updateSbExpand() {
    const noTabs = sessions.size === 0;
    $('sidebar-fab').classList.toggle('hidden', !sb.hidden || !noTabs);
    $('sb-expand').classList.toggle('hidden', !sb.hidden || noTabs);
  }

  // 隐藏 / 显示
  $('btn-hide-sb').onclick = () => { sb.hidden = true; applySidebar(); };
  $('sidebar-fab').onclick = () => { sb.hidden = false; applySidebar(); };
  $('sb-expand').onclick = () => { sb.hidden = false; applySidebar(); };

  // 拖拽右缘调宽（Pointer Events，可拖出窗口边界）
  $('sb-resize').addEventListener('pointerdown', (e) => {
    e.preventDefault();
    const rz = $('sb-resize');
    rz.setPointerCapture(e.pointerId);
    rz.classList.add('drag');
    document.body.classList.add('resizing');
    const startX = e.clientX, startW = sb.width;
    const move = (ev) => {
      sb.width = Math.min(SB_MAX, Math.max(SB_MIN, startW + ev.clientX - startX));
      $('sidebar').style.width = sb.width + 'px';
    };
    const up = () => {
      rz.releasePointerCapture(e.pointerId);
      rz.removeEventListener('pointermove', move);
      rz.removeEventListener('pointerup', up);
      rz.removeEventListener('pointercancel', up);
      rz.classList.remove('drag');
      document.body.classList.remove('resizing');
      saveSb();
      fitActive();
    };
    rz.addEventListener('pointermove', move);
    rz.addEventListener('pointerup', up);
    rz.addEventListener('pointercancel', up);
  });

  // ==================== 统一风格确认弹窗（替代浏览器原生 confirm） ====================
  let cfResolve = null;
  function dlgConfirm(msg, title) {
    return new Promise((resolve) => {
      cfResolve = resolve;
      $('cf-title').textContent = title || '确认操作';
      $('cf-msg').textContent = msg;
      $('confirm-overlay').classList.remove('hidden');
      setTimeout(() => $('cf-yes').focus(), 0);
    });
  }
  function cfDone(v) {
    $('confirm-overlay').classList.add('hidden');
    if (cfResolve) { cfResolve(v); cfResolve = null; }
  }
  $('cf-yes').onclick = () => cfDone(true);
  $('cf-no').onclick = () => cfDone(false);
  $('confirm-overlay').addEventListener('mousedown', (e) => {
    if (e.target === $('confirm-overlay')) cfDone(false);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && !$('confirm-overlay').classList.contains('hidden')) cfDone(false);
  });

  // ==================== 视图切换 ====================
  function showEmpty() {
    $('empty-state').classList.remove('hidden');
    $('session-view').classList.add('hidden');
    closeFilePanel();
    syncHostActive();
    updateSbExpand();
  }

  // 高亮当前标签对应的主机
  function syncHostActive() {
    const s = activeS();
    const hid = s && s.cfg && s.cfg.host_id;
    document.querySelectorAll('.host-item').forEach(el =>
      el.classList.toggle('active', !!hid && el.dataset.id === hid));
  }

  // ==================== 主机资产 ====================
  async function loadHosts() {
    let hosts = [];
    try { hosts = await api('/api/hosts'); }
    catch (e) { if (e.status !== 401) toast(e.message, true); return; }
    $('login-overlay').classList.add('hidden');   // 已登录（刷新场景）
    $('host-count').textContent = '数量 ' + hosts.length;
    const box = $('host-list');
    box.textContent = '';
    if (!hosts.length) {
      const d = document.createElement('div');
      d.className = 'host-empty';
      d.textContent = '暂无主机\n点右上「＋ 主机」添加';
      box.appendChild(d);
      return;
    }
    hosts.forEach(h => {
      const item = document.createElement('div');
      item.className = 'host-item';
      item.dataset.id = h.id;
      item.title = h.name + '\n' + h.username + '@' + h.host + ':' + h.port +
                   (h.remark ? '\n备注：' + h.remark : '');

      const nm = document.createElement('div');
      nm.className = 'host-name';
      nm.textContent = h.name;

      item.append(nm);                      // 资产的增删改统一在「设置」里
      item.onclick = () => newSession({ host_id: h.id });
      box.appendChild(item);
    });
  }

  function openHostModal(host) {
    $('host-modal-title').textContent = host ? '编辑主机' : '新增主机';
    $('host-form').dataset.id = host ? host.id : '';
    $('hf-name').value  = host ? host.name : '';
    $('hf-host').value  = host ? host.host : '';
    $('hf-port').value  = host ? host.port : 22;
    $('hf-user').value  = host ? host.username : '';
    $('hf-pass').value  = '';
    $('hf-pass').placeholder = host ? '密码不填为沿用旧密码' : '';

    $('hf-key').value   = '';
    $('hf-keypass').value = '';
    $('hf-remark').value = host ? host.remark : '';
    $('hf-trust').checked = host ? host.trust : false;
    $('host-overlay').classList.remove('hidden');
    $('hf-name').focus();
  }

  $('host-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const id = $('host-form').dataset.id;
    const btn = $('host-submit');
    btn.disabled = true;
    try {
      const body = {
        name: $('hf-name').value, host: $('hf-host').value, port: $('hf-port').value,
        username: $('hf-user').value, password: $('hf-pass').value,
        key: $('hf-key').value, key_passphrase: $('hf-keypass').value,
        trust: $('hf-trust').checked, remark: $('hf-remark').value,
      };
      if (id) await api('/api/hosts/' + id, { method: 'PUT', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      else    await api('/api/hosts', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify(body) });
      $('host-overlay').classList.add('hidden');
      toast(id ? '主机已更新' : '主机已添加');
      loadHosts();
      refreshSettingsHosts();
    } catch (e) {
      toast(e.message, true);
    } finally {
      btn.disabled = false;
    }
  });

  async function deleteHost(h) {
    if (!(await dlgConfirm('确定删除主机「' + h.name + '」？\n（已建立的连接不受影响）', '删除主机'))) return;
    try {
      await api('/api/hosts/' + h.id, { method: 'DELETE' });
      toast('已删除 ' + h.name);
      loadHosts();
      refreshSettingsHosts();
    } catch (e) { toast(e.message, true); }
  }

  $('btn-new-host2').onclick = () => openSettings('hosts');
  $('btn-new-host').onclick = () => openHostModal(null);

  // ==================== 手动连接 ====================
  $('btn-manual').onclick = () => { $('manual-overlay').classList.remove('hidden'); $('mf-host').focus(); };
  $('btn-manual2').onclick = () => { $('manual-overlay').classList.remove('hidden'); $('mf-host').focus(); };

  $('manual-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    $('manual-overlay').classList.add('hidden');
    newSession({
      host: $('mf-host').value.trim(),
      port: $('mf-port').value || '22',
      username: $('mf-user').value.trim(),
      password: $('mf-pass').value,
      key: $('mf-key').value.trim(),
      key_passphrase: $('mf-keypass').value,
      trust_host_key: $('mf-trust').checked,
    });
  });

  // 弹窗通用关闭
  document.querySelectorAll('[data-close]').forEach(b =>
    b.onclick = () => b.closest('.overlay').classList.add('hidden'));
  document.querySelectorAll('.overlay:not(#login-overlay)').forEach(ov =>
    ov.addEventListener('mousedown', (e) => { if (e.target === ov) ov.classList.add('hidden'); }));

  // ==================== 终端会话（多标签） ====================
  function makeKeyHandler(term) {
    // Ctrl+C 有选区复制、无选区中断；Ctrl+V 交给浏览器原生 paste
    return (e) => {
      if (e.type !== 'keydown') return true;
      const ctrl = e.ctrlKey || e.metaKey;
      const key = e.key.toLowerCase();
      if (ctrl && !e.altKey && !e.shiftKey && key === 'c') {
        if (term.hasSelection()) {
          copyText(term.getSelection());
          term.clearSelection();
          return false;
        }
        return true;
      }
      if (ctrl && !e.altKey && !e.shiftKey && key === 'v') return false;
      return true;
    };
  }

  function ensureTerm(s) {
    if (s.term) return;
    const box = document.createElement('div');
    box.className = 'term-box' + (s.id === activeId ? ' active' : '');
    $('term-stack').appendChild(box);
    s.box = box;

    const term = new Terminal({
      cursorBlink: true,
      fontFamily: 'Consolas, "Cascadia Mono", "Courier New", monospace',
      fontSize: 14,
      scrollback: 5000,
      theme: { background: '#1e1e1e', foreground: '#dddddd', cursor: '#dddddd' },
    });
    const fit = new FitAddon.FitAddon();
    term.loadAddon(fit);
    term.open(box);
    term.attachCustomKeyEventHandler(makeKeyHandler(term));

    const send = (obj) => {
      if (s.ws && s.ws.readyState === WebSocket.OPEN) s.ws.send(JSON.stringify(obj));
    };
    term.onData((data) => send({ type: 'input', data: data }));

    // 只在标签可见时 fit，避免隐藏状态下尺寸计算错误
    const origFit = fit.fit.bind(fit);
    fit.fit = function () {
      if (box.classList.contains('active')) {
        origFit();
        send({ type: 'resize', cols: term.cols, rows: term.rows });
      }
    };
    box.addEventListener('click', () => term.focus());
    s.term = term;
    s.fit = fit;
    fit.fit();
  }

  function setTabStatus(s) {
    // 仅两态：正常连接绿色，其余（连接中/断开/异常）红色
    const dot = s.tab.querySelector('.tab-dot');
    dot.className = 'tab-dot ' + (s.status === 'on' ? 'on' : 'off');
  }

  // 标签页当前视觉顺序（拖拽排序后以 DOM 为准）
  function tabOrder() {
    return [...$('tabs').children].map(el => Number(el.dataset.id));
  }

  function addTabEl(s) {
    const t = document.createElement('div');
    t.className = 'tab';
    t.dataset.id = s.id;
    t.draggable = true;         // 支持拖动排序
    const dot = document.createElement('span');
    dot.className = 'tab-dot off';
    const nm = document.createElement('span');
    nm.className = 'tab-name';
    nm.textContent = s.name;
    const x = document.createElement('span');
    x.className = 'tab-x';
    x.textContent = '✕';
    x.title = '关闭';
    x.onclick = (e) => { e.stopPropagation(); tryCloseSession(s.id); };
    t.append(dot, nm, x);
    t.onclick = () => activateSession(s.id);
    t.oncontextmenu = (e) => { e.preventDefault(); openCtxMenu(e, s.id); };

    // ---------- 拖拽排序 ----------
    t.addEventListener('dragstart', (e) => {
      dragTabId = s.id;
      t.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setData('text/plain', String(s.id)); } catch (err) {}
    });
    t.addEventListener('dragend', () => {
      dragTabId = null;
      t.classList.remove('dragging');
    });
    t.addEventListener('dragover', (e) => {
      if (dragTabId === null || dragTabId === s.id) return;
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      const dragged = document.querySelector('.tab.dragging');
      if (!dragged) return;
      // 鼠标过半则插到其后，否则插到其前（拖动过程中实时预览）
      const rect = t.getBoundingClientRect();
      if ((e.clientX - rect.left) > rect.width / 2) t.after(dragged);
      else t.before(dragged);
    });

    $('tabs').appendChild(t);
    s.tab = t;
  }

  function closeWs(s) {
    if (!s.ws) return;
    const w = s.ws;
    s.ws = null;
    w.onclose = w.onerror = w.onmessage = w.onopen = null;
    try { w.close(); } catch (e) {}
  }

  function connectSession(s) {
    s.status = 'connecting';
    s.token = null;
    s.pending = '';
    setTabStatus(s);
    closeWs(s);

    const proto = location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(proto + '://' + location.host + '/ws');
    s.ws = ws;

    ws.onopen = () => ws.send(JSON.stringify(Object.assign({ type: 'connect' }, s.cfg)));

    ws.onmessage = (ev) => {
      let msg;
      try { msg = JSON.parse(ev.data); } catch (e) { return; }
      if (msg.type === 'connected') {
        s.status = 'on';
        s.token = msg.token;
        s.label = msg.label;
        s.name = msg.name || msg.label;
        s.tab.querySelector('.tab-name').textContent = s.name;
        s.tab.title = s.label;
        setTabStatus(s);               // 绿点
        ensureTerm(s);
        if (s.pending) { s.term.write(s.pending); s.pending = ''; }
      } else if (msg.type === 'data') {
        if (s.term) s.term.write(msg.data); else s.pending += msg.data;
      } else if (msg.type === 'error') {
        s.status = 'err';
        if (s.term) {          // 重连失败：终端里显示，标签保留可再次重连
          s.term.write('\r\n\x1b[31m[连接失败] ' + (msg.message || '') + '\x1b[0m\r\n');
          setTabStatus(s);
        } else {               // 首次连接失败：直接移除标签
          toast('连接失败：' + (msg.message || '未知错误'), true);
          closeSession(s.id);
        }
      } else if (msg.type === 'closed') {
        s.status = 'off';
        if (s.term) s.term.write('\r\n\x1b[33m[连接已断开]\x1b[0m\r\n');
        setTabStatus(s);
      }
    };

    ws.onerror = () => { toast('无法连接 WebSSH 服务，请确认程序仍在运行。', true); };

    ws.onclose = (ev) => {
      if (ev && ev.code === 4401) {          // 登录过期
        s.status = 'off';
        setTabStatus(s);
        toast('登录已过期，请重新登录', true);
        showLogin();
        return;
      }
      if (s.ws !== ws) return;   // 主动关闭（重连 / 关标签）不处理
      if (s.status === 'on') {
        s.status = 'off';
        if (s.term) s.term.write('\r\n\x1b[33m[连接已断开]\x1b[0m\r\n');
        setTabStatus(s);
      }
    };
  }

  function newSession(cfg) {
    const id = ++seq;
    const s = { id, cfg, ws: null, term: null, fit: null, box: null, tab: null,
                token: null, label: '', name: '连接中…', status: 'connecting', pending: '',
                panelOpen: false, panelPath: null };   // 文件面板状态每会话独立
    sessions.set(id, s);
    addTabEl(s);
    activateSession(id);
    connectSession(s);
    return s;
  }

  function activateSession(id) {
    const s = sessions.get(id);
    if (!s) return;
    activeId = id;
    sessions.forEach((x) => {
      x.tab.classList.toggle('active', x.id === id);
      if (x.box) x.box.classList.toggle('active', x.id === id);
    });
    $('empty-state').classList.add('hidden');
    $('session-view').classList.remove('hidden');
    syncHostActive();
    updateSbExpand();
    // 恢复该会话自己的文件面板状态（传输任务独立于面板，不受切换影响）
    if (s.panelOpen) {
      showPanel();
      if (s.panelPath) { curPath = s.panelPath; $('fp-path').value = curPath; refreshFiles(); }
      else loadFiles('.');
    } else {
      hidePanel();
    }
    if (s.term) { s.fit.fit(); setTimeout(() => s.term.focus(), 0); }
  }

  function sessionActiveTasks(id) {
    const arr = [];
    TASKS.forEach(t => {
      if (t.sessId === id && (t.status === 'running' || t.status === 'cancelling')) arr.push(t);
    });
    return arr;
  }
  function purgeSessionTasks(id) {
    TASKS.forEach((t, tid) => { if (t.sessId === id) TASKS.delete(tid); });
    updateTaskBadge();
    renderTasks();
  }

  async function tryCloseSession(id) {
    const act = sessionActiveTasks(id);
    if (act.length &&
        !(await dlgConfirm('该标签有 ' + act.length + ' 个传输任务正在进行，\n关闭将取消这些任务。', '关闭标签')))
      return;
    closeSession(id);
  }

  function closeSession(id) {
    const s = sessions.get(id);
    if (!s) return;
    sessionActiveTasks(id).forEach(t => { try { if (t.cancel) t.cancel(); } catch (e) {} });
    purgeSessionTasks(id);
    closeWs(s);
    if (s.term) { try { s.term.dispose(); } catch (e) {} }
    if (s.box) s.box.remove();
    if (s.tab) s.tab.remove();
    sessions.delete(id);
    if (activeId === id) {
      activeId = null;
      // 按标签栏视觉顺序取相邻标签（优先右侧，其次左侧）
      const order = tabOrder().filter(x => sessions.has(x));
      const idx = order.indexOf(id);
      const next = order[idx + 1] !== undefined ? order[idx + 1]
                 : order[idx - 1] !== undefined ? order[idx - 1] : undefined;
      if (next !== undefined) activateSession(next);
      else showEmpty();
    }
    updateSbExpand();
  }

  function reconnectSession(s) {
    if (s.term) s.term.reset();
    connectSession(s);
    activateSession(s.id);
  }

  // ---------- 标签右键菜单：复制窗口 / 重新连接 / 关闭当前 / 关闭所有 ----------
  let ctxTargetId = null;
  function openCtxMenu(e, id) {
    ctxTargetId = id;
    const m = $('ctx-menu');
    m.classList.remove('hidden');
    let x = e.clientX, y = e.clientY;
    if (x + m.offsetWidth > innerWidth - 8) x = innerWidth - m.offsetWidth - 8;
    if (y + m.offsetHeight > innerHeight - 8) y = innerHeight - m.offsetHeight - 8;
    m.style.left = x + 'px';
    m.style.top = y + 'px';
  }
  function hideCtxMenu() {
    $('ctx-menu').classList.add('hidden');
    ctxTargetId = null;
  }
  document.addEventListener('mousedown', (e) => {
    if (!e.target.closest('#ctx-menu')) hideCtxMenu();
  });
  window.addEventListener('blur', hideCtxMenu);
  $('ctx-menu').addEventListener('click', async (e) => {
    const it = e.target.closest('.ctx-item');
    if (!it) return;
    const act = it.dataset.act;
    const s = sessions.get(ctxTargetId);
    hideCtxMenu();
    if (act === 'closeAll') {
      let n = 0;
      sessions.forEach(sx => { n += sessionActiveTasks(sx.id).length; });
      if (n && !(await dlgConfirm('共有 ' + n + ' 个传输任务正在进行，\n关闭所有标签将取消这些任务。', '关闭所有标签')))
        return;
      [...sessions.keys()].forEach(id => closeSession(id));
      return;
    }
    if (!s) return;
    if (act === 'dup') newSession(s.cfg);              // 复制窗口：同配置新开标签
    else if (act === 'reconn') reconnectSession(s);    // 重新连接
    else if (act === 'close') tryCloseSession(s.id);   // 关闭当前
  });

  new ResizeObserver(() => fitActive()).observe($('term-stack'));

  // ==================== 文件面板（绑定当前标签会话） ====================
  const fpToken = () => { const s = activeS(); return s && s.token; };

  // 面板宽度（与侧边栏一致，可拖拽并持久化）
  const FP_KEY = 'webssh_filepanel';
  const FP_MIN = 220, FP_MAX = 560;
  let fpWidth = 320;
  try { fpWidth = Number(JSON.parse(localStorage.getItem(FP_KEY) || '{}').width) || 320; } catch (e) {}
  fpWidth = Math.min(FP_MAX, Math.max(FP_MIN, fpWidth));
  $('file-panel').style.width = fpWidth + 'px';

  function showPanel() {
    $('file-panel').classList.remove('hidden');
    $('btn-files').textContent = '»';
    $('btn-files').title = '收起文件管理';
  }
  function hidePanel() {
    $('file-panel').classList.add('hidden');
    $('btn-files').textContent = '«';
    $('btn-files').title = '展开文件管理';
    curPath = null;
    fitActive();
  }
  function openFilePanel() {
    const s = activeS();
    if (!s || !s.token) { toast('当前标签未连接', true); return; }
    s.panelOpen = true;
    showPanel();
    loadFiles(s.panelPath || '.');
  }
  function closeFilePanel() {          // 仅隐藏面板，传输任务不受影响
    const s = activeS();
    if (s) s.panelOpen = false;
    hidePanel();
  }
  $('btn-files').onclick = () => {
    if ($('file-panel').classList.contains('hidden')) openFilePanel();
    else closeFilePanel();
  };

  // 拖拽左缘调宽（向左拖变宽）
  $('fp-resize').addEventListener('pointerdown', (e) => {
    e.preventDefault();
    const rz = $('fp-resize');
    rz.setPointerCapture(e.pointerId);
    rz.classList.add('drag');
    document.body.classList.add('resizing');
    const startX = e.clientX, startW = fpWidth;
    const move = (ev) => {
      fpWidth = Math.min(FP_MAX, Math.max(FP_MIN, startW - (ev.clientX - startX)));
      $('file-panel').style.width = fpWidth + 'px';
    };
    const up = () => {
      rz.releasePointerCapture(e.pointerId);
      rz.removeEventListener('pointermove', move);
      rz.removeEventListener('pointerup', up);
      rz.removeEventListener('pointercancel', up);
      rz.classList.remove('drag');
      document.body.classList.remove('resizing');
      localStorage.setItem(FP_KEY, JSON.stringify({ width: fpWidth }));
      fitActive();
    };
    rz.addEventListener('pointermove', move);
    rz.addEventListener('pointerup', up);
    rz.addEventListener('pointercancel', up);
  });

  function fpStatus(msg, isErr) {
    const el = $('fp-status');
    el.textContent = msg || '';
    el.className = isErr ? 'err' : '';
  }

  // 地址栏：输入实时加载（路径完整即刷新列表）；回车 / 点击框外作为兜底触发
  $('fp-path').addEventListener('keydown', (ev) => {
    if (ev.key === 'Enter') {
      const v = $('fp-path').value.trim();
      if (v) loadFiles(v);
    } else if (ev.key === 'Escape') {
      $('fp-path').value = curPath || '';
      $('fp-path').blur();
    }
  });
  $('fp-path').addEventListener('blur', () => {          // 兜底：点击框外触发显示
    const v = $('fp-path').value.trim();
    if (!v) return;
    if (v === curPath) { $('fp-path').value = curPath; return; }   // 已实时加载过：仅规范化显示
    loadFiles(v);
  });
  ['focus', 'click'].forEach(ev =>
    $('fp-path').addEventListener(ev, () => {
      $('fp-path').readOnly = false;
      $('fp-path').classList.remove('invalid');
    }));

  let fpLiveTimer = null;
  let fpLastLive = null;                     // 上次实时尝试过的输入值（判重用，不能拿 curPath 比：
                                             // 从无效路径删回有效路径时 v===curPath 会被误跳过）
  $('fp-path').addEventListener('input', () => {         // 实时：路径完整时直接刷新列表
    clearTimeout(fpLiveTimer);
    fpLiveTimer = setTimeout(async () => {
      const v = $('fp-path').value.trim();
      if (!v || v === fpLastLive) return;
      fpLastLive = v;
      const s = activeS();
      const tk = s && s.token;
      if (!tk) return;
      try {
        const data = await api('/api/files?token=' + encodeURIComponent(tk) +
                               '&path=' + encodeURIComponent(v));
        applyFiles(s, data, true);           // 输入编辑中：只刷新列表，不动输入框内容（不去尾部 /）
      } catch (e) { showInvalidList(e.status === 403 ? '权限不足' : '无效路径'); }  // 实时：立即反馈，输入框保持原样
    }, 350);
  });

  function showInvalidList(text) {       // 仅列表区显示提示（编辑中调用，不动输入框）
    const box = $('fp-list');
    box.textContent = '';
    const d = document.createElement('div');
    d.className = 'fp-empty';
    d.textContent = text || '无效路径';
    box.appendChild(d);
    fpStatus('');
  }

  function showInvalidPath(text) {           // 回车/失焦后仍无效：路径标红 + 列表显示"无效路径"，仅此而已
    $('fp-path').classList.add('invalid');
    showInvalidList();
  }

  function applyFiles(s, data, keepInput) {
    curPath = data.path;
    s.panelPath = curPath;                   // 会话记住自己的目录
    fpLastLive = data.path;
    const inp = $('fp-path');
    inp.classList.remove('invalid');         // 加载成功即恢复正常颜色
    if (!keepInput) {                        // 回车/失焦时才规范化输入框（如去掉尾部 /）
      inp.value = curPath;
      inp.title = curPath;
      inp.readOnly = false;
    }
    renderFiles(data.entries);
    // 状态行：条数 + 当前路径所在文件系统的空间状态
    let text = data.entries.length + ' 项';
    if (data.vfs && data.vfs.total > 0)
      text += ' · 已用 ' + humanSize(data.vfs.used) + ' / ' +
              humanSize(data.vfs.total) + '（' + data.vfs.percent + '%）';
    fpStatus(text);
  }

  async function loadFiles(path, keepInput) {   // 回车/失焦兜底：路径无效时显示"无效路径"
    const s = activeS();
    const tk = s && s.token;
    if (!tk) return;
    if (!keepInput) fpStatus('加载中…');
    try {
      const data = await api('/api/files?token=' + encodeURIComponent(tk) +
                             '&path=' + encodeURIComponent(path));
      applyFiles(s, data, keepInput);        // keepInput=后台刷新：不动输入框
    } catch (e) {
      if (keepInput) return;                 // 后台刷新失败静默
      if (/会话/.test(e.message || '')) { toast(e.message, true); return; }
      showInvalidPath();                     // 路径不存在：标红 + 列表显示"无效路径"，不改输入内容
    }
  }

  function refreshFiles() {                  // 后台静默刷新当前目录（任务完成/切回标签）
    if (curPath) loadFiles(curPath, true);
  }

  function renderFiles(entries) {
    const box = $('fp-list');
    box.textContent = '';
    if (!entries.length) {
      const d = document.createElement('div');
      d.className = 'fp-empty';
      d.textContent = '空目录';
      box.appendChild(d);
      return;
    }
    entries.forEach(en => {
      const row = document.createElement('div');
      row.className = 'fp-row';

      const nm = document.createElement('span');
      nm.className = 'fp-name' + (en.is_dir ? ' dir' : '');
      nm.textContent = (en.is_dir ? '📁 ' : '📄 ') + en.name;

      if (en.is_dir) {
        row.appendChild(nm);
        row.onclick = () => loadFiles(curPath + '/' + en.name);
      } else {
        const meta = document.createElement('span');
        meta.className = 'fp-meta';
        meta.textContent = humanSize(en.size);
        const acts = document.createElement('span');
        acts.className = 'fp-acts';
        const a = document.createElement('button');
        a.type = 'button';
        a.className = 'icon-btn';
        a.textContent = '⬇'; a.title = '下载';
        a.onclick = (e) => { e.stopPropagation(); startDownload(activeS(), curPath, en); };
        const b = document.createElement('button');
        b.type = 'button';
        b.className = 'icon-btn danger';
        b.textContent = '🗑'; b.title = '删除';
        b.onclick = (e) => { e.stopPropagation(); deleteRemote(en); };
        acts.append(a, b);
        row.append(nm, meta, acts);
      }
      box.appendChild(row);
    });
  }

  $('fp-up').onclick = () => {
    if (!curPath || curPath === '/') return;
    const parent = curPath.replace(/\/+$/, '').replace(/\/[^/]*$/, '');
    loadFiles(parent || '/');
  };
  $('fp-refresh').onclick = () => refreshFiles();

  async function deleteRemote(en) {
    if (!(await dlgConfirm('确定删除' + (en.is_dir ? '目录' : '文件') + '「' + en.name + '」？', '删除'))) return;
    try {
      await api('/api/files?token=' + encodeURIComponent((activeS() || {}).token || '') +
                '&path=' + encodeURIComponent(curPath + '/' + en.name), { method: 'DELETE' });
      toast('已删除 ' + en.name);
      loadFiles(curPath);
    } catch (e) { toast(e.message, true); }
  }

  // ==================== 传输任务管理器（多任务并行展示 + 取消） ====================
  const TASKS = new Map();          // id -> task
  let taskSeq = 0;
  const UP_PART = 16 * 1024 * 1024; // 上传分片 16MB
  const UP_PAR = 5;                 // 并发分片数

  function activeTaskCount() {
    let n = 0;
    TASKS.forEach(t => { if (t.status === 'running' || t.status === 'cancelling') n++; });
    return n;
  }
  function updateTaskBadge() {
    const n = activeTaskCount();
    $('task-badge').textContent = n ? '（' + n + '）' : '';
    $('tasks-count').textContent = TASKS.size ? ' · 共 ' + TASKS.size + ' 条' : '';
  }

  function mkTask(kind, sess, name, size) {
    const t = { id: ++taskSeq, kind, sessId: sess.id, sessName: sess.name || '', name,
                size: size || 0, sent: 0, status: 'running', speed: 0, err: '',
                lastTick: performance.now(), lastSent: 0, cancel: null };
    TASKS.set(t.id, t);
    updateTaskBadge();
    renderTasks();
    return t;
  }

  function taskTick(t) {
    const now = performance.now();
    if (now - t.lastTick >= 500) {
      t.speed = (t.sent - t.lastSent) / ((now - t.lastTick) / 1000);
      t.lastTick = now;
      t.lastSent = t.sent;
      renderTasks();
    }
  }

  function finishTask(t, sess, dir) {
    t.speed = 0;
    updateTaskBadge();
    renderTasks();
    // 若该会话面板正打开且还在那个目录，刷新列表
    const cur = activeS();
    if (sess && cur && cur.id === sess.id && sess.panelOpen && dir && dir === curPath)
      refreshFiles();
  }

  function renderTasks() {
    const box = $('task-list');
    if ($('tasks-overlay').classList.contains('hidden')) return;   // 弹窗未开时跳过渲染
    box.textContent = '';
    if (!TASKS.size) {
      const d = document.createElement('div');
      d.className = 'task-empty';
      d.textContent = '暂无传输任务';
      box.appendChild(d);
      return;
    }
    [...TASKS.values()].reverse().forEach(t => {
      const row = document.createElement('div');
      row.className = 'task-row';

      const head = document.createElement('div');
      head.className = 'task-head';
      const kind = document.createElement('span');
      kind.className = 'task-kind';
      kind.textContent = t.kind === 'up' ? '⬆' : '⬇';
      const nm = document.createElement('span');
      nm.className = 'task-name';
      nm.textContent = t.name;
      nm.title = t.name;
      const sn = document.createElement('span');
      sn.className = 'task-sess';
      sn.textContent = t.sessName;
      head.append(kind, nm, sn);

      const bar = document.createElement('div');
      bar.className = 'task-bar';
      const fill = document.createElement('div');
      fill.className = 'task-fill' + (t.status === 'done' ? ' done' :
                         (t.status === 'failed' || t.status === 'cancelled') ? ' err' : '');
      const pct = t.size > 0 ? Math.min(100, t.sent / t.size * 100)
                 : (t.status === 'done' ? 100 : 0);
      fill.style.width = pct.toFixed(1) + '%';
      bar.appendChild(fill);

      const meta = document.createElement('div');
      meta.className = 'task-meta';
      const left = document.createElement('span');
      left.textContent = humanSize(t.sent) + (t.size > 0 ? ' / ' + humanSize(t.size) : '') +
        (t.speed > 0 ? ' · ' + humanSize(t.speed) + '/s' : '');
      meta.appendChild(left);
      if (t.status === 'running') {
        const btn = document.createElement('button');
        btn.className = 'task-cancel';
        btn.textContent = '取消';
        btn.onclick = () => { if (t.cancel) t.cancel(); };
        meta.appendChild(btn);
      } else {
        const st = document.createElement('span');
        const map = { done: '✓ 完成', failed: '✗ ' + (t.err || '失败'),
                      cancelled: '已取消', cancelling: '取消中…', browser: '已转浏览器下载' };
        st.textContent = map[t.status] || t.status;
        if (t.status === 'done') st.style.color = '#4ec9b0';
        if (t.status === 'failed') st.style.color = '#f48771';
        meta.appendChild(st);
      }

      row.append(head, bar, meta);
      box.appendChild(row);
    });
  }

  $('btn-tasks').onclick = () => {
    $('tasks-overlay').classList.remove('hidden');
    renderTasks();
  };
  $('btn-clear-done').onclick = () => {
    TASKS.forEach((t, id) => {
      if (t.status !== 'running' && t.status !== 'cancelling') TASKS.delete(id);
    });
    updateTaskBadge();
    renderTasks();
  };

  // ---------- 上传：分片并行（每片独立 PUT + offset 随机写） ----------
  function startUpload(sess, dir, file) {
    const t = mkTask('up', sess, file.name, file.size);
    const tk = sess.token;
    if (!tk) { t.status = 'failed'; t.err = '会话未连接'; finishTask(t, sess, dir); return; }

    const nParts = Math.max(1, Math.ceil(file.size / UP_PART));
    const loaded = new Array(nParts).fill(0);
    const xhrs = new Set();
    let nextPart = 0, failure = null;

    t.cancel = () => {
      t.status = 'cancelling';
      xhrs.forEach(x => { try { x.abort(); } catch (e) {} });
      renderTasks();
    };

    function sendPart(i) {
      return new Promise((resolve) => {
        const x = new XMLHttpRequest();
        xhrs.add(x);
        const off = i * UP_PART;
        const blob = file.slice(off, Math.min(file.size, off + UP_PART));
        x.open('PUT', '/api/upload?token=' + encodeURIComponent(tk) +
               '&path=' + encodeURIComponent(dir) +
               '&name=' + encodeURIComponent(file.name) +
               '&offset=' + off);
        x.upload.onprogress = (e) => {
          const d = e.loaded - loaded[i];
          loaded[i] = e.loaded;
          t.sent += d;
          taskTick(t);
        };
        const done = () => { xhrs.delete(x); resolve(); };
        x.onload = () => {
          if (x.status === 200) { done(); return; }
          if (!failure) {
            let msg = 'HTTP ' + x.status;
            try { msg = JSON.parse(x.responseText).detail || msg; } catch (e) {}
            failure = msg;
            t.status = 'failed'; t.err = msg;
            xhrs.forEach(o => { try { o.abort(); } catch (e) {} });
          }
          done();
        };
        x.onerror = () => {
          if (t.status !== 'cancelling' && !failure) { t.status = 'failed'; t.err = '网络错误'; }
          xhrs.forEach(o => { try { o.abort(); } catch (e) {} });
          done();
        };
        x.onabort = done;
        x.send(blob);
      });
    }

    (async () => {
      const workers = [];
      for (let k = 0; k < Math.min(UP_PAR, nParts); k++) {
        workers.push((async () => {
          while (t.status === 'running' && !failure) {
            const i = nextPart++;
            if (i >= nParts) break;
            await sendPart(i);
          }
        })());
      }
      await Promise.all(workers);
      if (t.status === 'running' && !failure) { t.status = 'done'; t.sent = file.size; }
      else if (t.status === 'cancelling') t.status = 'cancelled';
      finishTask(t, sess, dir);
    })();
  }

  // 上传入口：多选文件逐个建任务（同一时刻一个文件内并行、文件间串行）
  $('fp-input').addEventListener('change', async (ev) => {
    const files = Array.from(ev.target.files || []);
    ev.target.value = '';
    const s = activeS();
    const dir = curPath;
    if (!s || !s.token || !dir) { toast('当前标签未连接', true); return; }
    for (const f of files) {
      startUpload(s, dir, f);
      await new Promise(r => {                 // 等这个文件的所有分片发完再开下一个
        const wait = () => {
          const t = [...TASKS.values()].find(x => x.name === f.name && x.sessId === s.id && x.status === 'running');
          if (t) setTimeout(wait, 300); else r();
        };
        wait();
      });
    }
  });

  // ---------- 下载：先预检存在性，File System Access API 流式落盘（进度+取消），降级原生下载 ----------
  async function startDownload(sess, dir, en) {
    const tk = sess && sess.token;
    if (!tk) { toast('当前标签未连接', true); return; }
    const remote = dir + '/' + en.name;
    // 服务器上文件可能已被删除：预检，不存在则直接提示，不创建任务
    try {
      const st = await api('/api/stat?token=' + encodeURIComponent(tk) +
                           '&path=' + encodeURIComponent(remote));
      if (!st.exists) {
        toast('文件不存在（可能已被删除）', true);
        refreshFiles();
        return;
      }
      en.size = st.size || en.size;
    } catch (e) { toast(e.message, true); return; }

    const t = mkTask('down', sess, en.name, en.size);

    if (!window.showSaveFilePicker) {          // Firefox 等：交给浏览器下载器
      const a = document.createElement('a');
      a.href = '/api/download?token=' + encodeURIComponent(tk) +
               '&path=' + encodeURIComponent(remote);
      a.download = en.name;
      a.click();
      t.status = 'browser';
      finishTask(t, sess, dir);
      return;
    }

    let handle;
    try {
      handle = await window.showSaveFilePicker({ suggestedName: en.name });
    } catch (e) {
      t.status = (e && e.name === 'AbortError') ? 'cancelled' : 'failed';
      t.err = '未选择保存位置';
      finishTask(t, sess, dir);
      return;
    }

    try {
      const w = await handle.createWritable();
      const res = await fetch('/api/download?token=' + encodeURIComponent(tk) +
                              '&path=' + encodeURIComponent(remote));
      if (!res.ok) throw new Error('HTTP ' + res.status);
      const total = +(res.headers.get('Content-Length') || en.size || 0);
      if (total) t.size = total;
      const reader = res.body.getReader();

      t.cancel = async () => {
        t.status = 'cancelling';
        try { await reader.cancel(); } catch (e) {}
      };

      while (true) {
        const { done, value } = await reader.read();
        if (done) { t.status = 'done'; break; }
        if (t.status === 'cancelling') {
          try { await reader.cancel(); } catch (e) {}
          await w.close();
          t.status = 'cancelled';
          return finishTask(t, sess, dir);
        }
        await w.write(value);
        t.sent += value.byteLength;
        taskTick(t);
      }
      await w.close();
    } catch (e) {
      if (t.status !== 'cancelling') { t.status = 'failed'; t.err = e.message || '下载失败'; }
      else t.status = 'cancelled';
    }
    finishTask(t, sess, dir);
  }

  // ==================== 设置中心 ====================
  function openSettings(tab) {
    if (!ME) return;
    $('settings-overlay').classList.remove('hidden');
    switchSetTab(tab || 'hosts');
  }
  $('btn-settings').onclick = () => openSettings('hosts');

  function switchSetTab(tab) {
    document.querySelectorAll('.set-tab').forEach(t =>
      t.classList.toggle('active', t.dataset.tab === tab));
    $('set-hosts').classList.toggle('hidden', tab !== 'hosts');
    $('set-passwd').classList.toggle('hidden', tab !== 'passwd');
    $('set-users').classList.toggle('hidden', tab !== 'users');
    if (tab === 'hosts') renderSettingsHosts(true);
    if (tab === 'users') renderUsers(true);
    if (tab === 'passwd') {
      const adm = ME && ME.admin;
      $('pw-old-row').classList.toggle('hidden', adm);
      $('pw-admin-hint').classList.toggle('hidden', !adm);
    }
  }
  document.querySelectorAll('.set-tab').forEach(t =>
    t.onclick = () => switchSetTab(t.dataset.tab));

  function refreshSettingsHosts() {
    if (!$('settings-overlay').classList.contains('hidden')) renderSettingsHosts(true);
  }

  let settingsHosts = [], hostQ = '', hostPage = 1;
  const PAGE_SIZE = 50;
  $('sh-search').addEventListener('input', () => {
    hostQ = $('sh-search').value; hostPage = 1; renderSettingsHosts(false);
  });

  function renderPager(elId, page, pages, total, go) {
    const box = $(elId);
    box.textContent = '';
    if (!total) return;                         // 无数据时不显示分页条
    const cnt = document.createElement('span');
    cnt.textContent = '共 ' + total + ' 条';
    if (pages <= 1) { box.appendChild(cnt); return; }   // 单页无需翻页控件
    const prev = document.createElement('button');
    prev.type = 'button';
    prev.className = 'text-btn';
    prev.textContent = '‹ 上一页';
    prev.disabled = page <= 1;
    prev.onclick = () => go(page - 1);
    const jump = document.createElement('input');   // 页码可编辑跳转
    jump.className = 'page-jump';
    jump.value = page;
    const doJump = () => {
      const v = parseInt(jump.value, 10);
      if (v >= 1 && v <= pages && v !== page) go(v);
      else jump.value = page;
    };
    jump.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { doJump(); jump.blur(); }
    });
    jump.addEventListener('blur', doJump);
    const of = document.createElement('span');
    of.textContent = '/ ' + pages + ' 页';
    const next = document.createElement('button');
    next.type = 'button';
    next.className = 'text-btn';
    next.textContent = '下一页 ›';
    next.disabled = page >= pages;
    next.onclick = () => go(page + 1);
    box.append(cnt, prev, jump, of, next);
  }

  async function renderSettingsHosts(refresh) {
    const box = $('set-host-list');
    box.textContent = '';
    if (refresh) {
      try { settingsHosts = await api('/api/hosts'); } catch (e) { return; }
    }
    const kw = hostQ.trim().toLowerCase();
    const filtered = kw
      ? settingsHosts.filter(h => [h.name, h.host, h.username, h.remark]
          .some(v => (v || '').toLowerCase().includes(kw)))
      : settingsHosts;
    const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    if (hostPage > pages) hostPage = pages;
    if (!filtered.length) {
      const d = document.createElement('div');
      d.className = 'set-empty';
      d.textContent = settingsHosts.length ? '无匹配结果' : '暂无主机，点右上「＋ 新增主机」添加';
      box.appendChild(d);
      renderPager('sh-pager', 1, 1, 0, () => {});
      return;
    }
    filtered.slice((hostPage - 1) * PAGE_SIZE, hostPage * PAGE_SIZE).forEach(h => {
      const row = document.createElement('div');
      row.className = 'set-row';
      const main = document.createElement('div');
      main.className = 'sr-main';
      const n1 = document.createElement('div');
      n1.textContent = h.name;
      const n2 = document.createElement('div');
      n2.className = 'sr-sub';
      n2.textContent = h.username + '@' + h.host + ':' + h.port + (h.remark ? ' · ' + h.remark : '');
      main.append(n1, n2);
      const bEdit = document.createElement('button');
      bEdit.type = 'button';
      bEdit.className = 'text-btn';
      bEdit.textContent = '编辑';
      bEdit.onclick = () => openHostModal(h);
      const bDel = document.createElement('button');
      bDel.type = 'button';
      bDel.className = 'text-btn danger';
      bDel.textContent = '删除';
      bDel.onclick = () => deleteHost(h);
      row.append(main, bEdit, bDel);
      box.appendChild(row);
    });
    renderPager('sh-pager', hostPage, pages, filtered.length, (pg) => { hostPage = pg; renderSettingsHosts(false); });
  }
  $('btn-add-host2').onclick = () => openHostModal(null);

  // ---------- 修改密码 ----------
  $('pw-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const nw = $('pw-new').value;
    if (nw !== $('pw-new2').value) { toast('两次输入的新密码不一致', true); return; }
    try {
      await api('/api/me/password', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ old_password: $('pw-old').value, new_password: nw }),
      });
      $('pw-old').value = ''; $('pw-new').value = ''; $('pw-new2').value = '';
      toast('密码已修改，请重新登录');
      setTimeout(async () => {             // 旧凭证已全部作废，统一走退出流程
        try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
        $('settings-overlay').classList.add('hidden');
        [...sessions.keys()].forEach(id => closeSession(id));
        $('host-list').textContent = '';
        showLogin();
      }, 900);
    } catch (e) { toast(e.message, true); }
  });

  // ---------- 用户管理（仅 admin 可见） ----------
  let settingsUsers = [], userQ = '', userPage = 1;
  $('su-search').addEventListener('input', () => {
    userQ = $('su-search').value; userPage = 1; renderUsers(false);
  });

  async function renderUsers(refresh) {
    const box = $('user-list');
    box.textContent = '';
    if (refresh) {
      try { settingsUsers = await api('/api/users'); } catch (e) { return; }
    }
    const kw = userQ.trim().toLowerCase();
    const filtered = kw
      ? settingsUsers.filter(u => u.user.toLowerCase().includes(kw))
      : settingsUsers;
    const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
    if (userPage > pages) userPage = pages;
    if (!filtered.length) {
      const d = document.createElement('div');
      d.className = 'set-empty';
      d.textContent = settingsUsers.length ? '无匹配结果' : '暂无用户';
      box.appendChild(d);
      renderPager('su-pager', 1, 1, 0, () => {});
      return;
    }
    filtered.slice((userPage - 1) * PAGE_SIZE, userPage * PAGE_SIZE).forEach(u => {
      const row = document.createElement('div');
      row.className = 'set-row';
      const main = document.createElement('div');
      main.className = 'sr-main';
      main.textContent = u.user;
      row.appendChild(main);
      if (u.admin) {
        const tag = document.createElement('span');
        tag.className = 'tag';
        tag.textContent = '管理员';
        row.appendChild(tag);
      }
      if (ME && u.user !== ME.user) {
        const bPw = document.createElement('button');
        bPw.type = 'button';
        bPw.className = 'text-btn';
        bPw.textContent = '修改密码';
        bPw.title = '修改该用户的密码';
        bPw.onclick = async () => {
          const np = await dlgPrompt('重置「' + u.user + '」的密码', '新密码（至少 8 位）', 'password');
          if (!np) return;
          try {
            await api('/api/users/' + encodeURIComponent(u.user) + '/password', {
              method: 'PUT', headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ new_password: np }),
            });
            toast('已重置 ' + u.user + ' 的密码');
          } catch (e) { toast(e.message, true); }
        };
        if (u.user !== 'admin') {              // admin 用户不允许删除
          const bDel = document.createElement('button');
          bDel.type = 'button';
          bDel.className = 'text-btn danger';
          bDel.textContent = '删除';
          bDel.onclick = async () => {
            if (!(await dlgConfirm('确定删除用户「' + u.user + '」？' + String.fromCharCode(10) + '其名下的主机资产将一并删除。', '删除用户'))) return;
            try {
              await api('/api/users/' + encodeURIComponent(u.user), { method: 'DELETE' });
              toast('已删除 ' + u.user);
              renderUsers(true);
            } catch (e) { toast(e.message, true); }
          };
          row.append(bPw, bDel);
        } else {
          row.appendChild(bPw);
        }
      }
      box.appendChild(row);
    });
    renderPager('su-pager', userPage, pages, filtered.length, (pg) => { userPage = pg; renderUsers(false); });
  }

  $('btn-add-user').onclick = () => {
    $('user-overlay').classList.remove('hidden');
    $('nu-user').value = ''; $('nu-pass').value = ''; $('nu-admin').checked = false;
    setTimeout(() => $('nu-user').focus(), 0);
  };
  $('user-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    try {
      const name = $('nu-user').value.trim();
      await api('/api/users', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ user: name, password: $('nu-pass').value,
                               admin: $('nu-admin').checked }),
      });
      toast('已添加用户 ' + name);
      $('user-overlay').classList.add('hidden');
      renderUsers(true);
    } catch (e) { toast(e.message, true); }
  });

  // ---------- 通用输入弹窗 ----------
  let ptResolve = null;
  function dlgPrompt(title, placeholder, type) {
    return new Promise((resolve) => {
      ptResolve = resolve;
      $('pt-title').textContent = title || '输入';
      const inp = $('pt-input');
      inp.type = type || 'text';
      inp.value = '';
      inp.placeholder = placeholder || '';
      $('prompt-overlay').classList.remove('hidden');
      setTimeout(() => inp.focus(), 0);
    });
  }
  function ptDone(v) {
    $('prompt-overlay').classList.add('hidden');
    if (ptResolve) { ptResolve(v); ptResolve = null; }
  }
  $('pt-yes').onclick = () => ptDone($('pt-input').value.trim() || null);
  $('pt-no').onclick = () => ptDone(null);
  $('pt-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') ptDone($('pt-input').value.trim() || null);
    if (e.key === 'Escape') ptDone(null);
  });
  $('prompt-overlay').addEventListener('mousedown', (e) => {
    if (e.target === $('prompt-overlay')) ptDone(null);
  });

  // ---------- 退出登录 ----------
  $('btn-logout').onclick = async () => {
    if (!(await dlgConfirm('确定退出登录？已打开的终端将被关闭。', '退出登录'))) return;
    try { await api('/api/logout', { method: 'POST' }); } catch (e) {}
    [...sessions.keys()].forEach(id => closeSession(id));   // 强制关标签（含任务）
    $('host-list').textContent = '';
    showLogin();
  };

  // ==================== 启动 ====================
  applySidebar();
  (async () => {                      // 刷新后静默恢复登录态（签名 Cookie，不掉线）
    try {
      ME = await api('/api/me');
      applyMe();
    } catch (e) { /* 401 → 登录框已由 api() 弹出 */ }
    loadHosts();
  })();
})();
</script>
</body>
</html>"""


@app.get("/")
async def index():
    return HTMLResponse(HTML)


def _ensure_selfsigned_cert():
    """首次生成自签证书（含本机局域网 IP 的 SAN，尽力而为）；返回 (cert, key)"""
    cert_p = os.path.join(DATA_DIR, "webssh_cert.pem")
    key_p = os.path.join(DATA_DIR, "webssh_key.pem")
    if os.path.exists(cert_p) and os.path.exists(key_p):
        return cert_p, key_p
    import datetime
    import ipaddress
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

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
    return cert_p, key_p


if __name__ == "__main__":
    HOST = "0.0.0.0"     # 监听所有网卡（局域网可访问）；仅本机使用改成 "127.0.0.1"
    PORT = 8080
    USE_TLS = "--no-tls" not in sys.argv   # 默认 HTTPS，加 --no-tls 回退 HTTP
    ssl_kw = {}
    if USE_TLS:
        cert_p, key_p = _ensure_selfsigned_cert()
        ssl_kw = {"ssl_certfile": cert_p, "ssl_keyfile": key_p}
        print(f"HTTPS 证书： {cert_p}（自签，浏览器首次访问需手动信任）")
    scheme = "https" if USE_TLS else "http"
    threading.Timer(1.2, lambda: webbrowser.open(f"{scheme}://127.0.0.1:{PORT}/")).start()
    print(f"WebSSH {VERSION} 启动中： {scheme}://127.0.0.1:{PORT}/（已监听 0.0.0.0，局域网可通过 {scheme}://<本机IP>:{PORT} 访问）")
    print(f"默认管理员： {DEFAULT_ADMIN_USER} / {DEFAULT_ADMIN_PASS}（加盐哈希存于 data/auth.json，用户管理在设置里）")
    print(f"数据目录： {DATA_DIR}   启动参数： --no-tls 可回退 HTTP")
    print("若浏览器未自动打开，请手动访问上面的地址。按 Ctrl+C 退出。")
    uvicorn.run(app, host=HOST, port=PORT, log_level="warning", server_header=False, **ssl_kw)
