"""配置、凭据加密、认证/用户体系、主机资产存储"""
import asyncio
import hashlib
import hmac
import json
import os
import re
import secrets
import threading
from datetime import datetime
import time

from cryptography.fernet import Fernet, InvalidToken
from fastapi import APIRouter, Depends, HTTPException, Request, Response

router = APIRouter()

VERSION = "v2.0.0"

def install_security_headers(app):
    """安全响应头：防嗅探/防点击劫持/禁缓存；HTTPS 时附加 HSTS"""
    @app.middleware("http")
    async def _headers(request: Request, call_next):
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
    return app

_MOD_DIR = os.path.dirname(os.path.abspath(__file__))
# 仓库布局（src/ 下）→ 项目根；发布包布局（模块摊平在包内）→ 包自身目录，
# 保证 data/ 始终随包走（--with-data 携带的资产才能被读到）
BASE_DIR = os.path.dirname(_MOD_DIR) if os.path.basename(_MOD_DIR) == "src" else _MOD_DIR
# WEBSSH_DATA_DIR 可重定向数据目录（容器/多实例部署有用；e2e 靠它隔离测试数据，
# 绝不触碰真实 data/——曾因测试后清理误删过用户真实主机数据）
DATA_DIR = os.environ.get("WEBSSH_DATA_DIR") or os.path.join(BASE_DIR, "data")
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


async def _hash_pw_async(password: str, salt: str) -> str:
    """PBKDF2 移入线程池——不阻塞事件循环（终端/SFTP 不卡顿）"""
    return await asyncio.get_running_loop().run_in_executor(
        None, _hash_pw, password, salt)


def _load_auth() -> dict:
    """格式：{"users": {名字: {salt, hash, admin}}}；兼容迁移旧版单用户文件。
    文件损坏时 fail-fast 拒绝启动（而非静默重置为默认弱口令）。"""
    data = None
    if os.path.exists(AUTH_FILE):
        try:
            with open(AUTH_FILE, encoding="utf-8") as f:
                data = json.load(f)
        except ValueError as e:
            raise RuntimeError(
                f"auth.json 已损坏（{e}）。为安全起见拒绝启动。"
                f"请手动检查/恢复 {AUTH_FILE}，确认无误后删除并重启（将重建默认 admin）。") from e
    if data is not None and "users" not in data and "salt" not in data:
        raise RuntimeError(f"auth.json 结构异常（缺少 users 字段）。请检查 {AUTH_FILE}。")
    if isinstance(data, dict) and "users" in data and not data["users"]:
        raise RuntimeError(f"auth.json 的 users 为空——系统无任何可登录账号。"
                           f"请检查 {AUTH_FILE}（删除后重启将重建默认 admin）。")
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
    """原子写：tmp + os.replace（防崩溃/断电写坏文件）"""
    tmp = AUTH_FILE + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(AUTH, f, ensure_ascii=False, indent=2)
    os.replace(tmp, AUTH_FILE)


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


_LOGIN_FAILS: dict = {}        # key（用户名或IP） -> [连续失败次数, 锁定截止时间戳]
_FAIL_LIMIT = 5
_LOCK_SECONDS = 300
_FAILS_MAX = 10000             # 字典上限，防内存被恶意刷爆


def _login_guard(user: str):
    """登录限速：连续错 5 次锁定 5 分钟"""
    rec = _LOGIN_FAILS.get(user)
    if rec:
        if rec[1] and rec[1] > time.time():
            left = int(rec[1] - time.time()) + 1
            raise HTTPException(429, f"失败次数过多，请 {left // 60} 分 {left % 60} 秒后再试")
        if rec[1] and rec[1] <= time.time():    # 锁过期，清零重新计
            _LOGIN_FAILS.pop(user, None)


def _login_fail(key: str):
    if len(_LOGIN_FAILS) > _FAILS_MAX:           # 防内存泄漏：清理已过期条目
        now = time.time()
        for k in list(_LOGIN_FAILS):
            if _LOGIN_FAILS[k][1] and _LOGIN_FAILS[k][1] < now:
                _LOGIN_FAILS.pop(k, None)
        if len(_LOGIN_FAILS) > _FAILS_MAX:       # 仍超限：淘汰最旧一半（不清整表，防误清锁定）
            for k in list(_LOGIN_FAILS.keys())[:len(_LOGIN_FAILS) // 2]:
                _LOGIN_FAILS.pop(k, None)
    rec = _LOGIN_FAILS.setdefault(key, [0, 0.0])
    rec[0] += 1
    if rec[0] >= _FAIL_LIMIT:
        rec[1] = time.time() + _LOCK_SECONDS
        rec[0] = 0


@router.post("/api/login")
async def login(request: Request, body: dict, response: Response):
    user = str(body.get("user") or "").strip()
    password = str(body.get("password") or "")
    client_ip = request.client.host if request.client else "unknown"
    _login_guard(user)                       # 按用户名限速
    _login_guard("ip:" + client_ip)          # 按来源 IP 限速（防换用户名绕过）
    rec = AUTH["users"].get(user)
    if not rec:
        await _hash_pw_async(password, _DUMMY_SALT)  # 恒时：防用户名枚举
        _login_fail(user)
        _login_fail("ip:" + client_ip)
        raise HTTPException(401, "账号或密码错误")
    if not hmac.compare_digest(rec["hash"], await _hash_pw_async(password, rec["salt"])):
        _login_fail(user)
        _login_fail("ip:" + client_ip)
        raise HTTPException(401, "账号或密码错误")
    _LOGIN_FAILS.pop(user, None)
    _LOGIN_FAILS.pop("ip:" + client_ip, None)
    response.set_cookie("webssh_session", _issue_login_token(user),
                        httponly=True, samesite="strict", secure=request.url.scheme == "https",
                        max_age=SESSION_HOURS * 3600)
    return {"ok": True, "user": user, "admin": bool(rec.get("admin"))}


@router.get("/api/me")
async def whoami(request: Request, _: None = Depends(require_auth)):
    u = _need_user(request)
    return {"user": u, "admin": _is_admin(u)}


@router.post("/api/logout")
async def logout(response: Response):
    response.delete_cookie("webssh_session")
    return {"ok": True}


@router.put("/api/me/password")
async def change_my_password(request: Request, body: dict, _: None = Depends(require_auth)):
    u = _need_user(request)
    old = str(body.get("old_password") or "")
    new = str(body.get("new_password") or "")
    if len(new) < 8:
        raise HTTPException(400, "新密码至少 8 位")
    with _AUTH_LOCK:                        # 取引用，锁内不做耗时操作
        rec = AUTH["users"].get(u)
        if rec is None:                     # 等待期间账号已被并发删除
            raise HTTPException(404, "用户不存在")
        old_salt, old_hash = rec["salt"], rec["hash"]
        old_ver = rec.get("pwver", 1)       # 版本号：防哈希期间被并发改密/重置
    if not _is_admin(u):                    # 管理员改自己免验旧密码（锁外验，PBKDF2 不持锁）
        if not hmac.compare_digest(old_hash, await _hash_pw_async(old, old_salt)):
            raise HTTPException(403, "旧密码不正确")
    new_salt = secrets.token_hex(16)
    new_hash = await _hash_pw_async(new, new_salt)   # 锁外算哈希（不冻结事件循环）
    with _AUTH_LOCK:                        # 锁内只做赋值 + 落盘（微秒级）
        if AUTH["users"].get(u) is not rec or rec.get("pwver", 1) != old_ver:
            # 账号已删（或删后重建）/ 哈希窗口内密码已被改过——放弃本次修改。
            # is not rec 只能抓"删除/重建"；改密/重置是原地变更同一 dict，须靠
            # 版本号识别。典型场景：凭证泄漏后管理员应急重置，不能被持旧密码者覆盖
            raise HTTPException(409, "密码刚被其他操作修改（可能已被管理员重置），请重新登录后再试")
        rec["salt"] = new_salt
        rec["hash"] = new_hash
        rec["pwver"] = rec.get("pwver", 1) + 1   # 版本+1：该用户所有旧 Cookie 立即作废
        _save_auth()
    return {"ok": True}


# ---------- 会话清理回调（ssh.py 注册，避免循环依赖） ----------
_session_cleanup_hooks = []


def register_session_cleanup(fn):
    """ssh.py 启动时注册：fn(username) → 关闭该用户全部 SSH 会话"""
    _session_cleanup_hooks.append(fn)


# ---------- 用户管理（仅 admin） ----------
@router.get("/api/users")
async def list_users(request: Request, _: None = Depends(require_auth)):
    _need_admin(request)
    return [{"user": n, "admin": bool(r.get("admin"))}
            for n, r in sorted(AUTH["users"].items())]


@router.post("/api/users", status_code=201)
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
    salt = secrets.token_hex(16)
    pw_hash = await _hash_pw_async(pwd, salt)      # 锁外算哈希（不冻结事件循环）
    with _AUTH_LOCK:
        if name in AUTH["users"]:                   # 锁内复查（防并发建同名用户）
            raise HTTPException(400, "用户已存在")
        AUTH["users"][name] = {"salt": salt, "hash": pw_hash,
                               "admin": bool(body.get("admin")), "pwver": 1}
        _save_auth()
    return {"ok": True}


@router.delete("/api/users/{name}")
async def delete_user(request: Request, name: str, _: None = Depends(require_auth)):
    cur = _need_admin(request)
    if name == DEFAULT_ADMIN_USER:
        raise HTTPException(400, "admin 用户不允许删除")
    if name == cur:
        raise HTTPException(400, "不能删除当前登录用户")
    rec = AUTH["users"].get(name)
    if rec is None:
        raise HTTPException(404, "用户不存在")
    if rec.get("admin") and             sum(1 for r in AUTH["users"].values() if r.get("admin")) <= 1:
        raise HTTPException(400, "至少保留一个管理员")
    with _AUTH_LOCK:
        if AUTH["users"].get(name) is not rec:   # 并发删除：后到者 404 而非 KeyError 500
            raise HTTPException(404, "用户不存在")
        del AUTH["users"][name]
        _save_auth()
    with _STORE_LOCK:                      # 该用户名下资产与分组一并删除（否则成孤儿数据）
        groups = _load_groups()
        groups.pop(name, None)
        _save_hosts([h for h in _load_hosts() if h.get("owner") != name], groups)
    for hook in _session_cleanup_hooks:    # 清理该用户的活跃 SSH 会话
        try:
            hook(name)
        except Exception:
            pass
    return {"ok": True}


@router.put("/api/users/{name}/password")
async def reset_user_password(request: Request, name: str, body: dict, _: None = Depends(require_auth)):
    _need_admin(request)
    if name not in AUTH["users"]:
        raise HTTPException(404, "用户不存在")
    new = str(body.get("new_password") or "")
    if len(new) < 8:
        raise HTTPException(400, "密码至少 8 位")
    new_salt = secrets.token_hex(16)
    new_hash = await _hash_pw_async(new, new_salt)   # 锁外算哈希
    with _AUTH_LOCK:
        rec = AUTH["users"].get(name)
        if rec is None:                     # 等哈希期间用户已被并发删除
            raise HTTPException(404, "用户不存在")
        rec["salt"] = new_salt
        rec["hash"] = new_hash
        rec["pwver"] = rec.get("pwver", 1) + 1   # 被重置用户的所有旧 Cookie 立即作废
        _save_auth()
    return {"ok": True}



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


def _load_groups() -> dict:
    """主机分组：{owner: [组名, ...]}，与 hosts 同文件（hosts.json）存放"""
    try:
        with open(HOSTS_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        raw = data.get("groups", {}) if isinstance(data, dict) else {}
        return {u: [str(g) for g in gl] for u, gl in raw.items() if isinstance(gl, list)}
    except (OSError, ValueError):
        return {}


def _save_hosts(hosts: list, groups=None):
    os.makedirs(DATA_DIR, exist_ok=True)
    tmp = HOSTS_FILE + ".tmp"
    payload = {"hosts": hosts, "groups": _load_groups() if groups is None else groups}
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False, indent=2)
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
        "group": h.get("group", ""),
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


@router.get("/api/hosts")
async def list_hosts(request: Request, _: None = Depends(require_auth)):
    user = _need_user(request)
    with _STORE_LOCK:
        return [_host_public(h) for h in _load_hosts() if h.get("owner") == user]


@router.post("/api/hosts", status_code=201)
async def create_host(request: Request, body: dict, _: None = Depends(require_auth)):
    name, host, port, username, password, key, key_pass, trust, remark = _validate_host_body(body, True)
    group = str(body.get("group") or "").strip()[:32]
    rec = {
        "id": secrets.token_hex(8), "owner": _need_user(request),
        "name": name, "host": host, "port": port, "username": username,
        "password_enc": enc(password), "key_enc": enc(key), "key_passphrase_enc": enc(key_pass),
        "trust": trust, "remark": remark, "group": group,
        "created_at": datetime.now().isoformat(timespec="seconds"),
    }
    with _STORE_LOCK:
        if group and group not in _load_groups().get(rec["owner"], []):
            raise HTTPException(400, "分组不存在")
        hosts = _load_hosts()
        hosts.append(rec)
        _save_hosts(hosts)
    return _host_public(rec)


@router.put("/api/hosts/order")
async def reorder_hosts(request: Request, body: dict, _: None = Depends(require_auth)):
    """主机列表拖拽排序：ids 为该用户主机 id 的新顺序（整体提交）。
    注意：本路由必须注册在 PUT /api/hosts/{hid} 之前，否则 "order" 会被当成 hid。"""
    user = _need_user(request)
    ids = body.get("ids")
    if not isinstance(ids, list) or not all(isinstance(i, str) and i for i in ids):
        raise HTTPException(400, "ids 需为非空字符串数组")
    with _STORE_LOCK:
        hosts = _load_hosts()
        mine = [h for h in hosts if h.get("owner") == user]
        by_id = {h["id"]: h for h in mine}
        for i in ids:
            if i not in by_id:                 # 含他人/已删除的主机 id：整体拒绝
                raise HTTPException(404, "主机不存在")
        done, ordered = set(), []
        for i in ids:                          # 去重保序
            if i not in done:
                done.add(i)
                ordered.append(by_id[i])
        rest = [h for h in mine if h["id"] not in done]   # 并发新建的主机附在末尾
        merged = [h for h in hosts if h.get("owner") != user] + ordered + rest
        _save_hosts(merged)
        return [_host_public(h) for h in ordered + rest]


@router.put("/api/hosts/{hid}")
async def update_host(request: Request, hid: str, body: dict, _: None = Depends(require_auth)):
    name, host, port, username, password, key, key_pass, trust, remark = _validate_host_body(body, False)
    group = str(body.get("group") or "").strip()[:32]
    with _STORE_LOCK:
        user = _need_user(request)
        if group and group not in _load_groups().get(user, []):
            raise HTTPException(400, "分组不存在")
        hosts = _load_hosts()
        for h in hosts:
            if h["id"] == hid and h.get("owner") == user:
                h.update({
                    "name": name, "host": host, "port": port, "username": username,
                    "trust": trust, "remark": remark, "group": group,
                    # 编辑时留空 = 保持原凭据不变
                    "password_enc": enc(password) if password else h.get("password_enc", ""),
                    "key_enc": enc(key) if key else h.get("key_enc", ""),
                    "key_passphrase_enc": enc(key_pass) if key_pass else h.get("key_passphrase_enc", ""),
                })
                _save_hosts(hosts)
                return _host_public(h)
    raise HTTPException(404, "主机不存在")


# ---------- 主机分组（按用户隔离） ----------
@router.get("/api/groups")
async def list_groups(request: Request, _: None = Depends(require_auth)):
    user = _need_user(request)
    with _STORE_LOCK:
        return _load_groups().get(user, [])


@router.post("/api/groups", status_code=201)
async def create_group(request: Request, body: dict, _: None = Depends(require_auth)):
    user = _need_user(request)
    name = str(body.get("name") or "").strip()
    if not (1 <= len(name) <= 32):
        raise HTTPException(400, "分组名需为 1-32 个字符")
    with _STORE_LOCK:
        groups = _load_groups()
        mine = groups.setdefault(user, [])
        if name in mine:
            raise HTTPException(400, "分组已存在")
        if len(mine) >= 50:
            raise HTTPException(400, "分组数量已达上限（50）")
        mine.append(name)
        _save_hosts(_load_hosts(), groups)
    return {"ok": True}


@router.delete("/api/groups/{name}")
async def delete_group(request: Request, name: str, _: None = Depends(require_auth)):
    user = _need_user(request)
    with _STORE_LOCK:
        groups = _load_groups()
        if name not in groups.get(user, []):
            raise HTTPException(404, "分组不存在")
        groups[user].remove(name)
        hosts = _load_hosts()
        for h in hosts:                    # 组内主机移出分组（主机本身保留）
            if h.get("owner") == user and h.get("group") == name:
                h["group"] = ""
        _save_hosts(hosts, groups)
    return {"ok": True}


@router.delete("/api/hosts/{hid}")
async def delete_host(request: Request, hid: str, _: None = Depends(require_auth)):
    with _STORE_LOCK:
        user = _need_user(request)
        hosts = _load_hosts()
        left = [h for h in hosts if not (h["id"] == hid and h.get("owner") == user)]
        if len(left) == len(hosts):
            raise HTTPException(404, "主机不存在")
        _save_hosts(left)
    return {"ok": True}
