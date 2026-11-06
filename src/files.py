"""SFTP 文件接口：列表 / 预检 / 下载 / 分片上传 / 删除"""
import posixpath
import stat as stat_mod

import asyncssh
from asyncssh.sftp import FX_NO_SUCH_FILE, FX_PERMISSION_DENIED
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from urllib.parse import quote

from ssh import _get_session, _sanitize_name
from core import require_auth, _need_user

router = APIRouter()


@router.get("/api/files")
async def list_files(request: Request, token: str, path: str = ".", _: None = Depends(require_auth)):
    sess = _get_session(token, user=_need_user(request))
    try:
        sftp = await sess.get_sftp()
        p = await sftp.realpath(path or ".")
        attrs = await sftp.readdir(p)
    except asyncssh.SFTPError as e:
        if e.code == FX_PERMISSION_DENIED:            # 与"路径不存在"区分开
            raise HTTPException(403, "权限不足")
        raise HTTPException(404, "路径不存在")
    entries = []
    for a in attrs:
        if a.filename in (".", ".."):
            continue
        entries.append({
            "name": a.filename,
            "is_dir": stat_mod.S_ISDIR(a.attrs.permissions or 0),
            "size": int(a.attrs.size or 0),
            "mtime": int(a.attrs.mtime or 0),
        })
    entries.sort(key=lambda e: (not e["is_dir"], e["name"].lower()))
    # 当前路径所在文件系统的空间状态（statvfs 扩展，服务器不支持则为 null）
    vfs = None
    try:
        v = await sftp.statvfs(p)
        unit = v.f_frsize or v.f_bsize or 1
        total = v.f_blocks * unit
        free = v.f_bfree * unit
        vfs = {"total": total, "free": free, "used": total - free,
               "percent": round((total - free) / total * 100, 1) if total else 0.0}
    except Exception:
        pass
    return {"path": p, "entries": entries, "vfs": vfs}


@router.get("/api/stat")
async def stat_path(token: str, path: str, _: None = Depends(require_auth)):
    """下载前预检：文件是否还存在（服务器上可能已被删除）"""
    sess = _get_session(token, user=_need_user(request))
    try:
        sftp = await sess.get_sftp()
        st = await sftp.stat(path)
    except asyncssh.SFTPError:
        return {"exists": False}
    return {"exists": True, "is_dir": stat_mod.S_ISDIR(st.permissions or 0),
            "size": int(st.size or 0)}


# ---------- 大文件传输调优参数（asyncssh 原生流水线） ----------
# 局域网/低延迟：大块 + 中并发（1MB×32 = 32MB 在途窗口）
# 广域网/高延迟可调小 DL_BLOCK 至 ~256KB 并调大 DL_AHEAD 至 64
DL_BLOCK = 1 << 20        # 读块 1MB
DL_AHEAD = 16             # 预取深度（未决读请求窗口）
UP_BUF = 1 << 20          # 上传聚合写缓冲 1MB
UP_AHEAD = 8             # 写流水线未决窗口


@router.get("/api/download")
async def download_file(request: Request, token: str, path: str, _: None = Depends(require_auth)):
    sess = _get_session(token, user=_need_user(request))
    try:
        sftp = await sess.get_sftp()
        st = await sftp.stat(path)
        if stat_mod.S_ISDIR(st.permissions or 0):
            raise HTTPException(400, "目录不能下载，请进入目录后下载文件")
        size = int(st.size or 0)
    except asyncssh.SFTPError:
        raise HTTPException(404, "文件不存在或无法访问")
    # block_size + max_requests：asyncssh 原生流水线
    # 局域网实测：带 offset 的定位读比纯顺序读更快（本机 RTT≈0 时 offset 无退化）
    # 广域网高延迟场景可去掉 offset 让 asyncssh 走顺序预取路径
    f = await sftp.open(path, "rb", block_size=DL_BLOCK, max_requests=DL_AHEAD)

    async def pump():
        pos = 0
        try:
            while pos < size:
                chunk = await f.read(min(DL_BLOCK, size - pos), offset=pos)
                if not chunk:
                    break
                data = bytes(chunk)
                pos += len(data)
                yield data
        finally:
            try:
                await f.close()
            except Exception:
                pass

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


@router.put("/api/upload")
async def upload_file(request: Request, token: str, path: str, name: str, offset: int = 0,
                      _: None = Depends(require_auth)):
    """分片并行上传：前端把大文件切成多段，各带 offset 并发 PUT，
    后端对同一文件按 offset 随机写（asyncssh 单客户端天然支持并发请求）。"""
    sess = _get_session(token, user=_need_user(request))
    name = _sanitize_name(name)
    if offset < 0:
        raise HTTPException(400, "offset 不合法")
    target = posixpath.join(path, name)
    sftp = await sess.get_sftp()

    async def open_rw():
        # 首个到达的分片建文件，其余随机写（per-target 锁避免并发建文件互删）
        async with sess.upload_lock(target):
            try:
                return await sftp.open(target, "r+b", block_size=UP_BUF, max_requests=UP_AHEAD)
            except asyncssh.SFTPError:
                f = await sftp.open(target, "wb")          # 创建
                await f.close()
                return await sftp.open(target, "r+b", block_size=UP_BUF, max_requests=UP_AHEAD)

    f = await open_rw()
    written = 0
    try:
        buf = bytearray()
        async for chunk in request.stream():
            buf.extend(chunk)
            if len(buf) >= UP_BUF:
                data = bytes(buf)
                await f.write(data, offset + written)
                written += len(data)
                buf.clear()
        if buf:
            data = bytes(buf)
            await f.write(data, offset + written)
            written += len(data)
    except Exception:
        raise HTTPException(500, "上传中断")
    finally:
        try:
            await f.close()
        except Exception:
            pass
    return {"written": written}


@router.delete("/api/files")
async def delete_file(request: Request, token: str, path: str, _: None = Depends(require_auth)):
    sess = _get_session(token, user=_need_user(request))
    try:
        sftp = await sess.get_sftp()
        st = await sftp.stat(path)
        if stat_mod.S_ISDIR(st.permissions or 0):
            await sftp.rmdir(path)
        else:
            await sftp.remove(path)
    except asyncssh.SFTPError as e:
        if e.code == FX_PERMISSION_DENIED:
            raise HTTPException(403, "权限不足")
        raise HTTPException(404, "文件不存在")
    return {"ok": True}