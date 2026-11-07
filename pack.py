#!/usr/bin/env python3
"""WebSSH 多架构打包脚本。

用法：
    python pack.py                          # 默认构建 Windows x64 包
    python pack.py --arch linux-x86_64      # 构建 Linux x86_64 包（飞腾/鲲鹏用 linux-aarch64）
    python pack.py --arch mac-arm64         # 构建 Apple Silicon 包
    python pack.py --arch all               # 全部架构依次构建
    任意命令可加 --with-data 连同 data/ 主机资产打包

说明：
    四个平台的运行时均取自 python-build-standalone（首次构建自动下载；GitHub 不通时可
    浏览器手动下载对应 tar.gz 放入 build_cache/runtimes/ 自动识别），依赖 wheel 解包进
    运行时 site-packages——全程在 Windows 上完成，无需目标系统。产物解压后双击
    run.bat / 执行 run.sh 即用，免系统 Python、免联网。
    运行时/wheel 均缓存在 build_cache/，重复构建秒级完成。
"""
import argparse
import json
import re
import os
import shutil
import subprocess
import sys
import tarfile
import urllib.request
import zipfile

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE_DIR)

PYVER = "3.12"                       # 便携运行时统一用 3.12
SKIP_DIRS = {"__pycache__", ".ipynb_checkpoints", "build_cache", ".venv"}
STAGE = os.path.join("build_cache", "stage")

with open(os.path.join("src", "core.py"), encoding="utf-8") as _f:  # 版本号取自代码变量
    VERSION = re.search(r'^VERSION = "(.+?)"', _f.read(), re.M).group(1)

ARCHS = {
    "win-x64": {
        "runtime": "runtime",
        "triple": "x86_64-pc-windows-msvc",
        "pip_platform": "win_amd64",
        "fmt": "zip",
    },
    "linux-x86_64": {
        "runtime": "runtime-linux-x86_64",
        "triple": "x86_64-unknown-linux-gnu",
        "pip_platform": "manylinux2014_x86_64",
        "fmt": "tar.gz",
    },
    "linux-aarch64": {
        "runtime": "runtime-linux-aarch64",
        "triple": "aarch64-unknown-linux-gnu",
        "pip_platform": "manylinux2014_aarch64",
        "fmt": "tar.gz",
    },
    "mac-arm64": {
        "runtime": "runtime-mac-arm64",
        "triple": "aarch64-apple-darwin",
        "pip_platform": "macosx_11_0_arm64",
        "fmt": "tar.gz",
    },
}

UNIX_LAUNCHER = """#!/bin/sh
# WebSSH 启动（Linux/macOS）：使用包内运行时，免系统 Python、免联网
cd "$(dirname "$0")"
xattr -dr com.apple.quarantine runtime >/dev/null 2>&1   # macOS：去除下载隔离属性(Gatekeeper)
chmod -R u+rx runtime/bin >/dev/null 2>&1                 # 兜底：某些解压工具会丢可执行位

# ==== 地址绑定与端口（按需修改；外部已设同名环境变量时以环境变量为准）====
: "\${WEBSSH_HOST:=0.0.0.0}"
: "\${WEBSSH_PORT:=8089}"
export WEBSSH_HOST WEBSSH_PORT
# ==================================

exec runtime/bin/python3 main.py "$@"
"""

WIN_LAUNCHER = """@echo off
rem WebSSH 启动（Windows）：使用包内运行时，免系统 Python、免联网
cd /d "%~dp0"
if not exist runtime\\python.exe (
  echo [run.bat] runtime\\python.exe not found.
  pause
  exit /b 1
)

rem ==== 地址绑定与端口（按需修改；外部已设同名环境变量时以环境变量为准）====
if not defined WEBSSH_HOST set WEBSSH_HOST=0.0.0.0
if not defined WEBSSH_PORT set WEBSSH_PORT=8089
rem ==================================

runtime\\python.exe main.py %*
pause
"""


def http_download(url, dest, retries=5):
    """分块下载 + 超时 + 重试（国内访问 GitHub 慢且易断流）"""
    part = dest + ".part"
    for attempt in range(1, retries + 1):
        try:
            done = os.path.getsize(part) if os.path.exists(part) else 0
            req = urllib.request.Request(url, headers={"Range": f"bytes={done}-"} if done else {})
            with urllib.request.urlopen(req, timeout=60) as r, open(part, "ab" if done else "wb") as f:
                total = int(r.headers.get("Content-Range", r.headers.get("Content-Length", "0")).split("/")[-1])
                while True:
                    chunk = r.read(262144)
                    if not chunk:
                        break
                    f.write(chunk)
                    got = done + f.tell()
                    if total and got % (5 * 1024 * 1024) < 262144:
                        print(f"  [pack] 下载中 {got/1048576:.0f}/{total/1048576:.0f} MB", flush=True)
            if total and os.path.getsize(part) != total:
                raise IOError("不完整")
            os.replace(part, dest)
            return
        except Exception as e:
            print(f"  [pack] 下载中断（第 {attempt} 次）：{e}，断点续传中...", flush=True)
    raise RuntimeError("下载失败: " + url)

# ---------------------------------------------------------------- 依赖收集
def req_list():
    with open("requirements.txt", encoding="utf-8") as f:
        return [l.strip() for l in f if l.strip() and not l.startswith("#")]


def download_deps(platform_tag):
    """下载指定平台的全部 wheel（纯 Python 包自动通用）"""
    wheeldir = os.path.join("build_cache", "wheels-" + platform_tag)
    done_flag = os.path.join(wheeldir, ".done")
    if os.path.exists(done_flag):
        return wheeldir
    os.makedirs(wheeldir, exist_ok=True)
    mirrors = ["https://pypi.tuna.tsinghua.edu.cn/simple", None]   # 优先清华源，失败回退官方
    # httpx：包内 test_e2e.py 自检需要（requirements.txt 已含，此处双保险）
    attempts = [req_list() + ["httpx"], ["fastapi", "uvicorn", "websockets", "paramiko", "httpx"]]
    for reqs in attempts:
        for idx in mirrors:
            cmd = [sys.executable, "-m", "pip", "download", "-d", wheeldir,
                   "--platform", platform_tag, "--implementation", "cp",
                   "--python-version", PYVER, "--abi", "cp" + PYVER.replace(".", ""),
                   "--only-binary=:all:", "-q"]
            if idx:
                cmd += ["-i", idx]
            cmd += reqs
            try:
                subprocess.run(cmd, check=True)
                open(done_flag, "w").close()
                return wheeldir
            except subprocess.CalledProcessError:
                continue
        if reqs is not attempts[-1]:
            print("  [pack] [standard] 依赖在该平台不全，退化为 uvicorn+websockets 精简组合")
    nl = chr(10)
    print(nl + "  [pack] ✗ 依赖 wheel 下载失败（PyPI/清华源均不可达）。")
    print("        可在有网机器上执行 pip download 预下载后，把 *.whl 放入：")
    print(f"        {os.path.abspath(os.path.join('build_cache', 'wheels-' + platform_tag))}{os.sep}")
    print("        再重新运行本打包命令。" + nl)
    raise RuntimeError("依赖下载失败: " + platform_tag)


def unzip_wheels(wheeldir, site_packages):
    os.makedirs(site_packages, exist_ok=True)
    for fn in os.listdir(wheeldir):
        if fn.endswith(".whl"):
            with zipfile.ZipFile(os.path.join(wheeldir, fn)) as z:
                z.extractall(site_packages)


# ---------------------------------------------------------------- 运行时
def runtime_py(arch):
    """该架构运行时里 Python 可执行文件的相对路径"""
    return ("python.exe",) if arch == "win-x64" else ("bin", "python3")


def stdlib_dir(arch):
    """该架构运行时 stdlib 目录的相对路径（win/unix 布局不同）"""
    return ("Lib",) if arch == "win-x64" else ("lib", "python" + PYVER)


def ensure_runtime(arch):
    """下载 python-build-standalone 自包含运行时并把依赖 wheel 解包进去（各平台通用）"""
    cfg = ARCHS[arch]
    rtdir = cfg["runtime"]
    py = os.path.join(rtdir, *runtime_py(arch))
    ok_flag = os.path.join(rtdir, ".deps-ok")
    if os.path.exists(py) and os.path.exists(ok_flag):
        prune_runtime(rtdir, arch)
        return
    if not os.path.exists(py):
        cache = os.path.join("build_cache", "runtimes")
        os.makedirs(cache, exist_ok=True)
        # 优先复用本地缓存（含手动下载放入的包），避免访问 GitHub
        tgz = None
        for suffix in ("install_only_stripped.tar.gz", "install_only.tar.gz"):
            for fn in sorted(os.listdir(cache)):
                if (fn.startswith("cpython-3.12.") and cfg["triple"] in fn
                        and fn.endswith(suffix)):
                    tgz = os.path.join(cache, fn)
                    print(f"  [pack] 使用缓存运行时: {fn}")
                    break
            if tgz:
                break
        if not tgz:
            # 查询最新 release，匹配 cpython-3.12.x+tag-<triple>-install_only(_stripped).tar.gz
            print(f"  [pack] 下载 {arch} 自包含 Python 运行时（来自 python-build-standalone）...")
            url = None
            try:
                with urllib.request.urlopen(
                        "https://api.github.com/repos/astral-sh/python-build-standalone/releases/latest",
                        timeout=20) as r:
                    rel = json.load(r)
                asset = None
                for suffix in ("install_only_stripped.tar.gz", "install_only.tar.gz"):
                    for a in rel.get("assets", []):
                        n = a["name"]
                        if (n.startswith("cpython-3.12.") and cfg["triple"] in n
                                and n.endswith(suffix)):
                            asset = a
                            break
                    if asset:
                        break
                if asset:
                    url = asset["browser_download_url"]
            except Exception:
                url = None
            if url is None:
                # API 不可达：用已知发布号直接构造下载地址并仍尝试直连
                tag = "20261026"
                name = f"cpython-3.12.16+{tag}-{cfg['triple']}-install_only_stripped.tar.gz"
                from urllib.parse import quote
                url = ("https://github.com/astral-sh/python-build-standalone/releases/download/"
                       f"{tag}/{quote(name)}")
            tgz = os.path.join(cache, os.path.basename(url).replace("%2B", "+"))
            if not os.path.exists(tgz):
                try:
                    http_download(url, tgz, retries=2)   # 快速失败：不通就尽快转手动下载指引
                except Exception:
                    print("\n  [pack] ✗ 无法联网下载运行时（GitHub 不可达）。请用浏览器手动下载：\n")
                    print(f"        链接: {url}")
                    print(f"        放到: {os.path.abspath(os.path.join('build_cache', 'runtimes'))}"
                          f"{os.sep} 目录下（保持 .tar.gz 原样，无需解压改名）")
                    print("        然后重新运行本打包命令即可自动识别继续。\n")
                    sys.exit(1)
        tmp = os.path.join(cache, "extract-" + arch)
        if os.path.exists(tmp):
            shutil.rmtree(tmp)
        os.makedirs(tmp)
        with tarfile.open(tgz) as t:
            # share/（terminfo 符号链接在 Windows 无法解出）与 man/ 对运行无用，跳过
            members = [m for m in t.getmembers()
                       if not m.name.startswith(("python/share/", "python/man/"))]
            t.extractall(tmp, members=members, filter="data")
        inner = os.path.join(tmp, "python")          # 官方包内层目录名为 python/
        if not os.path.isdir(inner):
            raise RuntimeError("运行时包结构异常")
        if os.path.exists(rtdir):
            shutil.rmtree(rtdir)
        shutil.move(inner, rtdir)
        shutil.rmtree(tmp, ignore_errors=True)
    print(f"  [pack] 解包 {arch} 依赖 wheel 到运行时...")
    sp = os.path.join(rtdir, *stdlib_dir(arch), "site-packages")
    unzip_wheels(download_deps(cfg["pip_platform"]), sp)
    prune_runtime(rtdir, arch)
    open(ok_flag, "w").close()


def prune_runtime(rtdir, arch):
    """瘦身：去掉 stdlib 测试集/tkinter/静态库/字节码缓存等运行无用部分。
    布局由 arch 决定——不能用 isdir("Lib") 嗅探：Windows 文件系统大小写不敏感，
    linux 运行时的 lib/ 会被误判成 Lib/，导致整套剪裁静默失效（实测踩过）"""
    import glob
    win_layout = arch == "win-x64"
    std = stdlib_dir(arch)
    for d in ("test", "idlelib", "tkinter", "turtledemo", "ensurepip", "lib2to3"):
        p2 = os.path.join(rtdir, *std, d)
        if os.path.isdir(p2):
            shutil.rmtree(p2, ignore_errors=True)
    for d in ("share", "man"):
        p2 = os.path.join(rtdir, d)
        if os.path.isdir(p2):
            shutil.rmtree(p2, ignore_errors=True)
    # Tcl/Tk 残部（tkinter 已删，这些库无用）
    if win_layout:
        for pat in ("_tkinter*", "tcl*", "tk*"):
            for f in glob.glob(os.path.join(rtdir, "DLLs", pat)):
                if os.path.isfile(f):
                    os.remove(f)
        for pat in ("tcl*", "tk*"):
            for d in glob.glob(os.path.join(rtdir, pat)):
                if os.path.isdir(d):
                    shutil.rmtree(d, ignore_errors=True)
    else:
        for f in glob.glob(os.path.join(rtdir, "lib", "python" + PYVER,
                                        "lib-dynload", "_tkinter*")) +              glob.glob(os.path.join(rtdir, "lib", "python" + PYVER,
                                        "lib-dynload", "*_tkinter*")):
            if os.path.isfile(f):
                os.remove(f)               # _tkinter 扩展模块（tkinter 已删，留着无用）
        for pat in ("itcl*", "tcl*", "tk*", "tcl9*", "tk9*"):
            for d in glob.glob(os.path.join(rtdir, "lib", pat)):
                shutil.rmtree(d, ignore_errors=True)
        for so in glob.glob(os.path.join(rtdir, "lib", "*tcl*")) +              glob.glob(os.path.join(rtdir, "lib", "*tk*")):
            if os.path.isfile(so):
                os.remove(so)
        for a in glob.glob(os.path.join(rtdir, "lib", "**", "*.a"), recursive=True) +              glob.glob(os.path.join(rtdir, "lib", "python" + PYVER, "config-*")):
            if os.path.isdir(a):
                shutil.rmtree(a, ignore_errors=True)
            elif os.path.exists(a):
                os.remove(a)
    sp_base = os.path.join(rtdir, *std, "site-packages")
    for junk in ("pip", "pip-", "setuptools", "pkg_resources", "_distutils_hack",
                 "wheel", "uvloop"):            # 包内不再装包：构建工具剪掉
                                                  # 注意不能写 "uv"——会把 uvicorn 误删！
        for name in os.listdir(sp_base) if os.path.isdir(sp_base) else []:
            if name.startswith(junk):
                p3 = os.path.join(sp_base, name)
                shutil.rmtree(p3, ignore_errors=True) if os.path.isdir(p3) else os.remove(p3)
    for dp, dns, fns in os.walk(rtdir):
        if os.path.basename(dp) == "__pycache__":
            shutil.rmtree(dp, ignore_errors=True)
            continue
        for f in fns:
            if f.endswith((".pyc", ".pyo")):
                os.remove(os.path.join(dp, f))

# ---------------------------------------------------------------- 打包
def copy_tree(dst, root, dest_name):
    """把 root 目录整体拷入 dst/dest_name/（运行时在包内统一叫 runtime/）"""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in SKIP_DIRS and d not in ARCHS.values()]
        for f in filenames:
            if f.endswith((".pyc", ".pyo")) or f in (".deps-ok",):
                continue
            p = os.path.join(dirpath, f)
            rel = os.path.relpath(p, root)
            target = os.path.join(dst, dest_name, rel)
            os.makedirs(os.path.dirname(target), exist_ok=True)
            shutil.copy2(p, target)


def make_dist(arch, with_data):
    cfg = ARCHS[arch]
    ensure_runtime(arch)

    if os.path.exists(STAGE):
        shutil.rmtree(STAGE)
    dst = os.path.join(STAGE, "WebSSH")
    os.makedirs(dst)
    # 独立包只放"运行必需"：应用 + 运行时 + 唯一启动入口 + 说明/自检。
    # 不放：系统 Python 启动脚本、requirements.txt（依赖已预装）
    for f in ("main.py", "core.py", "ssh.py", "files.py", "page.py"):   # 应用模块（入口 + 业务）
        shutil.copy2(os.path.join("src", f), os.path.join(dst, f))
    if os.path.exists("test_e2e.py"):                        # 新机自检
        shutil.copy2("test_e2e.py", os.path.join(dst, "test_e2e.py"))
    # 包内 README 面向使用者（英文默认 + 顶部切换中文）；项目 README（含构建/源码说明）不入包
    shutil.copy2("README_PACKAGE.md", os.path.join(dst, "README.md"))
    shutil.copy2("README_PACKAGE.zh-CN.md", os.path.join(dst, "README.zh-CN.md"))
    copy_tree(dst, cfg["runtime"], "runtime")
    if arch == "win-x64":                    # 唯一启动脚本：run.bat / run.sh
        with open(os.path.join(dst, "run.bat"), "w", encoding="utf-8", newline="\r\n") as f:
            f.write(WIN_LAUNCHER)
    else:
        with open(os.path.join(dst, "run.sh"), "w", encoding="utf-8", newline="\n") as f:
            f.write(UNIX_LAUNCHER)
    if with_data:
        copy_tree(dst, "data", "data")

    out = f"WebSSH_{VERSION}_{arch.replace('-', '_')}." + cfg["fmt"]
    if cfg["fmt"] == "zip":
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
            for dp, dns, fns in os.walk(STAGE):
                for fn in fns:
                    p = os.path.join(dp, fn)
                    z.write(p, os.path.relpath(p, STAGE).replace(os.sep, "/"))
    else:
        with tarfile.open(out, "w:gz") as t:
            def _fix_mode(ti):
                # Windows 打包不保留可执行位：手动写入 Unix 权限
                if ti.isdir():
                    ti.mode = 0o755
                elif ti.name == "WebSSH/run.sh" or "/runtime/bin/" in ti.name:
                    ti.mode = 0o755          # 解释器与脚本必须可执行
                else:
                    ti.mode = 0o644
                return ti
            t.add(dst, arcname="WebSSH", filter=_fix_mode)
    size = os.path.getsize(out) / 1048576
    verify_dist(out, cfg["fmt"])
    print(f"[pack] {arch:14s} -> {out}（{size:.1f} MB）{' 含数据' if with_data else ''}")


# ---------------------------------------------------------------- 出包验收
def verify_dist(out, fmt):
    """出包即验收：应用入口/关键依赖/启动脚本/权限不齐直接判失败（防止静默损坏）"""
    need_pkgs = ["uvicorn/__init__.py", "fastapi/__init__.py", "paramiko/__init__.py",
                 "websockets/__init__.py", "cryptography/__init__.py", "nacl/__init__.py",
                 "typing_extensions.py", "httpx/__init__.py", "asyncssh/__init__.py"]
    problems = []
    if fmt == "zip":
        z = zipfile.ZipFile(out)
        names = set(z.namelist())
        sp = "runtime/Lib/site-packages/"                     # win 布局
        entry = "WebSSH/run.bat"
        if entry not in names:
            problems.append("缺 run.bat")
        else:
            bat = z.read(entry).decode(errors="replace")
            if "main.py" not in bat:
                problems.append("run.bat 未启动 main.py")
    else:
        t = tarfile.open(out)
        members = t.getmembers()
        names = {m.name for m in members}
        mode = {m.name: m.mode for m in members}
        sp = "runtime/lib/python" + PYVER + "/site-packages/"   # unix 布局
        for f in ("WebSSH/run.sh", "WebSSH/runtime/bin/python3"):
            if f not in names:
                problems.append("缺 " + f)
        if "WebSSH/run.sh" in names:
            if mode["WebSSH/run.sh"] & 0o111 == 0:
                problems.append("WebSSH/run.sh 无可执行位")
            sh = t.extractfile("WebSSH/run.sh").read().decode(errors="replace")
            if "xattr" not in sh or "chmod" not in sh:
                problems.append("run.sh 缺 xattr/chmod 自愈")
            if "main.py" not in sh:
                problems.append("run.sh 未启动 main.py")
        if "WebSSH/runtime/bin/python3" in names and                mode["WebSSH/runtime/bin/python3"] & 0o111 == 0:
            problems.append("WebSSH/runtime/bin/python3 无可执行位")
    for f in ("main.py", "core.py", "ssh.py", "files.py", "page.py", "test_e2e.py",
              "README.md", "README.zh-CN.md"):
        if ("WebSSH/" + f) not in names:
            problems.append("缺应用文件 " + f)
    for pk in need_pkgs:
        if ("WebSSH/" + sp + pk) not in names:
            problems.append("缺依赖 " + pk)
    if problems:
        raise SystemExit("[pack] ✗ 验收失败: " + "; ".join(problems))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arch", default="win-x64",
                    choices=list(ARCHS) + ["all"], help="目标架构（默认 win-x64）")
    ap.add_argument("--with-data", action="store_true", help="连同 data/ 资产打包")
    args = ap.parse_args()
    targets = list(ARCHS) if args.arch == "all" else [args.arch]
    for a in targets:
        make_dist(a, args.with_data)


if __name__ == "__main__":
    main()
