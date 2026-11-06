# WebSSH —— 好用且安全的网页版 Shell 连接工具

在浏览器里连服务器：主机列表点击即连、多标签终端、SFTP 文件上传下载。
整个服务端就是一个 `WebSSH.py`——零数据库、零构建，解压即用；
登录认证、资产隔离、凭据加密等安全机制开箱即用：比纯终端工具安全，比堡垒机轻盈。

## 快速开始（免装 Python、免联网）

发布包自带完整运行时，解压即用：
macOS 首次运行可能弹“无法验证开发者”提示（无签名的自包含二进制），在 系统设置 → 隐私与安全性 里点“仍要允许”即可。
| 平台 | 包名（版本号随代码变量） | 启动 |
|---|---|---|
| Windows x64 | `WebSSH_v1.0.0_win_x64.zip` | 解压后双击 **`run.bat`** |
| Linux x86_64（麒麟/CentOS/Ubuntu） | `WebSSH_v1.0.0_linux_x86_64.tar.gz` | `tar xzf … && cd WebSSH && sh run.sh` |
| Linux aarch64（飞腾/鲲鹏） | `WebSSH_v1.0.0_linux_aarch64.tar.gz` | 同上 |
| macOS Apple Silicon | `WebSSH_v1.0.0_mac_arm64.tar.gz` | 同上 |

浏览器访问 `https://127.0.0.1:8080/`（自签证书首次告警，点"继续访问"；局域网用 `https://<本机IP>:8080/`）。
默认账号 `admin / Admin#1234`，**部署后立即改密码**。

包内只有：`WebSSH.py` + `runtime/`（运行时与依赖）+ `run.bat`/`run.sh` + `README` + `test_e2e.py`（新机自检）。

## 构建发布包

需可连接至 github

```bash
python pack.py                          # 默认构建 win_x64 包
python pack.py --arch linux-x86_64      # 其余架构按需
python pack.py --arch linux-aarch64     # 飞腾/鲲鹏
python pack.py --arch mac-arm64
python pack.py --arch all               # 全部
python pack.py --with-data              # 任意命令可加：连 data/ 资产一起打包
```

- 版本号自动取自 `WebSSH.py` 的 `VERSION` 变量，包名自动跟随
- 依赖 wheel 走**清华源**（失败回退官方 PyPI）
- Linux/mac 运行时取自 python-build-standalone（优先 `stripped` 版）；**GitHub 不通时**可浏览器手动下载
  对应 tar.gz 放入 `build_cache/runtimes/`，脚本会自动识别（同名含 `-install_only_stripped.tar.gz`）
- 运行时与 wheel 均缓存于 `build_cache/`，重复构建秒级完成
- 产物已裁剪：去掉 stdlib 测试集、tkinter、静态库、pip/setuptools、调试符号

## 源码方式（备选，需系统 Python 3.7+）

```bash
pip install -r requirements.txt
python WebSSH.py
# 或仓库内的 run.bat（Windows）/ run.sh（Linux/macOS，自动建 .venv 隔离依赖，兼容麒麟 V10 的 Python 3.7）
```

## 运行参数

```bash
python WebSSH.py               # 默认 HTTPS + 监听 0.0.0.0:8080
python WebSSH.py --no-tls      # 回退 HTTP
# run.bat / run.sh 支持透传参数，如：sh run.sh --no-tls
```

- 仅本机使用：`WebSSH.py` 末尾 `HOST` 改回 `"127.0.0.1"`
- 自签证书首次自动生成于 `data/webssh_cert.pem`（10 年，SAN 含本机局域网 IP）

## 内置安全机制

- 登录防爆破：同账号连错 5 次锁 5 分钟（不存在的用户名同样计数）
- 密码版本化登录态：改密后该用户全部旧 Cookie 立即作废
- 安全响应头：nosniff / DENY / CSP / no-store，HTTPS 下附加 HSTS，隐藏 server 指纹
- 主机密码/私钥 Fernet 加密落盘，任何接口不下发密码明文（快捷连接只传 host_id）
- 文件传输与终端会话绑定（随机 token，断开即失效）
- 主机密钥默认拒绝未知；勾选"信任"则 TOFU 记录指纹、变更即拒绝
- TLS 仅 1.2/1.3

## 登录与用户

- 多用户：admin 可在「设置」里新增用户、重置他人密码、删除用户（admin 账号不可删）
- 修改密码：普通用户需旧密码，admin 免验；改密后需重新登录
- 资产与用户绑定：每个用户只能看到和连接自己的主机
- 重置全部账号：删除 `data/auth.json` 后重启

## 迁移与数据

| 文件 | 作用 | 说明 |
|---|---|---|
| `data/hosts.json` | 主机资产（按用户归属，密码加密） | 随包迁移 |
| `data/secret.key` | 凭据加密密钥 | ⚠️ 必须与 hosts.json 成对；**拿到包的人即可解密**，只走可信渠道 |
| `data/auth.json` | 平台账号哈希 | 可选，不带则重建默认 admin |
| `data/known_hosts` | TOFU 指纹 | 可选，缺省自动重建 |

## 测试

```bash
python test_e2e.py     # 或包内：runtime/python3(或python.exe) 执行，30 秒全链路自检
```
