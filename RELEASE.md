# WebSSH 发布流程（GitHub Release）

> 适用场景：把四个平台的安装包发布到 GitHub，供直接下载。
> 原因说明：GitHub **网页上传附件限制单文件 25MB**，我们的包 22~69MB，
> 必须走命令行（API 通道，单文件上限 2GB），因此使用官方 CLI 工具 `gh`。

## 一、安装 GitHub CLI（每台机器一次）

任选其一：

```powershell
# 方式 A：winget（Win10/11 自带）
winget install --id GitHub.cli
```

```
# 方式 B：MSI 直装（Server 系统无 winget 时）
浏览器打开 https://github.com/cli/cli/releases/latest
下载 gh_x.x.x_windows_amd64.msi → 双击安装
```

**安装后必须新开一个终端窗口**（PATH 是启动时加载的，旧窗口里 gh 永远"不是内部或外部命令"），验证：

```bash
gh --version
```

## 二、登录 GitHub（每台机器一次）

```bash
gh auth login
```

交互选项依次选：`GitHub.com` → `HTTPS` → `Login with a web browser`，
终端会显示一个一次性代码，按回车后浏览器打开 GitHub 授权页，粘贴代码确认。

## 三、发布 Release

### 1. 构建四个包（在项目源码目录）

```bash
python pack.py --arch all
```

产物（版本号取自 `src/core.py` 的 `VERSION` 变量）：

```
WebSSH_v1.0.0_win_x64.zip
WebSSH_v1.0.0_linux_x86_64.tar.gz
WebSSH_v1.0.0_linux_aarch64.tar.gz
WebSSH_v1.0.0_mac_arm64.tar.gz
```

每次打包自动做完整性验收（关键依赖/启动脚本/权限），验收不过构建直接失败。

### 2. 上传发布（在包所在目录执行，单行）

```bash
gh release create -R awei0819/WebSSH v1.0.0 WebSSH_v1.0.0_win_x64.zip WebSSH_v1.0.0_linux_x86_64.tar.gz WebSSH_v1.0.0_linux_aarch64.tar.gz WebSSH_v1.0.0_mac_arm64.tar.gz -t "v1.0.0" -n "好用且安全的网页版 Shell 连接工具，解压即用"
```

参数说明：

| 参数 | 含义 |
|---|---|
| `-R awei0819/WebSSH` | 目标仓库（不在 git 克隆目录里执行时必须带） |
| `v1.0.0` | tag 名，不存在会自动创建 |
| 四个文件 | 作为附件上传（API 通道，上限 2GB/个） |
| `-t` | Release 标题 |
| `-n` | 描述文字；想用长文案可改为 `-F release_notes.md` |

### 3. 验证

命令成功后终端会输出 Release 地址。直接下载链接格式：

```
https://github.com/awei0819/WebSSH/releases/download/v1.0.0/WebSSH_v1.0.0_win_x64.zip
```

可被 `curl -LO` / `wget` 直接引用。注意：**仓库为 Private 时 Release 仅协作者可见**，
公开下载需先把仓库转 Public（Settings → General → Danger Zone）。

## 四、后续版本发布节奏

1. 修改 `src/core.py` 的 `VERSION = "v1.0.1"`
2. `python pack.py --arch all` 出新包（包名自动带新版本号）
3. 提交代码并推送
4. `gh release create -R awei0819/WebSSH v1.0.1 WebSSH_v1.0.1_*.zip ...`（同上）

三处版本号保持一致：代码变量 / 包名 / tag。

## 五、常见问题

| 现象 | 处理 |
|---|---|
| 网页上传报 `File size too big: 25 MB are allowed` | 网页通道的硬限制，走本文档的 gh 命令 |
| `'gh' 不是内部或外部命令` | 装完后**新开**终端窗口；仍不行说明没装成功 |
| `gh release create` 报认证失败 | 重跑 `gh auth login`，或 `gh auth status` 查看状态 |
| 传错了想重发 | `gh release delete v1.0.0 -R awei0819/WebSSH --yes` 删除后重建；或 `gh release upload v1.0.0 文件 --clobber -R ...` 覆盖附件 |
