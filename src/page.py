"""
前端页面（单页应用）。登录页副标题的 __VERSION__ 占位符在导入时替换为
core.VERSION——版本号唯一来源在 core.py，改版本不用动这里。
"""
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
  #user-bar { display: flex; align-items: center; gap: 6px; margin-top: 8px;
              font-size: 12px; color: #9cdcfe;
              padding: 2px 10px 6px 12px; }
  /* 窄侧边栏：按钮不可压缩（CJK 逐字换行会变竖排），用户名最后收缩 */
  #user-bar .icon-btn { flex: none; white-space: nowrap; }   /* 左/右留白：绿点与两侧边框保持距离 */
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

  .gp-row-name { flex: 1; min-width: 0; white-space: nowrap; overflow: hidden;
                 text-overflow: ellipsis; }

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
  .host-empty { color: #666; font-size: 12px; text-align: center; margin-top: 16px;
                line-height: 2; white-space: pre-line; }
  #host-title { display: flex; align-items: center; justify-content: space-between;
               padding: 8px 12px 4px; font-size: 12px; color: #888; }
  #host-count { font-size: 11px; color: #666; }
  .side-search { margin: 4px 8px 2px; }
  .side-search input { width: 100%; background: #1e1e1e; border: 1px solid #3c3c3c; color: #ddd;
                       border-radius: 4px; padding: 3px 8px; font-size: 11px; outline: none; }
  .side-search input:focus { border-color: #0e639c; }
  .host-item { display: flex; align-items: center; gap: 4px; padding: 5px 10px; border-radius: 6px;
               cursor: pointer; margin-bottom: 2px; border: 1px solid transparent; }
  .host-item:hover { background: #242424; border-color: #2f2f2f; }
  .host-item.dragging { opacity: .4; }
  .host-item.sub { padding-left: 28px; }   /* 树形缩进（全部主机/分组之下） */
  /* ---------- 分组树节点 ---------- */
  .grp-item { display: flex; align-items: center; gap: 6px; padding: 5px 10px; font-size: 12px;
              color: #9cdcfe; cursor: pointer; border-radius: 6px; user-select: none;
              margin-bottom: 2px; }
  .grp-item:hover { background: #242424; }
  .grp-chev { display: flex; flex: none; color: #9cdcfe; width: 12px; height: 12px;
              transition: transform .15s; }
  .grp-chev.open { transform: rotate(90deg); }
  .grp-folder { display: flex; flex: none; }
  .grp-name { flex: 1; min-width: 0; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .grp-count { color: #666; font-size: 11px; flex: none; }
  .ht-btns { display: flex; align-items: center; gap: 6px; }
  .host-name { font-size: 13px; flex: 1; min-width: 0; white-space: nowrap; overflow: hidden;
               text-overflow: ellipsis; }
  .host-actions { display: none; gap: 2px; }
  .host-item:hover .host-actions { display: flex; }
  .icon-btn { background: none; border: none; color: #9cdcfe; cursor: pointer; font-size: 13px;
              padding: 3px 5px; border-radius: 4px; line-height: 1; text-decoration: none; }
  .icon-btn:hover { background: #333; color: #fff; }
  .icon-btn.danger:hover { color: #f48771; }
  .icon-btn.flip-x { transform: scaleX(-1); }   /* 铅笔笔尖朝左下（✎ 原本朝右下，水平镜像） */
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
  .ctx-menu { position: fixed; z-index: 200; background: #2a2a2a; border: 1px solid #454545;
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
  .field input.invalid { border-color: #f48771; }   /* 地址/名称校验未过 */
  .err-line { color: #f48771; font-size: 11px; margin: -4px 0 6px; }
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
    <div id="host-title"><span>主机列表</span><span class="ht-btns">
      <button id="btn-new-group" type="button" class="text-btn" title="新建分组">＋ 分组</button>
      <span id="host-count">数量 0</span></span></div>
    <div class="side-search">
      <input id="host-search" placeholder="搜索名称 / IP / 备注" spellcheck="false" autocomplete="off">
    </div>
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
        <div id="hf-name-err" class="err-line hidden">同名主机已存在</div>
        <input id="hf-name" required maxlength="64" placeholder="如：生产-web01" autocomplete="off">
      </div>
      <div class="row">
        <div class="field" style="flex:2">
          <label>主机 IP / 域名</label>
          <div id="hf-host-err" class="err-line hidden">IP 地址不合法</div>
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
      <div id="hf-trust-hint" class="hidden" style="color:#f48771;font-size:11px;margin:-6px 0 12px">
        未勾选时：未记录过指纹的主机连接将被直接拒绝（已记录过指纹的主机不受影响）
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
          <div id="mf-host-err" class="err-line hidden">IP 地址不合法</div>
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
<div id="ctx-menu" class="ctx-menu hidden">
  <div class="ctx-item" data-act="dup">复制窗口</div>
  <div class="ctx-item" data-act="reconn">重新连接</div>
  <div class="ctx-sep"></div>
  <div class="ctx-item" data-act="close">关闭当前</div>
  <div class="ctx-item danger" data-act="closeAll">关闭所有</div>
</div>

<!-- 主机右键菜单（内容按目标动态生成：加入分组 / 移出 / 编辑 / 删除） -->
<div id="host-ctx-menu" class="ctx-menu hidden"></div>

<!-- 登录页 -->
<div class="overlay hidden" id="login-overlay">
  <div class="card" style="width:360px">
    <h1>⌨ WebSSH</h1>
    <p class="login-sub">轻量堡垒机 __VERSION__ · 请登录</p>
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

<!-- 通用输入弹窗（可选实时校验：红框 + 红字） -->
<div class="overlay hidden" id="prompt-overlay">
  <div class="card" style="width:360px">
    <h1 id="pt-title">输入</h1>
    <div class="field" style="margin-top:4px">
      <div id="pt-err" class="err-line hidden"></div>
      <input id="pt-input" autocomplete="off">
    </div>
    <div class="modal-actions">
      <button type="button" class="ghost" id="pt-no">取 消</button>
      <button type="button" id="pt-yes">确 定</button>
    </div>
  </div>
</div>

<!-- 分组归属选择 弹窗（多归属复选，搜索 + 分页） -->
<div class="overlay hidden" id="grp-pick-overlay">
  <div class="card" style="width:380px;max-height:80vh;display:flex;flex-direction:column">
    <h1 id="gp-title" style="flex:none">分组归属</h1>
    <div class="set-toolbar" style="flex:none">
      <input id="gp-search" class="set-search" placeholder="搜索分组名称" autocomplete="off" spellcheck="false">
    </div>
    <div id="gp-list" class="set-list" style="flex:1;min-height:100px"></div>
    <div class="set-pager" id="gp-pager" style="flex:none"></div>
    <div class="modal-actions" style="flex:none">
      <button type="button" class="ghost" data-close>取 消</button>
      <button type="button" id="gp-yes">保 存</button>
    </div>
  </div>
</div>

<!-- 分组成员批量管理 弹窗（添加/移除主机，样式与设置-主机管理一致） -->
<div class="overlay hidden" id="host-pick-overlay">
  <div class="card" style="width:520px;max-height:86vh;display:flex;flex-direction:column">
    <h1 id="hp-title" style="flex:none">选择主机</h1>
    <div class="set-toolbar" style="flex:none">
      <input id="hp-search" class="set-search" placeholder="搜索名称 / IP / 用户名 / 备注" autocomplete="off" spellcheck="false">
    </div>
    <div id="hp-list" class="set-list" style="flex:1;min-height:120px"></div>
    <div class="set-pager" id="hp-pager" style="flex:none"></div>
    <div class="modal-actions" style="flex:none">
      <button type="button" class="ghost" data-close>取 消</button>
      <button type="button" id="hp-yes">确 定</button>
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
  let dragHostId = null;        // 正在拖拽排序的主机
  let HOSTS = [];               // 当前主机列表缓存（拖拽排序时对比新旧顺序）
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
    // 成功提示 1.5s 即散；错误信息需要阅读时间，留 3.5s
    toastTimer = setTimeout(() => { t.className = ''; }, isErr ? 3500 : 1500);
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

  // 主机地址校验（与后端 _valid_host 同规则）：形似 IP 的必须真是合法 IP
  const _OCT = /(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)/;
  const _V4 = new RegExp('^' + _OCT.source + '(\\.' + _OCT.source + '){3}$');
  const _V6 = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
  function validHostAddr(h) {
    h = (h || '').trim();
    if (!h) return false;
    if (/^[\d.]+$/.test(h)) return _V4.test(h);    // 纯数字点分 → 严格 IPv4（如 999.1.1.1 拒绝）
    if (h.includes(':')) return _V6.test(h);       // IPv6（含 v4 映射形式）
    if (h.length > 253) return false;
    return /^[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/.test(h);
  }
  // 地址输入框：失焦标红框+红字，改对了自动恢复（输入中不判，避免敲到一半闪红）；提交前严格拦截
  ['hf-host', 'mf-host'].forEach(id => {
    const el = $(id);
    const err = $(id + '-err');
    const mark = (bad) => { el.classList.toggle('invalid', bad); err.classList.toggle('hidden', !bad); };
    el.addEventListener('input', () => { if (validHostAddr(el.value)) mark(false); });
    el.addEventListener('blur', () => { if (el.value.trim()) mark(!validHostAddr(el.value)); });
    el._markInvalid = mark;                        // 供提交拦截复用
  });

  // 名称冲突（用户内唯一，编辑时排除自己）：红框 + 框上红字，改了对齐消失
  function nameConflict(name) {
    const id = $('host-form').dataset.id;          // 编辑时的自身 id（排除自己）
    const n = (name || '').trim();
    return !!n && HOSTS.some(h => h.name === n && h.id !== id);
  }
  function syncNameErr() {
    const bad = nameConflict($('hf-name').value);
    $('hf-name').classList.toggle('invalid', bad);
    $('hf-name-err').classList.toggle('hidden', !bad);
    return bad;
  }
  $('hf-name').addEventListener('input', syncNameErr);
  $('hf-name').addEventListener('blur', syncNameErr);

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
    updateSbExpand();
  }

  // ==================== 主机资产（树形：全部主机 + 自定义分组） ====================
  let GROUPS = [];                          // 分组名列表
  let GRP_OPEN = {};                        // 展开状态（'*'=全部主机），localStorage 持久化
  try { Object.assign(GRP_OPEN, JSON.parse(localStorage.getItem('webssh_grp_open') || '{}')); } catch (e) {}

  function saveGrpOpen() { localStorage.setItem('webssh_grp_open', JSON.stringify(GRP_OPEN)); }

  function folderIcon() {                   // 浅色文件夹图标（JumpServer 风格）
    const s = document.createElement('span');
    s.className = 'grp-folder';
    s.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#c8c8c8" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z"/></svg>';
    return s;
  }

  function starIcon() {                     // 收藏夹星标（区别于分组文件夹）
    const s = document.createElement('span');
    s.className = 'grp-folder';
    s.innerHTML = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="#dcdcaa" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>';
    return s;
  }

  function grpNode(key, label, count, icon, forceOpen) {
    const open = forceOpen ||
        (GRP_OPEN[key] === undefined ? (key === '*' || key === 'fav') : !!GRP_OPEN[key]);
    const node = document.createElement('div');
    node.className = 'grp-item';
    const chev = document.createElement('span');
    chev.className = 'grp-chev' + (open ? ' open' : '');
    chev.innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"><polyline points="9 18 15 12 9 6"/></svg>';
    const name = document.createElement('span');
    name.className = 'grp-name';
    name.textContent = label;
    name.title = label + '（右键更多操作）';
    const cnt = document.createElement('span');
    cnt.className = 'grp-count';
    cnt.textContent = count;
    node.append(chev, icon || folderIcon(), name, cnt);
    node.onclick = () => { GRP_OPEN[key] = !open; saveGrpOpen(); renderHosts(); };
    node.oncontextmenu = (e) => { e.preventDefault(); openNodeCtx(e, key); };
    return { node, open };
  }

  function hostRow(h, parentKey) {
    const item = document.createElement('div');
    item.className = 'host-item sub';
    item.dataset.id = h.id;
    item.dataset.parent = parentKey;        // 所属区块：排序只认"全部主机"（'*'）里的行
    item.title = h.name + '\n' + h.username + '@' + h.host + ':' + h.port +
                 (h.remark ? '\n备注：' + h.remark : '') + '\n拖拽可排序 · 右键更多操作';

    const nm = document.createElement('div');
    nm.className = 'host-name';
    nm.textContent = h.name;

    item.append(nm);
    item.onclick = () => newSession({ host_id: h.id });
    item.oncontextmenu = (e) => { e.preventDefault(); openHostCtx(e, h, parentKey); };

    // 拖拽排序：各区块内独立进行（发起与接收都限定同区块——收藏夹/分组行是重复
    // 渲染，跨区块接收会让被拖行落入其他区块的 DOM，收集时首现位置错乱）
    item.draggable = true;
    item.addEventListener('dragstart', (e) => {
      dragHostId = h.id;
      item.classList.add('dragging');
      e.dataTransfer.effectAllowed = 'move';
      try { e.dataTransfer.setData('text/plain', h.id); } catch (err) {}
    });
    item.addEventListener('dragend', () => {
      dragHostId = null;
      item.classList.remove('dragging');
      saveHostOrder(item.dataset.parent);   // 拖拽结束后行仍在原区块（接收有同区块守卫）
    });
    item.addEventListener('dragover', (e) => {
      if (dragHostId === null || dragHostId === h.id) return;
      const dragged = document.querySelector('.host-item.dragging');
      if (!dragged || dragged.dataset.parent !== item.dataset.parent) return;   // 仅同区块接收
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      const rect = item.getBoundingClientRect();
      if ((e.clientX - rect.left) > rect.width / 2) item.after(dragged);
      else item.before(dragged);
    });
    return item;
  }

  function renderHosts() {
    const box = $('host-list');
    box.textContent = '';
    const kw = hostQ.trim().toLowerCase();   // 侧边栏搜索：命中主机，区块随命中过滤
    const hit = (h) => !kw || [h.name, h.host, h.remark]
        .some(v => (v || '').toLowerCase().includes(kw));
    const allHosts = kw ? HOSTS.filter(hit) : HOSTS;
    const favs = HOSTS.filter(h => h.fav && hit(h));
    $('host-count').textContent = kw
        ? '数量 ' + allHosts.length + '/' + HOSTS.length : '数量 ' + HOSTS.length;
    if (kw && !allHosts.length) {
      const d = document.createElement('div');
      d.className = 'host-empty';
      d.textContent = '无匹配主机';
      box.appendChild(d);
      return;
    }
    const openAll = !!kw;                    // 搜索时全部展开，直接看到命中行
    if (favs.length || !kw) {
      const fav = grpNode('fav', '收藏夹', favs.length, starIcon(), openAll);
      box.appendChild(fav.node);
      if (fav.open) favs.forEach(h => box.appendChild(hostRow(h, 'fav')));
    }
    const all = grpNode('*', '全部主机', allHosts.length, null, openAll);
    box.appendChild(all.node);
    if (all.open) allHosts.forEach(h => box.appendChild(hostRow(h, '*')));
    if (!HOSTS.length) {                     // 空列表提示挂在"全部主机"节点下方
      const d = document.createElement('div');
      d.className = 'host-empty';
      d.textContent = '暂无主机\n点右上「＋ 主机」添加';
      box.appendChild(d);
    }
    GROUPS.forEach(g => {
      const members = HOSTS.filter(h => (h.groups || []).includes(g) && hit(h));
      if (kw && !members.length) return;     // 搜索时隐藏无命中的分组
      const n = grpNode(g, g, members.length, null, openAll);
      box.appendChild(n.node);
      if (n.open) members.forEach(h => box.appendChild(hostRow(h, g)));
    });
  }

  $('host-search').addEventListener('input', () => {
    hostQ = $('host-search').value;
    renderHosts();
  });

  async function loadHosts() {
    let hosts, groups;
    try {
      [hosts, groups] = await Promise.all([api('/api/hosts'), api('/api/groups')]);
    } catch (e) { if (e.status !== 401) toast(e.message, true); return; }
    HOSTS = hosts;
    GROUPS = groups;
    $('login-overlay').classList.add('hidden');   // 已登录（刷新场景）
    renderHosts();
  }

  async function saveHostOrder(section) {
    // 各区块内独立排序：收集该区块的行序，分组/收藏区按"占位合并"回全局序——
    // 成员的新相对顺序放回它们在全局序列中原有的槽位，不动区块外的其他主机
    const rows = [...document.querySelectorAll(
        `#host-list .host-item[data-parent="${CSS.escape(section)}"]`)];
    if (!rows.length) return;
    let ids;
    if (section === '*') {
      ids = rows.map(el => el.dataset.id);
    } else {
      const sub = rows.map(el => el.dataset.id);
      let i = 0;
      ids = HOSTS.map(h => sub.includes(h.id) ? sub[i++] : h.id);
    }
    if (ids.join('\n') === HOSTS.map(h => h.id).join('\n')) return;   // 顺序未变
    try {
      HOSTS = await api('/api/hosts/order', {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ids }),
      });
      renderHosts();                        // 其他区块（重复行）同步为新顺序
    } catch (e) {
      toast('排序保存失败：' + e.message, true);
      loadHosts();                          // 回滚为服务端顺序
    }
  }

  // ---------- 新建分组 / 主机右键菜单 ----------
  // 分组名校验：长度 / 保留字（* fav 撞树节点 key）/ 重名（改名排除自身）
  function groupNameValidator(oldName) {
    return (v) => {
      const n = (v || '').trim();
      if (!(n.length >= 1 && n.length <= 32)) return '分组名需为 1-32 个字符';
      if (n === '*' || n === 'fav') return '分组名不能为 * 或 fav';
      if (GROUPS.includes(n) && n !== oldName) return '分组名已存在';
      return '';
    };
  }

  $('btn-new-group').onclick = async () => {
    const name = await dlgPrompt('新建分组', '分组名称（1-32 字符）', null, null, groupNameValidator());
    if (!name) return;
    try {
      await api('/api/groups', { method: 'POST', headers: { 'Content-Type': 'application/json' },
                                 body: JSON.stringify({ name }) });
      loadHosts();
    } catch (e) { toast(e.message, true); }
  };

  function hideHostCtx() { $('host-ctx-menu').classList.add('hidden'); }

  function placeCtx(e, m) {                 // 弹出定位 + 屏幕边缘钳制
    m.classList.remove('hidden');
    let x = e.clientX, y = e.clientY;
    if (x + m.offsetWidth > innerWidth - 8) x = innerWidth - m.offsetWidth - 8;
    if (y + m.offsetHeight > innerHeight - 8) y = innerHeight - m.offsetHeight - 8;
    m.style.left = x + 'px';
    m.style.top = y + 'px';
  }

  // 树节点右键菜单：分组=重命名/删除/全部折叠/全部展开；收藏夹与全部主机=仅折叠/展开
  function openNodeCtx(e, key) {
    const m = $('host-ctx-menu');
    m.textContent = '';
    const add = (txt, fn, danger) => {
      const it = document.createElement('div');
      it.className = 'ctx-item' + (danger ? ' danger' : '');
      it.textContent = txt;
      it.onclick = () => { hideHostCtx(); fn(); };
      m.appendChild(it);
    };
    const sep = () => { const s = document.createElement('div'); s.className = 'ctx-sep'; m.appendChild(s); };
    if (key !== '*' && key !== 'fav') {
      const hasMembers = HOSTS.some(h => (h.groups || []).includes(key));
      add('添加主机', () => openHostPicker(key, 'add'));
      if (hasMembers) add('移除主机', () => openHostPicker(key, 'remove'));   // 空组不显示
      sep();
      add('重命名分组', () => renameGroup(key));
      add('删除分组', () => delGroupFlow(key), true);
      sep();
    }
    add('全部折叠', () => setAllNodesOpen(false));
    add('全部展开', () => setAllNodesOpen(true));
    placeCtx(e, m);
  }

  function setAllNodesOpen(open) {
    GRP_OPEN = { '*': open, 'fav': open };
    GROUPS.forEach(g => { GRP_OPEN[g] = open; });
    saveGrpOpen();
    renderHosts();
  }

  async function renameGroup(oldName) {
    const name = await dlgPrompt('重命名分组', '分组名称（1-32 字符）', null, oldName,
                                 groupNameValidator(oldName));
    if (!name || name === oldName) return;
    try {
      await api('/api/groups/' + encodeURIComponent(oldName), {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name }),
      });
      loadHosts();
    } catch (e) { toast(e.message, true); }
  }

  async function delGroupFlow(g) {
    if (!(await dlgConfirm('删除分组「' + g + '」？\n组内主机将移出分组（主机本身保留）。', '删除分组'))) return;
    try { await api('/api/groups/' + encodeURIComponent(g), { method: 'DELETE' }); loadHosts(); }
    catch (e) { toast(e.message, true); }
  }

  // 主机右键菜单按所在区块变化：收藏夹行只管收藏；分组行给"移出本组"快捷项；
  // 全部主机行提供完整的分组归属管理
  function openHostCtx(e, h, section) {
    const m = $('host-ctx-menu');
    m.textContent = '';
    const add = (txt, fn, danger) => {
      const it = document.createElement('div');
      it.className = 'ctx-item' + (danger ? ' danger' : '');
      it.textContent = txt;
      it.onclick = () => { hideHostCtx(); fn(); };
      m.appendChild(it);
    };
    const sep = () => { const s = document.createElement('div'); s.className = 'ctx-sep'; m.appendChild(s); };
    if (section === 'fav') {                // 收藏夹里的行：只做收藏切换
      add('★ 取消收藏', () => patchHost(h, { fav: false }));
      placeCtx(e, m);
      return;
    }
    add(h.fav ? '★ 取消收藏' : '★ 收藏', () => patchHost(h, { fav: !h.fav }));
    if (section === '*') {
      if (GROUPS.length) {
        add('分组归属', () => openGroupPick(h));
        sep();
      }
    } else {
      add('移出分组（' + section + '）',
          () => patchHost(h, { groups: (h.groups || []).filter(g => g !== section) }));
      sep();
    }
    add('编辑', () => openHostModal(h));
    add('删除', () => deleteHost(h), true);
    placeCtx(e, m);
  }

  // 分组归属选择器：多归属复选 + 搜索 + 分页（选择集跨页/跨搜索保持）
  let _gpHost = null;
  let _gp = null;                           // { q, page, selected:Set }
  const GP_PAGE = 20;

  function openGroupPick(h) {
    _gpHost = h;
    _gp = { q: '', page: 1, selected: new Set(h.groups || []) };
    $('gp-title').textContent = '「' + h.name + '」的分组归属';
    $('gp-search').value = '';
    $('grp-pick-overlay').classList.remove('hidden');
    renderGroupPick();
    setTimeout(() => $('gp-search').focus(), 0);
  }

  function renderGroupPick() {
    const kw = _gp.q.trim().toLowerCase();
    const pool = kw ? GROUPS.filter(g => g.toLowerCase().includes(kw)) : GROUPS.slice();
    const pages = Math.max(1, Math.ceil(pool.length / GP_PAGE));
    if (_gp.page > pages) _gp.page = pages;
    const box = $('gp-list');
    box.textContent = '';
    if (!GROUPS.length) {
      const d = document.createElement('div');
      d.className = 'set-empty';
      d.textContent = '暂无分组，点侧边栏顶部「＋ 分组」创建';
      box.appendChild(d);
    } else if (!pool.length) {
      const d = document.createElement('div');
      d.className = 'set-empty';
      d.textContent = '无匹配结果';
      box.appendChild(d);
    }
    pool.slice((_gp.page - 1) * GP_PAGE, _gp.page * GP_PAGE).forEach(g => {
      const row = document.createElement('label');
      row.className = 'set-row';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = _gp.selected.has(g);
      cb.onchange = () => { cb.checked ? _gp.selected.add(g) : _gp.selected.delete(g); };
      const nm = document.createElement('span');   // 与侧边栏树节点一致：图标在左、名称在右
      nm.className = 'gp-row-name';
      nm.textContent = g;
      row.append(cb, folderIcon(), nm);
      box.appendChild(row);
    });
    renderPager('gp-pager', _gp.page, pages, pool.length,
                pg => { _gp.page = pg; renderGroupPick(); });
  }

  $('gp-search').addEventListener('input', () => {
    _gp.q = $('gp-search').value;
    _gp.page = 1;
    renderGroupPick();
  });

  $('gp-yes').onclick = async () => {
    const h = _gpHost;
    if (!h) return;
    const groups = GROUPS.filter(g => _gp.selected.has(g));   // 按 GROUPS 序稳定输出
    $('grp-pick-overlay').classList.add('hidden');
    await patchHost(h, { groups });        // base 自带 fav/其余字段，凭据沿用
  };

  // ---------- 分组成员批量管理：添加（未入组的）/ 移除（组内的），搜索 + 分页 + 多选 ----------
  let _hp = null;                          // { group, mode, selected:Set, q, page }
  const HP_PAGE = 20;

  function openHostPicker(group, mode) {
    _hp = { group, mode, selected: new Set(), q: '', page: 1 };
    $('hp-title').textContent = mode === 'add'
        ? '添加主机到「' + group + '」' : '从「' + group + '」移除主机';
    $('hp-search').value = '';
    $('host-pick-overlay').classList.remove('hidden');
    renderHostPicker();
    setTimeout(() => $('hp-search').focus(), 0);
  }

  function renderHostPicker() {
    const { group, mode, q } = _hp;
    const kw = q.trim().toLowerCase();
    let pool = mode === 'add'
        ? HOSTS.filter(h => !(h.groups || []).includes(group))     // 添加：隐藏已入组的
        : HOSTS.filter(h => (h.groups || []).includes(group));     // 移除：只显示组内的
    if (kw) pool = pool.filter(h => [h.name, h.host, h.username, h.remark]   // 与设置-主机管理同字段
        .some(v => (v || '').toLowerCase().includes(kw)));
    const pages = Math.max(1, Math.ceil(pool.length / HP_PAGE));
    if (_hp.page > pages) _hp.page = pages;
    const box = $('hp-list');
    box.textContent = '';
    if (!pool.length) {
      const d = document.createElement('div');
      d.className = 'set-empty';
      d.textContent = kw ? '无匹配结果'
          : (mode === 'add' ? '没有可添加的主机' : '分组内没有主机');
      box.appendChild(d);
    }
    // 行样式与设置-主机管理一致：名称 + 用户@IP:端口 · 备注
    pool.slice((_hp.page - 1) * HP_PAGE, _hp.page * HP_PAGE).forEach(h => {
      const row = document.createElement('label');
      row.className = 'set-row';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = _hp.selected.has(h.id);
      cb.onchange = () => { cb.checked ? _hp.selected.add(h.id) : _hp.selected.delete(h.id); };
      const main = document.createElement('div');
      main.className = 'sr-main';
      const n1 = document.createElement('div');
      n1.textContent = h.name;
      const n2 = document.createElement('div');
      n2.className = 'sr-sub';
      n2.textContent = h.username + '@' + h.host + ':' + h.port +
                       (h.remark ? ' · ' + h.remark : '');
      main.append(n1, n2);
      row.append(cb, main);
      box.appendChild(row);
    });
    renderPager('hp-pager', _hp.page, pages, pool.length,
                pg => { _hp.page = pg; renderHostPicker(); });
  }

  $('hp-search').addEventListener('input', () => {
    _hp.q = $('hp-search').value;
    _hp.page = 1;
    renderHostPicker();
  });

  $('hp-yes').onclick = async () => {
    const { group, mode, selected } = _hp;
    $('host-pick-overlay').classList.add('hidden');
    if (!selected.size) return;
    const targets = HOSTS.filter(h => selected.has(h.id));
    try {
      for (const h of targets) {                 // 顺序执行、失败即停：不留部分成功的静默状态
        const groups = mode === 'add'
            ? [...(h.groups || []), group].filter((g, i, a) => a.indexOf(g) === i)
            : (h.groups || []).filter(g => g !== group);
        await api('/api/hosts/' + h.id, {
          method: 'PUT', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            name: h.name, host: h.host, port: h.port, username: h.username,
            trust: h.trust, remark: h.remark || '', groups, fav: !!h.fav,
          }),                                   // 各自带 base 字段，凭据沿用
        });
      }
      loadHosts();
    } catch (er) {
      toast(er.message, true);
      loadHosts();                          // 已生效的部分如实刷新展示
    }
  };

  async function patchHost(h, patch) {      // 右键菜单的轻量变更（分组/收藏），凭据留空=沿用
    try {
      await api('/api/hosts/' + h.id, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(Object.assign({
          name: h.name, host: h.host, port: h.port, username: h.username,
          trust: h.trust, remark: h.remark || '', groups: h.groups || [],
          fav: !!h.fav,                        // 后端全量替换语义：base 必须带上，否则改组会清掉收藏
        }, patch)),
      });
      loadHosts();
    } catch (e) { toast(e.message, true); }
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
    $('hf-trust').checked = host ? host.trust : true;   // 新建默认信任：资产主机本就要反复连接
    syncTrustHint();
    $('host-overlay').classList.remove('hidden');
    $('hf-name').focus();
  }

  // 不信任警示：未记录过指纹的主机在未勾选时连接会被直接拒绝
  function syncTrustHint() {
    $('hf-trust-hint').classList.toggle('hidden', $('hf-trust').checked);
  }
  $('hf-trust').addEventListener('change', syncTrustHint);

  $('host-form').addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const id = $('host-form').dataset.id;
    const btn = $('host-submit');
    btn.disabled = true;
    try {
      if (!validHostAddr($('hf-host').value)) {         // 提交前拦截，不发无效请求
        $('hf-host')._markInvalid(true);
        $('hf-host').focus();
        toast('主机地址不合法（需为合法 IP 或域名）', true);
        return;                                         // finally 恢复按钮
      }
      if (syncNameErr()) {                              // 名称冲突：同样拦截 + toast
        $('hf-name').focus();
        toast('同名主机已存在', true);
        return;
      }
      const cur = HOSTS.find(x => x.id === id);   // 编辑时沿用分组/收藏（表单不含这两项）
      const body = {
        name: $('hf-name').value, host: $('hf-host').value, port: $('hf-port').value,
        username: $('hf-user').value, password: $('hf-pass').value,
        key: $('hf-key').value, key_passphrase: $('hf-keypass').value,
        trust: $('hf-trust').checked, remark: $('hf-remark').value,
        groups: cur ? (cur.groups || []) : [], fav: !!(cur && cur.fav),
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
    if (!validHostAddr($('mf-host').value)) {
      $('mf-host')._markInvalid(true);
      $('mf-host').focus();
      toast('主机地址不合法（需为合法 IP 或域名）', true);
      return;
    }
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
      if (ev && ev.code === 4403) {          // Origin 校验拒绝（跨站访问/代理改写头）
        s.status = 'off';
        setTabStatus(s);
        toast('WebSocket 被拒绝：来源校验失败（Origin 不匹配）', true);
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
    if (!e.target.closest('#host-ctx-menu')) hideHostCtx();
  });
  window.addEventListener('blur', hideCtxMenu);
  window.addEventListener('blur', hideHostCtx);
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
      } catch (e) { showInvalidList(e.status === 409 ? '会话已断开' :
                                    e.status === 403 ? '权限不足' : '无效路径'); }  // 实时：立即反馈，输入框保持原样
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

  function showInvalidPath(text) {           // 回车/失焦后仍无效：路径标红 + 列表提示，仅此而已
    $('fp-path').classList.add('invalid');
    showInvalidList(text);
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
      if (!res.ok) {                       // 会话死亡/权限等：解析后端 detail，任务列表可见原因
        let msg = 'HTTP ' + res.status;
        try { msg = (await res.json()).detail || msg; } catch (e) {}
        throw new Error(msg);
      }
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
          const np = await dlgPrompt('重置「' + u.user + '」的密码', '新密码（至少 8 位）', 'password',
                                     null, v => (v || '').length >= 8 ? '' : '密码至少 8 位');
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

  // ---------- 通用输入弹窗（可选实时校验） ----------
  let ptResolve = null;
  let _ptValidate = null;                   // (value) => 错误文案 | ''（空=通过）
  function dlgPrompt(title, placeholder, type, defval, validate) {
    return new Promise((resolve) => {
      ptResolve = resolve;
      _ptValidate = validate || null;
      $('pt-title').textContent = title || '输入';
      const inp = $('pt-input');
      inp.type = type || 'text';
      inp.value = defval || '';
      inp.placeholder = placeholder || '';
      inp.classList.remove('invalid');
      $('pt-err').classList.add('hidden');
      $('prompt-overlay').classList.remove('hidden');
      setTimeout(() => { inp.focus(); if (defval) inp.select(); }, 0);
    });
  }
  function ptErr() {                        // 刷新红框红字，返回当前错误文案
    const inp = $('pt-input');
    const err = _ptValidate ? _ptValidate(inp.value) : '';
    inp.classList.toggle('invalid', !!err);
    $('pt-err').textContent = err || '';
    $('pt-err').classList.toggle('hidden', !err);
    return err;
  }
  $('pt-input').addEventListener('input', () => { if (_ptValidate) ptErr(); });
  $('pt-yes').onclick = () => { if (ptErr()) return; ptDone($('pt-input').value.trim() || null); };
  $('pt-no').onclick = () => ptDone(null);
  $('pt-input').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { if (ptErr()) return; ptDone($('pt-input').value.trim() || null); }
    if (e.key === 'Escape') ptDone(null);
  });
  function ptDone(v) {
    $('prompt-overlay').classList.add('hidden');
    if (ptResolve) { ptResolve(v); ptResolve = null; }
  }
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

from core import VERSION as _VERSION

HTML = HTML.replace("__VERSION__", _VERSION)

