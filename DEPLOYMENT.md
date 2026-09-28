# 部署与服务管理

## Windows 后台服务

在项目目录运行以下命令。先安装 Node.js 和包含 `pythonw.exe` 的 Python，再创建项目虚拟环境：

```powershell
npm.cmd ci
python -m venv .venv
& ./.venv/Scripts/python.exe -m pip install -r requirements.txt
npm.cmd run deploy:windows
```

安装脚本注册当前用户的计划任务 `toSub2 Persistent Server`，由 `scripts/windows-daemon.py` 启动无窗口 Node.js 服务。默认控制台为 `http://127.0.0.1:4399/`；用户登录后自动启动，异常退出后自动恢复。安装目录写入本地配置，移动目录前请停止旧任务，再重新安装。

- 本地部署配置：`%LOCALAPPDATA%/toSub2/deployment.json`。
- 服务日志：`%LOCALAPPDATA%/toSub2/logs`。
- Windows 加密凭据：`%LOCALAPPDATA%/toSub2/credentials`，由当前用户 DPAPI 保护。
- 账号任务及授权输出默认位于项目的 `tmp/chatgpt-onboarding-console`。

这些目录包含运行状态或账号资料，不应提交到 Git。原始 HAR 抓包也不应上传。

## 查看、停止与启动

```powershell
$taskName = 'toSub2 Persistent Server'
Get-ScheduledTask -TaskName $taskName
Get-ScheduledTaskInfo -TaskName $taskName

# 等待当前账号操作结束后，停止服务及其自动恢复。
Disable-ScheduledTask -TaskName $taskName
Stop-ScheduledTask -TaskName $taskName

# 启动服务并恢复自动运行。
Enable-ScheduledTask -TaskName $taskName
Start-ScheduledTask -TaskName $taskName

# 查看日志，按 Ctrl+C 结束查看。
Get-Content -LiteralPath (Join-Path $env:LOCALAPPDATA 'toSub2/logs/console-error.log') -Tail 30 -Wait
```

更新代码和依赖后，按“停止”再“启动”的顺序重启，并刷新浏览器页面。重置 2FA 等安全操作执行中请先等待其完成，再重启服务。

同一端口只运行一个服务。已安装计划任务时，不要同时启动 `npm run dev` 或另一个 PM2 实例。脚本发现同名任务或占用端口时会拒绝重复安装。

## 前台运行或 PM2

调试时可使用 `npm run dev`，关闭对应终端即结束前台服务。项目也保留 `ecosystem.config.cjs` 和 `daemon:start / daemon:restart / daemon:stop / daemon:logs` 脚本；使用 PM2 时需自行安装、配置 PM2，并避免与 Windows 计划任务重复运行。

## 验证

```powershell
$env:TOSUB2_PYTHON = (Resolve-Path -LiteralPath '.venv/Scripts/python.exe').Path
npm.cmd run check
# 单独运行 2FA、退出设备和账号资料专项测试：
npm.cmd run check:2fa
```

测试使用虚构账号和本机模拟 HTTP 服务。Windows 集成测试使用隔离的临时 DPAPI 凭据目录，不修改真实账号。测试通过不代表已经在真实 ChatGPT 账号上执行重置或确认所有设备退出。
