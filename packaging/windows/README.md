# A信 ASL Windows 便携包

解压到本地 NTFS 目录。安装目录及其上级路径必须防止不受信任的账户修改或替换安装文件；不要在其他账户可写的共享目录运行。脚本不会替你配置或审核 ACL。保留包内的 `active-release.txt`。打开 PowerShell，在解压目录下执行：

```powershell
.\Start-ASL.ps1 -DataDirectory 'E:\Your-Asl-Data'
```

请把示例路径替换为实际数据目录。现有资料和迁移后的资料都从指定目录加载。
不要直接双击 `asl-ui.exe`：它不会自动选择资料目录。
如果同一资料的后台已运行，只打开当前版本的界面：

```powershell
.\Start-ASL.ps1 -ViewerOnly -DataDirectory 'E:\Your-Asl-Data'
```

此模式不启动或重启后台。

需要登录后后台运行时，在解压后的目录执行：

```powershell
.\Set-ASLLogin.ps1 -Enable -DataDirectory 'E:\Your-Asl-Data'
.\Set-ASLLogin.ps1
```

`.\Set-ASLLogin.ps1 -Disable` 移除当前用户的登录启动项。

`SHA256SUMS.txt` 记录包内文件的散列。发布身份由独立签名清单及可信发布公钥核验。

正式发行包还必须在 ZIP 封包前完成全部 EXE 的 Authenticode 签名，并提供独立的 Ed25519 更新清单、64 字节签名和 32 字节公钥。构建、旧版复验和密钥保管步骤见 `RELEASE.md`；不要使用 PFX 密码参数或把发布私钥放进解压目录。

把安装根目录的 `asl.exe` 设为 MCP 宿主命令，参数为 `mcp --home <本机数据目录>`。同一安装目录内更新后保持这个路径；请重连宿主以启用新版。打包不会默认打开 MCP，也不授予查询或文件权限。授权与配置见源码仓库的 `docs/05-agent-gui.md`。

离线更新使用 PowerShell 7。先正常退出 ASL。在独立核实发布公钥后，只需固定一次：

```powershell
.\Update-ASL.ps1 -PinReleaseKey '<已核实的公钥文件>'
.\Update-ASL.ps1 -Package '<更新 ZIP>' -Manifest '<签名清单 JSON>' -Signature '<签名文件>'
```

验证成功后，下次运行 `Start-ASL.ps1` 使用新版本。此前版本保留在本地。预检失败不会启用新版；如果新版已启动并迁移数据库，不要直接用旧版打开它。

根目录的启动脚本、验签器、Agent 入口及固定公钥属于引导层，普通更新不替换它们。当前 ZIP 布局为 v2，签名清单仍为 v1。此前的 v1 布局开发包没有 Agent 入口，不能原地更新到 v2；请在核验全包后解压到新的受保护安装目录，复用数据目录，并重新配置宿主与登录启动。不要覆盖旧的安装目录。

# ASL for Windows

Extract the archive to a local NTFS directory protected from writes or
replacement by untrusted accounts, including through its parent directories.
Do not run from a shared-writable directory. The scripts do not configure or
audit ACLs. Keep the bundled `active-release.txt`. In PowerShell, run
`.\Start-ASL.ps1 -DataDirectory '<absolute data directory>'` from the extracted
directory. Use the same data directory to reopen an existing profile.
Do not double-click `asl-ui.exe`; it does not automatically select a profile.
When Core is already running for that profile, use
`.\Start-ASL.ps1 -ViewerOnly -DataDirectory '<absolute data directory>'`
to reopen the active version's viewer without restarting Core.

`.\Set-ASLLogin.ps1 -Enable -DataDirectory '<absolute data directory>'` registers
background startup for the current Windows user. Running it without arguments
shows the current status. `.\Set-ASLLogin.ps1 -Disable` removes the startup entry.

`SHA256SUMS.txt` lists the file digests. Verify the separate release manifest
signature against your trusted release key to authenticate the package.

An official distribution also requires Authenticode on every EXE before ZIP
creation plus an independent Ed25519 manifest, 64-byte signature, and 32-byte
public key. See `RELEASE.md`. Do not place a release private key in the
extracted directory.

Configure the root `asl.exe` as the MCP host command with arguments
`mcp --home <absolute data directory>`. The command path stays the same across
updates within that installation; reconnect the host to use the new release.
Packaging does not enable MCP or grant permission to query or transfer files.

For offline updates, close ASL first and run the updater in PowerShell 7.
Pin an independently verified release key once with
`.\Update-ASL.ps1 -PinReleaseKey '<32-byte public key file>'`.
Apply an update with `.\Update-ASL.ps1 -Package '<ZIP>' -Manifest '<manifest JSON>' -Signature '<signature file>'`.
The next `Start-ASL.ps1` uses the new release. The previous release stays on
disk, and a failed preflight leaves it active. Do not reopen migrated data with
an older binary after the new release has started.

The root launchers, verifier and pinned key are not replaced by ordinary updates.
The ZIP uses layout v2; the signed manifest remains v1. Older v1-layout
development packages have no agent entry and cannot update in place to v2.
Independently authenticate the new distribution, extract it into a new protected
directory, keep your separate data directory, and update the host and login
startup configuration. Do not overwrite the existing installation directory.
