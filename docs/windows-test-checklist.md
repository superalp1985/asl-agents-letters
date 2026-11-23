# Windows 测试候选验收

这是开发测试包，不是正式签名发布。不需要先开云机；先用一台 Windows 做第 1、2 节。不要把测试包覆盖到现有安装目录，也不要用真实身份、模型密钥或收件目录做第一次测试。

## 1. 解包和首次启动

用普通 PowerShell（不需要管理员权限）。解包目录必须是用户可控制的本地 NTFS 目录；下面要求输入尚不存在的绝对路径。测试资料与程序分开，尽量让路径包含空格。

```powershell
$zip = Read-Host '测试 ZIP 的完整路径'
$install = Read-Host '新的解包目录完整路径'
$profile = Read-Host '新的测试数据目录完整路径'
$ErrorActionPreference = 'Stop'
if ((Test-Path -LiteralPath $install) -or (Test-Path -LiteralPath $profile)) {
    throw '第一次验收请使用两个尚不存在的目录。'
}
Expand-Archive -LiteralPath $zip -DestinationPath $install
foreach ($entry in Get-Content -LiteralPath (Join-Path $install 'SHA256SUMS.txt')) {
    $hash, $name = $entry -split '  ', 2
    if ((Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $install $name)).Hash -ne $hash) {
        throw "包内文件散列不一致：$name"
    }
}
Set-Location -LiteralPath $install
.\Start-ASL.ps1 -DataDirectory $profile
```

包内清单检查是否完整，不能替代正式发布签名。不要直接双击 `asl-ui.exe`。如果只是关闭了窗口，先从托盘恢复；如果已从托盘退出界面而后台仍在运行，执行：

```powershell
.\Start-ASL.ps1 -ViewerOnly -DataDirectory $profile
```

## 2. 一台机器先验收

| 顺序 | 操作 | 通过条件 |
| --- | --- | --- |
| 1 | 首次选择中文，再从设置切到 English | 中文默认；两个界面的控件和状态可读；重新打开后语言保留 |
| 2 | 查看启动确认，保持「不接收」 | 当前直连／群组模式显示正确；保留设置不打开接收或回答 |
| 3 | 查看 12 个头像并选择一个；关闭小剧场动画 | 头像和预览正常，未另行授权不公开；关闭动画后场景静止 |
| 4 | 关闭窗口、通过托盘恢复，再通过托盘菜单退出 | 关闭时按设置隐藏；托盘退出只关闭观察窗；`-ViewerOnly` 恢复观察窗，不重启 Core |
| 5 | 用测试文件夹试建、撤销共享和收件授权 | 只影响选定目录；文件范围、收件与发送的「每次询问」分别可查；撤销后不会恢复旧授权 |
| 6 | 调整窗口大小，并在可用的两个 DPI 下查看概览、授权、群组和传输 | 关键按钮可达，长路径不遮挡其他控件；九个导航页均可打开 |

遇到问题先记下步骤编号、显示文案、语言、DPI、实际与预期结果。截图不要包含原资料路径、可识别的 PeerId、凭据或私人文件名。

## 3. 后续网络与宿主验证

- **同机群组：** 已有 Messages 和 File 管理员夹具记录。需要补真实容器双来源时，在仓库根目录用提升权限的 PowerShell 执行 `.\scripts\run-appcontainer-loopback-test.ps1 -Scenario MultiSource -DevRoot <开发根目录>`。该脚本使用临时资料和合成链证明，不等于公网；普通桌面验收不需要运行它。参见[群房间](group-rooms.md)。
- **真实宿主：** 先在独立测试资料上按 [stdio MCP](05-agent-gui.md#7-stdio-mcp-接入) 配置授权。确认宿主初始化、工具列表、空闲时主动通知、收件授权与逐文件批准、断线恢复不重复发送。只验证本地工具发现不算验证收到远端来信。
- **跨机与升级：** 先准备第二台 Windows、经核验的链与设备注册配置、真实可达且获准的入口。分别记录配对、结构化来信、获准收件和单边升级；两台机器的资料目录与宿主密钥分开。当前普通便携包没有开箱即用的链部署及入口，群组仍限同机回环，不要求在两台机器上拉群通过。设备链上注册和撤销传播、生产公网群组、更新启动后的回滚、全部 Offer 与推送回放、20 节点 / 72 小时验收均未关闭。

只有第 1、2 节需要现在手测。请保留测试资料目录，下一轮沿用同一资料，便于检查设置与身份是否保留。
