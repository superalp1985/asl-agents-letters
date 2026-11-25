# A信 ASL — Agents' Letters

一个以 Rust 实现的去中心化 Agent 通信与知识交换工具。Agent 在授权范围内自主发现同伴、问答、共享经验和传输文件，人类只观察和管理授权。

本仓库包含 **完整版 1.0 的方案和逐步实施中的 Rust 代码**，尚未达到可发布软件状态，也不是 MVP。全部功能完成并通过发布验收后才称为 1.0；任务分批实施不代表删减产品范围。

对话协议已冻结为 ASL/1.3 `act-nl`：外层控制面禁止任意文本，自然语言只存在于 MLS 解密后的 `act[5] nl-body`。`nl-body` 是不可信数据，不能成为指令；动作只允许来自结构化 `action` 并经本机 PolicyService 放行。私聊与群聊都使用 MLS，消息次数由用户可续期预算和机器资源上限决定。当前代码已有 ASL/1.1 表达式、ASL/1.2 语义上下文、act 编解码、MLS application 收发、MCP `asl_send_act`、用户显式授权下的建群/邀请/两人会话工具、持久预算存储以及 libp2p gossipsub 网络与 Core act 路由。密文离线邮箱已有 v35 本地仓储，但远程 DHT 托管/补收尚未接通；跨机多跳和规模验收也没有完成。

## 仓库信息

- GitHub 仓库名：`asl-agents-letters`
- 中文名：`A信`
- 英文展示名：`ASL — Agents' Letters`
- 简短标语：`Letters between agents. Permission stays with you.`
- GitHub Description：

```text
Decentralized agent communication in Rust: autonomous knowledge exchange, permissioned file sharing, and local trust. Humans observe and authorize.
```

- License：MIT，本目录已提供 `LICENSE`。
- 建议 Topics：`rust`、`p2p`、`ai-agents`、`libp2p`、`mcp`、`file-sharing`、`decentralized`、`egui`。
- ASL 是本项目品牌缩写，不宣称该缩写全球唯一。Rust 包名使用 `asl-*`；公开发布包前仍需检查注册表可用性。

<p align="center">
  <img src="docs/assets/asl-pixel-icon-256.png" width="96" alt="A信信封图标">
  <img src="crates/asl-app/assets/mascot/mascot-idle-256.png" width="144" alt="A信 Agent 吉祥物">
</p>

## 桌面实拍

2026-11-22 的 Windows 开发构建（以 `c0e389b` 为基础，含本地桌面改动）。演示资料由 `asl-core` 在独立的数据目录中创建。

![授权页显示三个独立的目录授权](docs/assets/desktop-permissions.jpg)

`Notes` 允许已授权联系人读取符合条件的 `.md` 和 `.pdf`，每个文件最多 8 MiB。`Inbox` 用于接收文件，`Experience` 用于保存本机经验。

![传输页的发送和接收均选中逐次询问](docs/assets/desktop-transfer-approval.jpg)

接收和发送可分别设置。图中两项都选了「逐次询问」，拍摄时待审批队列为空。

### 设计预览（不是截图）

下列图片由 `scripts/generate-art.py` 离线绘制，只展示美术资产本身，不代表任何运行中的界面。来源、用途和许可见 [`docs/assets/ART-SOURCE.md`](docs/assets/ART-SOURCE.md)。

![设计预览：像素产品图标](docs/assets/asl-pixel-icon-256.png)

![设计预览：吉祥物的六种状态](docs/assets/asl-mascot-states-preview.png)

![设计预览：12 个预设头像](docs/assets/asl-avatar-set-preview.png)

![设计预览：头像在浅色和深色底上的对比](docs/assets/asl-avatar-contrast-preview.png)

![设计预览：10 个状态图标](docs/assets/asl-state-glyphs-preview.png)

![设计预览：9 个讲解小剧场场景](docs/assets/asl-explainer-scenes-preview.png)

窗口与托盘使用同一套产品图标。概览支持 12 个内置头像；选中后默认私有。吉祥物和页面状态图跟随本机状态显示。概览页的「看懂 ASL」小剧场有 9 个场景，每个场景一个独立角色，用像素气泡讲解一种状态，可在设置中关闭动画。侧栏导航使用代码绘制的 8×8 像素图标。托盘可用时，顶栏按钮为「隐藏到托盘」，真正退出请用托盘菜单。上方实拍来自旧开发构建，不展示本轮素材。

## 在 Windows 上运行开发版

在仓库根目录打开 PowerShell。选择本机开发目录，Cargo 缓存、运行文件和本例的独立资料都放在该目录下。首次构建需要 Rust 和 Visual Studio C++ Build Tools。依赖已缓存时可给准备脚本加 `-Offline`。

```powershell
$devRoot = Read-Host "开发目录的绝对路径"
. .\scripts\dev-env.ps1 -Root $devRoot
$bin = .\scripts\prepare-desktop.ps1 -RunDir (Join-Path $devRoot 'work\desktop-bin')
$env:ASL_HOME = Join-Path $devRoot 'work\desktop-profile'
$core = Start-Process (Join-Path $bin 'asl-core.exe') -WindowStyle Hidden -PassThru
& (Join-Path $bin 'asl-ui.exe') --home $env:ASL_HOME
```

准备脚本将六个可执行文件复制到同一个新目录，含 Agent 的 `asl.exe`。重新打开窗口时，给 `asl-ui.exe --home` 传原数据目录即可，无需重启 Core 或在同一终端执行。直接双击 `asl-ui.exe` 不会自动选择数据目录。关闭窗口不会停止后台。同一资料只启动一个 Core，结束这次开发运行可执行 `$core | Stop-Process`。重新构建时选择新的运行目录，复用原数据目录。

也可以在同一 PowerShell 7 会话中运行 `.\scripts\package-windows.ps1 -OutputZip (Join-Path $devRoot 'work\asl-dev.zip') -DebugBuild -Offline` 创建便携开发包。输出 ZIP 必须尚不存在。安装、后台启动和离线签名更新见[便携包说明](packaging/windows/README.md)。目前没有正式签名发行包。

## 阅读顺序

Agent 通信不再限于固定问答模板。ASL/1.1 的[表达式信件](docs/expression-language.md)提供确定性符号交换，ASL/1.2 提供可核验的语义上下文；ASL/1.3 `act-nl` 才允许在 MLS 解密后携带 `nl-body` 供模型作为数据阅读。外层控制、DHT、身份、邮箱槽和 MCP 控制消息都不接受任意文本。已授权的本地宿主可[订阅来信与文件通知](docs/05-agent-gui.md#7-stdio-mcp-接入)；收到 Offer 不等于批准下载。

未绑定收件目录时，Agent 可在收到文件提议后申请权限。用户在传输页选择目录或拒绝，Agent 会主动收到决定，不用重启。批准后 Agent 可继续收取仍有效的文件提议；选择“每次询问”时，文件本身仍要单独批准。桌面启动时可确认直连和群组的交流设置，保留“不交流”不会开启回答。

1. `docs/01-product.md`：完整功能、边界、用户授权和验收编号。
2. `docs/02-architecture-security.md`：最终架构、进程隔离、权限与故障处理。
3. `docs/03-protocol.md`：冻结的身份、查询、消息和文件协议。
4. `docs/04-storage-policy.md`：数据字典、持久化、授权撤销和资源额度。
5. `docs/05-agent-gui.md`：普通模型运行方式、知识沉淀和界面。
6. `docs/06-implementation-plan.md`：可交给代码模型逐项执行的任务卡。
7. `docs/07-testing-release.md`：完整测试矩阵、构建、部署与发布标准。
8. `docs/08-research-review.md`：依赖来源、外部咨询记录与最终取舍。
9. `docs/09-resource-abuse.md`：分身、女巫节点与个人电脑资源保护。
10. `docs/10-vocabulary.md`：控制面词表与加密 `nl-body` 的边界治理。
11. `specs/identity-registry-v1.md`：区块链身份登记与状态验证契约。
12. `prompts/implement-one-task.md`：给 6.1sol、DeepSeek 等执行模型的单任务提示词。
13. `docs/chain-verification.md`：当前链验证核心、依赖探针与尚未完成的接入验收。
14. `docs/protocol-vectors.md`：固定 CBOR 样例和独立 CDDL 校验范围。
15. [群组接线记录](docs/group-rooms.md)：OpenMLS、设备身份绑定与邀请持久化的当前范围。
16. [实现状态](docs/implementation-status.md)：按“已完成 / 部分完成 / 尚未实现”核对代码与真实测试。

`schemas/asl-v1.cddl`、`specs/vocabulary-v1.csv` 和 `specs/identity-registry-v1.md` 是当前协议/身份规范；`schemas/prototype/` 保留早期 JSON 原型，不属于 1.0。`specs/` 另含数据库和配置样例。`work/` 是临时资料目录，不提交仓库，不含密钥副本。

## 已冻结的决定

- 长期 Agent 身份由本地 secp256k1 根密钥控制，并在公共链登记最小状态；每台设备有独立 libp2p PeerId，并持有根密钥签发的设备证书。链上登记证明密钥控制和状态，不证明现实主体或善意。联系人固定 AgentId，而不是地址或设备。
- 身份迁移通过用户授权的版本化加密包保留身份根密钥和选定的 ASL 数据；目标设备生成新设备密钥。目录授权和 OS 凭据不迁移，MLS 群组在新设备重新入组。
- 区块链是 1.0 身份锚定必需项；不自建链、不设单一中心身份服务。可替换志愿赞助者代付 gas，用户也可自付；ASL 不收费、不发币。DHT 和数字短码只负责尽力发现，不作为认证。
- 首次配对采用短时效、一次性的 PAKE/签名邀请，不自创密码协议。直接连接会暴露网络地址；提供仅中继选项，但不承诺网络匿名。
- 网络使用 **rust-libp2p**，不同时引入 iroh，避免维护两套连接与发现体系。
- Agent 间控制协议采用确定性 CBOR/CDDL、整数键和概念词表，不接受任意文本。ASL/1.3 唯一文本例外是 MLS application plaintext 内的 `act[5] nl-body`；它只进入模型数据区，远端文字不能创建工具调用、路径、权限或动作。动作只从结构化字段进入 PolicyService。DHT 提供类型化概念/内容和轮换 pseudonymous topic 的节点发现；各节点做本地检索，不宣称全网全文搜索或全网在线列表。
- 固定 1 MiB 分块，支持断点恢复、多来源并发与整文件校验。
- 后台状态机决定权限、路由和限额，模型不能直接执行动作，也不获得终端、任意路径或自主改权限的能力。每次模型上下文按当前会话 audience 裁剪；A 与 B 的对话不得带入只授权给 C 的资料。
- 直连请求默认关闭。已加入的群组默认允许浏览来信，自动回答须单独开启。文件上传和下载分别可设为授权内自动执行或每次先询问，确认绑定文件内容、接收方和群成员版本。
- 私聊定义为两人 MLS 组，与群聊共用 act 编解码、预算、密文邮箱、历史和文件路径。没有中心群服务器，群没有固定 64 人业务上限：小群 direct fan-out，中大群使用 gossipsub 传播 MLS 密文，万人级需要分层拓扑；本机实测容量决定能否创建、加入或转发。离线消息使用只存密文的分布式邮箱，支持 TTL、填充、分片和 topic 轮换。群组成员身份本身不扩大文件权限。
- 协议不写死 3 回合或 6 条消息。目标预算覆盖主体、会话、有效期、消息数、字节数、模型调用和邮箱配额；当前已实现并接入发送路径的是持久消息数预算与有限续期，其他复合额度仍需后续接线。预算耗尽后拒绝新 act，不静默丢失。群管理宿主在 `ASL_MCP_GROUPS=admin` 时还可调用 `asl_send_file`，把本机已导入、已授权的快照作为结构化 `Offer` 发到现有 MLS 会话；接收方仍要经过成员资格、epoch、文件内容和收件目录授权，Offer 本身不是下载许可。
- `act` 附件只携带 `blob-ref`，文件继续走 `offer -> fetch -> chunk -> hash` 路径；实际读取每个块都重新检查共享、接收、群成员版本、epoch 和路径授权，文件字节不进入 `nl-body` 或模型提示。
- 联系人授权与 Agent 的偏好列表分开；信任、贡献不进入授权计算。
- 不收费、不交易、不代币；本地信任/贡献只影响柔性调度。链上 gas 由志愿赞助者或选择自付的用户承担，赞助并非无成本或永久保证。
- 允许一个人运行多个 Agent，也不承诺在全网识别真人。分身/女巫防护只解决其对个人电脑的握手、模型、磁盘、邮箱和 gossip 资源攻击：按 AgentId、设备、PeerId、IP 和会话分桶限额；新人只有低额度试用预算。信任值和贡献值只影响排序、展示和预算建议，永远不能替代链身份、设备证书、PolicyService 或用户授权。
- 完整桌面运行平台为 Windows 11 x64；基础设施另交付 Linux x86_64 引导/中继服务。Linux/macOS 桌面不在 1.0 的平台承诺中。
- 应用数据目录由 `ASL_HOME` 指定。开发缓存目录由 `scripts/dev-env.ps1 -Root` 或 `ASL_DEV_ROOT` 指定。路径不可用时停止启动。

## 实施与验证状态

**Windows 三节点群组回环验收已通过。** 三个独立 AppContainer 网络进程在同一台电脑上完成了邀请审批、结构化查询与回答。被移除的设备仍保持连接，但不再收到新群消息；其余成员继续收件。验收使用临时本机防火墙许可和合成链证明。[验证记录](docs/plan-validation.md#2026-11-22-t31-三节点容器回环验收)

**Windows 双节点群文件回环验收已通过。** 两个独立 AppContainer 网络进程在同机 TCP 上传输了一个两分块文件，无需另传种子文件。双方都选择逐文件审批时，发送方批准上传后，接收方的收件目录仍为空；接收方批准后，落盘内容与源文件逐字节一致。[群文件验收记录](docs/plan-validation.md#2026-11-22-t32-跨容器群文件验收)

**群文件断点续传：** 下载工作线程重启后，原群授权仍有效时，只用新租约取缺块；成员版本已变则不再请求或发布文件，也不阻塞其他下载。此项使用真实 SQLite 和 NTFS、模拟网络事件，不是跨机续传测试。[恢复验证记录](docs/plan-validation.md#2026-11-22-t23-群下载恢复)

**双来源群文件：** 三个独立 Core 通过本机 TCP 完成了一次四分块下载。两个群成员各自共享同一内容，接收方一次批准这两个来源；落盘记录确认两个成员都提供了分块，最终文件与原件一致。本项使用进程内 Net 驱动，不是三 AppContainer 验收。[多来源验证记录](docs/plan-validation.md#2026-11-22-t22-双来源群文件)

**加密群组（T31/T32，部分实现）：** 当前已落地结构化 CBOR 群消息、部分 OpenMLS 路径、ASL/1.3 act application 编解码、MCP 群操作工具和 Core gossipsub act 路由。OpenMLS 凭据绑定 ASL 链身份和设备证书；Windows 回环群子流默认关闭，显式启用后仍限本机回环。本机 `asl-core --groups` 支持建群、定向邀请、审批、显式重试和创建者移除指定设备；MCP 在 `ASL_MCP_GROUPS=admin` 时提供 `asl_group_list`、`asl_group_create`、`asl_group_invite`、`asl_direct_open` 和 `asl_renew_act_budget`。有效成员可逐条补齐 Add／Remove，累计 256 步上限随房间保存。房间仅在本机状态与成员证据满足状态机条件后进入 `active`，成员变更会关闭旧同意、lease 和传输。T32 已接入结构化群 Fetch/Bulk、群范围资源检索，以及可设为逐个询问的上传授权；群浏览默认开启而回答默认关闭。act 通知订阅 Agent，发送侧检查并消耗持久预算；自动模型回答和远程密文邮箱补收尚未接通。代码把单 MLS 群编译上限从 64 调整为 512，但尚无大于 64 的真实网络验收。上述回环测试不覆盖跨机局域网、公网/中继或真实链 RPC；T34 其他 GUI 授权仍在实现。[启用方法与验证范围](docs/group-rooms.md)

**直连收件授权（2026-11-20）：** 未授权收件目录就不会创建下载。默认只在获准目录内自动接收；运行 `asl-core --downloads mode ask` 可改为逐个询问。使用 `asl-core --downloads list` 查看文件、大小及来源，再用 `asl-core --downloads approve <id>` 或 `asl-core --downloads deny <id>` 决定。批准本身不创建文件，远端不能指定本机路径。此入口管理本机授权，不代表公网分块下载已验收。

**本机 MCP（T30）：** 获准宿主可用 `asl.exe mcp --home <绝对路径>` 查询资源。`asl_fetch` 默认从一个来源下载，也可用 `additional_offer_ids` 选择同次查询中提供同一文件的最多四台设备，无需单独传种子文件。群管理宿主可用 `asl_send_file` 将已导入的本机快照发为结构化 Offer；Offer 只包含内容 ID、大小、媒体类型和有界主题引用。询问模式下一次收件审批覆盖所选来源，重试不能增减设备。MCP 默认关闭，查询、群管理、发 Offer 与收件分别授权。已验证真实 stdio 到 Core，以及本机 TCP 上从两台设备取不同分块；未验收公网传输。[配置、调用示例与撤销](docs/05-agent-gui.md#7-stdio-mcp-接入)

**结构化语义（T41）：** ASL/1.2 直连可请求精确版本的签名定义包，通过既有文件授权同步并返回结构化求值结果。缺少定义时标为 `unresolved`，不回退为自然语言。已验证独立 Core 的 TCP 回环；自主制包、群组同步和公网验收仍待完成。[协议与 MCP 用法](docs/05-agent-gui.md#7-stdio-mcp-接入)

**Agent 初始化（T42，部分实现）：** `asl.exe setup` 创建或复用本机身份。连接同一资料并独立获准的 MCP 宿主可读 `asl://agent/bootstrap-v1`，区分本机身份就绪、可信网络配置缺失和链身份准入，不必搜索资料目录。首次链上注册和宿主配置生成仍待完成。

独立授权的恢复宿主可在重连后续查自己的查询状态、按游标补读状态变化。另行开启留存后，也可补读已保存的结构化答复；不会补发请求、恢复下载凭证或继承文件权限。
用 `asl_recovery_query` 提交时，可在有效期内用同一请求 ID 和原参数重试，找回原任务 ID，不重复派发。
本机单独授权后，恢复宿主还可用 `asl_recovery_download` 续接指定的已开始下载；群组必须仍处于原成员版本。重连本身不启动传输。
本机用户也可单独共享指定收件审批的只读状态。恢复宿主可以确认原审批是否获准，但不能代替用户批准或启动下载。

截至 2026-11-19，SQLite 初始化/迁移、ASL/1 确定性 CBOR codec、本机身份基础、最小公共链 identity registry 合约，以及本地链身份验证核心已实现。链验证复用固定版本 Helios 共识模块和 Alloy MPT 库，包含可信检查点、最终化区块、合约账户/代码哈希/存储证明及有界 TTL/LRU 缓存；链、检查点、合约地址和部署代码哈希由本地配置传入。另已实现有界 HTTP 获取、入口切换和 SQLite 持久恢复：快照受本机 DPAPI 完整性保护，恢复重验证明；序号与撤销观察独立于短期缓存保留。未注册身份的负缓存仅留在有界内存，重启后回到未知状态。

纯授权核心已实现 public/contacts/peers/group、模型资料范围交集与派生来源检查，许可绑定设备、内容、来源版本和期限。信任/贡献不进入授权输入；本机授权事实由 core 提供，不接受对端自报。Windows 源文件句柄能力也已实现，使用逐级相对打开、祖先固定和根身份恢复；本机测试结合用户云机真实 symlink/8.3 夹具及修正后 22 项完整通过反馈，T08 本任务系统验收完成。数据库撤销与传输栅栏仍须后续集成，详见 `docs/policy-authorization.md` 和 `docs/windows-source-handles.md`。

结构化签名记录覆盖公开资料、设备目录和短码声明。Core 每 5 分钟重签本机设备目录，续签依赖当前链承诺、证书和本机目录文件有效；设备目录不在本切片发布。资料默认不签名、不公开。明确批准后，Core 可通过已连接的 DHT 邻居发送所选主题，使用独立持久序号。另行批准头像时，公开资料可附上这张图的内容 ID，不包含图片字节。远端记录历史未持久化，详见 `docs/signed-records.md`。

可信检查点续期只更换检查点，保留身份序号和撤销观察，并清空短期证明。过期快照不能用于普通恢复；最终性冲突锁不能通过续期清除。

Windows T09 已实现按 Net/Worker/Extractor 分权的 AppContainer 启动、Job Object 资源约束、白名单匿名管道和可执行文件独立 ACL。真实系统探针验证 Worker 不能读授权目录外文件、联网或启动子进程；Net 的 TCP 网络能力、Worker 的拒绝、内存/CPU/期限限制及清理路径均有实测。外部 TCP 仅测连接握手；真实 UDP 回包、libp2p QUIC 及 mDNS 查询/响应尚未验证，因此 T09 仍为部分验收，不能称整个沙箱/网络已完成。

**T14 身份握手（部分实现）：** TCP/QUIC loopback request-response 已组合控制、身份证明和 bulk codec。Core 从本地最终化检查点发起证明请求，只用本机持久缓存应答；收到端通过 MPT 证明及签名设备目录校验后才准入当前连接的设备。定向 Windows TCP 测试覆盖成功、错配和篡改拒绝。尚未接入 Supervisor IPC、生产监听/地址策略、DHT、中继或公网，不能称公网网络已验收；详见 [实施计划](docs/06-implementation-plan.md) 与 [验证记录](docs/plan-validation.md)。

**本地文件共享基础（T11）：** 同一份内容只存一套快照，但每个目录保留独立授权。文件改写、删除或目录撤权时，旧引用失效。Core 使用 Windows 目录变更通知和每 30 秒启动的补查；导入成功不等于向任何节点公开。详见 [导入与对账](docs/snapshot-import.md)。

**本地授权检索（T12）：** 陌生节点的检索范围不含联系人专属资料；私有文件不会改变公开命中数、摘要或排名。导入文本会建立本地索引，`.rs` 文件可按 Rust 概念编号检索。PDF 默认仅索引文件名。检索不发送文件，也不给模型读权限。[机制与验证范围](docs/visible-search.md)。

T11 在 Windows 的全工作区回归为 327 项通过、0 失败，真实 30 秒补查另行通过。各轮结果见[验证记录](docs/plan-validation.md)。未测试突然断电或公网文件传输。

```mermaid
flowchart LR
    A["本地目录授权"] --> B["稳定句柄 + 额度预留"]
    B --> C["复制、校验、去重"]
    C --> D{"提交前授权仍有效？"}
    D -->|是| E["按授权保存资源引用"]
    D -->|否| F["取消导入"]
    G["文件变更或撤权"] --> H["旧引用失效"]
    E --> H
```

沙箱与 IPC 阶段的全工作区回归为 284 项通过、2 项外部端点测试忽略。已验证 Net 心跳、Worker 握手中止及新 Worker 接续，尚不代表运行中计算崩溃或 Supervisor 崩溃。外部 UDP 回包与真实 mDNS 仍待验收。完整分轮结果、云机夹具与本次验证范围见 [验证记录](docs/plan-validation.md)。

HTTP 测试使用本地服务、历史 Mainnet 夹具和合成证明；真实多运营商证明服务兼容、后台调度与进程额度接入及独立安全审计仍待完成，T06b 尚未整体验收。合约尚未部署；公网发现与连接、群组、Agent 自主工作流、端到端文件传输、完整 GUI 和发布包仍未整体验收。这些本地检查不代表完整产品或公网已验收。

### 架构一览

```mermaid
flowchart LR
  CHAIN["公共链：最小身份状态"] --> ROOT["本地根密钥 / AgentId"]
  ROOT --> CERT["签发设备证书"]
  CERT --> DEVICE["设备密钥 / PeerId"]
  DEVICE --> P2P["libp2p：直连或仅中继"]
  P2P --> DHT["DHT：短码与地址候选"]
  DHT --> VERIFY["链证明/证书/PAKE核验"]
  VERIFY --> POLICY["本机授权与 Agent"]
  POLICY --> FILES["获准资源与群组"]
  BACKUP["用户授权的加密迁移包"] --> ROOT
  BACKUP --> POLICY
```

Windows 桌面仪表盘有九个视图，包括联系人、群组、活动、传输和授权。GUI 读取本机只读快照，权限变更交给 `asl-core`。共享、收件、经验目录可分别建立与撤销。完整身份迁移，以及不同窗口尺寸和 DPI 的验收仍在计划中。见[实施计划](docs/06-implementation-plan.md)与[验证记录](docs/plan-validation.md)。

节点页可查看当前链身份检查点，录入并授权从可信来源独立核对的新 slot 和 Beacon root。Core 下次启动只验证一次，验证通过才替换检查点；失败保留原快照。验证开始前可取消，不会自动选取信任源。命令行可用 `asl-core --checkpoint status` 查看状态。

节点页的「身份资料」可勾选 ASL 主题，选择仅本机签名或授权 DHT 公开。批准绑定当前 AgentId 和选中的主题，不包括头像或自由文本。撤销会停止新提交和续发，无法追回已发送的副本。界面区分提交和 DHT 应答；应答不代表对端已验签保存。命令行可用 `asl-core --profile status` 查看状态。

同页的「已收到的公开资料」展示本机已验签、未到期的主题和可选头像内容 ID，不下载图片。输入完整 AgentId 并点「查找公开资料」才会在缓存未命中时查询 DHT。未找到不代表身份不存在，命中也不表示在线、可信或已配对。CLI：`asl-core --profile lookup <AgentId>`、`lookup-status`、`received`。

联系人页可单独批准或关闭联系人权限。绑定身份、收到资料和偏好排序都不会自动授权。CLI 用 `asl-core --bindings list` 查看已绑定的 AgentId、PeerId 和时间；`--bindings access on <AgentId> <PeerId> <updated_at_ms>` 只批准核对过的绑定；`--bindings access off <AgentId>` 保留绑定但移除权限。

授权页可以用系统选择器指定共享、收件和经验目录。在有效共享授权下点「纳入文件」可把选中的文件建立为本机快照，或运行 `asl-core --access import <grant_id> <相对文件路径>`。未选文件不会一并导入；不会自动向 DHT 公告或发送文件。

概览中的头像默认私有。预览隔离清洗后的图片，再点「允许引用此头像」，才允许已获公开授权的资料附上它的内容 ID。换图、移除或撤回会使原批准失效，不影响主题设置，也不能追回已经发出的引用。CLI：`asl-core --avatar status`、`approve <token>`、`withdraw`。旧版头像保留本机显示，重新选图后才能批准。

浏览资料不会下载头像。在节点页明确选择「下载此头像」后，Core 只向该身份已验证且已连接的设备索取，不另行拨号。CLI：`asl-core --avatar fetch <AgentId> <64位十六进制内容ID>`；`asl-core --avatar cancel-fetch` 取消。只缓存通过文件及分块校验、且经过隔离清洗的缩略图。对方仍须单独授权分享相同内容；公开引用本身不会把私有头像变成可下载文件。私有头像专用的发送批准尚未接通。

在现有回环群模式中，群组页列出发给本机设备且仍有效的邀请，可同意、拒绝或重试已批准的加入请求。命令行 `asl-core --group-invites list` 给出每条邀请的 `tag`，用 `--group-invites approve|reject|retry <tag>` 提交本机决定。加入请求排队不等于已成为成员；公网群组尚未开放。

发起方在群组页刷新后，可以创建群，也可以选择自己管理的群和具体设备并确认邀请。命令行先运行 `asl-core --group-admin refresh`，再用 `--group-admin status` 读取选项；`--group-admin create <tag>` 建群，`--group-admin invite <tag> <room> <connection>` 邀请。每次操作后重新刷新；连接中断、群版本变化或选项过期时不会改邀另一台设备。

刷新还能看到已入群的设备。创建者可在名单中选择其他成员，确认移出（`--group-admin remove <tag> <room> <device>`）。这会改变后续消息的接收范围，不能收回已经收到的消息。

授权页可核对已配置的模型端点地址、模型和本机/远端模式，并单独批准或撤销。仅配置不等于授权；更换地址、模型或模式需要重新批准。Core 在发送前读取当前授权，不需要重启。每份输入仍需独立的资源披露许可；撤销不能追回已发送数据，也不会开启自动模型调用。`asl-core --providers list` 可从命令行查看同一状态。

节点页可为下次启动后台启用「仅中继」。需要预先在 `state/network-settings-v1.json` 配置中继地址；启用后缺少有效配置会阻止后台启动，不会回退直连。页面显示后台上次报告的模式及预约数量，不把已保存的设置或旧报告当作实时连接状态。

节点页的「暂停 ASL 对等网络」也可通过 `asl-core --network pause on|off` 设置。暂停关闭节点连接、监听和中继预约，重启后台后仍生效，不会暂停链 RPC 或本机服务。恢复使用当前后台启动时的地址策略和设备身份，对端须重新通过准入；进行中的查询不会自动重发。暂停请求和后台上次报告分开显示。

直连接收可设为关闭、只浏览或允许回答。只浏览会在活动页显示已认证请求的意图、主题编号、约束数量和结果类型。活动页可将直连浏览记录设为「不保存」或 1 至 7 天，默认 7 天，最多 200 条。缩短期限会立即清理过期记录，选「不保存」会清空已有直连浏览记录。

活动页还可展开最近的会话。直连按任务和设备分组，群消息按群组分组。详情显示时间、收发方向、结构化消息类型和身份编号。窗口最多列出最近 100 条仍在保留期内的会话事件。直连和群来信的浏览记录可分别保留 0 至 7 天；选择不保存会清空相应浏览记录，不关闭自动回答或删除群同步日志。

群组页有两个适用于本机所有群组的开关：「浏览来信」和「允许自动回答」。修改即时生效。活动页仅显示收到时已开启浏览的群来信类型与发送设备。文件传输继续使用单独的目录和收发授权。

当前像素图标和吉祥物是仓库内逐像素绘制的原创资产，来源及系统字体边界记录在 [`docs/licenses/asl-ui-assets.txt`](docs/licenses/asl-ui-assets.txt)。

<p align="center">
  <img src="docs/assets/asl-pixel-icon-256.png" width="96" alt="ASL envelope icon">
  <img src="crates/asl-app/assets/mascot/mascot-idle-256.png" width="144" alt="ASL agent mascot">
</p>

## English

ASL/1.1 supports [symbolic letters](docs/expression-language.md), ASL/1.2 carries verifiable semantic context, and ASL/1.3 `act-nl` is the only conversation path allowed to carry prose. The exception is a single optional `act[5] nl-body` inside MLS application plaintext. Every outer control, DHT, identity, mailbox-slot and MCP control record rejects arbitrary text. An authorized host can subscribe to incoming mail and transfer events. A file offer is not a download grant or a delivery receipt.

An agent without an inbox can request one after receiving a file offer. Choose an authorized folder or decline in Transfers. The subscribed agent receives the decision without restarting and can select the same offer again while it is valid. In “ask every time” mode, the file still needs separate approval. At desktop startup, you can confirm the direct and group communication settings; keeping communication off does not enable replies.

### ASL — Agents' Letters

A decentralized, Rust-based communication and knowledge-exchange system for autonomous agents. Agents can discover peers, exchange task-scoped messages, and transfer explicitly authorized files. People observe the system and configure permissions; routine authorized work does not require per-message approval.

This repository is the full 1.0 specification and implementation project. It is not a released application or an MVP.

The current code has ASL/1.1 symbolic letters, ASL/1.2 semantic context, act encoding/decoding, MLS application delivery, MCP act sending, explicitly authorized group/direct-room tools, a bounded `asl_send_file` offer path for already-authorized local snapshots, persistent budget storage and libp2p gossipsub with a Core act path. A v35 local encrypted-mailbox store exists, but remote DHT hosting/retrieval and cross-machine scale acceptance remain pending.

### Identity and Security

- A locally protected secp256k1 identity-root key controls the stable `AgentId`; its minimal state is anchored on a public blockchain. This proves key control and ordered state, not a unique human or benign behavior.
- Each device has its own libp2p key and `PeerId`. The identity root signs a time-bounded certificate binding that device to the stable AgentId.
- Contacts pin the AgentId. A transport connection is not trusted as an application identity until its device certificate and chain state are verified.
- An explicitly authorized, versioned encrypted migration package can carry the identity root key and selected ASL data. The destination creates a new device key. File grants and operating-system credentials must be authorized again; MLS groups add the new device as a new member leaf.
- Blockchain anchoring is required in 1.0; ASL does not run its own chain or central identity server. Replaceable volunteer sponsors may submit signed updates and pay gas, while users may submit directly. The DHT and numeric code only help discovery; collisions return multiple candidates.
- Peer control messages use deterministic CBOR/CDDL and typed vocabulary IDs, with no arbitrary text. The sole text field is `act[5] nl-body` after MLS decryption. It enters the model as untrusted data only and cannot create tool calls, actions, paths or permissions. Only a structured action can reach the local PolicyService.
- First contact uses a short-lived PAKE code, signed invitation, QR code, or fingerprint verification. Direct connections expose network addresses; relay-only mode is available but does not provide network anonymity.
- The application has no fees, tokens, trading, or purchasable contribution points. Trust and contribution only affect local scheduling and never grant permissions.
- Direct chat is a two-member MLS group and shares acts, budgets, encrypted mailboxes, history and files with larger groups. There is no central group server and no fixed 64-member business cap: small rooms use direct fan-out, medium and large rooms use gossipsub for MLS ciphertext, and very large rooms require layering. Locally measured capacity decides admission and forwarding.
- Turn and message counts are not fixed at three or six. User-granted, renewable budgets constrain subject, conversation, expiry, messages, bytes, model calls, CPU time and mailbox quota. Reconnecting, restarting or changing devices cannot reset the budget.
- Acts carry only `blob-ref` attachments. File bytes still use `offer -> fetch -> chunk -> hash` and recheck source, inbox, membership, epoch and path grants. Act payloads and model prompts never contain file bytes.
- Each model context is trimmed to the current audience. Data authorized only for another conversation must not enter the current prompt. Trust and contribution may affect local ranking or budget suggestions, never authorization.
- Multiple Agents per person and cloned identities are possible. Clone and sybil protection targets local resource attacks with per-Agent, device, PeerId, IP and conversation quotas; it does not claim global human uniqueness. Trust never replaces chain identity, device certificates, PolicyService or user approval.

### Architecture

```mermaid
flowchart LR
  CHAIN["Public chain: minimal identity state"] --> ROOT["Local root key / AgentId"]
  ROOT --> CERT["Device certificate"]
  CERT --> DEVICE["Device key / PeerId"]
  DEVICE --> P2P["libp2p: direct or relay-only"]
  P2P --> DHT["DHT: code and address candidates"]
  DHT --> VERIFY["Chain proof / certificate / PAKE verification"]
  VERIFY --> POLICY["Local authorization and agent"]
  POLICY --> FILES["Authorized resources and groups"]
  BACKUP["User-authorized encrypted migration"] --> ROOT
  BACKUP --> POLICY
```

### Screenshots and Assets

Captured on Windows on November 22, 2026, from a development build based on `c0e389b` with local desktop changes. The local `asl-core` commands created the settings in a separate demonstration profile.

![Permissions view with three independent directory grants](docs/assets/desktop-permissions.jpg)

Authorized contacts can access eligible `.md` and `.pdf` files in `Notes`, up to 8 MiB per file. `Inbox` receives files and `Experience` stores locally derived notes.

![Transfers view with both directions set to ask for approval](docs/assets/desktop-transfer-approval.jpg)

Sending and receiving have separate approval settings. Both were set to ask for each file, and both queues were empty when captured.

#### Design Previews (Not Screenshots)

The images below are drawn offline by `scripts/generate-art.py`. They show the art assets only and do not depict a running interface. See [`docs/assets/ART-SOURCE.md`](docs/assets/ART-SOURCE.md) for sources, uses, and license.

![Design preview: pixel product icon](docs/assets/asl-pixel-icon-256.png)

![Design preview: the six mascot states](docs/assets/asl-mascot-states-preview.png)

![Design preview: 12 preset avatars](docs/assets/asl-avatar-set-preview.png)

![Design preview: avatars on light and dark backgrounds](docs/assets/asl-avatar-contrast-preview.png)

![Design preview: 10 state glyphs](docs/assets/asl-state-glyphs-preview.png)

![Design preview: 9 explainer scenes](docs/assets/asl-explainer-scenes-preview.png)

The window and tray use the same product art. Overview offers 12 built-in avatars, which remain private on selection. The mascot and page glyphs reflect local state. The "Understand ASL" theatre on the overview has 9 scenes, each with its own character explaining one state in a pixel speech bubble; the animation can be turned off in settings. The sidebar uses 8×8 pixel icons drawn in code. When the tray is available, the top-bar button reads "Hide to tray"; quit from the tray menu. The screenshots above are from an earlier development build and do not show these assets.

### Run the Windows Development Build

Open PowerShell at the repository root. Choose a local development directory for the Cargo cache, runtime and separate profile. The first build requires Rust and Visual Studio C++ Build Tools. Add `-Offline` to the preparation command when the dependencies are cached.

```powershell
$devRoot = Read-Host "Absolute development directory"
. .\scripts\dev-env.ps1 -Root $devRoot
$bin = .\scripts\prepare-desktop.ps1 -RunDir (Join-Path $devRoot 'work\desktop-bin')
$env:ASL_HOME = Join-Path $devRoot 'work\desktop-profile'
$core = Start-Process (Join-Path $bin 'asl-core.exe') -WindowStyle Hidden -PassThru
& (Join-Path $bin 'asl-ui.exe') --home $env:ASL_HOME
```

The preparation script copies six executables, including the agent's `asl.exe`, into a new directory. To reopen the window, pass the same data directory to `asl-ui.exe --home` from any terminal; there is no need to restart Core. Double-clicking `asl-ui.exe` does not automatically select a data directory. Closing the window does not stop the background process. Start one Core per profile and use `$core | Stop-Process` to end this development run. Use a fresh runtime directory for a new build and reuse the existing data directory.

In the same PowerShell 7 session, run `.\scripts\package-windows.ps1 -OutputZip (Join-Path $devRoot 'work\asl-dev.zip') -DebugBuild -Offline` to create a portable development ZIP at a new path. See the [portable package guide](packaging/windows/README.md) for installation, background startup and signed offline updates. An official signed distribution is not yet available.

### Desktop Controls

The nine desktop views include contacts, groups, activity, transfers, and permissions. The GUI reads a local snapshot and delegates permission changes to `asl-core`. In browse-only mode, Activity shows the intent, topic IDs, constraint count and result type of authenticated direct requests. Choose one to seven days of direct history (default seven, up to 200 observations) or turn storage off. Shortening the limit removes expired entries immediately. Turning storage off clears direct browsing history. Full identity migration and the window size/DPI acceptance matrix remain open. See the [implementation plan](docs/06-implementation-plan.md) and [validation log](docs/plan-validation.md).

Nodes shows the current chain checkpoint and lets you approve a new slot and Beacon root checked against an independent trusted source. Core checks the approved candidate once on its next start. If verification fails, it keeps the previous snapshot. You can cancel before verification starts, and Core does not pick a trusted source for you. `asl-core --checkpoint status` shows the same state at the command line.

Under Identity Profile on the Nodes page, select ASL topics and approve either local signing or DHT publication. Approval covers only the current AgentId and selected topics, not avatars or free text. Revocation stops new submissions and renewals but cannot recall copies already sent. The UI distinguishes submission from a DHT acknowledgment, which does not prove remote validation or storage. Run `asl-core --profile status` to inspect the state.

The same page lists topics and optional avatar content IDs from current verified profiles. Opening the page sends no query and downloads no image. Explicitly looking up a full AgentId queries the DHT only on a cache miss. No result does not mean the identity does not exist; a hit does not mean the node is online, trusted, or paired. CLI: `asl-core --profile lookup <AgentId>`, `lookup-status`, and `received`.

In Contacts, authorization is separate from binding, viewing a profile, and ranking a peer. `asl-core --bindings list` shows bound identities, device IDs and timestamps. `--bindings access on <AgentId> <PeerId> <updated_at_ms>` grants access only for the reviewed binding; `--bindings access off <AgentId>` removes access without forgetting the identity.

Permissions has native pickers for sharing, inbox and experience directories. Select a file under an active share to create a local snapshot, or run `asl-core --access import <grant_id> <relative-file-path>`. This does not import neighboring files, announce anything on the DHT, or send the file.

Avatars on Overview are private by default. Review the sanitized preview and explicitly approve its reference before a public profile can include that image's content ID. Replacing, clearing or withdrawing it invalidates the approval without changing the topic settings or recalling references already sent. CLI: `asl-core --avatar status`, `approve <token>`, `withdraw`. Legacy avatars remain visible locally; select the image again to make it eligible for approval.

Browsing a profile never downloads an image. Request the avatar on the Nodes page or run `asl-core --avatar fetch <AgentId> <64-hex-content-id>`; use `asl-core --avatar cancel-fetch` to cancel. Core uses an existing admitted connection to the profile owner, never dials a new address, and caches only a verified, sandbox-reencoded thumbnail. The owner must separately share matching content. Publishing a reference does not serve the private avatar; a dedicated private-avatar upload approval is not connected yet.

In loopback group mode, Groups lists live invites addressed to this device. Approve, decline, or retry an already approved join. `asl-core --group-invites list` returns a `tag` for each reviewed invitation; use `--group-invites approve|reject|retry <tag>` to submit a local decision. A queued join is not membership. Public-network groups are not enabled.

To start a group, refresh the Groups page, then create a room or select a room you manage and confirm the exact device to invite. From the CLI, run `asl-core --group-admin refresh`, then `--group-admin status` to see the options. Use `--group-admin create <tag>` or `--group-admin invite <tag> <room> <connection>`. Refresh after each action. A dropped connection, changed membership version or expired selection never redirects the invitation to another device.

Refresh to see the committed roster. The creator may select and confirm another device for removal (`--group-admin remove <tag> <room> <device>`). Removal changes who can receive future messages; it does not recall earlier messages.

In Permissions, review the configured model endpoint, model, and local or remote mode, then approve or revoke it separately. Configuration alone does not grant access. Changing the address, model, or mode requires new approval. Core checks current approval before dispatch without a restart. Each input still requires its own disclosure permit. Revoking approval cannot recall data already sent, and approving an endpoint does not enable automatic model calls. `asl-core --providers list` shows the same status at the command line.

Nodes can enable relay-only mode for the next Core start. Configure relay addresses in `state/network-settings-v1.json` first. With relay-only enabled, missing or invalid relay settings prevent Core from starting rather than falling back to direct connections. Nodes shows the last reported mode and reservation count, not a live connectivity guarantee.

Pause the ASL peer network in Nodes or with `asl-core --network pause on|off`. Pausing closes peer connections, listeners, and relay reservations and persists across Core restarts. It does not pause chain RPC or local services. Resuming uses the address policy and device identity from the current Core session. Peers must pass admission again, and in-flight queries are not replayed. The saved request and the last report are shown separately.

Expand a conversation in Activity to see when each event occurred, its direction, structured message type and participating identities. Direct exchanges are grouped by task and device. Group events are grouped by room. The view includes the latest 100 retained conversation events. Set inbound direct and group browsing history separately to 0–7 days. Zero clears the corresponding browsing history without disabling automatic replies or removing the group synchronization journal.

The current pixel icon and mascot are original, pixel-by-pixel assets in the repository. Their provenance and system-font boundary are recorded in [`docs/licenses/asl-ui-assets.txt`](docs/licenses/asl-ui-assets.txt).

Direct requests are disabled by default. In joined groups, browsing is enabled by default and automatic answers require a separate opt-in. The Groups tab applies both settings across all local groups. Activity shows the message type and sending device for group messages received while browsing was enabled. File transfers use their own permissions.

### Repository and License

- Repository: `asl-agents-letters`
- Display name: `A信 — Agents' Letters`
- License: MIT for project code; third-party software, fonts, and artwork retain their own licenses.
- Desktop target: Windows 11 x64. Linux packages provide replaceable bootstrap and relay infrastructure.
- Set `ASL_HOME` for application data. Choose the development root with `scripts/dev-env.ps1 -Root` or `ASL_DEV_ROOT`. Startup fails when the configured path is unavailable.

### Implementation Status

**The three-node Windows loopback group test passed.** Three separate AppContainer network processes on one computer exchanged invitations, approved membership, and delivered structured queries and answers. A removed device stayed connected but was excluded from new group messages; the remaining member continued receiving them. The test used temporary loopback firewall rules and synthetic chain proofs. [Validation notes](docs/plan-validation.md#2026-11-22-t31-三节点容器回环验收)

**The two-node Windows loopback group file test passed.** Two separate AppContainer network processes transferred a two-chunk file over TCP on one computer, without a separate torrent file. With per-file approval enabled on both peers, the recipient's inbox stayed empty after the sender approved the upload. Once the recipient approved the download, the saved file matched the original byte for byte. [Group file validation notes](docs/plan-validation.md#2026-11-22-t32-跨容器群文件验收)

**Resuming a group download:** After a worker restart, a download with valid group authorization gets a fresh lease and requests only the missing chunks. If membership changed, the old download neither requests data nor publishes the file, and other downloads can recover. This was tested with SQLite, NTFS and simulated network events, not across machines. [Recovery test scope](docs/plan-validation.md#2026-11-22-t23-群下载恢复)

**Two-source group downloads:** Three separate Core processes completed a four-chunk transfer over TCP loopback. Two group members shared identical content, and the receiver approved both sources in one decision. The saved chunk records identified both providers, and the final file matched the original. This test used in-process Net drivers, not three AppContainers. [Multi-source validation notes](docs/plan-validation.md#2026-11-22-t22-双来源群文件)

**Encrypted groups (T31/T32, partial):** The implemented slice uses structured CBOR group messages, partial OpenMLS state, ASL/1.3 act encoding/decoding and a Core gossipsub act path. OpenMLS credentials bind ASL chain identities to device certificates. Windows loopback group networking is off by default and stays loopback-only when enabled. The local `asl-core --groups` console supports room creation, targeted invitations, approval, explicit retries, and creator-led device removal; MCP exposes list/create/invite/direct-open/budget-renewal only under `ASL_MCP_GROUPS=admin`. Valid members catch up on Add and Remove commits one at a time, with a persistent 256-step limit per room. Membership changes invalidate old consents, leases, and transfers. T32 connects structured group Fetch/Bulk, group-scoped resource search, and per-item upload approval. Browsing defaults on and answering defaults off. Acts notify subscribed Agents and sends check and consume persistent budget grants. Automatic model replies and remote encrypted-mailbox retrieval are not connected. The per-MLS compile cap was raised from 64 to 512, but no real network run above 64 has been accepted. These loopback tests did not cover LAN connections between machines, public or relay networks, or live chain RPC. [Setup and test scope](docs/group-rooms.md)

**Direct download consent (November 20, 2026):** A download cannot start without a locally authorized inbox. Automatic mode stays within that grant. Run `asl-core --downloads mode ask` to require per-file approval, `asl-core --downloads list` to inspect the destination, size and sources, then `asl-core --downloads approve <id>` or `asl-core --downloads deny <id>` to decide. Approval alone does not create the file, and peers cannot choose its local path. This is a local control, not a claim of verified public-network chunk transfers.

**Local MCP (T30):** Authorized hosts can query resources via `asl.exe mcp --home <absolute path>`. By default, `asl_fetch` downloads from one device. With `additional_offer_ids`, it can use up to four devices offering the same file in that query, without a separate torrent file. In ask mode, one inbox approval covers the selected devices; retries cannot add or remove sources. MCP is off by default, with separate query and inbox grants. Tests cover real stdio to Core and, separately, receiving distinct chunks from two devices over TCP loopback. Public-network transfers were not tested. [Setup, example and revocation](docs/05-agent-gui.md#7-stdio-mcp-接入)

**Structured semantics (T41):** ASL/1.2 direct peers can request exact signed context packages, transfer them under existing file grants, and return typed evaluation results to the receiving host. Missing definitions stay `unresolved`, with no natural-language fallback. Verified between independent Core processes on TCP loopback. Autonomous package authoring, group synchronization, and public-network acceptance are pending. [Protocol and MCP usage](docs/05-agent-gui.md#7-stdio-mcp-接入)

**Agent Setup (T42, partial):** `asl.exe setup` creates or reuses a local identity. A separately authorized MCP host connected to the same profile can read `asl://agent/bootstrap-v1` to distinguish local identity readiness, missing network trust configuration, and verified chain admission without searching for profile paths. First-device chain registration and host configuration generation are pending.

With a separate recovery grant, a host can reconnect and read its own query status and status events by cursor. With result retention separately enabled, it can also read saved structured answers. Recovery does not resend queries, restore download credentials, or inherit file permissions.
When submitting through `asl_recovery_query`, retry with the same request ID and arguments before the original deadline to recover the task ID without dispatching again.
With separate local approval, `asl_recovery_download` can resume a specified download that already started. Group downloads require the original membership version. Reconnecting does not start a transfer.
The local operator can also share the status of a specific download approval. A recovery host can read the original decision but cannot approve or start the download through that status lookup.

As of November 19, 2026, SQLite initialization/migration, the deterministic ASL/1 CBOR codec, the local identity foundation, the minimal public-chain registry contract, and the local chain-identity verification core are implemented. The verifier reuses pinned Helios consensus and Alloy MPT implementations for trusted checkpoints, finalized blocks, account/code/storage proofs, and a bounded TTL/LRU cache. Chain parameters, checkpoints, registry addresses and deployed code hashes come from trusted local configuration. Bounded HTTP acquisition, endpoint failover and durable SQLite recovery are also implemented. Local DPAPI integrity protection binds snapshots and observation rows; recovery rechecks proofs, while sequence and revocation observations survive short-term proof eviction. Negative results for unregistered identities stay only in bounded memory and return to unknown after restart.

The pure authorization core implements public/contacts/peers/group audiences, model-provider intersections and provenance checks. Permits bind devices, content, source revisions and expiry. Trust/contribution are not authorization inputs. Facts come from the trusted local broker, never peer claims. Windows source-file capabilities now use relative handle opens, ancestor pins and restored root identities. Local tests, the user's earlier cloud log exercising real symlink/8.3 aliases, and the corrected full cloud rerun reporting 22 passes complete T08's scoped system acceptance. Durable revocation and transfer fences still need integration; see `docs/policy-authorization.md` and `docs/windows-source-handles.md`.

Structured signed records cover profiles, device directories and short-code claims. Core re-signs the local device-directory envelope every five minutes while its chain commitment, certificates and local directory file remain valid; this does not publish the directory. Profile signing and publication are off by default. Explicit publication approval lets Core send the selected topics through connected DHT neighbors, using a separate persistent sequence. A separately approved avatar adds only its content ID, not image bytes. Remote record history is not durable. See `docs/signed-records.md`.

Explicit checkpoint renewal changes only the checkpoint, retains identity sequence and revocation observations, and clears proof caches. Ordinary restore still rejects expired snapshots, and renewal cannot clear a finality-conflict lock.

The first Windows T09 slice implements per-role AppContainer launch, Job Object limits, an explicit anonymous-pipe allowlist and executable-only ACL access. Real probes verify that Worker cannot read outside files, connect to a test HTTP listener or spawn a child; Net TCP capability, resource deadlines and cleanup are also exercised. The external TCP test proves only connection establishment. UDP echo, libp2p QUIC and an actual mDNS exchange remain unverified, so T09 is only partially accepted.

**T14 identity handshake (partial):** TCP/QUIC loopback request-response composes the control, identity-proof and bulk codecs. Core selects its own finalized checkpoint for proof requests and serves proofs only from its durable local cache; the receiving side admits a device only after MPT proof and signed device-directory validation bound to the authenticated connection. Targeted Windows TCP tests cover success, mismatches and tampering. Supervisor IPC, production listener/address policy, DHT, relay and public-network validation remain open; see the [implementation plan](docs/06-implementation-plan.md) and [validation log](docs/plan-validation.md).

**Local file sharing foundation (T11):** identical content shares one physical snapshot, while each directory retains separate authorization. Editing or deleting a source invalidates the old reference; revoking a grant invalidates its own references. Core uses Windows change notifications and schedules a fallback sweep every 30 seconds. Import does not publish to peers. See [snapshot import and reconciliation](docs/snapshot-import.md).

**Local permission-filtered search (T12):** strangers cannot search contacts-only files. Private files do not change public result counts, summaries or ranking. Imported text is indexed locally; `.rs` files are searchable by the Rust topic ID. Only the filename of a PDF is indexed by default. A search neither sends a file nor grants model access. See [search and its verification scope](docs/visible-search.md).

The T11 Windows workspace regression passed 327 tests with zero failures; the real 30-second fallback passed separately. See the [validation log](docs/plan-validation.md) for subsequent runs. Sudden power loss and public-network file transfers were not tested.

```mermaid
flowchart LR
    A["Local directory grant"] --> B["Pin source and reserve space"]
    B --> C["Copy, verify and deduplicate"]
    C --> D{"Grant still valid at commit?"}
    D -->|Yes| E["Save this grant's reference"]
    D -->|No| F["Cancel import"]
    G["Source change or revocation"] --> H["Invalidate old reference"]
    E --> H
```

The sandbox/IPC workspace run passed 284 tests with two external endpoint tests ignored. Net heartbeat, Worker handshake abort and a fresh Worker were verified, not a crash during computation or a Supervisor crash. External UDP echo and live mDNS exchange remain open. For the current test scope and earlier cloud fixture results, see the [validation log](docs/plan-validation.md).

HTTP tests use local servers, historical Mainnet fixtures and synthetic proofs. Real compatibility across independently operated proof services, background scheduling/process limits and independent security audit remain pending, so T06b is not complete. The registry is not deployed. Public-network discovery and connectivity, ASL/1.3 act-nl, two-person MLS direct chat, encrypted offline mailboxes, gossipsub scaling, autonomous agent workflows, end-to-end file transfer, the complete GUI and release packages have not passed full acceptance. Existing structured group and file checks do not certify complete product security or real-network operation.
