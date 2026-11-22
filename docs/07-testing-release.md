# 验收、部署与完整发布

## 1. 三类证据不能混淆

方案校验只验证文档、schema、SQL 和任务一致性；单元测试验证确定性逻辑；真实系统与网络测试验证 AppContainer、文件系统、NAT、中继、界面与资源占用。

| 功能 | 当前状态 | 边界 |
| --- | --- | --- |
| SQLite 初始化与迁移 | 已实现；6 项对应测试通过 | 不代表完整业务表访问、保留策略和全产品存储流程均已完成 |
| CBOR wire codec | 已实现；9 项协议、4 项固定样例测试通过 | 14 帧/3 记录的固定样例和 3 个结构反例，Rust 与独立 CDDL 校验结果一致；多节点互操作待执行，详见 `protocol-vectors.md` |
| 区块链 identity registry 合约 | 已实现；14 项 Foundry 测试通过 | 未部署、未独立审计；轻客户端验证已有局部实现，不能据此放行正式部署 |
| 区块链轻客户端/状态证明 | T06b 部分实现；70 项对应测试通过 | 最终化共识/MPT 验证、有界 HTTP、持久恢复与显式本机 checkpoint 续期已有实现；真实多运营商互测、续期授权界面、进程预算和独立安全审计仍待完成，详见 `chain-verification.md` |
| 纯授权核心 | T07 已实现；36 项对应测试通过 | 内存策略判定及来源交集，独立工程复核无阻断发现；不包含持久撤权、文件读取或发送栅栏 |
| Windows 源文件句柄 | T08 已实现并完成本任务系统验收；本机与用户云机均报告 22 项通过 | 云机先前完整日志覆盖真实 symlink/8.3 别名，盘符修正后用户反馈 22 通过、0 失败、1.27 秒；新反馈仅有结果摘要。不是 AppContainer 或完整产品验收，详见 `windows-source-handles.md` |
| Windows AppContainer/Job Object | T09 实现与真实负向探针已完成首轮；任务验收部分完成 | 本机真实测试覆盖读文件/Worker 联网与子进程拒绝、ACL/继承句柄、资源限制、清理、Net 外网 TCP 连接和多播 membership；公网 TCP 只证连接握手，外部 UDP echo、libp2p QUIC 与 mDNS query/response 未验收。执行文件 ACL DACL 更新有真实跨进程 mutex 串行化测试。最后一次独立复核发现的并发问题已修；不是独立安全审计 |
| Supervisor 与有界 IPC | T10 实现切片及本机真实进程验证完成；系统验收部分完成 | 固定角色/消息/操作、序号、方向及 4 MiB 限制有单测；真实 AppContainer 测试覆盖 Net 心跳、Worker 在任务启动确认后、Core 放行执行前被终止时当前调用失败且新 Worker 可继续处理。此用例不代表计算中的崩溃注入。Supervisor 进程级故障注入和完整公网互通仍待验收 |
| 默认后台收件与续传 | T23 工作线程已接入，验证见[实施计划](06-implementation-plan.md) | 真实认证 TCP 回环从 Fetch 到 NTFS 发布，链准入为夹具；续传用真实 NTFS/SQLite 和模拟网络事件。未验收生产跨进程下载全链路、公网重连或 GUI |
| Inline 与文档/头像 Extractor | T24 本机功能切片已实现并通过定向验证 | inline 仅回传已请求且 hash 匹配的有界内存内容；Windows AppContainer 实测固定 PDF/头像操作。未完成 GUI 流程、文件传输端到端集成、完整工作区或公网验收 |
| 本地授权检索 | T12 本地导入、索引、受限查询与撤权清理 | 中文正文、结构化概念、SQL/FTS 字面值、跨授权隔离、链身份撤销、有限分页与事务恢复有本机测试；不代表 PDF 解析、模型访问或远端搜索已接通 |
| 结构化签名记录 | T13 核心已实现；T31 本机目录续签已接入 | 严格 CBOR、当前链控制者签名、目录承诺、目录续签序号持久化；Profile 的 DHT 发布、远端记录历史持久化与真实公开投递仍待接入 |
| T14 传输与身份握手 | 部分实现，仍未验收整项 | TCP/QUIC loopback request-response、Core 链证明准入及缓存 proof serving 有定向测试；设备密钥启动交付、Net/Core 命令事件与 loopback 监听已接入子进程边界；Core 自动身份闸门、公网地址策略、mDNS、DHT、中继和完整公网互测待完成 |
| T27 Agent 查询 | 入站授权直答、出站联系人直询和公开 DHT provider 查找已接入 | 只接受结构化任务，回复关联原查询并复核身份。MCP 已接入；持久任务历史、GUI、离线投递、MLS 群及公网互通仍未验收 |
| T30 本机 MCP | 四个工具、Core 启动授权、加密会话和收件授权已接入 | 真实 stdio 子进程到真实 Core 覆盖离线查询和会话隔离；另用实际 MCP 消息处理、认证 TCP 回环、链准入夹具验证 Offer、批准与 NTFS 发布。不是公网或生产跨进程下载全链路。命令与分项结果见[实施计划](06-implementation-plan.md#t30--本机-stdio-mcp) |
| T31/T32 三节点群消息 | Windows AppContainer 同机 TCP 回环已通过[管理员定向验收](plan-validation.md#2026-11-22-t31-三节点容器回环验收) | 含邀请审批、结构化问答、浏览开关和剔除在线成员；不含跨容器传文件、真实链 RPC 或跨机网络 |
| T32 双节点群文件 | Windows AppContainer 同机 TCP 回环已通过[管理员定向验收](plan-validation.md#2026-11-22-t32-跨容器群文件验收) | 单来源、双端逐文件审批、两个分块和收件文件逐字节核对；不含多来源并发、断点续传或跨机网络 |
| 完整 P2P 网络、群组与 GUI | 完整产品尚未验收 | 单机群消息结果不能替代公网发现/连接、Agent 自主行为、文件传输或完整 GUI 的系统验收 |

2026-11-20 T27 出站联系人直询切片集中验证（Windows x64，Rust 1.100.0，Cargo、target、临时目录均位于 E 盘，离线）：

- `cargo test -p asl-app --lib --locked --offline direct_outbound::tests -- --test-threads=1`：3 项通过，覆盖仅询问本地授权联系人、结构化响应关联、公开 scope 拒绝及错误 root 丢弃。
- `cargo test -p asl-agent --lib --locked --offline query::tests -- --test-threads=1`：6 项通过，覆盖联系人优先、scope 限制、provider 上限、超时、重放去重及终结状态释放。
- `cargo check -p asl-app --tests --offline`：通过；`cargo clippy -p asl-app -p asl-agent -p asl-store --all-targets --locked --offline -- -D warnings`、`cargo +1.100.0 fmt --all -- --check` 与 `git diff --check`：通过。

本轮未运行全工作区测试、实际链/RPC、公网 DHT、跨节点互通、GUI 或完整资源传输；Cargo 报告 `proc-macro-error2 v2.0.1` 的未来 Rust 兼容性提示。

2026-11-17 T06a 合约验收：

- `forge fmt --check`：通过。
- `forge test -vv`：14 项通过，0 失败。
- `forge build --sizes`：成功；IdentityRegistry 运行时代码 4,548 字节、initcode 5,517 字节。
- `forge inspect IdentityRegistry storage-layout`：与 `specs/identity-registry-v1.md` 记录的 slot 0–2 布局一致。
- `forge inspect IdentityRegistry deployedBytecode | cast keccak`：runtime template hash 为 `0x447a1a286b4e8947950a81fa38751eaecfe1871fdfd360f09c5505e523635961`。
- 构建输出包含 4 条 `reentrancy-events` 提示和 1 条 `block-timestamp` 提示；本记录保留原始告警，不将构建成功描述为静态检查或安全审计通过。

2026-11-17 工作区验证结果：

- `cargo test --workspace --all-targets --locked`：通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `scripts/validate-cddl.ps1`：通过（固定使用 `cddl` 0.10.7，检查 CDDL 语法并验证固定 ACK 向量）。
- Rust workspace 测试本轮合计 31 项通过；T06a 合约 14 项 Foundry 测试单独统计。

以上结果只覆盖当前工作区已有 Rust 代码与测试、identity registry 合约固定测试、CDDL 语法及一个固定帧向量。registry 尚未部署或独立审计，完整多帧互操作、轻客户端/状态证明、Windows AppContainer、真实公网网络或完整产品安全验证尚未完成；这些结果不能作为完整 1.0 发布验收。

2026-11-19 T14 设备身份启动交付验证（Windows，Rust 1.100.0；Cargo、Rustup、target、临时文件和测试夹具均位于 E 盘）：

- `cargo test --workspace --all-targets --locked -- --test-threads=1`：通过；包含身份创建/损坏拒绝、NetReady PeerId 匹配及真实 AppContainer Supervisor 启动；5 项条件性/子进程入口测试按设计 ignored。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `cargo build --workspace --release --locked`：通过。
- 默认并行的 `cargo test --workspace --all-targets --locked` 连续两次在 `chain::http::tests::http_historical_sync_persists_every_verified_step_and_restores_offline` 的恢复步骤返回 `InvalidLocalState`；该测试单独运行通过，`asl-app` 单测串行运行通过，全工作区串行运行通过。并行敏感性尚未定位或修复，不能把默认并行测试记为通过。

本轮只验证受保护设备密钥经私有管道交给 Net、Net 解码后计算的 PeerId 与本地身份精确一致，以及这些失败场景；没有验证 Net 使用该密钥建立 libp2p 连接、Core/Net 网络身份闸门、公网监听或完整 T14。

2026-11-19 T14 Net/Core 运行时接线验证（Windows，Rust 1.100.0；Cargo、Rustup、target、临时目录和测试夹具均在 E 盘）：

- `cargo test --workspace --all-targets --locked -- --test-threads=1`：通过。`asl-app` 133 项单元测试通过；Net driver 双向控制请求/响应 handle 映射、IPC 角色/长度边界和 Windows 条件性子进程用例均在本轮范围内。其他 workspace all-targets 通过；需外部目标、子进程入口或生产计时器的用例按设计 ignored。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `cargo build --workspace --release --locked`：通过。

验证限于本机 workspace 与 loopback transport；新增 Windows AppContainer 命令用例验证非 loopback 监听按策略拒绝并返回关联操作 ID。没有验证自动 Core 身份闸门、公网监听/拨号、DHT、mDNS、中继或完整 T14。Cargo 另报告 `proc-macro-error2 v2.0.1` 存在未来 Rust 兼容性提示；不影响本轮命令结果。

## 2. 阻断发布的反例

| 编号 | 输入或故障 | 必须观察到的结果 |
| --- | --- | --- |
| A01 | 远端要求读取未授权文件、忽略规则、执行命令 | 不读文件、不执行，固定拒绝，无部分输出 |
| A02 | query/文档含路径、URL、伪系统消息 | 不新增能力、不驱动 HTTP、无宿主上下文导入 |
| A03 | junction/symlink/ADS/硬链接/UNC/设备名 | 拒绝；句柄与目录身份检查有真实测试 |
| A04 | 目录组件在检查与读取间被替换 | 不越出原授权根；失败关闭 |
| A05 | 上传、模型调用或发件排队期间撤销 | 新读取/未交接发送停止，旧 permit 不能续用 |
| A06 | 高贡献或自动偏好节点索取 contacts 资源 | 没有明确联系人授权即拒绝 |
| A07 | 三节点 query 环、重复 ID、旧消息恢复 | 不应用层转发，每请求最多一次，无自动回声 |
| A08 | 无效/超长 CBOR、重复键、不定长值、未知字段/概念、非首选编码 | 在分配或模型调用前拒绝 |
| A09 | 未授权 provider 或 HTTP 重定向 | 不发送数据，不把认证头转给其他地址 |
| A10 | 超大/矛盾 manifest、count 溢出、尾随数据 | 有界分配，拒绝，无巨额磁盘预留 |
| A11 | 重复块、坏块、错响应 ID、恶意来源 | 不提交无效块、不重复计分，来源被隔离 |
| A12 | 任意写盘/sync/事务点杀进程 | 恢复重验，最终 hash 一致，额度不重复 |
| A13 | 块都正确但 file_hash 矛盾 | corrupt、冷却，不能反复重下 |
| A14 | 多个 manifest 抢占逻辑额度但无进展 | 来源/任务/全局限制，5 分钟后释放 |
| A15 | DHT 伪签名、旧序号、过期、PUT flood | 不入库或淘汰，存储与队列有界 |
| A16 | worker 打开文件、联网、启动子进程 | AppContainer+Job 真实阻止，不是 mock 自述 |
| A17 | 网络 process 自报 peer 与认证连接不一致 | 拒绝；仅认证适配器生成身份事件 |
| A18 | 多身份刷贡献、重复使用同一结果 | 本机有效任务去重，不提高权限，不突破总额度 |
| A19 | inbox/私有来源派生后自动公开 | 权限交集使其保持私有或拒绝发布 |
| A20 | 数据卷失联、DB损坏、更新失败 | 不回落 C、不重建宽松授权，状态可恢复 |
| A21 | 群非成员/旧 epoch、回答关闭、传输未确认/确认过期 | 不解密/回答/读写；当前成员有效群授权通过；每次授权只用于绑定的内容和目标 |
| A22 | 1,000 个模拟身份并发建立连接、重复身份或克隆设备 | 机器级 CPU/RSS/连接/磁盘/模型总额度不超硬上限；合法多 Agent 均受同一预算 |
| A23 | 错误 state proof、错误 registry code hash、伪造/陈旧最终化状态 | 身份状态校验失败；未知身份进入最低额度，不放宽权限 |
| A24 | 链重组、赞助者不可用、gas 拥堵或 proof RPC 返回不一致 | 未最终化增权不生效；缓存过期降级；赞助者退出不阻止自付或已有身份离线验证 |
| A25 | query/answer/profile/offer/group 明文企图携带自然语言、字符串或未知 byte blob | CDDL/wire lint 或解码器拒绝；本地无法映射的任务不发出 |

路径隔离、沙箱、认证、签名、撤销与模型输入前过滤由独立工程复核者读取代码并重跑。普通模型自评、截图或“没有报错”不替代复核。

## 3. 传输测试矩阵

文件长度覆盖 0、1、32KiB、32KiB+1、1MiB−1、1MiB、1MiB+1、128MiB、4GiB；64GiB 边界可先用 manifest/稀疏测试验证数学，再用真实存储条件做至少一次完整大文件测试并说明实测大小。

来源覆盖 1、2、4 个；坏来源、断线、超时、重复、乱序、最后块损坏、不同来源同 manifest、不同 manifest 不混源。恢复覆盖每个持久化阶段。

必须记录真实大小，不把 128MiB 成功写成“64GiB 已验证”。完整 1.0 可以支持更大规格，但未实测上界要在发布说明中如实标注。

## 4. 网络与去中心化测试

- 20 节点，至少两套独立配置的公网入口/中继。
- 同 LAN、家庭 NAT、UDP 不通、仅 TCP、仅中继、入口切换。
- 一个入口关闭后，已知节点继续工作；新安装节点通过另一个入口加入。
- 所有入口不可达时状态清楚，不虚构入网；LAN 仍按 mDNS 能力工作。
- provider 失效、旧记录、时钟偏差、断网重连、relay 额度耗尽。
- 公共链轻客户端 checkpoint、最终性更新、账户/存储 proof、错误 proof 与重组；赞助交易拒绝/退出时的明确降级。
- 完成跨多个授权来源的下载，并在中继更换后恢复。
- 基础设施只处理加密转发和路由，不需要用户账号/目录/模型密钥。

至少 72 小时持续运行。记录 node 数、连接数、队列深度、DHT字节、RSS、CPU、磁盘、模型调用数与有效任务数。无任务时模型调用必须为 0；资源有界比某个宣传数字更重要。

## 5. GUI 与普通模型验收

截图尺寸 1280×800、1920×1080、960×640；Windows 125%、150%、200% DPI；长中文标题、无头像、长 PeerId、空结果、离线、失败和清理状态。文本不遮挡，主要操作只属于授权。

执行模型验收按 T39：实际调用目标模型写指定任务、独立编译测试并记录修正。运行模型验收至少 100 组固定输入，包含正确引用、无证据、注入、结构对象错误、超时和非法引用。非法输出执行率必须为 0；有效回答率如实报告，不编造模型能力。线上语义 wire 不包含自由文本字段。

## 6. 本机开发环境

开发脚本要求指定本地磁盘目录，并为当前 PowerShell 进程设置 `ASL_HOME`、Cargo、rustup 和临时文件路径。下面提示输入本机实际开发根目录；不会修改机器级设置或自动切换磁盘。

```powershell
$devRoot = Read-Host 'Enter the local ASL development root'
. .\scripts\dev-env.ps1 -Root $devRoot
```

不得使用 setx 改机器全局设置，不挪动用户既有工具链。选用的本地磁盘必须有足够空间；不假设机器存在某个盘符，也不自动改写到其他磁盘。OS 自身的少量沙箱/字体/图形缓存不属于应用可完全控制的范围。

最终检查：

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
cargo deny check
```

fuzz 工具、SBOM 工具及其版本在 T02 锁定；记录实际工具版本、命令、执行时长与结果。不得把不存在的脚本名写成已执行证据。

## 7. Linux 自托管入口

发布 `asl-infra` x86_64 Linux 包、`specs/infra.example.toml` 对应配置和 systemd unit。非 root 用户运行，TCP/UDP 端口默认为 4001，身份持久化，配置/密钥目录只对服务用户可读。通配监听需显式填写真实 `external_addresses`；示例使用的文档网段不能直接部署。

运营者配置 reservation、circuit、流量与存储上限，属于基础设施保护而非产品收费。中继看到连接元数据和流量大小，不能承诺它完全不知谁与谁通信。

至少两个独立入口可配置；内置列表是初始便利，不是唯一真源。没有可达入口的新节点无法凭空找到公网网络。

完整公开发布必须提供并验证打包种子里的真实地址，不能交付空列表却宣传开箱公网自动发现。用户另选自建网络属于网络授权，不依赖官方账户。方案阶段不编造尚未部署的公网地址。

## 8. 发布与更新

必须交付 Windows 便携包/安装包、Linux infra 包、hash 清单、独立发布密钥的 Ed25519 签名、SBOM、第三方 notices 和构建版本信息。发布密钥不复用节点身份。

Windows Authenticode 可在维护者持有合适证书时附加；产品更新的签名验证不依赖购买证书或付费账号。更新镜像可替换，离线导入仍验证签名，关闭更新服务不影响已安装节点运行。

数据库迁移有备份和向前兼容说明；更新不能自动恢复更宽松的历史授权。所有严重安全问题修复后才打完整 1.0 标签。

## 9. 当前资料包验收

本轮制作运行的资料校验脚本保存在 `work/validate_package.py`，报告导出到 `docs/plan-validation.md`。它校验 schema、SQL、配置、任务和文件一致性；不代表上面的应用验收已执行。
