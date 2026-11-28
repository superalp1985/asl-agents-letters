# ASL 实现状态（2026-11-28）

本表只记录仓库中可指认的代码和实际运行过的验证。计划项没有被列成完成项。

## 2026-11-28 当前工作树

以下项目已完成代码接线；2026-11-28 的统一本地/回环结果记录在下方“最近一次整体检查”：

- ASL/1.4 `ShardBinding` / `ShardForward`、自动多子 MLS 邀请、根策略逐子群传播、所有者根签名、持久转发 receipt 和来源保留交付。
- v49 加密 shard-forward outbox：控制帧与目标 shard ratchet 提交同事务入队，定向发送成功才清除，gossip-only 或暂时不可达继续退避，目标 epoch/binding 变化和过期明确终止。
- PDF/DOCX/XLSX/PPTX 本机文本抽取：输入/输出、ZIP/XML 部件和 FTS 正文均有界，宏、加密、符号链接和越界 OOXML 关系拒绝；导入与重建索引已接线。
- AutoNAT、relay reservation、direct-first dialing、DCUtR、relay fallback，以及 reachability/route IPC 事件和配置化超时/上限。
- `asl setup` 单流程预检、签名 network seed、链身份 `--onboard/--status` 恢复、MCP bootstrap 状态摘要和外部前置条件报告。
- 链上目录注册 → 最终性 → 目录安装 → DHT 发布编排；迁移 v2 的旧设备撤销授权、联系人设备重绑定和新设备重入请求。
- Linux 离线发布验签/安装/升级/回滚、Windows 可复现打包/验证/回滚和外部部署检查脚本。

## 2026-11-28 统一验收

- `cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1`：最终日志退出码 0；1006 个用例通过、0 失败、13 项按设计忽略。
- `cargo +1.100.0 test -p asl-app --lib --features desktop-ui --locked --offline --no-fail-fast -- --test-threads=1`：323 通过、0 失败、5 忽略。
- `cargo +1.100.0 clippy --workspace --all-targets --features asl-app/desktop-ui --locked --offline -- -D warnings`：通过。
- `cargo +1.100.0 fmt --all -- --check`、`git diff --check`：通过。
- `cargo +1.100.0 run -p asl-types --example export_schema_vectors --locked --offline -- --check`：36 个向量，26 接受、10 拒绝。
- `scripts/validate-cddl.ps1`：两个 CDDL 文件语法通过，语料 26 接受、10 拒绝。
- `cargo +1.100.0 build --workspace --release --locked --offline`：通过。
- Windows 离线测试包：`E:\ASL\dist\ASL-Windows-x64-Test-2026-11-28-v49.zip`，80,952,123 字节，SHA-256 `A60E314973480E98FFE7536E6154D1DE887AE12C4229FB3307C09DB01D088789`。
- 本轮代码与全量测试已覆盖 v49 schema、Office/PDF Extractor 编译路径、跨 shard outbox 事务路径和 desktop-ui 编译；真实公网、跨机、真实链 RPC、真实窗口/DPI 和独立安全审计仍未执行。

## 已完成并验证

| 能力 | 代码入口 | 当前证据 |
| --- | --- | --- |
| ASL/1.3 act 确定性 CBOR | `crates/asl-types/src/protocol/act.rs` | act 单测 2 项；总 act 上限 60 KiB，`nl-body` 上限 32 KiB |
| act 作为 MLS application 明文 | `crates/asl-groups/src/application.rs` | GroupApplication act round-trip；旧结构化帧回归通过 |
| act 入站通知与不可信正文隔离 | `crates/asl-app/src/agent_mail.rs` | 事件将控制字段与 `untrusted_remote_data` 分开 |
| MCP 发 act、建群、邀请、两人会话、预算续期 | `crates/asl-app/src/mcp/` | `asl-app` 全目标编译；MCP 契约定向 4 项通过 |
| 群主策略、管理员/成员/禁言与发送权限 | `crates/asl-types/src/protocol/group_control.rs`、`group_access.rs`、MLS `Policy` 应用 | `group_control` round-trip 1 项、存储策略 2 项通过；入站/出站检查已接线 |
| 持久发送预算 | `crates/asl-store/src/mailbox.rs` | 授予、续期、持久扣减、有限窗口测试 |
| libp2p gossipsub | `crates/asl-net/src/transport/gossip.rs` | 真实双节点 TCP/Noise 收发；asl-net lib 35 项通过 |
| gossipsub IPC 与 Core act 路径 | `crates/asl-app/src/ipc/`、`supervisor/groups.rs` | IPC round-trip 1 项和全工作区编译；无跨机多跳验收 |
| 两人/小群 MLS 房间工具 | `supervisor/groups.rs`、MCP 群工具 | 三 Core direct 群消息进程测试和双 Core 群文件双端审批测试通过 |
| v35 opaque 邮箱/预算仓储与 v36 群权限 | `specs/schema-v35.sql`、`specs/schema-v36.sql`、`crates/asl-store/src/mailbox.rs`、`group_access.rs` | v34→v36、幂等、覆盖拒绝、TTL、配额、预算和群权限 8 项通过 |
| Act 自动模型回复 | `crates/asl-agent/src/act_reply.rs`、`supervisor/auto_reply.rs` | 仅对 `Ask` 生成 `Inform/Clarify`；严格 JSON，禁止 action/tool/path，远端正文只作 untrusted data；使用本机已批准模型端点；asl-agent 全部目标测试通过 |
| Act 本地证据、历史与迁移 | `supervisor/auto_reply_evidence.rs`、`asl-store/src/act_history.rs`、`asl-app/src/act_history_export.rs`、`mcp/contract.rs`、`asl-store/src/migration.rs` | 在线群请求按当前群 audience 搜索最多 4 个同时具备 ReadChunk/ModelInput permit 的文本片段；收发 Act 元数据及 DPAPI 保护的本地正文进入 7 天可配置保留，GUI 显示截断预览；CLI 和独立授权的 MCP `asl_act_history_search` 可做本机有界子串搜索，CLI 可显式导出新 JSON；`history` 迁移携带 Act 历史，`groups` 迁移只携带最多 512 条无密钥群重入线索 |
| DHT 密文邮箱网络闭环 | `crates/asl-net/src/mailbox.rs`、`transport/mailbox.rs`、`supervisor/mailbox_wire.rs` | 8 KiB 带 hash 记录、16 分片批次、3 天轮换 epoch、7 天本地 TTL、已知联系人和群成员拉取、MLS 再验证；真实双节点 DHT put/get 通过 |

## 部分完成

| 能力 | 已完成 | 尚缺 |
| --- | --- | --- |
| 公网入口与资源 provider 发布 | `bootstrap_multiaddrs` 按地址策略拨号；配置发布公钥和 network ID 后校验 Ed25519 seed；显式 public grant 的 content/concept hash 进入 provider 发布集合 | 真实签名 `network-seeds.json`、地址部署、冷启动公网、双机和资源索引验收 |
| 链上身份生命周期 | 签名目录、register/update/revoke、config-driven sponsor/self-pay/fallback、最终性等待、目录安装、typed DHT 发布、`resume/status/revoke-onchain` 状态机和 Foundry 部署脚本 | 真实合约部署、资金、真实交易和跨设备链上迁移验收 |
| AutoNAT / DCUtR | AutoNAT、relay reservation、direct-first、DCUtR、relay fallback、reachability/route 事件和配置化 limits 已接线 | 最终本地编译/测试已通过；真实公网 NAT 矩阵、打洞成功率和 relay 降级验收 |
| DHT 持久化 | SQLite provider 缓存支持同一 key 多 provider；验证后的 record/provider 观测落盘；启动和网络恢复时按可配置批次回灌 Net store，过期数据跳过 | 真实跨机 DHT 重启、NAT 后持久性和长时间 provider 重放尚未验收 |
| Act 送达确认 | 已认证群成员收到非 Ack Act 后，按消息 ID 去重并生成带期限的结构化 `Act Ack`，复用 MLS、预算和 DHT 邮箱 | 真实双机送达时间、回执丢失/重试和 GUI 状态显示尚未验收 |
| 群伸缩与网络 | 单 MLS 编译上限 512；SQLite v49 用代码内递归查询按逻辑根聚合唯一 Agent，邀请前检查 10,000 上限；自动创建/链接最多 19 个独立子 MLS；根/子群策略传播；ASL/1.4 所有者签名绑定、持久去重、逐子群重加密、加密 outbox 和来源保留转发 | 最终本地编译/测试已通过；真实 512/2,000/10,000 跨机矩阵、公网 NAT/relay 和多跳收敛 |
| 群权限 | owner policy、能力分层管理员、文字/文件/邀请权限、群主策略转移、逐内容哈希文件权限、creator 移除审批和入站/出站检查 | 真实多设备策略同步；MLS creator 仍负责 Remove Commit，策略转移不迁移 creator 私钥 |
| 群加入/重入请求 | 经认证连接的结构化 `InviteRequest`、5 分钟期限、群主本机审批队列、设备/Agent 精确绑定、每群 32 条及每 Agent 每小时 5 条上限、在线连接复核后复用定向邀请、GUI/CLI/MCP 持久拒绝 | 真实双机审批和跨设备迁移全链路验收 |
| 文件传输 | 群 offer/fetch/chunk/hash、双端审批、多来源基础、act attachment ref、`asl_send_file`、Offer 密文邮箱；ASL/1.4 跨 shard Offer/Fetch 增加逻辑根和源 shard 元数据，逻辑群主可把文档请求路由回源 shard | 新增代码统一验收、公网跨机、真实两设备大文件；跨 shard 文件字节仍要求双方建立直接认证连接，邮箱只保存 Offer/密文 |
| 文档文本抽取 | PDF/DOCX/XLSX/PPTX 自动识别；输入 4 MiB、输出 2 MiB、FTS 正文 32 KiB；宏、加密、符号链接和越界 OOXML 关系拒绝；导入与重建索引已接入 | 独立 OOXML 夹具/恶意包压力矩阵；超大文档与真实 GUI 安装路径验收 |
| 逻辑群 shard-forward outbox | v49 持久表保存已加密控制帧、路由、尝试次数和期限；与 ratchet 提交同事务，定向成功才清除，gossip-only 继续 pending，按退避重试并清理 terminal | 专门的崩溃/重启/并发重试测试和真实双机目标 shard 收敛验收 |
| 预算 | 消息数 + 消息字节/模型调用/CPU/邮箱默认预算、续期、发送/模型/邮箱实际扣减；GUI 显示用量并续期 24h；MCP/CLI 可续期 | 真实跨机配额压力、CPU 外部进程计量精度和用户自定义策略验收 |
| 浏览/回答 | 入站 act 主动通知；浏览关闭时不记录本地正文；回答开启时 `Ask` 可通过已批准模型生成严格结构化回复；在线连接及已认证 MLS mailbox/gossip 请求都从缓存链/设备证据重建群作用域，并自动选择当前 audience 内、双许可的本地证据；history 迁移包含 Act 预览 | 缓存链/设备证据过期时回退 data-free；GUI 会话操作和 MLS 群密钥随设备迁移 |
| 联系人与群定位 | Contacts 以完整 AgentId 为首要添加入口，公开精确发现使用专用 AgentId DHT provider 键；Lookup 动作保存完整目标并由 Core 精确过滤候选；有期限签名邀请、二维码、绑定 AgentId+设备的临时短码、DHT token 发现、单次消费和 Pairing 确认已接通；新请求默认逐次确认，可显式选择自动接受或拒绝；本地共享群要求同一认证 PeerId，近期交互使用固定到期证据，接受后只创建本机绑定，不授予联系人访问；`ASL_MCP_CONTACTS=manage` 下 Agent 可读取绑定/候选并排队精确查询，但不能批准候选或改策略；群列表和管理详情显示完整 Group ID 并可复制 | 远端签名的来源记录、多设备策略自动同步仍需实现/实机验收；旧 16 位码只保留兼容 |

## 目标对齐

| 目标 | 已有代码 | 仍缺代码 | 仍需部署/验收 |
| --- | --- | --- | --- |
| libp2p 去中心化传输 | TCP/QUIC + Noise、mDNS、DHT provider、relay v2、AutoNAT/DCUtR、direct-first/fallback、bootstrap、签名 seed、持久回灌和 route 状态 | 最终本地编译/测试已通过；真实网络自适应和长时间重连 | 至少两个独立运营的 bootstrap/relay、真实双机公网和 72 小时运行 |
| 区块链身份与迁移 | 根身份、AgentId、设备证书、Helios/MPT、注册/更新/撤销、sponsor/self-pay/fallback、最终性、目录安装、DHT 发布、`setup --onboard`、迁移撤销授权和重入 | 最终本地编译/测试已通过 | 合约正式部署、真实 RPC/最终性、资金/赞助、真实交易和撤销传播 |
| 去中心化资源发现 | Kademlia provider、公开 content/concept hash、public/contacts/groups audience、密文邮箱、多子 MLS 链接 | 最终本地编译/测试已通过；更多离线补收路径 | 真实公网 DHT、NAT 后节点、资源索引和冷启动发现 |
| 所有语义高效表达 | 确定性 CBOR、ASL/1.1 表达式、ASL/1.2 上下文、ASL/1.3 act/action/attachment、ASL/1.4 shard 转发、语义历史匹配、哈希 token 索引和 MCP 工具 | 最终本地编译/测试已通过 | 真实模型、跨机语义包、提示注入红队和跨 audience 测试 |
| 文件传输 | 分块 hash、断点、多来源、双端审批、群文件 Offer/Fetch/Bulk、inline 和收件目录 | 最终本地编译/测试已通过；生产公网传输编排和故障恢复策略 | 两台真实设备大文件、NAT/relay、重启续传和恶意分块压力测试 |
| Agent 安装与可用性 | `asl.exe setup` 单流程、MCP bootstrap、首次语言选择、签名 seed、`identity-registration onboard/resume/status/revoke-onchain`、目录发布重试、托盘、头像和网络/群/传输 GUI | 最终本地编译/测试已通过 | 真实签名种子/发布包、正式链交易、Windows 实机 DPI/托盘和 Linux infra 实机 |
| 用户授权 | 目录白名单、硬路径边界、设备/群/受众授权、逐次传输审批、信任与授权解耦、群主策略转移、能力分层管理员、逐文件策略和复合预算 | 最终本地编译/测试已通过 | 真实多设备管理员操作、跨 audience 外泄测试和独立安全审计 |

## 待外部环境或验收

- 远程密文邮箱的真实双机、公网 DHT/NAT/relay 验收、送达回执和多跳补收；当前是已知联系人或群成员按轮换键主动拉取，离线 Offer 需来源设备在 Offer 有效期内重新上线后才可进入在线分块传输。
- MLS Remove Commit 仍由 creator 提交；管理员通过加密请求和 creator 审批闭环，不获得 creator 私钥。策略群主转移也不会迁移 MLS creator 私钥。
- 提示注入红队、跨 audience 外泄测试和分身资源压力测试。
- 两台真实设备上的建群、迁移群线索、加入/重入请求、邀请、act、重启恢复、公网和真实链 RPC 全链路验收。
- 自动多子 MLS 和跨 shard 转发的最终本地检查已通过；512/2,000/10,000 跨机容量仍待验收。

## 最近一次整体检查

- `cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1`：最终日志退出码 0，1006 通过、0 失败、13 项按设计忽略。
- `cargo +1.100.0 test -p asl-app --lib --features desktop-ui --locked --offline --no-fail-fast -- --test-threads=1`：323 通过、0 失败、5 忽略。
- `cargo +1.100.0 clippy --workspace --all-targets --features asl-app/desktop-ui --locked --offline -- -D warnings`：通过。
- `cargo +1.100.0 fmt --all -- --check`、`git diff --check`：通过。
- `cargo +1.100.0 run -p asl-types --example export_schema_vectors --locked --offline -- --check`：通过，36 个向量中 26 接受、10 拒绝，签名是合成夹具。
- `scripts/validate-cddl.ps1`：通过；两个 CDDL 文件语法符合，26 接受、10 拒绝符合预期。
- 全量测试未覆盖公网、跨机多跳、真实链 RPC、真实窗口/DPI 或安全审计。远程密文邮箱已有 DHT 单元/双节点网络验证，但未完成真实两设备、NAT/relay 和重启补收验收。`asl_send_file` 的 Core→MLS→接收端闭环仍待两设备验收。
- 最终全量回归曾出现一次 `positive_proof_is_reverified_after_restart_without_renewing_expiry` 的 `InvalidLocalState`；定位为测试数据库名在 PID 复用时潜在碰撞，已加入随机后缀。精确测试连续 3 次通过；修复后的 `cargo +1.100.0 test --workspace --all-targets --locked` 退出码 0，所有非忽略用例通过。
- 同一工作树的 `cargo +1.100.0 clippy --workspace --all-targets --locked -- -D warnings` 退出码 0。上面的测试和 Clippy 覆盖当前工作区；仍未覆盖真实双机公网/NAT/relay、真实链 RPC、真实窗口/DPI 或独立安全审计。

## 2026-11-27 完整工作区回归

- `cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1`：退出码 0，所有非忽略测试通过；AppContainer 管理员权限、PowerShell 7、外部 TCP/UDP 目标和生产计时器用例仍按设计 ignored。
- `cargo +1.100.0 clippy --workspace --all-targets --locked --offline -- -D warnings`：通过。
- `cargo +1.100.0 fmt --all -- --check`、`git diff --check`：通过。
- `cargo +1.100.0 run -p asl-types --example export_schema_vectors --locked --offline -- --check`：36 vectors，26 accepted / 10 rejected。
- `scripts/validate-cddl.ps1` 在 E 盘 cddl 0.10.7 下通过。

本轮代码新增：DHT record/provider 持久回灌、链身份 onboard/resume/status/revoke 状态机、群 Context* MLS 路径、逐文件哈希权限、管理员禁言委派、复合预算默认授予/实际扣减/GUI 与 MCP 续期、Act 365 天哈希索引、10,000 成员 shard plan 和 shard/backbone 转发。尚未完成真实链交易、公开 NAT/relay、两机、多子 MLS 群和 72 小时/安全审计验收。

## 2026-11-27 功能接线（新增代码，待集中测试）

- 网络设置新增 `bootstrap_multiaddrs`，启动/恢复时按地址策略解析并拨号；`asl-core --network scope|listen|groups|bootstrap|relay` 可编辑并校验配置。
- 显式 public grant 的 content/concept hash 现在可由 Core 发布为 DHT provider；资源名、路径、摘要和文件列表不进入 provider 记录。
- 首次链注册新增签名设备目录生成、EIP-712 注册/更新/撤销请求、ABI calldata 和 raw transaction RPC 广播入口；首次注册必须先运行 `prepare-directory`，不能让 commitment 与链上值不一致。
- 收到已认证成员的 Act 后会生成去重、带期限的结构化 `Act Ack`，继续复用现有 MLS、预算和 DHT 邮箱路径。
- 本轮完成 `cargo +1.100.0 check --workspace --all-targets --locked --offline`、`cargo +1.100.0 clippy --workspace --all-targets --locked --offline -- -D warnings` 和格式检查；没有运行新增功能的单元/集成测试，也没有真实公网或真实链交易。

## Windows 测试包

- 离线 debug 便携包（2026-11-27）：`E:\ASL\dist\ASL-Windows-x64-Test-2026-11-27-20261127-131810.zip`
- 文件大小：77,884,442 字节。
- SHA-256：`3207D1142F9B680EBA054ED7E81C3192691CDD35A76158FFF41CAB4D58B00486`
- 包内 18 个文件，包含 `asl-core.exe`、`asl-ui.exe`、启动/更新脚本、SHA256SUMS、SBOM、第三方许可和 MPL sources。
