# ASL 实现状态（2026-11-26）

本表只记录仓库中可指认的代码和实际运行过的验证。计划项没有被列成完成项。

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
| Act 本地证据、历史与迁移 | `supervisor/auto_reply_evidence.rs`、`asl-store/src/act_history.rs`、`asl-app/src/act_history_export.rs`、`asl-store/src/migration.rs` | 在线群请求按当前群 audience 搜索最多 4 个同时具备 ReadChunk/ModelInput permit 的文本片段；收发 Act 元数据及 DPAPI 保护的本地正文进入 7 天可配置保留，GUI 显示截断预览；本机可按不区分大小写的子串检索最近 1,000 条保留历史，并由用户显式导出到新 JSON 文件；`history` 迁移携带 Act 历史，`groups` 迁移只携带最多 512 条群 ID/群名/群主/最后 epoch 重入线索，不复制 MLS 密钥 |
| DHT 密文邮箱网络闭环 | `crates/asl-net/src/mailbox.rs`、`transport/mailbox.rs`、`supervisor/mailbox_wire.rs` | 8 KiB 带 hash 记录、16 分片批次、3 天轮换 epoch、7 天本地 TTL、已知联系人和群成员拉取、MLS 再验证；真实双节点 DHT put/get 通过 |

## 部分完成

| 能力 | 已完成 | 尚缺 |
| --- | --- | --- |
| 群伸缩与网络 | 单 MLS 编译上限 512；direct fan-out、gossipsub、Core act 路由；群子流可跟随 loopback/LAN/Internet/relay 地址策略，默认关闭 | 真实双机公网/NAT/relay、跨机多跳收敛、2/32/128/512/2,000/10,000 容量矩阵、分层桥接 |
| 群权限 | 群主策略消息、管理员、禁言、成员文字/文件/邀请默认权限、入站/出站 act/Offer 检查 | 真实多设备策略同步、管理员管理动作、群主转移和更细粒度逐文件策略 |
| 群加入/重入请求 | 经认证连接的结构化 `InviteRequest`、5 分钟期限、群主本机审批队列、设备/Agent 精确绑定、每群 32 条及每 Agent 每小时 5 条上限、在线连接复核后复用定向邀请、GUI/CLI 持久拒绝 | 真实双机审批和跨设备迁移全链路验收 |
| 文件传输 | 群 offer/fetch/chunk/hash、双端审批、多来源基础、act attachment ref、`asl_send_file` 对本机已授权快照发 Offer、Offer 可进入密文邮箱等待补收 | 公网跨机、真实两设备大文件验收；邮箱只保存 Offer/密文，文件字节仍走在线授权传输；Offer 本身不是下载许可 |
| 预算 | 消息数授予、续期、发送侧原子扣减 | 字节、模型调用、CPU、邮箱复合额度与 GUI 策略 |
| 浏览/回答 | 入站 act 主动通知；浏览关闭时不记录本地正文；回答开启时 `Ask` 可通过已批准模型生成严格结构化回复；在线连接及已认证 MLS mailbox/gossip 请求都从缓存链/设备证据重建群作用域，并自动选择当前 audience 内、双许可的本地证据；history 迁移包含 Act 预览 | 缓存链/设备证据过期时回退 data-free；GUI 会话操作和 MLS 群密钥随设备迁移 |
| 联系人与群定位 | Contacts 以完整 AgentId 为首要添加入口，公开精确发现使用专用 AgentId DHT provider 键；Lookup 动作保存完整目标并由 Core 精确过滤候选；有期限签名邀请、二维码、绑定 AgentId+设备的临时短码、DHT token 发现、单次消费和 Pairing 确认已接通；群列表和管理详情显示完整 Group ID 并可复制 | 邀请权限规则和多设备策略同步尚未接通；旧 16 位码只保留兼容 |

## 尚未实现

- 远程密文邮箱的真实双机、公网 DHT/NAT/relay 验收、送达回执和多跳补收；当前是已知联系人或群成员按轮换键主动拉取，离线 Offer 需来源设备在 Offer 有效期内重新上线后才可进入在线分块传输。
- Act 历史的语义排序和跨保留期索引；当前只有当前用户可解密、最多扫描 1,000 条的本地子串搜索及显式 JSON 导出。
- 提示注入红队、跨 audience 外泄测试和分身资源压力测试。
- 两台真实设备上的建群、迁移群线索、加入/重入请求、邀请、act、重启恢复、公网和真实链 RPC 全链路验收。
- 分层万人群和完整发布包。

## 最近一次整体检查

- `cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1`：退出码 0，**0 失败、13 项环境/子进程用途忽略**；包含 ASL/1.3 act、DHT 密文邮箱、Act 历史搜索/导出、群加入/重入请求、无密钥迁移群线索、群组进程、文件审批和 v39 迁移。首次回归发现群管理快照 200 条上限与请求列表 100 条上限不一致，已统一；v32 升级夹具也已显式清理 v38/v39 表。
- 最终改动后的 `cargo +1.100.0 test -p asl-app --lib --features desktop-ui --locked --offline --no-fail-fast -- --test-threads=1`：303 通过、0 失败、5 忽略；`cargo +1.100.0 clippy -p asl-types -p asl-store -p asl-app --all-targets --features desktop-ui --locked --offline -- -D warnings`：通过。
- `cargo +1.100.0 fmt --all -- --check`、`git diff --check`：通过。
- `cargo +1.100.0 run -p asl-types --example export_schema_vectors --locked --offline -- --check`：通过，35 个向量中 25 接受、10 拒绝，签名是合成夹具。
- `scripts/validate-cddl.ps1`：通过；两个 CDDL 文件语法符合，25 接受、10 拒绝符合预期。
- 全量测试未覆盖公网、跨机多跳、真实链 RPC、真实窗口/DPI 或安全审计。远程密文邮箱已有 DHT 单元/双节点网络验证，但未完成真实两设备、NAT/relay 和重启补收验收。`asl_send_file` 的 Core→MLS→接收端闭环仍待两设备验收。
