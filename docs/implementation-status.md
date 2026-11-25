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

## 部分完成

| 能力 | 已完成 | 尚缺 |
| --- | --- | --- |
| 群伸缩 | 单 MLS 编译上限 512；direct fan-out、gossipsub 网络和 Core act 路由 | 跨机多跳收敛、2/32/128/512/2,000/10,000 容量矩阵、分层桥接 |
| 群权限 | 群主策略消息、管理员、禁言、成员文字/文件/邀请默认权限、入站/出站 act/Offer 检查 | 真实多设备策略同步、管理员管理动作、群主转移和更细粒度逐文件策略 |
| 文件传输 | 群 offer/fetch/chunk/hash、双端审批、多来源基础、act attachment ref、`asl_send_file` 对本机已授权快照发 Offer | 远程 DHT 邮箱、公网跨机、真实两设备大文件验收；Offer 本身不是下载许可 |
| 预算 | 消息数授予、续期、发送侧原子扣减 | 字节、模型调用、CPU、邮箱复合额度与 GUI 策略 |
| 浏览/回答 | 入站 act 主动通知；浏览关闭时不交付 act | 模型自动回复流水线、audience 自动裁剪、GUI 会话操作 |

## 尚未实现

- DHT/relay 上的远程密文邮箱投递、拉取、主题轮换和离线补收；当前只有本地 opaque 仓储。
- act 历史持久化和跨设备迁移。
- 提示注入红队、跨 audience 外泄测试和分身资源压力测试。
- 两台真实设备上的建群、邀请、act、重启恢复、公网和真实链 RPC 全链路验收。
- 分层万人群和完整发布包。

## 最近一次整体检查

- `cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1`：**904 通过、0 失败、13 忽略**；包含 `asl_send_file`、群主策略、v36 迁移和 UI 成员权限显示。
- `cargo +1.100.0 clippy --workspace --all-targets --locked --offline -- -D warnings`：通过。
- `cargo +1.100.0 run -p asl-types --example export_schema_vectors --locked --offline -- --check`：通过，35 个向量中 25 接受、10 拒绝，签名是合成夹具。
- `scripts/validate-cddl.ps1`：本轮本机 PATH 缺少 `cddl` 命令，未执行成功；此前独立运行记录仍只对应当时快照。
- 全量测试未覆盖公网、跨机多跳、真实链 RPC、远程密文邮箱、真实窗口/DPI 或安全审计。`asl_send_file` 的 Core→MLS→接收端闭环仍待两设备验收。
