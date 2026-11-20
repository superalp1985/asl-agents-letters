# 数据、授权、持久化与接口

## 1. 数据根与文件布局

`ASL_HOME` 由本机显式配置，指向本地固定 NTFS 卷上的绝对路径。路径不存在时可在获准父目录创建。卷不可用、遇到重解析点或 ACL 不符合要求时停止。

```text
data/
  config.toml
  state/network-identity-v1.json
  state/model-providers-v1.json
  state/asl.sqlite3
  identity/agent-root-secp256k1.dpapi
  identity/device-key.dpapi
  identity/device-directory.cbor
  credentials/provider-<provider-id>.dpapi
  snapshots/ab/<content_id>.blob
  manifests/ab/<content_id>.mnf
  incoming/<transfer_id>.part
  inbox/<content_id>.bin
  derived/<resource_key>.json
  assets/avatars/<content_id>.png
  logs/
  backups/
```

首次启动只在 `identity/device-key.dpapi` 不存在时生成 Ed25519 设备密钥，并以独占新建方式保存；已有文件无法解密、格式错误或不是普通文件时停止启动，不会静默换身份。设备密钥由 DPAPI 保护，Net 子进程只在启动时通过私有继承管道接收一次。

`state/network-identity-v1.json` 由本地操作者配置版本化链部署、最终性 checkpoint、缓存限额及 beacon/execution 服务入口；其中没有默认合约地址、RPC 地址或 checkpoint。`identity/device-directory.cbor` 是当前根身份签名的设备目录。任一文件缺失时网络身份准入保持关闭；身份根、目录 commitment 与本机最终化链状态全部一致后才会开放准入。

`state/model-providers-v1.json` 是本机版本化 provider 注册表，保存显式 endpoint、模型名、远端/本地模式、启用状态和请求时限，不含 API Key。`credentials/provider-<provider-id>.dpapi` 只保存对应 provider 的 DPAPI 密文；远端 provider 必须有凭据，本地 loopback provider 可不配置凭据。Core 固定向登记的 endpoint 发送请求，不跟随跳转、不读取提示词中的 URL；每次调用都重新验证绑定 provider 与本地/远端模式的 ModelInput permit。缺少注册表时不启用任何模型 provider。

路径全部由程序用已验证 ID 推导，不能从 peer、模型或文档中接受路径字符串。存储命名空间按对象种类区分，不提供裸块 hash 读取 API。程序自身密钥、凭据、数据库、缓存和 logs 禁止被普通共享 grant 覆盖；头像/经验只有显式生成的资源引用可发布。

## 2. 数据表

数据库按 `specs/schema-v1.sql` 至 `specs/schema-v11.sql` 连续迁移。v2 增加本地导入预留与授权版本绑定；v3 清理失效本地引用的全文索引，在撤权、替换和删除时随事务移除对应索引行，不影响同内容的其他授权。这不是对磁盘或备份的安全擦除。v8 增加派生知识的公开继承标记、独立写入目录身份绑定及写入引用表；v9 为资源增加本地来源 AgentId 归因，既有资源默认无归因且不能获得贡献分；v10 将下载 manifest 字节与暂存文件身份绑定持久化，移除依赖 manifest 路径的旧列。v11 为本机直连下载确认补上目标文件名、大小和来源集合；旧的未绑定记录不作放行凭据。链证明缓存最多 128 个 Agent proof、合计最多 32 MiB，按 TTL/LRU 清理；单个 proof 最多 256 KiB。DDL 的存在不代表所有应用事务都已实现。

T06b 现已实现链状态、身份观察和证明缓存的原子事务，DDL 字段不变。永久身份观察单独设 10,000 项硬上限；满额拒绝新的观察，不静默删除高水位或撤销记录。DPAPI 保护的本地快照绑定完整链配置与上述行的摘要，恢复先验证完整性与配置，再重验未过期证明。写失败或并发旧快照覆盖失败后停止返回正向链身份。DPAPI 不提供整库历史回滚防护；同一 Windows 用户恶意程序或已被恢复的整份旧数据库不在此完整性机制的保证内。

运行时仅把已注册或已撤销身份的证明与观察写入数据库。未注册身份的有效不存在证明只进入有界 TTL/LRU 内存缓存，不创建永久 agents 行，重启后回到 Unknown；已有高水位不能被不存在证明降级。存储层只检查行的一致性，不判定证明语义，不能绕过 DurableIdentityResolver 直接写入网络返回的证明。恢复时用当前时间检查过期，再独立恢复历史 LRU 时间，不能用某条记录的旧访问时间清理其他证明。

| 表组 | 表 | 责任 |
| --- | --- | --- |
| 配置/身份 | settings、agents、local_agent_identity、device_identities、local_device_identity、chain_state_cache、identity_registry_states、identity_proof_cache、schema_migrations | AgentId/本机根密钥引用、链身份状态/最终性缓存、远端设备证书、授权修订与迁移 |
| 节点 | agents、device_identities、peers、authorized_contacts、preferred_peers | 稳定 Agent、设备证书、连接观察、按 AgentId 固定的授权成员和自主偏好，彼此不混用 |
| 授权 | providers、grants、grant_agents、write_grants、transfer_consents | 模型端点、读/披露范围、独立写入和绑定文件/接收 Agent 的确认 |
| 群组 | asl_groups、group_members、group_events | MLS 群状态、成员授权与有期限密文事件 |
| 内容 | snapshots、resources、resource_fts、derivation_sources | 物理内容、授权引用、本机检索索引和溯源 |
| 任务 | tasks、messages、offers、outbox、processed_requests | 有界会话、CBOR 语义帧、重试与去重 |
| 传输 | reservations、transfers、transfer_sources、transfer_chunks | 额度、目标、来源和持久块状态 |
| 证据 | trust_events、contribution_events、model_calls、security_events | 本地评价、调用状态和脱敏审计 |

T19 已将 `tasks`、`messages`、`outbox` 和 `processed_requests` 接入 `asl-store`：任务预算、消息方向/类型、有限重试和请求去重在 SQLite 事务中持久化，重启后不会仅因内存状态丢失而再次回答旧请求。`messages.body_cbor` 保存已通过现有确定性 CBOR 编解码器的结构化控制帧；这表示本地存储路径已实现，不表示真实 Core/Net handler、完整公网会话或所有协议帧的端到端接入已完成。`fetch_grant`、lease 及其他传输授权不写入聊天消息和 outbox。

T27 将 `processed_requests` 和 `direct_inbound_conversations` 接入生产直连处理路径。发起检索前在一个事务内占用 AgentId/message ID 去重键并推进 AgentId/root-task 的三轮、六条语义消息预算；回答交给 Net 前在当前授权事务内再预留一条语义消息。请求去重和会话预算均跨进程重启和设备迁移保留，过期十分钟。直连回复暂不进入 T19 `messages` 或 outbox。SQLite 当前授权与本机回答设置在交给 Net 前再次检查；本地持久化和 CBOR 结构分别验收，不代表公网联调通过。

T28 实现类型化派生经验记录：只接收已由 `ValidatedDecision` 校验的 claims；本地生成来源、时间和 `derived_unverified` 标签，模型不能指定路径、验证状态或发布策略。写入目录使用独立 `write_grant`，固定目录身份、create-new 文件和字节额度；每个来源都需通过 `WriteDerived`，公开还需每个来源同时通过 `PublishRecord`，否则仅本地私有。记录以 JSON 落盘并进入本地索引；来源或写入授权撤销后，派生记录级联停用并从 FTS 移除。该切片尚不表示经验收集流程已接入后台自主运行或 GUI。

T29 将本机观察按 integrity/availability/evidence/promise 分开保存；出站请求成功、超时或断连只影响 availability，块 hash 成败只影响 integrity。偏好与信誉读取不写 `authorized_contacts`，检索候选始终从该授权表产生。贡献事件只接受完成任务、匹配任务 AgentId、匹配资源来源 AgentId 且状态为 `verified` 的远端资源；同一 `task_id + content_id + help_kind` 全机只记一次，全 AgentId 共用滚动 24 小时 100 条上限。传输完成、哈希通过或模型自报有用都不会单独记贡献。远端资源来源归因尚未接入完整导入/使用流程，因此缺少来源 AgentId 的资源不会自动产生贡献。

数据库是本机数据边界，不是线上协议：`local_task_text`、资源标题/摘要、模型片段和 GUI 标签可包含本地文本，但不能未经映射复制到 ASL peer message、DHT 记录、链上状态或 MLS 应用明文。线上结构使用 `body_cbor` 等有界 BLOB。公开 profile、offer 和语义任务必须遵循 `schemas/asl-v1.cddl`，不得因数据库使用 JSON 或 TEXT 就将这些字段发送出去。

秘密不进 settings、messages 或 security_events。日志中的 peer 可截断显示，完整身份只存业务表；lease、API Key、私钥和模型端点认证头不进入诊断。

FTS5 的结果不能直接返回 peer。检索前先确定请求者可读的 resource_key 集合，再以集合约束执行 MATCH。不能先把私有片段交给模型，再指望输出过滤。

## 3. 应用类型与职责

类型定义放 `asl-types/src/ids.rs`、`task.rs`、`error.rs`；确定性 CBOR 类型须与 CDDL 同步；权限结构放 `asl-policy/src/types.rs`。

```rust
pub enum AccessOperation {
    Search, ReadMetadata, ReadChunk, PublishRecord, ModelInput, WriteDerived,
}
pub enum Principal {
    Agent(AgentId), LocalTask(TaskId), ModelProvider(ProviderId),
}
pub struct AccessRequest {
    pub grant_id: GrantId,
    pub resource_key: ResourceKey,
    pub principal: Principal,
    pub operation: AccessOperation,
}
pub struct PolicyRevision(pub u64);
pub struct AslError {
    pub code: ErrorCode,
    pub local_detail: Option<String>, // 仅限已脱敏的本地说明
}
```

`Permit` 由 policy 构造，只读字段包含协议文档列出的内容；不得实现可接受远端输入的 Deserialize。`ErrorCode` 与协议错误码逐一对应，序列化为 snake_case。

`ChunkAssignment` 含 peer/index/deadline，`VerifiedChunk` 含 index/hash/bytes，`FailureKind` 枚举 timeout/disconnected/bad_hash/cancelled。`CandidateSet` 是当前调用内 CandidateId 到 `resource_key + permit + bounded_local_text + evidence` 的映射；`AgentDecision` 只能生成 CDDL 定义的结构化语义/决策对象，不含 prose 字段。

仓储入口固定为：

```rust
pub trait ResourceRepository {
    fn visible_keys(&self, principal: &Principal) -> Result<Vec<ResourceKey>, AslError>;
    fn search_visible(&self, keys: &[ResourceKey], concept_ids: &[ConceptRef], limit: u32)
        -> Result<Vec<SearchHit>, AslError>;
}
pub trait ReservationRepository {
    fn reserve(&self, request: &ReservationRequest) -> Result<ReservationId, AslError>;
    fn record_progress(&self, id: ReservationId, now_ms: u64) -> Result<(), AslError>;
    fn release(&self, id: ReservationId) -> Result<(), AslError>;
}
```

`SearchHit` 字段是 resource_key/content_id/local_title/local_summary/local_concept_ids/score；不带文件路径。标题和摘要只供本机显示/索引，不进入网络 Offer。`ReservationRequest` 字段是 task_id/peer_id/kind/bytes/now_ms/idle_limit_ms。kind 为 snapshot/download/derived；quota 在仓储事务内从当前授权读，不从请求者输入读。ID 及失败幂等语义由 tests 固定。

## 4. 权限算法

grant 失效、epoch 不符、源引用 inactive、对象不存在时统一拒绝。对外不存在与无权限都映射 not_found，本地审计可区分。

披露允许条件：

```text
active resource
AND ready snapshot
AND active grant
AND current epoch
AND audience allows requester
AND operation allowed
AND size/type/retention rules satisfied
```

public 允许任何已验证链状态和身份根设备证书的 Agent；contacts 必须位于按 AgentId 固定的 authorized_contacts；peers audience 必须匹配 grant_agents 中的 AgentId；group 必须是当前有效 MLS 设备成员。群 audience 是单独授权，不会转换成 contacts。偏好、信任、贡献、头像、名字均不参与。

群授权按群 ID 生效，对该群当前及之后经本地授权加入的成员都有效。成员加入、退出或移除会增加 membership epoch；permit、lease 和每次询问确认绑定当时 epoch，发送前重新检查。被移除成员不能取得新的群范围内容，已下载的字节不可召回。

`transfer_consents` 的待确认状态不构成 Permit。上传确认绑定源 grant、内容 ID 和目标 PeerId 或 group+epoch；下载确认绑定内容 ID、目标 write grant 和可选 group+epoch。确认过期、授权撤销或绑定变化后必须重新确认；确认之前不得开始源文件读取或目标文件写入。

**已实现的直连收件规则：** 不指定活动 inbox 授权不能接收。SQLite `transfer_approval.download_mode` 缺省或 `"automatic"` 时仅在本机选定的授权目录、文件名和额度内启动；`"ask"` 才逐次询问，未知设置报错。示例 TOML 显式选择询问，不代表运行时会自动加载该样例。收件与上传设置独立，不开放远端审批或群组收件入口。

一次同意绑定内容 ID、字节数、本机文件名、写授权 ID/版本及去重排序后的来源 PeerId 集合。待确认时不创建任务、预留或文件；同意与开始分开，消费确认与预留同一事务，创建 `.part` 前再次检查目录身份、授权版本和期限或自动模式。相同申请复用原编号，到期前切换到自动模式也不覆盖已有待处理、拒绝或已消费决定。全机有效窗口内最多 32 项（含拒绝及已消费），本机确认期限缺省 300 秒，可调为 1–300 秒；过期后不可见、不可消费，下一次创建询问时清理。确认不存 lease，不授予获取新数据块的权限。

本机操作针对当前进程 `ASL_HOME` 指定的数据目录。`asl-core --downloads mode` 查看模式；`mode ask` / `mode automatic` 设置后立即供同一目录内的 Core 读取。`asl-core --downloads list` 返回未过期的待决定或已批准项；`asl-core --downloads approve <id>` / `asl-core --downloads deny <id>` 只修改决定。列表不触发下载恢复，命令也不能代为建立目录授权。如果决定时旧清单的 lease 已过期，应用入口需要同一来源、同一内容的新清单；未过期也不表示对端一定在线。

派生资料包含至多 8 个直接来源、展开后至多 32 个 grant 引用、最大溯源深度 4。对 peer 的访问要求所有叶来源都允许该 peer，且远端再利用规则允许；交集为空、循环、超深或不可判定时标私有，不尝试猜测。

模型披露单独求交：每个片段的 grant 必须允许同一个 provider。never 不能传给任何模型；local_only 只能传给明确授权的本地端点。worker 无网络只是隔离，不表示 core 可以随意把资料发往云端。

## 5. 事务与额度

同一连接串行执行授权写事务；SQLite WAL + foreign_keys + synchronous=FULL。数据库连接不能跨进程共享。

预留事务先计算 active held/consumed，再检查全局、任务、来源及写授权上限，成功才插 reservations。默认单任务 1 GiB、陌生来源总预留 512 MiB；可由规则级授权提高，但单文件仍不得超过 64 GiB。未指定来源，或任意候选来源未获本机联系人授权的任务，共用这项陌生来源额度。身份验证、登记 PeerId 和信任评分都不豁免这项额度。

无有效进展 5 分钟释放 held 预留并暂停任务；不能通过重复 ack/坏块刷新进展时间。已完成消耗从 reserved 转为实际文件占用；释放和重试幂等，不可双减或双加。

可用空间检查只是提示，不等于 OS 保证的物理预留。遇到 ENOSPC/Windows 磁盘满应停止写、保持安全的已提交块状态，等待清理或结束任务，不删除源文件来腾空间。

## 6. 崩溃恢复

1. 启动校验数据根、密钥、schema 和授权表。
2. 所有旧 lease 失效，permit 只存在当前 core 内存。
3. assigned/buffered 块重置 missing；重验 durable 块，损坏则退回 missing。
4. 校验 part 文件的 ID、长度和写授权，拒绝把替换成重解析点的 part 当普通文件。
5. 整文件 hash 与 manifest 不一致时标 corrupt，释放预留、隔离/清理 part，并把该 content_id 冷却 24 小时，不能无限重下。
6. 仅重试未过期 outgoing，最多 3 次，间隔 1、5、30 秒；总有效期默认 10 分钟。
7. 不把历史消息重新作为新 query 投喂模型。

下载冷却记录持久化在 SQLite schema v4 的 `transfer_cooldowns` 中；它只阻止同一 `content_id` 在冷却窗口内重新创建下载，不上传、不进入信任或贡献记录。schema v5 增加 `direct_inbound_conversations`，保存直连会话的本地轮次、语义消息预算和到期时间。schema v10 将有界 manifest 字节与暂存文件身份保存在 `transfers` 中，避免恢复依赖单独 manifest 路径。`transfers`、`transfer_chunks` 和 `reservations` 保存下载状态；`assigned` 块在重启时回到 `missing`，`durable` 块必须重新读盘校验。接收目标必须来自活动的 inbox 写授权；写入使用固定目录句柄、create-new 暂存文件、文件身份校验和不覆盖原子重命名。目录额度同时计算进行中的预留与已完成下载；这只约束经本机 broker 建立的任务，不代表可阻止用户或其他进程自行占用该目录。

## 7. 清理、备份与身份迁移

聊天默认 7 天、接收文件默认 30 天、失败 part 默认 3 天。用户授权允许的范围由配置保存；Agent 只能在范围内提前清理，不能擅自延长。

清理引用在事务内完成；物理内容仅在没有有效资源/任务引用时回收。source 文件永远不删除。清理使用已固定的应用根句柄，不跟随路径或链接。

本机 DPAPI/keystore 保护身份根密钥与设备密钥。身份迁移是单独的、用户显式触发的加密导出流程，优先复用成熟 `age` passphrase 文件格式，不自创 KDF/AEAD 封装。包内明文归档有固定 magic、主/次版本、AgentId、根密钥 seed、公钥校验值、用户选择的联系人/信任/短期历史与清单 hash；不含设备私钥、系统凭据、文件目录路径授权、未选中的共享资料或 MLS ratchet 状态。导入检查版本、AgentId 推导、清单 hash 和所有记录边界后，再建立本机事务。

目标设备导入后必须生成新设备密钥，由根密钥签发更高 serial 的设备证书，并以链上 state commitment 更新设备集合，随后发布签名设备目录。迁移模式下旧实例应先停止；无法联系旧设备或获得最新最终化链状态时，撤销传播可能延迟，不能承诺即时全网撤销。群组通过 MLS 将新设备作为新叶子加入；不复制旧设备 ratchet 状态。目录路径、OS 凭据、grant 和传输中的短期 lease 必须重新授权/生成。

迁移文件只写入用户明确选择并授权的本地目录。`age` 口令由人提供，仅用于本次迁移，不入日志；加密工具负责 KDF、AEAD 和文件格式。未知主版本、截断、损坏、错误口令或清单校验失败均拒绝导入，不做部分身份恢复。

迁移明文归档的概念字段如下，具体二进制/归档编码由 T35 与 schema 一并冻结：

```text
magic = "ASLMIG01"
format_version = 1
agent_id
identity_root_key_seed
identity_root_public_key_checksum
selected_data_manifest
selected_data_payload
```

身份根密钥 seed 仅存在于 age 加密后的包内；公钥校验和用于发现归档损坏，不替代 age 完整性保护。导出不得修改源身份或删除旧设备数据。恢复只能显式授权；不会在数据库错误时静默重建空授权。恢复后先重验卷、文件身份、grants 与快照，再开放网络。
