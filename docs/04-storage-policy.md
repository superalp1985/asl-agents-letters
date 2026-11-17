# 数据、授权、持久化与接口

## 1. 数据根与文件布局

`ASL_HOME` 是绝对本地固定 NTFS 卷目录，默认 `E:\ASL\data`。路径不存在可以在获准父目录创建；卷不可用、重解析或 ACL 不符合要求时停止，不回落到用户目录。

```text
data/
  config.toml
  state/asl.sqlite3
  identity/node.dpapi
  credentials/providers.dpapi
  snapshots/ab/<content_id>.blob
  manifests/ab/<content_id>.mnf
  incoming/<transfer_id>.part
  inbox/<content_id>.bin
  derived/<resource_key>.md
  assets/avatars/<content_id>.png
  logs/
  backups/
```

路径全部由程序用已验证 ID 推导，不能从 peer、模型或文档中接受路径字符串。存储命名空间按对象种类区分，不提供裸块 hash 读取 API。程序自身密钥、凭据、数据库、缓存和 logs 禁止被普通共享 grant 覆盖；头像/经验只有显式生成的资源引用可发布。

## 2. 数据表

完整 DDL 见 `specs/schema-v1.sql`，以它为字段名真源。DDL 已通过本机 SQLite 语法与约束校验不代表应用事务实现已完成。

| 表组 | 表 | 责任 |
| --- | --- | --- |
| 配置/身份 | settings、identities、policy_state、schema_migrations | 非秘密设置、身份密文引用、授权修订与迁移 |
| 节点 | peers、authorized_contacts、preferred_peers | 公开观察、授权成员和自主偏好，三者不混用 |
| 授权 | providers、grants、grant_peers、write_grants、transfer_consents | 模型端点、读/披露范围、独立写入和绑定文件/接收者的确认 |
| 群组 | asl_groups、group_members、group_events | MLS 群状态、成员授权与有期限密文事件 |
| 内容 | snapshots、resources、resource_fts、derivation_sources | 物理内容、授权引用、全文索引和溯源 |
| 任务 | tasks、messages、offers、outbox、processed_requests | 有界会话、拉取描述、重试与去重 |
| 传输 | reservations、transfers、transfer_sources、transfer_chunks | 额度、目标、来源和持久块状态 |
| 证据 | trust_events、contribution_events、model_calls、security_events | 本地评价、调用状态和脱敏审计 |

秘密不进 settings、messages 或 security_events。日志中的 peer 可截断显示，完整身份只存业务表；lease、API Key、私钥和模型端点认证头不进入诊断。

FTS5 的结果不能直接返回 peer。检索前先确定请求者可读的 resource_key 集合，再以集合约束执行 MATCH。不能先把私有片段交给模型，再指望输出过滤。

## 3. 应用类型与职责

类型定义放 `asl-types/src/ids.rs`、`task.rs`、`error.rs`；权限结构放 `asl-policy/src/types.rs`。

```rust
pub enum AccessOperation {
    Search, ReadMetadata, ReadChunk, PublishRecord, ModelInput, WriteDerived,
}
pub enum Principal {
    Peer(PeerIdText), LocalTask(TaskId), ModelProvider(String),
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

`ChunkAssignment` 含 peer/index/deadline，`VerifiedChunk` 含 index/hash/bytes，`FailureKind` 枚举 timeout/disconnected/bad_hash/cancelled。`CandidateSet` 是当前调用内 CandidateId 到 `resource_key + permit + bounded_text` 的映射；`AgentDecision` 字段严格对应 JSON schema。

仓储入口固定为：

```rust
pub trait ResourceRepository {
    fn visible_keys(&self, principal: &Principal) -> Result<Vec<ResourceKey>, AslError>;
    fn search_visible(&self, keys: &[ResourceKey], terms: &[String], limit: u32)
        -> Result<Vec<SearchHit>, AslError>;
}
pub trait ReservationRepository {
    fn reserve(&self, request: &ReservationRequest) -> Result<ReservationId, AslError>;
    fn record_progress(&self, id: ReservationId, now_ms: u64) -> Result<(), AslError>;
    fn release(&self, id: ReservationId) -> Result<(), AslError>;
}
```

`SearchHit` 字段是 resource_key/content_id/title/summary/tags/score；不带文件路径。`ReservationRequest` 字段是 task_id/peer_id/kind/bytes/now_ms/idle_limit_ms。kind 为 snapshot/download/derived；quota 在仓储事务内从当前授权读，不从请求者输入读。ID 及失败幂等语义由 tests 固定。

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

public 允许任何已通过 ASL hello 的 peer；contacts 必须位于 authorized_contacts；peers 必须在 grant_peers；group 必须是当前有效群的成员。群 audience 是单独授权，不会转换成 contacts。偏好、信任、贡献、头像、名字均不参与。

群授权按群 ID 生效，对该群当前及之后经本地授权加入的成员都有效。成员加入、退出或移除会增加 membership epoch；permit、lease 和每次询问确认绑定当时 epoch，发送前重新检查。被移除成员不能取得新的群范围内容，已下载的字节不可召回。

`transfer_consents` 的待确认状态不构成 Permit。上传确认绑定源 grant、内容 ID 和目标 PeerId 或 group+epoch；下载确认绑定内容 ID、目标 write grant 和可选 group+epoch。确认过期、授权撤销或绑定变化后必须重新确认；确认之前不得开始源文件读取或目标文件写入。

派生资料包含至多 8 个直接来源、展开后至多 32 个 grant 引用、最大溯源深度 4。对 peer 的访问要求所有叶来源都允许该 peer，且远端再利用规则允许；交集为空、循环、超深或不可判定时标私有，不尝试猜测。

模型披露单独求交：每个片段的 grant 必须允许同一个 provider。never 不能传给任何模型；local_only 只能传给明确授权的本地端点。worker 无网络只是隔离，不表示 core 可以随意把资料发往云端。

## 5. 事务与额度

同一连接串行执行授权写事务；SQLite WAL + foreign_keys + synchronous=FULL。数据库连接不能跨进程共享。

预留事务先计算 active held/consumed，再检查全局、任务、来源及写授权上限，成功才插 reservations。默认单任务 1 GiB、陌生来源总预留 512 MiB；可由规则级授权提高，但单文件仍不得超过 64 GiB。

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

## 7. 清理、备份与身份迁移

聊天默认 7 天、接收文件默认 30 天、失败 part 默认 3 天。用户授权允许的范围由配置保存；Agent 只能在范围内提前清理，不能擅自延长。

清理引用在事务内完成；物理内容仅在没有有效资源/任务引用时回收。source 文件永远不删除。清理使用已固定的应用根句柄，不跟随路径或链接。

备份在 E 盘授权目录生成一致性 SQLite backup 和非秘密配置。DPAPI 身份不能直接跨 Windows 用户使用；跨机导出使用 Argon2id（64 MiB、3 次、1 lane，算法版本 0x13）与 XChaCha20-Poly1305。口令由人提供作为一次迁移授权，不存日志。

导出格式固定为以下 63 字节头，作为 AEAD 的全部 AAD，后接 80 字节密文：

```text
ASCII "ASLKEY01" (8)
argon2_version u16 BE = 0x13
memory_kib u32 BE = 65536
iterations u32 BE = 3
parallelism u8 = 1
salt 16 bytes
nonce 24 bytes
ciphertext_length u32 BE = 80
```

明文是 Ed25519 seed 32 字节 + public key 32 字节；AEAD 标签 16 字节，文件总长 143。导入先检查固定长度、magic 和固定参数，再运行 KDF，防止参数耗尽攻击；解密后由 seed 重新导出公钥并对比。口令按原始 UTF-8 使用，不隐式规范化，最多 1,024 字节。salt/nonce 从操作系统 CSPRNG 取得；加密、KDF 和清零使用固定库，不自行实现密码算法。

恢复只能显式授权；不会在数据库错误时静默重建空授权。恢复后先重验卷、文件身份、grants 与快照，再开放网络。
