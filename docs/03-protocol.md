# ASL/1 冻结协议与应用接口

本文件描述应用协议。libp2p 适配器的具体 API 必须针对固定版本编译，不照搬本文件为不存在的库方法。协议变更需增加版本并重跑互通测试。

## 1. 基础类型

| 名称 | 定义 |
| --- | --- |
| `PeerIdText` | libp2p Ed25519 公钥导出的有效 PeerId；不得只按字符串长度接受 |
| `Id128` | 16 个随机字节，线格式为 32 个小写十六进制字符 |
| `ContentId` / `Hash32` | 32 字节 BLAKE3，线格式为 64 个小写十六进制字符 |
| `TimeMs` | Unix 毫秒，范围 0 到 i64::MAX；协议校验允许最多 5 分钟时钟偏差 |
| `ResourceKey` | 本机资源引用 ID，使用 Id128；不是路径，也不是权限 |
| `CandidateId` | 当前模型调用内的 `c_` 加 16 个小写十六进制字符，不可跨调用复用 |
| `GrantId` / `TaskId` / `TransferId` | 不同 Rust newtype，内部均为 Id128，不能互换 |

所有网络帧先检查长度后分配；拒绝重复 JSON 字段、未知字段、无效 UTF-8、溢出、超深嵌套和未知版本。已知结构使用 `serde(deny_unknown_fields)`，嵌套自由 JSON 不得成为权限输入。

## 2. 协议名与限制

| 协议 | 用途 | 限制 |
| --- | --- | --- |
| `/asl/kad/1.0.0` | ASL 网络的 Kademlia | 记录值最多 8 KiB；本机最多 10,000 条/64 MiB，含额外索引的上限另计 |
| `/asl/control/1.0.0` | hello、query、answer、offer、fetch、error | 每帧 UTF-8 JSON 最多 64 KiB，前缀 u32 BE |
| `/asl/blob/1.0.0` | manifest、块、inline 拉取 | 一请求一响应；manifest 最多 2,097,210 字节，数据块最多 1 MiB |
| `/asl/group/1.0.0` | 定向群邀请/加入响应和有界群状态同步 | 每帧最多 256 KiB；仅点对点传输已授权对端 |
| 本机 IPC/1 | core 与受限子进程 | 4 MiB 单帧硬上限，按消息种类再缩小；继承管道，不监听公网 |

manifest 上限按固定格式精确计算：58 字节头 + 65,536×32 字节 hash = 2,097,210。不得先按对方声明长度分配无限 Vec。

控制连接经 libp2p 认证与加密。hello 的 PeerId 必须与连接身份一致，协议 major 不兼容就断开；不能把自报 PeerId 作为认证。

blob 协议使用受限 request-response codec，不另写传输加密。每块一条请求；每条请求明确声明内容 ID、lease、块号。64 KiB 控制 codec 与 bulk codec 分开。

## 3. 签名记录

DHT 只接受 profile 和应用允许的少量记录；资源发现主要使用 provider，不把一大份文件清单写入单值记录。

签名原文精确定义：

```text
ASCII "ASL-RECORD-v1\0"
kind                 u8               // profile=1
public_key           32 bytes          // Ed25519
sequence             u64 big-endian
issued_at_ms         u64 big-endian
expires_at_ms        u64 big-endian
payload_length       u32 big-endian
payload              payload_length bytes, raw UTF-8 JSON
```

Ed25519 签名覆盖上述原始字节，不对解析后重新序列化的 JSON 签名。载荷和签名封装后仍需满足 8 KiB 记录上限。公钥导出的 PeerId 必须等于记录 key 的 owner。

记录验证：kind、长度、签名、owner、时间窗口、最大 TTL、sequence 单调性、payload schema、同 owner 存储份额全部通过才入库。net 必须接入 Kademlia 的入站过滤事件，由验证器决定是否写入记录存储。启动时通过测试验证“未通过过滤的 PUT 不落库”。

profile 最长 30 分钟、每 5 分钟重新发布；相同 sequence 只接受完全相同字节。撤下资料后不再续发，旧资料可能存续至 TTL 或远端缓存过期。

profile payload 严格遵循 `schemas/profile.schema.json`；未授权字段用空值而非填猜测资料。schema 字符数之外仍检查签名封装后的 8 KiB 总字节。头像必须同时存在一条明确公开的应用管理资源引用，不能因 profile 中出现 hash 就绕过文件授权。

## 4. 发现与标签

NFKC → Unicode lowercase → 首尾去空白 → 连续空白折叠。标签长度为 1–48 个 Unicode scalar，规范化 UTF-8 不超过 128 字节；每资源最多 8 个，每节点最多发布 128 个。

```text
tag key     = BLAKE3("ASL-TAG-v1\0" + normalized_tag_utf8)
content key = BLAKE3("ASL-CONTENT-v1\0" + content_id_bytes)
profile key = BLAKE3("ASL-PROFILE-v1\0" + peer_id_utf8)
```

只对 public 范围资源发布 tag/content provider。contacts 与指定 peers 的资源仅在获准直询中返回；hash 和标签都不是保密技术。

provider 记录最长 1 小时，15 分钟续发；应用只把它视为候选节点，必须直连验证。入口与 provider 地址先经本机地址策略过滤，禁止借远端地址驱动 HTTP、SMB、文件协议或系统命令。

mDNS 得到候选地址后同样完成 ASL hello，不把局域网存在当授权。

## 5. 查询与对话

控制 envelope 的完整字段由 `schemas/wire.schema.json` 冻结：

```json
{
  "v": 1,
  "kind": "query",
  "id": "00000000000000000000000000000001",
  "root_task_id": "00000000000000000000000000000002",
  "reply_to": null,
  "created_at_ms": 1794844800000,
  "expires_at_ms": 1794844810000,
  "body": {
    "text": "寻找 Rust 程序在 Windows 下限制目录读取的经验",
    "terms": ["rust", "windows"],
    "round": 0
  }
}
```

远端 root_task_id 仅用于关联，不能证明任务真实、贡献有效或授权存在。入站请求的处理额度始终由本机生成和维护。

顺序：授权联系人与本地已知相关节点 → 最多 3 个允许公开的 term 的 provider 查找 → 合并去重最多 16 个候选 → 逐个或最多 4 个并行直询 → 本地结果排序。

一次搜索 10 秒；单问答最多 3 个 query/answer 回合和 6 条语义消息；offer 不自动延长预算。消息 ID 去重 10 分钟，容量最多 20,000 条，超容量丢弃最旧过期项；无可清理空间则拒绝新入站任务。

**不转发应用层 query。** 接收者只检索自己的获准索引；不能擅自把别人的问题再问其他节点。DHT 自身仍做路由层多跳。这个边界减少递归与查询泄露，不删减原始问答功能。

answer、offer、error 和 ack 不创建新的入站问答任务。只有本机已授权 outgoing task 可在剩余预算内发下一次 query。

## 6. Offer 与 lease

offer 包含 `offer_id/content_id/title/summary/tags/file_size/source_peer/expires`，不含源路径。标题最多 160 字符，摘要最多 1,200 字符，tags 最多 8 项。

接收者接受 offer 后发送 `fetch_request`；提供者重新检查当前授权，回复 `fetch_grant`，签发 60 秒随机 lease，再请求 manifest。经 DHT 发现的公共资源和公开头像允许 offer_id=null，但仍按 content_id 找到可访问资源并验证 grant，不能跳过授权。不存在和无权限对远端统一返回 not_found。

lease 绑定连接身份、内容、grant epoch 与 policy revision。revision 变化触发重判而不是无条件撤销，见架构文档。重连或重启后重新申请，不能仅凭 content_id 下载。fetch_grant 的 lease 不进入聊天记录、outbox 或普通日志。

外部 lease 是随机 256 bit 的不透明令牌，只在提供者内存保存其授权映射，不把内部 grant/root/path 暴露出去。日志不得记录 lease 原文。

## 7. 固定 manifest

```text
magic                8 bytes          ASCII "ASLMNF01"
version              u16 BE           1
file_size            u64 BE           0..68,719,476,736
chunk_size           u32 BE           1,048,576
chunk_count          u32 BE           ceil(file_size/chunk_size), empty=0
file_blake3          32 bytes
chunk_blake3         chunk_count × 32 bytes, in chunk order
```

头长度是 8+2+8+4+4+32=58。`ContentId = BLAKE3(完整 manifest 原始字节)`，任何长度和 hash 改动都会改变 ID。固定块尺寸使不同节点对同一内容产生同一 ID。

验证顺序固定：总长度至少 58 → magic/version → file_size 上限 → chunk_size 常量 → 检查 ceil 不溢出 → count 相等且不超过 65,536 → 精确总长度无尾随字节 → 计算 content_id → 比对期望 ID。

长度不是文件完整性证明。完成接收后还必须逐块、整文件分别校验。空文件需验证 BLAKE3(empty)；其 manifest 只有 58 字节。

## 8. 块与多来源调度

bulk 请求为固定 91 字节：

```text
ASCII "ASLB01" (6) | operation u8 | request_id (16) |
content_id (32) | lease_id (32) | chunk_index u32 BE
```

operation 为 manifest=1、chunk=2、inline=3；manifest/inline 的 index 必须为 0。响应为 u32 BE 帧长，后接：

```text
ASCII "ASLR01" (6) | request_id (16) | status u8 |
payload_length u32 BE | payload
```

响应头 27 字节，最大帧长为 27+2,097,210=2,097,237，不含外层 4 字节。status=0 成功、1 not_found、2 busy、3 expired、4 integrity_failed、5 cancelled；非成功时 payload_length 必须为 0。请求 ID 必须匹配当前连接上的待完成请求；未知、重复和超期响应不写盘。状态 1 同时用于无权限和不存在，避免裸 hash 探测。

每块请求含 lease、content_id、index；长度由 manifest 推导，远端不能指定任意 offset/length。最后一块为剩余字节，空文件不请求块。

块状态：

```text
Missing -> Assigned(peer, deadline) -> BufferedVerified -> DurableVerified
Assigned -> Missing                  on timeout/disconnect
BufferedVerified -> Missing          on failed write/sync
Any non-durable -> Cancelled         on revoke/cancel
```

先 hash 验证再写入，批次 sync 成功后才能提交 DurableVerified。一次最多 8 个待持久化块，崩溃最多重拉这些未提交块。重复块不重复写账。

每下载最多 4 个来源，每来源 2 个并发请求；调度优先缺失块、再处理超时块。3 次坏 hash 后禁用该来源于当前传输，记录完整性证据，不用贡献抵扣。

恢复时重验所有已标 DurableVerified 块；坏块退回 Missing。全文件 hash 和 content_id 都通过后，以本地生成名称原子移入私有接收区。未完成对象不能对外作为完整文件提供。

中继耗尽是来源暂不可用，可以续连或选择其他授权来源；不绕过运营者配额。完整下载不能依赖某个固定中继。

## 9. Inline、小文件与防推送

原始字节最多 32 KiB，可走 bulk 的 inline 响应，仍需 manifest/hash、接收授权、额度预留和对应请求 ID。offer 只是元数据，不能把附件直接写盘。

文件名与扩展名由本地策略生成，远端标题只显示，不用于路径拼接。压缩包不自动解压。

## 10. 应用层接口

以下是本项目自有接口，放在所列文件，不是外部 crate API：

```rust
// asl-types/src/manifest.rs
pub struct Manifest {
    pub file_size: u64,
    pub file_hash: [u8; 32],
    pub chunk_hashes: Vec<[u8; 32]>,
}
pub enum ManifestError {
    TooShort, BadMagic, BadVersion, FileTooLarge, BadChunkSize,
    BadChunkCount, BadLength, ContentIdMismatch, IntegerOverflow,
}
pub fn decode_manifest(
    bytes: &[u8], expected_content_id: [u8; 32]
) -> Result<Manifest, ManifestError>;
pub fn encode_manifest(manifest: &Manifest) -> Result<Vec<u8>, ManifestError>;

// asl-policy/src/service.rs: Permit 不可从网络反序列化
pub trait PolicyService {
    fn authorize(&self, request: &AccessRequest, now_ms: u64)
        -> Result<Permit, AslError>;
    fn revalidate(&self, permit: &Permit, now_ms: u64)
        -> Result<(), AslError>;
    fn revoke(&self, grant: GrantId, expected_epoch: u64)
        -> Result<PolicyRevision, AslError>;
}

// asl-transfer/src/scheduler.rs: 纯状态，不进行网络和磁盘 IO
pub trait ChunkScheduler {
    fn next(&mut self, now_ms: u64) -> Vec<ChunkAssignment>;
    fn received(&mut self, peer: &PeerIdText, index: u32, bytes: &[u8])
        -> Result<VerifiedChunk, AslError>;
    fn mark_durable(&mut self, indexes: &[u32]) -> Result<(), AslError>;
    fn failed(&mut self, peer: &PeerIdText, index: u32, reason: FailureKind);
}

// asl-agent/src/decision.rs
pub fn validate_decision(
    raw: &str, candidates: &CandidateSet
) -> Result<AgentDecision, DecisionError>;
```

`encode_manifest` 固定写入 chunk_size/count 并验证 size 与 hashes 数量；不接受自定义块长。`CandidateSet` 带 permit 关联，返回前 core 仍需重新验证授权。

## 11. 错误码

```text
policy_denied, grant_revoked, not_found, offline, timeout, busy,
quota_exceeded, integrity_failed, invalid_message, incompatible_version,
model_invalid, model_unavailable, sandbox_unavailable, disk_full,
relay_capacity, cancelled, internal_error
```

错误回复不得携带本地路径、密钥、数据库内容或异常堆栈。远端错误文本不作为本机指令执行。
