# ASL/1 结构化协议与应用接口

本文件描述应用协议。libp2p 适配器的具体 API 必须针对固定版本编译，不照搬本文件为不存在的库方法。`schemas/asl-v1.cddl` 是线格式规范，本文补充关系、语义和限制。Rust 确定性 CBOR codec 已实现于 `crates/asl-types/src/protocol/cbor.rs`；旧 JSON parser/schema 已移入 `schemas/prototype/`，不属于 ASL/1。`cddl` 0.10.7 已通过语法检查和固定样例独立验证：14 种帧、3 种签名记录通过，3 个结构错误反例拒绝；可用 `scripts/validate-cddl.ps1` 重跑。具体边界见 `docs/protocol-vectors.md`；这些样例不代表完整多节点互操作或密码学认证。协议变更需增加版本并重跑互通测试。

## 1. 基础类型

| 名称 | 定义 |
| --- | --- |
| `AgentId` | 32 字节，按 `specs/identity-registry-v1.md` 从身份根公钥确定 |
| `PeerId` | 当前设备有效 libp2p PeerId 的规范二进制编码；不得仅按长度接受 |
| `DeviceCertificate` | 身份根 secp256k1 密钥对 `{AgentId, device PeerId, serial, issued_at_ms, expires_at_ms}` 的域分离签名 |
| `Id128` | 16 个 CSPRNG 字节 |
| `ContentId` / `Hash32` | 32 字节 BLAKE3 |
| `TimeMs` | Unix 毫秒整数，范围 0 到 i64::MAX；协议校验允许最多 5 分钟时钟偏差 |
| `ResourceKey` | 本机资源引用 ID，使用 Id128；不是路径，也不是权限 |
| `CandidateId` | 当前模型调用内的随机 16 字节不透明 ID，不可跨调用复用 |
| `GrantId` / `TaskId` / `TransferId` | 不同 Rust newtype，内部均为 Id128，不能互换 |

### 1.1 线上语义边界

- ASL 应用层语义帧、DHT 资料记录、身份设备目录、查询、回答、offer 和 MLS 应用明文使用类型化结构。自然语言字符串不得出现在这些结构中。
- 使用确定性 CBOR（RFC 8949）及 CDDL（RFC 8610）；整数 map key、定长 ID、有限容器和版本化枚举。ASL/1 schema 不定义 text string。Agent 间不能以 JSON string、文件名、标签、错误说明或任意 byte string 偷渡 prose。
- 人类 GUI 的本地化文字只由已知概念 ID 渲染；UI 的自然语言任务通过本机映射为概念/约束后再决定是否发送。不可映射的语义不发送，不回退为自由文本。
- 规范结构外的字节串只允许出现在用途固定的密码学值、hash、签名、PeerId、文件/MLS 密文载荷中。验证器按具体用途检查长度、格式和状态转移，不把未知 blob 交给模型。
- 文件载荷与控制消息分流，是由本地 grant 明确授权的不透明对象；接收文件不自动解析成对话、指令、可执行内容或模型上下文。人类选择授权模型处理时，仍按不可信数据进入隔离模型闸门。
- 本地配置、GUI 标签、日志和数据库可以有文本字段；它们不属于对端可控的 ASL 语义 wire。链上也不得写入自然语言字段。
- 所有帧先检查长度再分配；CBOR 最大嵌套深度 16、单容器最多 4,096 项；拒绝重复 map key、不定长项、非首选编码、尾随字节、未知关键枚举、未知字段及未知主版本。

### 1.2 固定枚举

线上只发送下表的无符号整数，不发送枚举名称。未知值必须拒绝。

| 枚举 | 编号与含义 |
| --- | --- |
| feature | 1 query；2 blob；3 inline；4 profile |
| intent | 1 查找证据；2 定位资源；3 核验主张；4 识别 Agent；5 提供资源；6 群组评议 |
| constraint operator | 0 等于；1 不等于；2 小于；3 小于等于；4 大于；5 大于等于；6 包含；7 属于集合 |
| result shape | 0 claims；1 resources；2 agents |
| answer status | 0 answered；1 no_match；2 declined；3 unsupported |
| result status | 0 complete；1 partial；2 unverified |
| media kind | 0 other；1 document；2 image；3 audio；4 video；5 archive；6 structured_data |
| group operation | 0 application；1 membership |
| error code | 1–17，依次对应第 11 节列出的错误码 |

Pairing exchange 的 attempt 从 1 开始，最大为 5；0 不合法。

## 2. 协议名与限制

| 协议 | 用途 | 限制 |
| --- | --- | --- |
| `/asl/kad/1.0.0` | ASL 网络的 Kademlia | 记录值最多 8 KiB；本机最多 10,000 条/64 MiB，含额外索引的上限另计 |
| `/asl/control/1.0.0` | hello、query、answer、offer、fetch、error | request-response 单帧确定性 CBOR 最多 64 KiB，前缀 u32 BE |
| `/asl/identity-proof/1.1.0` | 按需交换链上身份状态与设备目录证明 | 请求为固定 IdentityProofRequest，响应确定性 CBOR 最多 256 KiB；均带 u32 BE 长度前缀；不兼容的 1.0.0 不协商 |
| `/asl/blob/1.0.0` | manifest、块、inline 拉取 | request-response 一请求一响应；请求固定 91 字节，响应最多 2,097,237 字节（不含外层 u32 BE 前缀），manifest 最多 2,097,210 字节，数据块最多 1 MiB |
| `/asl/group/1.0.0` | 定向群邀请/加入和有界 MLS 状态同步 | 每帧最多 256 KiB；MLS 解密后的 ASL 应用明文必须符合 CDDL |
| 本机 IPC/1 | core 与受限子进程 | 4 MiB 单帧硬上限，按消息种类再缩小；继承管道，不监听公网 |

manifest 上限按固定格式精确计算：58 字节头 + 65,536×32 字节 hash = 2,097,210。不得先按对方声明长度分配无限 Vec。

IPC/1 的 T14 类型消息使用 16 字节不透明 connection handle 和已认证设备 PeerId；连接事件只能由 Net 角色发送，PeerId 仅代表 Noise/libp2p 设备传输认证，不代表 AgentId 已验证。Net 启动时先从私有输入管道读取 `ASLK` v1 前导：4 字节 magic、u16 BE 版本、u32 BE 长度及最多 1 KiB Ed25519 libp2p protobuf 密钥。该前导不是 IPC 帧；未知版本、格式错误或超限在分配正文前拒绝。Net 解码密钥后以 IPC kind 16 `NetReady` 返回 PeerId，Supervisor 将其与 DPAPI 本地设备身份比较，不匹配则终止子进程。本机 Agent 根身份也由当前用户 DPAPI 在启动时 create-once 加载或生成，但不等于链上身份状态已验证。身份证明请求/应答复用 `/asl/identity-proof/1.1.0` 的规范 CBOR 帧，额外绑定 connection handle；入站请求另带不透明 response handle，Core 回答时必须原样带回。每种 IPC 消息在读取 body 前执行自身长度上限。运行时将 handle 绑定活动连接、将 response handle 绑定原请求，并在断开后使旧句柄失效。Net 子进程连接表、传输事件/命令、身份证明转发和 `CoreAdmission` 身份闸门现已实现；身份闸门只有在 Core 显式创建并用于接收/发送事件时才生效，基础 `Supervisor::run` 尚未自动装载链状态 resolver、签名目录、有效 Hello 或接管业务事件循环，不能据此声称生产网络已自动启用身份准入。

后续接线状态（2026-11-19）：Net 子进程连接表、传输命令/事件及身份证明转发已接通；`CoreAdmission` 在同一 IPC connection handle 上协调 Hello、身份链证明和设备目录核验，并在核验前拦截控制/bulk 业务事件及出站业务命令。准入失败通过 IPC kind 32 `CloseConnection` 关闭对应传输连接。Supervisor 可持有绑定到自身根 AgentId 与实际 Net PeerId 的准入状态，防止外部调用方替换本地身份上下文；但仍需显式提供有效 resolver 和签名目录。基础 `Supervisor::run` 尚未自动加载 registry/链状态 resolver、签名目录或生成本地 Hello，也未把普通业务事件接入应用；本机根身份的持久化不等于已锚定或网络准入。传输目前限 loopback，公网策略与完整 T14 尚未验收。

控制与身份证明子流各只承载一个 request-response 帧。接收端先读取 4 字节大端长度，在验证对应通道上限后才分配 payload；读满后要求发送端关闭写半流，不接受尾随帧。控制 codec 只接受 `WireFrame::is_control` 帧，身份证明 codec 只接受方向正确的身份请求/响应。codec 只负责线格式与大小边界，不认证 AgentId、不授权业务操作、不匹配请求 ID，也不证明链状态；这些检查由 Core `DeviceSession`/`CoreAdmission` 执行。任何未经过该身份闸门的调用路径，都不得把控制/bulk 消息交给 Agent 或据此生成业务回复。

控制连接经 libp2p 认证与加密。传输握手认证设备 PeerId；ASL hello 携带 AgentId 和设备证书。双方按需在独立 identity-proof stream 交换证明：request 的 checkpoint 字段绑定请求方本机已接受的 finalized block hash，不能由对端指定信任根；响应必须精确匹配 request ID、AgentId 和 checkpoint。响应包含 finalized height/block hash/state root、完整 EIP-1186 account verifier inputs（nonce、balance、storage root、code hash、nodes）、恰好三个 `{slot: bytes32, value: bytes32, nodes}` 路径，以及最多 8 KiB 的身份根签名 device-directory record。链 ID、registry address 和可信状态根只取本机已验证配置/轻客户端；controller、commitment、sequence、revocation 等状态由 Core 运行现有 Ethereum MPT 验证器从槽值解码，不采信对端派生字段。随后 Core 验证签名目录、链上 commitment/sequence、当前证书和传输 PeerId。每条路径最多 32 个节点、每节点最多 2 KiB、总帧 256 KiB。证明必须来自请求中指定的 checkpoint；对端无法提供时握手失败，不接受它建议的新 root。昂贵验签/证明验证必须经过每连接及全局预算闸门；验证成功前只放行有界 hello/proof/pair 消息。

`/asl/identity-proof/1.1.0` 修正此前 1.0.0 线格式与现有验证器不兼容的问题：旧结构省略账户 trie 验证所需字段、用 64 位 storage slot 且携带未经验证器推导的注册状态。本项目尚未发布，故直接冻结新的 1.1.0，禁止静默兼容旧结构。身份目录作为签名记录随身份证明返回，避免为目录另造信任根或额外发现步骤；记录本身仍须按第 3 节完整验签和核对当前链状态。

PAIR invite/exchange 帧只含 AgentId、PeerId、期限、一次性 token、有限尝试序号、transcript hash 和所选成熟 PAKE 的有界密码学 payload。MLS group envelope 外层只含 group ID、epoch、操作码和有界 ciphertext；OpenMLS 解密后的 plaintext 必须再次通过 ASL 语义 CDDL 校验。

设备证书签名覆盖下列规范二进制：

```text
ASCII "ASL-DEVICE-v1\0"
agent_id              32 bytes
peer_id_length        u16 big-endian
peer_id               peer_id_length bytes, canonical binary PeerId
serial                u64 big-endian
issued_at_ms          u64 big-endian
expires_at_ms         u64 big-endian
```

The signature preimage is hashed with Keccak-256 and signed with secp256k1
ECDSA. A `signature65` is `r[32] || s[32] || v[1]`; `s` must be low and `v`
is 27 or 28. Verification recovers the signer and compares its address with
the current controller proven by the identity registry.

注册状态证明得到当前身份根公钥/控制地址。验证器检查根密钥签名、证书有效期、已观察到的最高 serial、链上设备状态承诺，以及证书 PeerId 与当前已认证传输 PeerId 完全一致。验证通过后再放行普通应用帧；不能把自报 PeerId 或 DHT 记录当成认证。协议 major 不兼容就断开。

blob 协议使用受限 request-response codec，不另写传输加密。每块一条请求；每条请求明确声明内容 ID、lease、块号。64 KiB 控制 codec 与 bulk codec 分开。

## 3. 签名记录

DHT 只接受 profile 和应用允许的少量记录；资源发现主要使用 provider，不把一大份文件清单写入单值记录。

签名原文精确定义：

```text
ASCII "ASL-RECORD-v1\0"
kind                 u8               // profile=1, device_directory=2, short_code=3
agent_id             32 bytes
sequence             u64 big-endian
issued_at_ms         u64 big-endian
expires_at_ms        u64 big-endian
payload_length       u32 big-endian
payload              payload_length bytes, deterministic CBOR per CDDL
```

身份根密钥对上述原始字节作域分离签名。载荷和签名封装后仍需满足 8 KiB 记录上限。链状态中的 AgentId 必须等于记录 owner。

记录验证：kind、长度、根密钥签名、AgentId owner、时间窗口、最大 TTL、sequence 单调性、payload CDDL、同 owner 存储份额全部通过才入库。net 必须接入 Kademlia 的入站过滤事件，由验证器决定是否写入记录存储。启动时通过测试验证“未通过过滤的 PUT 不落库”。

`kind=2` 的 device directory 严格包含版本、AgentId、最多 64 个设备证书及撤销 serial；同一目录不得重复 PeerId 或 serial。设备证书有效期最多 30 天，目录自身最长 30 分钟并周期续发。目录的规范 CBOR commitment 必须与链上 `stateCommitment` 匹配。已钉住联系人本地记住见过的最高目录 sequence/设备 serial，拒绝回滚。断链期间无法证明最新全局撤销状态，GUI 不宣传离线撤销的实时保证。

profile 最长 30 分钟、每 5 分钟重新发布；相同 sequence 只接受完全相同字节。撤下资料后不再续发，旧资料可能存续至 TTL 或远端缓存过期。profile key 基于 AgentId，签名者为身份根，避免设备轮换改变联系人身份。

profile payload 严格遵循 CDDL 中的 profile 结构，只能包含概念 ID 和明确授权的头像 content ID。昵称、描述、地点及任意标签文本不发布。头像必须同时存在一条明确公开的应用管理资源引用，不能因 profile 中出现 hash 就绕过文件授权。

T13 编码补全（2026-11-18）：之前规范只冻结了签名原文，缺少封装、设备目录和短码声明的 CDDL。新增 `signed-record` 定义，不改变已有控制帧或合约存储。封装采用确定性整数键 map：0=版本 1、1=kind、2=AgentId、3=publication sequence、4=issued、5=expires、6=规范载荷字节、7=65 字节签名；整个封装最多 8 KiB。载荷字节必须再次通过对应已知结构的严格解码，不能承载任意 blob 或文本。所有记录最长 30 分钟。身份根签名复用设备证书的 Keccak-256、secp256k1 low-S 及 v=27/28 格式。

profile 载荷直接复用现有 profile 控制对象，内部 owner/sequence 必须与封装相同。device directory 载荷为整数键 map：0=版本 1、1=AgentId、2=registry sequence、3=设备证书数组、4=撤销 serial 数组；设备至多 64 项，按原始 PeerId 字节严格排序，PeerId 和 serial 都不得重复。撤销 serial 至多 64 项，非零、递增，不能与活跃证书重叠；8 KiB 总上限仍优先于数量上限。`stateCommitment = BLAKE3("ASL-DEVICE-DIRECTORY-v1\0" || canonical_payload_bytes)`，同时验证载荷 registry sequence 等于当前最终化链状态序号。外层 publication sequence 与链序号独立，刷新外层时间不改变目录承诺，也不要求每次续发都上链。

kind=3 的短码声明载荷为 0=版本 1、1=AgentId、2=0 至 9999999999999999 的整数，必须等于下节固定派生算法。前导零与四位分组仅由本地 UI 格式化，线上不增加字符串字段。记录有效、签名正确也只产生发现候选，不产生联系人或文件权限。

## 4. 发现与标签

主题通过版本化概念 ID 表达，不对人类文本执行线上规范化。词表 label 只在本地 UI 使用。词表 ID 只增不改；定义变化分配新 ID。每资源最多 16 个概念引用，每节点最多发布 128 个。

```text
concept key = BLAKE3("ASL-CONCEPT-v1\0" + vocabulary_id_u16be + concept_id_u32be)
content key = BLAKE3("ASL-CONTENT-v1\0" + content_id_bytes)
profile key = BLAKE3("ASL-PROFILE-v1\0" + agent_id_bytes)
```

只对 public 范围资源发布 concept/content provider。contacts 与指定 peers 的资源仅在获准直询中返回；hash 和概念 ID 都不是保密技术。

持久短码按固定版本算法从 AgentId 派生，显示为分组十进制数字。短码只提供查找便利，不是身份、认证凭据或全局唯一名称。DHT 使用 `BLAKE3("ASL-HANDLE-v1\0" + normalized_code_utf8)` 查找，并允许同一键返回多个候选。每个候选必须提供身份根签名的 AgentId/短码声明；客户端校验链身份状态后仍将候选保持为未核验联系人，直到 PAKE/指纹步骤完成。DHT 隐瞒、日蚀和离线仍可能造成漏查。

固定 1.0 派生算法：`n = LE64(BLAKE3("ASL-HANDLE-ID-v1\0" || agent_id_bytes)[0..8]) mod 10^16`，左侧补零至 16 位，界面按每 4 位分组。输出碰撞是合法状态，禁止抢占/覆盖或声称全局唯一。数字短码只用于发现，不进行链上注册，不作为凭证。身份解析通过版本化 `IdentityResolver` 接口。

配对协议使用独立 `/asl/pair/1.0.0` request-response。局域网配对码为一次性 6 位 PAKE 凭据，有效期 2–5 分钟；公网邀请优先使用含随机至少 128-bit token、目标 AgentId、期限和身份根签名的二维码/链接，也可用 12 位一次性 PAKE 码。线上只编码固定字段，不含自然语言说明。所有 PAKE 记录绑定双方 AgentId、设备 PeerId、传输会话 transcript 和期限；最多 5 次在线尝试，成功或过期立即作废。具体 Rust PAKE crate 必须经依赖/安全评估后固定，未完成前不得自行拼装密码学协议。

provider 记录最长 1 小时，15 分钟续发；应用只把它视为候选节点，必须直连验证。入口与 provider 地址先经本机地址策略过滤，禁止借远端地址驱动 HTTP、SMB、文件协议或系统命令。

mDNS 得到候选地址后同样完成 ASL hello，不把局域网存在当授权。

## 5. 查询与对话

控制帧 schema 由 `schemas/asl-v1.cddl` 冻结。逻辑查询只含：

```text
protocol_version
message_kind = query
message_id, root_task_id, reply_to
created_at_ms, expires_at_ms
intent_concept_id
topic_concept_ids[]
typed_constraints[]
desired_result_shape
bounded_budget
```

线格式用 CBOR 整数 map key 和数字枚举，不传上列字段名。`intent_concept_id`、主题和谓词都必须来自协商的词表版本；本机不能把任意文字装入 value 字段或未知概念的扩展区。

远端 root_task_id 仅用于关联，不能证明任务真实、贡献有效或授权存在。入站请求的处理额度始终由本机生成和维护。

顺序：授权联系人与本地已知相关节点 → 最多 3 个允许公开的概念键 provider 查找 → 合并去重最多 16 个候选 → 逐个或最多 4 个并行直询 → 本地结果排序。

一次搜索 10 秒；单问答最多 3 个 query/answer 回合和 6 条语义消息；offer 不自动延长预算。消息 ID 去重 10 分钟，容量最多 20,000 条，超容量丢弃最旧过期项；无可清理空间则拒绝新入站任务。

**不转发应用层 query。** 接收者只检索自己的获准索引；不能擅自把别人的问题再问其他节点。DHT 自身仍做路由层多跳。这个边界减少递归与查询泄露，不删减原始问答功能。

answer、offer、error 和 ack 不创建新的入站问答任务。只有本机已授权 outgoing task 可在剩余预算内发下一次 query。

## 6. Offer 与 lease

offer 包含 `offer_id/content_id/concept_ids/file_size/media_kind/expires`，不含源路径、文件名、标题、摘要或自由文本标签。每个概念 ID 按协商的词表版本解释。文件名在本机接收后生成；本地索引仍可存标题/摘要，但不得随 offer 发出。

接收者接受 offer 后发送 `fetch_request`；提供者重新检查当前授权，回复 `fetch_grant`，签发 60 秒随机 lease，再请求 manifest。经 DHT 发现的公共资源和公开头像允许 offer_id=null，但仍按 content_id 找到可访问资源并验证 grant，不能跳过授权。不存在和无权限对远端统一返回 not_found。

lease 绑定连接身份、内容、grant epoch 与 policy revision。revision 变化触发重判而不是无条件撤销，见架构文档。重连或重启后重新申请，不能仅凭 content_id 下载。fetch_grant 的 lease 不进入聊天记录、outbox 或普通日志。

外部 lease 是随机 256 bit 的不透明令牌，只在提供者内存保存其授权映射，不把内部 grant/root/path 暴露出去。日志不得记录 lease 原文。

## 7. 固定 manifest

manifest 相当于内嵌在文件传输协议里的种子元数据，不生成或交换独立 `.torrent` 文件。`Offer` 和公开发现只提供引用；接收方持有效 lease，在 `/asl/blob/1.0.0` 请求 `manifest` 操作，其成功响应的 payload 就是下列二进制清单。完整清单不进入 `Offer`、DHT 或控制帧；块数由文件大小与协议固定块长推导，无需在 `Offer` 增加字段。

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

`/asl/blob/1.0.0` codec 严格要求请求恰为 91 字节、响应长度恰为 27+payload_length；两端在读取 payload 后都要求发送半流结束，不接受尾随请求/响应。请求和响应的 magic、操作码、状态码、固定索引、payload 上限和错误状态空 payload 规则在 codec 层先校验。codec 不校验 lease、内容授权、请求是否属于当前连接或块 hash；这些由 Core/transfer 层绑定当前认证会话后处理。

每块请求含 lease、content_id、index；长度由 manifest 推导，远端不能指定任意 offset/length。最后一块为剩余字节，空文件不请求块。

块状态：

```text
Missing -> Assigned(peer, deadline) -> BufferedVerified -> DurableVerified
Assigned -> Missing                  on timeout/disconnect
BufferedVerified -> Missing          on failed write/sync
Any non-durable -> Cancelled         on revoke/cancel
```

先 hash 验证再写入，批次 sync 成功后才能提交 DurableVerified。一次最多 8 个待持久化块，崩溃最多重拉这些未提交块。重复块不重复写账。

同一 `ContentId` 的一份已校验 manifest 可用于核对所有来源的块，无需从每个节点重复请求清单。每个来源仍须独立签发当前连接的 lease；知道 `ContentId` 不代表可以下载，也不触发自动做种。

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

`AccessRequest` 的设备认证和群上下文由本机 scoped policy service 提供，
不新增可由对端自报的权限字段。`Permit` 绑定具体服务实例及已认证设备；
群范围许可还绑定 membership epoch。纯授权判定与后续持久撤销、文件句柄和
传输 lease 的职责边界见 `docs/policy-authorization.md`。

`encode_manifest` 固定写入 chunk_size/count 并验证 size 与 hashes 数量；不接受自定义块长。`CandidateSet` 带 permit 关联，返回前 core 仍需重新验证授权。

## 11. 错误码

```text
policy_denied, grant_revoked, not_found, offline, timeout, busy,
quota_exceeded, integrity_failed, invalid_message, incompatible_version,
model_invalid, model_unavailable, sandbox_unavailable, disk_full,
relay_capacity, cancelled, internal_error
```

错误回复不得携带本地路径、密钥、数据库内容或异常堆栈。远端错误文本不作为本机指令执行。
