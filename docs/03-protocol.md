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

ASL/1.1 新增 [表达式信件](expression-language.md)（kind 15）。内置 Query 词表只限制自动检索接口，不限制 Agent 通信主题。已准入且支持 1.1 的双方可以组合请求、条件、断言和定义，用同一 `root_task_id` 分多封信澄清陌生概念。符号不会自动解析为路径、命令、授权、工具调用或事实。1.0 节点仍沿用原协议，不回退为自然语言。

ASL/1.2 增加摘要绑定的语义上下文帧（kind 16-19）。`ContextExpression` 的每个外部概念范围必须绑定完整的 authority、namespace、revision 和 digest；发送端须先基于当前已验证身份链状态检查签名、依赖和一致性向量。接收端使用本机同一链状态重新验证，仅向 MCP 报告 `value`、`unresolved` 或 `invalid`。缺少上下文时仍可收件，但不得猜测含义或据此执行动作。此处不表示 ContextRequest/Offer 文件同步已经完成；上下文文件仍只能使用既有授权传输。

上下文帧只可在双方 Hello 均声明协议 minor 2 或更高时使用。旧节点不会收到上下文表达式，也不会把新帧降级成 ASL/1.1 表达式或自然语言。

ASL/1.3 增加 `act-nl`（Hello feature 5）。`act` 不是外层 `control-frame`，只能作为 MLS `Application` 解密后的 `group-application` 明文；私聊是两人 MLS 组，与群聊共用同一 act 路径。act 控制字段包括 message/conversation/causal ID、act type、reply-to、结构化 action、blob-ref 附件、hop 和期限；唯一可选任意文本字段是 `act[5] nl-body`，最多 32 KiB。`nl-body` 是不可信远端数据，不能成为系统/开发者指令、工具调用、路径、授权、目标或动作。动作只能来自结构化 `action` 并经 PolicyService；文件字节仍走 `offer/fetch/chunk/hash`，act 只携带 blob-ref。

当前实现边界：`Act` 编解码、MLS application 封装、入站事件中的 `untrusted_remote_data` 标记、MCP `asl_send_act`、显式管理授权下的群/两人会话 MCP 工具、发送侧持久预算和 gossipsub act 路由已接入。回答开启时，`Ask` 可由本机已批准模型生成严格解析的 `Inform/Clarify`，模型不能返回 action、tool、path 或附件控制字段；在线群请求会从当前 audience 快照选择最多 4 个同时具备 `ReadChunk`/`ModelInput` permit 的本地文本证据。DHT 密文邮箱已接 8 KiB 记录、分片批次、3 天轮换键和 7 天 TTL；已知联系人或群成员可拉取并用 MLS 重新验证发送者。Act 元数据和 DPAPI 保护的本机正文预览进入活动历史，选择 `history` 的加密身份迁移包可携带未过期历史。邮箱不携带文件字节，不提供远端送达回执；真实两设备、公网/NAT/relay 和 MLS 密钥迁移仍待验收。

ASL/1.3 群内还定义了 `group-policy` 控制值：它只在 MLS 解密后由群创建者（群主）发出，包含单调递增的 policy revision、成员默认权限位、管理员 PeerId 和禁言 PeerId。`1=成员可发文字`、`2=成员可发文件`、`4=成员可邀请`；管理员由群主指定，群主始终拥有最高权限。接收方必须用 MLS 当前 epoch 的 sender leaf 验证发送者确实是该群创建者，再原子替换本机策略。成员端对入站 act 和文件 Offer 都重新检查该策略；策略消息本身不进入自然语言数据区，也记录为无文本控制事件。

- 使用确定性 CBOR（RFC 8949）及 CDDL（RFC 8610）；整数 map key、定长 ID、有限容器和版本化枚举。外层控制面、DHT 记录、身份记录、offer、群成员事件和预算均不定义任意 text string。已有配对邀请的单句说明是固定长度兼容例外；ASL/1.3 仅额外允许 MLS 解密后的 `act[5] nl-body`。
- 规范结构外的字节串只允许出现在用途固定的密码学值、hash、签名、PeerId、文件/MLS 密文载荷中。验证器按具体用途检查长度、格式和状态转移，不把未知 blob 交给模型。
- 文件载荷与控制消息分流，是由本地 grant 明确授权的不透明对象；接收文件不自动解析成对话、指令、可执行内容或模型上下文。人类选择授权模型处理时，仍按不可信数据进入隔离模型闸门。
- 本地配置、GUI 标签、日志和数据库可以有文本字段；它们不属于对端可控的 ASL 语义 wire。链上也不得写入自然语言字段。
- 所有帧先检查长度再分配；CBOR 最大嵌套深度 16、单容器最多 4,096 项；拒绝重复 map key、不定长项、非首选编码、尾随字节、未知关键枚举、未知字段及未知主版本。

### 1.2 固定枚举

线上只发送下表的无符号整数，不发送枚举名称。未知值必须拒绝。

| 枚举 | 编号与含义 |
| --- | --- |
| feature | 1 query；2 blob；3 inline；4 profile；5 act-nl |
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
| `/asl/group/1.0.0` | 定向群邀请/加入和有界 MLS 状态同步 | 每帧最多 256 KiB；MLS 解密后的 ASL 应用明文必须符合 CDDL；大群 gossipsub/分层尚未接入 |
| 本机 IPC/1 | core 与受限子进程 | 4 MiB 单帧硬上限，按消息种类再缩小；继承管道，不监听公网 |

manifest 上限按固定格式精确计算：58 字节头 + 65,536×32 字节 hash = 2,097,210。不得先按对方声明长度分配无限 Vec。

IPC/1 的 T14 类型消息使用 16 字节不透明 connection handle 和已认证设备 PeerId；连接事件只能由 Net 角色发送，PeerId 仅代表 Noise/libp2p 设备传输认证，不代表 AgentId 已验证。Net 启动时先从私有输入管道读取 `ASLK` v2 前导：4 字节 magic、u16 BE 版本、u32 BE 密钥长度、1 字节回环群开关（`0` 关闭，`1` 开启），随后是最多 1 KiB Ed25519 libp2p protobuf 密钥。该前导不是 IPC 帧；未知版本、格式错误或超限在分配正文前拒绝。Net 解码密钥后以 IPC kind 16 `NetReady` 返回 PeerId，Supervisor 将其与 DPAPI 本地设备身份比较，不匹配则终止子进程。本机 Agent 根身份也由当前用户 DPAPI 在启动时 create-once 加载或生成，但不等于链上身份状态已验证。身份证明请求/应答复用 `/asl/identity-proof/1.1.0` 的规范 CBOR 帧，额外绑定 connection handle；入站请求另带不透明 response handle，Core 回答时必须原样带回。每种 IPC 消息在读取 body 前执行自身长度上限。运行时将 handle 绑定活动连接、将 response handle 绑定原请求，并在断开后使旧句柄失效。Net 子进程连接表、传输事件/命令、身份证明转发和 `CoreAdmission` 身份闸门现已实现；Supervisor 启动时加载本地链状态 resolver 和签名设备目录，并只对通过链身份验证的本机 Agent 建立准入状态。常驻事件泵只向本地 handler 交付通过身份准入的 peer 事件，回调生成的控制/bulk 出站命令再次校验；缺少本机准入状态时关闭远端连接。默认命令行入口不接入 Agent 会话处理，不代表应用会自动回答消息。

T24 增加本机 IPC kind 41 `RunExtractorTask`（仅 Core -> Extractor）与 kind 42 `ExtractorResult`（仅 Extractor -> Core）。请求固定为 task ID、`PdfText`/`Avatar` 枚举、u32 BE 长度和输入字节；单帧上限 4 MiB。结果固定为 task ID、`Completed`/`Rejected` 枚举、u32 BE 长度和输出字节；PDF 文本最多 2 MiB，头像最多 64 KiB。拒绝结果不含正文。Extractor 没有文件路径、网络或可继承文件句柄；Core 只提交已在内存中的文档并按 task ID 关联一次性响应。

后续接线状态（2026-11-19）：Net 子进程连接表、传输命令/事件及身份证明转发已接通；`CoreAdmission` 在同一 IPC connection handle 上协调 Hello、身份链证明和设备目录核验，并在核验前拦截控制/bulk 业务事件及出站业务命令。准入失败通过 IPC kind 32 `CloseConnection` 关闭对应传输连接。Supervisor 从本机严格版本化信任配置、有效链状态和签名设备目录构造绑定自身根 AgentId 与实际 Net PeerId 的 Hello/准入状态；缺少配置、目录或链上 Active 身份时不开放业务消息。常驻事件泵将已准入事件交给本地 handler 并校验其出站命令；Agent 会话处理尚未接入，默认命令行 handler 静默。启动后的周期同步和首次注册仍未实现；传输目前限 loopback，公网策略与完整 T14 尚未验收。

T27 直连集成（2026-11-20）更新了上面的历史接线状态：常驻命令行入口现在可以在用户本机允许回答后处理已准入的直接 query，缺省仍静默。检索只用结构化词表，回复沿用已定义的 `Answer` 或 `Offer`，不新增公网线字段、文本消息、文件读取或传输能力。本机 IPC kind 43 `ReplyDirect` 仅 Core -> Net，携带原 connection handle、原 response handle、u64 BE 有效期限（毫秒）和既有控制帧；Net 在送交传输前核对期限、回复类型及单次句柄。已通过 Core 授权并交接的回复不会延长有效期。

IPC kind 38 `DiscoveryCandidate` 仅由 Net 发给 Core，正文为 u16 长度加规范 PeerId、传输类型、SocketAddr 和状态枚举（1=Discovered，2=Expired），正文上限 151 字节。它只表示通过本机地址策略筛选的 mDNS 候选元数据，不表示传输连接已建立、Agent 身份已验证或节点在线，也不授予联系人、查询或文件权限。Supervisor 将其转换成不产生网络命令的 `LocalNetworkObservation`，只交给单独的只读观察回调，不进入 Agent 业务 handler；默认事件泵不显示或持久化该观察。

IPC kind 44 `FindProviders` 仅由 Core 发给 Net，固定包含非零 lookup ID 和 32 字节 DHT key。kind 45 `DhtProviders` 仅由 Net 发给 Core，包含 lookup ID、完成/失败状态及最多 20 个去重 provider 候选；每个候选只含规范 PeerId、可选的 TCP/QUIC SocketAddr 和已配置 relay 路由标志。Net 只从本地 provider/routing 地址中选取符合当前地址策略、且 PeerId 绑定一致的直接端点；无可用直接端点时不携带地址。候选及地址均为不可信发现数据，不表示 Agent 身份、资源内容或授权。Supervisor 将结果作为本机只读网络观察交给当前出站查询状态机；只有 CoreAdmission 提供的已准入连接才会收到 ASL Query。`network-settings-v1.json` 的 `bootstrap_multiaddrs` 现在会在启动/恢复时按当前地址策略逐个拨号；显式 public grant 的 content/concept hash 会进入 provider 发布集合。打包发布仍需提供真实、可达、签名的 `assets/network-seeds.json` 并完成冷启动公网验收。

接收侧 IPC kind 27 `BulkReceived` 携带连接句柄、Net 端记录的原始本机请求 ID，以及通过 `/asl/blob/1.0.0` 响应关联校验的 BulkResponse。Core 再按当前准入的 AgentId、PeerId、连接、请求 ID 和期限匹配一次性待决请求；ASL blob 线上格式不变。匹配成功的普通 Bulk 响应通过 `BulkTransferResponse` 回调；未匹配响应不会交给调用方。

本机网络处理器发出的 `FetchRequest` 按 Net 返回的原始控制请求 ID 关联 `FetchGrant`；Grant 的 `message_id` 独立，不用于关联。Core 检查同一准入连接、AgentId、PeerId、内容 ID、文件大小上限和 lease 期限，再在该连接发一次 manifest 请求。Bulk 响应的有效期取请求超时、会话和 lease 期限的最早值。清单按 `content_id` 校验，文件大小与 Grant 一致后，Core 才发出 `FetchManifestReceived` 本机事件，保留原请求 ID 和 root task ID。若收到的原始清单字节确实哈希为所请求的 `content_id`，但不符合固定清单格式，Core 交付关联的 `FetchManifestCorrupt` 本机事件；错哈希、Grant 大小不符或过期响应均不产生该事件。这些事件不产生磁盘写入授权，也不自动下载文件或接受 Offer。

控制与身份证明子流各只承载一个 request-response 帧。接收端先读取 4 字节大端长度，在验证对应通道上限后才分配 payload；读满后要求发送端关闭写半流，不接受尾随帧。控制 codec 只接受 `WireFrame::is_control` 帧，身份证明 codec 只接受方向正确的身份请求/响应。codec 只负责线格式与大小边界，不认证 AgentId、不授权业务操作、不匹配请求 ID，也不证明链状态；这些检查由 Core `DeviceSession`/`CoreAdmission` 执行。任何未经过该身份闸门的调用路径，都不得把控制/bulk 消息交给 Agent 或据此生成业务回复。

控制连接经 libp2p 认证与加密。传输握手认证设备 PeerId；ASL hello 携带 AgentId 和设备证书。双方按需在独立 identity-proof stream 交换证明：request 的 checkpoint 字段绑定请求方本机已接受的 finalized block hash，不能由对端指定信任根；响应必须精确匹配 request ID、AgentId 和 checkpoint。响应包含 finalized height/block hash/state root、完整 EIP-1186 account verifier inputs（nonce、balance、storage root、code hash、nodes）、恰好三个 `{slot: bytes32, value: bytes32, nodes}` 路径，以及最多 8 KiB 的身份根签名 device-directory record。链 ID、registry address 和可信状态根只取本机已验证配置/轻客户端；controller、commitment、sequence、revocation 等状态由 Core 运行现有 Ethereum MPT 验证器从槽值解码，不采信对端派生字段。随后 Core 验证签名目录、链上 commitment/sequence、当前证书和传输 PeerId。每条路径最多 32 个节点、每节点最多 2 KiB、总帧 256 KiB。证明必须来自请求中指定的 checkpoint；对端无法提供时握手失败，不接受它建议的新 root。昂贵验签/证明验证必须经过每连接及全局预算闸门；验证成功前只放行有界 hello/proof/pair 消息。

`/asl/identity-proof/1.1.0` 修正此前 1.0.0 线格式与现有验证器不兼容的问题：旧结构省略账户 trie 验证所需字段、用 64 位 storage slot 且携带未经验证器推导的注册状态。本项目尚未发布，故直接冻结新的 1.1.0，禁止静默兼容旧结构。身份目录作为签名记录随身份证明返回，避免为目录另造信任根或额外发现步骤；记录本身仍须按第 3 节完整验签和核对当前链状态。

PAIR invite/exchange 使用整数键 CBOR。邀请携带 0 至 120 个 Unicode 字符的可选单句说明；拒绝换行、控制字符和句中多个句末标点，说明内容纳入身份根签名和 transcript。nonce 为 256-bit 随机值，不是低熵口令；身份通过已验证链状态下的身份根签名校验。邀请需本机用户明确批准才可接受，只建立 AgentId 本地 pin，不改变文件/目录授权。提示限额为每 AgentId 每 24 小时 1 次、本机每小时 20 次、最多 5 个同时待处理提示；超限邀请得到签名拒绝，不弹提示、不建立联系人。

### 群子流

`group-envelope` 外层不变：非零 16 字节消息 ID、非零 32 字节线上群 ID、`0..=2^63-1` epoch、操作码及最多 65,536 字节载荷。操作 `0` 是完整 TLS 编码的 MLS 1.0 `PrivateMessage`（Application）；解密后只接收 CDDL 的 `group-application`，其中 ASL/1.3 可包含 `act` 或群主 `group-policy`，其他应用帧仍不接受任意文本。操作 `1` 的载荷必须单独按 `group-membership` 做第二次确定性 CBOR 验证（数组首项为版本 `1`），不接受自由文本。其 MLS 对象字段最多 65,408 字节且必须是无尾随数据的完整 TLS 编码 `MLSMessage`。KeyPackage 必须是一次性包；Welcome 只含指定包引用的一个收件项，携带 ratchet tree 扩展，新成员叶子必须与已提交 KeyPackage 的叶子一致。群使用固定套件 `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`；Commit/SyncCommit 必须是该群、该基础 epoch 的 MLS `PrivateMessage`（Commit）。

| 请求 | 允许的回复 | 回复 epoch |
| --- | --- | --- |
| Application、Invite、InviteRequest、Commit | Receipt | 请求 epoch |
| KeyPackage | Welcome，回显邀请 ID | 请求 epoch + 1 |
| SyncRequest | SyncCommit、AtHead、SyncUnavailable | 请求 epoch |

Invite 通过 envelope 的消息 ID 标识邀请，写明目标 AgentId、目标 PeerId 和过期时间；不带群名、成员表或留言。InviteRequest 由希望加入或重新加入的设备发往群主，使用 `epoch=0` 表示请求方不知道当前 head；群主收到后必须以当前认证连接、群创建者和活动房间重新绑定 AgentId/PeerId，再把请求写入短期本机审批队列。该请求不携带群名、自由文本或成员资格推断。KeyPackage 是接受邀请后的新请求，显式携带原邀请 ID。每个回复必须匹配原请求的消息 ID、完整群 ID 和已认证对端。Receipt 只表示收到了对应请求，不表示同意入群、持久写入或资源授权。

ASL 创建者证明是 MLS `GroupContext` 的私用扩展 `0xF720`，不改外层 CBOR。扩展数据是 `0x01 || random_nonce[32] || creator_agent_id[32] || canonical_creator_peer_id[1..128]`，线上群 ID 是 `SHA-256(ASCII "ASL-MLS-ROOM-v1\0" || extension_data)`。`RequiredCapabilities` 必须列出 `0xF720`，每个叶子必须声明支持；创建者使用当前已验证设备，身份承诺在同一群内不可变。收到 Welcome 时须独立重算承诺，从已验证树中定位该 AgentId/PeerId 的叶子，再要求 MLS 签名者索引与该叶子相同，且设备证书与原邀请和当前认证连接一致。不能以 Welcome 签名者、叶子序号或未验证 SQL 角色推导创建者。缺少扩展或必需能力的开发房间不能通过 Core 对账，不自动升级或启用群权限。不支持该能力的旧开发 KeyPackage 不能在此房间重用，需重新邀请和审批。

同步绑定值是 `MLS-Exporter("ASL group sync binding v1", "", 32)` 的 32 字节结果，不发送原始 epoch authenticator。服务方必须独立从请求 epoch 的已提交状态取得绑定并作比对，且只服务当前有效成员；该 epoch 是本机持久 head 时回 `AtHead`，否则一次最多返回一个连续提交。缺少记录、分支不一致或无法复核成员身份时不能返回 `AtHead` 或提交。单一 `AtHead` 回复不能恢复授权；请求方仍须核对本机持久状态、链身份和群策略。

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

记录验证：kind、长度、根密钥签名、AgentId owner、时间窗口、最大 TTL、sequence 单调性、payload CDDL、记录键与 owner/kind 的绑定全部通过才入库。net 使用 Kademlia `FilterBoth`，将入站 PUT 暂存为限量候选并通过私有 IPC 交 Core；Core 使用当前链状态 resolver、`verify_record` 和本地 `RecordHistory` 决定接受或拒绝。Core 未启用、身份非 Active、签名/键/时效/序号检查失败时均明确拒绝；候选在通过前不会进入 DHT store 或 Agent handler。provider PUT 是不同类型的未认证发现指针，不得等同于身份声明；其 PeerId 地址仍经本机网络策略过滤，后续身份握手独立验证。

identity record key 使用下列域分离派生，禁止共用键或接受任意 key/value 配对：

```text
profile key = BLAKE3("ASL-PROFILE-v1\0" || agent_id_bytes)
device directory key = BLAKE3("ASL-DEVICE-DIRECTORY-v1\0" || agent_id_bytes)
short-code claim key = BLAKE3("ASL-SHORT-CODE-CLAIM-v1\0" || agent_id_bytes)
```

短码的多候选发现键只用于 provider 查询，不作单值 record key。Agent 完成直接身份验证后，短码声明使用其按 AgentId 隔离的短码记录键读取；因此短码碰撞不会发生单值覆盖。记录和 provider store 均有单值、数量、地址及总字节上限。DHT store 与防回滚观察当前为本进程内存状态，不能视为重启后的持久记录或高水位。

`kind=2` 的 device directory 严格包含版本、AgentId、最多 64 个设备证书及撤销 serial；同一目录不得重复 PeerId 或 serial。设备证书有效期最多 30 天，目录自身最长 30 分钟并周期续发。目录的规范 CBOR commitment 必须与链上 `stateCommitment` 匹配。已钉住联系人本地记住见过的最高目录 sequence/设备 serial，拒绝回滚。断链期间无法证明最新全局撤销状态，GUI 不宣传离线撤销的实时保证。

profile 最长 30 分钟、每 5 分钟重新发布；相同 sequence 只接受完全相同字节。撤下资料后不再续发，旧资料可能存续至 TTL 或远端缓存过期。profile key 基于 AgentId，签名者为身份根，避免设备轮换改变联系人身份。

本机 Core → Net IPC：kind 56（16 字节操作 ID、32 字节 AgentId）准备发布，查最近邻；57（同 ID、1 至 8192 字节签名记录）提交 PUT；58（原操作 ID、独立回执 ID，各 16 字节）取消。kind 59（16 字节操作 ID、32 字节目标 AgentId）按派生的资料键执行 GET。Net 复用 kind 19/20 回报操作结果；GET 启动不代表命中，候选记录仍须进入现有验签路径。PUT 应答不代表接收方已验签。线上记录 CBOR 不变。

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

持久短码按固定版本算法从 AgentId 派生，显示为分组十进制数字。短码只提供查找便利，不是身份、认证凭据或全局唯一名称。DHT 使用 `BLAKE3("ASL-HANDLE-v1\0" + 16 位补零十进制 ASCII)` 查找，并通过可返回多个 PeerId 的 provider 记录发现候选。任何候选均不代表 Agent 身份或授权；直接握手得到 AgentId 后，Core 验证链状态、根签名设备证书和 PeerId，再计算短码并过滤候选。碰撞保留多个已验证候选，由本机授权具体目标。DHT 隐瞒、日蚀和离线仍可能造成漏查。

固定 1.0 派生算法：`n = LE64(BLAKE3("ASL-HANDLE-ID-v1\0" || agent_id_bytes)[0..8]) mod 10^16`，左侧补零至 16 位，界面按每 4 位分组。输出碰撞是合法状态，禁止抢占/覆盖或声称全局唯一。数字短码只用于发现，不进行链上注册，不作为凭证。身份解析通过版本化 `IdentityResolver` 接口。

当前活动配置不接受 `/asl/pair/1.0.0` 邀请或响应；旧类型仅保留作协议迁移兼容，Core 会关闭携带旧配对事件的连接，不生成提示或回执。短码查找通过 DHT provider 获得不可信 PeerId 候选，拨号后必须先通过链身份、设备证书与认证 PeerId 校验，再由本机用户在联系人页明确绑定。绑定只固定本地 AgentId/PeerId 观察，不会自动加入 `authorized_contacts`，也不授权查询、目录、资源、文件或群组。短码不是秘密、认证因子或全局唯一名称；公开 provider 发布默认关闭。

短码 provider 记录最长 1 小时，Net 负责本地续发与撤下；Core 只在用户显式启用公开短码且身份准入有效时发出 provider 操作。provider 记录只提供路由发现，不承载身份声明。应用只把它视为候选节点，必须直连验证。入口与 provider 地址先经本机地址策略过滤，禁止借远端地址驱动 HTTP、SMB、文件协议或系统命令。

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

一次确定性搜索 10 秒。旧 `query/answer` 的 3 回合/6 条限制只是兼容检索路径，不适用于 ASL/1.3 act 对话；act 不按固定回合数或消息数截断，由用户授予的可续期预算和本机资源上限终止。offer 不自动延长预算。消息 ID 去重 10 分钟，容量最多 20,000 条，超容量丢弃最旧过期项；无可清理空间则拒绝新入站任务。

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

每下载最多 4 个来源，每来源 2 个并发请求；调度优先缺失块、再处理超时块。Net 按已认证设备 PeerId 对实际在途的 manifest、chunk 和 inline 请求共享两槽上限，直到传输报告响应、失败或连接关闭；Core 命令入队及本机调度超时都不会释放 Net 的占位。Net 无槽时按原请求 ID 返回本机容量失败，不向远端发送请求。3 次坏 hash 后禁用该来源于当前传输，记录完整性证据，不用贡献抵扣。

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
