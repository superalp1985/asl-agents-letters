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
  credentials/provider-v1-<config-fingerprint>.dpapi
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

`state/model-providers-v1.json` 是本机版本化 provider 注册表，保存显式 endpoint、模型名、远端/本地模式、启用状态和请求时限，不含 API Key。`enabled_by_user` 仅使该配置可供审批；当前授权指纹另存于 SQLite `settings` 的 `agent.model_provider_approval_v1.<id>`。授权必须匹配完整配置的 V1 指纹。`credentials/provider-v1-<config-fingerprint>.dpapi` 只保存该精确配置的 DPAPI 密文；旧的仅按 ID 命名的凭据不会自动复用。远端 provider 必须有凭据，本地 loopback provider 可不配置凭据。

Core 每次调用读取当前配置与授权，并在交给 HTTP 客户端前重查两者；撤销阻止后续通过检查的请求，不取消已经交给客户端的请求。网关固定向登记的 endpoint 发送请求，不跟随跳转、不读取提示词中的 URL；每次调用还须独立验证每份输入绑定 provider 与本地/远端模式的 `ModelInput` permit。注册表缺失或不合法时不调用模型，不影响对等服务启动。`asl-core --providers list` 仅输出配置、指纹及授权状态，`allow <id> <fingerprint>` 只批准核对过且仍一致的配置，`revoke <id>` 可在原配置已更换或删除时清除旧批准。这些命令不接收 API Key。

路径全部由程序用已验证 ID 推导，不能从 peer、模型或文档中接受路径字符串。存储命名空间按对象种类区分，不提供裸块 hash 读取 API。程序自身密钥、凭据、数据库、缓存和 logs 禁止被普通共享 grant 覆盖；头像/经验只有显式生成的资源引用可发布。

## 2. 数据表

当前版本为 SQLite v43。v35 新增密文邮箱槽/分片、持久会话预算、act 事件、附件引用、gossip topic 和容量测量表；v36 新增群主策略投影和成员角色/禁言/权限投影；v37 新增有期限联系人邀请、一次性消费 receipt、Pairing 确认提示和 CLI/Core 动作队列；v38 新增有界、短期有效的群加入/重入请求；v39 新增不含 MLS 快照的迁移群线索；v40/v41 增加 DHT 持久缓存与群主设备字段；v42 增加逐文件权限、委派管理员能力和同 key 多 provider 缓存；v43 增加不保存正文的 Act token 哈希索引。`group_file_policies` 的 key 是本地群 ID 与 32 字节内容 hash，只保存 read/send/fetch 位，不保存文件名或路径；`group_admin_capabilities` 只保存活动管理员 PeerId 与能力位。两项均在 `apply_group_control` 的同一事务内整表替换；管理员禁言只能提交与当前 owner 策略 revision、权限、owner、文件策略和能力位完全一致的 muted 快照。`conversation_act_semantic_index` 只保存域分离 token 哈希、room/act ID、方向和类型，默认保留 365 天；正文到期删除后仍可返回引用和命中分数，但不会恢复明文。DHT 邮箱投递、Core/Net 命令和已知联系人或群成员轮换拉取已接通；送达回执和真实公网/NAT/relay 验收尚未完成。`specs/schema-v20.sql` 为群事件增加可空的 `browse_kind`，v21 增加独立的 `browse_expires_at_ms`，迁移时仅为原本可见的事件保留原期限。验证通过的群来信在提交密文和接收状态的同一事务内读取本机浏览授权与保留期限。仅在允许浏览且期限非零时写入消息类型与活动页到期时间，不延长群事件的原期限。缩短期限会在设置事务内清除过期的浏览字段，选择 0 天会清除全部浏览字段。群事件密文、去重和同步记录沿用原策略，这不是密文擦除。

v22 增加 `observed_remote_profiles`，保存 Core 已验签的远端公开主题投影。每个 Agent 一条、总量最多 200 条，不保存头像或原始报文。只读面板按有效期、链观察与本机撤销状态过滤；该表不用于身份、权限或信任判定。

v24 为同一投影增加可空的 `avatar_content_id`。旧资料不补填。新验签的资料按同一序号规则替换或移除引用；仅有头像引用的有效资料也可展示。引用不是图片、下载授权或可信本机路径，不写入资源索引。

v25 的 `local_avatar_selection` 和 `avatar_reference_grant` 各至多一行。选择存清洗后的字节、清洗版本和随机代次；旧偏好仅供显示，不补授权。专用 grant 绑定身份、资源、grant ID/epoch 和 ASLMNF01 清单 ID，不出现在共享文件、索引或模型输入中。换图/移除与撤销旧 grant 在同一事务内，撤回保留预览但更换代次。这里批准的是资料引用，不是文件传输。

v26 的 `avatar_receipts` 仅供接收方使用。迁移不为旧引用创建请求。全库最多一个待收请求，有效期不超过 60 秒及对应资料期限；完成后只保存最多 64 KiB 的清洗结果。已接收的图片不因缓存命中而变成可搜索或可转发的资源。读取仍检查本机身份、远端资料版本、绑定和链检查点。

数据库按 `specs/schema-v1.sql` 至 `specs/schema-v19.sql` 连续迁移。v2 增加本地导入预留与授权版本绑定；v3 清理失效本地引用的全文索引，在撤权、替换和删除时随事务移除对应索引行，不影响同内容的其他授权。这不是对磁盘或备份的安全擦除。v8 增加派生知识的公开继承标记、独立写入目录身份绑定及写入引用表；v9 为资源增加本地来源 AgentId 归因，既有资源默认无归因且不能获得贡献分；v10 将下载 manifest 字节与暂存文件身份绑定持久化，移除依赖 manifest 路径的旧列。v11 为本机直连下载确认补上目标文件名、大小和来源集合；旧的未绑定记录不作放行凭据。v12 增加线上群 ID 与本地房间键的一对一映射和密封状态存储。v13 记录入站群邀请的提示额度、审批后的一次性密封 KeyPackage 和消费状态；提交 Welcome 候选时一并写入新房间和成员投影。v14 增加出站定向邀请，并在发方将 Welcome 与 MLS 快照、成员变更和提交事件一起落盘。v15 增加连续同步提交历史，按每群最多 256 步及 7 天保留；只记录新提交，不回填旧事件。v16 将下载同意和持久传输绑定到本地群 ID、成员 epoch、目标写入 grant 与 grant epoch；成员增删推进 epoch 后，旧群同意、旧租约和旧块请求不能继续使用。v17 为上传确认保存认证目标设备、文件名和文件大小，并为按内容、授权版本、目标设备和群 epoch 去重查找建立索引。v18 将原有本机 AgentId pin 迁移到 `contact_bindings`，新增已核验的短码候选及有界本机动作队列，并以本机设置记录短码是否允许通过 DHT provider 发布。撤销时原子移除相关联系人授权和旧 pin；绑定本身不创建联系人查询授权、目录读取权限、文件权限或群组权限。v19 增加本机直连观察记录，仅保存 AgentId、设备 PeerId、结构化意图/主题编号、约束数量和结果形状；不保存自由文本或约束值。记录按 AgentId/消息 ID 去重，最多保留 200 条、每条 7 天，到期时在 Core 启动或新请求入站时清理。链证明缓存最多 128 个 Agent proof、合计最多 32 MiB，按 TTL/LRU 清理；单个 proof 最多 256 KiB。本机准入另在内存保留其已验证证明，不受对端 LRU 淘汰影响，仍受原时效和链观察限制。DDL 的存在不代表所有应用事务都已实现。

T06b 现已实现链状态、身份观察和证明缓存的原子事务，DDL 字段不变。永久身份观察单独设 10,000 项硬上限；满额拒绝新的观察，不静默删除高水位或撤销记录。DPAPI 保护的本地快照绑定完整链配置与上述行的摘要，恢复先验证完整性与配置，再重验未过期证明。写失败或并发旧快照覆盖失败后停止返回正向链身份。DPAPI 不提供整库历史回滚防护；同一 Windows 用户恶意程序或已被恢复的整份旧数据库不在此完整性机制的保证内。

运行时仅把已注册或已撤销身份的证明与观察写入数据库。未注册身份的有效不存在证明只进入有界 TTL/LRU 内存缓存，不创建永久 agents 行，重启后回到 Unknown；已有高水位不能被不存在证明降级。存储层只检查行的一致性，不判定证明语义，不能绕过 DurableIdentityResolver 直接写入网络返回的证明。恢复时用当前时间检查过期，再独立恢复历史 LRU 时间，不能用某条记录的旧访问时间清理其他证明。

| 表组 | 表 | 责任 |
| --- | --- | --- |
| 配置/身份 | settings、agents、local_agent_identity、device_identities、local_device_identity、chain_state_cache、identity_registry_states、identity_proof_cache、contact_bindings、contact_binding_candidates、contact_binding_actions、schema_migrations | AgentId/本机根密钥引用、链身份状态/最终性缓存、远端设备证书、本机身份 pin、待核验发现候选及受限动作队列 |
| 节点 | agents、device_identities、peers、authorized_contacts、preferred_peers | 稳定 Agent、设备证书、连接观察、按 AgentId 固定的授权成员和自主偏好，彼此不混用 |
| 授权 | providers、grants、grant_agents、write_grants、transfer_consents | 模型端点、读/披露范围、独立写入和绑定文件/接收 Agent 的确认 |
| 群组 | asl_groups、group_members、group_events、group_access_policies、group_access_members、group_file_policies、group_admin_capabilities、mls_room_states、mls_incoming_invites | MLS 群状态、成员投影、群主策略、管理员/禁言/能力投影、逐文件权限、定向入群邀请与有期限密文事件 |
| 内容 | snapshots、resources、resource_fts、derivation_sources、semantic_context_candidates、semantic_context_resources | 物理内容、授权引用、本机检索索引、溯源和已验证语义上下文候选/精确资源关联 |
| 任务 | tasks、messages、offers、outbox、processed_requests | 有界会话、确定性 CBOR 语义帧、重试与去重；不代表 ASL/1.3 act 已完成 |
| 本机观察 | direct_inbound_observations | 有界、短期的结构化直连请求浏览记录，不含请求正文或回复 |
| 传输 | reservations、transfers、transfer_sources、transfer_chunks | 额度、目标、来源和持久块状态 |
| 证据 | trust_events、contribution_events、model_calls、security_events | 本地评价、调用状态和脱敏审计 |

T19 已将 `tasks`、`messages`、`outbox` 和 `processed_requests` 接入 `asl-store`：旧结构化会话的任务预算、消息方向/类型、有限重试和请求去重在 SQLite 事务中持久化，重启后不会仅因内存状态丢失而再次回答旧请求。`messages.body_cbor` 只保存现有确定性 CBOR 控制帧，不能用来表示 ASL/1.3 `act-nl` 的自然语言正文。这表示旧本地存储路径已实现，不表示真实 Core/Net handler、完整公网会话或所有协议帧的端到端接入已完成。`fetch_grant`、lease 及其他传输授权不写入聊天消息和 outbox。

T27 将 `processed_requests` 和 `direct_inbound_conversations` 接入生产直连处理路径。现有切片在一个事务内占用 AgentId/message ID 去重键并推进旧的 AgentId/root-task 三轮、六条语义消息额度；这是兼容当前代码的旧规则，不是最终对话预算。ASL/1.3 起改由 `conversation_budget_grants` 持久化主体、会话范围、有效期、消息数、字节数、模型调用数和资源额度，续期只能增加新版本，不能通过重连、更换设备或清空内存重置。请求去重跨进程重启和设备迁移保留。直连回复暂不进入 T19 `messages` 或 outbox。SQLite 当前授权与本机回答设置在交给 Net 前再次检查；本地持久化和 CBOR 结构分别验收，不代表公网联调通过。GUI 概览可将本机模式设为关闭、只浏览或回答；默认关闭，设置通过 `asl-core --direct-inbound` 进入同一 Core 控制路径。

MCP 运行时补授收件目录复用 `write_grants`。`settings` 只保留一条十分钟有效的本机请求及决定；只有持有对应等待通道的已认证订阅会话可取得临时绑定，不按宿主名恢复。拒绝、过期或旧请求 ID 都不会授予目录。下载仍按当前目录状态、额度和逐文件策略处理。直连上传在资源读取授权通过后，使用当前已验证会话和证书登记接收设备；该登记不授予联系人或资源权限。

SQLite v28 的 MCP 恢复日志与会话收件授权分离。每份资料最多 64 个一小时内创建的恢复查询，状态变更和游标随任务保留、同事务写入和过期清理。存储本机恢复身份摘要，不保存密钥、正文、Offer 或下载许可。恢复身份更换、查询范围改变或配置关闭后，Core 启动时清空旧记录；读取不提交任何网络操作。

SQLite v29 增加可选的本机请求 ID 和参数摘要。对恢复宿主，判定重复请求、预留任务 ID、记录首次状态在同一事务中，只有新预留可提交队列。接受的重试期限最长一小时，不超出任务记录保留期限。清理带请求 ID 的记录时，同时持久化防回拨时间下限。v28 已有任务旧状态原样升级，不补造请求 ID。

SQLite v30 增加独立授权的查询答复快照，默认不保存。每个任务最多 13 KiB，沿用任务的一小时保留期限与相同的恢复身份核验。快照与任务状态在同一事务中更新，只含已接收的结构化答复和截断标记，不含 Offer、收件权限或下载状态。关闭留存并重启会清空旧快照但保留任务日志；迁移不补写旧答复。

SQLite v31 的显式下载续接授权与查询日志分离。授权绑定已开始的直连传输、当前 MCP 恢复身份、收件目录授权版本和五分钟期限；每份资料最多 16 条。迁移不自动绑定旧传输。续传按原记录选择尚可用的来源，沿用已校验分块与接收目录，重新取得网络许可，不重建待审批项。更换恢复身份或范围清空绑定；撤销收件目录授权或续传授权后不再接受新续传。

群组下载沿用同一续接记录，不增加数据库字段。群 ID 和成员版本取自原传输，恢复授权和续传状态查询都不能把旧版本换成新版本。工作线程还会核对原选来源的设备和成员资格，沿用现有群组 Fetch 与分块校验；不降级为直连 Fetch。群组暂停、版本改变或来源不再获准时，不继续使用已有续传授权。

SQLite v32 的审批状态共享只保存审批 ID 与恢复身份摘要，引用原收件审批，不另建下载或审批。首次读到过期记录时移除共享绑定；原审批被清理时随外键删除。每次读取重新核对恢复身份、收件授权版本和群组成员版本。不复制文件路径、Offer、凭证或批准能力；不自动把旧审批共享给宿主。

SQLite v33 增加 `semantic_context_candidates`，只缓存已通过结构校验的有界签名候选，主键绑定 authority/namespace/revision/digest，不把“已缓存”解释为签名、链身份、依赖图或一致性向量已经通过。v34 增加 `semantic_context_resources`，仅把导入文件中确实观察到、且仍能通过共享句柄授权复验的 `.aslc` 内容与精确语义引用关联；缓存不会扩大该文件的 shared audience。

T34 本机身份绑定切片：SQLite v18 将旧 AgentId pin 迁移为绑定状态，最多保留 200 条待确认/忽略的发现候选及 64 条待办本机动作。UI 从只读 Dashboard 投影展示本机 16 位短码、候选和绑定；修改通过相邻 `asl-core --bindings` 子命令排入 Core 动作队列，不由 GUI 直接写库。发布默认为关闭；启用时只发布短码 provider 指针，搜索只用于发现候选。Supervisor 仅在链身份、设备证书与认证 PeerId 全部通过后记录候选；绑定须由本机明确批准，且批准时要求该精确 AgentId/PeerId 仍处于当前已核验连接。批准不触发旧 `/asl/pair/1.0.0` 请求/响应，也不创建 `authorized_contacts`、资源 grant、群组成员或文件权限；撤销会封锁 Agent 并断开现有连接，重启时从本机撤销状态恢复封锁。动作返回值仅表示排队，不表示绑定、发现或网络发布已经完成；DHT 不可达仍会导致查找失败。尚未包含身份迁移包、公开链注册流程或公网 DHT 可达性验收。

T28 实现类型化派生经验记录：只接收已由 `ValidatedDecision` 校验的 claims；本地生成来源、时间和 `derived_unverified` 标签，模型不能指定路径、验证状态或发布策略。写入目录使用独立 `write_grant`，固定目录身份、create-new 文件和字节额度；每个来源都需通过 `WriteDerived`，公开还需每个来源同时通过 `PublishRecord`，否则仅本地私有。记录以 JSON 落盘并进入本地索引；来源或写入授权撤销后，派生记录级联停用并从 FTS 移除。该切片尚不表示经验收集流程已接入后台自主运行或 GUI。

T29 将本机观察按 integrity/availability/evidence/promise 分开保存；出站请求成功、超时或断连只影响 availability，块 hash 成败只影响 integrity。偏好与信誉读取不写 `authorized_contacts`，检索候选始终从该授权表产生。贡献事件只接受完成任务、匹配任务 AgentId、匹配资源来源 AgentId 且状态为 `verified` 的远端资源；同一 `task_id + content_id + help_kind` 全机只记一次，全 AgentId 共用滚动 24 小时 100 条上限。传输完成、哈希通过或模型自报有用都不会单独记贡献。远端资源来源归因尚未接入完整导入/使用流程，因此缺少来源 AgentId 的资源不会自动产生贡献。

数据库是本机数据边界，不是线上协议：`local_task_text`、资源标题/摘要、模型片段和 GUI 标签可包含本地文本，但不能未经映射复制到 ASL 外层控制帧、DHT 记录或链上状态。ASL/1.3 唯一允许的自然语言是 MLS 解密后的 `act[5] nl-body`；不可信远端正文只能作为本机数据区内容保存和交给模型阅读，不能成为本地策略、系统提示、工具指令、路径或动作。线上控制结构继续使用 `body_cbor` 等有界 BLOB。公开 profile、offer 和语义任务必须遵循 `schemas/asl-v1.cddl`，不得因数据库使用 JSON 或 TEXT 就将这些字段发送出去。

## 2.1 v35 增量存储（底座已实现）

当前 v1–v34 迁移保持不变；v35 已通过新迁移增加下列表。`asl-store::mailbox` 已实现 opaque 密文槽/分片的写入、读取、签收、TTL 清理，以及持久预算授予、有限续期和原子扣减。远程 DHT 记录、Core/Net 邮箱命令、已知联系人与群成员轮换拉取已接线；发送端从本地密文槽构建有界批次，接收端解密后仍须 MLS 成员/epoch 校验。GUI 预算续期、送达回执和真实公网/NAT/relay 补收仍未完成，不能把 DHT 缓存当作送达证明。

| 表或等价仓储 | 责任 | 约束 |
| --- | --- | --- |
| `conversation_rooms` | 私聊/群聊到 MLS group_id、角色、状态和容量等级的唯一映射 | 私聊是两人 MLS 组，和群聊共用 act、预算、历史、邮箱和附件路径 |
| `conversation_budget_grants` | 主体、会话范围、消息/字节/模型调用/CPU/邮箱额度、期限和续期链 | 原子扣减；重启、换设备、重连不能重置；信任值和贡献值不参与授权 |
| `conversation_act_events` | act-id、conversation-id、类型、因果根、reply-to、MLS epoch、处理状态和回复关联；本机正文预览按用户 DPAPI 保护 | 去重与排序使用结构字段；`nl-body` 单独标记 untrusted data，不作为动作来源；群浏览关闭时不写入入站正文，保留期 0 会清除历史 |
| `conversation_attachment_refs` | act 到 blob-ref、offer、下载授权和状态 | 只存引用；字节仍走 `offer/fetch/chunk/hash`，不嵌入 act |
| `mailbox_slots` | 轮换 topic、密文摘要、大小桶、TTL、签收和本机配额 | 只存 envelope 密文与路由元数据，不存 `nl-body`、身份资料、文件名或明文主题 |
| `mailbox_shards` | 分片序号、密文摘要、宿主能力和重组状态 | 不得保存明文；容量不足时明确排队/拒绝 |
| `gossip_topic_state` | 群/epoch 绑定、主题轮换、mesh 健康度和本地资源预算 | 主题不包含群名、Agent 名或长期稳定标签；gossip 只传播密文 |
| `local_capacity_measurements` | 本机容量等级、测量时间和参数 | 只作本机准入与路由选择，不成为身份可信度、权限或收费门槛 |

会话历史、预算、act 事件、附件引用、邮箱和容量表都必须引用当前已验证的 AgentId、设备证书和 MLS epoch。邮箱内容的持久化边界是密文；本机解密后的历史按本地保留策略另存，但必须带 conversation audience、来源和不可信数据标记。清理邮箱槽、密文分片和过期容量样本时，不删除仍有效的共享源文件或未发送的本地 outbox。

秘密不进 settings、messages 或 security_events。日志中的 peer 可截断显示，完整身份只存业务表；lease、API Key、私钥和模型端点认证头不进入诊断。

FTS5 的结果不能直接返回 peer。检索前先确定请求者可读的 resource_key 集合，再以集合约束执行 MATCH。不能先把私有片段交给模型，再指望输出过滤。

## 2.2 v36 群权限存储（已实现）

v36 不改写 v1–v35，只增加：

- `group_access_policies`：每个群一条群主策略，保存单调递增的 revision、成员默认权限位和更新时间。
- `group_access_members`：只保存管理员和禁言投影；群主始终由 `asl_groups.creator_peer_id` 推导，普通成员不需要额外行。

策略只能由群创建者通过 MLS 应用明文中的 `group-policy` 下发。Core 先核对当前 epoch 的 MLS sender 等于创建者，再在同一事务中替换策略、管理员和禁言集合。策略 revision 不能回退；成员从 MLS 群移除后仍保留的旧行不会授予发送权限。群组成员列表和操作入口会把角色、禁言、文字发送、文件发送和邀请权限分开显示。

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

T34 GUI 的目录授权通过受限本机 `asl-core --access` 命令进入 `SnapshotBroker`：共享目录记录固定文件身份、扩展名、audience、单文件上限和派生披露开关；收件目录使用独立的 `write_grants` 与下载授权命令。完整路径只显示于本机授权页，不进入网络消息或远端可控记录。建立共享 grant 不会自动读取目录、导入文件或发布资源；导入、检索、公告和传输仍走各自现有能力及授权判定。撤销共享 grant 在同一事务中推进 grant epoch 与 `policy_revision`、停用其资源引用；后续对外查询按最新 SQLite 授权快照重建/更新 PolicyEngine，块读取继续重验 permit。撤销收件/派生写 grant 同样推进权限版本，写入端必须按当前 grant epoch 重验。纯 `PolicyService` 接口不接受路径，也不代替目录能力管理。

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

**已实现的收件规则：** 不指定活动 inbox 授权不能接收。SQLite `transfer_approval.download_mode` 缺省或 `"automatic"` 时仅在本机选定的授权目录、文件名和额度内启动；`"ask"` 才逐次询问，未知设置报错。直连与群下载共用本机收件模式，群确认还绑定群 ID 和 membership epoch；不开放远端审批入口。示例 TOML 显式选择询问，不代表运行时会自动加载该样例。收件与上传设置独立。

一次同意绑定内容 ID、字节数、本机文件名、写授权 ID/版本及去重排序后的来源 PeerId 集合。待确认时不创建任务、预留或文件；同意与开始分开，消费确认与预留同一事务，创建 `.part` 前再次检查目录身份、授权版本和期限或自动模式。相同申请复用原编号，到期前切换到自动模式也不覆盖已有待处理、拒绝或已消费决定。全机有效窗口内最多 32 项（含拒绝及已消费），本机确认期限缺省 300 秒，可调为 1–300 秒；过期后不可见、不可消费，下一次创建询问时清理。确认不存 lease，不授予获取新数据块的权限。

本机操作针对当前进程 `ASL_HOME` 指定的数据目录。`asl-core --downloads mode` 查看模式；`mode ask` / `mode automatic` 设置后立即供同一目录内的 Core 读取。`asl-core --downloads list` 返回未过期的待决定或已批准项；`asl-core --downloads approve <id>` / `asl-core --downloads deny <id>` 只修改决定。列表不触发下载恢复，命令也不能代为建立目录授权。如果决定时旧清单的 lease 已过期，应用入口需要同一来源、同一内容的新清单；未过期也不表示对端一定在线。

**上传确认：** SQLite `transfer_approval.upload_mode` 缺省或 `"automatic"` 时沿用已授权共享范围内的自动上传；`"ask"` 时每个源授权版本、内容 ID、认证目标设备及可选群 epoch 产生一个本机待决定项。待决定时只返回结构化 `FetchPending`，不签发 lease；因此对端不能读取 manifest 或文件块。拒绝和过期对网络统一表现为 `not_found`。批准只允许同一绑定的 Fetch 重试一次，Core 在发送 grant 前重新核对共享 grant、资源、设备与群成员 epoch，并原子消费批准。块请求不重复弹出确认。

本机通过 `asl-core --uploads mode` 查看模式、`mode ask` / `mode automatic` 设置；`list` 查看未过期的待决定项，`approve <id>` / `deny <id>` 记录决定。命令只操作本地 `ASL_HOME` 下的数据库，不连接远端、不主动传输文件；一次确认不能授权另一个设备、内容版本或群成员 epoch。上传确认与下载确认各自有提示额度，不用信任值或贡献值覆盖授权。

桌面传输页使用同一组只读列表和 Core 命令，分别控制上传/下载模式，并显示待处理及已批准项目。批准仅更新本地决定；下载批准等待相同请求继续，上传批准等待对端重试。面板不创建 Permit、lease 或传输任务，不扩展任何目录、设备或群组授权。

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

下载冷却记录持久化在 SQLite schema v4 的 `transfer_cooldowns` 中；它在冷却窗口内阻止同一 `content_id` 的本机新 `Fetch` 任务和下载创建，不上传、不进入信任或贡献记录。若与本机任务及原请求匹配的 manifest 字节哈希正确但结构无效，工作线程同样记录 24 小时冷却，不建立任务预留或暂存文件。错哈希或 Grant 大小不符不会导致整个内容 ID 冷却。schema v5 增加 `direct_inbound_conversations`，保存直连会话的本地轮次、语义消息预算和到期时间。schema v10 将有界 manifest 字节与暂存文件身份保存在 `transfers` 中，避免恢复依赖单独 manifest 路径。`transfers`、`transfer_chunks` 和 `reservations` 保存下载状态；`assigned` 块在重启时回到 `missing`，`durable` 块必须重新读盘校验。接收目标必须来自活动的 inbox 写授权；写入使用固定目录句柄、create-new 暂存文件、文件身份校验和不覆盖原子重命名。目录额度同时计算进行中的预留与已完成下载；这只约束经本机 broker 建立的任务，不代表可阻止用户或其他进程自行占用该目录。

## 7. 清理、备份与身份迁移

聊天默认 7 天，失败 part 清理上限为 3 天。v27 的收件清理默认关闭，需本机按目录启用，最长 30 天。`asl-core --downloads retention <inbox-grant-id> [1..30|off]` 可查询或修改。只登记启用后完成的新收件。缩短期限会缩短已登记文件的期限；延长不延长已有期限，关闭清除该目录已有的清理计划。清理跳过已有有效内容引用、原文件身份不符、大小或修改时间不符以及已撤权的文件。不扫描或删除目录里的其他文件。

Core 运行循环启动时及其后每分钟清理到期活动。直连观察按保存时的期限删除。直连消息在消息和所属任务均到期且无待发引用后清除，群事件只清除到期的浏览标记，MLS 密文由群协议保留规则处理。下载工作线程分批回收失败满三天、预留已释放的 `.part`，仅处理活动收件授权下能核对原始文件身份的记录。

本机可用 `asl-core --diagnostics <绝对输出文件路径>` 导出 JSON。输出目录应已存在，并与 ASL 数据根分离。报告含程序及数据库版本、上次记录的网络状态及汇总计数。导出读取只读数据库，完成后以不覆盖方式保存所选文件。

清理引用在事务内完成；物理内容仅在没有有效资源/任务引用时回收。source 文件永远不删除。清理使用已固定的应用根句柄，不跟随路径或链接。

本机 DPAPI/keystore 保护身份根密钥与设备密钥。身份迁移是单独的、用户显式触发的加密导出流程，优先复用成熟 `age` passphrase 文件格式，不自创 KDF/AEAD 封装。包内明文归档有固定 magic、主/次版本、AgentId、根密钥 seed、公钥校验值、用户选择的联系人/信任/短期历史、无密钥群线索与清单 hash；不含设备私钥、系统凭据、文件目录路径授权、未选中的共享资料或 MLS ratchet 状态。导入检查版本、AgentId 推导、清单 hash 和所有记录边界后，再建立本机事务。

目标设备导入后必须生成新设备密钥，由根密钥签发更高 serial 的设备证书，并以链上 state commitment 更新设备集合，随后发布签名设备目录。迁移模式下旧实例应先停止；无法联系旧设备或获得最新最终化链状态时，撤销传播可能延迟，不能承诺即时全网撤销。群组通过 MLS 将新设备作为新叶子加入；不复制旧设备 ratchet 状态。目录路径、OS 凭据、grant 和传输中的短期 lease 必须重新授权/生成。

迁移文件只写入用户明确选择并授权的本地目录。`age` 口令由人提供，仅用于本次迁移，不入日志；加密工具负责 KDF、AEAD 和文件格式。未知主版本、截断、损坏、错误口令或清单校验失败均拒绝导入，不做部分身份恢复。

已实现 Windows 本地迁移命令。退出源 Core 后，在 `ASL_HOME` 指向源资料目录的终端运行 `asl-core --migration export <目标文件绝对路径> [contacts] [trust] [history] [groups]`；导出默认只包含身份根。还原用 `asl-core --migration import-new <包绝对路径> <新资料目录绝对路径>`。目标目录不能已存在。口令仅通过交互终端输入。可选短期历史仅包含未到期的直连观察，使用原期限；联系人保留绑定与撤销状态，不继承设备绑定或访问授权。`groups` 只保存最多 512 条完整 Group ID、群名、群主 AgentId 和最后 epoch，目标端写成 `needs_rejoin` 线索；不复制 MLS 快照、密钥或成员资格，成功 Welcome 后删除对应线索。导入生成新设备密钥，显示 `pending_device_registration`。此命令不签发设备证书、不提交链交易或复制网络配置。

迁移明文归档的概念字段如下，具体二进制/归档编码由 T35 与 schema 一并冻结：

```text
magic = "ASLMIG01"
format_version = 1 (u8)
agent_id
identity_root_key_seed
identity_root_public_key_checksum
selected_data_length (u32 big endian)
selected_data_blake3
selected_data_payload (typed JSON, max 16 MiB)
```

身份根密钥 seed 仅存在于 age 加密后的包内；公钥校验和用于发现归档损坏，不替代 age 完整性保护。导出不得修改源身份或删除旧设备数据。恢复只能显式授权；不会在数据库错误时静默重建空授权。恢复后先重验卷、文件身份、grants 与快照，再开放网络。
