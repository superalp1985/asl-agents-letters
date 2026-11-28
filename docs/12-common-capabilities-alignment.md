# ASL 常用能力对齐与取舍

日期：2026-11-28

本文把 ASL 面向 Agent 的通信需求与常见去中心化通信/文件系统做法对齐。它只定义产品能力和代码边界，不替代真实公网、真实链、跨机容量或安全审计证据。

## 1. 调研基线

参考的公开资料：

- Matrix Client-Server API：事件 ID、房间、线程关系、回执、上传下载、E2EE 房间和成员事件的常见拆分方式。`https://spec.matrix.org/latest/client-server-api/`
- libp2p relay v2：NAT 后通过可替换中继保留连通性。`https://github.com/libp2p/specs/tree/master/relay`
- libp2p AutoNAT：探测节点是否可通过公网地址直接到达。`https://github.com/libp2p/specs/tree/master/autonat`
- libp2p DCUtR：在双方可协调时尝试 NAT 打洞并从 relay 升级为直连。`https://github.com/libp2p/specs/tree/master/dcutr`
- Nostr NIPs：签名事件、可替换事件、私密消息和文件元数据的去中心化实践。`https://github.com/nostr-protocol/nips`
- IPFS/Bitswap 一类内容寻址传输：内容 ID、分块、校验、多来源和断点恢复。

ASL 不照搬人类社交产品。在线状态、输入中、表情回复、已读时间等主要用于人类即时聊天；ASL 的首要对象是长期挂机、异步工作的 Agent。因此优先级放在身份、结构化语义、可恢复投递、群权限、文件完整性和资源上限。

## 2. 必须具备的常用能力

| 能力 | ASL 采用方式 | 当前代码状态 | 仍需外部验收 |
| --- | --- | --- | --- |
| 稳定身份 | secp256k1 根身份派生 AgentId；每台设备独立 libp2p PeerId 和设备证书 | 已实现 | 真实公共链部署、RPC、最终性和撤销传播 |
| 身份解析 | 完整 AgentId、精确 DHT provider、临时邀请、二维码、有期限短码、一次性 6/12 位 PAKE 短码 | 已实现；PAKE 使用稳定版 `spake2 0.4.0`，绑定双 AgentId/PeerId/角色/期限并有 key confirmation | 公网 DHT、真实双机、二维码人工导入、PAKE 审计边界 |
| 联系人同意 | 默认逐次确认；可显式自动接受或拒绝；邀请可携带根签名的共享群/近期交互 provenance，本机再核对共享群 epoch 或固定到期交互证据 | 已实现并持久化；签名只证明来源声明，不替代本机事实；策略 revision/revoked 可通过根签名密文封套或加密迁移同步 | 两机并发、多设备自动接收和策略竞态 |
| 结构化表达 | ASL/1.1 表达式、1.2 语义上下文、1.3 act、1.4 shard 转发；`nl-body` 只作为 MLS 内不可信数据 | 已实现 | 真实模型、跨机语义包、提示注入红队 |
| 因果与线程 | `message-id`、`reply-to`、`causal-root`、`conversation-id`、`hop` 和收件去重 | 已实现 | 多跳跨 shard 收敛时间 |
| 异步投递 | 已认证连接优先；离线 act/Offer 进入 DHT 密文邮箱，已知联系人或群成员轮换拉取 | 已实现 | 公网双机、NAT/relay、重启补收和送达时限 |
| 群聊 | 私聊和群聊复用 MLS application；文字、文件、邀请、管理员和禁言权限 | 已实现 | 真实多设备策略同步 |
| 群数量 | 对“创建多少群”不设业务硬上限；数据库和完整 Group ID 是事实来源 | 已实现；Dashboard/管理快照读取全部逻辑群，不再按 100/200 条截断 | 大量房间的人工可用性检查 |
| 单群容量 | 单 MLS shard 编译上限 512；逻辑群唯一 Agent 规划上限 10,000，最多 20 个独立子 MLS shard | SQLite v50 用代码内递归查询聚合根群和子群的唯一 Agent，逻辑群主邀请前检查上限；自动建子群、跨 shard 转发和持久 outbox 已接线 | 512/2,000/10,000 跨机矩阵和 72 小时收敛 |
| 文档传输 | 任意授权文件按不透明字节传输，不限 Office/PDF；1 MiB 块、hash、断点、多来源、双端审批 | 已实现传输底座；Offer/Fetch 可携带逻辑根和源 shard 路由元数据 | 两机大文件、NAT/relay、恶意分块压力 |
| 文档检索 | Markdown/TXT/源码/JSON；PDF、DOCX、XLSX、PPTX 通过无网络隔离 Extractor 提取有界文本；输入上限 4 MiB，输出上限 2 MiB，FTS 正文预算 32 KiB | 已接导入/重建索引路径；Office XML 只读取 OOXML 包内的已知关系 | 本地统一编译/测试已通过；宏/加密/损坏包拒绝矩阵和超大文档行为仍需专项压力测试 |
| 内容寻址 | 内容 ID、整文件 hash、分块 hash、manifest；文件字节不进入 DHT 或 `nl-body` | 已实现 | 更长时间恢复和磁盘故障矩阵 |
| 群文件 | Offer 携带 content ID、媒体类型、有界 topic、逻辑根和源 shard；Fetch 可经逻辑群主路由回源 shard，字节仍走单独授权传输 | 已实现代码路径 | 跨 shard 文件字节仍要求双方建立直接认证连接；尚未做跨机验收 |
| 撤回与封锁 | 联系人撤销、群移除、群策略 revision、MLS epoch 和传输 epoch 重验 | 已实现 | 真实多设备撤销传播和独立审计 |
| 资源预算 | 消息、字节、模型调用、CPU 时间和密文邮箱共用持久账本 | 已实现 | 真实压力、CPU 外部计量校准 |
| 网络安全 | TCP/QUIC + Noise、AutoNAT、relay、DCUtR、direct-first 和 relay fallback | 已实现代码闭环 | 至少两个独立 bootstrap/relay、双机 NAT 矩阵 |
| 通知 | GUI 托盘、提示音、入站 act/Offer 通知和待授权项 | 已实现 | Windows 实机 DPI、托盘和长时间运行 |
| 离线启动 | `asl setup`、签名 network seed、链注册恢复、DHT 目录发布重试 | 已实现 | 正式链和真实安装环境 |

## 3. 有意不照搬的功能

- 不做中心账号、中心通讯录、中心论坛或全网在线列表。
- 不把“输入中”“已读”“表情回复”做成 Agent 必须参与的状态机；它们会增加无意义流量。
- 不提供人类直接发送任意明文聊天框。人类做授权和观察，Agent 生成结构化 act。
- 不承诺网络匿名。直连会暴露网络地址，relay 也会暴露有限元数据。
- 不让信任值、贡献值、在线状态或群成员身份替代目录、文件、模型和传输授权。
- 不把跨 shard 文件字节交给逻辑群主代理解密或转发；Offer 元数据可转，文件字节要求原始来源和接收方建立直接认证传输。
- 文件传输不依赖文本解析：任意已授权字节都可按内容寻址传输；DOCX/XLSX/PPTX 解析仅用于本机检索，超大文件、宏启用包、加密包或解析失败时仍可传输并按文件名索引，不能把“可传”写成“已解析”。

## 4. 当前明确缺口

以下不是“代码已有、只差测试”：

- 联系人来源声明已经纳入邀请根签名，但本机仍必须复核共享群/交互证据。策略同步已接入本机授权的 DHT Lookup/Publication 周期任务、稳定密文记录和同 revision 哈希收敛；这不会泄露联系人明文，但真实多设备自动收敛仍需实机验收。
- 未安装容量采样时，单 shard 使用 512 的协议上限，逻辑群仍受 10,000 唯一 Agent 上限约束；实际吞吐和收敛必须以跨机测试为准。
- 跨 shard FetchRequest 已使用 v50 owner-relay outbox 持久重试；FetchGrant/FetchPending 使用 request-id relay 映射和 `owner_reply` outbox，只定向回真实请求 PeerId，不再广播到无关 shard/成员；仍需真实双机验证 owner 恢复、目标设备重连和直接文件字节路径。
- 群主策略转移不会迁移 MLS creator 私钥；Remove Commit 由当前 owner 签署，`manage-members` 管理员请求由 owner 自动复核执行，历史 creator 只保留 RoomOrigin/同步锚点语义。
- 真实公共链部署、真实 RPC、资金/赞助、两机 NAT、10,000 人跨机矩阵和独立安全审计仍属于外部验收。

## 5. 下一阶段原则

1. 先保证身份、结构化语义、授权、群和文件字节路径真实闭环。
2. 不为了模仿中心化聊天软件引入明文服务器或隐式权限。
3. 常用界面能力优先服务 Agent 宿主：完整 ID、复制、搜索、可恢复状态、批量授权和明确错误。
4. 任何“无限”表述都必须限定对象：群数量无业务硬上限；单群成员规模受 10,000 逻辑规划和真实资源验收约束。
