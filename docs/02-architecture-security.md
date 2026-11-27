# 架构、安全边界与故障设计

## 1. 最终技术路线

Rust workspace，八个 crate。使用 rust-libp2p 一个网络栈；不同时引入 iroh、iroh-blobs 或第二套 DHT。完整版要求精确标签发现、多个入口、中继、独立文件授权与多来源调度，单栈更便于冻结接口和测试。

固定采用 QUIC + TCP/Noise/Yamux、Kademlia、mDNS、identify、ping、relay v2、AutoNAT、DCUtR、request-response 和 gossipsub。小群通过对已认证成员 direct fan-out 投递 MLS 密文；中大群用 gossipsub 传播 MLS 密文；万人级需要分层拓扑。协议不设 64 人业务上限，路由由本机实测容量决定。gossip 不授予成员资格，也不广播文件清单；不接 IPFS 的公共 DHT 命名空间。OpenMLS 实现 MLS 群密码学，不自行设计群密钥协议。

身份分为本机保护的 secp256k1 身份根密钥与逐设备传输密钥。AgentId 由初始根公钥派生；公共链登记当前控制者、设备状态承诺、序号和撤销状态。每台设备的 libp2p PeerId 由独立 Ed25519 密钥得到，并由身份根密钥签发有期限的设备证书。联系人固定 AgentId，网络连接认证设备。DHT/短码只负责发现。链验证依赖已验证最终化区块头及状态证明；链不能证明真人身份、唯一控制者、善意或设备安全。

链上默认生产配置建议 Ethereum Mainnet + 极小、不可升级、无管理员 EVM registry。T06a 已实现 immutable 合约和本地 Foundry 测试；T06b 已实现本地 Helios/Alloy 验证、有界 HTTP 获取和 SQLite 持久恢复。尚未部署、测量主网 gas、真实多运营商证明服务互测或独立审计。链 ID、地址和实际部署 runtime code hash 通过版本化网络配置提供，代码不硬编码端点或部署地址。ASL 不维护私有链，不收费、不发币。多个独立志愿提交者可替用户提交其签名操作并承担 gas；用户可选自付。若都不可用，新身份保持 pending_anchor，链校验失败只能降级，不能扩大权限。详见 `specs/identity-registry-v1.md`。

P2P 控制协议采用确定性 CBOR/CDDL、整数键、定长标识和版本化概念词表。外层帧、DHT 记录、身份记录、群成员事件、邮箱槽、预算、附件和 MCP 控制消息都不得出现任意文本。ASL/1.3 唯一例外是 MLS application plaintext 内的可选 `act[5] nl-body`：解码器只在 act 正文接受 text string，其余位置遇到 text string 必须拒绝。`nl-body` 是不可信数据，不是命令、路径、策略、动作或寻址信息。

候选依赖版本见 `specs/dependency-baseline.json`。版本已查询，但依赖组合尚未编译；必须在任务 T01/T02/T14/T39 编译探针后形成 Cargo.lock，不由模型自行追最新版。

## 2. 进程与数据流

```mermaid
flowchart LR
  U["GUI：观察/授权"] --> C["core broker"]
  M["宿主 Agent / stdio MCP"] --> C
  C --> DB["策略/SQLite/不可变快照"]
  C --> N["net 沙箱：libp2p"]
  N <--> P["其他节点 / 可替换中继"]
  C --> W["worker 沙箱：受限上下文与结构化对象"]
  C --> X["extract helper：文档/头像"]
  C --> H["获准模型端点 HTTP"]
```

`asl.exe` 是桌面入口和本地 CLI；`asl-core.exe` 是后台 supervisor/broker；`asl-net.exe` 跑网络；`asl-worker.exe` 处理模型输入输出；`asl-extractor.exe` 以固定操作处理 PDF 文本与头像图像。Linux 基础设施使用 `asl-infra`，不接触用户共享目录。

可信计算基包含 core、net 的连接认证适配器和 Windows 权限模块。core 持有身份根密钥的静态存储引用、设备证书签发权、授权、数据库、资料快照和模型 HTTP 凭据，只执行固定实现，不运行来自模型的代码。net 只持有当前设备的 libp2p 私钥；net 只能通过有界 IPC 请求已授权操作，worker/helper 无任意文件工具、无直接网络、无宿主私人上下文。

libp2p 握手需要网络进程使用设备私钥。启动时 core 经私有继承管道把当前设备密钥的内存副本交给 net。传输握手完成后，ASL Hello 携带 AgentId 和身份根签名设备证书；core 从本机已验证的最终化检查点发起独立 identity-proof 子流请求，对端只可用其本机配置身份和缓存证明应答。core 验证 MPT 状态证明、签名设备目录、有效期、序号及证书 PeerId 与该认证连接 PeerId 的一致性。校验完成前不向 Agent 暴露普通应用消息。net 被攻陷仍可冒充当前设备并观察其流量，但不能签发新的身份根设备证书或转移稳定身份；这不等同于 net 完全失陷时会话内容仍安全。连接身份只能取认证 driver 给出的 PeerId，不能接受消息自报值。net 退出后清除设备密钥副本；任何凭据都不交给 worker。

八个 crate 的依赖图：

```text
asl-types
  ├─ asl-store
  ├─ asl-policy
  ├─ asl-transfer
  └─ asl-net
asl-groups -> types + store；封装 OpenMLS 群状态
asl-agent -> types + store + policy + transfer + groups 的应用接口
asl-app   -> 上述模块；负责进程入口、UI、MCP 和组合
```

不允许 net 直接依赖 store 的数据库连接或 policy 的目录句柄。跨进程只传不可变 DTO、受限字节和短期授权 ID。

`asl-net` 仅将有界不透明 MLS 字节通过认证连接发送给明确的群成员；不为非成员转发群消息。解密、成员状态和群授权留在 core 的 `asl-groups`。入站应用消息只有通过设备证书、AgentId 钉住状态、MLS 验证、当前成员/epoch 检查后才交给 Agent。MLS credential 同时绑定 AgentId 与设备证书；新设备作为新叶子加入，不复制旧设备 ratchet 状态。连接时序和通信双方仍可被观察。

群授权是独立的 audience 类型，不能隐式折算为 `contacts`。群成员变更增加群成员 epoch；群范围 permit、lease 和待处理传输绑定该 epoch，并在发送前重新判定。新成员只有在本地授权该群范围后才能读取群资源。每次询问确认同样绑定接收 PeerId 与群 epoch。

群内角色参考 QQ/微信的群主、管理员、成员和禁言模型，但不把群角色当成全局授权。群主由 MLS room creator 绑定，通过 MLS application plaintext 的 `group-policy` 下发文字/文件/邀请权限、管理员和禁言设备；revision 单调递增，非群主 sender 不能改策略。成员端在 act/Query/Expression、文件 Offer 和邀请路径重新检查策略；群主、管理员、信任值和贡献值都不能绕过本机目录、收件目录、设备证书或传输审批。

### 2.1 act、私聊与预算

ASL/1.3 `act` 只能从 MLS application plaintext 解码。私聊定义为两人 MLS 组，不得另建“已验证连接直接发明文”的旁路；私聊和群聊共用 act 编解码、去重、预算、因果链、邮箱、历史和附件引用。`conversation-id` 等于 MLS `group_id`，路由只决定 ciphertext 如何传播，不改变群身份。

每次入站 act 按固定顺序处理：认证连接与设备证书、验证活动链身份、检查 MLS 成员/epoch、去重、扣减预算、持久化、通知 Agent，然后才允许模型或本地处理。`ask` 可以触发检索和模型回答；浏览模式可读但不回答。`inform`、`clarify` 和 `ack` 进入历史；`request` 只能引用本机 PolicyService 注册的 action-id，远端文字本身不能执行动作。

预算由主体、会话、有效期、消息数、字节数、模型调用数、CPU/时间和邮箱配额组成，可由用户明确续期。续期生成新版本并持久记录消耗；换设备、重连、重启或更换 PeerId 不能重置旧额度。预算耗尽后等待用户授权。机器硬上限、队列和并发仍然生效，因此“不写死轮数”不等于无限资源。

### 2.2 提示注入与 audience 裁剪

MLS 能阻止第三方读取或篡改，但不能约束发送者本人。对端 `nl-body` 可能包含提示注入，所以必须进入独立的 `untrusted-remote-data` 数据区，并携带来源 AgentId、conversation-id、act-id 和 audience；不得拼进系统提示、开发者提示、策略文本、工具说明或本机任务目标。

模型不能通过文字创建工具调用。模型只能生成新的 `nl-body` 或结构化 action proposal；真正动作必须来自 act 的结构化 `action` 字段并经 PolicyService 重验，敏感动作按本机策略请求用户确认。模型上下文在组装前按 audience 裁剪：只允许当前会话成员、当前发送者和本机策略共同允许的资料进入提示，不允许“可能有用”就读取只授权给另一会话的数据。回复发送前还要再次检查输出是否包含当前 audience 无权获知的资料。

### 2.3 邮箱、gossip 与附件

离线邮箱是 DHT/relay 上的密文存储，不是中心明文服务器。发件端生成设备或 MLS 加密 envelope；托管节点只保存随机槽位、密文摘要、TTL、大小桶和有限可用性信息。邮箱按固定大小桶填充并可按 `shard-id` 分片，topic 使用轮换 pseudonymous 标识，不包含群名、Agent 名或长期稳定可追踪标签。收件端通过认证后拉取密文、校验摘要、重组和解密；本地落盘只保存密文，解密后的历史按本机保留策略处理。

gossipsub 只传播 MLS ciphertext 和受限路由元数据。主题与群/epoch 绑定并轮换；接收端按 act-id、group-id、epoch 和摘要去重。成员资格仍只由 MLS Commit 决定。群可从 direct fan-out 迁移到 gossip，迁移不改 `group_id`、epoch 或消息去重语义。

act 附件只携带 `blob-ref`。文件继续走既有 `offer -> fetch -> chunk -> hash` 授权路径，读取每个块都重新检查共享 grant、接收 grant、成员资格、epoch、路径白名单和期限。文件字节、文件名和路径不嵌入 `nl-body`、gossip 主题或模型提示。

## 3. Windows 隔离

公开无人值守目标为 Windows 11 x64，数据卷要求本地 NTFS。程序检查系统能力、ACL 和隔离启动是否生效；失败进入 `SandboxUnavailable`，不能退回普通权限 worker 继续对外服务。

- net 使用独立 AppContainer 身份，只授予确需的网络能力和 IPC，不授予用户资料目录。
- worker/helper 不授予网络能力或用户目录；仅得到本次操作的输入和输出管道。
- 子进程加入 Job Object，限制内存、CPU 时间、活动进程数和退出联动；活动进程上限为 1，禁止自行启动子进程。
- IPC 使用匿名管道与进程创建时的明确句柄白名单；broker 管道端点默认不可继承，仅在受锁保护的创建调用中为白名单制作短暂可继承副本并立即清除标志。文件、密钥和数据库句柄不在列表中；启动环境由系统路径及已核验的已知文件夹重建，不复制父进程环境或 API Key。
- 可执行文件通过已固定的 NTFS 文件句柄单独授予对应随机 sandbox SID 读取/执行 ACL，进程结束后撤销；同一文件的 DACL 读改写由进程内锁和按文件身份命名的跨进程 mutex 串行化。不把 `ASL_HOME` 根目录或父目录整体开放给它。OS 自身 AppContainer profile 目录由 Windows 管理。
- Windows API 与 `unsafe` 集中在 `asl-policy/src/platform/windows/`。不能把低完整性令牌当成 AppContainer 等价替代。

T10 IPC v1 使用私有继承匿名管道、固定消息枚举、方向/角色校验、单向严格递增序号和 4 MiB 整帧上限；不包含 shell、路径或自由文本字段。Core 的 Net 事件队列有界为 8 帧，EOF/解码错误会结束读取线程，避免反复累积错误。Net 启动前导 `ASLK` v1 在同一私有管道承载一次性设备密钥 protobuf，正文上限 1 KiB，密钥缓冲区在 Core 和 Net 清零；它不是普通 IPC 消息，也不包含密钥文件句柄。Net 解码 Ed25519 密钥后发送专用 `NetReady(PeerId)`；Supervisor 必须与 DPAPI 本地设备身份的 PeerId 精确匹配，否则终止 Net 并拒绝启动。本机 Agent 根身份也已在启动时通过 DPAPI create-once 加载或生成，但这不代表已完成链锚定。T14 的 Net/Core IPC 已有传输 PeerId、连接关闭和身份证明请求/应答消息；帧头先校验角色、方向、序号和各类型长度上限，再读取正文。`PeerAuthenticated` 仅表示 Net 的 libp2p 传输认证结果，不表示 Agent 身份已验证；Core 仍须使用本机最终化检查点验证 MPT 证明、签名设备目录和证书 PeerId。connection/response handle 由 Net 绑定到具体活动连接，并在关闭后作废。`CoreAdmission` 已把这些身份核验接成收发门禁；Supervisor 启动时加载本地链状态 resolver 和签名设备目录，只在本机身份通过验证后持有准入状态。常驻网络事件泵自动推进身份握手，未准入事件不会交给应用；准入事件经本地 handler，handler 返回的控制/bulk 命令重新经过准入校验。命令行入口目前使用静默 handler，Agent 会话处理尚未接入；Worker 任务仍只携带待校验的 ASL 控制帧字节，原始 payload 不直接转发给 Agent。T24 另设 Extractor 入口：IPC kind 41/42 仅允许 Core 与 Extractor 交换固定 PDF/头像操作和有界字节；每次调用创建无网络、无用户目录的一次性子进程，PDF 输出最多 2 MiB，头像在进程内解码并重编码后最多 64 KiB。

T14/T16 后续状态（2026-11-19）：Net 子进程默认仍驱动 loopback-only transport，Net/Core IPC 已接入监听、拨号、身份、控制、bulk 和网络地址策略命令/事件；活动连接和请求/响应句柄在 Net 内绑定。T16 地址策略已接入 Swarm 地址准入、mDNS 候选过滤及启动时设置加载。`state/network-settings-v1.json` 缺失时使用 LoopbackOnly、关闭监听、端口 0；存在时严格读取版本 1，先要求 Net 确认地址策略，再按设置选择性启动 TCP/QUIC 监听。回环策略绑定回环接口，其他策略通过网卡枚举只绑定策略允许的具体地址；配置错误或 Net 拒绝策略/监听时启动失败，不会退回较宽范围。此文件目前没有 GUI 编辑/保存流程；网卡热插拔更新、IPv6 链路本地作用域地址、AppContainer multicast 和真实 LAN/公网验收仍未完成。`CoreAdmission` 已协调 Hello、链证明和目录核验；入站身份证明在单一全局限速器后按 FIFO 校验，待验队列最多 16 份、等待超过 10 秒关闭连接，等待中的连接不获准业务帧。Supervisor 启动时读取本地版本化信任配置和签名设备目录，恢复或按显式 checkpoint 初始化链验证器，并仅在本机链身份、根地址、目录 commitment 与实际 Net PeerId 全部相符时创建准入状态；缺少配置、目录或有效链身份时保持关闭。常驻事件泵已接入握手、未准入连接关闭与应用回调；默认命令行入口不回答应用请求。启动后周期链同步、首次身份注册和 Agent 会话处理仍未完成，因此 T14 未关闭。

T16 mDNS 观察通道：已筛选的发现/过期候选经 IPC kind 38 进入 Core 的独立本地只读观察回调，不进入 `CoreAdmission` 的 Agent 事件 handler，也不产生授权或联系人状态。候选记录和待派发观察均有固定容量；只有先前记录过且仍符合当前地址策略的候选才会报告过期。候选发现不是在线状态；GUI 展示、AppContainer 组播权限和真实 LAN 验收仍待完成。

T18 Public scope 出站查询现在通过 IPC kind 44/45 请求 DHT provider 候选并收集本机地址策略允许的端点；这些结果只用于候选拨号，不构成身份或授权。Core 仅在 provider 连接完成现有链身份准入后发送 Query，同一 PeerId 同时只有一个待完成的出站控制请求。默认 LoopbackOnly 未改变，Net 拨号仍重新校验地址策略。`network-settings-v1.json` 已支持 `bootstrap_multiaddrs`，并在启动/恢复时逐个拨号；安装目录存在 `assets/network-seeds.json` 时，显式 bootstrap 为空才读取该文件，并校验版本、有效期、bootstrap 角色、数量及 PeerId/地址绑定。显式 public grant 的 content/concept hash 会进入 provider 发布集合。真实打包 seed 部署、冷启动公网、资源索引和双机互通仍需验收。

网络能力包括不同地址类型的适配必须真实验证；AppContainer 的网络权限不等于按域名限制出站。外部模型 HTTP 由 core 的固定网关发起。

T09 实现已有按角色启动、独立 profile、子进程限制、Job 资源限制、显式管道继承、执行文件 ACL、期限 watchdog 和真实否定探针。剩余 TCP/UDP 外部端点、QUIC 及 mDNS 请求/响应必须单独实测；单独创建 multicast membership 不等于 mDNS 已验收。所有其他 ASL 子进程启动必须继续经过统一 broker/sandbox 启动路径，不能并行使用未采用句柄白名单的裸 `CreateProcess`。

隔离不能抵抗管理员、内核入侵、同账号调试器或已被攻陷的 core。安全文档必须陈述威胁范围，不能宣传“绝对不泄露”。

T31 将上述私有启动前导从 `ASLK` v1 升为 v2，新增默认关闭的回环群开关；具体字段见[协议](03-protocol.md#2-协议名与限制)。启用后 Net 仍独立执行回环策略，不允许切换到其他地址范围或中继；原始群帧与本机审批入口不进入 Agent 或 Worker。

## 4. 文件与授权强制点

每项授权包含根目录身份、扩展名、披露范围、模型处理范围、额度、epoch 与状态。contacts 成员变化还会增加全局 `policy_revision`。contacts 键为稳定 AgentId/根公钥，不以可变 PeerId 或网络地址为键。

访问始终是 `授权句柄 + 受限相对文件标识`，不是 `远端路径 -> open()`。目录遍历和文件打开拒绝 `..`、绝对路径、UNC、设备名、ADS、reparse point，检查卷和目录/文件身份，拒绝硬链接计数大于 1 的源文件。

Windows 实现必须验证句柄相对打开、路径组件替换和重命名竞态；不能只 `canonicalize` 再用普通路径重新打开。cap-std 是可评估的工具，不免除这些测试。

导入时稳定打开源文件、拒绝其他写入/删除并建立不可变快照；需要快照的磁盘额度必须事先取得。模型和 net 从不自行打开原始目录。

grant 的快照引用、文件 hash 和实际字节存储分离。同一 content_id 可物理去重，但不能因“磁盘上有这个 hash”就授权访问。授权判断必须沿 `grant -> resource -> snapshot -> requester` 路径完成。

目录变更由 watcher 加定期全量对账发现；源文件移除后停止新公告和新 lease。此机制有扫描延迟；要求立即停止披露时使用撤销授权。历史已发送副本无法召回。

## 5. 撤销与竞态

短期 permit 包含：

```text
permit_id, grant_id, grant_epoch, policy_revision,
requester_agent_id, authenticated_device_peer_id,
content_id, operation, expires_at_ms
```

撤销在同一事务内增加 epoch/revision、停用资源引用并记审计。提交后，core 立即取消相关队列、未开始读取、尚未交给 net 的块和模型调用；每次读取、输出、发送前重新验证 permit。

任何 await 之后继续发送前都需重新验证，不得缓存“曾经允许”作为永远有效。权限变更事件带 revision，net 按序 ACK；新请求不得越过尚未确认的撤销栅栏。grant_epoch 是该 grant 的失效条件；全局 policy_revision 只触发重新判定和审计。无关策略变更不应把所有大文件下载取消。联系人授权以 requester AgentId 重新判定；一次 permit 同时绑定 AgentId 和已认证设备 PeerId，撤下身份或设备撤销后立即失效。

公开承诺是“撤销提交后不再授权新的披露，并尽力取消尚未发出的数据”。已经交给传输层或外部模型端点的数据不可收回，不承诺并发时最多只存在一个在途块。

## 6. 模型与 HTTP 网关

模型只接触为当前 audience 裁剪过的片段，候选 ID 不包含路径。远端 `nl-body` 只能进入数据区，不能成为系统指令或工具调用。模型输出可以包含对话正文或结构化 action proposal，但不能给出 peer 权限、授权、命令、URL、文件位置或额度；只有结构化 `action` 经 PolicyService 才能触发动作。schema 正确也不意味着内容真实，所有 refs 还要做集合成员及当前授权检查。

provider 由人预先授权，凭据不传给 worker。HTTP 禁止自动重定向，HTTPS 校验开启，限制响应、时间与重试。URL 来自配置，不来自 peer 或模型。局域网/loopback provider 必须单独授权，拒绝请求元数据地址和任意 URL 抓取。

对外 query 内容本身需要披露许可。接入宿主不等于接管其权限；不能保证过滤宿主主动塞进 query 的任意秘密。

## 6.1 公网发现与地址隐私

直连模式会向通信对端暴露本机可达网络地址；DHT 查询目标、在线时间、引导节点和中继元数据也可能被关联。界面不把假名身份标为“匿名”。仅中继模式只拨打配置的 relay 地址，不发布或拨打直连候选；入站电路也必须来自配置的 relay，完成握手后再绑定实际 PeerId。relay 仍可观察连接关系、时序和流量大小。

所有 DHT、短码、mDNS、邀请和对端提供的地址都只是候选输入。按网络模式过滤环回、私网、链路本地、未授权本机服务与不允许的地址类别；地址解析后再次检查，禁止把 multiaddr 转换成 HTTP、SMB、文件 URL 或系统命令。设备证书及需要时的链状态验证前仅允许有界握手，不处理语义请求、文件、模型或群协议。陌生身份的连接、流、握手次数和字节数均有独立上限；已验证身份仍需通过本机 audience/grant 才能读资源或收发文件。合法多 Agent 共享同一 supervisor 的机器级总限额，细项见 `docs/09-resource-abuse.md`。

短码查找使用 DHT provider 候选；公开短码默认关闭。provider 命中只触发受地址策略限制的拨号，客户端仍须验证注册链状态、根密钥签名设备证书与认证 PeerId。只有本机用户明确绑定后才记录本地 AgentId/PeerId 关系；它不写入 `authorized_contacts`，也不赋予目录读取、文件、资源或群组权限。活动配置拒绝旧 `/asl/pair/1.0.0` 邀请/响应并关闭连接，不展示远端文本，也不创建提示回执；因此旧版提示频率限制不构成当前入站路径的安全依赖。低熵数字短码只用于发现，不作认证凭据。

## 7. 资源保护与调度

统一上限是运行保护。默认同时 8 个上传块、单 peer 2 个；每项下载最多 4 个来源、每来源 2 个块；最多 4 个模型任务。每项会话不再写死 3 回合/6 条消息，而由用户可续期预算控制消息、字节、模型调用、CPU/时间、邮箱配额和出站请求数；编译期帧上限、队列长度和并发仍是机器级硬约束。

公平队列先应用授权和 audience，偏好和信誉不能引入新候选。已授权联系人按本地偏好及分维度信誉软排序；单次查询最多 16 个联系人，超过时保留一个轮转探索位，避免固定只询问排名最高的节点。可靠性与有效贡献不改变任何授权，也不能抵消协议拒绝、坏 hash 或额度耗尽。

分身/女巫防护是本机资源边界：握手、身份证明、act 入站、模型调用、邮箱投递/拉取、gossip 主题和群邀请分别按 `AgentId + device + PeerId + IP + conversation` 分桶限额。新身份只有低额度试用预算；同一群/设备/来源的待决邀请有数量和期限限制。资源耗尽时优先保留已有合法会话，拒绝新连接、新群和新邮箱。信任值和贡献值只影响排序、展示和预算建议，永远不绕过硬资源额度、PolicyService 或文件授权。

所有队列、DHT 待查、去重记录、记录存储、日志和模型响应都必须有字节/数量/期限三类界限。换身份不能绕过本机总额度。

## 8. 故障语义

| 故障 | 行为 |
| --- | --- |
| 沙箱失败 | 停止对外无人值守能力，GUI 展示原因，禁止普通进程回退 |
| 模型不可用 | 仍可回答确定性资源匹配；act 仍可认证、解密、展示和通知，但不生成模型答复，状态明确为 `model_unavailable` |
| 链不可达 | 使用缓存的已验证最终化状态；新/过期身份进入最低额度，不能假装已链上验证 |
| 所有赞助提交者退出 | 已登记身份可照常验证；新身份保持 pending_anchor，可按本机授权使用 LAN；用户自付路径可选 |
| DHT 失败 | 继续已知联系人直连，不假造搜索结果 |
| 直连失败 | 尝试获准中继；中继容量不足时等待/失败，不要求永远直连 |
| 短码冲突/污染 | 展示多个已通过身份准入但尚未本机绑定的候选；须逐个本机确认，不自动授权 |
| 根密钥丢失/泄露 | 有根密钥时可提交链上轮换/吊销；密钥彻底丢失时无中心恢复，必须建立新身份并重新核验 |
| 设备证书过期/被撤销 | 拒绝该设备的新 ASL 会话；不因同一 AgentId 自动信任新设备 |
| 磁盘不足 | 先停止新额度预留，保存可恢复状态，不删除用户源文件 |
| 数据库损坏 | 停止权限相关操作，使用明确恢复流程，不重建为空授权 |
| 授权版本冲突 | 拒绝并重新求 permit，不接受旧 grant |
| 版本不兼容 | 返回 incompatible；不能猜测解析未知版本 |

## 9. 中继设计纠正

不采纳“所有大文件都必须直连”的限制，它会破坏方便性和完整传输能力。中继可承载文件，但需配置明确的电路字节、时间和并发上限。每块请求有边界，电路耗尽时保存状态、重连或切换其他允许中继。

不能靠拆连接绕过运营者限额；也不能把“软件不收费”误解成“他人中继资源无限”。发布包附带可替换入口与自托管配置，首次加入仍需至少一个可达入口。

便捷入网由发布包的 `assets/network-seeds.json` 提供至少两个运营配置独立的真实入口，受发布清单签名保护。首次网络授权后自动使用，不要求日常用户手工填写地址。显式 bootstrap 配置优先，缓存的已知节点次之，内置入口最后补充；用户可以禁用内置列表并授权自己的网络。入口不是身份审批机关，关闭维护者更新站不影响已经入网的节点。

身份迁移包保留身份根密钥与用户选定的 ASL 本地数据，不包含可直接复用的设备私钥、OS 凭据或目录 grant。导入后创建新设备密钥并签发新证书，同时更新链上设备状态承诺；旧设备需停止或通过链上最终化更新/本地拒绝状态退役。群 MLS 状态不复制；可选的 `groups` 数据只包含完整 Group ID、群名、群主 AgentId 和最后 epoch，供新设备向群主发起重入请求。标准 MLS Add/Welcome 和群主本机审批仍是唯二成员变更路径。迁移文件格式和身份后端均有版本号与明确拒绝未知主版本的规则。
