# T13 结构化签名记录

记录核心已实现，工作区 226 项测试函数通过，含 24 项 codec 和 37 项签名/资料服务测试。
T13 依赖已实现的 T03 codec 和 T06 根身份，与 T08 尚缺少的系统夹具无依赖。

## 规范补全

原协议已有精确签名原文、profile 控制对象和设备目录语义，但没有完整
DHT 记录封装及目录/短码 CDDL。按 `docs/03-protocol.md` 第 3 节补全：

- 保留已有 kind 1/2；追加 kind 3 短码声明；追加 kind 4 联系策略密文封套。
- 外层固定字段与规范载荷都必须严格解析，整个记录不超过 8 KiB。
- profile 复用原控制对象，并核对内外 owner/sequence。
- 设备目录包含明确 registry sequence；BLAKE3 域分离承诺绑定其完整规范载荷。
- 目录外层续发时间与 publication sequence 不进入目录承诺，不要求每 5 分钟上链。
- 短码为固定算法派生的整数；它仍允许碰撞，不构成认证或授权。
- kind 4 只承载根签名加密策略密文，sequence 等于策略 revision；联系人 ID 和来源规则不进 DHT 明文。

线上没有文本、昵称、路径、地址或可以任意解释的扩展字段。
未来需要新字段或记录种类时必须显式修改版本化规范。

## 分层接口

`asl-types::record` 负责类型、严格规范 CBOR、固定签名原文和承诺/短码计算。
它不读时钟、不接受私钥，也不判断链身份或证书签名。

`asl-app::profile::sign_record` 复用 `AgentIdentity` 的根签名实现，
不把根密钥导出到类型层或 net。签名是本机可信调用，不等于已获准发布。

`verify_record` 每次调用本机 `IdentityResolver` 获取当前有效身份，
核对 owner、时效和当前链控制地址，再验证根签名。
设备目录还要核对链上 commitment/sequence，并验证每张活跃设备证书。
不能用一份之前返回的 `VerifiedRecord` 替代新连接的身份验证。
对端发来的布尔值、controller 或“已验证”对象不能替代 resolver。

任务卡中的 `kind/payload_cbor` 是概念入口；具体 Rust 绑定使用已校验的
`RecordPayload` 枚举推导 kind，显式传入本机身份和签发时间。
验证入口额外接收本机 resolver，而不是从记录携带的公钥推断当前控制者。
这些参数补全不改变冻结的签名原文或旧控制帧，也不允许签发任意二进制载荷。

## 单调观察

`RecordHistory` 保存一个 owner 四类身份记录的序号和精确字节摘要。
更低序号拒绝，同序号只接受相同字节；过期或错误记录不能覆盖已有观察。
设备观察记住同一 PeerId 的最高 serial/证书、serial 所属设备及已知撤销，
换目录后也不能重新启用已观察的撤销 serial。

设备历史由本机指定容量，范围为 1 至 4,096 个不同 serial；
达到上限时拒绝新增，不静默删除防回滚信息。更新先验证整个候选，
配额和任何一项不符时不改变历史。一个历史对象只处理一个 owner，
全网记录总量与每 owner 存储额度由 T17 的 bounded DHT store 与 Core 准入入口约束。

当前历史只在内存中。T17 将通过 DHT 的记录候选先交 Core 校验，再由 Core
回传明确接受/拒绝决定；记录键、根签名、当前 Active 链状态、有效期和本地
序号历史都通过后才落入 net store。profile、device directory 与短码声明使用
按 owner/kind 分开的域分离键；联系策略使用独立加密 kind 4 键，短码查找本身使用可多候选的 provider 键，
不会用碰撞的短码覆盖单值记录。DHT store 和历史高水位仍未持久化；进程重启
不保证防回滚观察延续，不能把这里写成重启防回滚已完成。
入站验证的机器级 CPU/请求额度也由后续 broker/net 闸门执行，
不能把单条记录的结构上限当成全局女巫防护已经完成。

## 联系策略密文同步

联系人请求策略保存在 SQLite `settings`，不是授权表。每次本机修改（模式、共享群来源、近期交互 TTL 或撤销）推进单调 revision。`asl-core --bindings policy-export <path>` 生成或复用根签名 kind 4 记录；内部 JSON 先由 Agent root secret 派生的 age 密钥加密，外层只暴露 revision、revoked 与密文。自动同步把精确记录字节和退避状态保存在 `settings`，重试不重签；记录过期后才推进 revision。同一 revision 的多设备冲突先保证 revoked 优先，再按完整记录 BLAKE3 较小的字节串胜出，DHT store、Core 历史、DHT cache 和 runtime 使用同一规则。`policy-import` 只在本地 `policy-sync on` 已授权、记录 owner/控制器/期限/签名正确时应用；策略撤销使用更高 revision 的拒绝快照，旧快照不能回滚当前策略。`Selection.contacts` 的加密身份迁移包也携带同一 revision 和 revoked 字段，用于新设备恢复。该机制不同步 pending invite、候选、联系人访问 grant、文件或群权限。

## 本机资料续发

`ProfilePublisher` 默认关闭。只有本机明确配置后产生待发布记录，
每 5 分钟续发，最长 30 分钟有效。每次产出重新解析本机链身份；
带头像时还要调用 `PolicyService` 检查显式资源的公开发布许可。
头像 content ID 从许可取得，不从任意输入 hash 推断文件权限。
头像重编码和像素限制由独立 Extractor helper 执行。概览或 `--avatar approve <token>` 只批准当前预览的内容 ID；既不批准资料 DHT 出站，也不允许读取图片文件。主题公开和头像引用须分别授权。本地审批代次、清洗版本、grant 和资源 key 不上网。

撤下后不再产生新记录；旧记录已披露的字节只能等待远端 TTL/缓存过期。
这个服务只返回候选字节，没有打开 DHT。Core 现已按本机签名授权调用该服务：
`asl-core --profile approve-local-signing <AgentId-base58> <topic-id>...`
保存当前身份及明确选择的 ASL v1 主题；`status` 读取批准和上次候选状态，`revoke` 撤销。
Core 只在身份和设备目录当前有效、对等网络未暂停时签名，五分钟后可续签。
SQLite 仅保存序号和时间，不保存或导出候选字节。更换授权或撤销后，旧结果不写回。
本机签名批准不会自动转为发送批准。`asl-core --profile approve-publication
<AgentId-base58> <topic-id>...` 单独授权公开当前身份和所选主题；节点页提供同等操作。
选择仅本机签名或撤销会终止公开授权。Core 把查找最近节点与实际 PUT 分开：
查找只使用派生记录键，找到已连接的 DHT 邻居后才签名；将内容交给 Net 前，用
SQLite 写事务复核授权版本和暂停状态。Net 使用单阶段 `put_record_to`，不在
本地留下自动续发副本。正常续期为五分钟；无应答时最多每 30 秒重试一次。
撤销请求会立即阻止新的提交。交给 Net 的签名内容在入队前先记录唯一操作 ID 和 Net PID；
如已有在途提交，撤销或更换授权暂不完成。CLI 返回 `pending_network_drain`，节点页显示“资料授权变更中”。
只有匹配的 PUT 终态、Net 处理完取消后的独立回执，或重启后确认旧 Net 进程已退出，才能完成变更。
等待期间可以更新目标设置，但新授权不能提前发布。已开始发送或已被其他节点收到的副本不能追回。
没有证据证明旧 Net 已退出时保持等待，包括 PID 被另一个活动进程占用的情况。

libp2p-kad 0.49.0 在 `FilterBoth` 模式的 PUT 应答不等待对端 Core 决定落库。
界面上的 DHT 应答只表示传输应答，不证明对端已验签保存。该路径不放宽
现有拨号/中继策略，不新增引导节点；公网仍待验收。

远端资料被动浏览沿用 Core 接受的 DHT 候选。SQLite 只投影 AgentId、
已知主题编号、可选的 32 字节头像内容 ID、序号和有效期等展示元数据，最多 200 个 Agent；不保存
封装字节或图片，也不按内容 ID 自动下载。新版资料可替换或清空旧引用。节点页只读此投影，过期或与当前本地链观察不一致的
记录不展示。打开列表不发请求。用户可明确指定完整 AgentId，在本机投影无命中时经 Core/Net 向 DHT 查询该资料键；返回候选仍须过同一套身份、签名、序号和投影规则。整个资料目录每 15 秒一个查询窗口，同目标合并。到期只表示没拿到可展示的资料，不是链身份不存在。缓存不用来验签、拨号、修改信任或授权。
这个有界投影不替代 Core 的签名历史，不保证跨重启防回滚。

Core 的本机设备目录续签另有持久 publication cursor：它每 5 分钟基于当前有效链状态和已配置目录载荷重签 envelope，并通过 SQLite `settings` 原子预留单调序号。源目录文件被移除、链状态过期、commitment 不匹配或设备证书无效时不续签。这个运行时机制不等于 DHT 发布，也不改变 `ProfilePublisher` 的显式配置和调用方序号责任。

Core 的本机资料签名使用与设备目录分开的 SQLite 游标；撤销不重置序号。
短码签名记录的发布序号仍由调用方管理。本地收到的远端记录历史仍为内存状态；
本模块不会把序号清零当成恢复，也不提供自动身份重置。

## 验证范围

测试采用一次性生成的身份和合成 Trie 证明验证结果。
真实 RPC、链注册、DHT 入站过滤和跨节点互操作不属于这里的本机测试。
`cargo test --workspace --all-targets --locked` 共 226 项测试函数通过。
`cargo clippy --workspace --all-targets --locked -- -D warnings` 和
`cargo fmt --all -- --check` 通过。`scripts/validate-cddl.ps1` 通过 CDDL
语法及固定 ACK 验证；它没有验证全部签名记录的跨实现互操作。
独立复核者静态检查未发现可确认的实现缺陷，并独立重跑 24 项 codec
和 37 项签名/资料服务测试通过。复核指出的授权绑定测试弱项已补强：
资源指向另一份有效授权，确保拒绝原因确实是请求与资源的授权不一致。

无新增依赖或锁文件变化；许可证检查沿用之前切片，本轮未重跑。
Foundry、真实链服务、DHT、MLS、Windows 沙箱和完整 GUI 未在本轮验收。
T08 的 symlink 权限和真实 8.3 别名夹具限制仍存在；
新记录测试不覆盖或补足这些缺失的系统向量。
