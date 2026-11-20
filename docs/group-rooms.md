# T31 群组接线记录

## 已实现：群消息编解码

群子流沿用冻结的 `/asl/group/1.0.0`、4 字节大端长度前缀和确定性 CBOR `group-envelope`。收发只接受群 envelope；整帧上限 256 KiB，envelope 内的 MLS 密文上限 64 KiB。未注册群子流，不开放网络入口。编解码不认证身份、不授权群成员、不匹配回复。

`GroupPacket` 对操作 `1` 内的 `group-membership` 进行二次确定性 CBOR 校验，限制请求和回复种类、完全匹配群 ID、请求 ID、预期 epoch 和邀请 ID。网络 codec 仍只检查外层，内层检查由 Core 调用，不能代替已认证连接和待决请求校验。OpenMLS 适配器核验普通 KeyPackage、单收件项 Welcome、解密后的群 ID/epoch/套件及本机叶子，并检查 Application/Commit 是相符的 MLS 私有消息。同步绑定由 MLS exporter 派生，不发送原始 epoch authenticator。完整消息表见 [协议](03-protocol.md#群子流)。

MLS 应用明文通过 `group-application` 校验，只复用既有 Query、Answer、Offer。没有新增自由文本、未知字节载荷、群内 Fetch 或嵌套群 envelope；外层 CBOR 字段和值不变。Agent 应用规则（例如不让群回复触发新回复）仍由后续 T32 实现。

集成夹具使用固定 OpenMLS 0.9.2、RustCrypto 0.6.0 和测试身份，真实执行 KeyPackage、Welcome、应用消息认证与解密、移除提交，检查被移除成员不能读取下一 epoch 的消息。夹具的 BasicCredential 不等于 ASL 链身份；测试并不验收实际群邀请、持久化、成员授权、生产子进程或公网。

## 已实现：本机状态读写

SQLite v12 已支持在同一事务创建 `needs_sync` 房间与 MLS 状态记录，存放完整 32 字节线上 ID、唯一的本地 `GroupId(Id128)` 及不透明密封状态。旧授权 ID 不重写，无旧群自动升级，也不写入任何成员行。读取按完整线上 ID 精确匹配。

Windows 本机适配复用 OpenMLS 的内存存储与现有 DPAPI，密封快照绑定本机房间 ID、完整线上 ID、当前设备、版本与 MLS epoch。恢复会检查绑定和 OpenMLS 组状态；快照不属于身份迁移包。SQLite 持久化与 DPAPI 恢复各有定向测试，真实 OpenMLS 夹具用恢复后的接收方处理应用消息及移除提交。Core 尚未调用这些接口，也没有恢复或激活群权限。

## 已实现：MLS 身份与候选事务

MLS 1.0 使用 `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`。Core 带独立随机 MLS 签名密钥，严禁把传输私钥作为 MLS 签名密钥使用。ASL BasicCredential 内容为 `signature65 || canonical_device_certificate_cbor`；根签名的预映像是 `ASL-MLS-LEAF-v1\0 || wire_group_id[32] || mls_signing_public_key[32] || canonical_device_certificate_cbor`。检查群 ID、公钥编码和当前 ASL 证书。通过已有链解析器核对活动身份根、已验证设备目录和证书有效期；直接来源还须匹配当前认证连接中精确的 Hello 证书。同 Agent 的其他设备、过期/被替换证书和其他房间均不可复用该叶子。签名绑定只证明身份根授权该公钥；MLS 自身仍须验证该叶子或消息的签名和密钥持有关系，链证据的新鲜度沿用现有解析器规则。

SQLite `BEGIN IMMEDIATE` 比较本机/线上群 ID、快照版本、MLS epoch、成员授权 epoch 和全局权限版本，一起提交候选快照、成员投影和群事件。应用消息用群 ID、认证发送设备和 MLS 明文的消息 ID 去重，不信任外层消息 ID；提交事件用群 ID、基础 epoch 和已验证 MLS 数据去重。更新 ratchet 不增加成员授权 epoch，候选成员变化也不会使本机房间从 `needs_sync` 切为 `active`；后续只有实际授权成员或可用状态变化才推进成员授权 epoch 及全局权限版本。事件写入 7 天期限，定时清理待接入。生产 Core 仍需在提交之前重新核对本机权限与链证据，提交失败时丢弃候选，成功后才允许交付明文或排队发送。

## 待实现：生产权限与投递

- OpenMLS 内部显式使用同一 32 字节，而不是使用库的默认 ID。仅在本机创建房间或收到已批准并验证的 Welcome 后建立映射；发现未知线上 ID 不构成授权。
- 从 OpenMLS 验证后的 KeyPackage、Welcome 树、Add/Update/Commit 叶子取出公钥和证书，核对当前链状态。重启先关闭群权限，核对密封快照、SQL 成员投影、当前设备和链证据后才重新启用。过期、撤销和换设备需要 MLS 叶子更新或移除；不得仅删 SQL 成员行却继续用旧 MLS epoch 发信。移除与迁移不会复制旧 ratchet，也不会将群成员升级为联系人。
- 上游 `openmls_sqlite_storage` 0.3.0 的 `rusqlite` 0.37 与本项目锁定的 0.43 各自链接 SQLite，不能直接同时接入。继续使用每房间独立的内存 provider，并将密封后的候选状态与成员投影用同一个 SQLite 事务提交。

## 已实现：入站邀请本机状态

SQLite v13 记录完整线上群 ID、邀请 ID、基础 epoch、邀请方及本机目标的 AgentId 和 PeerId、短期有效期。邀请最多有效 5 分钟；同 AgentId 的不同设备共享 24 小时 1 次额度，另有本机每小时 20 次、同时未结 5 条上限。拒绝、过期和完成不退还提示额度；过期清理会移除密封包，保留 24 小时内的提示历史。定时调用清理待接入。群邀请不带任何自由文本。

Windows DPAPI 适配只持久化单次 KeyPackage 和对应 MLS 签名密钥，绑定该邀请元组、请求 ID 与包引用，可重建同一请求和新的候选 provider。审批先持久化才可发送，同一线上群最多一个获批的待加入包；启动后可按本机身份及设备发现尚未过期的审批。SQLite 原子消费审批、关闭同群其余邀请、创建新房间并写入冻结快照和已验证的成员投影；失败统一回滚。房间保持 `needs_sync`，不修改权限版本。这一阶段未连接 GUI 同意操作、链验证、发方事务或网络；DPAPI 和 SQLite 各自验证。

### 定向入群与有限同步：剩余接线约束

- 邀请只发往经认证且明确指定的 `AgentId`、`PeerId`。记录关联的群 ID、随机邀请 ID、当前基础 epoch、签发方和短期有效期。本机接受前不生成或发送 KeyPackage；邀请本身不带成员表、加入密钥或自由文本，不授予资源访问。
- 创建者验证 OpenMLS 签名、版本、套件、链身份和邀请状态。只有新增成员的提交与待发 Welcome 一起持久化后才能向目标发出。只可向仍有资格的原目标重发同一份已提交 Welcome，不能为同一包再做一次 Add。接收方必须用当前连接证书核对 Welcome 签名者，并校验完整 roster 和本机授权后，才能提交候选。连接重试不能扩大授权或重复消费。
- 在发送 KeyPackage 前确保本机设备已登记；校验 Welcome 时确认成员都有经验证的本机身份行。候选房间的创建者权限必须另有群内证据，不能把 Welcome 签名或成功解密等同于创建者授权。重启时先清理过期审批，再核验原邀请方的设备和链状态；不能因为出现在恢复清单中就自动发出请求。
- 同步只向仍获准的成员提供连续提交，最多 256 个 epoch，每次一个。起点由本机持久状态决定，并核对独立的 epoch 绑定、回复节点、请求 ID、群 ID 和连续提交；传递提交的当前成员与基础 epoch 的 MLS 签名者分别认证。单个成员变更使用内联提议，不依赖未缓存的外部提议。超预算、日志缺失或分支冲突时停用投递并保留 `needs_sync`，不能跳过提交或退回旧 epoch。
- 不得把编解码成功当作入群，所有群数据都不发布到 DHT。
