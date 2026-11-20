# T31 群组接线记录

## 已实现：群消息编解码

群子流沿用冻结的 `/asl/group/1.0.0`、4 字节大端长度前缀和确定性 CBOR `group-envelope`。收发只接受群 envelope；整帧上限 256 KiB，envelope 内的 MLS 密文上限 64 KiB。未注册群子流，不开放网络入口。编解码不认证身份、不授权群成员、不匹配回复。

MLS 应用明文通过 `group-application` 校验，只复用既有 Query、Answer、Offer。没有新增自由文本、未知字节载荷、群内 Fetch 或嵌套群 envelope；外层 CBOR 字段和值不变。Agent 应用规则（例如不让群回复触发新回复）仍由后续 T32 实现。

集成夹具使用固定 OpenMLS 0.9.2、RustCrypto 0.6.0 和测试身份，真实执行 KeyPackage、Welcome、应用消息认证与解密、移除提交，检查被移除成员不能读取下一 epoch 的消息。夹具的 BasicCredential 不等于 ASL 链身份；测试并不验收实际群邀请、持久化、成员授权、生产子进程或公网。

## 待实现：持久化与权威绑定

- 本地库的 `GroupId(Id128)` 用于授权、成员、短期事件和传输确认；线上 `GroupEnvelope.group_id` 是完整 32 字节。新增不可变唯一映射（本地 ID → 32 字节 BLOB），不重写旧授权键、不截断、不迁移或自动承认无 MLS 状态的历史群。OpenMLS 内部显式使用同一 32 字节，而不是使用库的默认 ID。仅在本机创建房间或收到已批准并验证的 Welcome 后建立映射；发现未知线上 ID 不构成授权。
- 使用独立 MLS 签名密钥，不能复用交给 Net 的传输私钥。MLS 签名公钥必须有受当前链状态约束的 AgentId、PeerId、设备证书绑定；加入、同步和应用消息都要核对相应证书与成员状态。实时分发仅面向当前获准接收的设备。移除与迁移不会复制旧 ratchet，也不会将群成员升级为联系人。
- `membership_epoch` 只随授权成员变化前进，独立于 MLS `mls_epoch`。从提交后的 MLS 叶子投影 SQL 成员；权限、撤销、重放状态与新 ratchet 一起在同一 `asl.sqlite3` 事务提交。先处理本机与 MLS 双方校验，持久提交后才可发布成员视图、交付明文或发送新密文。事务失败时丢弃本次变更后的内存群状态并重载；重启发现投影不一致时暂停群权限并显示 `needs_sync`。
- 上游 `openmls_sqlite_storage` 0.3.0 的 `rusqlite` 0.37 与本项目锁定的 0.43 各自链接 SQLite，不能直接同时接入。不要为了接入绕开事务或改成未经保护的临时文件。复用 OpenMLS RustCrypto 与存储接口，需选择与现有 SQLite 兼容的有版本存储适配器；本机状态保护及事务失败恢复是该模块的验收项。
- 线上的 membership 操作需先约定定向邀请、单次 KeyPackage、Welcome 和 commit catch-up 的精确类型及关联条件，再部署 request-response 行为。不得把编解码成功当成已加入房间，也不得向未知节点发树、成员或事件。
