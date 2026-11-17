# ASL 第二轮复核意见

说明：以下均为设计层面的推断，我没有编译或运行任何代码，也无法核实所列 crate 版本与其 API 是否相互兼容。

## 1. 需要修正的实质问题（按严重度排序）

**① 两跳查询存在"代理越权"，且与"外部请求默认不转问"字面冲突。**
B 替 A 转问 C 时，C 看到的连接对端是 B。若 C 按 B 的 contacts 权限作答，B 再回传给 A，就发生越权。hop、origin、visited 又都是转发者自报的。修正：
- 转发请求必须带 origin 用应用签名密钥签署的根任务令牌，字段为 task_id、max_hops、expires、nonce。
- hop≥1 的请求，应答方一律只按 public grant 评估，不按转发者身份，也不按未经验证的 origin。
- 中间节点只能原样回传带范围标记的结果，不得把自己凭 contacts 权限取得的内容并入。
- 把"两跳"写成确定定义：origin→B 为第 1 跳，B→C 为第 2 跳；B 只有在本机策略显式开启代转时才转发，默认关闭。
- visited 摘要会泄露邻居关系，只放截断哈希并限制条数。

**② broker 信任沙箱网络进程报告的 peer_id，与"broker 持有密钥"也不自洽。**
libp2p 握手需要身份私钥在 swarm 所在进程内可用。我不确定 0.57 是否提供远程签名钩子，不应假设有。修正为双密钥：
- 传输身份密钥放在网络进程，承认它随该进程失陷。
- 另设应用签名密钥，只在 broker。grant 绑定对端的应用公钥。
- 每个读取或租约请求由请求方应用密钥签名，含 nonce、expires 和接收方标识，broker 自行验签后才放行。

这样网络进程失陷后只能重放有效期内的请求，不能伪造任意对端。

**③ 模型输出的 text 是自由文本，是绕过 refs 校验的泄露通道。**
修正：
- 授权过滤必须在检索之前。为对端 P 服务时，送入模型的上下文只能包含 P 当前有权读取的材料；inbox 和 derived 中权限不含 P 的内容不得进入提示词。
- 入站任务的 terms 只允许触发本地检索，不得触发 DHT 或对外查询，否则查询词本身就是外泄信道。
- 把资料发给外部模型端点本身是出站披露，要按"端点 × 数据分区"单独授权，默认不发送远端来源内容。
- 远端内容一律作为数据段包裹，明确不作为指令。

**④ 按 hash 复用带来存在性探测和类型混淆。**
修正：
- 块请求只能用（lease_id, content_id, chunk_index）寻址，禁止按裸块 hash 取数。
- 无授权与不存在返回同一错误码，响应形态一致。
- 存储键为（kind, hash），kind 取 manifest、chunk、inline 之一，防止一段恰好等于某 manifest 原像的块数据被当作 manifest 提供。这不改变 manifest 格式。
- 明确 content provider 记录与标签同规则，非 public grant 的 content_id 不发布到公共 DHT。

**⑤ 租约绑定 policy_revision 的语义未定。**
若它是全局版本号，任何无关策略改动都会让 64 GiB 的下载租约全部失效。若读块时不逐次检查，撤销又不生效。修正：
- grant_epoch 按 grant 递增，只在该 grant 被撤销或收窄时加一。
- 每次读块，broker 在同一 SQLite 读事务内核对 grant_epoch 和 expires。
- policy_revision 只用于审计和缓存失效，不作为租约失效条件；或者明确写成"仅影响该 grant 的修订"。
- 租约短期有效，可续签。

**⑥ Windows 条件未写全，可能无法实现。**
- AppContainer 监听入站、局域网 mDNS 多播和 QUIC UDP 各需要哪些网络能力与防火墙规则，必须先做验证性原型再冻结。mDNS 不可用时应明确降级为"无局域网发现"，而不是放宽沙箱。
- DPAPI 用户范围要求用户登录会话，所以"后台"应定义为登录后启动的每用户进程，不是开机即运行的系统服务。
- ASL_HOME 须校验为本地固定卷，且文件系统支持 ACL 与重解析点检查（如 NTFS）。exFAT 或可移动盘应拒绝，否则目录隔离规则无从落实。

**⑦ 下载失败语义与额度锁定未定义。**
- 所有块 hash 都通过而整文件 hash 不符，说明 manifest 本身自相矛盾。此时应丢弃 .part，将该 content_id 标记为坏并限期不重试，不得循环下载。
- 恶意 manifest 可以声明 64 GiB 来占满逻辑预留。预留要有按对端和按任务的上限，以及无进展超时释放。
- 单块校验失败应记到具体来源并降权。

**⑧ 版本基线未编译即冻结，"完整 1.0"缺少门禁。**
任务卡依赖"确切接口"，接口却尚未被编译证实。修正：
- 先提交 Cargo.lock 和各 adapter 的最小编译样例，再让任务卡引用应用接口。
- 完整 1.0 可以不做 MVP，但要按依赖顺序设里程碑，每个里程碑有可重跑的验收命令。
- 标签规范化要钉死 Unicode 数据版本，并附测试向量，否则不同版本节点对同一标签会算出不同的 DHT 键。

## 2. relay 无中央账号时的可用性条件

- **入口地址。** 至少需要一个事先已知的公网可达 bootstrap 地址，内置列表或用户填写均可。全部失效时，新节点只剩局域网发现。
- **DHT 存储。** NAT 后的节点通常只能作 DHT 客户端，记录实际落在公网节点上。公网节点很少时，bootstrap 事实上就是集中存储点。provider 记录会过期，发布者离线后资源不可发现。
- **AutoNAT。** 需要多个公网节点协助探测，节点太少时可达性判断不可靠。
- **打洞与中继限额。** DCUtR 在对称 NAT 或 UDP 被封时会失败，此时只能走中继。relay v2 的电路通常带时长和字节上限，具体默认值请按所用版本核对。必须写明仅中继连接下大文件的行为：拒绝、限速，或仅在运营者放宽限额的 relay 上允许。
- **滥用控制。** 没有账号时身份成本近乎为零，relay 只能按 peer 和 IP 限制预约数与流量。高峰时正常用户也会被拒。
- **元数据。** relay 运营者看不到内容，但看得到谁连谁、何时连、流量多大，需向用户说明。
- **其他。** relay 的身份密钥和地址要稳定，轮换会使已发布的电路地址失效。带过期时间的签名记录依赖各方时钟大致同步，需定义容差。

## 3. 小任务卡样例：manifest 验证

**任务 T-manifest-01**

- 只修改 `crates/asl-transfer/src/manifest.rs`，测试写在同文件。
- 依赖只用 `blake3`。
- `MANIFEST_MAGIC: [u8; 8]` 与 `MANIFEST_VERSION: u16` 从 `asl-types` 导入，不得自定义。这两个值尚待负责人冻结。

**接口**

```rust
pub fn parse_manifest(bytes: &[u8], expected_content_id: &[u8; 32])
    -> Result<Manifest, ManifestError>;

pub struct Manifest {
    pub file_size: u64,
    pub chunk_count: u32,
    pub file_hash: [u8; 32],
    pub chunk_hashes: Vec<[u8; 32]>,
}

pub enum ManifestError {
    TooShort, TooLong, ContentIdMismatch, BadMagic, BadVersion,
    BadChunkSize, FileTooLarge, ChunkCountMismatch, LengthMismatch,
}
```

**常量**

| 名称 | 值 |
|---|---|
| HEADER | 58 字节（8+2+8+4+4+32） |
| CHUNK | 1 048 576 |
| MAX_FILE | 68 719 476 736（64 GiB） |
| MAX_LEN | 58 + 65 536×32 = 2 097 210 |

**检查顺序（必须严格按此，命中即返回）**

1. len < 58 返回 TooShort。
2. len > MAX_LEN 返回 TooLong。
3. BLAKE3(bytes) ≠ expected 返回 ContentIdMismatch。
4. magic 不符返回 BadMagic。
5. version 不符返回 BadVersion。
6. chunk_size ≠ CHUNK 返回 BadChunkSize。
7. file_size > MAX_FILE 返回 FileTooLarge。
8. 用 u64 计算期望块数：size 为 0 时取 0，否则取 (size + CHUNK − 1) / CHUNK。与 chunk_count 不等返回 ChunkCountMismatch。
9. len ≠ 58 + count×32 返回 LengthMismatch。
10. 以上全部通过后才分配 `chunk_hashes`。

**禁止**

- 不用 `unsafe`，不用 `as` 做窄化转换，不用可能 panic 的下标或 `unwrap`。
- 不做 I/O，不改格式。
- 不在此函数校验 full_file_blake3，那要等下载完成后才能做。

**8 个断言**

测试辅助函数 `build(size, count, chunk_size, n_hashes)` 生成字节并自行计算 content_id。

1. size=0、count=0、总长 58：返回 Ok，`chunk_hashes` 为空。
2. size=1、count=1、总长 90：返回 Ok。
3. size=1 MiB 时 count=1 返回 Ok；size=1 MiB+1 时 count=2 返回 Ok。
4. size=64 GiB、count=65 536、总长 2 097 210：返回 Ok。size=64 GiB+1：FileTooLarge。
5. chunk_size 为 1 048 575 或 2 097 152：BadChunkSize。
6. size=0 且 count=1 带 1 个 hash，或 size=1 MiB+1 且 count=1：ChunkCountMismatch，即使长度与声明的 count 自洽。
7. 合法 manifest 末尾多 1 字节或少 1 字节，并重算 id：LengthMismatch。输入 57 字节：TooShort。头部 count=0xFFFF_FFFF、size=64 GiB、正文仅 58 字节：ChunkCountMismatch，且不发生大分配。
8. 合法字节翻转任意 1 位而 expected 不变：ContentIdMismatch。magic 错误但 id 按错误字节重算：BadMagic，以此证明检查顺序。

**完成证据**

贴出 `cargo test -p asl-transfer manifest` 的原始输出。评审者独立重跑，生成者的自述不算通过。

## 4. 必须由真人复核的内容

- **Windows 平台模块。** AppContainer 与 Job 的配置、句柄继承清单、重解析点拒绝、文件身份与共享模式。
- **授权判定路径。** grant、租约和撤销的全链路，两跳令牌，"无授权等同不存在"的一致性。
- **密钥处理。** DPAPI 的使用、应用签名与验签、nonce 防重放、进程间 IPC 的消息边界。
- **不可信输入解析。** manifest、控制消息、bulk 协议和文档提取 helper，需要模糊测试并由人看结果。
- **模型上下文组装。** 检索前过滤是否真的在每条路径上生效。
- **资源耗尽面。** 额度预留、DHT 与中继限流、去重表上界。
- **依赖与发布。** 许可证与漏洞审计、锁文件、构建来源和发布签名。

理由：这些项的失败是静默的，越权时功能照常工作。弱模型写的测试往往只验证它自己理解的行为，如果理解错了，测试会和实现一起错。沙箱和竞态问题还依赖真实系统的行为，读代码推断不出来。

这不等于日常用户要干预 Agent。复核发生在构建和发布阶段，是一次性门禁。运行时的每个放行决定由已复核的确定性策略代码作出，不由模型作出，也不需要人逐次确认。用户只在建立或撤销授权、添加联系人、授权外部模型端点时做一次决定，其余时间 Agent 在这些边界内自主运行。