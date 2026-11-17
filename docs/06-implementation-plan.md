# ASL Full 1.0 Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` when available. Without those skills, use `prompts/implement-one-task.md` and execute one ready task at a time. No external skill is a runtime dependency.

**Goal:** 完整实现 R01–R30，发布可无人值守运行的 A信 1.0。

**Architecture:** 八个 crate，确定性 core broker 与 libp2p net 属于可信计算基，模型 worker/helper 被隔离。固定协议、策略服务、SQLite、MLS 群状态和纯传输调度器分别测试；GUI 只观察与授权。

**Tech Stack:** Rust 1.100.0、libp2p 0.57.1、OpenMLS 0.9.2、Tokio、SQLite/FTS5、egui/eframe 0.35.0、rmcp、Windows AppContainer/Job Object。

**Spec:** `docs/01-product.md` 至 `docs/05-agent-gui.md`、`schemas/`、`specs/`。

## Global Constraints

- 完整 1.0 包含 R01–R30，不删成 MVP。
- 单文件最多 68,719,476,736 字节，固定块 1,048,576 字节。
- 控制 JSON 最多 65,536 字节，manifest 最多 2,097,210 字节。
- 模型最多一次修复，非法输出整次拒绝。
- 应用层不转发 query；incoming 不产生远端检索。
- 信任/贡献/自动偏好不参与授权。
- E 盘数据和缓存，不静默回落 C 盘。
- Windows 沙箱建立失败时不得普通进程回退。
- 项目自身 MIT，第三方许可独立保留。
- browsing 与 answering 分别授权；默认不自动回答。
- upload/download 每次询问是可选授权策略；确认绑定内容、目标和群 membership epoch，不逐块确认。
- 群消息使用 MLS 端到端加密；只向明确成员点对点投递，不引入群广播 mesh。
- `unsafe` 仅允许在 `asl-policy/src/platform/windows/`，新增位置需专项复核。

## 文件地图

```text
Cargo.toml, Cargo.lock, rust-toolchain.toml, .cargo/config.toml
crates/
  asl-types/src/{ids,error,protocol,identity,manifest,record,task}.rs
  asl-store/src/{db,migrations,resources,quota,transfers,evidence,retention}.rs
  asl-policy/src/{types,service,audience,labels,paths,sandbox}.rs
    identity/{root,device,certificate,rotation}.rs
    platform/windows/{mod,volume,handles,appcontainer,job,dpapi}.rs
  asl-transfer/src/{scheduler,verify,resume,bulk,inline}.rs
  asl-net/src/{driver,behaviour,transport,identity,discovery,dht,pairing,address_policy,relay,codec}.rs
  asl-groups/src/{service,rooms,wire,catchup,storage}.rs
  asl-agent/src/{decision,prompt,gateway,runner,knowledge,reputation}.rs
  asl-app/src/{paths,supervisor,ipc,identity,backup,mcp,ui,update,diagnostics}.rs
    bin/{asl,asl-core,asl-net,asl-worker,asl-infra}.rs
crates/asl-app/tests/home_paths.rs
tests/{integration,adversarial,network}/
assets/{avatars,icons,licenses}/
packaging/{windows,linux}/
```

文件只有在对应任务实施时创建；本资料包没有假装生成这些应用文件。可拆分大文件，但不能改变冻结接口或增加循环 crate 依赖。

## 所有任务的执行循环

- [ ] 读取任务、依赖任务证据和引用规范；只处理当前任务列出的文件。
- [ ] 写出本任务的拒绝/失败测试，运行并确认预期失败。
- [ ] 实现并通过下面列出的全部正反例，不只通过示例断言。
- [ ] 执行格式、lint、相关测试；记录实际命令与结果。
- [ ] 审查 diff；提交或提供可审查补丁，更新任务状态。失败/未运行不得写成通过。

任务卡中的 Rust 片段是验收入口示例；其余向量同样必须实现。测试辅助数据只能是固定夹具，不可读取真实用户目录或密钥。

## 里程碑与依赖

- A：T01–T10，类型/持久化/权限与隔离基础。
- B：T11–T19，资源、网络、发现与对话。
- C：T20–T24，完整文件传输。
- D：T25–T30，普通模型自主流程、经验与接入。
- E：T31–T34，群协议/Agent 集成及完整 GUI。
- F：T35–T36，维护与打包。
- G：T37–T40，独立复核、真实网络及正式发布。

里程碑用于工程验收，不作为缩减版产品对外发布。

### T01 — Workspace、工具链与 E 盘路径

依赖：无。创建根 Cargo 文件、八个 crate、`asl-types/src/error.rs`、`asl-policy/src/platform/windows/volume.rs`、`asl-app/src/paths.rs`、`scripts/dev-env.ps1`、`crates/asl-app/tests/home_paths.rs`。

接口：`AppPaths::open(root: &Path) -> Result<AppPaths, AslError>`；提供 root/state/snapshots/incoming/logs 的只读路径。`dev-env.ps1` 仅修改当前进程的 PATH、CARGO_HOME、RUSTUP_HOME、CARGO_TARGET_DIR、TEMP、TMP，目标均在 E:\ASL。

```rust
assert!(AppPaths::open(std::path::Path::new("relative")).is_err());
```

验收：绝对 E 盘目录可用；相对路径、不可用卷、UNC、reparse、非 NTFS 拒绝；禁止调用系统用户目录 fallback。运行 `cargo check --workspace --locked`，首次生成 lock 后再带 locked 重跑。

### T02 — 依赖与外部 API 编译探针

依赖 T01。创建 `crates/asl-net/examples/transport_probe.rs`、`crates/asl-groups/examples/mls_probe.rs`、`crates/asl-app/examples/gui_probe.rs`、`deny.toml`。

只验证固定版本的 libp2p feature/transport、OpenMLS 协议类型、egui 绘制/重绘、rmcp stdio、SQLite FTS5 运行和 windows API feature。将只供 probe 的依赖留在 dev-dependencies，功能实现任务再提升为运行依赖。把实际使用的外部 API 导入与签名记录在 `docs/dependency-adapters.md`；不得编造方法。

```text
cargo check --workspace --all-targets --locked
cargo run -p asl-app --example gui_probe --locked
cargo run -p asl-net --example transport_probe --locked
cargo run -p asl-groups --example mls_probe --locked
cargo tree --locked
cargo deny check licenses
```

验收：构建成功与锁文件；许可证报告无未批准项。版本冲突只能有记录地调整，不由执行模型同时升级整个依赖树。

T02 实测完成（Windows，Rust 1.100.0）：workspace all-targets 检查、GUI/SQLite、libp2p 和 OpenMLS 三个 probe 均通过；依赖树成功解析；`cargo-deny 0.21.0` 的 `licenses` 检查通过。具体已验证 API 与未覆盖范围见 `docs/dependency-adapters.md`。探针不等同于功能验收，Swarm 构造留在 T14，OpenMLS 状态/provider 集成留在 T31，Windows API 调用留在对应策略任务。

### T03 — ID、错误码与严格控制消息

依赖 T02。创建 asl-types 的 ids/error/protocol/task 与 `tests/protocol.rs`。

接口：`parse_wire(bytes: &[u8]) -> Result<WireEnvelope, AslError>` 和可注入时钟的 `parse_wire_at(bytes, now_ms)`；`WireEnvelope` 严格映射 schema。完成 bytes、深度、未知字段、重复字段、有效设备 PeerId/AgentId 文本、设备证书字段格式与时间关系校验。证书签名验证属于 T06/T14，不在纯解析器中伪造信任。

```rust
assert!(parse_wire(br#"{"v":1,"v":1}"#).is_err());
assert!(parse_wire(&vec![b'x'; 65_537]).is_err());
```

其他验收：合法 hello/query/offer/fetch；错误 major、过期、expires<created、无效 hash/PeerId/AgentId/设备证书格式、重复字段（含嵌套 body）、未知 body 字段拒绝。所有 ErrorCode 线格式可往返。

T03 完成（2026-11-17）：新增强类型 ID、时间与错误码；按 wire schema 解析所有控制消息，帧上限/未知字段/重复字段/嵌套深度/身份格式/版本/时间均有拒绝测试。身份签名验证明确留给后续身份服务。`cargo test -p asl-types --locked` 10 项通过；workspace 全量测试也通过。

### T04 — Manifest 编解码与内容 ID

依赖 T03。创建 `asl-types/src/manifest.rs`，接口严格按协议文档，不采纳咨询稿的另一套 parse_manifest 名称。

```rust
let m = Manifest {
    file_size: 0,
    file_hash: *blake3::hash(b"").as_bytes(),
    chunk_hashes: vec![],
};
let bytes = encode_manifest(&m).unwrap();
assert_eq!(bytes.len(), 58);
let id = *blake3::hash(&bytes).as_bytes();
assert_eq!(decode_manifest(&bytes, id).unwrap().file_size, 0);
```

全部向量：0、1、1MiB、1MiB+1、64GiB、64GiB+1；57 字节；错误 magic/version/chunk_size；count=0xFFFFFFFF；缺/多 1 字节；修改 bytes 而 expected 不变。检查顺序遵循协议；禁止大分配和 panic。

### T05 — SQLite 初始化与迁移

依赖 T03。创建 asl-store db/migrations，导入提供的 SQL。接口 `open_store(path: &Path) -> Result<Store, AslError>`。

```sql
PRAGMA foreign_key_check;
SELECT revision FROM policy_state WHERE singleton=1;
```

验收：第一次初始化为版本 1，重复启动不重复建表；WAL/外键/同步设置正确；中断迁移回滚；更高未知 schema 停止，不删除数据库重建。SQL 注入文本只作为绑定参数。

### T06 — AIK、设备证书与 DPAPI

依赖 T05。创建 policy windows/dpapi 和 app identity 组合模块；测试用新生成身份，不读真实密钥。

接口拆为 `AgentIdentity::generate()`、`agent_id()`、`issue_device_certificate(device_peer_id, serial, validity)` 和独立 `DeviceIdentity::generate()`。AIK 使用 DPAPI/受限 keystore 保护；AIK 签名覆盖协议定义的规范二进制。此任务不把 AIK 注入 net，也不把设备 PeerId 当作稳定联系人身份。

```rust
let root = AgentIdentity::generate().unwrap();
let old_device = DeviceIdentity::generate().unwrap();
let cert = root.issue_device_certificate(old_device.peer_id(), 1, now_ms, expires_at_ms).unwrap();
assert!(cert.verify_for(root.agent_id(), old_device.peer_id(), now_ms).is_ok());
```

验收：重启后 AgentId 不变；设备密钥轮换后新 PeerId 由同一 AIK 认证；签名篡改、错误 AgentId/PeerId、过期/回滚 serial 均拒绝；net 只接收设备密钥内存副本且仅经私有 IPC；worker、日志、诊断无密钥；重置必须显式授权。PAKE/签名算法只复用已审查库，不自创协议。

### T07 — 纯授权判定与派生交集

依赖 T05。创建 policy types/service/audience/labels；实现冻结 PolicyService。

测试构造固定 public、contacts、peers 和 revoked grant。断言：无联系人授权则 contacts 拒绝；preferred 成员也拒绝；贡献从 0 改到任意高仍拒绝；交集只允许同时满足全部叶来源的 peer。

```text
cargo test -p asl-policy --test grant_policy
```

额外向量：epoch 变化、provider 不匹配、never、local_only、溯源环/深度 5/来源 33；全局 revision 的无关变更不取消仍然合法的 permit。

### T08 — Windows 文件句柄安全

依赖 T07。只创建 policy paths、windows/handles 和 `tests/path_boundaries.rs`。接口 `open_authorized_source(grant, relative) -> Result<AuthorizedFile, AslError>`，AuthorizedFile 不暴露可随意重开的路径。

```text
cargo test -p asl-policy --test path_boundaries -- --nocapture
```

测试夹具在 E:\ASL\work\test-fs，包含 inside/allowed.md、outside/secret.md、junction、symlink、硬链接、ADS 和重命名竞争。真实测试拒绝越界、硬链接>1、设备/UNC/绝对路径/短名绕过；普通允许文件正确读出。测试后只清理自己创建且已验证在该根下的路径。

### T09 — AppContainer 与 Job Object

依赖 T08、T02。创建 policy sandbox、windows/appcontainer/job，以及 probe helper。

接口 `spawn_sandbox(role, inherited_handles, limits) -> Result<SandboxChild, AslError>`；role 为 Net/Worker/Extractor；句柄使用显式 allowlist。

```text
cargo test -p asl-policy --test sandbox_probe -- --nocapture
```

验收在真实 Windows 测得：worker 读 outside、连 HTTP、启动子进程均失败；net 可进行获准 TCP/QUIC、mDNS，但读用户目录失败。AppContainer/Job 失效、ACL 不支持、句柄遗留均失败关闭。此任务必须独立复核，不能伪造 probe 返回值。

### T10 — Supervisor 与有界 IPC

依赖 T09、T06。创建 app supervisor/ipc 和四个 Windows bin 入口。

接口 `Supervisor::start(AppPaths)`；IPC 消息枚举固定，不接 shell command/path。连接身份使用私有继承管道，net peer 事件只来自已认证 driver。

验收：超 4MiB、未知角色、重复序列、非法操作拒绝；core 退出杀死子进程；worker 崩溃只失败当前任务；stderr 不污染 MCP stdout。

```text
cargo test -p asl-app --test supervisor_ipc
```

### T11 — 不可变快照与源目录对账

依赖 T10。创建 store resources、policy importer；导入时稳定读源、hash、写快照、落资源引用，成功后才公告。

接口 `import_source(grant_id, relative) -> ResourceKey`；磁盘对象以 kind/content_id 区分。外部更改触发 watcher，对账每 30 秒补漏。

验收：同内容两个 grant 物理去重但权限分离；导入失败不留下 ready；源改变/删除停止新 lease；导入期间撤销不发布；额度不足不读完整超大文件。

```text
cargo test -p asl-store --test snapshot_import
```

### T12 — 授权前置的全文检索

依赖 T11。创建 store search adapter，使用 jieba+FTS5。实现 visible_keys/search_visible。

验收固定夹具：public Rust、contact 私有 PDF 文本、无权 inbox。陌生 peer 检索“密码”不能得到私有命中、摘要、计数或模型片段；联系人仅看到明确授权集合。MATCH 特殊字符和 SQL 文本不改变查询结构。

```text
cargo test -p asl-store --test visible_search
```

### T13 — 记录签名与公开资料

依赖 T06、T03。创建 types record 与 app profile 服务。

接口 `sign_record(kind, payload, sequence, lifetime)` 与 `verify_record(bytes, expected_agent, now)`；以 AIK 按协议原始字节签名。profile、设备目录和持久短码声明都以 AgentId 为 owner。

验收：payload/owner/seq/时间/长度任一篡改失败；过期与旧 sequence 不替换新值；撤下资料停止续发；头像只发布内容引用不写 DHT 本体。

```text
cargo test -p asl-types --test signed_records
```

### T14 — libp2p Driver

依赖 T02、T10、T13。创建 net behaviour/transport/driver。

应用接口：`NetworkCommand` 枚举 Dial/SendControl/SendBulk/FindProviders/Provide/Unprovide/PutProfile/Stop；`NetworkEvent` 枚举 TransportConnected/IdentityVerified/Control/Bulk/Providers/Disconnected/Error。普通 Control 事件仅在 core 确认 AgentId/设备证书后产生。禁止将 libp2p 类型散布到 agent、store 和 GUI。

验收双进程 QUIC 与 TCP 的真实加密连接、有效设备 PeerId；传输认证后验证 AIK 设备证书且证书 PeerId 必须等于认证连接；伪造 AgentId、重放/过期/撤销设备证书均拒绝，身份验证前不放行应用消息；控制/大帧分 codec；关闭无资源泄漏。

```text
cargo test -p asl-net --test two_node_transport
```

### T15 — 引导、中继、NAT 与基础设施

依赖 T14。创建 net relay、app/bin/asl-infra、Linux systemd 示例。

基础设施只做 DHT/AutoNAT/relay，不具备 Agent 文件和模型能力。支持配置多个入口、稳定运营密钥、reservation/circuit/字节/时间/全局限制。

验收一个入口离线另一个可用；断网后恢复；中继耗尽产生 relay_capacity 并可恢复；允许 relay 承载多块文件；仅中继模式不发布或拨打暴露本机公网 IP 的直连地址，并显示 relay 可见的连接元数据边界。

发布前部署实际入口，生成打包用 network-seeds.json，字段为 version/network_id/generated_at_ms/expires_at_ms/nodes。nodes 每项含 operator_id/peer_id/multiaddrs/roles，roles 仅 bootstrap/relay/autonat；最多 32 个节点、每节点 8 个地址。由发布清单签名保护，不能填不可达假地址交付。用户自定义入口可替换整份内置列表，不需要中央准入。

```text
cargo test -p asl-net --test relay_failover
```

### T16 — mDNS、地址策略与连接观察

依赖 T14、T09。创建 net discovery。

验收 LAN 自动 hello；伪 mDNS 服务、错误协议、回环/公网/私网策略按配置过滤；DNS 解析后复查地址；禁止把 multiaddr 当 HTTP/SMB URL；证书验证前只允许有界身份握手；过期观测不显示在线。AppContainer 真机下验证组播与防火墙，不放宽沙箱绕过失败。

```text
cargo test -p asl-net --test discovery_policy
```

### T17 — DHT 标签与记录过滤

依赖 T13、T15。创建 net dht。

规范化由固定 Rust/toolchain 与 unicode-normalization 实现；测试 `ＲＵＳＴ -> rust`、`Ａ信 -> a信`、`Straße -> straße`、分解重音字母合并。协议文档记录实际 Unicode 数据版本并固定测试向量。

验收 public 才 start_providing；contacts/content 无公共广告；持久短码键允许多候选、声明必须由 AIK 签名且客户端复算；冲突不覆盖；128 标签上限、8KiB value、10k记录/64MiB 存储限制；非法签名 PUT 不落库。

```text
cargo test -p asl-net --test dht_limits
```

### T18 — 有界查询路由

依赖 T12、T17。创建 agent query router。

接口 `start_query(task: OutgoingTask) -> TaskId`；联系人先于新节点，最多 3 个 DHT term/16 peers/10 秒。incoming 只本地检索，不能把任何 query 直接转发。

验收三节点环不产生转问；query 被重放只处理一次；10 秒后不新增派发；contacts-only 任务不向 DHT 披露 term。

```text
cargo test -p asl-agent --test bounded_queries
```

### T18a — 数字短码与 PAKE 配对

依赖 T06、T14、T17。创建 `asl-net/src/pairing` 与身份解析 adapter。持久 16 位短码只查询候选；首次核验使用二维码/签名邀请或有期限的一次性 PAKE 码。PAKE 依赖需在本任务锁定前审查维护状态、许可和 API；不自行设计或拼接密码学协议。

验收：持久短码碰撞返回多个未核验候选；伪造声明、过期码、错误口令和 transcript/PeerId 不匹配拒绝；在线尝试最多 5 次，成功/过期后邀请码不可重放；配对成功只建立本地 AgentId pin，不隐式扩大目录授权。

### T19 — 会话、消息与有限 outbox

依赖 T18、T05。创建 store messages/outbox、agent conversation。

验收最多 3 回合/6 语义消息，answer/ack/error 不创建任务；重启不重新回答旧消息；离线最多 3 次本机重试且总 10 分钟。fetch_grant 和 lease 不进聊天/outbox。

```text
cargo test -p asl-agent --test conversation_lifecycle
```

### T20 — Fetch、lease 与撤销栅栏

依赖 T19、T07。创建 policy leases 和 core fetch handler。

实现 fetch_request/fetch_grant、60 秒随机 lease；绑定 authenticated peer/content/grant epoch。无权限/不存在统一 not_found。

验收：错 peer、错 content、过期、重启旧 lease、contacts 撤销均拒绝；无关 grant 更新重判后继续；读取前和发送前撤销都停止新披露。

```text
cargo test -p asl-policy --test lease_revocation
```

### T21 — Bulk codec 与安全块服务

依赖 T20、T04。创建 transfer bulk、net codec。

验收固定 91 字节请求、27 字节响应头，未知 op/status、长度不符、超上限拒绝；块 index 推导长度，不能指定任意 offset；没有 lease 不打开 snapshot；响应 ID 不匹配不写盘。

```text
cargo test -p asl-transfer --test bulk_codec
```

### T22 — 纯多来源调度器

依赖 T21。创建 transfer scheduler/verify。实现协议中的 ChunkScheduler，不做网络或磁盘 IO。

测试用假时钟固定来源 A/B/C/D：每来源最多 2、全下载最多 4 来源；超时重派；正确块 Verified；3 个坏 hash 禁用来源；重复块不重复完成。

```text
cargo test -p asl-transfer --test scheduler_faults
```

### T23 — 下载持久化、恢复与额度

依赖 T22、T05。创建 store quota/transfers 和 transfer resume。

验收：先预留、校验再写、sync 再 durable；每个崩溃点恢复；已标块重验；磁盘满安全停止；无进展 5 分钟释放；坏 manifest/整文件 hash 不一致冷却 24 小时不循环下载。

```text
cargo test -p asl-transfer --test resume_crash_points
```

### T24 — Inline、PDF 与头像 helper

依赖 T23、T09。创建 transfer inline、app helper roles、受限头像重编码。

验收：32KiB inline 上限、未经请求的附件不落盘；PDF 提取 10 秒/512MiB 限制、超页数/输出长度拒绝；解压炸弹/巨大像素/恶意 SVG 拒绝。PNG/WebP 头像重编码≤128×128、≤64KiB；不能自动执行或打开任何收到的文件。

```text
cargo test -p asl-app --test hostile_documents
```

### T25 — 模型 provider 与固定 HTTP 网关

依赖 T10、T07。创建 agent gateway 与 provider registry。

接口 `ModelGateway::complete(provider_id, AuthorizedPrompt) -> ModelText`；只有 core 调用。固定已授权 endpoint，无自动跳转；key 从 DPAPI 引用取，不进提示词。

验收 mock endpoint 的超时、错误、超大响应、重定向、授权外provider；远端文本中的 URL 不产生 HTTP；本地模型必须单独获准。无真实收费服务也能用 mock 跑测试。

```text
cargo test -p asl-agent --test model_gateway
```

### T26 — 严格模型 JSON 与修复

依赖 T25、T03。创建 agent decision/prompt。

接口按规范 validate_decision。通过条件同时是 schema、候选成员、当前授权、action 与方向。

```json
{"v":1,"action":"decline","text":"","refs":[],"terms":[],"reason_code":"no_match"}
```

验收上述合法；未知字段、额外 path、自由 Markdown、假 refs、重复字段、过长 text、answer 无 refs、decline 带文本都整次拒绝。一次修复失败固定 model_invalid，绝不部分执行。

### T27 — 自主状态机

依赖 T26、T18、T23。创建 agent runner。

验收 incoming 不调用远端查询；outgoing 只在授权范围内选资源；无事件不调用模型；answer 不自发回应；6 消息/3 轮/超时终止；模型不可用时资源匹配仍可确定性工作并如实标记 unavailable。

```text
cargo test -p asl-agent --test autonomous_state_machine
```

### T28 — 经验整理与权限继承

依赖 T27、T07。创建 agent knowledge 与 derivation_sources 仓储。

验收：local public 派生在规则授权后可发布；只要一个来源私有或远端不可复用即私有；循环/超深/源撤回后失效；模型不能把经验写成 policy 或 system prompt。写入只 create-new，受独立 write_grant 约束。

```text
cargo test -p asl-agent --test knowledge_labels
```

### T29 — 信任、贡献与公平队列

依赖 T28。创建 store evidence、agent reputation。

验收 `task/content/help_kind` 重复贡献只 1 条；incoming 垃圾资源不加贡献；换身份不能突破全局额度；preferred 不变 authorized_contacts；无授权的高分节点仍拒绝；可用性失败与恶意分开。

```text
cargo test -p asl-agent --test reputation_is_not_authority
```

### T30 — 本机 stdio MCP

依赖 T27、T29。创建 app mcp 和 CLI 子命令。

固定四工具，参数按 Agent 规范；输入 task/offer 必须属于当前本机授权会话，不接受任意路径/URL。

验收宿主工具调用 -> 后台任务 -> 结果/来源/下载全链路；stdout 纯协议；未知工具拒绝；ASL 不自动导入宿主聊天或扩大权限。

```text
cargo test -p asl-app --test mcp_contract
```

### T31 — OpenMLS 群房间与加密投递

依赖 T06、T14、T19。创建 `asl-groups` 房间服务、持久化适配器、基于现有认证连接的逐成员 fan-out 与定向邀请协议。优先复用 OpenMLS 0.9.2 的 RFC 9420 实现；不得自创群密钥、消息加密或成员树。

固定应用约束：最多 64 名成员、群消息最多 64 KiB、群事件本地保留 7 天、状态 catch-up 最多 256 个 epoch。MLS credential 必须绑定稳定 AgentId 与当前设备证书；迁移设备通过新叶子入组，不复制旧 ratchet 状态。仅当前成员收到群帧，OpenMLS 仅在核验 authenticated sender、AIK 证书、群成员和 epoch 后处理消息。群标识、群名、成员清单和群资源不发布到 DHT。

验收：邀请仅定向到指定 PeerId；加入前不接收群帧；非成员、伪造 credential、过期或重复消息、未授权成员变更和超预算 catch-up 均拒绝。并发/陈旧 commit 可恢复或明确进入 `needs_sync`，不静默分叉。离线成员消息尽力投递、不承诺必达；状态可从获准成员同步有限 commit，超预算后需重新邀请。验证成员退出/移除后的新消息不可解密，并说明旧消息无法远程删除。

### T32 — 群策略、浏览/回答与传输确认

依赖 T07、T20、T27、T31。创建确定性策略与 Agent 群事件适配。添加 `browse_enabled`、`answer_enabled`；回答关闭时保留群消息浏览但模型调用/回答数为零。群回复不能触发新回复；按 group/message ID 去重并沿用单轮预算。

新增 `group` 资源 audience；仅显式授权给群的资源可由当前成员获取。群 membership epoch 进入 permit/lease；成员变化后重判，移除成员失去新读取权限，既有副本不可召回。上传和下载分别支持 `authorized` / `ask`。ask 确认绑定 transfer、content ID、接收方或本地目标、grant epoch、可选 group epoch 与过期时间；超时拒绝，任何绑定变化要求重新确认，块级请求不得弹窗。

验收：浏览-only 收到并显示消息但不运行模型；回答关闭时无 query/answer 输出；偏好/贡献不能扩群权限；群成员不能读取未授权目录；撤销或成员移除使未发 lease 失效；未确认传输不读取/写入文件，过期确认拒绝，已确认内容/目标/epoch 改变后拒绝继续。

### T33 — 只读 GUI 与像素资产

依赖 T19、T23、T29、T32。创建 app ui、assets 及授权清单。

先实现只读 view model，UI 不直接操作数据库。包含概览、活动、节点、群组、传输、经验、信任/贡献和授权导航。稳定尺寸，无持续动画。

验收 1280×800、1920×1080、960×640 与 125%/150%/200% DPI；中文长名不溢出；无自由聊天输入/手动查询/积分编辑；关闭 GUI 后后台继续。提供真实构建截图：会话、短码候选、身份核验、授权、传输、群组、迁移。使用一次性测试身份并去除真实地址、路径和可关联身份信息。提供空闲重绘计数、独立图标及 Q 版女孩吉祥物；资产来源和许可证登记齐全。

### T34 — 授权界面与即时生效

依赖 T33、T07、T20、T32。创建 ui permissions/profile/provider/contact/group 视图。

所有写操作调用 PolicyService，不直接更新分数。公开字段修改、数据范围、联系人/群成员、模型、网络、浏览/回答、传输询问模式、保留/额度均显示将披露什么。

验收撤销立即触发栅栏；新联系人不是自动偏好；身份重置不隐式继承信任；无授权不能自动启动生图/云模型；目录选择默认 E。

### T35 — 保留、备份、诊断与崩溃恢复

依赖 T34、T23。创建 store retention、app diagnostics。

验收 7 天消息清理、3 天失败 part、30 天 inbox；不会延长人类上限；存在引用对象不误删；恢复不重建空授权；导出诊断不含 key/lease/原文敏感内容。提供版本化加密迁移包，支持用户选择本地 ASL 数据；导入保留 AIK、联系人、信任和选定记录，目标设备生成新设备密钥/证书；目录 grant、OS 凭据不迁移，MLS ratchet 不复制，需重新授权/入组。诊断导出是对输出目录的授权，默认不外传。

```text
cargo test -p asl-app --test retention_backup
```

### T36 — 便携包、登录启动与签名更新

依赖 T35。创建 packaging/windows、app update。

后台定义为当前 Windows 用户登录后的常驻进程，不冒充 SYSTEM 服务使用用户 DPAPI。便携包所有可控路径留 E；系统创建的小量 AppContainer/图形元数据如实说明。

更新使用已固定公钥验证清单签名、包 hash、版本/回滚策略；支持替换更新源和手动导入已签名包，不把更新站变成身份/运行必需服务。安装失败回滚二进制，不回滚授权数据库到更宽松状态。

### T37 — 独立安全复核与 fuzz

依赖 T36。创建 tests/adversarial、fuzz targets。

完成测试文档 A01–A20、A21 群成员/MLS/授权确认及身份/配对/迁移用例。优先路径/句柄、AIK/设备证书绑定、PAKE 重放与尝试限制、AppContainer 权限、签名/撤销竞态、manifest/codec、模型输入前过滤和额度。

```text
cargo test --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
```

保存 fuzz 种子、时长和崩溃复现，不把“没发现”写成证明安全。未解决的越权或身份错误禁止发布。

### T38 — 真实网络与 72 小时运行

依赖 T37、T15。创建 tests/network 测试驱动与报告。

20 节点，覆盖至少两个独立入口/中继运营配置、LAN、家庭 NAT、UDP 被限、仅中继网络、入口全失效后恢复。完整文件的多源、恢复和大文件中继均测试。

验收 72 小时队列/内存/磁盘有界；无任务模型调用为 0；无资源漏记；记录实际直连成功率而不作 100% 承诺。

### T39 — 普通编码模型与运行模型验收

依赖 T38。使用同一版本输入契约，将 T04、T18、T26 的独立副本交给目标 6.1sol/DeepSeek 等模型，不开放真实密钥/用户目录。

验收记录每模型的实际 model_id、提示词、重试次数、编译/测试输出和人工修正；不能只让设计模型“模拟弱模型”。运行模型另测试合法率、引用准确率与非法输出 fail-closed。

本任务没执行前只能说“按普通模型设计”，不能说“已确保所有弱模型完成”。

### T40 — 完整发布与追溯

依赖 T39、T32。完成中文完整置顶、英文完整置底的 README，包含真实构建截图、Agent 身份/配对图解、授权说明、协议、MIT/第三方 notices、图标与吉祥物资产清单、SBOM、构建来源、签名包、Linux infra 部署样例和所有 R 编号证据。

发布条件：R01–R30 全部有实现与实际验收；A01–A21 和新增身份/配对测试无阻断问题；真实网络/沙箱报告齐全。不得用演示视频、mock 或开发者的声明替代。

## 需求到任务映射

| 需求 | 主要任务 |
| --- | --- |
| R01–R03 | T06、T07、T13、T18a、T29、T34、T35 |
| R04–R06 | T14–T18 |
| R07–R09 | T19、T25–T27、T30 |
| R10–R11 | T07–T13、T17、T20 |
| R12–R14 | T20–T24 |
| R15–R16 | T28–T29 |
| R17–R18 | T33–T34 |
| R19–R20 | T05、T19、T23、T35 |
| R21–R22 | T09–T10、T25–T27、T37、T39 |
| R23–R26 | T01、T06、T15、T35–T40 |
| R27 | T02、T05、T14、T19、T20、T31–T34 |
| R28 | T06、T35 |
| R29 | T13、T17、T18a、T33 |
| R30 | T14–T18a、T33–T34、T37–T38 |

## 工作量判断

这是包含 Windows 隔离、网络和完整传输的中等规模系统，不是一次提示词能可靠完成的小应用。以 1–2 名熟悉 Rust 的工程人员负责复核、代码模型承担局部实现为假设，完整产品估算 4–8 个月；真实网络、沙箱或安全复核不通过会延长。估算不是工期承诺，也不能靠删验收换速度。
