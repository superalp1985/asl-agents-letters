# ASL Full 1.0 Implementation Plan

> **For agentic workers:** Use `superpowers:subagent-driven-development` or `superpowers:executing-plans` when available. Without those skills, use `prompts/implement-one-task.md` and execute one ready task at a time. No external skill is a runtime dependency.

**Goal:** 完整实现 R01–R33，发布可无人值守运行的 A信 1.0。

**Architecture:** Rust workspace 分层实现；确定性 core broker 与 libp2p net 属于可信计算基，模型 worker/helper 被隔离。确定性 CBOR/CDDL 语义协议、身份根/公共链校验、策略服务、SQLite、MLS 群状态和纯传输调度器分别测试；GUI 只观察与授权。

**Tech Stack:** Rust 1.100.0、libp2p 0.57.1、OpenMLS 0.9.2、Tokio、SQLite/FTS5、egui/eframe 0.35.0、rmcp、Windows AppContainer/Job Object。

**Spec:** `docs/01-product.md` 至 `docs/05-agent-gui.md`、`schemas/`、`specs/`。

## Global Constraints

- 完整 1.0 包含 R01–R33，不删成 MVP。
- 单文件最多 68,719,476,736 字节，固定块 1,048,576 字节。
- 控制 CBOR 最多 65,536 字节，manifest 最多 2,097,210 字节；控制协议不定义自由文本字段。
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
contracts/{src/IdentityRegistry.sol,test/IdentityRegistry.t.sol,foundry.toml}
```

文件只有在对应任务实施时创建；本资料包没有假装生成这些应用文件。可拆分大文件，但不能改变冻结接口或增加循环 crate 依赖。

## 所有任务的执行循环

- [ ] 读取任务、依赖任务证据和引用规范；只处理当前任务列出的文件。
- [ ] 写出本任务的拒绝/失败测试，运行并确认预期失败。
- [ ] 完成一个可审查功能切片后，集中运行其正反例、格式和 lint。
- [ ] 记录实际命令与结果；未运行的检查不得写成通过。
- [ ] 审查 diff；提交或提供可审查补丁，更新任务状态。失败/未运行不得写成通过。

任务卡中的 Rust 片段是验收入口示例；其余向量同样必须实现。测试辅助数据只能是固定夹具，不可读取真实用户目录或密钥。

## 里程碑与依赖

- A：T01–T10（含 T06a/T06b），类型/持久化/身份链/权限与隔离基础。
- B：T11–T19，资源、网络、发现与对话。
- C：T20–T24，完整文件传输。
- D：T25–T30，普通模型自主流程、经验与接入。
- E：T31–T34，群协议/Agent 集成及完整 GUI。
- F：T35–T36，维护与打包。
- G：T37–T40，独立复核、真实网络及正式发布。

里程碑用于工程验收，不作为缩减版产品对外发布。

### 当前恢复点（2026-11-18）

T07 授权核心、T08 文件句柄能力、T13 签名记录核心和 T06b 显式检查点续期切片已完成；固定协议样例已覆盖全部帧和记录。T09 沙箱首轮实现和本机否定探针已完成，独立复核后更新了继承句柄窗口与 UDP 确认测试。仍缺真实 UDP 回包、QUIC 和 mDNS 请求/响应验收，T09 不标整体验收完成。后续依赖 T09 的 T10 supervisor 及之后任务可在隔离接口上继续实施，但真实网络验收继续作为单独发布阻断。T08 本机不能创建真实符号链接或取得实际 8.3 别名，缺失向量由用户操作的 NTFS 云机补齐，不修改本机权限或卷设置。

云机补跑更新：首次完整日志证明实际符号链接和 8.3 别名已执行，暴露卷根 SUBST 的测试盘符硬编码。修正后用户反馈完整重跑 22 项通过、0 失败、1.27 秒；本次只提供结果摘要，没有新完整日志或提交 SHA。结合之前真实夹具日志与本机 SUBST 实测，T08 本任务验收完成，可以实施 T09。云机环境自 2026-11-18 起保留 7 天，后续系统测试按需使用；不是整个产品验收。

T06b 仍有真实多服务兼容、检查点授权界面、后台/进程额度和独立安全审计未完成；T13 仍需后续 DHT、持久历史和真实投递集成。以上核心切片完成不等于整个 1.0 或这些集成任务完成。

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

### T03 — ID、错误码与确定性 CBOR 协议

依赖 T02。创建 asl-types 的 ids/error/protocol/task 与 `tests/protocol.rs`。

线格式以 `schemas/asl-v1.cddl` 为真源；采用确定性 CBOR crate，具体依赖和 feature 在本任务前核实并固定，不手写 CBOR parser。把旧 JSON wire schema/parser 标记为 prototype 并从 ASL/1 入口移除。

接口：`decode_control(bytes: &[u8]) -> Result<WireFrame, AslError>`、`encode_control(&WireFrame) -> Result<Vec<u8>, AslError>`；时间由策略层验证，不让 codec 读取系统时钟。完成 bytes、深度、未知字段、重复 map key、定长 ID、设备证书字段格式与关系约束校验。证书/链状态签名验证属于身份模块，不在纯 codec 中伪造信任。线上值不含 text string。

```rust
assert!(decode_control(&too_long_frame).is_err());
assert!(decode_control(&duplicate_key_frame).is_err());
```

其他验收：合法 hello/query/offer/fetch；错误 major、expires<created、无效长度/PeerId/AgentId/设备证书格式、重复键（含嵌套 body）、未知字段/枚举、tstr 或任意 prose、未知 critical concept、超深/不定长/非确定性编码和尾随字节拒绝。当前时间过期由策略层判断；codec 只校验时间格式与字段关系。ErrorCode 在线格式为数字枚举。

T03 实现状态（2026-11-17）：旧 JSON parser/schema 已隔离到 `schemas/prototype/`；Rust CBOR codec、固定枚举和协议测试已实现。9 项协议测试、workspace 全量测试、Clippy 和格式检查通过；`scripts/validate-cddl.ps1` 通过 CDDL 语法检查及固定 ACK 向量验证。完整多帧互操作套件仍待补。

T03/T13 固定样例补充（2026-11-18）：共享原有协议夹具，新增 14 帧/3 记录的固定十六进制向量、3 个结构反例、结构化索引与默认只读的导出检查器。4 项向量测试及工作区共 251 项测试通过，Clippy、格式和许可证检查通过；独立 `cddl 0.10.7 --ci` 按每种精确 root 验证 17 接受/3 拒绝均符合预期。新增 serde_json 仅为已固定版本的 dev-dependency，线上格式和运行依赖未变。多节点互操作仍待 T14 以后完成，具体证据见 `docs/protocol-vectors.md`。

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

T04 完成（2026-11-17）：实现固定二进制 manifest 编解码和 BLAKE3 ContentId；解析前限制最大字节数，校验版本、文件大小、块长/数量、精确长度、空文件 hash 与期望 ID。7 项 manifest 测试及 workspace 全量测试、Clippy、格式检查通过。

### T05 — SQLite 初始化与迁移

依赖 T03。创建 asl-store db/migrations，导入提供的 SQL。接口 `open_store(path: &Path) -> Result<Store, AslError>`。

```sql
PRAGMA foreign_key_check;
SELECT revision FROM policy_state WHERE singleton=1;
```

验收：第一次初始化为版本 1，重复启动不重复建表；WAL/外键/同步设置正确；中断迁移回滚；更高未知 schema 停止，不删除数据库重建。SQL 注入文本只作为绑定参数。

T05 实现记录（2026-11-17）：SQLite `open_store` 与 schema v1 迁移已实现，包含 WAL、外键、FULL 同步、未知/局部数据库拒绝且不重建、事务失败回滚和绑定参数。6 项 store 测试及工作区测试、Clippy、格式检查通过。CBOR codec 是 T03 的独立实现；registry 合约已在 T06a 实现，轻客户端与状态证明仍属于 T06b 待实现范围。

### T06 — 身份根、设备证书与 DPAPI

依赖 T05。创建 policy windows/dpapi 和 app identity 组合模块；测试用新生成身份，不读真实密钥。

接口拆为 `AgentIdentity::generate()`、`agent_id()`、`issue_device_certificate(device_peer_id, serial, issued_at_ms, expires_at_ms)`、`verify_device_certificate(...)` 和独立 `DeviceIdentity::generate()`。身份根使用 secp256k1 ECDSA；证书按 `docs/03-protocol.md` 的规范字节构造，经 Keccak-256 后签名，65 字节签名为 `r || s || v`，其中 `s` 为 low-S、`v` 为 27/28。AgentId 按 `specs/identity-registry-v1.md` 派生。根密钥及设备私钥使用 Windows 当前用户 DPAPI 保护；存储路径由调用方提供，创建使用 create-new，不覆盖旧身份。加载失败不静默生成新身份。此任务不把根密钥注入 net，也不把设备 PeerId 当作稳定联系人身份。具体 Rust 密码学 crate/API 须核实成熟度与许可后固定，不自写椭圆曲线逻辑。

```rust
let root = AgentIdentity::generate().unwrap();
let old_device = DeviceIdentity::generate().unwrap();
let cert = root.issue_device_certificate(old_device.peer_id(), 1, now_ms, expires_at_ms).unwrap();
assert!(verify_device_certificate(
    &cert,
    root.agent_id(),
    &old_device.peer_id(),
    root.controller_address(),
    1,
    now_ms,
).is_ok());
```

验收：重启后 AgentId 不变；设备密钥轮换后新 PeerId 由同一身份根认证；签名篡改、错误 AgentId/PeerId、过期/回滚 serial 均拒绝；net 只接收设备密钥内存副本且仅经私有 IPC；worker、日志、诊断无密钥；重置必须显式授权。PAKE/签名算法只复用已审查库，不自创协议。

T06 实现记录（2026-11-17）：已固定并编译 `k256 0.14.0`、`sha3 0.12.0`、`rand 0.10.4`；完成根身份/AgentId 派生、独立 libp2p Ed25519 设备密钥、设备证书签发与本地验证、Windows 当前用户 DPAPI 保护文件、由 `AppPaths` 数据根派生的 identity 目录。工作区测试、Clippy、格式检查通过。尚未实现或验收：身份链最终化状态/撤销证明、net 私有 IPC 密钥交付、设备证书目录/链 commitment、PAKE、跨用户/跨机器恢复及迁移 UI。DPAPI 仅完成当前用户本机往返测试；身份与路径模块仍需独立安全复核。

### T06a — 最小公共链身份合约（已实现，2026-11-17）

依赖 T06。实现 `specs/identity-registry-v1.md` 中 immutable registry：register、state update、root rotation、irreversible revoke。合约无 owner、管理员、升级入口、个人资料或任意调用。EIP-712 domain 绑定 chain/contract；sequence/deadline 由合约强制。使用固定合约测试工具链与测试向量；本任务不部署主网，不引入代币或收费功能。

验收：AgentId 抢注/重复注册失败；伪签名、错误 domain、错误 chain、重复/跳跃 sequence、过期 deadline、无新控制密钥持有证明、吊销后更新全部失败；storage slots 和代码 hash 纳入规范。部署主网前须有独立合约审计和正式部署提案。

T06a 实现记录（2026-11-17）：新增 `contracts/src/IdentityRegistry.sol`，采用 OpenZeppelin Contracts 5.5.0（固定上游 commit）ECDSA/EIP-712。Foundry 1.9.0、Solidity 0.8.24 与 Cancun/optimizer 200/no-IR/无 metadata 构建参数固定。14 项合约测试通过，覆盖注册、AgentId 派生、伪签名与错误 domain/chain、部署后 chain ID 变化、序号重放/跳号、过期 deadline、根轮换双方签名与旧根拒绝、不可逆撤销和 storage slot 布局。运行时代码大小 4,548 字节；未打补丁的 runtime bytecode template hash、存储槽及完整操作签名均记录在 `specs/identity-registry-v1.md`。未部署，未做 gas 主网测量、独立审计、轻客户端或 storage proof；这些不是本任务的已验收范围。

### T06b — 链轻客户端与状态证明验证

依赖 T06a。通过版本化 Rust `IdentityResolver`/`IdentityProofVerifier` 接口接入现成 Ethereum light client 和成熟 MPT proof verifier；不信任单一 RPC 或 indexer，不自写共识/Trie 密码学。先对 Helios/Alloy 等候选做固定版本、许可证、API、Windows 资源限制和 proof 支持探针，未通过不锁定为运行依赖。

验收：可信 checkpoint、finalized header 更新、合约 code hash、account/storage proof、本机缓存过期、错误 RPC 和链重组均有固定测试；正向身份更新须在最终化后生效。chain proof 失败或服务离线只降级至最低额度。

T06b 部分实现（截至 2026-11-18）：Windows 探针通过后，接入固定 Helios 0.12.0 官方共识模块和 Alloy MPT 库，实现版本化验证/解析接口、可信 checkpoint/finalized-only 状态、registry account/code hash/三个 storage slots 验证及最多 128 项的 TTL/LRU 内存缓存。首轮新增 26 项链测试，工作区共 57 项测试通过。后续已实现 Reqwest 有界 HTTP 获取、可配置入口切换、区块哈希绑定的 EIP-1186 解析、SQLite 原子快照/CAS 和 DPAPI 保护恢复；高水位与撤销观察不随证明缓存过期删除，未注册身份负缓存只留在有界内存。该切片验收时工作区 108 项测试通过（49 链、34 store），Clippy、格式、许可证和 CDDL 检查通过。测试分别使用本地 HTTP 服务、历史 Mainnet 数据、合成 Trie 和局部状态转换，不能混称真实链部署验收。另已完成显式本机 checkpoint 续期 API：保留观察、清空证明、固定其余配置、拒绝回退与冲突锁，通过旧快照 CAS 原子替换；新增 21 项续期测试和工作区共 247 项测试通过，Clippy/格式通过，独立只读工程复核无阻断发现。真实多运营商证明服务兼容、检查点授权界面、后台调度/进程额度接入和独立安全审计仍待完成；本任务不标为整体完成。候选版本、Windows 测量、工程复核和具体边界见 `docs/chain-verification.md`。

### T07 — 纯授权判定与派生交集

依赖 T05。创建 policy types/service/audience/labels；实现冻结 PolicyService。

测试构造固定 public、contacts、peers 和 revoked grant。断言：无联系人授权则 contacts 拒绝；preferred 成员也拒绝；贡献从 0 改到任意高仍拒绝；交集只允许同时满足全部叶来源的 peer。

```text
cargo test -p asl-policy --test grant_policy
```

额外向量：epoch 变化、provider 不匹配、never、local_only、溯源环/深度 5/来源 33；全局 revision 的无关变更不取消仍然合法的 permit。

T07 实现记录（2026-11-18）：已拆分 types、audience、labels 和 service，保留冻结 AccessRequest/PolicyService 接口；使用本机 scoped service 绑定已认证设备与群上下文。public/contacts/peers/group、模型 provider 交集、来源图上限、内容/来源版本绑定、短期 Permit、撤销及快照版本检查已实现；信任/贡献不进入判定输入。36 项授权测试和工作区共 144 项测试通过，Clippy、格式、许可证与 CDDL 检查通过；独立只读工程复核无阻断发现，提出的两类测试遗漏已补齐。这里只完成内存授权判定；数据库撤销事务、文件句柄、lease、队列取消与浏览/回答状态机仍在各自后续任务实现。详见 `docs/policy-authorization.md`。

### T08 — Windows 文件句柄安全

依赖 T07。只创建 policy paths、windows/handles 和 `tests/path_boundaries.rs`。接口 `open_authorized_source(grant, relative) -> Result<AuthorizedFile, AslError>`，AuthorizedFile 不暴露可随意重开的路径。

```text
cargo test -p asl-policy --test path_boundaries -- --nocapture
```

测试夹具默认使用系统临时目录下的 `asl-test-fs`，或通过 `ASL_T08_FIXTURE_BASE` 指向指定 NTFS 目录；开发脚本将临时目录置于 E 盘。夹具包含 inside/allowed.md、outside/secret.md、junction、symlink、硬链接、ADS 和重命名竞争。真实测试拒绝越界、硬链接>1、设备/UNC/绝对路径/短名绕过；普通允许文件正确读出。测试后只清理自己创建且已验证在该根下的路径。

T08 验收完成（2026-11-18）：句柄相对打开、祖先固定、根身份恢复、保护目录排除、类型/大小/扩展名规则已实现，未暴露路径或原始句柄。真实 junction、硬链接、ADS、目录/卷根 SUBST、写入/删除/重命名锁及替换对照已执行；持有能力期间新增硬链接后，下一次读取失败关闭。本机 symlink/8.3 条件缺失，用户云机完整日志已补齐真实夹具；盘符修正后用户报告云机 22 项全部通过（1.27 秒），本次只有结果摘要，证据来源分开记录。独立工程复核提出的问题已修正；不修改机器权限或卷设置绕过测试。详细范围见 `docs/windows-source-handles.md`；后续持久撤销、AppContainer 和传输栅栏分别验收。

### T09 — AppContainer 与 Job Object

依赖 T08、T02。创建 policy sandbox、windows/appcontainer/job，以及 probe helper。受控子进程编译为 Windows GUI subsystem，保留三个匿名标准管道；不得使用 `CREATE_NO_WINDOW`（该组合在本机真实 AppContainer 探针下以 `STATUS_DLL_INIT_FAILED` 退出）。环境只由可信系统路径和 `SHGetKnownFolderPath` 重建 `LOCALAPPDATA`，不继承父进程环境。

接口 `spawn_sandbox(role, inherited_handles, limits) -> Result<SandboxChild, AslError>`；role 为 Net/Worker/Extractor；句柄使用显式 allowlist。

```text
cargo test -p asl-policy --test sandbox_probe -- --nocapture
```

验收在真实 Windows 测得：worker 读 outside、连 HTTP、启动子进程均失败；net 可进行获准 TCP/QUIC、mDNS，但读用户目录失败。AppContainer/Job 失效、ACL 不支持、句柄遗留均失败关闭。此任务必须独立复核，不能伪造 probe 返回值。

T09 当前实现记录（2026-11-18）：完成 Windows AppContainer 按 Net/Worker/Extractor 拆分、网络 capability 最小分配、真实子 token SID/capability 检查、唯一只读执行文件 ACL、Job 内存/CPU/单进程/kill-on-close 约束、helper CPU 与墙钟时限、三个匿名 IPC 管道、父环境清空、悬挂启动后入 Job 再放行及失败关闭。broker 端点永久不可继承；创建时只复制三只 allowlist handle，立即清除继承标志并通过本地进程创建锁串行化。执行文件 ACL 读改写现由进程内锁与按 pinned file identity 命名的跨进程 mutex 串行化，两个独立测试进程实测通过。新增真实 Windows helper 探针，覆盖文件越权、worker 联网/子进程拒绝、坏句柄不泄漏数据、ACL 只改可执行文件并恢复、超时/CPU/内存限制、句柄与子进程清理、Net 角色公网 TCP 能力及 multicast membership。外部 TCP 测试仅建立连接握手，实际 UDP echo、libp2p QUIC 和 mDNS 查询/响应仍未验收。独立初审发现的管道句柄暴露与 UDP 探针假阳性已按意见修正；Worker UDP 拒绝现在返回结构化失败并有 TEST-NET 回归测试。此前一次独立复核因工作区不可见未能检查本仓库；后续正确工作区复核发现 DACL 跨进程竞争，现已添加 mutex 与双进程测试，修正后的独立复核仍待确认。T09 保持部分完成，T10 实现不代表网络验收或独立安全审计关闭。

### T10 — Supervisor 与有界 IPC

依赖 T09、T06。创建 app supervisor/ipc 和四个 Windows bin 入口。

接口 `Supervisor::start(AppPaths)`；IPC 消息枚举固定，不接 shell command/path。连接身份使用私有继承管道，net peer 事件只来自已认证 driver。

验收：超 4MiB、未知角色、重复序列、非法操作拒绝；core 退出由 Job Object 终止子进程；worker 崩溃只失败当前任务。MCP server 尚未实现，stdio 隔离要求在 MCP 接入任务中端到端验收；IPC 子进程 stdout 只能包含固定二进制帧、诊断只能写 stderr。T10 IPC v1 暂不定义 peer identity event；T14 的网络消息必须来自已认证 driver 并经 core 身份校验。

```text
cargo test -p asl-app --test supervisor_ipc --locked --offline
```

T10 当前实现记录（2026-11-18）：完成固定 binary IPC v1（20 字节头、固定角色/消息/操作、每方向从 1 开始的严格序号、4 MiB 整帧上限），拒绝未知角色/消息/操作、错方向、重复/跳号、长度矛盾和超限帧；任务载荷在复制前限长。Net 事件通过容量为 8 的有界队列传递；EOF 或解码错误会终止读取线程，避免反复累积错误。新增 `Supervisor::start(AppPaths)`，通过相邻固定 Windows 二进制创建受限 Net 常驻子进程，Worker 每任务单独启动；Core 仅从 `ASL_HOME` 取数据根，无默认盘符回退。四个入口为 `asl`、`asl-core`、`asl-net`、`asl-worker`；IPC 子进程 stdout 仅承载 IPC 帧，诊断走 stderr。真实 Windows 测试覆盖 Net 心跳、Worker 结构化拒绝、收到任务启动确认后但 Core 放行执行前强制终止 Worker，验证当前调用失败，以及新 Worker 接续任务；该用例验证握手阶段中止，不代表计算中的崩溃注入。Worker 启动失败也不会影响 Net。T10 未实现 ASL 网络 driver/PeerId 事件、MCP 服务端或 GUI；IPC v1 不暴露 peer identity，T14 必须由认证 driver 与 core 身份校验共同接入。core 正常退出通过 supervisor 清理，异常退出依靠 T09 Job 的 `KILL_ON_JOB_CLOSE`；Supervisor 进程级故障注入及真实 MCP stdout 集成仍待后续验证，不能据此声称全部 T10 系统验收已关闭。

### T11 — 不可变快照与源目录对账

依赖 T10。创建 store resources、policy importer；导入时稳定读源、hash、写快照、落资源引用，成功后才公告。

接口 `import_source(grant_id, relative) -> ResourceKey`；磁盘对象以 kind/content_id 区分。外部更改触发 watcher，对账每 30 秒补漏。

验收：同内容两个 grant 物理去重但权限分离；导入失败不留下 ready；源改变/删除停止新 lease；导入期间撤销不发布；额度不足不读完整超大文件。

```text
cargo test -p asl-store --test snapshot_import
```

T11 本地导入与对账：Core 已接入 `SnapshotBroker`、目录变更通知和定时补查。导入以真实目录授权开稳定句柄，先预留再读文件；文件复制完成后重验授权版本和额度。资源引用按 grant 隔离，监听只检查已有引用，不自动收录新文件。SQLite 数据库升级为 v2；线上 ASL/1 协议没有变化。见 `docs/snapshot-import.md` 和 `docs/plan-validation.md`。此处没有向公网发公告或签发下载 lease；源引用失效和将来发送前的 lease 检查是不同验收项。

### T12 — 授权前置的全文检索

依赖 T11。创建 store search adapter，使用 jieba+FTS5。实现 visible_keys/search_visible。

验收固定夹具：public Rust、contact 私有 PDF 文本、无权 inbox。陌生 peer 检索“密码”不能得到私有命中、摘要、计数或模型片段；联系人仅看到明确授权集合。MATCH 特殊字符和 SQL 文本不改变查询结构。

```text
cargo test -p asl-store --test visible_search
```

T12 本地实现：导入时索引、已有引用的受限文本补录、Jieba/FTS5、检索和元数据双授权、结构化概念查询均已落地。仅在已授权的本地引用内计算命中与排名，不使用全库 BM25。PDF 夹具使用已提取文本，不代表 PDF 解析或公网 Agent 联调。见 `docs/visible-search.md`、`docs/plan-validation.md`。

### T13 — 记录签名与结构化公开资料

依赖 T06、T03。创建 types record 与 app profile 服务。

接口 `sign_record(kind, payload_cbor, sequence, lifetime)` 与 `verify_record(bytes, expected_agent, now)`；以身份根按协议原始字节签名。profile、设备目录和持久短码声明只含 CDDL 字段及概念 ID，并以 AgentId 为 owner。

验收：payload/owner/seq/时间/长度任一篡改失败；任意文本字段拒绝；设备目录 commitment 与链上状态不匹配拒绝；过期与旧 sequence 不替换新值；撤下资料停止续发；头像只发布内容引用不写 DHT 本体。

```text
cargo test -p asl-types --test signed_records
```

T13 实现记录（2026-11-18）：记录核心、严格嵌套 CBOR、固定签名原文、目录承诺与短码派生已实现；app 接入现有根签名和当前链身份 resolver，记录/设备序号与撤销观察单调、有界并原子更新。资料默认不发布，明确配置后每 5 分钟生成候选；撤下停止续发，头像引用每次经过公开资源授权。具体 Rust 入口使用已验证的 RecordPayload 推导 kind，并显式传入本机签发身份/时间及验证 resolver。此前未定义的记录封装/目录/短码 CDDL 已在协议文档中显式补全，没有更改既有控制帧或合约接口。24 项 codec、37 项 app 记录测试和工作区共 226 项测试函数通过，Clippy、格式和 CDDL 语法/ACK 检查通过。历史/发布游标仍为内存状态，DHT 入站过滤、总额度、持久化、实际投递与发送取消在后续任务集成；不声称 T17 或完整节点发现完成。详见 `docs/signed-records.md`。

### T14 — libp2p Driver 与链身份握手

依赖 T02、T10、T13。创建 net behaviour/transport/driver。

应用接口：`NetworkCommand` 枚举 Dial/SendControl/SendBulk/FindProviders/Provide/Unprovide/PutProfile/Stop；`NetworkEvent` 枚举 TransportConnected/IdentityProofRequired/IdentityVerified/Control/Bulk/Providers/Disconnected/Error。普通 Control 事件仅在 core 确认最终化链状态、身份根设备证书与认证 AgentId 后产生。禁止将 libp2p 类型散布到 agent、store 和 GUI。

验收双进程 QUIC 与 TCP 的真实加密连接、有效设备 PeerId；传输认证后验证链状态与根密钥设备证书且证书 PeerId 必须等于认证连接；伪造 AgentId、重放/过期/撤销设备证书均拒绝，身份验证前不放行应用消息；控制/大帧分 codec；关闭无资源泄漏。

```text
cargo test -p asl-net --test two_node_transport
```

T14 首轮实现记录（2026-11-18）：`asl-net` 已提供只绑定回环地址的 TCP Noise/Yamux 与 QUIC 传输适配器，拨号必须给出期望设备 PeerId；认证成功后产生与单条连接绑定的 `AuthenticatedPeer` 句柄，不把 libp2p 连接类型暴露给 Core。Core 的 `DeviceSession` 要求 hello、认证 PeerId、设备证书、已签名设备目录和当前活动链身份全部一致，并在证书过期、链身份受限、目录更新、历史推进、时钟回退或会话关闭后停止放行。传输处理到断开事件或被销毁时，旧句柄失效；重连必须重新握手。失败的入站传输握手只产生有界拒绝事件，监听器可继续服务。

本轮验收覆盖：独立进程 TCP/QUIC 回环加密连接、正确设备 PeerId、错误期望 PeerId 拒绝、连接准入状态的入站/出站并发与总量上限、Core 证书/目录/链状态绑定及旧会话不可恢复。连接上限目前有状态机单测，尚未进行公网压力或 AppContainer 负载验收。控制/身份/bulk request-response driver、身份状态验证、Supervisor IPC 接线、mDNS/公网地址策略、中继和公网端点仍属于后续切片；本记录不宣称完整 T14 已关闭。

T14 子流 codec 切片（2026-11-18）：新增独立 `/asl/control/1.0.0` 和 `/asl/identity-proof/1.0.0` request-response codec。两者共用协议已冻结的确定性 CBOR 编解码器，使用 u32 BE 长度前缀并在读取 payload 前校验限额；控制帧上限 65,536 字节，身份请求以固定字段限制为 93 字节，身份响应上限 262,144 字节。接收端读满后要求对端关闭写半流，拒绝尾随数据；协议串线、身份方向错误及超限长度均拒绝。固定向量测试覆盖错误边界；真实 TCP 与 QUIC libp2p Swarm request-response 测试分别完成控制和身份请求/响应往返。该切片只完成 codec 和子流线格式互操作，不注册生产网络 behaviour，不代表已有身份验证、请求 ID/AgentId 绑定、Supervisor IPC 或连接驱动；T14 仍未关闭。

T14 bulk codec 切片（2026-11-18）：新增 `/asl/blob/1.0.0` request-response codec。请求严格使用 91 字节固定格式，响应使用 u32 BE 长度前缀和 27 字节固定头，成功 payload 上限由 manifest 规范导出，为 2,097,210 字节；未知 magic/操作码/状态码、manifest/inline 非零 index、错误状态携带 payload、截断、尾随和超限长度均拒绝。真实 TCP 与 QUIC 子流测试传输并重新校验最大合法 2,097,210 字节 manifest。该切片不校验 lease/授权/块 hash，不注册生产网络 behaviour，不代表 transfer 调度、请求与认证连接绑定或完整 T14 已关闭。

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

概念发现不对自然语言标签做线上规范化，使用版本化概念 ID。

验收 public 才 start_providing；contacts/content 无公共广告；持久短码键允许多候选、声明必须由身份根签名且 AgentId 有有效链状态；冲突不覆盖；概念 ID/词表版本一致；8KiB value、10k记录/64MiB 存储限制；自然语言字段和非法签名 PUT 不落库。

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

### T26 — 严格结构化模型决策

依赖 T25、T03。创建 agent decision/prompt。

接口按规范 validate_decision。通过条件同时是本地结构 schema、候选成员、当前授权、action 与方向。模型适配器的内部输出可以使用本地 JSON transport，但映射后的决策类型不含 `text`/prose 字段；对端 wire 必须由 T03 CBOR encoder 生成。

验收：合法 answer/decline/request_more 的结构化对象可解码；未知字段、额外 path、自然语言通道、假 refs/概念、重复键、超限数组和类型不符整次拒绝。一次修复失败固定 model_invalid，绝不部分执行，绝不将模型原始输出转发给 peer。

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

固定应用约束：最多 64 名成员、群消息最多 64 KiB、群事件本地保留 7 天、状态 catch-up 最多 256 个 epoch。MLS credential 必须绑定稳定 AgentId 与当前已验证链状态/设备证书；迁移设备通过新叶子入组，不复制旧 ratchet 状态。MLS 解密后的 application plaintext 必须为 CDDL 定义的 ASL 结构对象；禁止自由自然语言字段。仅当前成员收到群帧，OpenMLS 仅在核验 authenticated sender、链状态、设备证书、群成员和 epoch 后处理消息。群标识、群名、成员清单和群资源不发布到 DHT。

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

验收 7 天消息清理、3 天失败 part、30 天 inbox；不会延长人类上限；存在引用对象不误删；恢复不重建空授权；导出诊断不含 key/lease/原文敏感内容。提供版本化加密迁移包，支持用户选择本地 ASL 数据；导入保留身份根、联系人、信任和选定记录，目标设备生成新设备密钥/证书；目录 grant、OS 凭据不迁移，MLS ratchet 不复制，需重新授权/入组。诊断导出是对输出目录的授权，默认不外传。

```text
cargo test -p asl-app --test retention_backup
```

### T36 — 便携包、登录启动与签名更新

依赖 T35。创建 packaging/windows、app update。

后台定义为当前 Windows 用户登录后的常驻进程，不冒充 SYSTEM 服务使用用户 DPAPI。便携包所有可控路径留 E；系统创建的小量 AppContainer/图形元数据如实说明。

更新使用已固定公钥验证清单签名、包 hash、版本/回滚策略；支持替换更新源和手动导入已签名包，不把更新站变成身份/运行必需服务。安装失败回滚二进制，不回滚授权数据库到更宽松状态。

### T37 — 独立安全复核与 fuzz

依赖 T36。创建 tests/adversarial、fuzz targets。

完成测试文档 A01–A25，覆盖群成员/MLS/授权确认、公共链证明/最终性、CBOR/CDDL 零文本协议、身份/配对/迁移与多 Agent 资源压测。优先路径/句柄、根密钥/设备证书绑定、PAKE 重放与尝试限制、AppContainer 权限、链签名/撤销竞态、manifest/codec、模型输入前过滤和机器总额度。

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

发布条件：R01–R33 全部有实现与实际验收；A01–A25 和新增身份/配对测试无阻断问题；真实网络/沙箱报告齐全。不得用演示视频、mock 或开发者的声明替代。

## 需求到任务映射

| 需求 | 主要任务 |
| --- | --- |
| R01–R03 | T05、T06、T06a、T06b、T07、T13、T14、T18a、T29、T34、T35 |
| R04–R06 | T14–T18 |
| R07–R09 | T19、T25–T27、T30 |
| R10–R11 | T07–T13、T17、T20 |
| R12–R14 | T20–T24 |
| R15–R16 | T28–T29 |
| R17–R18 | T33–T34 |
| R19–R20 | T05、T19、T23、T35 |
| R21–R22 | T03、T09–T10、T25–T27、T37、T39 |
| R23–R26 | T01、T06、T15、T35–T40 |
| R27 | T02、T05、T14、T19、T20、T31–T34 |
| R28 | T06、T35 |
| R29 | T13、T17、T18a、T33 |
| R30 | T14–T18a、T33–T34、T37–T38 |
| R31 | T05、T06、T06a、T06b、T13–T15、T37–T40 |
| R32 | T03、T13、T17–T19、T26–T28、T31–T32、T37、T39 |
| R33 | T09–T10、T14–T18、T20–T29、T37–T38 |

## 工作量判断

这是包含 Windows 隔离、网络和完整传输的中等规模系统，不是一次提示词能可靠完成的小应用。以 1–2 名熟悉 Rust 的工程人员负责复核、代码模型承担局部实现为假设，完整产品估算 4–8 个月；真实网络、沙箱或安全复核不通过会延长。估算不是工期承诺，也不能靠删验收换速度。
