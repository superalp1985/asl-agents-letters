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
- 数据和开发缓存放在用户显式选择的本地磁盘，不静默切换到其他磁盘。
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
    bin/{asl,asl-core,asl-net,asl-worker,asl-extractor,asl-infra}.rs
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

### T01 — Workspace、工具链与用户可配置路径

依赖：无。创建根 Cargo 文件、八个 crate、`asl-types/src/error.rs`、`asl-policy/src/platform/windows/volume.rs`、`asl-app/src/paths.rs`、`scripts/dev-env.ps1`、`crates/asl-app/tests/home_paths.rs`。

接口：`AppPaths::open(root: &Path) -> Result<AppPaths, AslError>`；提供 root/state/snapshots/incoming/logs 的只读路径。`dev-env.ps1` 要求显式本地磁盘根目录，只修改当前 PowerShell 进程的 PATH、ASL_HOME、CARGO_HOME、RUSTUP_HOME、CARGO_TARGET_DIR、TEMP、TMP；不写机器级环境变量，不回退到其他磁盘。

```rust
assert!(AppPaths::open(std::path::Path::new("relative")).is_err());
```

验收：绝对且可用的本地磁盘目录可用；相对路径、不可用卷、UNC、reparse、非 NTFS 拒绝；禁止调用系统用户目录 fallback 或静默改选磁盘。运行 `cargo check --workspace --locked`，首次生成 lock 后再带 locked 重跑。

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

接口拆为 `AgentIdentity::generate()`、`load_or_create_protected(path)`、`agent_id()`、`issue_device_certificate(device_peer_id, serial, issued_at_ms, expires_at_ms)`、`verify_device_certificate(...)` 和独立 `DeviceIdentity` 接口。身份根使用 secp256k1 ECDSA；证书按 `docs/03-protocol.md` 的规范字节构造，经 Keccak-256 后签名，65 字节签名为 `r || s || v`，其中 `s` 为 low-S、`v` 为 27/28。AgentId 按 `specs/identity-registry-v1.md` 派生。根密钥及设备私钥使用 Windows 当前用户 DPAPI 保护；存储路径由调用方提供，创建使用 create-new，不覆盖旧身份。`load_or_create_protected` 只在文件缺失时创建；现有文件损坏或类型不符时拒绝，不静默替换身份。此任务不把根密钥注入 net，也不把设备 PeerId 当作稳定联系人身份。具体 Rust 密码学 crate/API 须核实成熟度与许可后固定，不自写椭圆曲线逻辑。

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

T06 实现记录（更新于 2026-11-19）：已固定并编译 `k256 0.14.0`、`sha3 0.12.0`、`rand 0.10.4`；完成根身份/AgentId 派生、独立 libp2p Ed25519 设备密钥、设备证书签发与本地验证、Windows 当前用户 DPAPI 保护文件、由 `AppPaths` 数据根派生的 identity 目录。`Supervisor` 启动时通过 create-once 接口加载或生成根身份与设备身份；现有密钥文件损坏时拒绝启动，不自动换身份。此处只创建本机身份，不代表已登记到链或可完成网络准入。尚未实现或验收：身份链最终化状态/撤销证明、设备证书目录/链 commitment、PAKE、跨用户/跨机器恢复及迁移 UI。DPAPI 仅完成当前用户本机往返测试；身份与路径模块仍需独立安全复核。

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

测试夹具默认使用系统临时目录下的 `asl-test-fs`，或通过 `ASL_T08_FIXTURE_BASE` 指向指定 NTFS 目录；开发脚本将临时目录置于用户选择的开发盘。夹具包含 inside/allowed.md、outside/secret.md、junction、symlink、硬链接、ADS 和重命名竞争。真实测试拒绝越界、硬链接>1、设备/UNC/绝对路径/短名绕过；普通允许文件正确读出。测试后只清理自己创建且已验证在该根下的路径。

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

T14 身份证明 wire 修订（2026-11-19）：明确废弃未发布的 `/asl/identity-proof/1.0.0` 线格式并冻结 `/asl/identity-proof/1.1.0`。响应现在携带可供既有 MPT 验证器使用的完整账户字段、三个 256 位 slot/value 路径及最多 8 KiB 签名设备目录；不再接收对端声称的 controller、sequence 或 revoked 结果。`asl-app::chain::identity_proof_from_wire` 只从本机 deployment 配置补链 ID/registry 地址，并在映射前绑定 pending request ID、AgentId 和请求 checkpoint；映射结果由原 `EthereumProofVerifier` 执行真实 trie 验证。固定 CDDL/CBOR 样例与 TCP/QUIC 子流测试同步更新。仍未完成生产 Swarm behaviour、同一认证连接的请求响应绑定、proof serving、Core IPC 闸门和公网测试，故 T14 未关闭。

T14 组合网络行为切片（2026-11-19）：在现有 loopback-only Noise/Yamux 与 QUIC Swarm 注册 control、identity-proof 1.1 和 blob 三个 request-response behaviour。公共事件不暴露 libp2p request/channel 类型；出站请求与入站回复句柄绑定本地认证连接，IdentityProof 的 request ID/AgentId/checkpoint 与 Bulk 的 request ID 在交付/回复时核对。每协议每 peer 最多 2 条并行子流，超时 10 秒，等待中的请求和回复句柄各有 96 项总上限。新增 TCP/QUIC 组合驱动往返测试。本切片仍只绑定 loopback 地址；Net/Core Supervisor IPC、链证明接收与目录验签、Core 的未验证控制帧身份闸门、生产 proof serving 和公网地址策略未完成。`ControlRequest` 明确仍是待身份验证事件，T14 不关闭。

T14 Core 身份证明准入切片（2026-11-19）：`DeviceSession::begin_network_hello` 由本机选择最终化检查点和随机请求 ID，并只经本会话已认证连接发送证明请求。`serve_local_identity_proof` 仅为本机配置的 AgentId 返回持久缓存中检查点完全匹配且未过期的证明；入站请求不能触发链 RPC 或指定其他身份。`finish_network_hello` 将响应令牌绑定到同一连接和 pending request，使用现有 MPT verifier 校验证明，再核验签名设备目录，只准入绑定到该传输 PeerId 的证书。任一步失败都会关闭该会话。Windows TCP 回环集成测试覆盖成功准入、checkpoint/AgentId 错配、缓存过期、证明状态值篡改及目录篡改拒绝。`asl-net` 回复句柄改为借用，错误尝试不会消耗仍有效的句柄。本切片尚未接入 Net/Core Supervisor IPC，未配置生产/公网监听与地址策略，不代表公网或完整 T14 验收。

T14 Net/Core IPC wire 切片（2026-11-19）：为传输 PeerId、断开事件、身份证明请求/响应增加固定 IPC 类型；身份证明载荷复用 identity-proof 1.1 规范 CBOR 编解码，并由 IPC 消息单独绑定 connection handle 和入站 response handle。Net 专属事件拒绝 Worker/Extractor 发送；connection、response handle 均为不透明 16 字节值。FrameReader 按消息类型在分配 body 前限长，身份证明消息不超过其协议帧 256 KiB 加固定封装。完成正反向往返、角色拒绝、畸形 PeerId、串线帧、超限证明及超限 body 预读测试。此线切片本身不接线身份握手。

T14 设备身份启动交付切片（2026-11-19）：首次启动仅在 DPAPI 设备密钥文件缺失时生成 Ed25519 身份，以独占新建方式保存；损坏或非普通文件拒绝且不自动更换身份。Supervisor 将 protobuf 密钥通过现有私有继承输入管道的 `ASLK` v1 有界前导一次性交给 Net，最大 1 KiB；临时序列化、解密和管道接收缓冲均使用 `Zeroizing`，密钥未加入可 Clone/Debug 的 IPC 消息。Net 解码后从密钥导出 PeerId 并返回专用 `NetReady`；Supervisor 精确比对本机 PeerId，缺帧、错身份或 IPC 错误均停止 Net。新增往返、错误版本、畸形/超限预读、错 PeerId、本机持久化和损坏文件拒绝测试。Windows `asl-app` Supervisor 集成测试实际启动 AppContainer Net 并通过该握手。该切片只验证密钥交付与本机设备身份一致性；Net 尚未运行 libp2p driver、连接事件或身份证明转发，不代表公网身份验证或 T14 关闭。

T14 Net/Core 运行时接线切片（2026-11-19）：Net 子进程现以 Tokio 驱动既有 `LocalTransport`，Core 可经 Supervisor 下发 TCP/QUIC loopback 监听、拨号、身份证明、控制和 bulk 命令，并接收有界结构化事件。连接 handle 由 Net 随机生成并映射到实际活动连接；request token 与 connection handle、协议及 Core request ID 关联，回复 handle 绑定来源连接/协议并限时有效。IPC 固定字段编码，不新增自由文本；地址只在传输层当前 loopback 策略允许后执行。Core 暴露的控制/bulk 入站事件明确命名为 `Unverified...`；`DeviceSession` 增加 IPC handle 绑定的证明请求/完成接口，错误连接或 request ID 会关闭会话。新增 Net driver 双向控制请求/响应句柄往返，以及 Windows AppContainer 子进程拒绝非 loopback 监听并返回关联操作失败事件的覆盖。此切片没有将 `DeviceSession` 自动接入 Supervisor 事件循环，也没有生产监听配置、公网策略、DHT、mDNS 或完整公网互测；因此普通业务帧仍须由后续 Core 身份闸门处理，T14 仍未关闭。

T14 Core 网络身份准入协调器切片（2026-11-19）：新增 `CoreAdmission`，显式协调活动连接的 Hello、身份链证明、签名设备目录和控制/bulk 收发。核验前只生成握手命令或关闭命令，不向 Agent 派发业务事件；出站业务控制/bulk 命令也必须通过同连接身份状态重验。新增 kind 32 `CloseConnection`，失败只关闭对应连接。Hello 请求应答先于身份证明请求派发；无效/过期握手请求失败会清理会话。该协调器目前由 Core 调用方显式构造，基础 `Supervisor::run` 尚未加载 registry/链状态 resolver、已签名设备目录或构造有效 Hello；本机根身份的存在不代表其已经锚定到链或获准入网。loopback 以外地址策略、公网运行、DHT/mDNS 和完整 T14 仍未验收。

T14 Supervisor 本地身份绑定切片（2026-11-19）：`CoreAdmission::for_local_identity` 只从身份根对应 AgentId 的签名设备目录中选择当前 Net 设备的证书，再创建 Hello 并执行活动链、目录签名与 commitment 校验；调用者不能传入不同的根 AgentId 或 PeerId。Supervisor 自身持有该准入状态，网络事件/出站控制与 bulk 命令经过其内部门禁，不再由调用者替换准入器。准入仍须显式提供有效的本地链 resolver 和签名目录；`Supervisor::start/run` 尚未读取生产信任配置或自动启用联网，缺失配置不开放业务通信。

T14 启动身份准入加载切片（2026-11-19）：新增严格版本化的 `network-identity-v1.json` 与固定位置的签名设备目录加载。配置必须提供部署、共识/fork/checkpoint、HTTP 服务入口和缓存限制；不设默认 RPC、合约地址或信任 checkpoint。启动时仅从既有 SQLite 链快照恢复，或以本地配置 checkpoint 通过指定服务 bootstrap；随后同步最终性并获取本机 AgentId 的状态证明。只有当前根地址仍为 Active 且已签名设备目录/设备 PeerId/链上 commitment 一致时才启用 `CoreAdmission`。缺少配置、目录、链服务或链上锚定分别保持未准入状态；损坏的本机链快照或不匹配目录失败关闭。首次注册、目录承诺签名和 GUI 配置仍未实现；启动后的周期续验见下方独立切片。

T14 Supervisor 网络事件泵切片（2026-11-19）：`Supervisor::run_with_network_handler` 以有界 Net/Core IPC 接收队列驱动 `CoreAdmission`，自动完成 Hello、身份链证明请求/响应和断开清理；无有效本机准入时，对远端连接及应用帧只发关闭命令，不向 handler 暴露载荷。通过准入的结构化事件交给本地 handler；其返回的控制/bulk 命令再次经过 peer、连接和会话状态校验。默认 `run()` 使用静默 handler，不伪造回答；实际 Agent 会话运行时尚未接入。事件轮询超时与 Net 子进程 EOF 分开处理；异步 Ping/Pong 与周期健康检查不阻塞事件接收。公网 listener 与首次注册仍未完成；周期链同步由下方后续切片补上。

T14 Core 准入与 T06 根身份启动模块验证（2026-11-19，Windows x64，Rust 1.100.0）：`cargo test -p asl-app --all-targets --locked` 通过 159 项，1 项忽略；`cargo test -p asl-net --all-targets --locked` 通过 25 项，1 项忽略。`cargo clippy -p asl-app -p asl-net --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check` 与 `git diff --check` 通过。覆盖范围仅为 `asl-app`、`asl-net` 与格式/静态 lint，不代表 workspace 全量测试或 T14 公网/生产验收。Cargo 提示 `proc-macro-error2 2.0.1` 含未来 Rust 版本兼容性问题；本轮未处理该无关依赖告警。

T14 启动准入加载模块验证（2026-11-19，Windows x64，Rust 1.100.0）：`cargo test -p asl-app --all-targets --locked` 通过 163 项、1 项忽略；`cargo clippy -p asl-app -p asl-net --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 通过。覆盖仅含 `asl-app`/`asl-net` 与格式、静态 lint；未运行 workspace 全量测试、公网互操作、首次注册或周期同步验收。Cargo 提示 `proc-macro-error2 2.0.1` 未来 Rust 兼容性告警，本轮未处理。

T14 Supervisor 网络事件泵模块验证（2026-11-19，Windows x64，Rust 1.100.0）：`cargo test -p asl-app --all-targets --locked` 通过 167 项、1 项忽略；`cargo clippy -p asl-app -p asl-net --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 通过。覆盖为 `asl-app`/`asl-net`、格式与静态 lint；未运行 workspace 全量测试、公网互操作、Agent handler 集成或链周期同步。Cargo 提示 `proc-macro-error2 2.0.1` 未来 Rust 兼容性告警，本轮未处理。

T14 周期链状态续验切片（2026-11-19）：新增独立链同步线程，按配置的身份证明缓存时限周期同步最终性并请求本机 AgentId 的注册表证明；刷新间隔由缓存时限推导，失败重试受配置 HTTP 超时约束。后台只操作独立 `EthereumLightClient` 副本，不读写共享 SQLite；更新及证明经 Core 原有 MPT verifier 和 durable resolver 单写入路径验证/提交，避免 HTTP 阻塞 Supervisor 或与证明缓存发生 CAS 写入竞争。本机根地址、Active 状态、签名设备目录 commitment、当前设备证书及有效期在每次续验后重验；链服务不可用或身份/目录失效时关闭当前会话并暂停所有应用帧，恢复有效续验后重新开放。没有新增 RPC 地址、协议字段或依赖。远端已准入身份仍按既有 `max_cache_age_secs` 缓存时限失效，不由此切片主动逐个拉取远端最新证明；首次注册、UI 配置、公网 listener 和公网互通验收仍未完成。

T14 周期链状态续验模块验证（2026-11-19，Windows x64，Rust 1.100.0）：`cargo test -p asl-app --all-targets --locked` 通过 169 项、0 失败、1 项忽略；`cargo clippy -p asl-app -p asl-net --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 通过。验证范围为 `asl-app`/`asl-net`、固定链服务夹具、Core 身份续验、SQLite 持久化与格式/lint；未运行 workspace 全量测试、真实公网链服务、首次注册、远端身份批量续验或公网互通验收。Cargo 保留 `proc-macro-error2 2.0.1` 的未来 Rust 兼容性提示，本轮未处理该无关依赖告警。

T14 身份证明验证预算切片（2026-11-19）：Net 已解析并绑定连接的身份证明响应进入 Core 后，不再立即执行 MPT/签名目录验证；每个 Supervisor 共用一个单调时钟 token bucket，限制为每秒 2 份、突发最多 2 份。最多 16 份排队，按接收 FIFO 验证；Supervisor 每轮事件等待均泵送队列。排队期间连接仍处于待验证态，不能收发应用帧；排队超过 10 秒、断连或容量不符时关闭连接并清除其队列项。限速位于昂贵链/签名验证之前；网络 codec、子流数、请求总量及连接数仍由既有各层限制。该切片不降低链证明验证标准、不授予低额度旁路，也不改变线协议或地址策略。

T14 身份证明验证预算模块验证（2026-11-19，Windows x64，Rust 1.100.0）：`cargo test -p asl-app --all-targets --locked` 通过 171 项、0 失败、1 项忽略；`cargo clippy -p asl-app -p asl-net --all-targets --locked -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 通过。新增单调预算测试覆盖突发上限、每秒补充、长空闲不累积额外额度及时钟回拨；Core 准入集成用例覆盖身份证明排队期间应用命令仍拒绝、额度补充后经轮询完成验证。测试/格式/lint 范围为 `asl-app`/`asl-net`。未运行 workspace 全量测试、真实公网/多运营商链服务、AppContainer 公网负载、72 小时运行或独立安全审计。Cargo 仍提示 `proc-macro-error2 2.0.1` 的未来 Rust 兼容性问题。

T16 地址策略、mDNS 与启动设置切片（2026-11-19）：地址分类现区分回环、私网、链路本地、全球单播和特殊用途网段；Swarm 入站本地/远端地址、出站拨号地址与 mDNS 发现地址都按同一显式策略复核。新增版本化设置读取 `state/network-settings-v1.json`：文件缺失时为 LoopbackOnly、不监听、TCP/QUIC 端口均为 0；未知字段、错误版本或超限文件拒绝启动。NetReady 后先发送地址策略并等待对应操作确认，再按配置启动 TCP/QUIC 监听；启动阶段其他网络事件会保留给常驻事件泵。回环策略绑定 loopback，其余策略通过通配请求触发网卡枚举，最终只绑定策略允许的具体网卡地址。此设置目前只有启动读取，没有 GUI 编辑/保存。策略须在首次监听/拨号前设置且进程内不可切换。LanOnly/Hybrid 才启用 libp2p mDNS；mDNS 候选须通过范围与 PeerId 后缀校验，最多 8 个候选并行自动拨号，拨号仍使用候选 PeerId 固定目标并进入既有链身份验证。DNS 地址继续拒绝，不做隐式解析；IPv6 链路本地作用域地址未纳入网卡枚举。网卡热插拔更新、候选过期 UI、AppContainer multicast、真实 LAN 自动 hello 或公网互通验收未完成；T16 未关闭。

T16 地址策略与发现切片验证（2026-11-19，Windows x64，Rust 1.100.0）：`cargo test -p asl-net --all-targets --locked --offline` 通过 31 项、0 失败、1 项忽略；`cargo test -p asl-app ipc::tests::fixed_messages_round_trip_with_role_and_sequence_binding --lib --locked --offline` 通过；`cargo clippy -p asl-net -p asl-app --all-targets --locked --offline -- -D warnings` 通过，格式化已运行。联合包测试中 `asl-app` 其余 144 项通过；IPC 用例已单独修复并复验通过，`supervisor::tests::sandboxed_worker_failure_does_not_stop_net_or_core` 在本机因 Windows 子进程组件启动返回 `NotFound`，尚未在原云机复验。没有运行 workspace 全量测试、真实 LAN/mDNS、防火墙/AppContainer 或公网互测；本记录不代表 T16 整体验收。

T16 启动设置与策略锁定切片验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘缓存）：`cargo test -p asl-app --lib --locked --offline network_settings::tests` 通过 4 项，`startup_operation_wait_preserves_unrelated_network_events` 通过 1 项；`cargo test -p asl-net --all-targets --locked --offline` 通过 32 项、0 失败、1 项忽略。`cargo clippy -p asl-app -p asl-net --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 通过。覆盖版本化网络设置、默认关闭监听、地址生成、启动操作确认事件保留及默认策略锁定；未运行 `asl-app` 全量测试、AppContainer multicast、防火墙、真实 LAN/mDNS、NAT/公网或 workspace 全量验收。Cargo 仍提示 `proc-macro-error2 2.0.1` 的未来 Rust 兼容性问题；本轮未处理该无关依赖告警。

T16 mDNS 候选生命周期观察切片（2026-11-19）：Net 对 mDNS Discovered/Expired 使用同一地址策略和 PeerId 后缀校验，并按 PeerId、传输类型及 SocketAddr 跟踪有限候选集；发现后保留原自动拨号和身份准入路径，已记录候选过期时派发对应状态。新增 IPC kind 38 固定结构消息和上限，Net/Core 角色仅允许 Net 向 Core 发送；Supervisor 将事件转为无命令输出的 `LocalNetworkObservation`，独立于 Agent 业务 handler，即使本机尚无 Agent 链身份准入也可供本地观察。候选元数据不能表示连接在线或 Agent 身份有效。GUI 展示、候选持久快照、AppContainer multicast、真实 LAN 自动 Hello 和公网验收仍未完成，T16 未关闭。

T16 mDNS 候选生命周期观察切片验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘 Cargo 缓存）：`cargo test -p asl-net --all-targets --locked --offline` 通过 46 项、0 失败、1 项忽略；另在修复测试中的重复匹配后，`cargo test -p asl-net --test relay_client --locked --offline` 通过 4 项。`cargo test -p asl-app --lib --locked --offline supervisor::tests::discovery_candidate_is_exposed_only_as_a_local_observation` 通过 1 项，`cargo test -p asl-app --test network_ipc --locked --offline` 通过 7 项。`cargo clippy -p asl-app -p asl-net --all-targets --locked --offline -- -D warnings`、`cargo +1.100.0 fmt --all -- --check` 和 `git diff --check` 通过。Cargo 保留 `proc-macro-error2 2.0.1` 的未来 Rust 兼容性提示。没有运行 `asl-app` 全量测试或 workspace 全量测试；mDNS 生命周期由合成事件单测覆盖，未做真实 LAN/mDNS、AppContainer 组播、防火墙、公网互通或 GUI 验收。T16 未关闭。

### T15 — 引导、中继、NAT 与基础设施

依赖 T14。创建 net relay、app/bin/asl-infra、Linux systemd 示例。

T15 中继切片（2026-11-19）：`asl-net::relay::RelayServer` 复用 libp2p relay v2，支持 TCP/QUIC、稳定 PeerId、预约/电路/时长/单电路字节上限及 libp2p 默认 peer/IP 请求速率限制。中继可从具体监听地址自动发布外部地址；通配监听必须在严格版本化配置中指定 `external_addresses`，不能以不可达地址伪装可用性。Linux `asl-infra` 使用配置目录中的身份密钥，权限限为 0600；未知配置、符号链接、过宽权限或损坏密钥均拒绝且不静默重建。客户端已接入预约、预约成功/失败事件和 relay-only 拨号；入站 relay 电路按配置端点准入，并在握手后绑定远端 PeerId。relay listener 关闭、地址过期或最后一条 relay 连接断开后，会报告不可用并按 1 至 60 秒有上限的指数退避自动重预约；首次预约成功后清除退避状态，退避中的 relay 不再作为新拨号候选。单机 TCP relay v2 集成测试覆盖 reservation 到认证电路、同地址 relay 重启后的自动恢复，以及一个 relay 离线时经另一个 relay 建立认证连接。配置样例中的外部 IP 属文档专用网段，部署前必须替换；当前没有已部署的公网入口或可发布 bootstrap 地址。

双 relay 基础故障切换（一个入口离线、另一个可用）和同地址恢复已有本机测试；Linux `asl-infra` 原生目标编译已于 2026-11-19 在 WSL Ubuntu x86_64 完成，但运行时、密钥权限行为和 systemd 尚未验证。真实公网互通、DHT/AutoNAT/DCUtR、每小时 peer/总字节桶仍未完成，因此没有生成虚构 `network-seeds.json`。T15 未关闭。

基础设施只做 DHT/AutoNAT/relay，不具备 Agent 文件和模型能力。支持配置多个入口、稳定运营密钥、reservation/circuit/字节/时间/全局限制。

验收一个入口离线另一个可用；断网后恢复；中继耗尽产生 relay_capacity 并可恢复；允许 relay 承载多块文件；仅中继模式不发布或拨打暴露本机公网 IP 的直连地址，并显示 relay 可见的连接元数据边界。

发布前部署实际入口，生成打包用 network-seeds.json，字段为 version/network_id/generated_at_ms/expires_at_ms/nodes。nodes 每项含 operator_id/peer_id/multiaddrs/roles，roles 仅 bootstrap/relay/autonat；最多 32 个节点、每节点 8 个地址。由发布清单签名保护，不能填不可达假地址交付。用户自定义入口可替换整份内置列表，不需要中央准入。

```text
cargo test -p asl-net --test relay_client
```

T15 relay 服务核心切片验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘缓存）：`cargo test -p asl-net --all-targets --locked --offline` 通过 36 项、0 失败、1 项忽略，覆盖 relay 限额拒绝、稳定 PeerId、relay multiaddr 顺序及 loopback TCP 监听；格式检查、`cargo clippy -p asl-app -p asl-net --all-targets --locked --offline -- -D warnings` 与 `git diff --check` 通过。未测试实际 relay 电路转发、多中继切换、NAT/DCUtR、Linux systemd、远端公网或每小时总流量限制；本记录不代表 T15 整体验收。Cargo 保留 `proc-macro-error2 2.0.1` 的未来 Rust 兼容性提示。

T15 relay-only 配置和入口切片验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘缓存）：`cargo check -p asl-app --bin asl-infra --locked --offline` 通过；`cargo test -p asl-app --lib --locked --offline -- --skip supervisor::tests::sandboxed_worker_failure_does_not_stop_net_or_core` 通过 152 项；`cargo test -p asl-net --all-targets --locked --offline` 通过 37 项、0 失败、1 项忽略；Clippy、格式和 `git diff --check` 通过。被跳过的 AppContainer 用例在本机子进程启动阶段 EOF，未作为通过计入。Linux Rust target 下载未完成，故 Linux 专属密钥文件权限/恢复和 systemd 入口尚未编译或运行；实际电路转发、多个入口切换、NAT、真实公网部署和总字节桶也未验收。T15 仍未关闭。

T15 relay client 与可达地址切片验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘缓存）：`cargo test -p asl-net --all-targets --locked --offline` 通过 39 项、0 失败、1 项忽略；包含两个 RelayOnly 节点通过本机 relay v2 建立认证电路。`asl-app`/`asl-net` 全目标测试、严格 Clippy、格式和 diff 检查均完成；一次最终联合重跑中，既有 `chain::http::tests::http_historical_sync_persists_every_verified_step_and_restores_offline` 偶发 `InvalidLocalState`，单测复跑通过，且此前联合运行通过 153 个 App 单元测试。AppContainer 子进程测试按本机已知环境问题跳过。Windows 本机没有验证 Linux 专属 `asl-infra` 主程序、systemd、公网/NAT、多个 relay 的故障恢复或 DHT/AutoNAT/DCUtR；Cargo 保留 `proc-macro-error2 2.0.1` 未来 Rust 兼容性提示。

T15 relay 断线重预约切片验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘缓存）：`cargo test -p asl-net --all-targets --locked --offline` 通过 42 项、0 失败、1 项忽略；新增集成测试确认配置 relay 停机后产生不可用状态，同一 PeerId/地址恢复后客户端经有上限指数退避自动重新预约。`cargo clippy -p asl-net --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 通过。仅验证单个本机 TCP relay 的停机/恢复，不代表多个 relay 故障切换、真实公网或 NAT 恢复已验收；Linux 专属入口和既有 Cargo 兼容性提示不在本轮范围。

T15 多 relay 故障切换切片验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘缓存）：`cargo test -p asl-net --all-targets --locked --offline` 通过 44 项、0 失败、1 项忽略；覆盖退避 relay 从新拨号候选中排除、一个 relay 下线后通过另一入口完成认证连接，以及 relay 持续离线时重预约失败仍保留事件循环并继续退避。`cargo clippy -p asl-net --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 与 `git diff --check` 通过。验证仅限本机 loopback TCP relay，不代表真实公网、NAT、DHT 或 Linux 基础设施已验收。

T15 relay 分块数据切片验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘缓存）：`cargo test -p asl-net --all-targets --locked --offline` 通过 45 项、0 失败、1 项忽略；新增测试通过 RelayOnly 认证连接往返 4 个独立 128 KiB bulk chunk，并校验 chunk 序号、请求关联 ID、状态和内容。`cargo clippy -p asl-net --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 与 `git diff --check` 通过。本测试只验证单机 TCP relay 上的顺序多块传输，不代表大文件断点续传、跨 relay 分块调度、真实公网带宽或 Linux 基础设施已验收。

T15 Linux 基础设施原生编译切片验证（2026-11-19，WSL Ubuntu x86_64，Rust 1.100.0，Cargo 离线模式，工具链/缓存/产物位于 E 盘）：`cargo check -p asl-app --bin asl-infra --locked --offline` 通过。WSL 缺少 `pkg-config` 命令，但已有 OpenSSL 开发头文件和库；本次仅为构建进程指定其路径，没有安装系统包或更改系统级配置。编译输出有既存 `proc-macro-error2 2.0.1` 未来兼容性提示。此次只确认 Linux 目标可编译；未运行 `asl-infra`，未实测 Linux 密钥文件权限/符号链接拒绝、systemd 服务或真实网络。T15 仍未关闭。

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

T17 DHT 记录过滤切片（2026-11-19）：新增 `asl-net::dht::BoundedRecordStore`，仅接受严格解码后的 profile、device directory 和 short-code signed record；记录键按版本化 domain 与 AgentId/kind 分离，概念键、内容键和短码 provider 查找键独立。store 限制单值 8 KiB、记录数 10,000、记录与 provider 估算总占用 64 MiB、每个 key 最多 20 个 provider、每个 provider 最多 8 个地址，并在写入新值时回收过期记录和 provider 的占额。Kademlia TTL/续发窗口固定为记录 30 分钟/10 分钟、provider 1 小时/15 分钟。`start_providing` 只接受 public audience；contacts、peers 和 group 不进入公共 provider 广告。入站 PutRecord 不直接落库，Net 只产生有界候选并经 IPC 交 Core；Core 重新校验记录键、根签名、当前链身份状态和本地序号历史后，显式回传接受或拒绝，未能完成准入的候选被拒绝。provider 地址仍先经过本机地址策略过滤，短码碰撞通过多个 provider 候选保留，不覆盖单值记录。

本切片已实现 net store、Kademlia 行为接线、Core 准入闸门、IPC 候选/决定消息及本机覆盖；DHT store、记录历史和待决候选仍为进程内存，尚未持久化，未完成跨公网节点互操作、真实 bootstrap/AutoNAT/DCUtR、查询路由、资源索引与文件传输集成。因此不能写成全网身份绑定、重启防回滚或完整 T17/T18 已完成。

T17 集中验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘 Cargo 缓存，离线）：`cargo test -p asl-net --all-targets --locked --offline` 通过 56 项、0 失败、1 项忽略；覆盖 DHT key/domain 分离、短码多 provider、签名记录序号冲突、8 KiB/10,000 条/64 MiB 有界 store、过期占额回收、公共 provider 范围、Net/Core IPC 及已有 TCP/QUIC/relay 测试。`cargo test -p asl-app --all-targets --locked --offline` 通过 182 项、0 失败、2 项忽略；包含 DHT 候选的 Core 身份/链状态准入、拒绝回传和 IPC 编解码。`cargo clippy -p asl-app -p asl-net --all-targets --locked --offline -- -D warnings`、`cargo +1.100.0 fmt --all -- --check` 和 `git diff --check` 均通过；本轮没有运行真实公网 DHT、跨实现互操作、持久化恢复、AppContainer mDNS/公网策略或 GUI 验收。Cargo 仍保留 `proc-macro-error2 2.0.1` 的未来 Rust 兼容性提示。

### T18 — 有界查询路由

依赖 T12、T17。创建 agent query router。

接口 `start_query(task: OutgoingTask) -> TaskId`；联系人先于新节点，最多 3 个 DHT term/16 peers/10 秒。incoming 只本地检索，不能把任何 query 直接转发。

验收三节点环不产生转问；query 被重放只处理一次；10 秒后不新增派发；contacts-only 任务不向 DHT 披露 term。

```text
cargo test -p asl-agent --test bounded_queries
```

T18 有界查询路由切片（2026-11-19）：新增 `asl-agent::QueryRouter` 纯状态路由器和结构化 `OutgoingTask`。出站任务先按本地联系人顺序产生直询动作，最多保留 16 个去重 PeerId；联系人全部结束后，只有 public scope 才产生最多 3 个概念 DHT lookup 动作，DHT 返回的 provider 只补足剩余直询名额。contacts-only 任务不会产生 DHT 动作，所有动作都绑定同一 root task、独立 message ID 和不超过 10 秒的时间窗。入站 `Query` 仅登记为本地执行候选，按 PeerId/message_id 去重并限 20,000 条、10 分钟保留；重复、过期或超界查询不再次执行，也没有把 query 转发给其他节点的动作。超时会清空待派发动作，过期后不再新增网络工作。

本切片只完成有界路由状态机与纯集成覆盖，尚未把动作接入实际 DHT driver、联系人持久表、`asl-store` SQLite 本地检索、Core/Agent handler 或真实三节点网络；不能写成完整查询、回答或资源发现已完成。

T18 集中验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘 Cargo 缓存，离线）：`cargo test -p asl-agent --all-targets --locked --offline` 通过 8 项、0 失败；`cargo test -p asl-agent --test bounded_queries --locked --offline` 通过 3 项、0 失败。覆盖联系人优先、contacts-only 不泄露 DHT term、DHT provider 16 节点上限、查询超时、入站重放去重和环形路由不转发。`cargo clippy -p asl-agent --all-targets --locked --offline -- -D warnings`、`cargo +1.100.0 fmt --all -- --check` 和 `git diff --check` 均通过。真实 DHT provider、SQLite 本地检索、网络三节点和 GUI 未在本轮验收。

T18 Public provider 查询与准入后直询切片（2026-11-20）：Public scope 现在通过 Net/Core IPC kind 44/45 发起有界 Kademlia provider lookup；每次查询最多 3 个概念 key，Net 单次最多返回 20 个去重 provider 候选，查询期限沿用 10 秒任务期限，Net DHT lookup 超时为 8 秒。Net 仅返回经过当前地址策略筛选的 provider/routing 端点或本机已配置 relay 可达标志；Core 将 PeerId 和地址视为候选，拨号后必须等 `CoreAdmission` 给出通过链身份、根签名设备证书和当前目录校验的活动连接，才发送结构化 Query。直询只在最多 4 个出站节点并发范围内进行，同一 PeerId 最多保留一条待完成控制请求。默认 LoopbackOnly 不因 Public scope 放宽；拨号时 Net 再次按锁定的本地地址策略核验。IPC 扩展不改变 ASL/1 应用线帧。当前没有 bootstrap 配置/节点入口，资源 provider 发布与资源索引接线未完成；因此不表示冷启动公网 DHT、跨网段/NAT 穿透或公网多节点互通已可用。

T18 Public provider 查询集中验收（2026-11-20，Windows x64，Rust 1.100.0，E 盘缓存与测试临时目录，离线）：`cargo test -p asl-agent -p asl-app -p asl-net --all-targets --locked --offline` 通过 290 项、0 失败、2 项忽略（`asl-agent` 34 项；`asl-app` 199 项、1 项忽略；`asl-net` 57 项、1 项忽略）。覆盖 DHT provider IPC 编解码和角色边界、provider 地址策略/PeerId 绑定、Public 查询只在身份准入连接后发送、TCP/QUIC 错误 PeerId 拒绝、拨号失败按 operation ID 回报。`cargo clippy -p asl-agent -p asl-app -p asl-net --all-targets --locked --offline -- -D warnings`、`cargo +1.100.0 fmt --all -- --check`、`git diff --check` 均通过。两项忽略分别是依赖生产 30 秒扫描周期的本地库测试及仅供子进程启动的 transport helper；Cargo 仍提示 `proc-macro-error2 2.0.1` 存在未来 Rust 兼容性问题。本轮未运行真实多节点 DHT、公网 bootstrap、跨网互通或资源 provider 发布验收。

### T18a — 数字短码与签名邀请配对

依赖 T06、T14、T17。创建 `asl-net/src/pairing`、签名邀请验证和本地联系人 pin 存储。持久 16 位短码只查询候选；候选通过 CoreAdmission 与链验证后再以 AgentId 匹配。首次配对使用目标绑定、身份根签名、至少 256-bit 随机 nonce 和短时效邀请；必须经过本机授权，成功只创建本地 AgentId pin，不写入资源授权。低熵口令 PAKE 暂不启用，除非有与目标 RFC 和当前 crate 版本对应的安全审计/规范一致性证据。

验收：持久短码碰撞保留多个候选，错误 AgentId 不匹配；伪造签名、错误目标、过期邀请和 transcript/PeerId 不匹配拒绝；邀请回执持久化且不可重放；配对成功只建立本地 AgentId pin，不隐式扩大目录授权。

T18a 配对核心切片（2026-11-20）：新增有界短码 provider 候选集与 CoreAdmission 后 AgentId 派生码过滤；新增 256-bit 随机、目标绑定、身份根签名邀请及针对双方 PeerId 的响应 transcript 签名；只有显式 `PairingAuthorization::Approve` 可接受邀请。SQLite schema v6 新增与 `authorized_contacts` 隔离的 `paired_contacts` 和一次性邀请回执，接受邀请只 pin AgentId，不创建资源 grant。低熵 PAKE 未加入，尚无满足本任务证据门槛的依赖决定。

T18a 配对 request-response 接线与提示限流（2026-11-20）：邀请和接受/拒绝响应已接入 `/asl/pair/1.0.0`、Net/Core IPC、Supervisor admission 流程。邀请可附一条签名覆盖的可选单句说明，最多 120 个 Unicode 字符；提示记录升级到 SQLite schema v7，按 AgentId 每 24 小时最多展示 1 次，全机每小时最多展示 20 次，最多 5 个并行待处理提示。超限邀请签名拒绝且不 pin；回答命令必须精确匹配当前待处理邀请、连接和响应句柄。完整配对 GUI 仍未实现，本轮不声明端到端 UI 已完成。

### T19 — 会话、消息与有限 outbox

依赖 T18、T05。创建 store messages/outbox、agent conversation。

验收最多 3 回合/6 语义消息，answer/ack/error 不创建任务；重启不重新回答旧消息；离线最多 3 次本机重试且总 10 分钟。fetch_grant 和 lease 不进聊天/outbox。

```text
cargo test -p asl-agent --test conversation_lifecycle
```

T19 已完成本地状态机与 SQLite 存储切片（2026-11-19）：`asl-agent::Conversation` 实现任务关联、Peer 绑定、3 回合/6 条语义消息预算、重复消息去重、10 分钟 outbox 窗口和最多 3 次离线重试；`asl-store::conversation` 将任务、CBOR `messages.body_cbor`、`outbox` 和 `processed_requests` 写入同一 SQLite 事务。回答、确认和错误只能挂到已有任务，未知回答不会创建任务；fetch request、fetch grant 和 lease 不进入聊天记录或 outbox。已有 schema v1 的表直接复用，本轮没有新增迁移。

T19 集中验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘 Cargo 缓存，离线）：`cargo test -p asl-agent -p asl-store --all-targets --locked --offline` 通过 93 项、0 失败、1 项忽略；新增 `asl-agent/tests/conversation_lifecycle.rs` 3 项和 `asl-store/tests/conversation_lifecycle.rs` 2 项，覆盖预算、重试、未知回答、非会话帧、重启后的 `processed_requests` 和 outbox 恢复。`cargo clippy -p asl-agent -p asl-store --all-targets --locked --offline -- -D warnings` 与 `cargo fmt --all -- --check` 通过。真实 Core/Net handler、SQLite 与网络运行时的联调、三节点公网互测和 GUI 仍未完成，不能将 T19 写成完整端到端会话已完成。

### T20 — Fetch、lease 与撤销栅栏

依赖 T19、T07。创建 policy leases 和 core fetch handler。

实现 fetch_request/fetch_grant、60 秒随机 lease；绑定 authenticated peer/content/grant epoch。无权限/不存在统一 not_found。

验收：错 peer、错 content、过期、重启旧 lease、contacts 撤销均拒绝；无关 grant 更新重判后继续；读取前和发送前撤销都停止新披露。

```text
cargo test -p asl-policy --test lease_revocation
```

T20 已完成授权层 lease/fetch grant 切片（2026-11-19）：`LeaseManager` 只在进程内保存随机 256 bit lease，默认最多 60 秒，绑定签发时的认证 Peer、content ID、ReadChunk Permit、grant epoch、policy revision 和可选群 epoch。`issue_fetch_grant` 在签发前重新验证 Permit，`validate_fetch_grant` 在每次使用前重新验证；Peer、内容、过期、重启后的旧 lease、联系人撤销均统一返回 `not_found` 语义，无关 policy revision 变化不会误撤销仍有效的来源。fetch grant 不进入 T19 会话或 outbox。

T20 集中验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘 Cargo 缓存，离线）：`cargo test -p asl-policy --test lease_revocation --locked --offline` 通过 4 项、0 失败；`cargo clippy -p asl-policy --all-targets --locked --offline -- -D warnings` 与 `cargo fmt --all -- --check` 通过。本轮仍未接入真实 Core 文件读取、manifest/chunk 服务、传输连接上下文、SQLite lease 审计或公网互测，不能将 T20 写成完整文件下载已完成。

### T21 — Bulk codec 与安全块服务

依赖 T20、T04。创建 transfer bulk、net codec。

验收固定 91 字节请求、27 字节响应头，未知 op/status、长度不符、超上限拒绝；块 index 推导长度，不能指定任意 offset；没有 lease 不打开 snapshot；响应 ID 不匹配不写盘。

```text
cargo test -p asl-transfer --test bulk_codec
```

T21 传输授权规划切片（2026-11-19）：复用现有 `asl-net` 固定 91 字节 bulk codec，在 `asl-transfer::bulk` 先验证当前 Peer 的 lease 和 manifest content ID，再按已验证 manifest 生成 `Manifest`、`Chunk` 或 `Inline` 的固定读取计划。chunk offset/length 由固定 1 MiB 块尺寸和 manifest 推导，不能由远端指定任意范围；越界块、非零固定 index、超 32 KiB inline、错误 manifest、错误 lease 和过期授权统一拒绝。该模块不接收路径、不按裸 hash 读盘，也不执行实际文件 IO。

T21 集中验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘 Cargo 缓存，离线）：`cargo test -p asl-transfer --all-targets --offline` 通过 2 项、0 失败；`cargo clippy -p asl-transfer --all-targets --offline -- -D warnings` 与 `cargo fmt --all -- --check` 通过。真实 bulk handler、manifest/chunk 磁盘读取、响应请求 ID 状态机、多来源调度和公网传输仍待后续 T22/T23，不能将本切片写成完整文件服务已完成。

T20/T21 Core 发送端接线（2026-11-20）：新增 `asl-app::TransferService`，通过已准入连接的 `DirectRequester` 重新读取授权快照、签发短期 FetchGrant，并在 bulk 请求时重验 ReadChunk Permit/lease；manifest、固定块或 inline 内容只从受保护的 `LocalLibraries` 快照句柄读取，发送前再次核对授权版本，块或整文件 hash 错误不会返回内容。Windows 集成用例覆盖本地公开 `.md` 导入、FetchGrant 与 Inline Bulk 响应。Windows x64 / Rust 1.100.0 / E 盘缓存离线集中验证：四个相关 crate 全目标测试 416 项通过、4 项按既有环境/子进程要求忽略；严格 Clippy、全 workspace 格式检查和本次文件差异检查通过。接收侧 Bulk 响应关联已接入 Core，但 manifest 消费、下载目录授权/每次询问及多来源持久化调度仍未实现，因此 T20–T24 完整下载链路仍未完成。

### T22 — 纯多来源调度器

依赖 T21。创建 transfer scheduler/verify。实现协议中的 ChunkScheduler，不做网络或磁盘 IO。

测试用假时钟固定来源 A/B/C/D：每来源最多 2、全下载最多 4 来源；超时重派；正确块 Verified；3 个坏 hash 禁用来源；重复块不重复完成。

```text
cargo test -p asl-transfer --all-targets --offline
```

T22 已完成纯状态多来源调度切片（2026-11-19）：`asl-transfer::scheduler::Scheduler` 接受已验证 manifest 的文件大小和块 hash，最多保留 4 个来源、每来源最多 2 个活动块、总计最多 8 个活动块；按固定超时回收未完成分配，坏 hash 累计 3 次后仅在当前传输内禁用来源。收到的数据先做精确块长度和 BLAKE3 校验，成功后进入 `Buffered`，由上层持久化成功后显式标记 `Durable`；重复完成、错 Peer、错块和非活动分配均不会改变完成状态。该模块不访问网络、路径或磁盘，也不产生来源发现或授权结论。

T22 集中验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘 Cargo 缓存，离线）：`cargo test -p asl-transfer --all-targets --offline` 通过 6 项、0 失败；覆盖来源/总并发上限、超时重派、3 次坏 hash 禁用、块 hash 与精确长度校验、重复块去重和 Buffered/Durable 状态。`cargo clippy -p asl-transfer --all-targets --offline -- -D warnings` 与 `cargo fmt --all -- --check` 通过。尚未接入真实网络请求、磁盘写入、恢复、总文件 hash、配额或公网传输；这些仍属于 T23 及后续集成，不能将 T22 写成完整下载已完成。

### T23 — 下载持久化、恢复与额度

依赖 T22、T05。创建 store quota/transfers 和 transfer resume。

验收：先预留、校验再写、sync 再 durable；每个崩溃点恢复；已标块重验；磁盘满安全停止；无进展 5 分钟释放；坏 manifest/整文件 hash 不一致冷却 24 小时不循环下载。

```text
cargo test -p asl-store --test transfer_resume --offline
```

T23 已完成下载持久化、恢复与额度切片（2026-11-19）：新增 SQLite schema v4 的 `transfer_cooldowns`，复用 `reservations`、`transfers`、`transfer_sources` 和 `transfer_chunks` 保存下载任务、来源、块状态及 24 小时完整性冷却。`asl-store::transfers::DownloadBroker` 在创建任务时先检查 write grant、全局/任务/陌生来源额度并提交 held reservation，再创建 `.part`；manifest 字节与暂存文件身份由 schema v10 持久化。块写入必须通过 manifest 推导的精确长度和 BLAKE3，文件 `sync_all` 后才把块置为 `durable`。重启会重置 assigned、重验 durable 块、释放过期/撤权/缺失文件任务，并在所有块完成后重验整文件 hash，再经固定 inbox 目录句柄原子重命名至授权目标。暂存文件使用 create-new，恢复时按文件身份重新打开，目标冲突不覆盖已有文件；完整 hash 不一致会释放预留、清理暂存并冷却该 content ID。

T23 集中验证（2026-11-19，Windows x64，Rust 1.100.0，E 盘 Cargo 缓存，离线）：`cargo test -p asl-store --all-targets --offline` 通过 86 项、0 失败、1 项忽略；新增 `transfer_resume` 4 项覆盖 durable 块跨重启、损坏块回退、完整 hash 冷却和额度先于 `.part` 创建。`cargo clippy -p asl-store --all-targets --offline -- -D warnings`、`cargo fmt --all` 与 `git diff --check` 通过。尚未把 DownloadBroker 接到真实 Core/Net 请求、权限询问 UI、T22 内存调度器或公网多来源传输；磁盘满/掉电只覆盖到 SQLite 与文件同步边界，不能据此声称真实公网下载已完成。

T23 收件目录写入补全（2026-11-20）：Windows `WriteGrant` 通过固定目录句柄 create-new、按文件身份重开，并以同目录不覆盖原子重命名完成暂存文件；SQLite schema v10 保存 manifest 字节及暂存文件身份，恢复不再依赖单独 manifest 路径。收件目录额度在同一预留事务中累计计算 held 与 consumed 下载，超额不会创建暂存文件。

T23 收件目录写入集中验证（2026-11-20，Windows x64、Rust 1.100.0、E 盘缓存、离线）：`cargo +1.100.0 test -q -p asl-policy -p asl-store -p asl-transfer -p asl-app --all-targets --locked --offline -- --test-threads=1` 全部可运行目标通过，0 失败；4 项按设计忽略（受控公网 TCP/UDP 端点、30 秒生产重扫计时器、子进程入口）。`cargo +1.100.0 clippy -q -p asl-policy -p asl-store -p asl-transfer -p asl-app --all-targets --locked --offline -- -D warnings`、`cargo +1.100.0 fmt --all -- --check` 和 `git diff --check` 均通过。新增覆盖目录移动期间的固定句柄、暂存文件身份/替换、目标冲突不覆盖、未分配 Peer 拒绝写入及 held/consumed 下载累计额度。接收端下载协调器、manifest 消费、块调度和逐次询问流程仍未接入；本次不表示 T20–T24 端到端文件下载已完成。

T23 接收侧 Bulk 响应关联（2026-11-20）：IPC kind 27 现在保留 Net 端原始请求 ID；Core 准入事件同时携带已验证连接上的 AgentId 与设备 PeerId。Core 发送 Bulk 请求前由 `TransferService` 的一次性待决表绑定请求操作、content ID、lease、连接、AgentId、PeerId 和 transport timeout；只有外层 IPC 请求 ID 与 BulkResponse 内 request ID 均匹配且身份/连接/期限一致时，响应才以 `BulkTransferResponse` 结构事件交给本机 handler。失败和断连只清除对应请求；重复、未知、错配或过期响应不推进状态。ASL blob wire frame 未变。此切片仅实现响应关联和分发，不包含 FetchGrant 到 manifest 的接收流程、DownloadBroker 写入、调度器、恢复、多来源或用户询问；T23/T20–T24 仍未完成。

T23 接收侧 Bulk 响应关联集中验证（2026-11-20，Windows x64、Rust 1.100.0、E 盘 Cargo 缓存、离线）：`cargo +1.100.0 test -p asl-app --lib bulk_response_tests --locked --offline` 通过 2 项，覆盖身份/连接/请求编号错配、重复、过期及 Bulk 失败关联；`cargo +1.100.0 test -p asl-app --test network_ipc --locked --offline` 通过 8 项，含 IPC 双请求编号不一致拒绝。`cargo +1.100.0 clippy -p asl-app -p asl-net --all-targets --locked --offline -- -D warnings`、`cargo +1.100.0 fmt -p asl-app -p asl-net -- --check` 和本切片文件 `git diff --check` 通过。未运行 `asl-app` 全测试、全 workspace、真实 LAN/公网传输、MCP 或 GUI；不能据此宣称端到端下载完成。

T23 接收清单切片（2026-11-20）：本机网络回调发出 `FetchRequest` 后，Core 按原始控制请求 ID 与当前连接的 AgentId、设备 PeerId 一次性关联 `FetchGrant`，不使用 Grant 自己的消息编号。核对内容及 lease 后复用 Bulk 请求表请求 manifest；只向本机交付内容 ID 与文件大小都匹配的 `FetchManifestReceived` 事件。`cargo +1.100.0 test -p asl-app --lib --test network_ipc --locked --offline -- --test-threads=1` 通过 188 项、0 失败，`asl-app` 全目标严格 Clippy 和格式检查通过。未启动默认后台拉取；待接入收件授权、下载任务持久化和块调度，再验收续传、多来源和真实节点。

T22/T23 续传调度接口（2026-11-20）：下载库向协调层提供经恢复检查的 manifest、durable 块号及可用来源，并支持按任务、来源和块号撤销未完成分配，不增加耐久进度。调度器可以从 durable 块恢复，跳过已落盘块；写入失败的缓冲块可以退回 missing。陌生来源预留修复为全机共享额度；任一候选来源不在本机已授权联系人中即计入，所有来源均为空也计入。不能用登记设备、切换身份或混入授权联系人绕过。仍需将已准入来源按本机任务登记到下载库，并接通每次询问与存储工作线程；这些接口本身不构成已联网的续传。

T22/T23 续传调度与额度验证（2026-11-20，Windows x64、Rust 1.100.0、E 盘缓存、离线）：`cargo +1.100.0 test -p asl-store --test transfer_resume -p asl-transfer --lib --locked --offline -- --test-threads=1` 通过 65 项、0 失败；`asl-app`、`asl-store`、`asl-transfer` 全目标严格 Clippy 和三包格式检查通过。本轮没有运行全 workspace、带身份的两节点文件下载或公网验收。

T23 本机直连收件确认（2026-11-20）：本机提供收件授权及文件名，Store 以一个入口处理授权内自动接收和显式询问。无活动授权不放行；待确认不创建任务、预留或 `.part`。确认不绑定会话令牌，绑定内容、大小、目录授权版本、文件名和来源集合；失效或拒绝的确认不可消费。`asl-core --downloads` 是本机控制入口，可查看或切换模式、列出申请、同意和拒绝，不执行传输恢复。批准不等于开始接收。[规则与期限](04-storage-policy.md)。

T23 下载来源登记（2026-11-20）：本机发起的 Fetch 收到相符清单后，Core 重新核验当前连接和链状态，并通过同一事务登记真实 Ed25519 设备、公钥、规范 CBOR 证书与 PeerId。单纯握手、未请求响应和独立 Bulk 请求不登记；已撤销证书、同编号冲突或与已有证书不一致时丢弃本次清单，不借下载替换证书，也不授予联系人权限。经验证的清单可以交给 `LocalDownloads`；该接口重新检查 lease，且仅接收本机选择的收件目录和单个文件名。证书换发需要独立身份更新流程。

本轮 Windows x64 / Rust 1.100.0 / `--locked --offline` 分批定向验收：`asl-policy` 库 21、`write_boundaries` 3、`asl-store` 库 46、`index_retention` 7、`transfer_resume` 19；`asl-app` 库 187、`asl-core` 1、`local_libraries` 4、`network_ipc` 8；`asl-types/schema_vectors` 4。共 300 通过、0 失败，1 项既有 30 秒重扫测试按设计忽略。上述四包全目标严格 Clippy 和格式检查通过。独立 Windows 进程测试覆盖列出、拒绝、批准真实本机请求，批准后仍由原 broker 创建并完成文件；来源登记走生产路由与本机链证明测试夹具。未验收 GUI、联网块调度、双节点完整下载或公网续传。

T23 大文件接收协调器（2026-11-20）：`LocalDownloads` 在本机授权任务上连接现有多来源调度器、已准入 Bulk 请求和 SQLite 持久化。一个任务最多 4 个预选来源、每来源 2 个并发块；询问模式批准绑定整个来源集合。超时、断连、出队失败或坏块会回收未完成分配，旧请求 ID 不为新分配记账；当前来源不可用时暂停该会话，仍可使用其他已获准来源。重启跳过已复验的 durable 块，只接受原来源重新提供的已验证 lease；该 lease 不写盘。完整性禁用跨恢复保留，无进度到期释放收件预留，复用 Store 的整文件校验和不覆盖发布。

初版运行入口 `Supervisor::run_with_download_driver` 提供已准入事件、定时轮询和可感知背压的发送接口；当时未改变默认 `asl-core`，也未自动接受 Offer。

Windows x64 / Rust 1.100.0 / E 盘缓存 / `--locked --offline` 定向验收：`asl-app` 下载 13、`network_ipc` 8；`asl-store` 库 46、`transfer_resume` 19；`asl-transfer` 库 10，共 96 项通过。下载用例使用真实 NTFS 和 SQLite、模拟受准入的收发事件；另有 `asl-net --test driver_requests` 1 项真实双节点 TCP/QUIC 回环，验证控制、身份和 Bulk 关联，不传输完整文件。上述三个变更包的全目标严格 Clippy 与格式检查通过；未运行全 workspace、GUI 或公网联调。

独立复核后的补强：轮询按批清理过期任务，即使任务已暂停或未进入调度；凭本机 Fetch 发起顺序识别新会话，不按 lease 到期时间排序；Core/Net 容量不足只退回未发送的块；已撤销的请求保留网络占位至响应、失败、断连或传输超时，期间不写盘、不提前补发。追加 Windows 定向验证：下载 16、传输/请求关联 7、`transfer_resume` 19，共 42 项通过；`asl-app`、`asl-store` 全目标严格 Clippy 与格式检查通过。未改 wire 格式。

T23 默认下载工作线程（2026-11-20）：默认 Core 启动一个独立磁盘工作线程；每个下载 broker 在打开 SQLite 和恢复之前，通过固定的 `state` 目录句柄独占此数据根的下载标记。受信任的同进程调用方通过 `download_channel` 提交本机选择的内容 ID、收件授权、文件名和来源，或用任务编号及既有来源恢复。队列有上限，一次运行一个任务，不根据 Offer、信任分数或联系人自动发起。已登记的离线备用设备仍绑定在原授权范围内，但不阻止已就绪来源开始；从未登记的设备须先通过准入和匹配清单登记。Core 只在设备和 Agent 均匹配的准入连接上发请求。工作线程负责收件审批、写入、同步和整文件校验；同步已写入的块时不占用 SQLite 写事务，标记 durable 前重验授权。清单来源登记的短暂数据库争用按本机背压处理。断线后，仅向重新准入的原选定来源申请新 lease，不持久化凭证，不自动拨号或增加来源。

集中验证（Windows x64，Rust 1.100.0，E 盘缓存，`--locked --offline`）：`asl-app` 库 204 项、`network_ipc` 8 项、`asl-store` 库 46 项、`transfer_resume` 20 项，共 278 项通过。`asl-app`、`asl-store`、`asl-policy` 全目标严格 Clippy 通过。模拟准入事件覆盖审批、离线备用来源、重连、重启后只拉缺块和禁止换来源。另有 1 项包含在 204 项中，使用两端真实 Ed25519 TCP 回环、生产 FetchGrant/manifest/块编解码、真实授权资源服务和 NTFS 发布；链准入是夹具，未覆盖生产 Core/Net 子进程的完整链路或公网续传。

默认 `asl-core` 只启动工作线程、恢复并清理下载状态，不提供外部提交渠道。MCP/GUI 未接入；未完成公网穿透、自动拨号或多机实测。

追加复核处理：暂存创建和最终发布仍在各自的写事务中完成同步与授权记账，避免重启时越过审批检查。暂存同步后再次检查审批窗口；分块写入在事务外同步，跨过下载到期时间时不得刷新过期的预留。交互发送前的授权事务遇到 SQLite 写锁争用时只停止当前回复，不退出 Core 或绕过权限。真实写锁争用回归确认不披露且释放锁后可以继续；最终暂存调整后 `transfer_resume` 20 项、`asl-store` 全目标严格 Clippy 和三个改动包的格式检查通过。

T23 清单冷却与网络占位（2026-11-20）：已关联的响应必须哈希为目标内容 ID 且结构无效，才会令本机工作线程写入 24 小时冷却；新 Fetch 在联系来源前检查冷却。坏哈希、Grant 大小不符或过期响应不会冷却内容。Net 以当前已认证设备的待决 Bulk 表限制实际在途数，各操作共用每设备两个槽；调度超时只回收逻辑工作，不能释放 Net 槽。Net 拒绝未发送的请求时带回原请求 ID；Core 在原 Fetch 窗口内为迟到的 Net 失败保留关联，不延长清单接受期限。两个改动均不修改对等协议或 IPC 编码。

集中验证（Windows x64、Rust 1.100.0、E 盘缓存、`--locked --offline`）：`asl-app`、`asl-store`、`asl-transfer` 库及 `network_ipc`、`transfer_resume` 测试合计 291 项通过；补充迟到失败关联后，`asl-app` 的 Bulk 关联 7 项和三包全目标严格 Clippy 通过。回归覆盖过期清单忽略、工作线程重启后冷却仍生效、TCP 回环实测第三个 Bulk 请求拒绝和响应后放行。未在真实公网或生产 Core/Net 子进程上复验，也未进行满槽断线重连的专项测试。

### T24 — Inline、PDF 与头像 helper

直连小文件接收接口（2026-11-20）：本机 handler 可把**已经获准并开始**的下载任务及其已验证来源传给 `LocalDownloads::prepare_inline`，得到走原有准入通道的一次请求与只在内存中的接收凭据。`InlineDownload::receive` 按原请求、AgentId、PeerId、连接及有效期接收匹配的响应；不匹配的响应不消费凭据，匹配响应只能处理一次。复用 Store 的块校验、同步、整文件校验和不覆盖重命名。空文件不制造虚拟块；超过 32 KiB 必须使用分块路径，不回退到 inline。无独立种子文件，不根据 Offer 自动落盘。

Windows x64 首轮定向验收：`cargo +1.100.0 test -p asl-app --lib downloads:: --locked --offline -- --test-threads=1` 通过 8 项，其中 3 项新增覆盖 0 / 32 KiB、错连接或 lease 后仍能接收正确响应、重放、损坏、过期、撤权和超限；`asl-app` 全目标严格 Clippy 通过。首轮使用本机真实 SQLite、NTFS 和已登记证书的测试夹具；未跑两台机器或公网联调。小文件收件随后接入 T23 默认下载工作线程。

依赖 T23、T09。创建 transfer inline、app helper roles、受限头像重编码。

验收：32KiB inline 上限、未经请求的附件不落盘；PDF 提取 10 秒/512MiB 限制、超页数/输出长度拒绝；解压炸弹/巨大像素/恶意 SVG 拒绝。PDF 输入不落盘且限制在 IPC 4 MiB 帧内；PNG/JPEG/静态 WebP 头像重编码≤128×128、≤64KiB；不能自动执行或打开任何收到的文件。

```text
cargo test -p asl-app --test hostile_documents
```

T24 实现切片（2026-11-19）：`asl-transfer::inline` 仅接受已登记的一次性请求，限制 32 KiB 和 32 个待决请求，并核对 content ID、长度及 BLAKE3；inline 数据只返回内存，不创建文件。新增独立 `asl-extractor.exe` 与 Core 专用 kind 41/42 IPC，一次性 Extractor 任务只接收固定 PDF/Avatar 操作和受限字节，返回前绑定 task ID；Extractor 无用户目录和网络能力。PDF 最多 500 页、输入小于单帧上限、UTF-8 输出最多 2 MiB；头像仅接受 PNG/JPEG/静态 WebP，限制尺寸、像素和解码分配，缩放到最多 128×128 后重编码且不超过 64 KiB。没有添加收到文件的自动执行或打开路径。

T24 集中验证（2026-11-19，Windows x64，Rust 1.100.0，Cargo 缓存/产物 E 盘）：`cargo test -p asl-app --all-targets --locked --offline` 通过 164 项单测及全部集成目标，其中 `hostile_documents` 3 项；1 项已有 30 秒重扫测试按环境要求忽略。Windows AppContainer 集成实测一次性 Extractor 对有效 PDF 提取文本、对无效 PDF 拒绝，并将 PNG 头像重编码到限制内。`cargo test -p asl-transfer --all-targets --locked --offline` 通过 9 项；`cargo clippy -p asl-app -p asl-transfer --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check` 通过。没有运行全工作区测试、GUI、真实 LAN/公网传输或发布打包；T24 的本机功能切片不代表 T20–T24 完整文件传输系统全部验收。

### T25 — 模型 provider 与固定 HTTP 网关

依赖 T10、T07。创建 agent gateway 与 provider registry。

接口 `ModelGateway::complete(provider_id, AuthorizedPrompt) -> ModelText`；只有 core 调用。固定已授权 endpoint，无自动跳转；key 从 DPAPI 引用取，不进提示词。

验收 mock endpoint 的超时、错误、超大响应、重定向、授权外provider；远端文本中的 URL 不产生 HTTP；本地模型必须单独获准。无真实收费服务也能用 mock 跑测试。

provider 配置文件为 `state/model-providers-v1.json`，每项包含 `id`、`endpoint`、`model`、`mode`、`enabled_by_user` 和 `request_timeout_ms`；不含凭据。ID 限小写字母、数字、连字符与下划线。远端 endpoint 仅 HTTPS，本地 endpoint 仅使用明确登记的 IPv4/IPv6 loopback 字面地址；缺失注册表时保持空 provider 集。凭据以 `provider-<provider-id>.dpapi` 单独存放；远端调用必须有 key，本地端点可无 key。Core 持有网关并逐次重验与 provider ID 和本地/远端模式绑定的 `ModelInput` permit；调用失败不会降级为其他 provider。

```text
cargo test -p asl-agent --test model_gateway
```

T25 实施切片（2026-11-20）：新增 `asl-agent::gateway` 注册表、固定 HTTP client 和有界 OpenAI-compatible JSON 请求/响应；禁用代理、重定向、自动重试及压缩，拒绝远端 HTTP 和非 loopback 本地 endpoint。`AuthorizedPrompt` 绑定 provider 并携带 1–4 个同 provider 的 ModelInput permit；每次发请求前重验。`asl-app::Supervisor` 持有网关，`DpapiProviderCredentialSource` 按 provider ID 保存/读取独立密文，Core 可调用、本地网络子进程不接触凭据。此切片没有实现 T26 的结构化决策解析、提示词来源组装或 GUI provider 设置界面；真实远端服务未调用。

T25 集中验证（2026-11-20）：Windows x64、Rust 1.100.0、E 盘构建环境，`asl-agent`、`asl-app`、`asl-policy` 三包的全部目标测试与严格 Clippy 通过；`model_gateway` 9 项通过。既有环境依赖测试仍按默认设置忽略。详见 `docs/plan-validation.md`，未运行全工作区或调用真实模型。

### T26 — 严格结构化模型决策

依赖 T25、T03。创建 agent decision/prompt。

接口按规范 validate_decision。通过条件同时是本地结构 schema、候选成员、当前授权、action 与方向。模型适配器的内部输出可以使用本地 JSON transport，但映射后的决策类型不含 `text`/prose 字段；对端 wire 必须由 T03 CBOR encoder 生成。

验收：合法 answer/decline/request_more 的结构化对象可解码；未知字段、额外 path、自然语言通道、假 refs/概念、重复键、超限数组和类型不符整次拒绝。一次修复失败固定 model_invalid，绝不部分执行，绝不将模型原始输出转发给 peer。

T26 实施切片（2026-11-20）：`asl-agent::decision` 按同一快照匹配接收者读取许可与模型输入许可，组装有界类型化上下文并严格校验本地 JSON。证据只从本次候选序号解析，类型和词表与 T03 共用；入站 `request_more` 转为 `insufficient_evidence`。模型两次无效输出返回 `model_invalid`；等待期间发生撤权或到期则直接停止，不再发送修复请求。T27 负责实际调度、取消、发送前复核和落地业务帧；此切片未开放新的网络或 IPC 入口。

### T27 — 自主状态机

依赖 T26、T18、T23。创建 agent runner。

验收 incoming 不调用远端查询；outgoing 只在授权范围内选资源；无事件不调用模型；answer 不自发回应；6 消息/3 轮/超时终止；模型不可用时资源匹配仍可确定性工作并如实标记 unavailable。

```text
cargo test -p asl-agent --test autonomous_state_machine
```

T27 入站切片（2026-11-20）：`asl-agent::runner::InboundRunner` 接收已通过 Core 身份准入的消息。默认关闭，浏览模式不产生回答任务；只有回答模式的有效 query 才创建本地工作。复用查询去重和会话预算，一个 AgentId 的多个设备共用一个待处理名额。模型不可用时，从当前接收者获准的本地元数据生成主题匹配结果或资源 offer，并在本机标记 `model_unavailable`；不读取文件内容、不触发传输、不发起外部查询。关停回答、断开连接或超时可令待处理工作失效；提取消息前需重验附带的资源许可。

T27 直连集成（2026-11-20）：`Supervisor::run()` 已将认证连接上的 query 接入 SQLite 授权检索和原请求应答通道。`asl-core --direct-inbound off|browse|answer` 写入当前 `ASL_HOME` 的本机设置；未设置时关闭，仅 `answer` 会运行检索和回复。直接检索仅考虑本机已导入且授权给该接收者的资源，每次检查最近最多 4096 条已索引候选，最多返回一个结构化匹配；`NoMatch` 始终标记为未验证，不代表完整库无结果。全局最多每 250 毫秒启动一次处理，同一 AgentId 的设备共用一秒冷却。SQLite 持久化 AgentId/root_task_id 的三轮/六条语义消息预算，以及 AgentId/message_id 的十分钟请求去重；重复、重启或换设备不能重答或重置预算。交给 Net 前重验持久链状态的目录 commitment、序号和控制器，另复核资源、当前本机开关及连接。最终授权与有限队列交接一起执行，不在 SQLite 事务内写管道；Net 检查交接期限和原连接的单次回复句柄。Offer 不含正文、路径或可直接使用的传输权限。

T27 出站联系人直询切片（2026-11-20）：新增有界 `OutgoingQueryPort`，只接受本地类型化 `OutgoingTask` 且限 `ContactsOnly`；队列最多 16 项、同时运行最多 8 项。Core 从本机 `authorized_contacts` 与当前已准入会话的交集中，按本地授权顺序挑选现有在线联系人；没有通过身份准入的 PeerId 不进入查询路由。发送前仍由 `CoreAdmission` 对该连接重验链身份，再通过原 Net request-response 通道发送固定 CBOR `Query`。Answer、Offer、Error 只按 request ID/AgentId/连接关联，Answer/Offer 还须匹配 root task 与有效期限；Offer 只接受资源型任务。结果经有界结构事件端口回交调用方，不自动追问、不自动拉取文件，也不调用模型。QueryRouter 终结任务后释放状态槽。

出站切片尚无 GUI/MCP 任务生产者，任务和结果暂不持久化；contacts-only 只向已在线且本地列入 `authorized_contacts` 的联系人直询，Public scope 已接入 DHT provider 查询和准入后直询。bootstrap 配置/节点入口、资源 provider 发布、离线投递、模型生成结构查询、结果本地历史及公网互通仍未接入。入站侧仍未实现多窗口检索或跨 Agent 公平排队、T26 异步模型、只浏览界面和 MLS 群消息。以上不关闭 T27。

### T28 — 经验整理与权限继承

依赖 T27、T07。创建 agent knowledge 与 derivation_sources 仓储。

验收：local public 派生在规则授权后可发布；只要一个来源私有或远端不可复用即私有；循环/超深/源撤回后失效；模型不能把经验写成 policy 或 system prompt。写入只 create-new，受独立 write_grant 约束。

```text
cargo test -p asl-agent --test knowledge_labels --locked
cargo test -p asl-store --test visible_search --locked
```

T28 实现切片（2026-11-20）：`KnowledgeRepository` 只保存已校验的类型化 claims，来源、时间和 `derived_unverified` 状态由本地生成；模型不能决定路径、公开性或验证标签。每个来源均需有效 `WriteDerived` permit；公开要求每个来源另有有效 `PublishRecord` permit，否则记录仅本地可见。派生文件通过固定目录身份的独立 `write_grant` 以 create-new 写入，并受额度约束；SQLite 持久化来源图、快照、索引与授权引用。来源文件失效、源 grant 撤销或写入 grant 撤销均级联停用派生后代并从 FTS 移除。直连检索加载派生来源策略并由现有策略引擎逐层核验。

T28 集中验证（2026-11-20，Windows x64、Rust 1.100.0、E 盘缓存、离线）：`cargo test -p asl-agent -p asl-app -p asl-policy -p asl-store --all-targets --locked --offline -- --test-threads=1` 通过 438 项，0 失败、4 项按环境/子进程用途忽略。之后新增的派生直连检索回归用例与完整 `visible_search` 目标共 11 项、`knowledge_labels` 1 项再次通过。相同四包的严格 Clippy 与全工作区 `cargo fmt --all -- --check` 通过。未运行全 workspace、真实模型、后台经验收集、GUI 或公网互通；本切片不代表端到端产品验收。

### T29 — 信任、贡献与公平队列

依赖 T28。创建 store evidence、agent reputation。

验收 `task/content/help_kind` 重复贡献只 1 条；incoming 垃圾资源不加贡献；换身份不能突破全局额度；preferred 不变 authorized_contacts；无授权的高分节点仍拒绝；可用性失败与恶意分开。

```text
cargo test -p asl-agent --test reputation_is_not_authority --locked
```

T29 实现切片（2026-11-20）：SQLite v9 为远端资源增加本地来源 AgentId；只有任务完成、任务 AgentId 与资源来源一致、资源处于 active/verified 时才可登记贡献，同一 task/content/help_kind 唯一且全身份共用 24 小时 100 条上限。信任观察使用固定维度和本地证据 hash；直连请求结果记 availability，块 hash 成败记 integrity。偏好写入单独 `preferred_peers`，Agent 只对现有 authorized 联系人排序；超过 16 个时查询路由保留一个轮转探索位。资源导入/使用流程尚未接入来源归因，所以来源未知的旧资源不会计贡献。

T29 集中验证（2026-11-20，Windows x64、Rust 1.100.0、E 盘缓存、离线）：`cargo test -p asl-agent -p asl-app -p asl-store --all-targets --locked --offline -- --test-threads=1` 全部通过；其中包含四项信誉/贡献专项验收及 app、store 全目标测试。三个 crate 的全目标严格 Clippy、全工作区格式检查及 `git diff --check` 均通过。此次验证不包含全 workspace、真实模型、来源 AgentId 的网络导入接线、GUI 或公网互通。

### T30 — 本机 stdio MCP

依赖 T10、T20–T24、T27、T29。T20–T24 的授权、codec、调度和 SQLite 下载组件必须先接入真实 Core/Net 收发及本机下载授权；仅有独立组件不能满足 `asl_fetch`。创建 app mcp、本机受限 IPC 和 CLI 子命令。

固定四工具，参数按 Agent 规范；输入 task/offer 必须属于当前本机授权会话，不接受任意路径/URL。

验收宿主工具调用 -> 后台任务 -> 结果/来源/下载全链路；stdout 纯协议；未知工具拒绝；ASL 不自动导入宿主聊天或扩大权限。

T30 查询任务交接切片（2026-11-20）：同进程受信任调用方可通过 `OutgoingQueryPort::submit_scoped` 提交结构化查询并取得独立的有界事件流。启动、已关联回复和终态只送达该任务的提交方，不进入原来的共享事件流。两类提交入口分别限制待处理数，共享事件阻塞不再拖住私有任务；未开放网络时，新私有提交返回离线或超时，已发起的私有任务仍会到期。原有网络授权规则不变。Windows `direct_outbound::tests` 6 项及 `asl-app` 全目标严格 Clippy 通过。尚未开放 stdio、宿主授权会话、私有 IPC 或 `asl_fetch`；不能据此宣称 MCP 已可使用。

T30 Windows 私有 IPC 切片（2026-11-20）：Policy 层新增基于现有 Tokio 及 NTFS 句柄校验的命名管道。端点由用户 SID 和数据根文件标识确定；服务端固定显式 ACL、拒绝远程客户端、独占绑定，保持同一管道实例接受下一条连接。客户端使用最小权限打开、限制服务端模拟并核对已打开管道的所有者。该模块未接入 Core 启动路径；尚无宿主授权会话、工具分派、真实 stdio 或下载接入。

T30 IPC 集中验证（Windows x64、Rust 1.100.0、E 盘缓存、离线）：`cargo +1.100.0 test -p asl-policy --all-targets --locked --offline -- --test-threads=1` 通过 117 项，2 项外网沙箱探针按原设定忽略。新增测试覆盖真实跨进程请求/回复、连续接入、重复绑定拒绝、不同根隔离、忙碌、接入前断开及缺失根。`asl-policy` 全目标严格 Clippy、格式检查和 `git diff --check` 通过。独立源码复核未发现本切片的发布阻断项；Core 接入仍须实现宿主授权和握手/I/O 时限。没有进行跨账户、远端 Windows 客户端或 MCP 端到端验收。

T30 Core/stdio 接入（2026-11-20）：`asl.exe mcp --home <绝对路径>` 开放固定四工具，默认无宿主授权。可信 Core 启动配置明确授权查询范围和可选 inbox grant；复用 Noise PSK 认证并保护本机命名管道记录。每次连接最多保留 16 个任务，任务与 Offer 句柄不跨连接。下载按当前 Offer 和本机收件授权提交，文件名由本机生成；询问状态返回 SQLite 预先分配的传输 ID，同一 Offer 重试不会重新排队。下载结果是传输引用，不宣称导入知识库。配置、撤销方式和同账户信任边界见 [Agent 与界面规范](05-agent-gui.md#7-stdio-mcp-接入)。

T30 接入集中验证（Windows x64、Rust 1.100.0、E 盘缓存、离线）：`asl-app` 库测试 222 项通过；替换后的 MCP 文件回环用例另跑 1 项通过。`mcp_contract` 3 项通过，包含真实 stdio 子进程至真实 Core、未授权/错密钥、未知工具、会话隔离和本机收件授权/撤销。`local_libraries` 4 项通过、1 项保留忽略；`asl-store` 的 `transfer_resume` 20 项通过。两 crate 全目标严格 Clippy 通过；库回环用例使用实际 MCP 换行 JSON 处理、Windows 加密管道以及经过认证的 TCP，请求由实际检索端生成 Offer，批准前不下载数据块或写文件，批准后两块校验并发布至 NTFS。回环使用链准入夹具和进程内传输驱动；未验收真实 stdio 子进程至独立 sandbox Net 的完整文件流程、生产链、公网或 GUI。

```text
cargo test -p asl-app --test mcp_contract
cargo test -p asl-app --lib mcp_offer_and_approved_tcp_chunks_publish_to_authorized_inbox
```

### T31 — OpenMLS 群房间与加密投递

依赖 T06、T14、T19。创建 `asl-groups` 房间服务、持久化适配器、基于现有认证连接的逐成员 fan-out 与定向邀请协议。优先复用 OpenMLS 0.9.2 的 RFC 9420 实现；不得自创群密钥、消息加密或成员树。

固定应用约束：最多 64 名成员、群消息最多 64 KiB、群事件本地保留 7 天、状态 catch-up 最多 256 个 epoch。MLS credential 必须绑定稳定 AgentId 与当前已验证链状态/设备证书；迁移设备通过新叶子入组，不复制旧 ratchet 状态。MLS 解密后的 application plaintext 必须为 CDDL 定义的 ASL 结构对象；禁止自由自然语言字段。仅当前成员收到群帧，OpenMLS 仅在核验 authenticated sender、链状态、设备证书、群成员和 epoch 后处理消息。群标识、群名、成员清单和群资源不发布到 DHT。

验收：邀请仅定向到指定 PeerId；加入前不接收群帧；非成员、伪造 credential、过期或重复消息、未授权成员变更和超预算 catch-up 均拒绝。并发/陈旧 commit 可恢复或明确进入 `needs_sync`，不静默分叉。离线成员消息尽力投递、不承诺必达；状态可从获准成员同步有限 commit，超预算后需重新邀请。验证成员退出/移除后的新消息不可解密，并说明旧消息无法远程删除。

T31 初始编解码切片（2026-11-20）：新增独立群子流 codec，复用冻结的 `GroupEnvelope`；MLS 应用明文只接受规范 Query、Answer、Offer。OpenMLS 0.9.2 集成夹具验证真实入组、应用消息及移除后新消息无法解密。此阶段未开放群子流，不包含生产链身份绑定、持久化、邀请、fan-out 或同步。线上/本机群 ID 的映射与 SQLite provider 兼容性已专项核对，待实施项见 [群组接线记录](group-rooms.md)。

T31 本机状态切片（2026-11-20）：SQLite v12 增加唯一线 ID 映射和密封状态字段；暂存事务不写群成员、不启用旧授权。Windows DPAPI 适配绑定本机/线上群 ID、当前设备、快照版本与 MLS epoch。Windows x64 定向验证：`asl-store` 库 47 项、`index_retention` 7 项、`asl-groups` 2 项、`asl-net` 子流 codec 6 项通过，相关 crate 全目标严格 Clippy 与 CDDL 固定向量验证通过。群 MLS 状态和 SQLite 测试分开执行；生产 Core 事务、链身份 credential、邀请、同步与网络仍待接入，不关闭 T31。

T31 身份及原子持久化切片（2026-11-20）：MLS 公钥绑定完整线上群 ID、当前链身份及精确设备证书；直连额外核对认证连接的 Hello。独立签名复核后加入严格公钥编码检查、签名预映像固定向量和独立证书到期断言。SQLite 同事务提交候选快照、成员投影和去重事件；验证重放、迟到的写入及外键失败回滚。Windows x64、Rust 1.100.0 锁定离线验证：`asl-app` 的 profile 51 项、`asl-groups` 2 项、`asl-store` 111 项通过（另有一个子进程入口按测试标记忽略）；涉及四 crate 全目标严格 Clippy 通过。身份用链证据夹具，SQLite 与 OpenMLS 恢复分别验证。房间仍为 `needs_sync`，未开启生产群网络、首次授权和重启激活；定向邀请、Welcome 与同步接线约束见 [群组接线记录](group-rooms.md)。

T31 成员协议与入站持久化切片（2026-11-20）：保持群帧外层不变，新增版本化成员 CBOR、请求/回复匹配和 OpenMLS 适配。独立协议复核后校验 Welcome 本机叶子与提交包的一致性，同步改用独立 MLS exporter 绑定。SQLite v13 以本机审批持久化一次性加入包，检查邀请额度和绑定；Welcome 提交事务同时消费包、保存候选快照和成员投影。Windows DPAPI 夹具恢复原包和签名密钥后走真实 OpenMLS 入群、应用和移除，不连接公网、链 RPC 或生产 Core。Windows x64、Rust 1.100.0 锁定离线验证：四 crate 定向 102 项测试通过，五 crate 全目标严格 Clippy 通过，CDDL 现有 20 个向量符合预期。房间仍为 `needs_sync`；出站邀请、Core 策略、同步提交日志和网络尚待接入。

T31 发方邀请持久化切片（2026-11-20）：SQLite v14 将目标设备的 Add、密封快照、成员投影、提交事件、一次性 KeyPackage 消费和待发 Welcome 原子提交。重试匹配完整请求，只取回原回复；移除作废旧回复，包消费记录保留到已验证的包寿命结束。Windows x64、Rust 1.100.0 锁定离线验证：`asl-store` 119 项、`asl-groups` 4 项通过，严格 Clippy 通过。真实 OpenMLS/DPAPI/SQLite 本机夹具验证存库后重开和入群，设备准入事实为合成数据。生产 Core 创建者证据、当前链与权限对账、有限同步及群子流仍未接入；房间不激活。详见 [群组接线记录](group-rooms.md)。

T31 Core 建群、入群与对账切片（2026-11-20）：本机建群生成与线上群 ID 绑定的 MLS 创建者承诺；获批 Welcome 同时核对承诺、树中签名者、当前连接和所有成员。SQLite 原子检查权限版本、对应的链状态和设备行并保存候选。重启对账兼顾目录历史，房间仍为 `needs_sync`。发方 Core Add/重放、GUI 审批、实际请求关联、目录续期调度、同步、房间启用与群网络待接。详见 [群组接线记录](group-rooms.md)。

T31 Core 发方切片（2026-11-20）：定向邀请与公开链及认证设备绑定；发方在独立 MLS 候选中只加入目标设备，先保存 Commit、成员投影和原 Welcome，再返回结构化回复。重试在同一读快照下核对成员链状态和房间版本。仍未接生产网络句柄、入站提示与审批工作流、同步、权限启用及群资源。详见 [群组接线记录](group-rooms.md)。

T31 Core 收方审批切片（2026-11-20）：只接受通过当前认证连接发给本机 AgentId/PeerId 的邀请；沿用 SQLite 的提示限额与去重。本机同意后才保存单次 KeyPackage，重开数据库仍只能恢复原请求，三个入口均核对双方持久链与设备状态。GUI、实际发送与待决回复绑定、同步及群资源仍待接。详见 [群组接线记录](group-rooms.md)。

T31 回环网络与待决回复切片（2026-11-21）：冻结群子流接入显式回环传输及有界 Net IPC；Core 群驱动将已审批的原请求和一次发送的本地凭据分别绑定到同一连接。队列两侧拒绝已超时的群请求，断开或失败清理待决状态，重试不改变线上请求；有效 Welcome 仍需完成 MLS、证书及存储事务。生产 Supervisor 路由、GUI 审批、目录调度、有限同步和群权限仍未接入。详见 [群组接线记录](group-rooms.md)。

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

验收撤销立即触发栅栏；新联系人不是自动偏好；身份重置不隐式继承信任；无授权不能自动启动生图/云模型；目录选择使用用户配置的 `ASL_HOME` 或显式本地路径，不假设盘符存在。

### T35 — 保留、备份、诊断与崩溃恢复

依赖 T34、T23。创建 store retention、app diagnostics。

验收 7 天消息清理、3 天失败 part、30 天 inbox；不会延长人类上限；存在引用对象不误删；恢复不重建空授权；导出诊断不含 key/lease/原文敏感内容。提供版本化加密迁移包，支持用户选择本地 ASL 数据；导入保留身份根、联系人、信任和选定记录，目标设备生成新设备密钥/证书；目录 grant、OS 凭据不迁移，MLS ratchet 不复制，需重新授权/入组。诊断导出是对输出目录的授权，默认不外传。

```text
cargo test -p asl-app --test retention_backup
```

### T36 — 便携包、登录启动与签名更新

依赖 T35。创建 packaging/windows、app update。

后台定义为当前 Windows 用户登录后的常驻进程，不冒充 SYSTEM 服务使用用户 DPAPI。便携包所有可控路径位于用户选择的应用根目录；系统创建的小量 AppContainer/图形元数据如实说明。

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
