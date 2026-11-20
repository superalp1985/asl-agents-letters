# 方案资料校验报告（历史）

本报告记录首次方案资料包生成时的 128 项检查，早于 R27 群聊/授权需求和 T01 代码实施；后附清单不代表当前工作树已重新校验。

该历史清单中的 JSON schema 路径已迁入 `schemas/prototype/`，不再是 ASL/1 真源。此报告不能用于证明当前方案资料包 128 项仍通过。

## 当前实现验证

### 已实现切片

- SQLite 初始化与迁移功能已有 Rust 实现；`cargo test -p asl-store --locked` 的 6 项测试通过。
- 测试实际执行 rusqlite migration，覆盖初始化/重复启动、WAL/foreign keys/FULL synchronous、参数绑定、未知 schema 拒绝、部分数据库拒绝和完整迁移失败回滚。
- ASL/1 确定性 CBOR codec 已实现；`cargo test -p asl-types --test protocol --locked` 的 9 项测试通过，包含全部 14 种帧的往返和固定字节向量。
- `scripts/validate-cddl.ps1` 通过：`cddl` 0.10.7 的 CDDL 语法检查及固定 ACK 字节向量验证成功；完整多帧互操作套件尚未执行。

### 2026-11-17 T06a 实现后验证范围

- `cargo test --workspace --all-targets --locked`：通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `scripts/validate-cddl.ps1`：通过（CDDL 语法及固定 ACK 字节向量）。
- `forge fmt --check`：通过（Foundry 1.9.0）。
- `forge test -vv`：14 项通过，0 失败（Solidity 0.8.24）。
- `forge build --sizes`：成功；IdentityRegistry runtime 4,548 字节，initcode 5,517 字节。
- `forge inspect IdentityRegistry storage-layout`：与身份规范中的存储布局一致。
- `forge inspect IdentityRegistry deployedBytecode | cast keccak`：template hash 与身份规范记录一致。

Rust workspace 本轮合计 31 项测试通过。Foundry 构建另打印 4 条事件顺序提示和 1 条区块时间戳提示，具体边界与 template hash 说明见 `specs/identity-registry-v1.md`。验证只覆盖当前工作区目标及其测试、identity registry 本地合约测试、CDDL 语法和一个固定 ACK 向量。合约未部署或独立审计；链轻客户端/状态证明、完整多帧互操作、Windows AppContainer、真实网络与完整产品安全均未由这些命令验证。

这些验证结果不构成完整产品、安全、沙箱、互操作或公网验收。

### 2026-11-17 T06b 验证核心实现后

- `cargo test --workspace --all-targets --locked`：57 项通过，含 26 项新增链验证测试。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- 独立依赖探针的格式检查及 `cargo run --manifest-path probes/chain-dependencies/Cargo.toml --offline`：通过；未发送 RPC 请求。
- `cargo deny --locked check licenses`：通过，另有四条既有未使用许可白名单提示。
- `scripts/validate-cddl.ps1`：通过（语法与固定 ACK 向量）。
- 内置 Helios 共识模块 10 个源码文件与固定上游归档逐字节相同；独立探针保留一条上游弃用提示。

历史 Mainnet checkpoint/BLS 最终性、合成 MPT 证明和局部缓存/重组测试分开记录。26 项链测试串行测量为 1.15 秒、CPU 1.14 秒、25 毫秒间隔采样最高工作内存 8,986,624 字节；它不是完整后台常驻资源测试。独立代码复核发现的两项问题已修正并通过新增回归测试；该复核不是完整安全审计。实时 RPC、多服务证明兼容、checkpoint/cache 持久化、身份流 codec 和独立安全审计仍待完成。本轮没有重跑 Foundry。完整范围见 `docs/chain-verification.md`。

### 2026-11-17 至 18 日 T06b HTTP 获取与持久恢复切片

- `cargo test --workspace --all-targets --locked`：108 项通过（49 项链验证/HTTP/恢复、34 项 store、其余 25 项）；包含 11 月 18 日缓存修复后的完整重跑。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `cargo deny --locked check licenses`：通过，保留四条既有未使用许可白名单提示。
- `scripts/validate-cddl.ps1`：通过（语法与固定 ACK 向量）。

新增 HTTP 测试实际开启 loopback TCP 服务，覆盖入口前缀/参数保留、错误服务切换、禁用重定向、无 Content-Length 的超大响应、超时、总请求预算、错误 JSON-RPC、MPT 失败切换、Gloas 完整 header 绑定以及历史共识数据的获取/落库/离线恢复。测试服务显式清除 Windows accept 连接继承的非阻塞状态，修正了集中测试中的随机连接提前关闭；未通过增加应用自动重试绕过该故障。

SQLite/恢复测试实际写入并重开 E 盘临时数据库，覆盖原子事务、旧写入者 CAS 拒绝、固定上下文、单条与总配额、整数边界、损坏快照/证明/观察拒绝、配置变化、过期 checkpoint、重启不延长证明寿命、高水位/撤销跨清理持久保留、最终性冲突阻止重启、写失败后停止正向解析，以及恢复中的 MPT 重验。完整性机制复用当前用户 DPAPI，不自创密码学。高水位记录硬上限 10,000，不静默删除。

本轮独立只读工程复核另发现两处缓存问题：恢复使用历史 LRU 时间清理其他仍有效证明，以及未注册身份负缓存遗留永久 agents 行。修复后用当前时间恢复 TTL、单独恢复 LRU；负缓存仅留在有界内存，重启 Unknown，不创建持久行。新增两项回归分别覆盖不同证明时间的恢复顺序，以及多身份不存在证明后数据库 agents 数量仍为零；均包含在上述 108 项中。

同一复核者已只读复查修复和回归夹具，确认原两项问题解决，限定范围未发现实质新问题。复核者未执行测试，以上命令结果为实施侧单独执行的证据；该复查不是完整安全审计或产品验收。

本轮没有访问真实 Beacon/RPC 服务、没有部署合约、没有执行多运营商 EIP-1186 互测或完整链同步资源测量；Foundry 与独立 probe 未重跑。授权 checkpoint 续期、后台/Windows 进程额度集成和独立安全审计未完成，T06b 继续保持部分完成。DPAPI 不声称阻止同用户恶意程序或整库旧副本回滚。所有开发下载、构建缓存与测试数据位于 E 盘。

### 2026-11-18 T07 纯授权判定

- `cargo test --workspace --all-targets --locked`：144 项通过，含 36 项新增 `grant_policy` 测试。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `cargo deny --locked check licenses`：通过，四条既有未使用白名单提示保留。
- `scripts/validate-cddl.ps1`：通过，范围仍为语法和固定 ACK 向量。

使用合成的本机策略事实测试全部 audience、认证设备绑定、模型 provider 交集、派生来源、版本/撤销/期限及来源图边界；没有把构造事实当成真实链或 MLS 认证。独立只读工程复核无阻断发现，提出的重复来源计数及模型许可跨 scope/撤权重验证两类遗漏已用三项测试补齐；完整测试、Clippy 和格式检查随后通过。复核者未执行测试，这不是独立安全审计。没有执行真实源文件打开、SQLite 撤销事务、沙箱或外网服务验收。详细职责边界见 `docs/policy-authorization.md`。

### 2026-11-18 T08 源文件句柄切片

- `cargo test --workspace --all-targets --locked`：165 项测试函数通过，含 21 项 `path_boundaries`。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- 独立复核者加载 E 盘环境，另行执行 `cargo test -p asl-policy --test path_boundaries --locked -- --nocapture --test-threads=1`：21 项通过。

真实 junction、硬链接、ADS、目录及卷根 SUBST、正常/中文路径、身份恢复、保护目录排除、写入/删除/重命名锁及替换对照已执行。持有能力期间真实新增硬链接成功，后续读取失败且未输出字节。重命名竞争中 256 次被锁拒绝、0 次成功并发替换、0 次回迁重试；锁释放前后替换对照成功。清理后没有本轮夹具或 SUBST 残留。

环境限制：文件/目录 symlink 创建返回 1314，实际 symlink 夹具未执行；测试文件/目录未分配 8.3 别名，实际别名分支未执行。虽然这些测试函数返回通过，不能把缺失分支算作验收。未修改机器权限、开发者模式或卷设置。T08 系统验收保持部分完成；先继续已满足依赖的 T13。

独立只读复核发现卷根 SUBST 规则遗漏、额外扩展名长度限制和竞态夹具共享冲突问题；修正及补测后复查无阻断发现。没有执行 AppContainer、写目录能力、持久撤销或传输栅栏，本轮未重跑许可证/CDDL/Foundry，没有更改依赖版本或锁文件。此复核与本机测试不构成完整安全审计。接口及边界见 `docs/windows-source-handles.md`。

### 2026-11-18 T13 结构化签名记录

- `cargo test --workspace --all-targets --locked`：226 项测试函数通过，其中新增 24 项 `signed_records`、37 项 `profile::tests`。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `scripts/validate-cddl.ps1`：通过，仍只含语法和固定 ACK 验证。
- 独立工程复核未发现可确认的实现缺陷；复核者另行重跑 24 项 codec 和 37 项 app 记录测试通过。指出的授权绑定测试弱项已补强为两份均有效的授权，单独检验请求/资源绑定。

新增测试使用真实的一次性根签名和合成 MPT 证明结果，覆盖三个记录种类、签名原文、low-S/v、当前控制者轮换、内外 owner/序号、时效、设备证书/链 commitment/registry sequence、嵌套文本与非规范编码拒绝、8,192/8,193 字节边界、单调观察与额度失败原子性，以及资料续发/撤下、头像公开授权和撤销。合成 Trie 结果不是实际 Mainnet 注册或最终化链部署的证据。

记录封装与目录/短码 CDDL 的规范缺项已显式补全，旧控制帧及合约接口不变。记录历史/发布游标仍为内存状态；DHT 仓储过滤、持久高水位、总额度、网络发送/取消及头像重编码不在本轮范围。无新增依赖或锁文件变化，许可证未重跑；Foundry、真实链服务、DHT/群组/Windows 沙箱和完整 GUI 未运行。T08 的真实 symlink/8.3 夹具缺失仍单独保留。详见 `docs/signed-records.md`。

### 2026-11-18 T06b 显式检查点续期

- `cargo test --workspace --all-targets --locked`：247 项测试函数通过，其中新增 21 项 `checkpoint_renewal_tests`，链模块共 70 项。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。

使用真实 E 盘 SQLite、当前用户 DPAPI 和合成的共识验证后状态/MPT 证明，覆盖过期恢复、观察精确保留、仍有效及已过期证明清空、重新证明、配置固定、检查点/执行头回退、旧/新 Gloas 投影、冲突锁、晚期 SQL 失败回滚和旧写入者 CAS 拒绝。普通恢复仍拒绝过期状态；续期不清除撤销或最终性冲突，不自动选择信任来源。合成检查点转换不是实际 BLS/弱主观性互操作证据。

独立只读工程复核检查生产逻辑与测试，没有确认的阻断发现；复核者未执行命令。两个同时续期调用未做确定性交错测试；旧写入者、底层 CAS 和晚期 SQL 回滚是独立记录的覆盖范围。授权界面、实际多服务链请求、后台进程额度与安全审计仍待完成。本轮未重跑 CDDL、许可证、Foundry 或外部依赖 probe，没有更改依赖/锁文件。

### 2026-11-18 T03/T13 固定协议样例

- `cargo test --workspace --all-targets --locked --offline`：251 项测试函数通过，新增 4 项固定向量测试。
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `cargo run -p asl-types --example export_schema_vectors --locked --offline -- --check`：20 个文件向量及结构化索引与生成器一致。
- `scripts/validate-cddl.ps1`：语法通过；独立 `cddl 0.10.7 --ci` 接受 17、拒绝 3，均符合预期。
- `cargo deny --locked check licenses`：通过，保留四条既有未使用许可白名单提示。
- 额外重跑 `cargo test -p asl-policy --test path_boundaries --locked --offline -- --nocapture --test-threads=1`：21 项函数通过，实际 symlink 仍返回 1314、真实 8.3 别名仍缺失，不计这些向量通过。测试夹具与 SUBST 清理后无残留。

固定样例覆盖全部 14 种帧、3 种签名记录及未知字段/文本字段/未知 kind 三个规范编码反例，原 ACK 文件未改。CDDL 工具默认模式可能在校验失败时返回 0，因此脚本启用 `--ci` 并核对成功/拒绝诊断；超时、崩溃及其他失败不计预期拒绝。每条使用精确 root，临时 wrapper 在 E 盘且运行后删除。只新增已固定 serde_json 的开发依赖及 lockfile 中相应引用，无运行依赖或协议字段变化。

独立静态工程复核无确认的阻断发现，对照了原夹具和 ACK 完整字节，检查全部样例、导出/校验入口与文档；复核者未重跑命令，超时和异常清理路径仅静态阅读。这不是多节点互操作、全量协议穷举、记录签名/链认证或完整安全验收。当前向量使用合成签名和证明字节；验证范围详见 `docs/protocol-vectors.md`。Foundry、真实链服务、Windows 沙箱与 GUI 本轮未运行。

### 2026-11-18 T08 云机夹具与盘符修正

用户提交的云机 C 盘 NTFS 输出实际覆盖文件/目录 symlink，以及文件/目录/授权根
8.3 别名。21 项函数中 20 通过、1 失败；失败来自卷根 SUBST 夹具残留的 `E:\`
硬编码，目录 SUBST 已执行。不是生产能力接受了越界路径，也不能记录整体验收通过。

测试现跟随所选夹具路径派生卷根，盘符大小写用例同步修正，新增 C/E/Z 路径
派生回归测试。修正后本机运行：

- `cargo test --workspace --all-targets --locked --offline`：252 项函数通过。
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`：通过。
- `cargo fmt --all -- --check` 和 `git diff --check`：通过。
- `cargo test -p asl-policy --test path_boundaries --locked --offline -- --nocapture --test-threads=1`：22 项函数通过；本机 symlink/8.3 仍未实际执行，卷根 SUBST 正确跟随 E 盘。

云机修正版完整重跑由用户反馈：22 项通过、0 失败、0 忽略，用时 1.27 秒。
本次提供的是测试结果摘要，没有新完整日志或提交 SHA；真实 symlink/8.3
夹具证据来自上一轮完整日志。与本机卷根 SUBST 实测结合，T08 本任务系统
验收完成，可继续 T09。不把用户执行写成代理远程执行，也不视作完整安全审计。
未改生产代码、依赖、锁文件、协议或机器设置；本次未重跑 CDDL、许可证、
Foundry 或独立复核。用户确认云机环境自 2026-11-18 起保留 7 天，按需再启动。

较早 T01 路径切片另行验证：

- `cargo check --workspace --locked` 通过。
- `cargo test -p asl-app --locked` 通过，4 个路径测试通过。
- 其余产品功能、SQLite 当前 DDL、群协议、Windows 沙箱与真实网络尚未完成或验收。

以下是原始方案阶段报告，仅保留作历史记录。

原报告日期：2026-11-17。执行环境：本机 Python、SQLite 与 jsonschema。

- 通过检查项：128。
- 校验时文件数：35；总大小约 195.3 KiB。
- 所有方案与本轮临时文件位于 E:\ASL；没有复制中转密钥。
- 两轮完整咨询返回 end_turn；第一次截断请求未当成完整评审。
- 已校验 JSON Schema、正反例、SQLite DDL/约束/FTS5、TOML、任务依赖和资料引用。

## 首次资料包未执行的验证（历史）

未实现或编译 ASL 应用，未测试 Windows 沙箱、真实网络、文件传输、运行性能、
应用层引用/授权检查、记录签名，或 6.1sol/DeepSeek 的实际编码和运行能力。
本报告不能作为产品安全或完整功能验收证据。

## 检查清单

- PASS required file: README.md
- PASS required file: LICENSE
- PASS required file: AGENTS.md
- PASS required file: .gitignore
- PASS required file: docs/01-product.md
- PASS required file: docs/02-architecture-security.md
- PASS required file: docs/03-protocol.md
- PASS required file: docs/04-storage-policy.md
- PASS required file: docs/05-agent-gui.md
- PASS required file: docs/06-implementation-plan.md
- PASS required file: docs/07-testing-release.md
- PASS required file: docs/08-research-review.md
- PASS required file: docs/reviews/fable-round-1.md
- PASS required file: docs/reviews/fable-round-2.md
- PASS required file: schemas/wire.schema.json
- PASS required file: schemas/agent-decision.schema.json
- PASS required file: schemas/profile.schema.json
- PASS required file: schemas/knowledge.schema.json
- PASS required file: specs/schema-v1.sql
- PASS required file: specs/dependency-baseline.json
- PASS required file: specs/asl-config.example.toml
- PASS required file: specs/infra.example.toml
- PASS required file: prompts/implement-one-task.md
- PASS required file: prompts/pixel-assets.md
- PASS JSON Schema meta-validation: wire
- PASS JSON Schema meta-validation: agent-decision
- PASS JSON Schema meta-validation: profile
- PASS JSON Schema meta-validation: knowledge
- PASS decision valid answer
- PASS decision valid decline
- PASS decision valid request_more
- PASS decision rejects extra path
- PASS answer requires a candidate
- PASS answer rejects query side channel
- PASS answer reason is constrained
- PASS answer length bounded
- PASS decline cannot carry arbitrary text
- PASS profile permits omitted public identity fields
- PASS profile rejects external avatar URL
- PASS knowledge schema accepts source-backed structure
- PASS model cannot self-verify knowledge
- PASS wire valid hello
- PASS wire valid query
- PASS wire valid answer
- PASS wire valid offer
- PASS wire valid fetch_request
- PASS wire valid fetch_grant
- PASS wire valid error
- PASS wire valid ack
- PASS wire rejects path in query
- PASS wire rejects unknown version
- PASS wire bounds rounds
- PASS wire validates lease encoding
- PASS wire bounds file size
- PASS SQLite DDL executes
- PASS SQLite schema version 1
- PASS SQLite foreign_keys enabled
- PASS SQLite integrity_check
- PASS SQLite foreign_key_check
- PASS preferred does not create contact authorization
- PASS contribution deduplicates task/content/help
- PASS task rounds SQL constraint
- PASS message cannot reference missing task
- PASS snapshot size SQL constraint
- PASS FTS5 query works on pretokenized Chinese
- PASS TOML config parses
- PASS data home remains E drive
- PASS no silent C fallback
- PASS sandbox no fallback
- PASS application query forwarding disabled
- PASS fixed manifest size constants
- PASS bulk request byte count
- PASS bulk response header byte count
- PASS identity export header and total byte counts
- PASS config chunk matches protocol
- PASS infra does not run Agent
- PASS dependency baseline is explicitly not a lockfile
- PASS 38 unique sequential task cards
- PASS valid earlier dependencies: T01
- PASS valid earlier dependencies: T02
- PASS valid earlier dependencies: T03
- PASS valid earlier dependencies: T04
- PASS valid earlier dependencies: T05
- PASS valid earlier dependencies: T06
- PASS valid earlier dependencies: T07
- PASS valid earlier dependencies: T08
- PASS valid earlier dependencies: T09
- PASS valid earlier dependencies: T10
- PASS valid earlier dependencies: T11
- PASS valid earlier dependencies: T12
- PASS valid earlier dependencies: T13
- PASS valid earlier dependencies: T14
- PASS valid earlier dependencies: T15
- PASS valid earlier dependencies: T16
- PASS valid earlier dependencies: T17
- PASS valid earlier dependencies: T18
- PASS valid earlier dependencies: T19
- PASS valid earlier dependencies: T20
- PASS valid earlier dependencies: T21
- PASS valid earlier dependencies: T22
- PASS valid earlier dependencies: T23
- PASS valid earlier dependencies: T24
- PASS valid earlier dependencies: T25
- PASS valid earlier dependencies: T26
- PASS valid earlier dependencies: T27
- PASS valid earlier dependencies: T28
- PASS valid earlier dependencies: T29
- PASS valid earlier dependencies: T30
- PASS valid earlier dependencies: T31
- PASS valid earlier dependencies: T32
- PASS valid earlier dependencies: T33
- PASS valid earlier dependencies: T34
- PASS valid earlier dependencies: T35
- PASS valid earlier dependencies: T36
- PASS valid earlier dependencies: T37
- PASS valid earlier dependencies: T38
- PASS 26 full-product requirements
- PASS no unfinished markers: 01-product.md
- PASS no unfinished markers: 02-architecture-security.md
- PASS no unfinished markers: 03-protocol.md
- PASS no unfinished markers: 04-storage-policy.md
- PASS no unfinished markers: 05-agent-gui.md
- PASS no unfinished markers: 06-implementation-plan.md
- PASS MIT license complete marker
- PASS work directory excluded from Git
- PASS relay credential not copied into any package file
- PASS consultation completed: round-1-native
- PASS consultation completed: round-2

### 2026-11-18 T09 AppContainer/Job 首轮与 T10 Supervisor/IPC

- `cargo test --workspace --all-targets --locked --offline`：281 项通过，2 项需外部网络端点的测试忽略。
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `git diff --check`：通过。
- `cargo test -p asl-app --test supervisor_ipc --locked --offline`：2 项通过。
- `cargo test -p asl-policy --lib named_acl_mutex_serializes_other_processes --locked --offline`：1 项通过。
- `cargo test -p asl-app supervisor::tests::sandboxed_worker_failure_does_not_stop_net_or_core --lib --locked --offline -- --exact --nocapture`：1 项通过。
- Windows sandbox probe：14 项通过、2 项需外部 endpoint 的用例默认忽略。
- Windows Supervisor/IPC 集成：Net 心跳、Worker 结构化拒绝结果、Worker 启动失败后 Net 仍可响应均通过。
- 单独启用公网 TCP probe：Net 连接到公共 IPv4 TCP 443 端点，Worker 对同一端点被拒；只验证 TCP 建连，不发送应用数据。
- 多播 socket membership 成功不等于实际 mDNS；尚无受控 UDP echo receiver，也没有在本轮接入 libp2p QUIC/mDNS query/response。

覆盖 Worker/Extractor 外部文件读取、联网和子进程拒绝，Net 文件拒绝/网络连接，
AppContainer SID/capability 核验，父环境变量清除，可执行文件 ACL 授权和精确
恢复，三个 broker 管道默认不可继承、进程句柄显式 allowlist、Job CPU/内存/
活动进程/终止限制、helper 超时、异常失败回收和无沙箱 fallback。Windows
版本为本机 NTFS/Rust1.100/MSVC。第一次独立只读复核发现临时可继承 pipe handle
暴露窗口及 UDP 探针未确认远端收包；已改为只在串行 CreateProcess 调用期间
使用临时复制句柄、立即清除继承标记，并要求 UDP 收到原 endpoint 的相同
payload。第二轮复核发现 Worker 预期 UDP 拒绝导致探针非零退出，现已改成结构化
false 并新增 TEST-NET 回归。此前一次独立复核运行在错误工作区，未检查本仓库；
随后在正确工作区的只读复核发现执行文件 DACL 读改写存在跨进程竞争，并指出
Worker 运行中崩溃测试不足。现以按固定文件身份命名的跨进程 mutex 串行化
DACL 读改写，双进程测试通过；Supervisor 测试现强制终止正在执行任务的 Worker，
确认当前任务失败、Net 仍响应且新 Worker 可完成下一任务。复核者正在只读复查
这两项修正，尚未收到其复查结论。不能宣称完整 T09 网络验收、通用沙箱安全证明
或独立安全审计。无协议/schema/Cargo.lock 变化；未重跑 CDDL、许可证、Foundry
或依赖探针。

T10 新增固定二进制 IPC、`asl`/`asl-core`/`asl-net`/`asl-worker` 入口及
真实受限子进程 Supervisor 测试。IPC 限长 4 MiB，拒绝未知角色/消息/操作、
错误方向、非预期序号和长度不匹配；Worker 每任务单独启动。Worker 在任务中
被强制终止后，当前任务失败，Net 继续响应，新的 Worker 可接续下一任务。
T09 的子进程清理测试验证了 Job Object 关闭的基础机制，但尚未做 Supervisor
进程级故障注入；MCP server/stdout 端到端也未实现或测试。
本轮因此记录 T10 代码切片通过工作区及真实子进程测试，不宣称完整系统验收。
本轮没有新增协议/schema、依赖锁或 CDDL 变化。

### 2026-11-18 T09/T10 复验与测试路径整理

- 使用 E 盘 Rust 1.100.0 工具链和 E 盘缓存执行
  `cargo test --workspace --all-targets --locked --offline`：284 项通过，
  2 项需要外部网络端点的测试忽略。
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `git diff --check`：通过。
- Windows 测试包含 Supervisor Net 心跳、Worker 任务握手阶段终止后的失败关闭与
  新 Worker 接续、ACL 跨进程 mutex，以及文件/网络/子进程隔离探针。
- Worker 中止用例在 Worker 报告 `TaskStarted` 后、Core 发送 `TaskContinue` 前
  终止进程；它验证握手中止时单次调用失败，不代表计算执行期间的进程级崩溃注入。
- Net 事件转发使用容量为 8 的有界队列；EOF 回归验证读取线程只发送一次终止错误后退出。
- UDP echo、libp2p QUIC、实际 mDNS 查询/响应、Supervisor 进程级故障注入和
  MCP stdout 集成仍未验收。未重跑许可证/CDDL、Foundry 或独立依赖探针。
- 测试夹具默认使用系统临时目录；T08/T09/T10 及通用夹具可分别通过测试专用
  环境变量指定位置。开发脚本仍将缓存和临时目录放在 E 盘；产品数据根配置不变。
- 这次工作区测试是在 E 盘 NTFS 环境执行。云机保留供后续真实系统测试使用，
  本次没有启动云机，也没有修改系统设置。

### 2026-11-18 T11：真实 Windows 本地导入、对账与中断恢复

- E 盘 NTFS，Rust 1.100.0：`cargo test --workspace --all-targets --locked --offline`，327 通过、0 失败、4 个测试入口默认忽略。4 项分别是外部 TCP、外部 UDP、真实 30 秒补查，以及供恢复测试启动的子进程入口；后者已由父测试执行，不是未经测试的恢复功能。
- 单跑 `cargo test -p asl-app --test local_libraries --locked --offline -- --ignored --exact periodic_sweep_finds_a_change_outside_watched_roots_without_an_app_hint`，1 项通过（30.08 秒）。`cargo clippy --workspace --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 通过。
- 从 SQLite v1 升级、稳定句柄读取、复制前预算、并发预留、提交前降额或撤权、同内容跨授权去重、同长度改写和删除、真实目录通知与丢通知后的补查均有覆盖。拒绝前已存在的不匹配对象，不覆盖或清理其原始字节。
- 中断测试让独立导入进程在安装阶段退出；到期前预留不释放，到期后重启能清理无引用的半成品，仍被引用的快照不受影响。清理受阻时保持预留，之后可重试。没有模拟拔电、磁盘控制器故障或整个操作系统崩溃。
- 本轮没有启用公网公告、文件传输或 lease，没有使用云机或重跑 Foundry/CDDL。用户可通过 Core 本地接口授予目录；GUI、自动收录目录中新文件和发送前的接收方授权仍不能从这组测试推断。

### 2026-11-18 T12：授权前置的本地检索

- Windows / E 盘：`cargo test --workspace --all-targets --locked --offline`，358 项通过，0 失败，4 个入口默认忽略（同 T11）。`cargo clippy --workspace --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check`、`cargo deny --offline check licenses` 通过。Jieba、词典版权声明已登记；间接依赖 `proc-macro-error2` 有 Rust 未来兼容提示，本工具链未因此失败。
- 测试使用真实 SQLite/FTS5、本地授权快照和 Windows 文件导入。覆盖本地中文/结构化概念检索、私有内容不改变公开命中/分数、伪造候选键、无权 inbox、允许 Search 但禁止 ReadMetadata、两个授权共用内容时的隔离、数据库/内存版本漂移、已撤销链身份、群/指定节点授权交集、大目录分页及游标失效。
- 独立代码复核报告的五个问题已分别处理：持久撤销优先于旧许可、按候选而非命中限制工作量、返回时权限失效需重试、SQLite v3 事务清理失效引用的 FTS 行、读取存储标签时先检查借用数据的长度。v1/v2 升级、回滚、反复授权/撤销以及真实的固定句柄前缀索引有用例。不代表磁盘安全擦除或经过独立安全审计。
- 未运行公网、云机、PDF 解析、Foundry 或模型测试；未开放节点文本消息、群聊或文件传输。线上 schema 未改，数据库版本与线上协议版本独立。

### 2026-11-18 T14 首轮：回环加密传输与 Core 身份闸门

- `cargo test -p asl-net --test two_node_transport --locked --offline`：5 项通过、0 失败、1 个子进程入口默认忽略。覆盖独立进程 TCP Noise/Yamux、QUIC、同进程 TCP 回环、错误期望 PeerId 拒绝，以及错误入站握手后监听器继续服务。
- `cargo test -p asl-app --lib profile::tests::connection_tests --locked --offline`：4 项通过、0 失败。覆盖未完成 hello 不放行、重复 hello 关闭、连接 PeerId 与 hello/证书不符、伪造 AgentId、旧证书、链撤销、目录变化、过期、历史推进、时钟回退和关闭后不可恢复。真实 TCP 回环回归验证了收到断开事件后旧会话失效、同设备重连必须重新握手、传输销毁后旧句柄不能完成 hello。
- 准入状态单测共 2 项。覆盖入站/出站握手与已建立连接共享总量上限，以及同一 PeerId 入站不会释放其独立的出站握手名额。此处是状态逻辑验证，不代表公网压力测试。
- 本轮实现仍限定为本机回环地址。传输层只证明设备 PeerId；普通业务帧必须另经 Core 的链身份、根签名设备证书和当前目录核验。尚未接入 identity-proof stream、请求响应 driver、控制/大帧实际子流 codec、AppContainer 真机网络、mDNS、公网地址、中继或 DHT，因此不能据此宣称完整 T14 或公网安全验收。

补充验证（2026-11-18）：`cargo test --workspace --all-targets --locked --offline` 全工作区通过，包含 TCP/QUIC 双进程、Core 身份闸门、路径边界、既有 Windows 沙箱和存储/协议测试；`cargo clippy --workspace --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check` 通过。新增的 T14 传输未在 AppContainer 内或公网运行。

### 2026-11-18 T14 控制/身份子流 codec

- `cargo test -p asl-net --test substream_codec --locked --offline`：5 项通过。验证固定协议向量的 request/response 往返、u32 BE framing、64 KiB 控制限制、93 字节身份请求上限、256 KiB 身份响应限制、截断/尾随数据拒绝、协议串线和身份消息方向。
- `cargo test -p asl-net --test libp2p_substreams --locked --offline`：2 项通过；每项分别在 TCP 和 QUIC 上建立真实 Swarm request-response 子流并验证控制或身份请求/响应到达预期 peer 和匹配的 request ID。该测试是同一进程内的两个 Swarm，既有独立进程测试仍只覆盖底层传输连接。
- `cargo test -p asl-net --test bulk_codec --locked --offline`：7 项通过。验证 91 字节请求、27 字节响应头、u32 BE 响应长度、操作码/固定索引、状态码、错误 payload、截断/尾随、先验响应固定头及敏感字段不进入 Debug。
- `cargo test -p asl-net --test libp2p_substreams --locked --offline`：3 项通过；控制、身份及 bulk codec 均在 TCP 和 QUIC 上执行真实 request-response 往返。bulk 用例传输并按预期 ContentId 重新校验最大合法 2,097,210 字节 manifest；两个 Swarm 同进程运行，独立进程测试仍只覆盖底层连接。
- 最终 bulk 切片通过全工作区 `cargo test --workspace --all-targets --locked --offline`、严格 Clippy、格式与 diff 检查。下方已有链恢复用例也在本轮全量中通过。
- 上述测试只证明 codec 线格式和真实子流互操作；生产 codec 未注册到 Swarm，不能把结果解释为 Core 身份闸门、请求与 AgentId 绑定、Supervisor IPC 或完整 T14 验收。后续集成需使用有界 stream 数与请求超时；本集成测试显式采用每连接最多 2 streams、10 秒超时。未在 AppContainer 或公网验证。

### 2026-11-19 T14 identity-proof 1.1.0 schema repair

- `/asl/identity-proof/1.0.0` 的原响应缺少 account nonce/balance/storage root/code hash，且 storage slot 只有 u64，无法输入现有 `EthereumProofVerifier`。未发布协议显式升级到 `/asl/identity-proof/1.1.0`，不保留旧响应的静默兼容。
- 新响应包含完整账户 MPT 输入、恰好 3 个 bytes32 slot/value 路径，以及 8 KiB 内签名设备目录记录；移除 wire 上未经证明的 controller、commitment、sequence、revoked 派生字段。Core adapter 从本机部署配置添加 chain ID 和 registry address，request ID、AgentId、checkpoint 任一不匹配时拒绝映射。
- `cargo test -p asl-app --lib chain::network_tests --locked --offline`：2 项通过；正例通过现有 Ethereum MPT verifier，负例覆盖 request ID、AgentId、checkpoint 错配。
- `cargo test -p asl-types --test protocol --test schema_vectors --locked --offline`：15 项通过；包括 8 KiB directory 上限、三条固定宽度 slot/value 与固定样例语料。
- `cargo test -p asl-net --test substream_codec --test libp2p_substreams --locked --offline`：8 项通过；TCP/QUIC 真实子流运行于同进程 Swarm。`scripts/validate-cddl.ps1`：17 个接受向量、3 个拒绝向量与 CDDL 语法均通过。
- 随后重新运行 `cargo test --workspace --all-targets --locked --offline`、`cargo clippy --workspace --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 和 `git diff --check`，均退出码为 0。全量测试包括 Windows AppContainer 用例；两项因云机环境限制的探针仍按既有规则标记 ignored。
- 本记录不代表 Swarm 生产接线、Core 身份准入、proof serving、Supervisor IPC、每连接请求绑定或公网安全验收；这些仍属于 T14 后续工作。

### 2026-11-19 T14 composed request-response behaviour

- Existing loopback Swarm now composes the frozen control, identity-proof 1.1 and bulk codecs. Request and response events retain opaque local tokens bound to the exact authenticated transport connection; identity proof context and bulk request IDs are checked before delivery. Per-protocol stream concurrency, request timeout and aggregate pending-token limits are configured.
- `cargo test -p asl-net --all-targets --locked --offline`: 23 passed, 1 ignored. The new integration test exercises all three request-response types over TCP and QUIC, including refusal of an identity response with a wrong AgentId or a different authenticated connection while retaining the pending response handle.
- `cargo clippy -p asl-net --all-targets --locked --offline -- -D warnings`: passed. Full-workspace verification for the combined changes is recorded below after completion.
- This remains a loopback-only transport slice. It does not connect network behaviour to Supervisor IPC, run the production Core identity gate, serve verified chain proofs/directories, or validate public address policy.
- Combined changes then passed `cargo test --workspace --all-targets --locked --offline`, strict workspace Clippy, `cargo fmt --all -- --check`, `git diff --check`, and `scripts/validate-cddl.ps1` (17 accepted, 3 rejected). Ignored Windows-only probes remain separately marked; no public-network or whole-product claim is made.
- Revalidation after extracting request ownership into `transport/requests.rs` and embedding the inbound connection ID in each opaque response token: the TCP/QUIC integration now also rejects using a valid response token on a second authenticated connection without consuming it. Fresh `cargo test --workspace --all-targets --locked --offline`, strict workspace Clippy, `cargo fmt --all -- --check`, `git diff --check`, and CDDL validation all passed (17 accepted, 3 rejected). The workspace run was on the local Windows host; ignored external-endpoint, production-timer, and subprocess-entry probes remain unrun.

### 2026-11-19 T14 Core identity-proof admission

- `DeviceSession::begin_network_hello` selects the locally finalized checkpoint and random request ID; the request is sent on that authenticated connection. `serve_local_identity_proof` only serves an exact-checkpoint proof already in durable local cache for the configured local AgentId. It does not initiate RPC work based on a remote request. `finish_network_hello` binds the response token to the same connection and pending request, verifies the MPT proof and signed device directory, then admits only the device certificate bound to the authenticated PeerId. Failed admission closes the session.
- `cargo test -p asl-net --all-targets --locked --offline`: 24 passed, 1 ignored. TCP/QUIC driver tests cover protocol association, request/response correlation, and rejection of an identity response token on another authenticated connection without consuming the valid token.
- `cargo test -p asl-app --lib profile::tests::connection_tests --locked --offline`: 5 passed. The Windows TCP loopback integration covers successful proof admission, refusal for mismatched AgentId/checkpoint or expired local proof, and rejection of tampered state proof or signed directory. Admission stays closed until all checks pass.
- Final `cargo test --workspace --all-targets --locked --offline` passed on Windows with Rust 1.100.0; includes 124 `asl-app` unit tests, all 22 NTFS path-boundary tests, and the T14 TCP/QUIC driver tests. Existing external endpoint, 30-second timer and subprocess-entry tests remain ignored by their documented environment requirements.
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`, `cargo fmt --all -- --check`, `git diff --check`, and `scripts/validate-cddl.ps1` passed; CDDL validation reported 17 accepted and 3 rejected vectors as expected.
- The implementation remains loopback-only and this run did not exercise public addresses, AppContainer networking, Supervisor IPC delivery of authenticated peer events, DHT, relay or multi-operator chain proof services. A source scan found no fixed public IP in product runtime code; loopback literals are confined to local tests. These results do not close T14 or certify public-network security.

### 2026-11-19 T14 Net/Core identity-proof IPC wire

- Added fixed IPC messages for authenticated transport PeerId, disconnection, identity-proof request/response, and the matching Core send/reply commands. PeerId bytes are canonically parsed; identity frames reuse the existing deterministic CBOR codec and must be the correct request/response variant.
- Net identity events are role-restricted to Net -> Core; Worker/Extractor cannot encode a peer-authentication event. The FrameReader enforces the per-message maximum from the fixed header before allocating the body; identity-proof bodies are capped at 256 KiB plus the fixed IPC envelope.
- `cargo test -p asl-app --test network_ipc --locked --offline`: 5 passed. Cases cover both message directions, role rejection, malformed PeerId, wrong nested frame kind, and proof size rejection.
- `cargo test -p asl-app --lib ipc::tests --locked --offline`: 7 passed, including reader probes proving oversized identity events and wrong-role/direction/sequence headers are rejected before their bodies are read.
- A role-boundary regression first exposed that Worker could encode a peer event; permissions were restricted to Net. A follow-up header test initially failed because the reader consumed the body before validating its role; header validation now rejects role, direction, sequence, and size before body allocation/read.
- Final `cargo test --workspace --all-targets --locked --offline` passed on Windows with Rust 1.100.0, with `ASL_T10_FIXTURE_BASE` under the configured E: development root. Strict workspace Clippy, `cargo fmt --all -- --check`, `git diff --check`, and `scripts/validate-cddl.ps1` passed; CDDL reported 17 accepted and 3 rejected vectors.
- A product-runtime source scan for fixed public IPv4 endpoints found no matches. The networking driver remains loopback-only and is not yet wired into the child process.
- This is only the IPC wire contract. No Supervisor/Net runtime mapping, device-key handoff, socket command handling, Core `DeviceSession` call, AppContainer networking, or public-network test was performed.

已有链 HTTP 历史同步测试曾在一次全量运行中于本地恢复时返回 `InvalidLocalState`；随后单项与全量重跑均通过。未确认该偶发失败的原因，本批未修改链 HTTP 或恢复代码。

### 2026-11-19 T22：纯多来源调度器

- `cargo test -p asl-transfer --all-targets --offline`：6 项通过、0 失败。覆盖最多 4 个来源、每来源最多 2 个并发块请求、总计最多 8 个请求、超时重派、坏 hash 三次禁用来源、精确块长度与 BLAKE3 校验、重复块不重复完成，以及 `Buffered` 到 `Durable` 的显式状态推进。
- `cargo clippy -p asl-transfer --all-targets --offline -- -D warnings` 与 `cargo fmt --all -- --check`：通过。
- 本轮只验证内存状态机；没有执行网络、磁盘、SQLite、断点恢复、磁盘额度、整文件 hash 或公网传输。T22 不关闭 T23，也不代表完整文件下载已完成。

### 2026-11-19 T23：下载持久化、恢复与额度

- `cargo test -p asl-store --all-targets --offline`：86 项通过、0 失败、1 项忽略；新增 `cargo test -p asl-store --test transfer_resume --offline` 的 4 项覆盖 durable 块跨重启、损坏块回退为 missing、完整 hash 错误冷却 24 小时，以及额度检查早于 `.part` 创建。
- `cargo clippy -p asl-store --all-targets --offline -- -D warnings`、`cargo fmt --all`、`git diff --check`：通过。SQLite schema 从 v3 升至 v4，新增 `transfer_cooldowns`，既有 v1/v2/v3 升级测试同步通过。
- 本轮验证了本机 Windows NTFS 上的 SQLite 预留、manifest/part 文件、块同步、durable 状态和授权目标完成；没有接入真实 Core/Net、T22 调度器、多来源公网传输、GUI 每次询问、磁盘满或掉电硬件场景。这些仍是后续集成验收范围。

### 2026-11-19 T24：Inline、PDF 与头像 Extractor

- `asl-transfer::inline` 登记单次请求后才接受最多 32 KiB 内容，并核对 content ID、长度和 BLAKE3；最多 32 个待决请求，响应只在内存中返回。`cargo test -p asl-transfer --all-targets --locked --offline`：9 项通过。
- `asl-extractor.exe` 通过仅限 Core -> Extractor 的 kind 41 输入和 Extractor -> Core 的 kind 42 结果处理固定 PDF/Avatar 操作；IPC 帧最多 4 MiB，输出最多 2 MiB，按 task ID 关联并在一次任务后退出。PDF 限 500 页、文本 2 MiB；头像限 PNG/JPEG/静态 WebP、尺寸/像素/解码内存，并规范化为不超过 128×128、64 KiB 的 PNG/WebP。
- `cargo test -p asl-app --all-targets --locked --offline`：164 项单测通过；所有集成目标通过，包括 `hostile_documents` 3 项、`home_paths` 5 项、`identity` 8 项、`network_ipc` 7 项、`supervisor_ipc` 2 项及其余目标。既有 30 秒定时重扫测试 1 项按环境要求忽略。Windows AppContainer Supervisor 用例实际调用 Extractor 验证有效 PDF、拒绝无效 PDF并重编码头像。
- `cargo clippy -p asl-app -p asl-transfer --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check`、`git diff --check`：通过。新增 `image-webp`、`lopdf`、`pdf-extract` 等依赖已锁定；Cargo 仍提示既有 `proc-macro-error2 2.0.1` 存在未来 Rust 兼容性问题。
- 没有运行 workspace 全量测试、GUI、端到端网络文件传输、LAN/公网互通或正式发布打包；本结果只覆盖 T24 本机功能切片，不表示 T20–T24 的完整传输链路已验收。

### 2026-11-20 T25：固定模型网关

- Windows x64 / Rust 1.100.0 / E 盘：`cargo test -p asl-agent -p asl-app -p asl-policy --all-targets --locked --offline` 与相同包范围的 `cargo clippy ... -- -D warnings` 通过。`model_gateway` 9 项、应用单测 165 项和 NTFS 路径边界 22 项通过；既有 30 秒重扫和两个外部网络探针按默认设置忽略。
- 本机 mock HTTP 测试覆盖超时、HTTP 错误、响应限长、禁止跳转、未授权 provider、提示词 URL 不触发额外请求、授权撤销后拒发以及同 ID 的本机/远端模式错配。独立的 Windows DPAPI 凭据往返测试也通过。
- 未调用真实模型服务或验证模型质量，未跑全工作区，未接入自主决策、GUI 或宿主工具。线上 CBOR 不变。

### 2026-11-20 T26：本机结构化模型决策

- Windows x64 / Rust 1.100.0 / E 盘：`cargo test -p asl-agent -p asl-types -p asl-policy --all-targets --locked --offline`、三包严格 Clippy、`cargo fmt --all -- --check` 与 `git diff --check` 通过。7 项新增决策测试、既有网关 9 项及 T03 固定线协议向量通过；已有两个外部网络探针默认忽略。
- 决策用例覆盖三种合法动作、重复键、未知字段/词表、错误类型/证据序号、超限数组、一项无效时拒绝整个结果、入站不扩散、错误作用域、撤权/到期以及修复只发一次且不附模型原始回复。用既有 CBOR 编解码器验证类型化回答往返。
- 未修改线上 CDDL 或依赖锁。未跑全工作区、未调用真实模型、未接入生产调度或实际发出回答。

### 2026-11-20 T27：入站调度和确定性资源回退

- Windows x64 / E 盘：`cargo test -p asl-agent --all-targets --locked --offline` 共 33 项通过，含 `autonomous_state_machine` 6 项；相同包范围严格 Clippy、`cargo fmt --all -- --check` 和 `git diff --check` 通过。
- 新增用例覆盖浏览时无工作项、确认不启动任务、无模型权限时的类型化回答与资源 offer、去重与第四轮拒绝、同一 AgentId 多设备共享待处理名额、许可跨设备不可复用、回复取出前撤权、模式切换与过期取消。
- 使用内存路由器和实际策略引擎测试，未使用真实模型、生产 SQLite 检索或模型片段读取、GUI、文件传输或公网；出站自动调研和 Core/Net 联调尚未验收。

### 2026-11-20 T27：生产直连回答接线

- Windows x64 / E 盘：`cargo test -p asl-app -p asl-store -p asl-agent -p asl-policy --all-targets --locked --offline -- --test-threads=1`：424 项通过、0 失败、4 项忽略。相同四包的严格 Clippy 与 `cargo fmt --all -- --check` 通过。未运行全 workspace。
- 真实 SQLite 用例验证默认/只浏览静默、显式回答、仅回传匹配主题、换设备和重启不会重答、跨重启三轮/六条消息预算、4096 个无权 peer 资源不挤占授权候选、v4 到 v5 迁移、联系人/目录授权撤销、本机切换关闭，以及持久目录序号变更否决旧设备会话。现有本地传输用例验证 kind 43 编解码、过期回复不消耗句柄，以及有效结构化回答沿原连接返回。
- 独立代码复核后补上持久链目录绑定、非阻塞有界交接与 Net 期限检查。仍未验证真实公网节点或链部署、持续管道背压、GUI、模型、传输及群；会话轮次跨重启和跨 Agent 公平排队仍是待办。

### 2026-11-20 T28：类型化派生经验与权限继承

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-agent -p asl-app -p asl-policy -p asl-store --all-targets --locked --offline -- --test-threads=1`：438 项通过、0 失败、4 项忽略。
- 补入派生直连搜索回归后，`cargo test -p asl-agent --test knowledge_labels -p asl-store --test visible_search --locked --offline`：12 项通过、0 失败；其中验证多来源公开/私有继承、源撤权级联、派生来源策略装载和直连检索。
- 相同四包 `cargo clippy --all-targets --locked --offline -- -D warnings` 与 `cargo fmt --all -- --check` 通过。验证范围仅为本机存储/策略/Agent/app 切片；未运行全 workspace、真实模型、后台经验收集、GUI、网络发布或公网互通。

### 2026-11-20 T20/T21：Core 发送端快照读取接线

- 在 `crates/asl-app/src/transfer.rs` 新增 Windows 集成用例：通过真实 `LocalLibraries` 导入本地公开 Markdown，执行 FetchGrant 签发与 Inline Bulk 服务，断言请求 ID、成功状态、原始字节和 BLAKE3。初次运行发现测试夹具的 AgentId 存储编码错误，修正为仓库使用的 Base58 后单项测试通过。
- Windows x64 / Rust 1.100.0 / E 盘 Cargo 与 target 缓存、离线：`cargo test -p asl-app -p asl-store -p asl-transfer -p asl-policy --all-targets --locked --offline -- --test-threads=1`：416 项通过、0 失败、4 项忽略。忽略项为既有 30 秒重扫计时器 1 项、外部 TCP/UDP receiver 2 项、子进程入口 1 项。
- `cargo clippy -p asl-app -p asl-store -p asl-transfer -p asl-policy --all-targets --locked --offline -- -D warnings`、`cargo fmt --all -- --check` 和针对本轮文件的 `git diff --check` 均通过。Cargo 提示既有 `proc-macro-error2 2.0.1` 将在未来 Rust 版本被拒绝；本轮未升级该依赖。
- 该用例只覆盖 Core 发送端快照路径；接收端下载流程、Ask 授权界面、真实 TCP/QUIC 文件往返、多来源下载和公网验证均未覆盖。未提交或推送。

### 2026-11-20 T31：发方邀请与 Welcome 事务

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-store -p asl-groups --all-targets --locked --offline -- --test-threads=1` 共 123 项通过、0 失败、1 项子进程入口按标记忽略。相同两包全目标严格 Clippy 通过。
- 独立复核后，KeyPackage 的消费标记不再随邀请 TTL 删除，提交日志使用冻结的内层尺寸上限。SQLite 验证 v13→v14 保留现有房间、存储失败全部回滚、重启后匹配原设备和原请求、移除后即使重入也不返回旧密文、过期邀请不能释放仍有效的包。
- Windows 集成测试使用真实 OpenMLS、DPAPI 和 SQLite，验证发方 Add/Welcome 同事务落盘后重开、恢复密封状态和收方入群。链/设备准入行与 MLS 身份是测试夹具，未运行生产 Core、链 RPC、群网络、GUI 或全工作区测试。线上协议与依赖锁未改。

### 2026-11-20 T31：Core 建群、入群与对账

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-app -p asl-groups -p asl-store --all-targets --locked --offline -- --test-threads=1`：384 项通过、0 失败、2 项按已有标记忽略。相同三包全目标严格 Clippy、`cargo fmt --all -- --check` 与 `git diff --check` 通过。已有 `proc-macro-error2 2.0.1` 的未来兼容提示。
- 真实 OpenMLS、DPAPI 与 SQLite 用例验证本机建群需要登记、MLS 有效但缺少创建者承诺的 Welcome 不消耗审批、有效 Welcome 单次入群、重开后只读对账、目录回退和撤销拒绝。SQLite 另验证审批提交时链状态不符不会消耗审批或留下房间，成员投影损坏时拒绝对账。
- 独立静态复核后要求 `RequiredCapabilities` 明确声明创建者扩展，并提供同一设备的目录续期接口。实际发外部请求的绑定、续期调度与发方 Core 仍待接入。未验收公网、GUI、真实链 RPC、同步或群权限启用；使用合成链证明。外层 CBOR、SQLite schema 和依赖锁未修改。

### 2026-11-20 T31：Core 定向邀请、Add 和 Welcome 重试

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-app -p asl-groups -p asl-store --all-targets --locked --offline -- --test-threads=1`：384 项通过、0 失败、2 项按已有标记忽略。相同三包全目标严格 Clippy、Rust 格式及 Git 空白检查通过。
- 双 Core 本机用例验证：未准入连接不能请求发出邀请；持久链序号错配时拒绝创建邀请、提交 Add 和重发 Welcome，且不推进 MLS epoch；成功后 SQLite 重开可取回字节完全相同的回复，改请求 ID 不可取回，发收双方的 MLS exporter 对同一 epoch 一致。
- 使用真实 OpenMLS、DPAPI、SQLite 与合成链证明；未开通生产群子流，未验收真实链 RPC、GUI 审批、公网群投递或同步。未修改 SQLite schema、外层 CBOR 或依赖锁。房间仍为 `needs_sync`。

### 2026-11-20 T31：Core 收方审批与加入包恢复

- Windows x64 / Rust 1.100.0 / E 盘离线：三包群相关库用例 15 项与 `asl-groups --test mls_application` 3 项通过，0 失败；相同三包全目标严格 Clippy 与格式检查通过。本切片未重跑全工作区。
- 双 Core 本机用例覆盖错设备拒收、重复邀请不再提示、未同意不能准备加入包、链状态错配不能批准、SQLite 重开后精确恢复原请求。测试用真实 OpenMLS、DPAPI 和 SQLite，链数据为合成证明。未启动 GUI、群子流或真实链 RPC。

### 2026-11-21 T31：回环网络与待决回复

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-app -p asl-net -p asl-store --all-targets --locked --offline -- --test-threads=1` 共 445 项通过、0 失败、3 项按原有标记忽略；同三包全目标严格 Clippy 与 `cargo fmt --all -- --check`、`git diff --check` 通过。此前并行运行复现了已记录的链历史恢复 `InvalidLocalState` 偶发失败，最终串行中该用例通过；本轮未改链 HTTP 代码。
- 真实 TCP 回环验证 Net 的 IPC 编解码、原连接回复句柄、过期发包拒绝、跨协议句柄拒绝、旧尝试与当前重试隔离，以及默认不开放群协议。独立的双 Core 用例用真实 OpenMLS、DPAPI 和 SQLite、合成链证据及注入的 Net 事件，验证重开数据库后按原 ID 和期限重发 Invite、过期请求不提交 Add、无实际待决发送不处理 Welcome、断开重试和单次入群。两类测试不是一条生产端到端链路。
- 独立静态复核定位并修正了邀请入队失败不能恢复、IPC 期限缺失和 Welcome 直接提交入口。子流协商/读写延迟不受本机 IPC 期限完整覆盖，生产开放前仍须接入。未验收生产 Supervisor 群路由、外网、GUI、真实链 RPC 或群同步。房间保留 `needs_sync`，未修改 P2P CBOR、SQLite schema 或依赖锁。

### 2026-11-21 T31：实际子流期限

- Windows x64 / E 盘离线：`cargo test -p asl-app -p asl-net --all-targets --locked --offline -- --test-threads=1` 共 328 项通过、0 失败、2 项按既有标记忽略。相同二包全目标严格 Clippy、Rust 格式和 Git 空白检查通过。
- 真实 TCP 回环验证出站过期后才驱动子流时，原请求没有到达对端，同连接的后续请求仍可送达；Net 不给过期入站事件发 IPC 回复句柄，正常往返使用原期限，旧尝试不能完成新的重试。codec 单测覆盖延迟首次读帧和结束发送半边受阻；既有双 Core 测试覆盖过期 KeyPackage 不提交 Add、原 Welcome 重试及单次入群。
- 独立静态复核后将关闭发送端纳入期限，并明确已完整进入传输层的请求不能靠本机超时撤回。未测真实子流关闭受阻时对端的投递结果，也未开启生产 Supervisor 群路由、GUI、公网或同步。未修改 P2P CBOR、SQLite schema 或依赖锁。

### 2026-11-21 T31：正式进程回环接线

- Windows x64 / Rust 1.100.0 / E 盘离线：首次集中验证 `asl-app`、`asl-net`、`asl-store` 全目标合计 456 项通过、0 失败、3 项按既有标记忽略。独立复核补齐目录历史、已审批状态保护及本机诊断后，定向群用例 25 项与正式 AppContainer Supervisor 用例 1 项全部通过；三包全目标严格 Clippy、Rust 格式与 Git 空白检查通过。
- 正式进程夹具验证 Net 可通过私有启动前导启用回环模式，且启用后拒绝切至 LAN。三 Core 用例使用合成链证明、真实 MLS/DPAPI/SQLite 和注入的 Net 事件，验证第三成员使用已断线成员的目录成功入群，以及旧目录不能替换已见的较新版本。SQLite 用例验证超限邀请不遗留设备或 peer 行，已批准的加入包不能被拒绝操作删除，本机清单只显示匹配当前设备的记录。
- 上述证据不是跨正式进程群入组端到端验收；没有实时链 RPC、公网群组、GUI、目录持续续期、同步或权限激活证据。房间仍为 `needs_sync`。未改 P2P CBOR、SQLite schema 或依赖锁。

### 2026-11-21 T31：本机签名设备目录热更新

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-app --lib --locked --offline profile:: -- --test-threads=1`，54 项通过、0 失败；`asl-app` 全目标严格 Clippy、Rust 格式和 Git 空白检查通过。
- 合成链证明验证旧封装到期、新封装生效前拒绝、拒绝回退和无效输入；入站身份证明使用新封装，Hello 仍以原设备证书发送。夹具不覆盖外部真实目录发布者、现场 RPC 或公网群组。

### 2026-11-21 T31：本机准入期限与同步历史

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-app -p asl-groups -p asl-net -p asl-store --all-targets --locked --offline -- --test-threads=1`，472 项通过、0 失败、3 项按已有标记忽略。相同四包全目标严格 Clippy、Rust 格式和 Git 空白检查通过。
- 本机合成链证明用例覆盖容量为 1 时同行证明淘汰普通本机缓存但不影响准入或证明回复，以及新鲜目录不能代替过期链证明。IPC 模拟用满写入队列验证断连去重、阻塞后补发及心跳先入队。
- SQLite v15 与 DPAPI v2 用例覆盖 v14 升级不回填、失败事务回滚、旧快照兼容、日志过期、256 步窗口、断档及密文和期限的摘要绑定。本机真实 MLS/DPAPI/SQLite 夹具核对已密封 Add、持久同步历史及 exporter；链数据仍是夹具。
- 未改 P2P CBOR 或依赖锁。未验收网络同步、群权限激活、真实链 RPC、跨正式进程入组或公网。

### 2026-11-21 T31：回环 Add 补齐与连续后缀核对

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-app -p asl-groups -p asl-net -p asl-store --all-targets --locked --offline -- --test-threads=1`，475 项通过、0 失败、3 项按已有标记忽略。相同四包全目标严格 Clippy、Rust 格式和 Git 空白检查通过。
- 三 Core 用例使用合成链证据、真实 OpenMLS、DPAPI、SQLite 和注入的 Net 事件，验证错误 exporter 拒绝、错句柄和重放不推进、单步添加及 `AtHead` 不改变房间和文件权限。SQLite 用例覆盖当前设备授权、处理途中到期回滚，及同长损坏的末步让整个后缀无法发送。
- 未改 P2P CBOR、SQLite schema 或依赖锁。未执行真实链 RPC、公网或跨正式进程群同步；未实现 Remove、Update 或权限激活。

### 2026-11-21 T31：持久补齐预算

- Windows x64 / Rust 1.100.0 / E 盘离线：`asl-app`、`asl-groups`、`asl-net`、`asl-store`、`asl-types` 五包全目标锁定、离线、串行测试 529 项通过、0 失败、3 项按已有标记忽略。相同五包全目标严格 Clippy、Rust 格式和 Git 空白检查通过。
- DPAPI v3 用例验证重开、历史滚动后计数不回退，达到 256 后拒绝下一步，旧 v2 快照保守计数，拒绝把带实际计数的快照降级成 v2。三 Core 恢复用例确认 `AtHead` 不清零。独立复核后限制 SQLite 签名者字段长度，逐步解码前查期限，并验证到期会停止剩余扫描。
- DPAPI 绑定快照与本机设备，不提供全数据库备份防回滚。未改线上协议或 SQLite schema；未测真实链 RPC、跨正式进程群同步或公网。
