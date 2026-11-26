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

### 2026-11-21 T31：群事件到期清理

- Windows x64 / E 盘离线：`asl-store` 的 `group_state::` 用例 18 项及 `asl-app` 的群相关库用例 13 项全部通过。两包全目标严格 Clippy、Rust 格式和 Git 空白检查通过；本切片未重跑五包全量。
- SQLite 用例验证每次最多删除 256 项、下一批清掉剩余到期项，同时移除关联同步记录并保留未到期的最新提交和房间版本。未模拟实际 30 秒计时、磁盘安全擦除或公网。

### 2026-11-21 T31：移除与同房间重入

- Windows x64 / Rust 1.100.0 / E 盘：锁定、离线、串行全目标测试最终覆盖五包。最后一次修正 Core 的后续同步时钟后重跑 `asl-app` 全目标，275 项通过、1 项按既有标记忽略；未再修改的 `asl-groups`、`asl-net`、`asl-store`、`asl-types` 在同一轮验证共 258 项通过、2 项按既有标记忽略。五包全目标严格 Clippy、Rust 格式与 Git 空白检查通过。
- Core 夹具验证创建者移除、非创建者拒绝、已撤销目标不阻塞保留成员的补齐、已被移除设备不能从更新后的节点拉取提交。重入须新的本机审批；保存后的房间 ID 不变，真实 OpenMLS 两端的 exporter 一致，重复 Welcome 不推进。SQLite 用例覆盖旧 Welcome 作废、过期批准与写入失败回滚、旧快照版本拒绝、重开后状态一致、旧同步记录清除。独立复核后，事务提交前复核当前证据和请求期限。
- 房间始终保持 `needs_sync`。Core 群测试使用合成链证明、真实 OpenMLS/DPAPI/SQLite 和注入的 Net 事件；不是跨正式进程的群组收发验收，未开启公网、LAN、中继、GUI 审批、群应用投递或文件权限。未修改 P2P CBOR、SQLite schema 或依赖锁。

### 2026-11-21 T31：结构化群应用的 MLS 封装

- Windows x64 / E 盘：`cargo test -p asl-groups --all-targets --locked --offline -- --test-threads=1`，12 项通过、0 失败。该包全目标严格 Clippy、Rust 格式和 Git 空白检查通过。
- 真实 OpenMLS 夹具验证成员能获取结构化明文、不匹配的本机签名密钥和对端叶子被拒、改外层 ID 无法绕过密文重放检查、自由文本拒绝，以及移除后不能读取新消息。另验证即使底层保留了旧 epoch 的解密密钥，ASL 也拒绝原样的旧 epoch 帧。未接线 Core 收发、授权或公网，也未修改 CBOR 格式、SQLite schema 或依赖锁。

### 2026-11-21 T31：Core 群应用本机事务

- Windows x64 / E 盘：`asl-app`、`asl-groups`、`asl-store`、`asl-types`、`asl-net` 五包锁定离线全目标测试，533 项通过、0 失败、3 项按已有标记忽略，不重复计入由测试启动的子进程。相同五包全目标严格 Clippy 与 Rust 格式检查通过。
- 三节点 Core 夹具使用真实 OpenMLS、DPAPI、SQLite 和合成链证明。覆盖定向验证的设备错配、已移除设备、旧 epoch、过期请求、未来时间戳、旧版本、改外层 ID 的重放，以及同内层 ID 的重新加密重放。注入 SQLite 快照写入失败，确认事件与 ratchet 都回滚，原合法消息随后仍可提交。独立复核后补齐最终时点的证书、会话和链新鲜度检查。
- 未更改 P2P CBOR、SQLite schema 或依赖锁。未接入生产群应用收发，未验收跨正式进程群应用、真实链 RPC 或公网；仍不激活房间或授予文件权限。

### 2026-11-21 T31：受限回环群消息投递

- Windows x64 / E 盘：`asl-app`、`asl-groups`、`asl-store`、`asl-types`、`asl-net` 锁定离线全目标测试，533 项通过、0 失败、3 项按已有标记忽略，不重复计入测试子进程。随后仅调整一个测试断言的写法并定向复验；五包全目标严格 Clippy、格式检查通过。
- 三节点夹具使用真实 OpenMLS、DPAPI、SQLite、合成链证明和注入的 Net 事件。覆盖同一密文向两个不同设备入队、独立请求句柄、普通成员只选创建者、回执入队失败仍返回已提交的收件事件，以及移除后创建者只向保留成员入队。网络投递与身份绑定路径经独立工程复核。
- 正式 Supervisor 收方已接线，发方仍须可信 Core 调用；未验收跨正式进程的群应用收发。未启用普通成员互发、Agent 自动行为、群文件授权、公网、LAN 或中继；未运行真实链 RPC。线上 CBOR、SQLite schema 和依赖锁不变。

### 2026-11-21 T31：可信发送与跨进程验收

- Windows x64 / E 盘：`cargo test -p asl-app --all-targets --locked --offline -- --test-threads=1`，275 项通过、0 失败、3 项忽略（既有 30 秒重扫测试、群子进程入口、跨进程场景）。`asl-app` 全目标严格 Clippy 和 Rust 格式检查通过。未重跑其他包。
- 跨进程场景单独运行时，两个测试宿主实际启动生产 Supervisor 和 AppContainer Net，并从 Net IPC 取得动态回环 TCP 监听地址。拨号经 IPC 入队，随后 Net 返回 `Transport`；临时 libp2p 诊断记录为 `Transport(... Timeout)`。未进入 ASL 身份准入，因而不计为群消息送达或移除验收。未修改系统网络规则或沙箱，临时诊断代码未保留。
- 测试宿主通过仅在测试中编译的合成最终性接入生产身份验证，不调用链 RPC。独立工程复核检查了本机发送入口、协议边界和测试清理。未改线上 CBOR、SQLite schema 或依赖锁。房间保持 `needs_sync`，无群文件权限或自动 Agent 行为。

### 2026-11-21 T31：三 Core 协议验收

- Windows x64 / Rust 1.100.0 / E 盘：`cargo test -p asl-app --all-targets --locked --offline -- --test-threads=1`，276 项通过、0 失败、3 项忽略（30 秒定时重扫、群测试子进程入口、真实 AppContainer 群互通）。`asl-app` 全目标严格 Clippy、Rust 格式及 Git 空白检查通过；未重跑其他包。
- 三个独立 Core 测试进程经生产 Net 驱动、真实匿名管道、生产 IPC 和 libp2p TCP 回环通信。链最终性为合成夹具，实际校验状态证明、签名证书与设备目录，并运行 DPAPI、SQLite 和 OpenMLS。覆盖定向邀请与本机审批、Welcome、Add／Remove 补齐、创建者投递到两名成员、普通成员只向创建者回发，以及移除后在线设备被排除、保留成员补齐后可继续接收。移除后先检查在线设备的投递名单，再等待同步，避免把空闲断线算作移除生效。
- 独立工程复核检查了三节点场景、测试清理和生产启动边界。测试用 Net 线程只在测试构建中启用，正式启动仍使用 AppContainer；本轮未重跑真实沙箱互通场景。未改沙箱、系统网络规则、线上 CBOR、SQLite schema 或依赖锁。未验收真实链 RPC、LAN、公网、中继或 GUI。房间仍为 `needs_sync`，无群文件权限或 Agent 自动收发。
- 后续只调整测试清理：Core 退出后显式 join 同进程 Net 驱动线程。定向三节点测试复跑通过 1 项；`asl-app` 全目标严格 Clippy、格式检查及 `git diff --check` 通过。

### 2026-11-21 T31：本机设备目录续签

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo test -p asl-app -p asl-store --all-targets --locked --offline -- --test-threads=1`，412 项通过、0 失败、4 项按既有标记忽略。`asl-app` 与 `asl-store` 全目标严格 Clippy、Rust 格式检查及 `git diff --check` 通过。
- 测试覆盖 5 分钟续签边界、Core 续签后忽略陈旧源文件、启动时过期封装重签、SQLite 序号跨重开/外部序号下界/耗尽行为；全目标编译覆盖 Supervisor 目录更新接线。身份链状态为合成 MPT 夹具；未执行真实 RPC、DHT 实际发布、公网、GUI 或真实 AppContainer 互通。目录续签仅更新本机直连身份证明材料，不声称已发布到 DHT。

### 2026-11-21 T32：群资源下载接线

- Windows x64 / Rust 1.100.0 / E 盘离线：`asl-store --lib` 71 项通过；`asl-agent --test model_gateway` 定向运行 9 项通过。`asl-agent` 与 `asl-store` 全目标严格 Clippy、工作区 Rust 格式检查和 `git diff --check` 通过。
- 四包（`asl-app`、`asl-policy`、`asl-store`、`asl-agent`）锁定离线全目标验证未完成：一次在 `asl-store` 的 5 个群状态测试失败，修正旧版本迁移夹具和成员 epoch 预期后，`asl-store --lib` 全部通过；随后全目标运行在 `asl-agent` 的 Mock HTTP 网关用例中失败，且失败用例在不同运行间变化。网关目标单独运行通过，因此本轮不记作四包全目标通过，仍需在后续模块集中验证时查明该不稳定性。
- 群资源测试覆盖 SQLite v16 下载绑定、成员 epoch 失效、授权 inline Fetch/Bulk，以及三 Core 群文件流程；群成员同步覆盖活动成员追踪创建者 head。未验证公网、中继、真实链 RPC、真实 AppContainer 群互通或完整 GUI。

### 2026-11-21 T32：集中验证续记

- Windows x64 / Rust 1.100.0 / E 盘缓存离线：`cargo +1.100.0 test -p asl-agent -p asl-app -p asl-groups -p asl-net -p asl-policy -p asl-store -p asl-types --all-targets --locked --offline -- --test-threads=1` 全部通过，无失败；原有环境/子进程忽略项保持忽略。此前记录的 Agent Mock HTTP 网关波动在本次全目标运行中未复现。
- 新增 SQLite 入站查询去重测试通过：相同发送者、根任务和消息在同一群中只领取一次；相同标识出现在另一群仍可领取。群查询使用独立的短生命周期 Agent runner，持久预算键按 wire group ID 做域分离。
- 七个 crate 全目标严格 Clippy（`-D warnings`）、工作区格式检查及 `git diff --check` 均通过。Cargo 仍提示 `proc-macro-error2 v2.0.1` 未来 Rust 兼容性问题。
- `group_messages_cross_sandboxed_net_processes` 仍因需要提权的临时 AppContainer 回环豁免而忽略；本轮没有验证真实 AppContainer 群互通、公网/中继、真实链 RPC 或完整 GUI，不能据此关闭 T32。

### 2026-11-21 T33：只读桌面仪表盘切片

- Windows x64 / Rust 1.100.0 / E 盘离线：`asl-store` 与启用 `desktop-ui` 的 `asl-app` 全目标测试完成；`asl-app` 共 284 项通过、3 项按既有标记忽略；`asl-store` 共 141 项通过、1 项按既有标记忽略，无失败。测试命令：`cargo +1.100.0 test -p asl-store -p asl-app --features asl-app/desktop-ui --all-targets --locked --offline -- --test-threads=1 --quiet`。
- Windows 桌面 `asl-ui` 构建成功。`asl-store`、`asl-app`（含桌面目标）严格 Clippy（`-D warnings`）通过，`cargo +1.100.0 fmt --all -- --check` 通过。Cargo 仍提示 `proc-macro-error2 v2.0.1` 的未来兼容性告警。
- 人工窗口观察确认中文字体、八个导航入口、空数据状态、桌面图标及原创像素吉祥物可见；首次观察发现概览垂直居中留出大块空白，已改为顶部排列。表格在窄窗口下改用横向滚动，尚未完成指定尺寸/DPI 矩阵。
- GUI 数据读取为 SQLite 只读连接，不迁移、不创建缺失目录/数据库，也不启动 Agent。发现当前 Core 尚无 `local_agent_identity` / `local_device_identity` 投影写入路径，故空白本机身份并非身份密钥丢失；需要后续接线。授权页当前只显示快照，不编辑权限。
- 未验收窗口关闭后后台持续工作、空闲重绘/RSS、短码/配对/迁移流程、长名称布局、公网/真实 AppContainer 网络或 T32 完整性；不关闭 T33。README 已修正“GUI 尚未实现”的过期陈述，记录当前范围，未放置空白测试画面冒充完整产品截图。像素资产和字体来源及许可边界见 `docs/licenses/asl-ui-assets.txt`。

### 2026-11-21 T34：本机身份绑定子切片

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo +1.100.0 test -p asl-store --lib --locked --offline -- --test-threads=1`，79 项通过。覆盖 v18 本机绑定存储、绑定不授予联系人授权、撤销/遗忘、有限动作队列及 v13/v14 迁移夹具。
- `cargo +1.100.0 test -p asl-app --all-targets --features desktop-ui --locked --offline -- --test-threads=1`：286 项通过、3 项按既有标记忽略；包含 `asl-core --bindings` 命令解析、IPC DHT 发布/撤销消息的固定角色与编解码，以及 Windows `asl-ui` 目标编译。严格 Clippy（`asl-app`、`asl-store` 全目标，含桌面 feature）、`cargo +1.100.0 fmt --all -- --check` 与 `git diff --check` 通过。
- 修正旧版数据库测试夹具遗留 v18 表/默认设置的问题；补齐 DHT provider 命令 IPC 最大消息长度白名单。未新增依赖或改变线上 CBOR；`RecordKey` 通过 `asl-net` 暴露给 IPC 适配层。
- 未端到端运行 Core 的短码发布/发现与候选批准；未验收真实 DHT、公网、真实链 RPC、AppContainer 网络、GUI 窗口布局或迁移/导出。测试中的跨 AppContainer 场景仍因需要提升权限而忽略。T34 其余授权视图和策略写操作未实现，不关闭 T34。

### 2026-11-21 T34：目录授权界面子切片

- Windows x64 / Rust 1.100.0 / E 盘离线：`asl-store --lib` 80 项通过。覆盖共享/收件授权的本机 Dashboard 投影、完整路径仅供本机授权页识别、扩展类型、额度和模型策略。
- `asl-app --all-targets --features desktop-ui` 全目标测试 288 项通过、3 项既有测试忽略。此整套运行早于最后补入的经验保存目录入口；该入口完成后重跑 `asl-core` 二进制测试 8 项通过。`asl-app`、`asl-store` 全目标严格 Clippy（`-D warnings`，含 Windows 桌面目标）通过，确认最终 GUI/Core 代码编译。
- 授权页可创建/撤销共享、收件和派生经验写目录。共享授权显示 audience、扩展名、单文件上限、模型禁用和派生披露选择；收件与派生写入分别走现有 Store broker API。撤销操作经用户确认，沿用 grant epoch 与 SQLite policy revision；未改线上 CBOR、schema 或依赖。
- GUI 不自动导入或公告共享目录内容。未做人工窗口布局/DPI验收；未验收真实 DHT、公网、身份迁移或其他 T34 policy/profile/provider/network 控件，因此不关闭 T34。

### 2026-11-21 T34：传输审批界面子切片

- Windows x64 / Rust 1.100.0 / E 盘离线：`cargo +1.100.0 test -p asl-store --lib --locked --offline dashboard::tests`，5 项通过。覆盖只读 Dashboard 默认模式、显式询问模式投影及空审批队列。
- `cargo +1.100.0 check -p asl-app --bin asl-ui --features desktop-ui --locked --offline`、对应桌面目标严格 Clippy，以及 `asl-store --all-targets` 严格 Clippy均通过。`cargo +1.100.0 fmt --all -- --check` 与 `git diff --check` 通过。
- GUI 复用 Store 现有上传/下载待审批筛选和 Core 命令，提供独立模式切换、批准/拒绝、未消费批准撤销及传输页定时刷新；不启动下载恢复流程，不创建 Permit/lease 或直接传输文件。未新增依赖、SQLite schema 或线上协议字段。
- 未做人工桌面窗口、布局/DPI或实时双节点审批验收；Cargo 仍提示 `proc-macro-error2 v2.0.1` 未来 Rust 兼容性告警。

### 2026-11-21 T34：直连只浏览活动记录

- Windows x64 / Rust 1.100.0 / E 盘离线：`asl-app` 含 `desktop-ui` 的全目标测试在联合运行中 289 项通过、3 项按既有标记忽略；随后 `asl-store --lib` 最终运行 84 项通过、0 失败。联合运行最初发现两处 v13/v14 迁移夹具降级时未移除 v19 表，已修正夹具后完成存储全量重跑；未重跑 app 测试，其 app 测试目标在首次联合运行中均通过。
- `asl-app` 与 `asl-store` 含桌面目标的全目标严格 Clippy（`-D warnings`）、工作区 Rust 格式检查和 `git diff --check` 最终通过。Cargo 仍报告 `proc-macro-error2 v2.0.1` 的未来兼容性告警。
- SQLite v19 新增本机直连观察表：按 AgentId/消息 ID 去重，最多保留 200 条、每条 7 天；Core 启动和每个新请求时清理过期记录。BrowseOnly 仅记录固定结构字段并在活动页显示，不存正文或约束值，不调用检索、不产生回复或传输。测试覆盖迁移、去重、全局上限、到期清理及只浏览请求不返回回复。
- 未做人工窗口布局/DPI验收、双节点实时浏览验收、AppContainer 或公网测试；群组浏览状态未纳入本切片。

### 2026-11-22 T34 群组浏览与自动回答

- Windows x64、Rust 1.100.0、离线。`group_inbound_settings` 通过，在含空格的临时数据目录调用正式 `asl-core`，验证默认只浏览、独立切换与非法输入处理。
- `group_messages_cross_core_processes_over_framed_ipc_and_tcp` 通过。三个 Core 进程经本机 TCP 收发结构化群消息。独立连接修改回答授权后，运行中的节点开始回答。关闭浏览期间收到的请求在重新开启后维持隐藏。
- `asl-store` 全目标测试 151 项通过，1 个子进程入口按标记忽略。`asl-app`、`asl-groups` 和 `asl-store` 含桌面目标的全目标严格 Clippy 通过。应用验证范围为上述两个场景。真实 AppContainer 互通、公网和人工窗口验收仍待执行。

### 2026-11-22 T33 桌面授权与收发审批截图

Windows x64 使用 Rust 1.100.0 离线构建 `asl-ui` 和 `asl-core`（`desktop-ui`）。独立 `ASL_HOME` 通过正式本机命令建立三个空演示目录的授权，上传和下载均选择逐次询问。实际打开概览时可见三项目录授权和只浏览模式，授权页可见各目录的用途、范围及额度，传输页可见两个独立审批设置。中英文 README 引用同两张原生窗口截图。此轮观察使用默认窗口尺寸，公网传输、待审批文件的端到端操作和多 DPI 仍待验收。

### 2026-11-22 T34 浏览期限、选群与联系人反馈

12 项定向测试通过，覆盖直连浏览期限的本机设置与记录清理、授权表单的群组选择及联系人操作反馈。`asl-app` 与 `asl-store` 全目标严格 Clippy 通过，桌面和 Core 构建成功。

### 2026-11-22 T33 关窗后的后台处理

Windows 上通过窗口的正常关闭请求退出独立演示资料的 `asl-ui`。退出前数据库仅有短码尾号 42 的旧请求。确认窗口进程退出后，向同一资料执行 `asl-core --bindings lookup 0000000000000043`，命令回报已排队。随后只读查询 SQLite 发现新增 `action_id=2`，`state=failed`、`result=unavailable`。该演示资料未配置链身份服务。原 Core 和 Net 两个进程均仍在运行。该场景验证后台确实处理了关窗后新提交的工作。公网短码发现及成功建联另行验收。

使用 `scripts/prepare-desktop.ps1 -Offline` 从锁定的 Cargo 构建生成五个独立的可执行文件，在路径含空格的新运行目录和空白资料目录中复现。窗口退出后，后台把短码尾号 44 的第一项请求处理为 `failed/unavailable`。随后结束测试 Core，Windows 同时清理其 Net 子进程。两次运行均使用正式的进程隔离设置。

在第二次运行的默认概览页静置 12 秒，采样末 Core、Net、GUI 工作集分别为 23.5、13.6、109.0 MiB，区间累计 CPU 时间分别约为 125、0、0 毫秒。此数据来自单机、单次、空白资料的调试构建。长期空闲、活跃传输及多个 DPI 下的资源采样仍待执行。

### 2026-11-22 T33 活动页会话详情

活动页按任务与设备区分直连会话，按群组归集多个设备的事件。展开后可查看完整任务或群组 ID、时间、消息类型、方向及身份。桌面读取最近 100 条仍在保留期内的可见事件，投影只包含会话元数据。

`asl-ui` 与 `conversation_lifecycle` 两个测试目标共 5 项通过。测试覆盖直连与群组 ID 相同、同一任务涉及不同设备、同一群的不同发送者、过期事件及关闭浏览时的群消息。两个目标的严格 Clippy 检查通过。

### 2026-11-22 T31 管理员回环测试故障

用户在本机管理员 PowerShell 中成功编译并执行了真实 AppContainer 群组用例。测试在 7.89 秒后报告 `Core fixture output: Disconnected, child: None`。父进程当时尚未取得退出状态，日志也没有给出失败阶段。

旧测试同步等待入站回环调试程序退出，导致程序运行期间 Net 无法启动。测试现为每个 Net 的调试程序分配独立管道，并用 Windows Job 管理其生命周期。父进程会报告节点、请求阶段和输出读取错误。

本机普通权限验证通过三项，分别覆盖三 Core 协议互通、带非 UTF-8 行的回复读取、持有者关闭后 Windows 回收仍在运行的辅助进程。正式 Net、Worker、Extractor 构建成功。`asl-app` 与 `asl-policy` 的库及测试目标严格 Clippy 通过。修正后的真实 AppContainer 三节点互通待管理员复跑。

### 2026-11-22 T31 网络容器权限登记

随后一次管理员运行中，三个 Net 均返回 TCP 监听端点。拨号报告 `Transport`，等待身份准入时连接列表为空，用例在 23.04 秒后失败。01:55 这次运行的 Windows 防火墙事件 2097 记录了三个临时容器各自入站、出站阻止规则的创建，2052 记录规则清理。两类事件都记录配置变化。此次拨号缺少可对应的丢包记录。

启动器原先只把 Net 的两项网络能力交给进程 token。现用同一份能力列表创建 Windows profile 和进程 token，Worker 与 Extractor 的列表均为空。修改后运行 `asl-policy --test sandbox_probe`，16 项通过，两个需外部 TCP/UDP 端点的用例按标记跳过。同一运行时段的 Windows 日志出现 ASL profile 的 Internet 与 Intranet 入站、出站允许规则。三 Core 宿主线程协议用例和测试输出读取用例均通过。`asl-app` 和 `asl-policy` 的库和测试目标通过严格 Clippy。修正后的真实 AppContainer 三节点群消息仍待管理员复测。

### 2026-11-22 T31 入站回环许可

02:08 的管理员运行用时 23.70 秒。`first` 向 `second` 拨号时，WFP 在接收端 `55195` 记录三次来自 `55196` 的入站丢弃。三条事件都指向 `filterId=138225`，规则名为 `AppContainerLoopback`，所在层为 `ALE_AUTH_RECV_ACCEPT_V4`。事件带有两项预期网络能力。捕获中入站回环允许规则 `138030` 仅匹配一个更早的 ASL 测试 profile。三个新入站调试程序均退出，错误为 `0x80320009`（`FWP_E_ALREADY_EXISTS`）。此次拨号止于 TCP 入站授权，尚未进入群组身份握手。

验收程序现按两阶段交接入站调试程序。两个成员先交换身份目录，再分别连接创建者；每个 Net 继续使用自己的独立 profile。按新顺序运行的三 Core 宿主线程协议和输出读取用例通过。使用本次捕获的 `filters.xml` 回放，检查器正确识别旧 SID 的入站许可，并拒绝本轮接收 SID。真实 AppContainer 交接和后续群投递待管理员运行。

### 2026-11-22 T31 接收节点防火墙规则

02:25 的管理员运行中，三个 Net 都已监听。`61690` 拨向 `61689` 的三次 TCP 入站丢弃均显示，接收方的 AppContainer 隔离规则 `138534` 已放行，Windows 防火墙随后按 `136631`（`Query User Default`）阻止入站。此次连接止于身份握手之前，23.70 秒后测试失败。

管理员夹具现在按接收方临时安装一条入站规则，拨号前读取有效策略，核对程序路径、SID 和端口。两端地址都限定为 IPv4 本机回环。正式启动路径不调用该脚本。当前普通权限运行中，三 Core 宿主线程协议和输出读取用例均通过，`asl-app` 库和测试目标的严格 Clippy 通过。真实规则安装、两次接收方配置及后续群消息投递仍待管理员验收。

PowerShell 模拟检查覆盖规则参数、输入管道关闭后撤回规则、策略未生效时停止并清理，以及外层脚本按本次运行标识清理。

### 2026-11-22 T31 三节点容器回环验收

用户在 Windows 管理员 PowerShell 运行 `scripts/run-appcontainer-loopback-test.ps1`；在 `be7763b` 加入接收端临时规则后，`supervisor::groups::process_tests::group_messages_cross_sandboxed_net_processes` 报告 **1 passed，0 failed，0 ignored，249 filtered out，53.31 秒**。三个 Core 各自通过真实 AppContainer Net 收发，在动态 TCP 回环端口监听；成员先互连，再分别拨向创建者，两阶段接收方交接成功。

用例完成建群、两次定向邀请与本机审批；创建者向两名成员投递结构化 Query，一名成员向创建者回发。启用回答后创建者收到结构化 Answer；另一成员关闭浏览后，新查询没有显示，重新启用也没有补录。移除该设备时其连接仍在，创建者只向剩余成员排队，剩余成员追至 MLS epoch 3 后继续收件。

链最终性与证明输入来自测试夹具，未访问真实链 RPC。本次没有运行全工作区、跨容器群文件传输、跨机 LAN、公网/中继或 GUI 验收；也未单独盘点退出后的系统规则。此前失败的抓包记录保留用于排查，不代表当前结果。

### 2026-11-22 T32 群文件双端审批

两个独立 Core 测试进程通过生产 Net 驱动、IPC 与 TCP 回环运行 OpenMLS 群文件请求和 Bulk 分块传输。源目录仅授权给该群，两端均选逐文件确认。用例明确观察下载驱动收到 `FetchPending`，核对两端审批绑定的内容及各自本地群 ID，验证两次决定前收件目录均为空；批准下载后按接收方选择的文件名发布，两块内容逐字节匹配。待决请求绑定原连接、设备、群和成员授权版本；线上包按 MLS epoch 检查。

`asl-app` 库的 `transfer::`、`downloads::runtime` 和 `group_file_crosses_core_processes_with_two_approvals` 合并定向测试 21 项通过、0 失败，15.64 秒；该包库与测试的严格 Clippy 通过。未重跑上一轮群消息测试、全工作区或真实 AppContainer 文件用例。此次未增加 GUI、MCP 或远程文件选择入口；也未验证公网或多来源并发下载。

### 2026-11-22 T32 跨容器群文件验收

用户在本机管理员 PowerShell 运行 `scripts/run-appcontainer-loopback-test.ps1 -Scenario File`。两个 Core 各自启动真实 AppContainer Net 并通过 TCP 回环连接。定向用例 `group_file_crosses_sandboxed_net_processes_with_two_approvals` 报告 **1 passed，0 failed，0 ignored，252 filtered out，21.20 秒**。这是测试耗时，不是文件传输速度。

仅授权给该群的文件通过两个分块传输。下载端观察到 `FetchPending`；上传批准前无下载审批，上传批准后仍须单独批准下载。两次决定前的收件目录检查均为空。完成后读取本机指定的目标文件，全部字节与源文件一致。

本次使用一个来源、合成链证明和本机审批接口，不经过 GUI；未验证跨机、公网中继、多来源并发或中断续传。未重跑全工作区。Cargo 的 `proc-macro-error2 v2.0.1` 未来兼容性警告不影响此次结果。

### 2026-11-22 T23 群下载恢复

Windows x64、Rust 1.100.0，`--locked --offline`。`asl-app --lib downloads::` 27 项、`asl-store --test transfer_resume` 26 项，合计 53 项通过；两包全目标严格 Clippy 通过。群恢复使用真实下载线程、NTFS 和 SQLite，网络准入与回复由夹具提供。

两块同时在途，第一块持久化后关闭工作线程。重开后只接受原来源，Fetch 仍携带原群 ID 和成员版本；新租约只请求第二块，最终逐字节核对通过。若停机期间群已换成员版本，即便群仍活动、来源仍在群中，旧任务也不会发 Fetch、发 Bulk 或发布文件。

补测最后一块已持久化、尚未发布时的恢复：旧群任务释放预留，另一份有效文件照常发布。清理只针对仍有本机收件授权且身份匹配的暂存文件；收件授权也已撤销时不删除它。未重跑全工作区或管理员 AppContainer 验收，不覆盖突然断电、多来源并发或公网续传。

### 2026-11-22 T22 双来源群文件

三个独立 Core 在本机通过群身份准入、生产 Net 驱动、管道 IPC 和真实 TCP 建立三成员房间。两名成员从各自独立的授权目录导入相同内容。接收方确认的来源集合恰为这两个设备，批准前收件目录为空；批准后收到 3 个 1 MiB 分块和一个 4 字节尾块。SQLite 中四个 durable 块的序号和来源均经核对，两个设备都贡献了数据，最终文件与原件逐字节一致。

为了确定下载线程并行持有不同设备的分块任务，测试夹具在交给磁盘线程前短暂保留第一来源的真实响应，直到另一设备返回不同块。没有模拟 TCP 响应，不据此推断带宽提升或数据包在物理链路上同时传输。

Windows x64、Rust 1.100.0，`--locked --offline`：群进程定向测试（跳过消息场景）3 项通过、2 项标记忽略，合计 32.05 秒；包括双来源下载、单来源双端审批和测试输出读取。随后 `asl-app` 全目标严格 Clippy、变更包格式检查通过。新增管理员 `-Scenario MultiSource` 入口仅做环境检查，未运行对应容器用例。链证明为夹具数据；未做跨机、公网、中继或来源掉线期间的多节点续传。

### 2026-11-22 T30 本机 MCP 选择多个下载来源

`asl_fetch` 接受同一查询中最多四个不同设备的 Offer，提交一个下载。选择测试覆盖内容或大小不符、过期 Offer、重复设备、无效句柄，以及提交后拒绝增减或替换来源；同一集合换序重试返回原传输。未修改 P2P 协议或数据库 schema。

双源用例从 MCP JSON 和本机加密管道发起查询。两个提供方各有独立的授权目录，通过真实 TCP 回环返回同一文件的不同分块。测试核对收件方只有一个审批项，且准确列出两台设备；批准前没有请求数据块，收件目录为空。收件后核对 SQLite 完成状态、来源覆盖和 NTFS 文件的全部字节。单源用例仍使用不带附加列表的旧调用。

Windows x64、Rust 1.100.0，`--locked --offline`：`asl-app --lib mcp` 14 项及 `asl-app --test mcp_contract` 3 项通过，`asl-app` 全目标严格 Clippy 通过。真实 stdio 子进程至 Core 是独立契约测试；双源文件用例使用进程内 Net 驱动和链身份夹具。未验证四台实际设备同时传输、跨机、三 AppContainer、公网或真实链。未重跑全工作区。

### 2026-11-22 T22 已批准的另一来源接替掉线设备

收件端通过本机 MCP 选择两个 Offer，批准一个双来源下载。第一个实际收到 Chunk 请求的提供方记录块号，随即关闭 TCP，不发送这个块。收件端观察到连接断开，原传输继续使用另一台已批准设备；按原传输 ID 和中断块号查询 SQLite，得到 `durable` 且来源正是幸存设备。最终 NTFS 文件与原件逐字节一致，未留下 `.part` 文件。

Windows x64，Rust 1.100.0：`asl-app --lib downloads::runtime::loopback` 的单源、正常双源、双源掉线三项通过（4.19 秒）；该包库与测试目标严格 Clippy 和格式检查通过。此轮只改测试夹具，未改调度器或授权规则。链身份使用夹具，TCP 是同机回环；未模拟接收端重启、所有来源同时离线、群组成员变更或公网链路。

### 2026-11-22 T34 群来信浏览期限

SQLite v21 迁移仅为原本可见的群来信回填浏览期限。实库测试覆盖缩短期限立即隐藏旧记录、延长不恢复或延长已有记录，以及设置为 0 后重启仍不保存新的浏览记录；同时核对 MLS 密文和原事件期限未改变。实际 `asl-core` 命令验证直连与群期限独立，并保留群浏览和自动回答开关。

Windows x64、Rust 1.100.0、`--locked --offline`：`asl-store` 全目标 158 项通过，1 个子进程入口按标记忽略；`asl-app` 的设置命令与桌面目标 4 项通过；三 Core 同机 IPC/TCP 群消息用例 1 项通过。两包含 `desktop-ui` 全目标严格 Clippy 通过。未操作原生 GUI 窗口、复跑管理员 AppContainer 或公网场景。

### 2026-11-22 T34 仅中继设置与预约报告

实际 `asl-core` 命令测试覆盖无中继时拒绝开启、保存限制后禁用直连监听、配置丢失时有效设置生成失败、清除限制后恢复原策略，以及不修改配置文件。Supervisor 投影测试使用 Net 事件夹具，确认预约成功去重、失效扣减，以及已保存的设置不覆盖当前报告。

Windows x64、Rust 1.100.0、`--locked --offline`：`asl-app` 的网络定向测试 20 项、CLI 和桌面目标 3 项、`asl-net --test relay_client` 4 项通过。中继测试使用同机 TCP，覆盖预约、认证电路、分块、重启恢复和备用中继。`asl-app` 与 `asl-store` 含桌面目标的全目标严格 Clippy 通过。未贯通原生窗口、实际 AppContainer 中继或公网链路；状态是最后一次报告，不是在线探测。

### 2026-11-22 T34 对等网络暂停与恢复

Supervisor 用真实 Net 驱动、进程内管道和同机 TCP 验证：保存暂停后启动不创建 Net；暂停使原 TCP 地址不可连接；恢复按同一设备及原回环地址策略重新监听；注入启动失败后保持停止，不自动重试。CLI 使用真实子进程与 SQLite，验证开关请求独立于后台报告、不修改地址配置。查询夹具验证已开始和等待中的查询返回离线。复核发现共享事件队列满时旧任务可能延迟到恢复后，修正为按网络会话识别旧任务；新增背压用例确认不会重放。

Windows x64、Rust 1.100.0、`--locked --offline`：`asl-app` 库测试 259 项通过、4 项忽略、1 项已知的沙箱 Worker 用例跳过；CLI 集成测试 1 项通过。首次集中运行中旧双源掉线夹具的 Bulk 错误与 Core 行为不一致，修正夹具后该用例通过。`asl-app` 与 `asl-store` 含 `desktop-ui` 的全目标严格 Clippy 及格式检查通过。未在真实 AppContainer 中运行本次暂停/恢复，也未验收活跃的中继电路、跨机公网或实际窗口操作。

### 2026-11-22 T34 模型端点授权与撤销

实际 `asl-core --providers` 命令写入本机 SQLite。同一网关实例、同机模拟 HTTP 覆盖默认拒绝、显式批准后收到预期模型及输入、审批前界面快照指纹失效、同 ID 换模型/地址/模式不继承批准、配置更换期间撤销后旧配置也不能调用，以及空 permit 和过期 permit 拒绝。另在请求准备期间改变授权，确认客户端未连出；Windows DPAPI 测试验证同 ID 换地址不能读取旧凭据。

Windows x64、Rust 1.100.0、E 盘缓存、`--locked --offline`：网关集成 10 项、真实 CLI 端到端 1 项、DPAPI 1 项通过。`asl-agent`、`asl-store`、`asl-app` 含 `desktop-ui` 全目标严格 Clippy、格式检查和差异检查通过。未运行云端或真实模型、原生窗口操作或全工作区测试。撤销阻止尚未通过发送前授权检查的调用，不取消已交给 HTTP 客户端的请求。

### 2026-11-22 T34 本机检查点更新

真实 `asl-core` CLI 子进程覆盖未配置状态、拒绝过时的审批上下文和非递增 slot、保存和取消候选，验证不改写配置文件。启动逻辑测试用合成的已验证执行状态以及真实 SQLite 与 DPAPI，覆盖过期快照更新、重启恢复、旧证明清空、原有身份观察保留、RPC 配置变化后不访问服务、验证失败不改链状态且不自动重试。NTFS 锁测试核对 Core 和下载工作者的独占句柄相互独立；Supervisor 同机 TCP 测试确认重复启动在网络进程启动前拒绝。

Windows x64、Rust 1.100.0、E 盘缓存、`--locked --offline`：定向检查点 28 项、CLI 1 项、独占句柄 1 项、Supervisor 1 项均通过。`asl-app`、`asl-store`、`asl-policy` 含桌面目标的全目标严格 Clippy、格式和差异检查通过。历史 Mainnet 夹具单独覆盖既有公开链共识验证；未验收真实 RPC 端到端续期、原生窗口操作或跨设备迁移。

### 2026-11-22 T34 资料本机签名授权

使用真实 SQLite 和 `asl-core --profile` 子进程核对默认关闭、当前身份核对、主题选择和撤销；只读 Dashboard 与持久游标测试覆盖重启后保留选项、不同 AgentId 不继承、资料序号与设备目录独立。CoreAdmission 使用合成链证据签发 CBOR，独立核对根签名和 30 分钟有效期；撤销并重新批准相同主题后旧候选仍不能写回。

Windows x64、Rust 1.100.0、E 盘缓存、`--locked --offline`：`asl-app` profile 57 项、真实 CLI 1 项、`asl-store` 定向 1 项通过；`asl-app` 和 `asl-store` 含桌面目标的全目标严格 Clippy 通过。未运行原生窗口、真实链 RPC 或 DHT 出站；没有新增网络发布能力、协议字段或依赖。

### 2026-11-22 T34 主题资料 DHT 出站

两个同机 libp2p TCP transport 通过已按策略建立的连接验证：查找阶段无资料候选、取消后旧操作无法提交、批准的 PUT 到达对端待验证入口、DHT 应答可以在对端不落库时成立、发送端不留自动续发副本。夹具传送结构合法的合成签名封装，不代表接收端已完成真实链身份验证。SQLite 和 Core 的定向测试覆盖仅本机授权不公开、暂停和授权版本更替拦截入队、查找应答不算发布、旧应答不写入新批准。

Windows x64、Rust 1.100.0、`--locked --offline`：同机 TCP 1 项、SQLite 2 项、IPC 21 项、Core 状态 1 项、真实 CLI 1 项通过。`asl-net`、`asl-store` 和 `asl-app` 含桌面目标的全目标严格 Clippy 通过。未在真实 AppContainer、公网、真实链 RPC 或原生桌面执行端到端发布，未接通远端资料浏览或头像。

### 2026-11-22 结构化来信与宿主收件

- `expression_hosts_exchange_a_definition_across_core_processes`：两个独立 Core、两套身份和 SQLite、两个 MCP 客户端，通过各自的加密本机管道和真实回环 TCP 完成 `meaning` → `meaning_is`。两个空闲接收方都由资源更新通知唤起；接收者读到原表达式，回复有独立消息 ID 并保留原任务 ID。联系人授权前，已连接和离线的非联系人均返回 `policy_denied`；授权后，只浏览可以收信，仍不能回复。改为允许回答才可发信。
- 同一进程夹具从接收目录未授权的宿主发起检索：另一端实际导入本地授权的 `.rs` 文件并返回 Offer。宿主被主动通知；`asl_fetch` 只创建本机目录权限提醒，没有创建下载任务、目录授权或待审批传输。另有被动 Offer 的邮箱边界用例；三项真实回环 TCP 下载分别覆盖单源、双源和断源替补，核对审批通知、批准前目标为空、完成通知和最终字节。
- Windows x64、Rust 1.100.0、`--locked --offline`：`asl-app --lib` 定向 20 项通过（MCP、双 Core、旧 minor 准入、三成员 MLS 和 TCP 下载）；`asl-store --lib` 定向 3 项通过（权限提醒合并/到期不授予权限、群活动保留、v22 → v23 迁移）。
- `asl-ui` 5 项与 `mcp_contract` 3 项通过，共 31 项定向测试。6 个相关 crate（`asl-types`、`asl-net`、`asl-agent`、`asl-groups`、`asl-store`、`asl-app`）全目标严格 Clippy、工作区格式和差异空白检查通过。Clippy 仍报告既有第三方 `proc-macro-error2` 的未来兼容性提示。
- 双 Core 用例使用合成链证明，Net 驱动器经帧化 IPC 运行在各 Core 的专用线程；不是跨机器、生产链、真实模型或 AppContainer 新协议互通验收。通知需要运行中的已订阅宿主，不承诺离线补投；入队不是送达，结构化定义也不等于对方已理解或接受。此轮不处理 DHT 公开资料撤权竞态。

追加验收：在上述双 Core 用例中，宿主没有预设收件目录。选择 Offer 后只出现本地申请，没有下载任务。运行中绑定目录后，原会话收到 `inbox_permission: granted`，重用同一个 Offer 得到逐文件审批。审批前目标目录为空；批准后收到 `file_received`，落盘的 17 字节与发送方原文件完全一致。发送方未预填接收设备，登记来自当前已验证连接。两端均未重启。

### 2026-11-22 资料撤权与在途发布

SQLite 定向用例在交接后撤销并重新批准另一组选题，重开数据库后仍不可提交；错误的完成 ID 不会激活新授权。Core 状态机测试在取消期间投递旧 PUT 的成功应答和无关回执，均不会结束等待。Net 驱动测试通过帧编码读回独立取消回执，并确认原操作不能再次提交。三项测试分别覆盖不同边界，不等同于真实 AppContainer 故障注入、公网 DHT 传播或对远端副本的删除。此次修改涉及私有 Core/Net IPC，需配套升级两个二进制文件。

### 2026-11-22 本机授权、资料 GET 与群邀请

- 两个 libp2p transport 经 TCP 实际执行 PUT、GET。GET 返回与发送字节相同的候选，拒绝后查询方没有本机副本。此夹具用合成签名，只验证传输，不证明生产链验签或公网发现。流式 IPC round-trip 包含两 ID 的取消帧及按 AgentId 查找帧。
- SQLite 覆盖缓存命中不发 GET、重复请求合并、暂停、超时、链撤销及过期后不再显示命中；联系人覆盖审核设备/绑定时间、独立撤权、重复操作不增加策略版本。两个 Core 的结构化来信与收件夹具通过正式绑定和显式联系人授权接口，不再手写联系人授权表。
- `local_access_cli_indexes_only_an_active_grants_selected_files` 运行真实 `asl-core`：授权本身不导入文件，选中的嵌套 `.rs` 成为唯一索引项，扩展名不符及目录越界不导入，撤销后数量归零且不能继续导入。本机头像的独立 Windows AppContainer 定向用例覆盖清洗、替换、清除与失败保留原头像；没有将头像上传。
- `group_file_crosses_core_processes_with_two_approvals` 在回环 TCP 上由第二个本机数据库连接提交邀请决定，Core 领取、核对并发送加入请求，随后房间进入预期 epoch，文件传输仍须原来的审批。Store 定向用例覆盖批准与重试不能互换、同一请求不能二次领取、错误设备不生效。没有重跑提权 AppContainer 群场景、真实桌面窗口、公网或跨机迁移。
- Windows x64、Rust 1.100.0、锁定依赖离线编译：桌面启动确认 3 项及资料命令行（含拒查本机 AgentId）通过。`asl-policy`、`asl-store`、`asl-net`、`asl-app` 含桌面功能的全目标严格 Clippy 通过；未运行全工作区测试。

### 2026-11-22 本机群管理与远端头像引用

- 回环 TCP、合成链证明、独立 Core：双 Core 从本机操作队列创建 MLS 房间，选择已验证设备邀请；批准前两边均无新增成员，批准后成员名单一致，文件仍走原有收发审批。三 Core 场景通过同一入口移出成员，创建者不能自移；被移出设备连接尚在，后续消息只交给剩余成员。不是公网或新一轮提权 AppContainer 验收。
- 发送端 Core、Store 及上述两个进程场景共 4 项通过。覆盖目标身份、连接或群版本变化时拒绝操作，选项不能跨本机身份、跨设备、跨期限或重复使用。桌面表单 4 项及 CLI 参数 1 项通过，包含选择失效、离线设备移除、排除已有成员和 PeerId 校验；未操作真实桌面窗口。
- 远端资料与数据库升级定向测试 9 项通过，包括 v23 → v24 不补填头像、仅有头像引用的有效资料、新序号替换或撤回、较早序号不能恢复，以及既有群历史升级用例。不验证头像图片下载、对外公开或跨机器传播。
- Windows x64、Rust 1.100.0、锁定依赖离线运行。`asl-app`、`asl-store` 含 `desktop-ui` 的全目标严格 Clippy 通过；未跑工作区全量测试。

### 2026-11-22 本机头像引用授权与撤回

- Windows x64、Rust 1.100.0，锁定依赖离线。38 项定向测试通过：SQLite 头像及旧版本升级 7 项、索引保留 7 项、资料授权状态 6 项、Core/Extractor/传输权限和签名 12 项、CLI/桌面逻辑/真实本机 CLI 3 项、TCP 回环资料传输 3 项。`asl-types`、`asl-policy`、`asl-store`、`asl-net`、`asl-app`（含 `desktop-ui`）全目标严格 Clippy 通过；未跑全工作区测试。
- 真实 CLI 调用隔离 Extractor 选图并生成预览，再用本机保护身份批准或撤回。旧 token 在换图或撤回后不能批准，旧库保留私有预览但不补授权。GUI 逻辑只提交当前纹理匹配的 token；此次未人工验收原生窗口。
- 同一身份的主题公开与头像批准顺序无关。仅本机签名、另一身份、缺少单独批准均无头像。通过真实身份根签名、独立 resolver 和合成链证明验证了先附上内容 ID、撤回后签发较新无头像的记录，以及旧记录不能恢复。单独的并发连接/回执测试覆盖在途发布、错误操作 ID、撤回、待变更主题和整体资料撤销。
- 两个实际 libp2p TCP 回环节点 PUT/GET 签名记录，收到的候选与发送字节一致；该传输夹具使用合成签名，不能替代上一项验签证据。已准入请求方知道真实头像内容 ID，仍无法通过普通 Fetch 或未获许可的 Bulk Manifest/Chunk/Inline 获得图片。没有对外开放头像文件读取，没有测试公网 DHT、跨机器传输或 AppContainer 网络。

### 2026-11-22 T34 明确索取远端头像

- Windows x64、Rust 1.100.0，锁定依赖离线。按不重复用例计：Store 12 项、App 库 15 项、Core CLI 2 项、桌面逻辑 4 项，另显式执行跨进程回环 1 项。`asl-policy`、`asl-store`、`asl-app`（含 `desktop-ui`）全目标严格 Clippy 通过。
- `explicit_avatar_crosses_core_processes_and_an_isolated_extractor` 使用两个独立 Core、进程内 Net 协议夹具、真实 TCP 回环和隔离 Extractor。接收端从已验签资料的投影入口开始；发送端另行授权一个普通图片文件并启用上传询问。查看资料没有排入请求；发起索取后，发送方看到正确的接收身份和内容 ID。批准前无缓存，批准后经清单、单块传输和隔离解码，把 256×192 图片变成 128×96，只存清洗结果。这个场景不验证公网、DHT 收录、私有头像专用上传或沙箱 Net。
- Store/接收逻辑覆盖 v25 → v26 不自动下载、并发取消与入队的先后顺序、暂停后不复活旧请求、错来源或错误回执通道、等待时间和重试上限、头像替换与资料版本变化、空或超限文件、清单与块散列不符。GUI/CLI 测试覆盖精确目标、过期预览与迟到本地读取。本轮未运行全工作区测试或人工界面验收。
### 2026-11-22 UI 语言、托盘与头像观察窗

- 接入 `state/ui-settings-v1.json`，默认中文，首次启动显示中文/English 选择，设置可切换语言、关闭窗口隐藏和提醒音。
- Windows GUI 尝试创建通知区域图标。关闭窗口在托盘可用时隐藏观察窗，双击恢复，右键菜单提供显示和退出。托盘创建失败时 GUI 仍可启动。
- 提醒音按活动、收发审批、入群邀请和本机操作完成的状态标记去重触发，设置关闭后不播放。
- 统一 egui 主题、间距、按钮状态、头像容器和默认像素信使视觉。远端头像仍保持明确选择、下载和本机缓存校验流程。
- 本轮继续把本机头像、远端头像、群组管理、群邀请、操作通知、错误状态和启动设置接入中文/English 本地化。协议字段名、AgentId、PeerId、内容 ID 和结构化消息内容保持原样。
- 定向验证范围：

  ```text
  cargo +1.100.0 fmt --all -- --check
  cargo +1.100.0 check -p asl-app --bin asl-ui --features desktop-ui --locked --offline
  cargo +1.100.0 clippy -p asl-app --bin asl-ui --features desktop-ui --locked --offline -- -D warnings
  cargo +1.100.0 clippy -p asl-policy --all-targets --locked --offline -- -D warnings
  cargo +1.100.0 test -p asl-app --bin asl-ui --features desktop-ui --locked --offline
  git diff --check
  ```

- 上述 GUI 单测为 15 项通过。尚未进行真实窗口截图、DPI 矩阵、托盘交互手测或完整工作区验收。

### 2026-11-23 UI 本地化收口

- 继续覆盖传输审批、联系人绑定、共享目录、收件目录、派生经验目录、启动设置和界面设置错误状态。English 模式下这些页面的操作标签、空状态、授权提示和失败提示不再依赖中文固定文案。
- 保留 Agent 间结构化通信约束，协议字段名、身份标识、PeerId、内容 ID 和模型状态码不因界面语言切换而改变。
- 本轮验证：

  ```text
  cargo +1.100.0 fmt --all -- --check
  cargo +1.100.0 check -p asl-app --bin asl-ui --features desktop-ui --locked --offline
  cargo +1.100.0 clippy -p asl-app --bin asl-ui --features desktop-ui --locked --offline -- -D warnings
  cargo +1.100.0 test -p asl-app --bin asl-ui --features desktop-ui --locked --offline
  cargo +1.100.0 clippy -p asl-policy --all-targets --locked --offline -- -D warnings
  git diff --check
  ```

- UI 单测 15 项通过。未进行真实窗口截图、DPI 矩阵、托盘人工交互和完整工作区验收。

### 2026-11-23 T35 活动与失败分片清理、诊断导出

- Windows x64、Rust 1.100.0、E 盘缓存。离线定向测试共 32 项通过。`diagnostics` 1 项，`activity_retention` 1 项，`conversation_lifecycle` 3 项，`transfer_resume` 27 项。`asl-app` 与 `asl-store` 的库、`asl-core` 和相关测试目标的严格 Clippy 通过。
- SQLite 回归覆盖到期边界、重复清理、保留活跃任务的去重记录和待发引用、保留 MLS 密文。NTFS 回归覆盖失败分片恰好三天回收、新近失败分片和活跃分片保留、同名替换文件保留。
- 诊断测试启动真实 `asl-core` 子进程，核对版本化内容、受保护目录拒绝和无覆盖写入。报告在特定测试目录生成。完整工作区、原生窗口、长时间定时运行和身份迁移仍待验收。

### 2026-11-23 T35 收件期限与本机身份迁移

- `transfer_resume` 28 项通过；收件期限测试覆盖默认关闭、只登记新收件、缩短期限、延长不追溯、关闭后不重新纳入旧文件、保留改动过的内容，以及成功回收后释放额度。SQLite v27 的 Store 单测 112 项通过。App 库同轮完成 279 项，5 项按既有标记忽略；之后没有重跑全库。
- `identity_migration` 与 `diagnostics` 各 1 项通过；相关库、`asl-core` 和定向测试目标严格 Clippy 通过。迁移测试使用真实 age 加密、Windows DPAPI 与 SQLite，覆盖口令错误、新目录限制、保留 AgentId、生成新 PeerId、选定联系人（含撤销）、本地信任记录及未到期直连观察。未执行链注册、证书签发、不同设备/账户互迁或 MLS 重新入组。

### 2026-11-23 T36 便携开发包与更新验证

- PowerShell 7 在 Windows 本机生成开发版便携 ZIP。打开归档核对 15 项条目；清单列出的 14 项 SHA-256 全部相符。ZIP 包含 5 个桌面运行二进制、启动/登录脚本、许可证、CycloneDX 运行依赖清单及三个锁定 MPL 组件的原始 `.crate` 源码。
- `cargo deny --offline check licenses` 通过（仍有数据集中未使用的许可规则提示）；Ed25519 更新验证单测通过，涵盖修改签名清单、替换公钥、包长度变化以及同版本/回滚拒绝。使用测试签名，不代表正式发行；未执行安装、失败回滚、真实登录启动、SBOM 外部校验或原生 UI 视觉验收。

### 2026-11-23 T36 连续签名更新与便携启动

- Windows x64、Rust 1.100.0、E 盘缓存，锁定依赖离线。更新验签单测 1 项、`windows_update` 显式集成测试 1 项通过，`asl-app` 库、Core 及测试目标严格 Clippy 通过。集成测试使用 PowerShell 7、真实根 Core 验签、只实现 `--version` 的候选夹具。覆盖固定公钥不可覆盖、坏签名、版本不符、额外 ZIP 成员、激活指针被占用时保留旧指向且不遗留候选目录、现用 Core 已缺失时仍能应用更高版本、拒绝同版本与降级，以及指针丢失时拒绝重新应用。独立测试资料文件未被修改。
- 独立静态复核指出原先的缺失指针回退、候选兼任验签、共享写权限和引导层兼容问题。新版显式分发初装指针，固定初装 Core 验签，以稳定的 `MPL-SOURCES.zip` 容纳依赖换版；双语安装说明区分常规更新与全包引导层更换。工作目录继承了较宽的 NTFS 权限；本机开发验证不等同于部署 ACL 审核。
- 重打调试 ZIP，核对 16 个包内文件及 15 项 SHA-256，确认含 7 个 MPL 源码归档。从含空格的解压路径用 `Start-ASL.ps1 -Background` 启动真实 Core 与 Net，并创建独立临时 SQLite 资料库。未修改真实登录启动项、启动 GUI、部署正式签名密钥或网络镜像。
- 这轮证明启用前故障不切换版本；未证明新版本打开原资料库后的故障回滚，也没有跨账户安装权限、正式发行、公网或异机迁移验收。

### 2026-11-23 工作区串行基线

- `cargo +1.100.0 test --workspace --all-targets --features asl-app/desktop-ui --locked --offline -- --test-threads=1`：本次编译产物累计 845 项通过、0 项失败、11 项忽略、7 项在对应测试进程中过滤。单独显式运行的 Windows 更新集成测试不计入 845 项。
- Funplay 同期更新了 GUI 素材和调用代码。该结果对应工作区测试开始时编译的快照，不覆盖编译后写入的 UI 变更，不能当作新 UI 或原生视觉验收。
- 之后从同期 GUI 快照重新生成开发 ZIP，核对 16 个包内文件及 15 项 SHA-256。该快照可打包，但全工作区严格 Clippy 未通过：UI 的 `tokens.rs` 有两处常量断言告警，`views.rs` 有一处测试模块后定义函数告警。Core 和更新测试目标的定向严格 Clippy 通过；本轮没有把两次快照的结果合写为全绿。

### 2026-11-23 Opus 美术与稳定 Agent 入口

- Windows x64、Rust 1.100.0、锁定依赖离线。桌面测试 17 项、头像 CLI 2 项、真实 MCP 契约 3 项通过；`asl-app` 与 `asl-policy` 含桌面功能的全目标严格 Clippy 通过。头像测试覆盖内置预设尺寸、私有默认值、切换后旧批准失效、非法预设编号不覆盖选择。
- 显式执行 `windows_update` 1 项通过。两次各自签名的更新由相同根 `asl.exe` 启动对应版本的候选夹具，原 `mcp --home` 参数不变；缺失激活指针时拒绝启动。候选使用测试夹具，不代表真实跨版本 Core/MCP 的业务互操作。
- 便携 ZIP 布局 v2 核对 18 个文件与 17 项散列。从含空格的解压目录运行真实 `asl.exe`，未启动 GUI 或配置授权也能完成 MCP `initialize`／`tools/list`，没有创建资料目录。未跑全工作区、未手测 Windows 托盘和 DPI，也未验证断线后任务续查。

### 2026-11-23 T36a 查询状态恢复与宿主兼容

- Windows x64、Rust 1.100.0、锁定依赖离线。`mcp_contract` 4 项、`asl-app` MCP 库定向 15 项、`asl-policy` 的 `local_ipc` 5 项通过；`asl-app`、`asl-policy`、`asl-store` 全目标严格 Clippy 通过。
- 真实 Core 和 stdio 宿主覆盖普通订阅与恢复宿主并行、Core 重启后通过任务号和游标续查、普通密钥拒绝、密钥轮换隔离，以及恢复宿主无下载权限。旧 Core 行为夹具覆盖功能探测拒绝后重新连接，已开始的旧版任务不因再次列工具或调用不支持的扩展而断开。
- Store 库 113 项通过；随后再次跑恢复日志用例，验证实际 SQLite 重开、未完成状态中断、分页和到期后时钟回拨不复活。静态复核发现的问题按本机管道隔离、向下兼容和到期处理分别修正；不把复核视为完整安全审计。
- 恢复读取不重发；原查询可能已排队或已发送。未实现正文恢复、推送回放、跨断线传输、用户主动重试幂等，也未验收真实跨版本节点互通或全工作区。

### 2026-11-23 T36a 恢复查询提交去重

- Windows x64、Rust 1.100.0、锁定依赖离线。`mcp_contract` 4 项、`asl-app` MCP 库定向 15 项、`asl-store` 库 115 项通过；`asl-app` 和 `asl-store` 全目标严格 Clippy 通过。
- 真实 Core 与 stdio 宿主验证同 ID 同参数在同会话和 Core 重启后返回原任务 ID，日志仅一条排队记录；同 ID 改参数、到期及普通密钥请求均被拒绝。旧工具列表与禁止恢复宿主下载的回归仍通过。
- SQLite 文件夹具验证 v28 旧任务升级到 v29 后保留原状态、不生成请求 ID；续查不占用新槽，清理后时钟回拨不能让原提交再次生效。预留成功不代表网络送达；未测试公网传输、真实跨版本节点或全工作区。

### 2026-11-23 T36a 结构化答复补读

- Windows x64、Rust 1.100.0、锁定依赖离线。MCP 库定向 16 项、`mcp_contract` 4 项、Store 库 115 项通过；`asl-app` 和 `asl-store` 含桌面的全目标严格 Clippy 通过。
- 注入已关联到查询的非空结构化答复，验证运行中保存部分结果、终态与结果跨 SQLite 重开保留；关闭单独的留存开关并重开后，任务状态仍可查，再开启不会恢复旧快照。真实 Core 与 stdio 覆盖工具发现、普通宿主拒绝及重启后读取已记录的空答复快照。未做远端非空答复跨机验收。
- Windows 调试 ZIP 核对 18 个文件和 17 项散列。未运行全工作区、公网测试、推送回放或断线续传验收。

### 2026-11-23 T36a 显式直连续传

- Windows x64、Rust 1.100.0、锁定依赖离线：下载工作线程 10 项、Core CLI 11 项、真实 MCP 契约 4 项、Store 库 115 项、NTFS/SQLite 下载恢复 29 项通过。`asl-app` 和 `asl-store` 含桌面功能的全目标严格 Clippy 通过。
- 真实下载工作线程和 SQLite/NTFS 夹具覆盖重启后读取原传输、拒绝未绑定或错误恢复身份、收件撤权后不主动请求、重新取得来源许可、只发缺块请求、核对最终字节和已完成任务重复请求不传文件。网络事件由夹具提供；MCP 进程测试单独覆盖工具发现、拒绝普通密钥和未知传输，不等同于公网端到端续传。
- 独立静态复核发现到期授权有时钟回拨复活风险；现以受限删除记住首次观察到的到期，NTFS/SQLite 夹具确认过期绑定已删除。未验收跨机公网、跨版本节点、未批准 Offer 回放或群组传输转交。

### 2026-11-23 T36a 显式群组续传

- Windows x64、Rust 1.100.0、锁定依赖离线：下载工作线程 13 项、NTFS/SQLite 下载恢复 29 项、真实 MCP 契约 4 项通过。`asl-app` 和 `asl-store` 含桌面功能的全目标严格 Clippy 通过。
- 工作线程和 NTFS/SQLite 夹具验证群组续接保留原成员版本和原来源，只请求缺失块并使用新许可。群版本变动或来源设备在运行中撤销，即使已经收到 Fetch 回应，也不继续请求分块或发布文件。依据独立静态复核，沿用设备身份表和注册逻辑固定的 PeerId/AgentId 映射，并在处理群组续传响应前重新检查当前来源成员资格及证书。
- 本机 TCP 的双 Core 群文件测试 1 项通过，验证原双端审批仍可用；它不是群组续传的端到端验收。未重跑提权 AppContainer 测试，未验收跨机器公网、跨版本节点或待批准 Offer 回放。

### 2026-11-23 T36a 收件审批状态补读

- Windows x64、Rust 1.100.0、锁定依赖离线：Store 库 115 项、NTFS/SQLite 下载 31 项、Core CLI 11 项、MCP 契约 4 项通过。`asl-app` 与 `asl-store` 含桌面功能的全目标严格 Clippy 通过。
- SQLite 夹具通过下载器产生待审批记录，覆盖未共享、等待、批准、拒绝、过期、收件撤权、群版本改变和恢复身份轮换。真实 Core 与 MCP 使用已存在审批夹具，验证通过本机 CLI 共享后跨 Core 重启读取、普通密钥无权读取，以及撤销共享后不可读。即使已批准，状态查询不创建下载，恢复工具也不能把尚未开始的下载当作断点续传。
- 未验收完整 Offer 或推送回放、跨版本双节点和公网传输；本轮没有修改线上协议。

### 2026-11-23 Windows 工作区收尾验证

- Windows x64、Rust 1.100.0、锁定依赖离线；`cargo test --workspace --all-targets --features asl-app/desktop-ui --locked --offline --no-fail-fast -- --test-threads=1`：859 通过、1 失败、11 忽略。收件审批跨 Core 重启的 MCP 回归通过。
- 失败为 `asl-agent` 的 `model_gateway::authorized_prompt_uses_only_registered_endpoint_and_returns_model_text`，本机模拟服务返回路径出现 `ProviderUnavailable`。前一次遇错停止的运行在同一测试目标中有两条不同用例报相同错误。没有定位根因，不能标记工作区测试全绿。
- 同配置的工作区全目标严格 Clippy、`cargo fmt --all -- --check` 和 `git diff --check` 通过。未执行真实外部模型、公网双节点、72 小时长跑或提权 AppContainer 验收。

### 2026-11-24 桌面启动与美术改动复检

- `asl-ui.exe --home <目录>` 可显式打开已有资料，优先于继承的 `ASL_HOME`；无参数仍兼容原启动器。参数缺失或不完整时不回退到其他资料目录。未读取到资料时不会先弹出无法保存的语言设置。
- Windows x64、Rust 1.100.0；沿用上一轮全工作区串行命令：**865 通过、0 失败、11 忽略**。工作区严格 Clippy、格式和差异检查通过。此前日志中的传输 `PermissionDenied` 和模拟网关 `ProviderUnavailable` 本轮未复现，尚未确认根因。
- 调试便携 ZIP 核对 17 项散列。在含空格的解包路径、不预设 `ASL_HOME` 的环境下通过 `Start-ASL.ps1 -DataDirectory` 启动，确认 SQLite 建在指定临时资料目录；不重启 Core 时可用显式 `--home` 重新打开窗口。渲染器直接截图确认无数据目录时显示指引、没有语言弹窗。新头像与动画帧通过编译内嵌资源的解码检查。
- 未操作用户已有资料，未逐项人工检查新界面与托盘，也未重跑需手动启用的 AppContainer 或公网验收。

### 2026-11-24 Windows 优化版测试候选

- `Start-ASL.ps1 -ViewerOnly` 只打开当前激活版本的界面。Cargo 路径由本机脚本或环境变量指定；独立 checkout 不需要 `E:` 盘。构建发布动作只对 Windows 文件共享冲突限时重试，不覆盖已有输出，不更改签名更新器。
- 本地模型 HTTP 夹具显式将已接受的连接设为阻塞，依旧受既有读超时限制。分段发送请求头／请求体的回归在修改前失败，修改后通过。正式模型网关、网络授权没有变更；真实模型服务未验收。
- `cargo test --workspace --all-targets --features asl-app/desktop-ui --locked --offline --no-fail-fast -- --test-threads=1`：各 Cargo 目标共 **865 通过、0 失败、13 忽略**；另有一个成功的子进程夹具摘要。单独运行并通过 5 项显式测试：便携窗口入口、打包共享冲突、两次签名更新预检与激活、跨 Core 头像隔离解码、30 秒生产补扫计时。
- 全目标严格 Clippy、格式与 Git 差异检查通过。CDDL 语法通过，24 个向量中 19 个接受、5 个拒绝，符合预期。
- Windows x64 优化版测试 ZIP：`ASL-Windows-x64-Test-2026-11-24.zip`。SHA-256：`0cb2e88910947e6850198d686fbcc5db9f714de6386eb7ff7a08be5ef6118881`。解包验证 18 个文件和 17 项散列；用新资料启动后，`-ViewerOnly` 重开界面时 Core 进程号不变。未使用用户旧资料。
- 这是供[单机人工验收](windows-test-checklist.md)的未签名包，不是正式 1.0。真实用户托盘与 DPI、提权容器多来源、真实链注册及撤销、跨机互通和长时间运行仍待验。

### 2026-11-25 计划 11 文档审计

- 本轮按 `docs/11-semantic-v2-scalable-groups-plan.md` 只做文档对齐，未修改代码，未运行 Rust、Cargo、CDDL、Foundry、GUI 或网络测试。此记录不是实现完成，也不是全量验收。
- 当前 SQLite 最新迁移明确为 v34：v33 保存有界语义上下文候选，v34 保存 `.aslc` 与精确 authority/namespace/revision/digest 的资源关联。act、可续期预算、两人 MLS 私聊、加密邮箱、gossip topic 和容量测量只作为 v35+ 设计，不得按已存在表或已实现事务处理。
- ASL/1.1 表达式和 ASL/1.2 语义上下文保持原用途；ASL/1.3 `act-nl` 已接入编解码、MLS 收发、MCP、群/两人会话工具、发送预算和 gossipsub act 路由。冻结边界是外层控制面、DHT、身份记录和 MCP 控制消息无任意文本，唯一自然语言为 MLS 解密后的 `act[5] nl-body`，且始终作为不可信远端数据。
- 已有查询/答复、OpenMLS 小群、邀请/审批、结构化群消息和群文件局部测试证据保留，但它们不等同于两人 MLS 私聊、act 通知/确认、加密邮箱、gossipsub、可伸缩大群或无限制交流。
- 最新工作树包含未提交文档与代码改动；此前 2026-11-24 的 `865 通过、0 失败、13 忽略` 只对应当时快照，不覆盖本轮工作树、v35+ 设计或新增语义上下文/ConfirmContext 接线。不得用历史全绿记录宣称最新工作树全量通过。

### 2026-11-25 ASL/1.3 act 与群工具接线

- 完成 ASL/1.3 `Act` 确定性 CBOR 编解码：外层 map 键 1-10，唯一文本字段为 `act[5] nl-body`（1..32 KiB），总 act 上限 60 KiB；`request` 必须带结构化 action，其他 act 类型不得伪装 action。`GroupApplication` 只能把 act 作为 MLS application plaintext 编解码，不新增外层 `WireFrame`。
- `asl-app` 已接入 act 入站事件：可信控制字段与 `act_cbor_hex` 分开推送，自然语言只放在 `untrusted_remote_data`。已接入 `asl_send_act`、`asl_group_list/create/invite`、`asl_direct_open`；群管理工具只有 `ASL_MCP_GROUPS=admin` 时出现，收件方仍需本机批准邀请。
- 单 MLS 群编译硬上限从 64 调整为 512；这是资源上限，不是跨机大群验收。libp2p gossipsub 网络层、Net IPC 命令/事件、Core 订阅/发布以及 gossip act 的 MLS/房间成员重验路径已接线；尚无跨机多跳群聊收敛验收。
- 实际运行：`asl-types` act 2 项、`asl-groups` 11 项、`asl-net` 35 项（含真实双节点 TCP/Noise gossipsub）、`asl-store mailbox::tests` 6 项、`asl-app` gossip IPC round-trip 1 项、真实 `mcp_contract` 4 项、三 Core 群消息进程测试 1 项和双 Core 群文件双端审批测试 1 项通过；`cargo check -p asl-app --all-targets --locked --offline` 与工作区全目标编译通过；`scripts/validate-cddl.ps1` 语法通过（24 接受、10 拒绝，含独立 act 向量）。
- 群消息进程测试首次运行发现 active room 列表把 TEXT `local_group_id` 当 BLOB 读取；修复为严格 32-hex 解码后重跑通过。`group_file_crosses_core_processes_with_two_approvals` 也通过，验证双 Core 群文件双端审批、分块下载和最终内容。两测试验证 direct 路径，不是 gossipsub 多跳或跨机。
- v35 迁移和 opaque 邮箱/预算仓储已实现并测试；本段是当时快照，远程 DHT 托管、邮箱收发和已知发送者离线补收后来已接线，见本文件末尾的 2026-11-26 Act 自动回复与 DHT 密文邮箱记录。Core/Agent 预算 UI 和送达回执仍未完成。
- 未运行最新工作区全量测试、严格 Clippy、真实两设备建群/邀请/act 互通、群文件回归、提示注入红队、离线邮箱投递、512 人大群或公网/链 RPC。上述功能不得仅凭本轮编译和局部测试标为完整验收。

### 2026-11-26 Agent 文件 Offer MCP 入口与工作区基线

- 新增 `asl_send_file`，仅在本机宿主获得 `ASL_MCP_GROUPS=admin` 且 Core/MLS 会话可用时暴露。参数绑定现有 MLS room、已导入本机快照 content ID、媒体类型和有界 ASL topic；Core 先验证快照与 active room，再发送结构化 `Offer`，不会接受任意路径、文件名、目录或自然语言。接收方仍走现有的成员/epoch、收件目录、传输审批和分块校验。
- `cargo +1.100.0 check -p asl-app --all-targets --locked --offline` 通过；`cargo +1.100.0 clippy -p asl-app --all-targets --locked --offline -- -D warnings` 通过。新增 MCP 参数单测 1 项通过：合法 `document` Offer 可解析，未知媒体类型、非 topic concept 和错误 content ID 被拒绝。
- 本轮变更后完整工作区测试已重跑：`cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1` 退出码 0；按 Cargo 目标汇总 **899 通过、0 失败、13 忽略**。`asl-app` 库 295 项通过、`asl-store` 203 项通过、`asl-net` 62 项通过、`asl-policy` 119 项通过、`asl-types` 76 项通过、`asl-agent` 42 项通过；忽略项均来自显式环境门槛或子进程入口。`scripts/validate-cddl.ps1` 本轮未执行成功，本机当前 PATH 没有 `cddl` 命令；schema exporter 通过并核对 34 个向量（24 接受、10 拒绝）。`asl_send_file` 的 Core→MLS→接收方端到端尚未单独验收，不能把它等同于公网文件传输完成。

### 2026-11-26 群主策略、角色与成员权限

- 新增 ASL/1.3 `group-policy` MLS application plaintext：群创建者是群主，策略包含单调递增 revision、成员文字/文件/邀请权限位、管理员 PeerId 和有期限的禁言设备集合。编码器使用确定性 CBOR；解码器拒绝零 revision、未知权限位、重复/乱序 PeerId、超限列表和非 canonical CBOR。
- SQLite v36 增量迁移新增 `group_access_policies` 与 `group_access_members`，不改 v1–v35。群主策略只能由当前 MLS room creator 的 sender leaf 应用；非群主、revision 回退、非活动成员、禁言群主均被拒绝。入站 act/查询/表达式/文件 Offer、出站 act/Offer/邀请和响应 Offer 均检查当前策略；目录授权、收件目录、设备证书和传输审批仍是独立硬边界。
- MCP 增加 `asl_group_members` 和 owner-only `asl_group_set_access`。GUI 群管理成员列表显示群主/管理员/成员、禁言和文字/文件/邀请权限。本轮未实现群主转移、管理员代管成员的独立策略编辑、跨设备策略同步人工验收或公网群组验收。
- 定向测试：`asl-types` 库 3 项、`asl-groups` 库 12 项、`asl-store` 库 123 项（含 group_access 2 项和 v36 迁移）、MCP stdio 7 项、UI 23 项、schema exporter 35 个向量（25 接受、10 拒绝）通过。修复了旧 v32 升级夹具未清理 v36 表的问题后，单独语义上下文集成测试 1 项通过。
- 最终统一运行：`cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1` 退出码 0；按 Cargo 目标汇总 **904 通过、0 失败、13 忽略**。工作区严格 Clippy、格式、schema exporter 和 `git diff --check` 通过。`scripts/validate-cddl.ps1` 仍因本机 PATH 没有 `cddl` 命令未执行；此前独立 CDDL 结果不代表本轮 35 个向量。

### 2026-11-26 有期限联系人邀请与二维码

- 新增 SQLite v37：`contact_invites` 保存完整签名、token、创建/到期时间、状态和绑定 AgentId；`contact_invite_receipts` 持久化单次消费；`contact_invite_prompts` 投影待确认 Pairing 请求；`contact_invite_actions` 承载 CLI/Core 的 import/decide 动作。v1–v36 迁移保持不改写。
- 新增独立 `ASL-CONTACT-INVITE:1:<base58>` canonical CBOR envelope，签名绑定 inviter、invite/token、时间、单句附言和 24 小时上限；二维码与完整 envelope 使用同一载荷。16 位临时短码采用 `ASL-CONTACT-INVITE-CODE:1:<inviter-AgentId>:<device-PeerId>:<code>`，必须同时绑定邀请人完整 AgentId 和签发设备，不代替长期身份；二维码使用 vendored `qrcodegen 1.8.0`。
- Contacts 页展示完整 AgentId、绑定 AgentId 和签发设备 PeerId 的临时短码、完整邀请和二维码；完整邀请在拨号前先查询本地链控制者并验签，短码路径先按绑定 PeerId 过滤 DHT provider，准入后再命中绑定的 AgentId 才发送 Pairing。导入必须经本机 Pairing 确认。DHT provider 只提供 token 发现，实际建联仍由双方签名 Pairing、设备证书和链身份核验完成。邀请消费不创建 `authorized_contacts`、文件授权或群成员资格。
- 定向验证：`asl-types` 6 项 contact invite、`asl-store` 9 项 contact invite、`asl-app` 1 项邀请类型、CLI 1 项、桌面 UI/二维码 28 项通过；真实临时资料执行 `--initialize-profile`、`--contact-invites create 5 "..."`、`list`、短码 `import` 成功。`cargo +1.100.0 clippy -p asl-app --all-targets --features desktop-ui --locked --offline -- -D warnings`、格式、schema exporter 和 `git diff --check` 通过。
- 安全复核后追加：完整 AgentId 查询使用 `lookup-agent` 在同一动作中保存目标 `AgentId`，公开发现使用 `ASL-AGENT-LOOKUP-v1` 专用 DHT provider 键，Core 只记录精确相等且通过链/设备准入的候选，不再把长号降级成短码后接受其他 Agent；临时短码编码为同时绑定邀请人 AgentId 和签发设备 PeerId 的 `ASL-CONTACT-INVITE-CODE:1:...`。完整 signed envelope 在 DHT 拨号前先查本地链控制者并验签；短码连接在 DHT provider 过滤和发送 Pairing 前都必须命中绑定的 AgentId/PeerId。公开精确发现默认关闭，用户开启后才发布该 provider，不授予联系人/文件权限。重启时无内存连接上下文的 pending prompt 自动关闭，Pairing 回复先进入 Net 再提交本地 receipt，拨号和 outgoing 请求按操作/连接/到期回收；Pairing 邀请 24 小时签名上限与 store 消费上限已统一。`send_network_command(ReplyPairing)` 只确认帧已写入 Net IPC，仍不等同远端实际收到；持久回复 outbox/远端送达确认尚未实现。
- 安全修复后的全工作区回归：首次运行唯一失败为既有 `model_endpoint_settings::cli_approval_controls_an_existing_gateway_without_restarting` 在本机 mock socket 上遇到 `Os { code: 10035, kind: WouldBlock }` 后返回 `ProviderUnavailable`。该 fixture 接受连接后继承 Windows 非阻塞状态，已改为显式 `set_nonblocking(false)`；精确用例随后 0.19 秒通过，并再次执行同命令全工作区测试，退出码 0。邀请修复相关的 `asl-store` 精确 lookup、`asl-app` 邀请类型、Core CLI 绑定/邀请参数测试和桌面目标编译均通过。
- 最终统一运行（含精确 AgentId DHT 键、设备绑定短码、Pairing 上限统一和 endpoint fixture 修复）：`cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1` 退出码 0；本轮 `--list` 枚举 929 项，忽略项仍为显式环境门槛/子进程入口。先前一次失败来自 `agent_setup` 仍断言 schema v36，修正为 v37 后重跑通过。跨两台真实设备、公网 DHT 可达性、二维码被真实摄像头扫描和跨机邀请确认仍未验收。

### 2026-11-26 Act 自动回复与 DHT 密文邮箱

- `asl-agent::act_reply` 只把 `Ask` act 转为严格结构的 `Inform` 或 `Clarify`。远端 `nl_body` 和本地证据 excerpt 都放在 untrusted JSON 数据区；回复解析拒绝 action、tool、path、附件和未知字段，正文上限 8 KiB。`AuthorizedPrompt::data_free` 允许已批准模型端点在没有本地私有证据时调用，带本地证据的路径仍要求 ReadChunk + ModelInput permit。
- `supervisor::auto_reply` 仅在群组开关允许回答时排队，使用注册表顺序中第一个已批准 provider；模型失败不发伪造回复，单会话 5 秒冷却，队列和最近请求均有界。当前应用接线使用 data-free 提示；本地证据选择接口已存在，但尚未把文件候选自动装进该后台回复。
- 新增 `asl-net::mailbox` 8 KiB 二进制记录：recipient/sender/topic/mailbox/shard、epoch、分片、TTL 和 BLAKE3 hash，记录键域分离。DHT store 只接受键与路由字段一致的密文邮箱记录；传输入口支持 put/get，并用真实双节点 TCP/Noise 测试验证 put 完成和 raw get。
- `supervisor::mailbox_wire` 将群 act/Offer 的 MLS 密文写入本地 opaque 槽，按 3 天轮换 epoch 组成最多 16 个 8 KiB 分片批次，发布到 DHT；已知联系人或群成员按最近 3 个 epoch 拉取，重组后仍由 MLS 验证实际成员/epoch。HTTP/relay/NAT 可达性仍来自现有配置化 libp2p 地址策略，不写死地址。
- 定向验证：`asl-net` mailbox lib 10 项、DHT limits 7 项、`asl-agent` 全目标 46 项、`asl-app` IPC round-trip 1 项和 DHT mailbox admission 1 项通过。完整工作区 `cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1` 退出码 0，0 失败、13 项环境/子进程用途忽略。
- `cargo +1.100.0 clippy -p asl-agent -p asl-net -p asl-store -p asl-app --all-targets --locked --offline -- -D warnings`、`cargo +1.100.0 fmt --all -- --check`、schema exporter（35 向量，25 接受、10 拒绝）和 `git diff --check` 通过。未完成真实两设备重启补收、送达回执、NAT/relay 邮箱矩阵、模型本地证据自动选取或公网 DHT 验收；不得把这些定向测试写成公网完成。

### 2026-11-26 本地证据、Act 历史与迁移

- 新增 `supervisor::auto_reply_evidence`：在线群 `Ask` 先经当前群 search snapshot，最多选择 4 个同时具备群作用域 `ReadChunk` 与 `ModelInput` permit 的本地文本，截断 1200 字符送入模型；查询正文不解释为路径、URL、action 或工具。Provider 本地/远端模式从已批准注册表配置传入，LocalOnly 授权不会误判为远端。DHT 邮箱和 gossip 经 MLS 验证后，可用缓存且仍在有效期内的链/设备证据重建同一群 requester，因此离线补收的 `Ask` 也能使用相同证据选择；缓存缺失或过期时回退 data-free。
- `conversation_act_events` 现实际记录收发 Act 的 conversation/act ID、epoch、类型、因果/回复引用、方向和保留时间。本地正文在 Windows 上按当前用户 DPAPI 保护，夜间/重启可读；群「浏览来信」关闭时不记录入站正文，保留期选择 0 会清除 Act 历史。
- 活动页直接显示 Act 的方向、类型和 120 字符预览。身份迁移的 `history` 选择会从未过期 Act 历史解密到 age 加密迁移包，再在目标设备重新 DPAPI 保护；不会复制旧设备密钥、目录授权或 MLS 私钥。
- 邮箱 Offer 的领取不再死绑接收时的连接：若 Offer 来自离线邮箱，用户/Agent 在来源设备后来上线且仍处同一群 epoch 时可以重新解析当前连接再进入既有双端传输审批；Offer 本身仍不是下载授权。
- 群组网络不再由代码强制回环：`NetworkSettingsV1`、Transport 地址策略和 relay 预约现在允许群子流跟随 loopback/LAN/Internet/RelayOnly 配置；默认仍关闭群组网络。这是配置接线，不替代真实双机公网、NAT 打洞或 relay 群消息验收。
- 定向验证：`asl-app` 自动证据 3 项、`asl-store` cached requester 1 项、Act history 2 项、Dashboard Act 预览 1 项、三 Core 群消息 1 项、双 Core 群文件 1 项、桌面会话分组 1 项、身份迁移含 Act 1 项通过。完整工作区测试退出码 0，0 失败、13 项按环境/子进程用途忽略。
- 严格 Clippy（`asl-store`/`asl-app`，含 `desktop-ui`）、格式、schema exporter（35 向量）和 `git diff --check` 通过。未覆盖真实双机迁移包、旧版本包兼容抽样、DPAPI 跨用户、邮箱 Offer 重新上线竞态或 GUI 不同 DPI 的人工检查。

### 2026-11-26 迁移夹具期限修正与最终集中验证

- 完整工作区测试曾只剩 `encrypted_migration_preserves_selected_data_with_a_fresh_device` 失败：测试把 Act 历史和直连查询的 `expires_at_ms` 设为 `now + 60_000`，age/scrypt 导入在负载下接近或超过该窗口，目标端 Dashboard 加载时 Act 已过期。测试夹具改为 7 天保留窗口，生产迁移逻辑未改。
- 精确回归 `cargo +1.100.0 test -p asl-app --test identity_migration --locked --offline -- --nocapture --test-threads=1`：1 项通过，用时 58.71 秒。
- 最终集中验证：`cargo +1.100.0 test --workspace --all-targets --locked --offline --no-fail-fast -- --test-threads=1` 退出码 0，0 失败、13 项环境/子进程用途忽略；`cargo +1.100.0 clippy -p asl-store -p asl-app -p asl-net --all-targets --features desktop-ui --locked --offline -- -D warnings`、`cargo +1.100.0 fmt --all -- --check`、`git diff --check` 和 schema exporter（35 向量：25 接受、10 拒绝）均通过。
- 本轮仍未验收真实双机公网/NAT/relay、真实链 RPC、跨用户 DPAPI、MLS 群密钥跨设备迁移或人工 DPI/窗口检查；不可用上述集中测试替代这些范围。
