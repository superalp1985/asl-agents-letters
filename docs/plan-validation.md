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

## 未执行的验证

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
