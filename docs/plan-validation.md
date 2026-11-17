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
