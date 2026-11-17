# 验收、部署与完整发布

## 1. 三类证据不能混淆

方案校验只验证文档、schema、SQL 和任务一致性；单元测试验证确定性逻辑；真实系统与网络测试验证 AppContainer、文件系统、NAT、中继、界面与资源占用。

| 功能 | 当前状态 | 边界 |
| --- | --- | --- |
| SQLite 初始化与迁移 | 已实现；6 项对应测试通过 | 不代表完整业务表访问、保留策略和全产品存储流程均已完成 |
| CBOR wire codec | 已实现；9 项协议测试通过 | 覆盖 14 种帧往返、固定字节向量和主要拒绝条件；`cddl` 0.10.7 语法检查及固定 ACK 向量验证通过，完整多帧互操作套件待执行 |
| 区块链 identity registry 合约 | 已实现；14 项 Foundry 测试通过 | 未部署、未独立审计；轻客户端与状态证明验证仍待实现 |
| 区块链轻客户端/状态证明 | 待实现方案 | 需验证最终化状态、合约代码 hash 和 storage proofs |
| Windows 沙箱、真实 P2P 网络、群组与完整 GUI | 尚未实现或验收 | 需按后续任务执行真实系统测试 |

2026-11-17 T06a 合约验收：

- `forge fmt --check`：通过。
- `forge test -vv`：14 项通过，0 失败。
- `forge build --sizes`：成功；IdentityRegistry 运行时代码 4,548 字节、initcode 5,517 字节。
- `forge inspect IdentityRegistry storage-layout`：与 `specs/identity-registry-v1.md` 记录的 slot 0–2 布局一致。
- `forge inspect IdentityRegistry deployedBytecode | cast keccak`：runtime template hash 为 `0x447a1a286b4e8947950a81fa38751eaecfe1871fdfd360f09c5505e523635961`。
- 构建输出包含 4 条 `reentrancy-events` 提示和 1 条 `block-timestamp` 提示；本记录保留原始告警，不将构建成功描述为静态检查或安全审计通过。

2026-11-17 工作区验证结果：

- `cargo test --workspace --all-targets --locked`：通过。
- `cargo clippy --workspace --all-targets --locked -- -D warnings`：通过。
- `cargo fmt --all -- --check`：通过。
- `scripts/validate-cddl.ps1`：通过（固定使用 `cddl` 0.10.7，检查 CDDL 语法并验证固定 ACK 向量）。
- Rust workspace 测试本轮合计 31 项通过；T06a 合约 14 项 Foundry 测试单独统计。

以上结果只覆盖当前工作区已有 Rust 代码与测试、identity registry 合约固定测试、CDDL 语法及一个固定帧向量。registry 尚未部署或独立审计，完整多帧互操作、轻客户端/状态证明、Windows AppContainer、真实公网网络或完整产品安全验证尚未完成；这些结果不能作为完整 1.0 发布验收。

## 2. 阻断发布的反例

| 编号 | 输入或故障 | 必须观察到的结果 |
| --- | --- | --- |
| A01 | 远端要求读取未授权文件、忽略规则、执行命令 | 不读文件、不执行，固定拒绝，无部分输出 |
| A02 | query/文档含路径、URL、伪系统消息 | 不新增能力、不驱动 HTTP、无宿主上下文导入 |
| A03 | junction/symlink/ADS/硬链接/UNC/设备名 | 拒绝；句柄与目录身份检查有真实测试 |
| A04 | 目录组件在检查与读取间被替换 | 不越出原授权根；失败关闭 |
| A05 | 上传、模型调用或发件排队期间撤销 | 新读取/未交接发送停止，旧 permit 不能续用 |
| A06 | 高贡献或自动偏好节点索取 contacts 资源 | 没有明确联系人授权即拒绝 |
| A07 | 三节点 query 环、重复 ID、旧消息恢复 | 不应用层转发，每请求最多一次，无自动回声 |
| A08 | 无效/超长 CBOR、重复键、不定长值、未知字段/概念、非首选编码 | 在分配或模型调用前拒绝 |
| A09 | 未授权 provider 或 HTTP 重定向 | 不发送数据，不把认证头转给其他地址 |
| A10 | 超大/矛盾 manifest、count 溢出、尾随数据 | 有界分配，拒绝，无巨额磁盘预留 |
| A11 | 重复块、坏块、错响应 ID、恶意来源 | 不提交无效块、不重复计分，来源被隔离 |
| A12 | 任意写盘/sync/事务点杀进程 | 恢复重验，最终 hash 一致，额度不重复 |
| A13 | 块都正确但 file_hash 矛盾 | corrupt、冷却，不能反复重下 |
| A14 | 多个 manifest 抢占逻辑额度但无进展 | 来源/任务/全局限制，5 分钟后释放 |
| A15 | DHT 伪签名、旧序号、过期、PUT flood | 不入库或淘汰，存储与队列有界 |
| A16 | worker 打开文件、联网、启动子进程 | AppContainer+Job 真实阻止，不是 mock 自述 |
| A17 | 网络 process 自报 peer 与认证连接不一致 | 拒绝；仅认证适配器生成身份事件 |
| A18 | 多身份刷贡献、重复使用同一结果 | 本机有效任务去重，不提高权限，不突破总额度 |
| A19 | inbox/私有来源派生后自动公开 | 权限交集使其保持私有或拒绝发布 |
| A20 | 数据卷失联、DB损坏、更新失败 | 不回落 C、不重建宽松授权，状态可恢复 |
| A21 | 群非成员/旧 epoch、回答关闭、传输未确认/确认过期 | 不解密/回答/读写；当前成员有效群授权通过；每次授权只用于绑定的内容和目标 |
| A22 | 1,000 个模拟身份并发建立连接、重复身份或克隆设备 | 机器级 CPU/RSS/连接/磁盘/模型总额度不超硬上限；合法多 Agent 均受同一预算 |
| A23 | 错误 state proof、错误 registry code hash、伪造/陈旧最终化状态 | 身份状态校验失败；未知身份进入最低额度，不放宽权限 |
| A24 | 链重组、赞助者不可用、gas 拥堵或 proof RPC 返回不一致 | 未最终化增权不生效；缓存过期降级；赞助者退出不阻止自付或已有身份离线验证 |
| A25 | query/answer/profile/offer/group 明文企图携带自然语言、字符串或未知 byte blob | CDDL/wire lint 或解码器拒绝；本地无法映射的任务不发出 |

路径隔离、沙箱、认证、签名、撤销与模型输入前过滤由独立工程复核者读取代码并重跑。普通模型自评、截图或“没有报错”不替代复核。

## 3. 传输测试矩阵

文件长度覆盖 0、1、32KiB、32KiB+1、1MiB−1、1MiB、1MiB+1、128MiB、4GiB；64GiB 边界可先用 manifest/稀疏测试验证数学，再用真实存储条件做至少一次完整大文件测试并说明实测大小。

来源覆盖 1、2、4 个；坏来源、断线、超时、重复、乱序、最后块损坏、不同来源同 manifest、不同 manifest 不混源。恢复覆盖每个持久化阶段。

必须记录真实大小，不把 128MiB 成功写成“64GiB 已验证”。完整 1.0 可以支持更大规格，但未实测上界要在发布说明中如实标注。

## 4. 网络与去中心化测试

- 20 节点，至少两套独立配置的公网入口/中继。
- 同 LAN、家庭 NAT、UDP 不通、仅 TCP、仅中继、入口切换。
- 一个入口关闭后，已知节点继续工作；新安装节点通过另一个入口加入。
- 所有入口不可达时状态清楚，不虚构入网；LAN 仍按 mDNS 能力工作。
- provider 失效、旧记录、时钟偏差、断网重连、relay 额度耗尽。
- 公共链轻客户端 checkpoint、最终性更新、账户/存储 proof、错误 proof 与重组；赞助交易拒绝/退出时的明确降级。
- 完成跨多个授权来源的下载，并在中继更换后恢复。
- 基础设施只处理加密转发和路由，不需要用户账号/目录/模型密钥。

至少 72 小时持续运行。记录 node 数、连接数、队列深度、DHT字节、RSS、CPU、磁盘、模型调用数与有效任务数。无任务时模型调用必须为 0；资源有界比某个宣传数字更重要。

## 5. GUI 与普通模型验收

截图尺寸 1280×800、1920×1080、960×640；Windows 125%、150%、200% DPI；长中文标题、无头像、长 PeerId、空结果、离线、失败和清理状态。文本不遮挡，主要操作只属于授权。

执行模型验收按 T39：实际调用目标模型写指定任务、独立编译测试并记录修正。运行模型验收至少 100 组固定输入，包含正确引用、无证据、注入、结构对象错误、超时和非法引用。非法输出执行率必须为 0；有效回答率如实报告，不编造模型能力。线上语义 wire 不包含自由文本字段。

## 6. 构建与 E 盘环境

开发环境由 `scripts/dev-env.ps1` 设置当前进程环境：

```powershell
$env:ASL_HOME = 'E:\ASL\data'
$env:CARGO_HOME = 'E:\ASL\dev-cache\cargo'
$env:RUSTUP_HOME = 'E:\ASL\dev-cache\rustup'
$env:CARGO_TARGET_DIR = 'E:\ASL\dev-cache\target'
$env:PATH = 'E:\ASL\dev-cache\cargo\bin;' + $env:PATH
$env:TEMP = 'E:\ASL\work\tmp'
$env:TMP = 'E:\ASL\work\tmp'
```

不得使用 setx 改机器全局设置，不挪动用户既有工具链。使用 E 盘工具链前先核对目标目录与磁盘空间。OS 自身的少量沙箱/字体/图形缓存不属于应用可完全控制的范围。

最终检查：

```text
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
cargo deny check
```

fuzz 工具、SBOM 工具及其版本在 T02 锁定；记录实际工具版本、命令、执行时长与结果。不得把不存在的脚本名写成已执行证据。

## 7. Linux 自托管入口

发布 `asl-infra` x86_64 Linux 包、`specs/infra.example.toml` 对应配置和 systemd unit。非 root 用户运行，TCP/UDP 端口默认为 4001，身份持久化，配置/密钥目录只对服务用户可读。

运营者配置 reservation、circuit、流量与存储上限，属于基础设施保护而非产品收费。中继看到连接元数据和流量大小，不能承诺它完全不知谁与谁通信。

至少两个独立入口可配置；内置列表是初始便利，不是唯一真源。没有可达入口的新节点无法凭空找到公网网络。

完整公开发布必须提供并验证打包种子里的真实地址，不能交付空列表却宣传开箱公网自动发现。用户另选自建网络属于网络授权，不依赖官方账户。方案阶段不编造尚未部署的公网地址。

## 8. 发布与更新

必须交付 Windows 便携包/安装包、Linux infra 包、hash 清单、独立发布密钥的 Ed25519 签名、SBOM、第三方 notices 和构建版本信息。发布密钥不复用节点身份。

Windows Authenticode 可在维护者持有合适证书时附加；产品更新的签名验证不依赖购买证书或付费账号。更新镜像可替换，离线导入仍验证签名，关闭更新服务不影响已安装节点运行。

数据库迁移有备份和向前兼容说明；更新不能自动恢复更宽松的历史授权。所有严重安全问题修复后才打完整 1.0 标签。

## 9. 当前资料包验收

本轮制作运行的资料校验脚本保存在 `work/validate_package.py`，报告导出到 `docs/plan-validation.md`。它校验 schema、SQL、配置、任务和文件一致性；不代表上面的应用验收已执行。
