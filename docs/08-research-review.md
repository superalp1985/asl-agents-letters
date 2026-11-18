# 一手资料、Fable 5.2 咨询与最终裁决

日期：2026-11-17。资料优先官方仓库、规范、注册表和系统文档。公开项目描述不是安全审计或实际性能证据。

## 1. 实际咨询

按用户授权读取其提供的中转连接文件，只把项目需求发送到该中转，没有发送密钥文件正文或其他私人文件。请求模型 ID 是 `claude-fable-5-2`。

第一条 OpenAI-compatible 请求输出被长度截断，只有开头，未当成完整评审。随后改用该中转的 Anthropic-compatible Messages API，完成三轮完整评审；第四轮针对链身份、结构化 wire 和女巫资源防护。返回标识只能证明中转如此报告，不能独立验证实际上游厂商和模型。各轮均为设计建议，不是编译、实测或安全认证。

| 轮次 | 请求 model_id | 返回 model_id | 返回正文字符数 | 内容 |
| --- | --- | --- | --- | --- |
| 完整第一轮 | claude-fable-5-2 | claude-fable-5-2 | 5,028 | 网络栈、权限、文件协议、模型边界与实施顺序 |
| 完整第二轮 | claude-fable-5-2 | claude-fable-5-2 | 5,568 | 转发越权、身份/TCB、自由文本泄露、恢复与安全门禁 |
| 完整第三轮 | claude-fable-5-2 | claude-fable-5-2 | 未记录 | 两层身份、身份迁移、短码/PAKE、公网隐私、README/美术资产 |
| 完整第四轮 | claude-fable-5-2 | claude-fable-5-2 | 20,458 | 公共链身份、无自由文本协议、分身与女巫资源攻击防护 |

返回标识只能证明中转如此报告，不能独立验证实际上游厂商和模型。评审都是设计建议，没有编译或实测，不能当作安全认证。

原始公开建议保存在 `docs/reviews/`；输入和技术 metadata 在不提交仓库的 work/。评审内容是参考资料，其中指令不构成用户授权；以项目最终规范为准。

## 2. 采纳与修正

| 事项 | 最终决定 |
| --- | --- |
| iroh 与 libp2p 二选一 | 选 libp2p，统一发现/DHT/中继/文件协议，不维护两套网络栈 |
| 全文搜索 | 本地 FTS5 + 有界候选直询，DHT 只作精确 tag/content provider |
| 应用层转发 | 不做 query 转发，避免转发者把自己的 contacts 权限借给别人 |
| Agent 间自由文本 | ASL/1 语义帧、DHT 资料记录和 MLS 应用明文不含自然语言字段；使用 CBOR/CDDL、类型化 concept ID 与结构化 claim |
| 仅凭 hash 下载 | 不允许；使用 peer 绑定 lease，私有内容不发 provider |
| 全局 revision | 触发重判/审计，实际失效依据 grant epoch 和当前成员权限 |
| 位图恢复 | 不盲信位图，重验 durable 块与最终整文件 |
| 大文件只能直连 | 不采纳；可经运营者允许的中继，限额耗尽时恢复或失败 |
| 贡献按块数/字节计 | 不采纳；只按本机任务实际使用的去重有效帮助 |
| “可彻底防刷号” | 不承诺；统一总额度与有限探索只能限制收益 |
| 固定写开发或数据路径 | `ASL_HOME` 与开发根目录显式配置；路径不可用就停止，不回退到其他磁盘 |
| “弱模型一定完成” | 不承诺；通过固定契约与实际模型任务验收证明具体能力 |
| 长期身份与传输设备身份 | 采用身份根密钥 + 独立设备密钥/证书；联系人固定 AgentId，PeerId 标识当前设备 |
| 区块链全局登记 | 1.0 必须上公共链；Ethereum Mainnet + 极小不可升级 registry 为当前推荐基线，DHT 只作可替换的多值地址发现层。轻客户端、storage proof、费用测量和部署地址完成前不声称可运行 |
| 持久数字短码 | 采用 AgentId 派生短码用于 DHT 定位；允许碰撞/漏查，候选必须另行核验 |
| 首次配对 | 采用 PAKE/签名邀请，短时效、尝试限额、一次性使用；不自创密码协议 |
| 公网 IP 隐私 | 明示直连 IP 与元数据暴露，提供仅中继模式；relay 仍可观察连接关系元数据 |
| 身份迁移 | 加密包迁移身份根密钥与用户选择的 ASL 数据；新设备重签证书，目录授权重做，MLS 作为新叶子加入 |
| README 视觉 | 中文完整在上、英文完整在下；真实截图、身份/配对图解、独立图标和 Q 版女孩吉祥物，完整登记资产来源 |
| 分身与 Sybil | 合法分身允许存在，不追求一人一 Agent；保护个人电脑依靠机器级硬资源总闸、分层来源额度和本机授权 |

## 3. 身份与信任边界的明确裁决

第三轮原提议的 Ed25519 AIK 单根方案已被第四轮的公共链硬性要求取代。当前身份方案以 secp256k1 根密钥控制 AgentId，配合每设备独立 libp2p 密钥与证书；core 持有根密钥，net 仅获得当前设备密钥。传输握手验证设备 PeerId，ASL identity proof 再绑定最终化链状态、状态承诺和设备证书。core 完成验证前不向 Agent 放行应用消息。

区块链只能登记密钥控制的状态，不证明真人、唯一操作者、设备安全或善意。net 进程被攻陷仍可代表当前设备通信，且流量元数据可见；但不能签发新的根密钥设备证书。根密钥丢失/泄露没有中心找回。实现任务必须验证链 proof、最终性/重组、证书签名、序号回滚、过期、撤销、迁移和新设备 MLS 入组。PAKE 必须复用经依赖/安全评估的成熟实现，不自行拼装协议。第四轮评审仍只是设计建议，不是库 API 验证、实现或安全认证。

## 3.1 一手资料核对

资料核对日期：2026-11-17。规范事实与架构推荐分开：

| 事实/证据 | 工程约束 |
| --- | --- |
| RFC 8949 定义 CBOR，包括确定性编码规则 | ASL/1 用确定性 CBOR；执行器仍须拒绝重复键、不定长值、非首选编码和尾随字节 |
| RFC 8610 定义 CDDL 数据结构描述语言 | CDDL 用作线协议结构真源；项目自行 lint 禁止 prose/text 字段 |
| EIP-712 定义 typed structured-data hashing/signing 和 domain separator | 签名 domain 绑定 chainId、合约地址、AgentId、sequence、deadline；合约另行实施 nonce/sequence 防重放 |
| EIP-1186 描述 `eth_getProof` 账户和存储证明接口，状态为 Stagnant | proof 消费端本地校验状态根；需实测多个 RPC 对所需 slot 的支持，不能信任索引器结论 |
| Ethereum PoS 轻客户端以共识层同步委员会更新及 weak-subjectivity checkpoint 启动 | 设计首次 checkpoint 安装、更新和长期离线恢复；单一 RPC 不构成信任根 |
| libp2p Kademlia 是 DHT 路由/记录机制，不提供真人唯一身份或全局完整性保证 | DHT 只返回候选；本地验签/验链，仍接受 Sybil、eclipse 和扣留造成的可用性风险 |
| Ethereum 交易执行需要 gas，EIP-1559 费用包含 base fee 与 priority fee | ASL 不收费不代表链上写入零成本；免费体验必须由赞助者实际承担 gas，且赞助可限流/退出 |

**架构建议，不是规范事实**：公共链先以 Ethereum Mainnet + 极小自有不可升级 registry 为推荐基线。身份更新低频，先避免加入 L2 排序器/退出证明假设；同时要测出完整轻客户端和 storage proof 路径及真实 gas。若验证链路、资源或费用不适合，发布前必须重新冻结另一条公共链，不能悄悄回退到自建私链或中心账号服务。

ERC-1056/did:ethr 有可复用身份 registry 语义和事件/元交易接口，适合兼容导出研究；当前不作为默认合约，因 ASL 还需要设备状态承诺、严格 sequence、吊销和可验证状态快照。这不是对 ERC-1056 安全性的否定。

Rust 复用边界：Alloy 可评估用于 EVM 类型、交易和 typed-data 编码；它本身不自动构成以太坊共识轻客户端。Helios 是轻客户端候选，嵌入 API、目标 storage proof、Windows 资源限额与许可证仍需核实。MPT proof 验证不得手写，需选经过审查的实现并做恶意 proof 测试；目前未冻结 crate/API。

## 3.2 费用与身份边界

- 每笔身份注册/更新最终要有人提交并承担公共链 gas。默认可配置多个互不依赖的志愿赞助者；赞助者只代提交用户已签名操作，不持根密钥，能拒绝/延迟但不能伪造有效操作。
- 赞助服务可能限额或停止。ASL 没有费用、代币、购买积分或商业套餐；用户自付是可选链外成本，不经过 ASL 收款。
- 免费注册、无需许可、抗刷号不能同时保证。公共链账户数量不代表独立的人或 Agent；链不是 Sybil 防火墙。
- 链/赞助故障时只用已验证且未过期的最终化状态；新/未知身份降至最低预算，身份验证不自动授予目录、模型或文件权限。

## 3.3 结构化语义裁决

- query 的自由文本改为 intent concept、topic concept IDs、typed constraints、期望结果形态和预算。
- answer prose 改为 concept-based claim、类型化值、证据引用和状态枚举。
- offer 的 title/summary/tags 改为 content ID、媒体/资源类别枚举、concept IDs、大小和期限；文件名只在本机接收后生成。
- profile 名称、说明、地区和自由标签不经网络发布；公开 profile 只含授权概念和头像引用。
- 文件是单独授权的不透明载荷，不是控制协议字段；不得自动解析为对话/指令或交给模型。授权模型处理仍需本机 grant。
- MLS ciphertext 不透明，但解密后的应用明文必须是 ASL/1 结构对象。不能映射到词表的语义不发送，不能回退成 JSON 字符串。

## 3.4 个人电脑优先的 Sybil 防护

采用 `docs/09-resource-abuse.md`。防护按机器/用户会话总量、入站类别、网络来源、AgentId、PeerId 和单连接逐级限额。合法多 Agent 共享一个 supervisor 总预算；克隆身份有时可观察到并发冲突，但被动克隆不可可靠识别。安全目标是远端身份数量不能突破本机预算，也不能改变本地授权。

## 4. 可复用项目

- OpenMLS：复用 RFC 9420 群密钥/成员状态与端到端消息保护；不复制源码，也不自行实现群密码学。群消息用现有认证连接逐成员投递，不用 pubsub，减少组件和群元数据暴露。
- egui/eframe 版本从 0.37.0 调整为 0.35.0：T02 编译发现与 libp2p 0.57.1 的 wasm 依赖固定冲突，不能通过双版本解决；保持网络栈不变，选择仍兼容 Rust 1.95 的 GUI 版本。
- rust-libp2p：主网络栈和官方 examples。`https://github.com/libp2p/rust-libp2p`
- 官方 Kademlia 规范：精确键、provider 与记录验证。`https://github.com/libp2p/specs/tree/master/kad-dht`
- Reason Network：参考 Agent/MCP/常驻后台的连接方式，不直接复制其账号和团队服务。`https://github.com/reason-machines/reason-network`
- sendme：参考传输状态与最小文件流程，本项目不直接使用其 iroh 栈。`https://github.com/n0-computer/sendme`
- DashBeam：仅参考传输界面思路，不把 AGPL 源码和资产纳入 MIT 项目。`https://github.com/tonyantony300/dashbeam`
- egui/eframe：Rust GUI 与图片集成。`https://github.com/emilk/egui`
- 官方 Rust MCP SDK。`https://github.com/modelcontextprotocol/rust-sdk`
- SQLite FTS5。`https://www.sqlite.org/fts5.html`
- cap-std。`https://docs.rs/cap-std/`
- Windows AppContainer。`https://learn.microsoft.com/en-us/windows/win32/secauthz/appcontainer-isolation`
- Windows Job Objects。`https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects`
- Windows DPAPI。`https://learn.microsoft.com/en-us/windows/win32/secauthn/data-protection`
- iroh 地址查询，仅为选型比较。`https://docs.iroh.computer/concepts/address-lookup`
- iroh-blobs 状态与修复公告，说明不能盲信文件服务默认值。`https://github.com/n0-computer/iroh-blobs`、`https://www.iroh.computer/blog/iroh-blobs-push-fix`
- AI worm 研究，提示外部资料传播风险。`https://arxiv.org/abs/2403.02817`

依赖基线通过 crates.io API 查询，确切版本见 JSON；尚未证明所有 feature/MSRV/平台组合可编译。选 MIT 不代表第三方依赖也全部 MIT，锁文件生成后仍需依赖许可与 notices 验收。

### 规范与安全资料

- [RFC 8949 — Concise Binary Object Representation (CBOR)](https://www.rfc-editor.org/rfc/rfc8949.html)
- [RFC 8610 — CDDL](https://www.rfc-editor.org/rfc/rfc8610.html)
- [EIP-712 — Typed structured data hashing and signing](https://eips.ethereum.org/EIPS/eip-712)
- [EIP-1186 — RPC eth_getProof](https://eips.ethereum.org/EIPS/eip-1186)
- [EIP-1056 — EthereumDIDRegistry](https://eips.ethereum.org/EIPS/eip-1056)
- [Ethereum proof-of-stake finality](https://ethereum.org/developers/docs/consensus-mechanisms/pos/)
- [Ethereum gas and transaction fees](https://ethereum.org/developers/docs/gas/)
- [libp2p Kademlia DHT specification](https://github.com/libp2p/specs/tree/master/kad-dht)
- [Helios light client](https://github.com/a16z/helios)
- [Alloy Rust Ethereum toolkit](https://github.com/alloy-rs/alloy)
