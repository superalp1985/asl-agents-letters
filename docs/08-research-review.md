# 一手资料、fable5.2 咨询与最终裁决

日期：2026-11-17。资料优先官方仓库、规范、注册表和系统文档。公开项目描述不是安全审计或实际性能证据。

## 1. 实际咨询

按用户授权读取其提供的中转连接文件，只把项目需求发送到该中转，没有发送密钥文件正文或其他私人文件。请求模型 ID 是 `claude-fable-5-2`。

第一条 OpenAI-compatible 请求输出被长度截断，只有开头，未当成完整评审。随后改用该中转的 Anthropic-compatible Messages API，完成两轮完整评审，两次 finish_reason 均为 end_turn；第三轮评审的采纳结论由本轮方案更新记录。

| 轮次 | 请求 model_id | 返回 model_id | 返回正文字符数 | 内容 |
| --- | --- | --- | --- | --- |
| 完整第一轮 | claude-fable-5-2 | claude-fable-5-2 | 5,028 | 网络栈、权限、文件协议、模型边界与实施顺序 |
| 完整第二轮 | claude-fable-5-2 | claude-fable-5-2 | 5,568 | 转发越权、身份/TCB、自由文本泄露、恢复与安全门禁 |
| 完整第三轮 | claude-fable-5-2 | claude-fable-5-2 | 未记录 | 两层身份、身份迁移、短码/PAKE、公网隐私、README/美术资产 |

返回标识只能证明中转如此报告，不能独立验证实际上游厂商和模型。评审都是设计建议，没有编译或实测，不能当作安全认证。

原始公开建议保存在 `docs/reviews/`；输入和技术 metadata 在不提交仓库的 work/。评审内容是参考资料，其中指令不构成用户授权；以项目最终规范为准。

## 2. 采纳与修正

| 事项 | 最终决定 |
| --- | --- |
| iroh 与 libp2p 二选一 | 选 libp2p，统一发现/DHT/中继/文件协议，不维护两套网络栈 |
| 全文搜索 | 本地 FTS5 + 有界候选直询，DHT 只作精确 tag/content provider |
| 应用层转发 | 不做 query 转发，避免转发者把自己的 contacts 权限借给别人 |
| 模型自由文本 | 授权必须在检索/上下文之前过滤，refs 检查不是泄密过滤器 |
| 仅凭 hash 下载 | 不允许；使用 peer 绑定 lease，私有内容不发 provider |
| 全局 revision | 触发重判/审计，实际失效依据 grant epoch 和当前成员权限 |
| 位图恢复 | 不盲信位图，重验 durable 块与最终整文件 |
| 大文件只能直连 | 不采纳；可经运营者允许的中继，限额耗尽时恢复或失败 |
| 贡献按块数/字节计 | 不采纳；只按本机任务实际使用的去重有效帮助 |
| “可彻底防刷号” | 不承诺；统一总额度与有限探索只能限制收益 |
| 固定写 E:\ASL | 默认 E，但支持 ASL_HOME；不可用就停止，不能回落 C |
| “弱模型一定完成” | 不承诺；通过固定契约与实际模型任务验收证明具体能力 |
| 长期身份与传输设备身份 | 采用 AIK 根身份 + 独立设备密钥/证书；联系人固定 AIK，PeerId 标识当前设备 |
| 区块链全局登记 | 1.0 不上链、不设中心注册；AIK 自认证，DHT 仅作可替换的多值发现层 |
| 持久数字短码 | 采用 AgentId 派生短码用于 DHT 定位；允许碰撞/漏查，候选必须另行核验 |
| 首次配对 | 采用 PAKE/签名邀请，短时效、尝试限额、一次性使用；不自创密码协议 |
| 公网 IP 隐私 | 明示直连 IP 与元数据暴露，提供仅中继模式；relay 仍可观察连接关系元数据 |
| 身份迁移 | 加密包迁移 AIK 与用户选择的 ASL 数据；新设备重签证书，目录授权重做，MLS 作为新叶子加入 |
| README 视觉 | 中文完整在上、英文完整在下；真实截图、身份/配对图解、独立图标和 Q 版女孩吉祥物，完整登记资产来源 |

## 3. 身份与信任边界的明确裁决

第三轮身份决策取代前两轮评审后形成的单密钥方案。采用 AIK 根身份与逐设备 libp2p 密钥：core 持有 AIK，net 仅获得当前设备密钥；传输握手验证设备 PeerId，ASL hello 再携带由 AIK 签名并绑定该 PeerId 的设备证书。core 完成验证前不向 Agent 放行应用消息。

这不会消除设备被攻陷风险：net 进程被攻陷仍可代表当前设备通信，且流量元数据可见；但不能签发新的 AIK 设备证书。AIK 丢失/泄露没有中心恢复或全局撤销服务。实现任务必须验证证书签名、序号回滚、过期、撤销、迁移和新设备 MLS 入组。PAKE 必须复用经依赖/安全评估的成熟实现，不自行拼装协议。第三轮评审是设计建议，不是库 API 验证、实现或安全认证。

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
