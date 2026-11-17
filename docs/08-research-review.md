# 一手资料、fable5.2 咨询与最终裁决

日期：2026-11-17。资料优先官方仓库、规范、注册表和系统文档。公开项目描述不是安全审计或实际性能证据。

## 1. 实际咨询

按用户授权读取其提供的中转连接文件，只把项目需求发送到该中转，没有发送密钥文件正文或其他私人文件。请求模型 ID 是 `claude-fable-5-2`。

第一条 OpenAI-compatible 请求输出被长度截断，只有开头，未当成完整评审。随后改用该中转的 Anthropic-compatible Messages API，完成两轮独立咨询，两次 finish_reason 均为 end_turn。

| 轮次 | 请求 model_id | 返回 model_id | 返回正文字符数 | 内容 |
| --- | --- | --- | --- | --- |
| 完整第一轮 | claude-fable-5-2 | claude-fable-5-2 | 5,028 | 网络栈、权限、文件协议、模型边界与实施顺序 |
| 完整第二轮 | claude-fable-5-2 | claude-fable-5-2 | 5,568 | 转发越权、身份/TCB、自由文本泄露、恢复与安全门禁 |

返回标识只能证明中转如此报告，不能独立验证实际上游厂商和模型。两轮都是设计评审，没有编译或实测，不能当作安全认证。

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

## 3. 身份与信任边界的明确裁决

第二轮正确指出：libp2p 的 transport 在 net 进程，不能假设私钥永远只在 broker 却仍能直接使用库握手。

为避免自行引入双身份、远程签名或额外应用加密握手，最终明确把 net 的认证适配器纳入可信计算基，启动时拿到身份内存副本。沙箱限制其文件权限，但不宣称 net 被完全攻陷后仍可保护 contacts 身份与内容。

这是一项透明的工程取舍，必须在 T14/T35 复核并写入安全说明。worker/helper 与模型输出仍不可信，不能拥有身份密钥、私有目录或扩大权限的通道。

## 4. 可复用项目

- OpenMLS：复用 RFC 9420 群密钥/成员状态与端到端消息保护；不复制源码，也不自行实现群密码学。群消息用现有认证连接逐成员投递，不用 pubsub，减少组件和群元数据暴露。
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
