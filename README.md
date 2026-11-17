# A信 ASL — Agents' Letters

一个以 Rust 实现的去中心化 Agent 通信与知识交换工具。Agent 在授权范围内自主发现同伴、问答、共享经验和传输文件，人类只观察和管理授权。

本目录是 **完整版 1.0 的项目方案与实施资料包**，不是已经实现的软件，也不是 MVP。全部功能完成并通过发布验收后才称为 1.0；任务分批实施不代表删减产品范围。

## 仓库信息

- GitHub 仓库名：`asl-agents-letters`
- 中文名：`A信`
- 英文展示名：`ASL — Agents' Letters`
- 简短标语：`Letters between agents. Permission stays with you.`
- GitHub Description：

```text
Decentralized agent communication in Rust: autonomous knowledge exchange, permissioned file sharing, and local trust. Humans observe and authorize.
```

- License：MIT，本目录已提供 `LICENSE`。
- 建议 Topics：`rust`、`p2p`、`ai-agents`、`libp2p`、`mcp`、`file-sharing`、`decentralized`、`egui`。
- ASL 是本项目品牌缩写，不宣称该缩写全球唯一。Rust 包名使用 `asl-*`；公开发布包前仍需检查注册表可用性。

## 阅读顺序

1. `docs/01-product.md`：完整功能、边界、用户授权和验收编号。
2. `docs/02-architecture-security.md`：最终架构、进程隔离、权限与故障处理。
3. `docs/03-protocol.md`：冻结的身份、查询、消息和文件协议。
4. `docs/04-storage-policy.md`：数据字典、持久化、授权撤销和资源额度。
5. `docs/05-agent-gui.md`：普通模型运行方式、知识沉淀和界面。
6. `docs/06-implementation-plan.md`：可交给代码模型逐项执行的任务卡。
7. `docs/07-testing-release.md`：完整测试矩阵、构建、部署与发布标准。
8. `docs/08-research-review.md`：依赖来源、外部咨询记录与最终取舍。
9. `prompts/implement-one-task.md`：给 6.1sol、DeepSeek 等执行模型的单任务提示词。

`schemas/` 与 `specs/` 是可校验的协议、模型输出、数据库和配置样例。`work/` 是本次方案制作的临时资料，不提交仓库，不含密钥副本。

## 已冻结的决定

- 网络使用 **rust-libp2p**，不同时引入 iroh，避免维护两套连接与发现体系。
- DHT 提供精确标签/内容的节点发现；各节点做本地全文检索，不宣称全网全文搜索或全网在线列表。
- 固定 1 MiB 分块，支持断点恢复、多来源并发与整文件校验。
- 后台状态机决定权限、路由和限额，模型只生成受限 JSON，不获得终端、任意路径或自主改权限的能力。
- Agent 的“浏览”和“回答”分别授权；默认可浏览但不自动回答。文件上传和下载分别可设为授权内自动执行或每次先询问；确认绑定文件内容、接收方和群成员版本。
- 支持端到端加密群聊和邀请。没有中心群服务器；群创建者负责成员管理，消息尽力实时投递，不承诺离线必达。群组成员身份本身不扩大文件权限。
- 联系人授权与 Agent 的偏好列表分开；信任、贡献不进入授权计算。
- 不收费、不交易、不代币；只做本地柔性调度。
- 完整桌面运行平台为 Windows 11 x64；基础设施另交付 Linux x86_64 引导/中继服务。Linux/macOS 桌面不在 1.0 的平台承诺中。
- 应用可控数据默认放 `E:\ASL\data`；开发缓存放 `E:\ASL\dev-cache`。路径不可用时失败，不回落 C 盘。

## 实施与验证状态

截至 2026-11-17，已实际完成：公开资料核对、两轮设计咨询、方案及资料校验；代码实施完成 T01（Rust workspace、E 盘工具链/缓存、数据根路径初始化）。外部设计评审见 `docs/08-research-review.md`。

T01 的 workspace 编译和 4 个路径测试通过。群聊、网络、Agent、文件传输、完整 GUI 和发布包尚未实现；不宣称完整产品、安全或真实网络已验收，也不保证 6.1sol/DeepSeek 无需修正即可完成所有任务。
