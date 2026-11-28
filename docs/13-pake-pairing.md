# PAKE 短码配对

状态：代码已接入并通过 workspace 自动化测试；真实双机、NAT/relay、二维码摄像头和独立审计仍待外部验收。

## 依赖裁决

- 采用 `spake2 0.4.0`，MIT OR Apache-2.0，`rust-version 1.60`，可在当前锁定的 Rust 1.100 工具链构建。
- 不使用 `0.5.0-pre.0` 作为生产路径。
- `spake2` 官方 README 明确表示没有独立第三方安全审计，且实现不保证严格 constant-time。因此本路径只用于一次性、短期、在线猜测受限的配对，不作为长期身份、设备认证或文件授权 bearer。
- 未采用 `opaque-ke`：它适合注册式 aPAKE，需要保存注册记录和更重的会话状态；当前需求是第一次联系前交换一次性短码，`spake2` 的非对称 A/B 模式更接近此场景。

## 协议

短码为 6 位或 12 位十进制数字，默认有效期 5 分钟，最大 15 分钟。短码只从邀请方的短期 `contact_invites.token` 派生；短码本身不是 AgentId 或 PeerId。

1. 邀请方创建 Pake invite，公开只包含完整 AgentId、设备 PeerId、invite id、短码和期限的 `ASL-PAKE-CODE:1:...` 发现串；来源端仍通过 DHT token provider 提供发现。
2. 输入方在认证连接建立后发送 `pake-start`，内含 SPAKE2 A share。Start 由输入方 Agent 根签名，并绑定：
   - exchange id（128-bit invite id）
   - owner AgentId 与 joiner AgentId
   - owner PeerId 与 joiner PeerId
   - A/B 角色（SPAKE2 identity 域）
   - 6/12 位长度和有效期
   - A share
3. 邀请方验证连接中的 AgentId/PeerId、本地活动 invite、短码长度、期限和 Start 签名，运行 SPAKE2 B 侧，返回 `pake-answer`。Answer 签名覆盖 Start 的全部绑定、B share 和 answer key confirmation。
4. 输入方验证 Answer 签名和 key confirmation，发送 `pake-confirm`。邀请方验证输入方的 confirm，消费 invite，成功时只写本地联系人 binding，并返回 `pake-receipt`。
5. 输入方验证 receipt 后完成 binding。失败、超时、伪造签名、重复 invite 或 key confirmation 不匹配都使连接关闭并尽量消费 invite。

每个 invite 同一时间只有一个 owner 会话，pending 会话上限为 8。邀请方在看到第一份有效 `pake-start` 时，会在 SQLite `settings` 中持久占用该 invite 的唯一尝试名额；猜错、回复丢失或进程重启都不能让同一短码再次尝试。该持久栅栏已有存储层测试。SPAKE2 临时密钥和会话本身仍不落盘，因此占用后重启必须重新生成短码。短码路径不创建 `authorized_contacts`、文件 grant、群成员资格或模型权限。

## 代码位置

- `crates/asl-app/src/pairing/pake.rs`：SPAKE2 状态、transcript、签名、key confirmation、pending runtime。
- `crates/asl-app/src/contact_invite.rs`：6/12 位短码、Pake envelope、token marker。
- `crates/asl-types/src/protocol.rs` 与 `protocol/cbor.rs`：`pake-start(20)`、`pake-answer(21)`、`pake-confirm(22)`、`pake-receipt(23)`。
- `crates/asl-app/src/supervisor/contact_invites.rs`：发现、连接后 PAKE 状态机、失败消费和联系人 binding。
- `crates/asl-app/src/bin/asl-core/contact_invite_control.rs`：`create-pake <5|15> <6|12> <note>`。
- `crates/asl-app/src/ui/contact_invites.rs`：生成、复制、二维码和导入入口。

## 安全边界与剩余风险

- 短码可被持码者使用；这是有意的 bearer 语义，不能替代完整 AgentId 的长期 pin。
- 6 位短码仍允许一次在线猜测，但每个 invite 的尝试名额在发出 Answer 前持久占用，并受期限限制；抗离线字典攻击来自 PAKE，不是短码长度。
- 传输层仍依赖 libp2p Noise、链身份证明、设备证书和 `CoreAdmission`；PAKE 不替代这些验证。
- 当前没有独立安全审计、6/12 位跨机尝试率矩阵、真实 NAT/relay 双机、二维码摄像头扫描或长时间重启验收。
- pending SPAKE2 状态不落盘；这是为了避免序列化秘密状态和扩大攻击面。尝试名额仍会持久占用，因此进程重启后用户必须重新生成短码，不能复用旧码继续猜测。
