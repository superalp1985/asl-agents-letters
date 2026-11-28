# 联系人来源证明与策略同步接口

日期：2026-11-28

本文只记录已接入代码的接口。联系人策略同步传输的是本机请求准入设置，不是联系人授权、文件授权、模型授权或群权限。

## 1. 远端来源证明

- `asl_types::protocol::ContactProvenance`
  - `SharedGroup { group_id, membership_epoch }`
  - `RecentInteraction { interaction_id, expires_at_ms }`
- `PairingInvite.provenance: Option<ContactProvenance>` 的 CBOR 键 9 纳入原 PairingInvite 根签名原文。没有该键的旧邀请签名不改变。
- `ContactInviteV1.provenance: Option<ContactProvenance>` 的 CBOR 键 8 纳入联系人邀请根签名，并在目标定向邀请中复制。
- `asl_types::contact_invite::encode_provenance` / `decode_provenance` 用于本机 settings 持久化；临时邀请的 provenance 保存在 `contacts.invite_provenance.v1.<invite-id>`，到期或消费后删除。
- Core 只在来源类型与本地策略开关匹配时尝试使用；`SignedRemote::allows` 仍要求：
  - 共享群：本机当前活动 MLS 群中同一认证 AgentId/PeerId，当前 epoch 不低于声明；
  - 近期交互：本机固定到期证据中的同一 interaction ID，且未过期。
- 远端签名只证明发送者作出声明，不证明群成员资格或交互事实。声明与本地证据不匹配时不自动绑定。

## 2. 本地策略与防回滚

- SQLite `settings`：
  - `contacts.request_policy.v1`：mode、共享群来源开关、近期交互 TTL、单调 `revision`、`revoked`。
  - `contacts.policy_sync_authorized.v1`：本机是否允许导入设备同步策略，默认 `false`。
- `ContactRequestPolicy.revision` 只能前进；相同 revision 的不同内容被拒绝。`revoked=true` 必须是 `Reject` 模式。
- `Store::revoke_contact_request_policy` 写入更高 revision 的拒绝快照；`set_contact_request_policy` 和原有来源规则动作也会推进 revision。
- `Store::apply_contact_policy_snapshot` 先检查本机同步授权，再拒绝 `revision <= current`，不通过来源证据或联系人绑定隐式授权。
- `Selection.contacts` 的现有加密身份迁移包携带 revision/revoked；旧迁移包缺失字段按 revision 0 处理，目标新库恢复时至少为 1。

## 3. 根签名密文封套

- `RecordKind::ContactPolicy = 4`。
- `RecordPayload::ContactPolicy(ContactPolicyEnvelope)`：AgentId、revision、nonce、非敏感 revoked 标志、密文；外层 `sequence` 必须等于 revision。
- ContactPolicy 记录有效期最多 24 小时；同一 revision 的冲突先按 revoked 优先，再按完整签名记录 BLAKE3 较小的字节串收敛，DHT store、Core 的 `RecordHistory`、DHT cache 和策略 runtime 使用同一规则。
- 密文由 Agent root secret 经 BLAKE3 `ASL-CONTACT-POLICY-ENCRYPTION-v1` 派生密钥后，使用现有 `age` scrypt 加密。
- 外层可见字段只有 owner、revision、nonce、期限和密文；联系人 ID、来源规则和撤销内容只在密文中。
- `asl_app::contact_policy_sync::export(identity, store, now_ms)` 生成记录。
- `asl_app::contact_policy_sync::import(identity, store, bytes, now_ms)` 验证 owner、签名、期限、sequence=revision 和涨 revision 后应用。
- Core 在 `Active` 且同步授权开启时每 60 秒 Lookup 本 AgentId 的 ContactPolicy 键；本地 revision 变化或记录临近过期时自动发布。发布状态保存在 `settings` 的 `contacts.policy_publication.v1`，包含精确记录字节、revision、期限和退避时间；失败重试复用同一记录，不重新随机生成。
- 只有记录过期才推进本地 policy revision 并生成新 record；这避免同一 sequence 的续发冲突。

## 4. 本机接口

- CLI：
  - `asl-core --bindings policy-sync on|off`
  - `asl-core --bindings policy-export <path>`，导出当前稳定缓存记录
  - `asl-core --bindings policy-import <path>`
  - `asl-core --bindings policy-revoke`
  - `asl-core --bindings policy-restore`，仅在显式人工恢复时清除撤销并回到逐次确认
  - `asl-core --bindings policy`，输出 revision、revoked 和 sync authorization。
  - `asl-core --contact-invites create-group <minutes> <note> <group-id> <epoch>`，生成带共享群 provenance 的签名邀请。
- GUI 联系人页：显示 policy revision、同步授权开关和撤销策略按钮；操作仍经相邻 `asl-core --bindings` 路径执行，不直接写 SQLite。
- MCP：不新增策略写工具。现有 `asl_contact_status` 只读返回 revision、revoked 和 sync authorization；不能批准、导入或修改策略。

## 5. 权限边界

- 来源证明和策略同步都不会写 `authorized_contacts`、资源 grant、文件 grant、模型 provider 授权或群成员资格。
- 自动联系人绑定只写本机 `contact_bindings`；是否允许联系人范围问询/文件仍需独立授权。
- 策略同步不会携带 pending invitation、候选、联系人访问 grant 或共享目录。

## 6. 未完成的外部条件

- kind 4 密文封套已接入 Core 的 DHT Lookup/Publication 周期任务；真实公网双机、NAT/relay、DHT 分区恢复和长时间自动收敛仍未验收。
- 没有两台真实设备上的并发 revision 竞争、时钟偏斜、旧包重放和跨设备撤销传播证据。
- 这些限制不改变本机导入授权和 anti-rollback 代码路径；自动 Lookup/Publication 已接入，但不得宣传为已完成公网多设备收敛验证。
