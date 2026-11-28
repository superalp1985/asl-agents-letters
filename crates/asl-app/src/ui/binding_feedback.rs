pub(super) fn kind(code: &str) -> &'static str {
    match code {
        "lookup" => "查找短码",
        "approve" => "确认绑定",
        "dismiss" => "忽略候选",
        "revoke" => "撤销绑定",
        "forget" => "遗忘绑定",
        "publish_code" => "允许 AgentId 精确发现",
        "unpublish_code" => "关闭 AgentId 精确发现",
        _ => "其他操作",
    }
}

pub(super) fn progress(state: &str, result: Option<&str>) -> &'static str {
    match (state, result) {
        ("queued", _) => "已排队",
        ("working", _) => "处理中",
        ("complete", Some("candidates_found")) => "找到已核验候选",
        ("complete", Some("searching")) => "已转交设备核验",
        ("complete", Some("no_candidates")) => "未找到新候选",
        ("complete", Some("approved")) => "已绑定",
        ("complete", Some("dismissed")) => "已忽略",
        ("complete", Some("revoked")) => "已撤销",
        ("complete", Some("forgotten")) => "已遗忘",
        ("complete", Some("enabled" | "disabled")) => "本机设置已更新",
        ("complete", _) => "已完成",
        ("failed", Some("expired")) => "查找超时",
        ("failed", Some("lookup_failed")) => "网络查找失败",
        ("failed", Some("identity_unavailable")) => "当前无法核验该设备",
        ("failed", Some("candidate_expired")) => "候选已失效",
        ("failed", Some("unavailable")) => "查找暂不可用",
        ("failed", Some("not_found")) => "未找到绑定",
        ("failed", _) => "操作失败",
        _ => "状态未知",
    }
}
