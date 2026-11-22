use asl_app::network_settings::{NetworkAddressScopeV1, NetworkSettingsV1};
use asl_store::dashboard::Dashboard;
use asl_store::network_privacy::NetworkRuntimeState;
use asl_types::error::AslError;
use eframe::egui::{Checkbox, RichText, Ui};

use super::{LocalAction, MUTED};

pub(super) fn show(
    ui: &mut Ui,
    config: &Result<NetworkSettingsV1, AslError>,
    data: &Dashboard,
    enabled: bool,
    action: &mut Option<LocalAction>,
) {
    ui.label(RichText::new("网络隐私").strong());
    let mut pause = data.network_pause_requested;
    if ui
        .add_enabled(
            enabled && action.is_none(),
            Checkbox::new(&mut pause, "暂停 ASL 对等网络"),
        )
        .on_hover_text("只暂停 ASL 节点连接，不暂停链 RPC 或本机服务。")
        .changed()
    {
        *action = Some(LocalAction::new(
            "network",
            ["pause".into(), (if pause { "on" } else { "off" }).into()],
        ));
    }
    ui.colored_label(MUTED, "直连会向对端暴露 IP；中继仍能看到连接元数据。");
    let fixed = config
        .as_ref()
        .is_ok_and(|c| c.address_scope == NetworkAddressScopeV1::RelayOnly);
    let can_enable = config
        .as_ref()
        .is_ok_and(|c| !c.relay_addresses.is_empty() && !c.loopback_groups);
    let mut checked = fixed || data.force_relay_only;
    if ui
        .add_enabled(
            enabled && action.is_none() && !fixed && (checked || can_enable),
            Checkbox::new(&mut checked, "仅中继（下次启动后台生效）"),
        )
        .changed()
    {
        *action = Some(LocalAction::new(
            "network",
            [
                "relay-only".into(),
                (if checked { "on" } else { "off" }).into(),
            ],
        ));
    }
    match config {
        Err(_) => ui.colored_label(MUTED, "网络配置无效"),
        Ok(_) if fixed => ui.colored_label(MUTED, "本机配置固定为仅中继"),
        Ok(c) if c.loopback_groups => ui.colored_label(MUTED, "回环群组模式不可与中继并用"),
        Ok(c) if c.relay_addresses.is_empty() => ui.colored_label(MUTED, "未配置中继地址"),
        Ok(c) => ui.colored_label(MUTED, format!("已配置地址：{}", c.relay_addresses.len())),
    };
    if let Some(last) = &data.network_report {
        let mode = if last.relay_only {
            "仅中继"
        } else {
            "按本机直连策略"
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let age_s = now.saturating_sub(last.observed_at_ms).max(0) / 1000;
        let runtime = match last.runtime {
            NetworkRuntimeState::Unknown => "状态未报告",
            NetworkRuntimeState::Running => "对等网络运行中",
            NetworkRuntimeState::Paused => "对等网络已暂停",
            NetworkRuntimeState::ResumeFailed => "恢复失败，对等网络未运行",
        };
        ui.label(format!("后台上次报告（{age_s} 秒前）：{runtime}"));
        ui.colored_label(
            MUTED,
            format!(
                "{mode}，已预约 {}/{}",
                last.reserved_relays, last.configured_relays
            ),
        );
        match (data.network_pause_requested, last.runtime) {
            (true, NetworkRuntimeState::Running) => {
                ui.colored_label(MUTED, "已请求暂停");
            }
            (false, NetworkRuntimeState::Paused) => {
                ui.colored_label(MUTED, "已请求恢复");
            }
            (false, NetworkRuntimeState::ResumeFailed) => {
                ui.colored_label(MUTED, "恢复失败")
                    .on_hover_text("重新开启暂停，等后台确认后关闭暂停可重试。");
            }
            _ => {}
        }
        if last.relay_only != (fixed || data.force_relay_only) {
            ui.colored_label(MUTED, "已保存的模式与上次报告不同");
        }
    } else {
        ui.colored_label(MUTED, "尚无后台网络报告");
    }
    ui.add_space(12.0);
}
