use asl_app::network_settings::{NetworkAddressScopeV1, NetworkSettingsV1};
use asl_store::dashboard::Dashboard;
use asl_store::network_privacy::NetworkRuntimeState;
use asl_types::error::AslError;
use eframe::egui::{Checkbox, RichText, Ui};

use super::{LocalAction, MUTED, locale::Language};

pub(super) fn show(
    ui: &mut Ui,
    config: &Result<NetworkSettingsV1, AslError>,
    data: &Dashboard,
    language: Language,
    enabled: bool,
    action: &mut Option<LocalAction>,
) {
    ui.label(RichText::new(label(language, "网络隐私", "Network privacy")).strong());
    let mut pause = data.network_pause_requested;
    if ui
        .add_enabled(
            enabled && action.is_none(),
            Checkbox::new(
                &mut pause,
                label(language, "暂停 ASL 对等网络", "Pause ASL peer network"),
            ),
        )
        .on_hover_text("只暂停 ASL 节点连接，不暂停链 RPC 或本机服务。")
        .changed()
    {
        *action = Some(LocalAction::new(
            "network",
            ["pause".into(), (if pause { "on" } else { "off" }).into()],
        ));
    }
    ui.colored_label(
        MUTED,
        label(
            language,
            "直连会向对端暴露 IP；中继仍能看到连接元数据。",
            "Direct connections expose your IP. Relays still see connection metadata.",
        ),
    );
    let fixed = config
        .as_ref()
        .is_ok_and(|c| c.address_scope == NetworkAddressScopeV1::RelayOnly);
    let can_enable = config.as_ref().is_ok_and(|c| !c.relay_addresses.is_empty());
    let mut checked = fixed || data.force_relay_only;
    if ui
        .add_enabled(
            enabled && action.is_none() && !fixed && (checked || can_enable),
            Checkbox::new(
                &mut checked,
                label(
                    language,
                    "仅中继（下次启动后台生效）",
                    "Relay only (applies on next startup)",
                ),
            ),
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
        Err(_) => ui.colored_label(
            MUTED,
            label(language, "网络配置无效", "Invalid network configuration"),
        ),
        Ok(_) if fixed => ui.colored_label(
            MUTED,
            label(
                language,
                "本机配置固定为仅中继",
                "Local configuration is fixed to relay-only",
            ),
        ),
        Ok(c) if c.relay_addresses.is_empty() => ui.colored_label(
            MUTED,
            label(language, "未配置中继地址", "No relay addresses configured"),
        ),
        Ok(c) => ui.colored_label(
            MUTED,
            format!(
                "{}: {}",
                label(language, "已配置地址", "Configured addresses"),
                c.relay_addresses.len()
            ),
        ),
    };
    if let Some(last) = &data.network_report {
        let mode = if last.relay_only {
            label(language, "仅中继", "Relay only")
        } else {
            label(language, "按本机直连策略", "Local direct policy")
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis()
            .min(i64::MAX as u128) as i64;
        let age_s = now.saturating_sub(last.observed_at_ms).max(0) / 1000;
        let runtime = match last.runtime {
            NetworkRuntimeState::Unknown => label(language, "状态未报告", "Status not reported"),
            NetworkRuntimeState::Running => {
                label(language, "对等网络运行中", "Peer network running")
            }
            NetworkRuntimeState::Paused => label(language, "对等网络已暂停", "Peer network paused"),
            NetworkRuntimeState::ResumeFailed => label(
                language,
                "恢复失败，对等网络未运行",
                "Resume failed, peer network stopped",
            ),
        };
        ui.horizontal_wrapped(|ui| {
            if matches!(
                last.runtime,
                NetworkRuntimeState::Paused | NetworkRuntimeState::ResumeFailed
            ) {
                super::views::inline_glyph(ui, super::art::Glyph::NetworkOffline);
            }
            ui.label(format!(
                "{} ({age_s}s): {runtime}",
                label(language, "后台上次报告", "Last backend report")
            ));
        });
        ui.colored_label(
            MUTED,
            format!(
                "{mode} · {}: {}/{}",
                label(language, "已预约", "Reserved"),
                last.reserved_relays,
                last.configured_relays
            ),
        );
        match (data.network_pause_requested, last.runtime) {
            (true, NetworkRuntimeState::Running) => {
                ui.colored_label(MUTED, label(language, "已请求暂停", "Pause requested"));
            }
            (false, NetworkRuntimeState::Paused) => {
                ui.colored_label(MUTED, label(language, "已请求恢复", "Resume requested"));
            }
            (false, NetworkRuntimeState::ResumeFailed) => {
                ui.colored_label(MUTED, label(language, "恢复失败", "Resume failed"))
                    .on_hover_text(label(
                        language,
                        "重新开启暂停，等后台确认后关闭暂停可重试。",
                        "Enable pause again, then disable it after the backend confirms.",
                    ));
            }
            _ => {}
        }
        if last.relay_only != (fixed || data.force_relay_only) {
            ui.colored_label(
                MUTED,
                label(
                    language,
                    "已保存的模式与上次报告不同",
                    "Saved mode differs from the last report",
                ),
            );
        }
    } else {
        ui.colored_label(
            MUTED,
            label(
                language,
                "尚无后台网络报告",
                "No backend network report yet",
            ),
        );
    }
    ui.add_space(12.0);
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}
