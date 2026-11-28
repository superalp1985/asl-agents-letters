use asl_app::network_settings::{NetworkAddressScopeV1, NetworkSettingsV1};
use asl_store::dashboard::Dashboard;
use asl_store::network_privacy::{NetworkReachability, NetworkRouteFailure, NetworkRuntimeState};
use asl_types::error::AslError;
use eframe::egui::{Button, Checkbox, ComboBox, Id, RichText, TextEdit, Ui};

use super::{
    LocalAction, MUTED,
    locale::Language,
    tokens::{DANGER, SUCCESS, WARNING},
};

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
                "{}: {} · {}: {} · {}: {}",
                label(language, "地址范围", "Address scope"),
                scope_label(language, c.address_scope),
                label(language, "引导入口", "Bootstrap"),
                c.bootstrap_multiaddrs.len(),
                label(language, "中继", "Relays"),
                c.relay_addresses.len()
            ),
        ),
    };
    if let Ok(c) = config {
        ui.add_space(8.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(label(language, "地址范围", "Address scope"));
            let mut scope = c.address_scope;
            ComboBox::from_id_salt("asl-network-scope")
                .selected_text(scope_label(language, scope))
                .show_ui(ui, |ui| {
                    for candidate in [
                        NetworkAddressScopeV1::LoopbackOnly,
                        NetworkAddressScopeV1::LanOnly,
                        NetworkAddressScopeV1::InternetOnly,
                        NetworkAddressScopeV1::Hybrid,
                        NetworkAddressScopeV1::RelayOnly,
                    ] {
                        ui.selectable_value(
                            &mut scope,
                            candidate,
                            scope_label(language, candidate),
                        );
                    }
                });
            if scope != c.address_scope {
                *action = Some(LocalAction::new(
                    "network",
                    ["scope".into(), scope_code(scope).into()],
                ));
            }
        });
        ui.label(
            RichText::new(label(
                language,
                "Bootstrap 入口（完整 multiaddr；添加后下次启动生效）",
                "Bootstrap entries (full multiaddr; applies next startup)",
            ))
            .color(MUTED),
        );
        let input_id = Id::new("asl-network-bootstrap-input");
        let mut input = ui
            .ctx()
            .data_mut(|data| data.get_temp::<String>(input_id).unwrap_or_default());
        ui.horizontal_wrapped(|ui| {
            ui.add_sized(
                [360.0, 26.0],
                TextEdit::singleline(&mut input).hint_text("/ip4/.../tcp/.../p2p/..."),
            );
            if ui
                .add_enabled(
                    !input.trim().is_empty(),
                    Button::new(label(language, "添加", "Add")),
                )
                .clicked()
            {
                *action = Some(LocalAction::new(
                    "network",
                    ["bootstrap".into(), "add".into(), input.trim().into()],
                ));
            }
            if ui
                .add_enabled(
                    !input.trim().is_empty(),
                    Button::new(label(language, "移除", "Remove")),
                )
                .clicked()
            {
                *action = Some(LocalAction::new(
                    "network",
                    ["bootstrap".into(), "remove".into(), input.trim().into()],
                ));
            }
        });
        ui.ctx().data_mut(|data| data.insert_temp(input_id, input));
        if c.address_scope != NetworkAddressScopeV1::RelayOnly {
            let port_id = Id::new("asl-network-ports");
            let mut ports = ui.ctx().data_mut(|data| {
                data.get_temp::<(String, String)>(port_id)
                    .unwrap_or_else(|| {
                        (
                            if c.tcp_port == 0 {
                                "4001".to_owned()
                            } else {
                                c.tcp_port.to_string()
                            },
                            if c.quic_port == 0 {
                                "4001".to_owned()
                            } else {
                                c.quic_port.to_string()
                            },
                        )
                    })
            });
            let mut listen = c.listen_on_interfaces;
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        enabled && action.is_none(),
                        Checkbox::new(
                            &mut listen,
                            label(language, "监听外部连接", "Listen for external connections"),
                        ),
                    )
                    .changed()
                {
                    *action = Some(LocalAction::new(
                        "network",
                        [
                            "listen".into(),
                            (if listen { "on" } else { "off" }).into(),
                            ports.0.clone().into(),
                            ports.1.clone().into(),
                        ],
                    ));
                }
                ui.label("TCP");
                ui.add_sized([70.0, 26.0], TextEdit::singleline(&mut ports.0));
                ui.label("QUIC");
                ui.add_sized([70.0, 26.0], TextEdit::singleline(&mut ports.1));
            });
            ui.ctx().data_mut(|data| data.insert_temp(port_id, ports));
        }
        let mut groups = c.loopback_groups;
        if ui
            .add_enabled(
                enabled && action.is_none(),
                Checkbox::new(
                    &mut groups,
                    label(language, "启用群组网络", "Enable group networking"),
                ),
            )
            .changed()
        {
            *action = Some(LocalAction::new(
                "network",
                ["groups".into(), (if groups { "on" } else { "off" }).into()],
            ));
        }
    }
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
        let (freshness, freshness_color) = report_freshness(language, age_s);
        let runtime = match last.runtime {
            NetworkRuntimeState::Unknown => label(language, "未报告", "Not reported"),
            NetworkRuntimeState::Running => {
                label(language, "后台报告为运行中", "Backend reported running")
            }
            NetworkRuntimeState::Paused => {
                label(language, "后台报告为已暂停", "Backend reported paused")
            }
            NetworkRuntimeState::ResumeFailed => label(
                language,
                "后台报告恢复失败，对等网络未运行",
                "Backend reported resume failure, peer network stopped",
            ),
        };
        ui.horizontal_wrapped(|ui| {
            if matches!(
                last.runtime,
                NetworkRuntimeState::Paused | NetworkRuntimeState::ResumeFailed
            ) {
                super::views::inline_glyph(ui, super::art::Glyph::NetworkOffline);
            }
            ui.label(RichText::new(freshness).strong().color(freshness_color));
            ui.label(format!("{} · {}", age_label(language, age_s), runtime));
        });
        ui.colored_label(
            MUTED,
            format!(
                "{}: {mode} · {}: {}/{} · {}: {}",
                label(language, "上报模式", "Reported mode"),
                label(language, "已预约中继", "Reserved relays"),
                last.reserved_relays,
                last.configured_relays,
                label(language, "监听入口", "Listening endpoints"),
                last.listening_endpoints
            ),
        );
        ui.colored_label(
            MUTED,
            format!(
                "{}: {} · {}: {}% · {}: {}",
                label(language, "入口可达性", "Entry reachability"),
                reachability_label(language, last.reachability),
                label(language, "置信度", "Confidence"),
                last.reachability_confidence.min(100),
                label(language, "公网入口地址", "Public entry address"),
                label(
                    language,
                    if last.public_entry {
                        "已报告"
                    } else {
                        "未报告"
                    },
                    if last.public_entry {
                        "Reported"
                    } else {
                        "Not reported"
                    }
                )
            ),
        );
        ui.colored_label(
            MUTED,
            format!(
                "{}: {} · {}: {} · {}: {} · {}: {} · {}: {}",
                label(language, "直连", "Direct"),
                last.direct_routes,
                label(language, "打洞直连", "Hole-punched"),
                last.hole_punched_routes,
                label(language, "中继", "Relayed"),
                last.relayed_routes,
                label(language, "协商中", "Negotiating"),
                last.negotiating_routes,
                label(language, "失败", "Failed"),
                last.failed_routes
            ),
        );
        if let Some(failure) = last.last_route_failure {
            ui.colored_label(
                DANGER,
                format!(
                    "{}: {}",
                    label(language, "最近路由失败", "Latest route failure"),
                    route_failure_label(language, failure)
                ),
            );
        }
        ui.colored_label(
            MUTED,
            label(
                language,
                "以上是 Core 持久化的最近观测快照，不是实时连接列表；超过 30 秒请按延迟状态理解。",
                "This is Core's persisted latest observation, not a live connection list; after 30 seconds treat it as delayed.",
            ),
        );
        if age_s > 300 && last.runtime == NetworkRuntimeState::Running {
            ui.colored_label(
                WARNING,
                label(
                    language,
                    "后台可能已退出或长时间没有网络事件，请检查 Core 状态。",
                    "The backend may have exited or received no network events for a long time; check Core status.",
                ),
            );
        }
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

fn scope_label(language: Language, scope: NetworkAddressScopeV1) -> &'static str {
    match (language, scope) {
        (Language::Zh, NetworkAddressScopeV1::LoopbackOnly) => "仅回环",
        (Language::Zh, NetworkAddressScopeV1::LanOnly) => "局域网",
        (Language::Zh, NetworkAddressScopeV1::InternetOnly) => "互联网",
        (Language::Zh, NetworkAddressScopeV1::Hybrid) => "混合",
        (Language::Zh, NetworkAddressScopeV1::RelayOnly) => "仅中继",
        (Language::En, NetworkAddressScopeV1::LoopbackOnly) => "Loopback only",
        (Language::En, NetworkAddressScopeV1::LanOnly) => "LAN only",
        (Language::En, NetworkAddressScopeV1::InternetOnly) => "Internet only",
        (Language::En, NetworkAddressScopeV1::Hybrid) => "Hybrid",
        (Language::En, NetworkAddressScopeV1::RelayOnly) => "Relay only",
    }
}

fn scope_code(scope: NetworkAddressScopeV1) -> &'static str {
    match scope {
        NetworkAddressScopeV1::LoopbackOnly => "loopback",
        NetworkAddressScopeV1::LanOnly => "lan",
        NetworkAddressScopeV1::InternetOnly => "internet",
        NetworkAddressScopeV1::Hybrid => "hybrid",
        NetworkAddressScopeV1::RelayOnly => "relay",
    }
}

fn age_label(language: Language, age_s: i64) -> String {
    match language {
        Language::Zh if age_s < 60 => format!("上报于 {age_s} 秒前"),
        Language::Zh if age_s < 3_600 => format!("上报于 {} 分钟前", age_s / 60),
        Language::Zh => format!("上报于 {} 小时前", age_s / 3_600),
        Language::En if age_s < 60 => format!("reported {age_s}s ago"),
        Language::En if age_s < 3_600 => format!("reported {}m ago", age_s / 60),
        Language::En => format!("reported {}h ago", age_s / 3_600),
    }
}

fn report_freshness(language: Language, age_s: i64) -> (&'static str, eframe::egui::Color32) {
    if age_s <= 30 {
        (label(language, "状态新鲜", "Fresh status"), SUCCESS)
    } else if age_s <= 300 {
        (label(language, "状态有延迟", "Delayed status"), WARNING)
    } else {
        (
            label(language, "快照可能过期", "Snapshot may be stale"),
            DANGER,
        )
    }
}

fn reachability_label(language: Language, reachability: NetworkReachability) -> &'static str {
    match (language, reachability) {
        (Language::Zh, NetworkReachability::Unreported) => "尚未上报",
        (Language::Zh, NetworkReachability::Unknown) => "未知",
        (Language::Zh, NetworkReachability::Private) => "仅内网/需中继",
        (Language::Zh, NetworkReachability::Public) => "公网可达",
        (Language::En, NetworkReachability::Unreported) => "Not reported",
        (Language::En, NetworkReachability::Unknown) => "Unknown",
        (Language::En, NetworkReachability::Private) => "Private or relay required",
        (Language::En, NetworkReachability::Public) => "Publicly reachable",
    }
}

fn route_failure_label(language: Language, failure: NetworkRouteFailure) -> &'static str {
    match (language, failure) {
        (Language::Zh, NetworkRouteFailure::DirectUnavailable) => "直连不可用",
        (Language::Zh, NetworkRouteFailure::RelayUnavailable) => "中继不可用",
        (Language::Zh, NetworkRouteFailure::HolePunchFailed) => "打洞失败",
        (Language::Zh, NetworkRouteFailure::TimedOut) => "超时",
        (Language::Zh, NetworkRouteFailure::PeerIdentityMismatch) => "对端身份不匹配",
        (Language::Zh, NetworkRouteFailure::Disconnected) => "已断开",
        (Language::En, NetworkRouteFailure::DirectUnavailable) => "Direct unavailable",
        (Language::En, NetworkRouteFailure::RelayUnavailable) => "Relay unavailable",
        (Language::En, NetworkRouteFailure::HolePunchFailed) => "Hole punch failed",
        (Language::En, NetworkRouteFailure::TimedOut) => "Timed out",
        (Language::En, NetworkRouteFailure::PeerIdentityMismatch) => "Peer identity mismatch",
        (Language::En, NetworkRouteFailure::Disconnected) => "Disconnected",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persisted_report_freshness_uses_explicit_age_thresholds() {
        assert_eq!(report_freshness(Language::Zh, 30), ("状态新鲜", SUCCESS));
        assert_eq!(report_freshness(Language::Zh, 31), ("状态有延迟", WARNING));
        assert_eq!(
            report_freshness(Language::En, 300),
            ("Delayed status", WARNING)
        );
        assert_eq!(
            report_freshness(Language::En, 301),
            ("Snapshot may be stale", DANGER)
        );
        assert_eq!(age_label(Language::Zh, 59), "上报于 59 秒前");
        assert_eq!(age_label(Language::En, 301), "reported 5m ago");
    }
}
