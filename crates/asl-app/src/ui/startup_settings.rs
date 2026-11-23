use asl_app::network_settings::NetworkAddressScopeV1;
use asl_store::dashboard::Dashboard;
use eframe::egui::{self, Context, RichText, Ui};

use super::{MUTED, Snapshot, locale::Language, views::Page};

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Decision {
    Keep,
    Open(Page),
}

pub(super) fn show(ctx: &Context, snapshot: &Snapshot, language: Language) -> Option<Decision> {
    egui::Modal::new(egui::Id::new("startup-settings"))
        .show(ctx, |ui| {
            let available = ctx.content_rect();
            ui.set_width((available.width() - 40.0).clamp(240.0, 480.0));
            ui.heading(match language {
                Language::Zh => "确认启动设置",
                Language::En => "Review startup settings",
            });
            ui.colored_label(
                MUTED,
                match language {
                    Language::Zh => "保留当前设置不会更改本机授权。",
                    Language::En => "Keeping these settings does not change local grants.",
                },
            );
            ui.separator();

            let mut destination = None;
            egui::ScrollArea::vertical()
                .max_height((available.height() - 122.0).clamp(80.0, 380.0))
                .show(ui, |ui| {
                    for (label, value, page) in rows(snapshot, language) {
                        if row(ui, label, &value, page, language) {
                            destination = Some(page);
                        }
                    }
                });
            ui.separator();
            if ui
                .button(match language {
                    Language::Zh => "保留当前设置",
                    Language::En => "Keep current settings",
                })
                .clicked()
            {
                Some(Decision::Keep)
            } else {
                destination.map(Decision::Open)
            }
        })
        .inner
}

fn row(ui: &mut Ui, label: &str, value: &str, page: Page, language: Language) -> bool {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(label).strong());
        ui.label(value);
        ui.link(language.page(page))
            .on_hover_text(match language {
                Language::Zh => format!("前往{}调整：{label}", language.page(page)),
                Language::En => format!("Open {} to change this setting", language.page(page)),
            })
            .clicked()
    })
    .inner
}

fn rows(snapshot: &Snapshot, language: Language) -> [(&'static str, String, Page); 9] {
    let data = &snapshot.dashboard;
    let (direct, group) = inbound_summary_for(data, language);
    let network = match &snapshot.network_config {
        Ok(config) if data.force_relay_only => {
            if config.clone().with_relay_only_override(true).is_ok() {
                label(language, "仅中继", "Relay only")
            } else {
                label(
                    language,
                    "仅中继配置无效",
                    "Relay-only configuration invalid",
                )
            }
        }
        Ok(config) => match config.address_scope {
            NetworkAddressScopeV1::LoopbackOnly => label(language, "仅本机回环", "Local loopback"),
            NetworkAddressScopeV1::LanOnly => label(language, "仅局域网", "LAN only"),
            NetworkAddressScopeV1::InternetOnly => label(language, "仅公网", "Internet only"),
            NetworkAddressScopeV1::Hybrid => label(language, "局域网与公网", "LAN and Internet"),
            NetworkAddressScopeV1::RelayOnly => label(language, "仅中继", "Relay only"),
        },
        Err(_) => label(language, "配置无效", "Invalid configuration"),
    };
    let pause = if data.network_pause_requested {
        label(language, "已请求暂停", "Pause requested")
    } else {
        label(language, "未请求暂停", "No pause requested")
    };
    let profile = if data.profile_signing.change_pending {
        label(language, "资料授权变更中", "Profile grant changing")
    } else {
        match data.profile_signing.approval.as_ref().filter(|approval| {
            data.identity.agent_id.as_ref().is_some_and(|agent| {
                bs58::encode(approval.agent_id.as_bytes()).into_string() == *agent
            })
        }) {
            Some(approval) if approval.publish => label(
                language,
                "签名与公开已授权",
                "Signing and publication approved",
            ),
            Some(_) => label(language, "仅授权本机签名", "Local signing only"),
            None => label(
                language,
                "签名与公开均未授权",
                "Signing and publication disabled",
            ),
        }
    };
    let model = match &snapshot.model_endpoints {
        Ok(endpoints) if endpoints.is_empty() => label(language, "未配置", "Not configured").into(),
        Ok(endpoints) => format!(
            "{} {}/{}",
            label(language, "已授权", "Authorized"),
            endpoints
                .iter()
                .filter(|endpoint| endpoint.authorized)
                .count(),
            endpoints.len()
        ),
        Err(_) => label(language, "无法读取", "Unreadable").into(),
    };
    let checkpoint = match &snapshot.checkpoints {
        Ok(Some(status)) if status.pending.is_some() => {
            label(language, "有待处理更新", "Update pending")
        }
        Ok(Some(_)) => label(language, "无待处理更新", "No pending update"),
        Ok(None) => label(language, "未配置", "Not configured"),
        Err(_) => label(language, "无法读取", "Unreadable"),
    };
    [
        (
            label(language, "直连接收", "Direct inbound"),
            direct.into(),
            Page::Overview,
        ),
        (
            label(language, "群组接收", "Group inbound"),
            group,
            Page::Groups,
        ),
        (
            label(language, "浏览记录保留", "Observation retention"),
            format!(
                "{}: {} · {}: {}",
                label(language, "直连", "Direct"),
                super::retention::label(data.direct_observation_days, language),
                label(language, "群组", "Group"),
                super::retention::label(data.group_observation_days, language),
            ),
            Page::Activity,
        ),
        (
            label(language, "文件传输", "File transfer"),
            format!(
                "{}: {} · {}: {}",
                label(language, "接收", "Receive"),
                transfer_mode_for(&data.download_mode, language),
                label(language, "发送", "Send"),
                transfer_mode_for(&data.upload_mode, language),
            ),
            Page::Transfers,
        ),
        (
            label(language, "对等网络设置", "Peer network"),
            format!(
                "{pause} · {}: {network}",
                label(language, "下次启动后台", "Next startup")
            ),
            Page::Nodes,
        ),
        (
            label(language, "短码发现", "Short-code discovery"),
            if data.binding_code_public {
                label(language, "公开", "On")
            } else {
                label(language, "关闭", "Off")
            }
            .into(),
            Page::Contacts,
        ),
        (
            label(language, "身份资料", "Identity profile"),
            profile.into(),
            Page::Nodes,
        ),
        (
            label(language, "模型端点", "Model endpoints"),
            model,
            Page::Access,
        ),
        (
            label(language, "可信检查点更新", "Trusted checkpoint"),
            checkpoint.into(),
            Page::Nodes,
        ),
    ]
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}

#[cfg(test)]
fn inbound_summary(data: &Dashboard) -> (&'static str, String) {
    inbound_summary_for(data, Language::Zh)
}

fn inbound_summary_for(data: &Dashboard, language: Language) -> (&'static str, String) {
    let direct = if data.direct_inbound_unset {
        label(language, "未设置（默认关闭）", "Unset (off by default)")
    } else {
        match data.direct_inbound_mode.as_str() {
            "browse" => label(language, "只浏览，不回答", "Browse only"),
            "answer" => label(language, "允许回答", "Allow answers"),
            _ => label(language, "关闭", "Off"),
        }
    };
    let group = format!(
        "{}{} · {}",
        if data.group_inbound_unset {
            format!(
                "{} · ",
                label(language, "未设置（默认）", "Unset (default)")
            )
        } else {
            String::new()
        },
        if data.group_inbound.browse_enabled {
            label(language, "浏览开启", "Browse on")
        } else {
            label(language, "浏览关闭", "Browse off")
        },
        if data.group_inbound.answer_enabled {
            label(language, "自动回答开启", "Auto-answer on")
        } else {
            label(language, "自动回答关闭", "Auto-answer off")
        },
    );
    (direct, group)
}

fn transfer_mode_for(mode: &str, language: Language) -> &'static str {
    match mode {
        "ask" => label(language, "每次询问", "Ask each time"),
        "automatic" => label(language, "授权范围内自动", "Automatic within grants"),
        _ => label(language, "未知", "Unknown"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use asl_app::network_settings::NetworkSettingsV1;
    use asl_store::group_state::GroupInboundPolicy;
    use egui::{
        Event, FullOutput, Modifiers, PointerButton, Pos2, RawInput, Rect, Shape, pos2, vec2,
    };

    #[test]
    fn distinguishes_direct_unset_off_browse_and_answer() {
        for (mode, unset, expected) in [
            ("off", true, "未设置（默认关闭）"),
            ("off", false, "关闭"),
            ("browse", false, "只浏览，不回答"),
            ("answer", false, "允许回答"),
        ] {
            let dashboard = Dashboard {
                direct_inbound_mode: mode.into(),
                direct_inbound_unset: unset,
                ..Dashboard::default()
            };
            assert_eq!(inbound_summary(&dashboard).0, expected);
        }
    }

    #[test]
    fn group_browsing_and_answering_are_reported_independently() {
        for (browse_enabled, answer_enabled, unset, expected) in [
            (
                true,
                false,
                true,
                "未设置（默认） · 浏览开启 · 自动回答关闭",
            ),
            (true, false, false, "浏览开启 · 自动回答关闭"),
            (false, false, false, "浏览关闭 · 自动回答关闭"),
            (false, true, false, "浏览关闭 · 自动回答开启"),
            (true, true, false, "浏览开启 · 自动回答开启"),
        ] {
            let dashboard = Dashboard {
                group_inbound: GroupInboundPolicy {
                    browse_enabled,
                    answer_enabled,
                },
                group_inbound_unset: unset,
                ..Dashboard::default()
            };
            assert_eq!(inbound_summary(&dashboard).1, expected);
        }
    }

    #[test]
    fn dialog_only_returns_a_decision_on_an_explicit_choice() {
        for (label, expected) in [
            ("保留当前设置", Decision::Keep),
            ("群组", Decision::Open(Page::Groups)),
        ] {
            let ctx = Context::default();
            let snapshot = Snapshot {
                avatar: Ok(None),
                dashboard: Dashboard::default(),
                network_config: Ok(NetworkSettingsV1::default()),
                model_endpoints: Ok(Vec::new()),
                checkpoints: Ok(None),
            };
            let size = Rect::from_min_size(Pos2::ZERO, vec2(460.0, 300.0));
            let frame = |events| {
                let mut decision = None;
                let output = ctx.run_ui(
                    RawInput {
                        screen_rect: Some(size),
                        events,
                        ..RawInput::default()
                    },
                    |_| decision = show(&ctx, &snapshot, Language::Zh),
                );
                (decision, output)
            };
            let click = |pos, pressed| Event::PointerButton {
                pos,
                button: PointerButton::Primary,
                pressed,
                modifiers: Modifiers::NONE,
            };
            assert_eq!(frame(Vec::new()).0, None);
            let outside = pos2(2.0, 2.0);
            assert_eq!(
                frame(vec![Event::PointerMoved(outside), click(outside, true)]).0,
                None
            );
            let (decision, output) = frame(vec![click(outside, false)]);
            assert_eq!(decision, None);

            let target = painted_label(&output, label);
            assert_eq!(
                frame(vec![Event::PointerMoved(target), click(target, true)]).0,
                None
            );
            assert_eq!(frame(vec![click(target, false)]).0, Some(expected));
        }
    }

    fn painted_label(output: &FullOutput, label: &str) -> Pos2 {
        output
            .shapes
            .iter()
            .find_map(|clipped| match &clipped.shape {
                Shape::Text(text) if text.galley.text() == label => {
                    let center = text.visual_bounding_rect().center();
                    clipped.clip_rect.contains(center).then_some(center)
                }
                _ => None,
            })
            .unwrap_or_else(|| panic!("missing visible label {label}"))
    }
}
