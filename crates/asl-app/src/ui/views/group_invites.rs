use crate::ui::LocalAction;
use asl_store::{dashboard::Dashboard, group_state::invite_review::Outcome};
use eframe::egui::{self, RichText};

use super::super::locale::Language;

pub(super) fn show(
    ui: &mut egui::Ui,
    data: &Dashboard,
    language: Language,
    enabled: bool,
    action: &mut Option<LocalAction>,
) {
    let status = data.group_decision.as_ref().map(|r| r.outcome);
    if data.group_invitations.is_empty() && status.is_none() {
        return;
    }
    ui.separator();
    ui.label(RichText::new(label(language, "入群邀请", "Group invitations")).strong());
    if let Some(outcome) = status {
        ui.weak(match outcome {
            Outcome::Queued => label(language, "上次操作：等待 Core 处理", "Queued for Core"),
            Outcome::Applying => label(language, "上次操作：处理中", "Core is processing"),
            Outcome::Declined => label(language, "上次操作：已拒绝", "Declined"),
            Outcome::JoinQueued => label(
                language,
                "加入请求已排队，等待群组确认",
                "Join queued, waiting for group confirmation",
            ),
            Outcome::ApprovedNotSent => label(
                language,
                "已批准，加入请求未发出",
                "Approved, join request not sent",
            ),
            Outcome::Failed => label(
                language,
                "操作未完成，请刷新邀请",
                "Operation failed, refresh invitations",
            ),
            Outcome::Unconfirmed => label(
                language,
                "上次操作未确认，不会自动重试",
                "Not confirmed, will not retry automatically",
            ),
        });
    }
    let enabled = enabled && !matches!(status, Some(Outcome::Queued | Outcome::Applying));
    for invite in &data.group_invitations {
        ui.push_id(&invite.tag, |ui| {
            ui.label(format!(
                "{} {} · {} {}",
                label(language, "群", "Group"),
                invite.room,
                label(language, "版本", "Epoch"),
                invite.epoch
            ));
            ui.label(format!(
                "{} {}",
                label(language, "邀请方", "Inviter"),
                invite.inviter
            ))
            .on_hover_text(format!(
                "{} {}",
                label(language, "设备", "Device"),
                invite.device
            ));
            ui.horizontal_wrapped(|ui| {
                let commands: &[(&str, &str)] = if invite.approved {
                    &[(label(language, "重试加入", "Retry join"), "retry")]
                } else {
                    &[
                        (label(language, "同意加入", "Accept"), "approve"),
                        (label(language, "拒绝", "Reject"), "reject"),
                    ]
                };
                for &(label, cmd) in commands {
                    if ui
                        .add_enabled(enabled && action.is_none(), egui::Button::new(label))
                        .clicked()
                    {
                        *action = Some(LocalAction::new(
                            "group-invites",
                            [cmd.into(), invite.tag.as_str().into()],
                        ));
                    }
                }
            });
        });
    }
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}
