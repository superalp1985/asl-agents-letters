use std::ffi::OsString;

use asl_store::dashboard::Dashboard;
use eframe::egui::{self, RichText, Ui};

use super::{LocalAction, MUTED, locale::Language, qr};

#[derive(Default)]
pub(super) struct Form {
    note: String,
    minutes: u64,
    import: String,
}

impl Form {
    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        data: &Dashboard,
        now_ms: i64,
        language: Language,
        actions_enabled: bool,
        action: &mut Option<LocalAction>,
    ) {
        ui.label(
            RichText::new(label(language, "临时邀请", "Temporary invite"))
                .strong()
                .size(16.0),
        );
        ui.label(
            RichText::new(label(
                language,
                "有期限的邀请只用于建立首次联系人请求；不会授予文件、群组或模型权限。",
                "An expiring invite only starts the first contact request. It grants no file, group or model access.",
            ))
            .color(MUTED),
        );

        if self.minutes == 0 {
            self.minutes = 15;
        }
        ui.horizontal_wrapped(|ui| {
            ui.label(label(language, "附言（可选）", "Note (optional)"));
            ui.add(
                egui::TextEdit::singleline(&mut self.note)
                    .hint_text(label(language, "一句话说明", "One short sentence"))
                    .char_limit(80)
                    .desired_width(260.0),
            );
            egui::ComboBox::from_id_salt("contact-invite-expiry")
                .selected_text(expiry_label(self.minutes, language))
                .show_ui(ui, |ui| {
                    for minutes in [5, 15, 60, 1_440] {
                        ui.selectable_value(
                            &mut self.minutes,
                            minutes,
                            expiry_label(minutes, language),
                        );
                    }
                });
            if ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::new(label(language, "生成临时邀请", "Create invite")),
                )
                .clicked()
            {
                *action = Some(LocalAction::new(
                    "contact-invites",
                    [
                        OsString::from("create"),
                        OsString::from(self.minutes.to_string()),
                        OsString::from(self.note.clone()),
                    ],
                ));
            }
        });

        for invite in &data.contact_invites {
            let model = match invite_model(invite) {
                Ok(model) => model,
                Err(_) => continue,
            };
            let envelope = match model.to_envelope(u64::try_from(now_ms).unwrap_or_default()) {
                Ok(envelope) => envelope,
                Err(_) => continue,
            };
            let short_code = asl_app::contact_invite::short_code_envelope(model.inviter, &model);
            ui.separator();
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(label(language, "待使用邀请", "Active invite")).strong());
                ui.weak(format!(
                    "{}{}",
                    label(language, "到期：", "Expires: "),
                    remaining(invite.expires_at_ms, now_ms, language)
                ));
                if ui
                    .small_button(label(language, "复制邀请", "Copy invite"))
                    .clicked()
                {
                    ui.ctx().copy_text(envelope.clone());
                }
                if ui.small_button(label(language, "撤销", "Revoke")).clicked() {
                    *action = Some(LocalAction::new(
                        "contact-invites",
                        [
                            OsString::from("revoke"),
                            OsString::from(alloy_primitives::hex::encode(invite.invite_id.0)),
                        ],
                    ));
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(format!(
                        "{}: {short_code}",
                        label(
                            language,
                            "临时短码（已绑定本机 AgentId）",
                            "Temporary code (bound to this AgentId)"
                        )
                    ))
                    .monospace()
                    .small(),
                );
                if ui
                    .small_button(label(language, "复制短码", "Copy code"))
                    .clicked()
                {
                    ui.ctx().copy_text(short_code);
                }
            });
            ui.add(
                egui::Label::new(RichText::new(envelope.clone()).monospace())
                    .wrap()
                    .selectable(true),
            )
            .on_hover_text(envelope.clone());
            if let Err(error) = qr::show(ui, &envelope, 180.0) {
                ui.colored_label(ui.visuals().error_fg_color, format!("{error:?}"));
            }
        }

        ui.separator();
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.import)
                    .hint_text(label(
                        language,
                        "粘贴完整邀请或已绑定 AgentId 的临时短码",
                        "Paste an invite or a temporary code bound to its AgentId",
                    ))
                    .desired_width(420.0),
            );
            if ui
                .add_enabled(
                    actions_enabled && action.is_none() && !self.import.trim().is_empty(),
                    egui::Button::new(label(language, "导入邀请", "Import invite")),
                )
                .clicked()
            {
                *action = Some(LocalAction::new(
                    "contact-invites",
                    [OsString::from("import"), OsString::from(self.import.trim())],
                ));
            }
        });

        if !data.contact_invite_prompts.is_empty() {
            ui.separator();
            ui.label(
                RichText::new(label(
                    language,
                    "待确认联系人请求",
                    "Pending contact requests",
                ))
                .strong(),
            );
            for prompt in &data.contact_invite_prompts {
                if prompt.expires_at_ms <= u64::try_from(now_ms).unwrap_or_default() {
                    continue;
                }
                ui.group(|ui| {
                    ui.label(format!(
                        "{} · {}{}",
                        prompt.note,
                        label(language, "到期：", "Expires: "),
                        remaining(prompt.expires_at_ms, now_ms, language)
                    ));
                    ui.weak(bs58::encode(prompt.remote_agent.as_bytes()).into_string());
                    ui.horizontal_wrapped(|ui| {
                        if ui
                            .add_enabled(
                                actions_enabled && action.is_none(),
                                egui::Button::new(label(language, "同意添加", "Accept")),
                            )
                            .clicked()
                        {
                            *action = Some(LocalAction::new(
                                "contact-invites",
                                [
                                    OsString::from("approve"),
                                    OsString::from(alloy_primitives::hex::encode(
                                        prompt.prompt_id.0,
                                    )),
                                ],
                            ));
                        }
                        if ui
                            .add_enabled(
                                actions_enabled && action.is_none(),
                                egui::Button::new(label(language, "拒绝", "Reject")),
                            )
                            .clicked()
                        {
                            *action = Some(LocalAction::new(
                                "contact-invites",
                                [
                                    OsString::from("reject"),
                                    OsString::from(alloy_primitives::hex::encode(
                                        prompt.prompt_id.0,
                                    )),
                                ],
                            ));
                        }
                    });
                });
            }
        }
    }
}

fn invite_model(
    invite: &asl_store::contact_invites::ContactInvite,
) -> Result<asl_types::contact_invite::ContactInviteV1, asl_types::error::AslError> {
    Ok(asl_types::contact_invite::ContactInviteV1 {
        version: asl_types::contact_invite::CONTACT_INVITE_VERSION,
        invite_id: invite.invite_id,
        token: invite.token,
        inviter: invite.agent_id,
        created_at_ms: invite.created_at_ms,
        expires_at_ms: invite.expires_at_ms,
        note: invite.note.clone().unwrap_or_default(),
        signature: asl_types::ids::Signature65(invite.signature),
    })
}

fn expiry_label(minutes: u64, language: Language) -> String {
    match minutes {
        5 => label(language, "5 分钟", "5 minutes").into(),
        15 => label(language, "15 分钟", "15 minutes").into(),
        60 => label(language, "1 小时", "1 hour").into(),
        _ => label(language, "24 小时", "24 hours").into(),
    }
}

fn remaining(expires_at_ms: u64, now_ms: i64, _language: Language) -> String {
    let seconds = expires_at_ms
        .saturating_sub(u64::try_from(now_ms).unwrap_or_default())
        .div_ceil(1_000);
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3_600 {
        format!("{}m", seconds / 60)
    } else {
        format!("{}h", seconds / 3_600)
    }
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}
