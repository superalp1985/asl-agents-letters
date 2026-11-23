use std::{collections::BTreeSet, ffi::OsString};

use asl_store::{
    dashboard::Dashboard,
    public_profile::{ProfilePublicationResult, ProfileSigningApproval},
};
use eframe::egui::{Button, RichText, Ui};

use super::{LocalAction, MUTED, art::Glyph, locale::Language};

#[derive(Default)]
pub(super) struct ProfileForm {
    lookup_target: String,
    agent: Option<String>,
    approval: Option<ProfileSigningApproval>,
    selected: BTreeSet<u32>,
}

impl ProfileForm {
    pub(super) fn lookup(
        &mut self,
        ui: &mut Ui,
        data: &Dashboard,
        language: Language,
        actions_enabled: bool,
        action: &mut Option<LocalAction>,
    ) {
        use asl_store::profile_lookup::LookupState;
        ui.horizontal_wrapped(|ui| {
            ui.add(
                eframe::egui::TextEdit::singleline(&mut self.lookup_target)
                    .hint_text("完整 AgentId")
                    .char_limit(44),
            );
            let target = self.lookup_target.trim();
            let valid = bs58::decode(target).onto(&mut [0u8; 32][..]) == Ok(32);
            if ui
                .add_enabled(
                    actions_enabled && !data.network_pause_requested && valid,
                    Button::new(label(language, "查找公开资料", "Find public profile")),
                )
                .on_hover_text("查询会向 DHT 邻居透露目标资料键，不会添加联系人。")
                .clicked()
            {
                *action = Some(LocalAction::new(
                    "profile",
                    ["lookup".into(), target.into()],
                ));
            }
        });
        if let Some(request) = &data.profile_lookup {
            let label = match request.state {
                LookupState::Queued => label(language, "已排队", "Queued"),
                LookupState::Searching => label(language, "查找中", "Searching"),
                LookupState::Available => {
                    label(language, "已找到验签资料", "Verified profile found")
                }
                LookupState::NoLongerVisible => label(
                    language,
                    "上次找到的资料现已不可见",
                    "The previously found profile is no longer visible",
                ),
                LookupState::NoVerifiedResult => label(
                    language,
                    "到期未获得可展示的验签资料",
                    "No verified profile became available before expiry",
                ),
                LookupState::Unavailable => label(language, "当前不可查询", "Unavailable"),
            };
            ui.horizontal_wrapped(|ui| {
                ui.label(label);
                ui.weak(bs58::encode(request.target.as_bytes()).into_string());
            });
        }
    }
    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        data: &Dashboard,
        now_ms: u64,
        language: Language,
        actions_enabled: bool,
        action: &mut Option<LocalAction>,
    ) {
        ui.label(RichText::new(label(language, "身份资料", "Identity profile")).strong());
        let Some(agent) = &data.identity.agent_id else {
            ui.label(label(
                language,
                "未建立本机身份",
                "Local identity is not established",
            ));
            return;
        };
        let status = &data.profile_signing;
        let approval = status
            .approval
            .as_ref()
            .filter(|approval| bs58::encode(approval.agent_id.as_bytes()).into_string() == *agent);
        let disclosure = if status.change_pending {
            label(
                language,
                "资料授权变更中 · 正在等待旧发布结束",
                "Profile grant is changing · waiting for the previous publication",
            )
        } else if approval.is_some_and(|approval| approval.publish) {
            match status.last_publication {
                None => label(
                    language,
                    "公开已授权 · 尚未提交",
                    "Public sharing authorized · not submitted",
                ),
                Some(ProfilePublicationResult::Submitted) => label(
                    language,
                    "上次已提交 Net · 未记录 DHT 应答",
                    "Submitted to Net · no DHT acknowledgement",
                ),
                Some(ProfilePublicationResult::DhtAcknowledged) => {
                    label(language, "已收到 DHT 应答", "DHT acknowledged")
                }
                Some(ProfilePublicationResult::NoAcknowledgment) => {
                    label(language, "未收到 DHT 应答", "No DHT acknowledgement")
                }
            }
        } else {
            label(language, "网络公开：关闭", "Network publication: off")
        };
        let public = approval.is_some_and(|approval| approval.publish);
        ui.horizontal(|ui| {
            super::views::inline_glyph(
                ui,
                if public {
                    Glyph::IdentityPublic
                } else {
                    Glyph::IdentityAnonymous
                },
            );
            ui.label(RichText::new(disclosure).color(MUTED));
        });
        if self.agent.as_ref() != Some(agent) || self.approval.as_ref() != approval {
            self.agent = Some(agent.clone());
            self.approval = approval.cloned();
            self.selected = approval
                .into_iter()
                .flat_map(|approval| approval.topics.iter().copied())
                .collect();
        }
        match (
            approval,
            status
                .last_candidate
                .filter(|record| (record.issued_at_ms..record.expires_at_ms).contains(&now_ms)),
        ) {
            (None, _) => ui.label(label(
                language,
                "未授权本机签名",
                "Local signing is not authorized",
            )),
            (Some(_), None) => ui.label(label(
                language,
                "已授权 · 尚无未过期的签名记录",
                "Authorized · no unexpired signature",
            )),
            (Some(_), Some(record)) => ui.label(format!(
                "{} · {} {}",
                label(language, "上次本机签名", "Last local signature"),
                label(language, "序号", "sequence"),
                record.sequence
            )),
        };
        ui.horizontal_wrapped(|ui| {
            for (id, label) in topic_labels() {
                let mut enabled = self.selected.contains(&id);
                if ui.checkbox(&mut enabled, label).changed() {
                    if enabled {
                        self.selected.insert(id);
                    } else {
                        self.selected.remove(&id);
                    }
                }
            }
        });
        let changed = approval.is_none_or(|approval| {
            !self
                .selected
                .iter()
                .copied()
                .eq(approval.topics.iter().copied())
        });
        ui.horizontal_wrapped(|ui| {
            if ui
                .add_enabled(
                    actions_enabled
                        && !self.selected.is_empty()
                        && (changed || approval.is_some_and(|approval| approval.publish)),
                    Button::new(label(language, "授权本机签名", "Authorize local signing")),
                )
                .clicked()
            {
                *action = Some(self.approve("approve-local-signing", agent));
            }
            if ui
                .add_enabled(
                    actions_enabled
                        && !self.selected.is_empty()
                        && (changed || approval.is_some_and(|approval| !approval.publish)),
                    Button::new(label(language, "授权公开所选主题", "Authorize selected topics")),
                )
                .on_hover_text("公开 AgentId 和所选主题。另行授权后可附头像内容 ID，不发送图片。已收到的副本无法撤回。")
                .clicked()
            {
                *action = Some(self.approve("approve-publication", agent));
            }
            if ui
                .add_enabled(
                    actions_enabled && status.approval.is_some(),
                    Button::new(label(language, "撤销资料授权", "Revoke profile grant")),
                )
                .clicked()
            {
                *action = Some(LocalAction::new("profile", ["revoke".into()]));
            }
        });
    }

    fn approve(&self, command: &str, agent: &str) -> LocalAction {
        let args = [OsString::from(command), agent.into()]
            .into_iter()
            .chain(self.selected.iter().map(|id| id.to_string().into()))
            .collect();
        LocalAction {
            command: "profile",
            args,
        }
    }
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}

pub(super) fn topic_labels() -> impl Iterator<Item = (u32, &'static str)> {
    // These leading columns in the frozen vocabulary contain no CSV escapes.
    include_str!("../../../../specs/vocabulary-v1.csv")
        .lines()
        .filter_map(|line| {
            let mut fields = line.splitn(6, ',');
            let vocabulary = fields.next()?;
            let id = fields.next()?.parse().ok()?;
            let kind = fields.next()?;
            let label = fields.nth(1)?;
            (vocabulary == "1" && kind == "topic").then_some((id, label))
        })
}
