use std::{collections::BTreeSet, ffi::OsString};

use asl_store::{dashboard::Dashboard, public_profile::ProfileSigningApproval};
use eframe::egui::{Button, RichText, Ui};

use super::{LocalAction, MUTED};

#[derive(Default)]
pub(super) struct ProfileForm {
    agent: Option<String>,
    approval: Option<ProfileSigningApproval>,
    selected: BTreeSet<u32>,
}

impl ProfileForm {
    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        data: &Dashboard,
        now_ms: u64,
        actions_enabled: bool,
        action: &mut Option<LocalAction>,
    ) {
        ui.label(RichText::new("身份资料").strong());
        ui.label(RichText::new("网络披露：未发布").color(MUTED));
        let Some(agent) = &data.identity.agent_id else {
            ui.label("未建立本机身份");
            return;
        };
        let status = &data.profile_signing;
        let approval = status
            .approval
            .as_ref()
            .filter(|approval| bs58::encode(approval.agent_id.as_bytes()).into_string() == *agent);
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
            (None, _) => ui.label("未授权本机签名"),
            (Some(_), None) => ui.label("已授权 · 尚无未过期的签名记录"),
            (Some(_), Some(record)) => ui.label(format!("上次本机签名 · 序号 {}", record.sequence)),
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
                    actions_enabled && changed && !self.selected.is_empty(),
                    Button::new("授权本机签名"),
                )
                .clicked()
            {
                let args = [OsString::from("approve-local-signing"), agent.into()]
                    .into_iter()
                    .chain(self.selected.iter().map(|id| id.to_string().into()))
                    .collect();
                *action = Some(LocalAction {
                    command: "profile",
                    args,
                });
            }
            if ui
                .add_enabled(
                    actions_enabled && status.approval.is_some(),
                    Button::new("撤销签名授权"),
                )
                .clicked()
            {
                *action = Some(LocalAction::new("profile", ["revoke".into()]));
            }
        });
    }
}

fn topic_labels() -> impl Iterator<Item = (u32, &'static str)> {
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
