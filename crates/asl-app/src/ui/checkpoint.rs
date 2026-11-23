use asl_app::checkpoint_access::{CheckpointStatus, parse_candidate};
use asl_types::error::AslError;
use eframe::egui::{Button, RichText, TextEdit, Ui};

use super::{LocalAction, MUTED, locale::Language};

#[derive(Default)]
pub(super) struct CheckpointForm {
    slot: String,
    root: String,
    reviewed_context: Option<String>,
}

impl CheckpointForm {
    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        snapshot: &Result<Option<CheckpointStatus>, AslError>,
        language: Language,
        actions_enabled: bool,
        action: &mut Option<LocalAction>,
    ) {
        ui.label(
            RichText::new(label(language, "链身份检查点", "Chain identity checkpoint")).strong(),
        );
        let status = match snapshot {
            Ok(Some(status)) => status,
            Ok(None) => {
                ui.label(
                    RichText::new(label(
                        language,
                        "未配置链身份",
                        "Chain identity not configured",
                    ))
                    .color(MUTED),
                );
                return;
            }
            Err(_) => {
                ui.label(label(
                    language,
                    "检查点状态不可用",
                    "Checkpoint status unavailable",
                ));
                return;
            }
        };
        ui.label(format!(
            "链 {} · 当前 slot {}",
            status.chain_id, status.current.slot
        ));
        ui.label(alloy_primitives::hex::encode_prefixed(
            status.current.beacon_root,
        ));
        if let Some(last) = status.last_attempt {
            let label = if last == status.current && status.snapshot_present {
                label(language, "已应用", "Applied")
            } else {
                label(language, "未应用", "Not applied")
            };
            ui.label(format!("上次尝试 slot {} · {label}", last.slot));
        }
        if let Some(pending) = status.pending {
            ui.label(format!(
                "{} · slot {}",
                label(language, "待启动验证", "Pending startup verification"),
                pending.slot
            ));
            ui.label(alloy_primitives::hex::encode_prefixed(pending.beacon_root));
            if ui
                .add_enabled(
                    actions_enabled,
                    Button::new(label(language, "取消待验证更新", "Cancel pending update")),
                )
                .clicked()
            {
                *action = Some(LocalAction::new("checkpoint", ["cancel".into()]));
            }
            return;
        }
        if !status.snapshot_present {
            ui.label(label(
                language,
                "未找到与当前检查点匹配的链快照",
                "No chain snapshot matches the current checkpoint",
            ));
            return;
        }
        let slot_edited = ui
            .add(
                TextEdit::singleline(&mut self.slot)
                    .hint_text(label(language, "新 slot", "New slot"))
                    .char_limit(20),
            )
            .changed();
        let root_edited = ui
            .add(
                TextEdit::singleline(&mut self.root)
                    .hint_text(label(language, "新 Beacon root", "New Beacon root"))
                    .char_limit(66),
            )
            .changed();
        if slot_edited || root_edited {
            self.reviewed_context = None;
        }
        let mut confirmed = self.reviewed_context.as_deref() == Some(status.context.as_str());
        if ui
            .checkbox(
                &mut confirmed,
                label(
                    language,
                    "已从可信来源核对 slot 和根哈希",
                    "I checked the slot and root hash against a trusted source",
                ),
            )
            .changed()
        {
            self.reviewed_context = confirmed.then(|| status.context.clone());
        }
        let candidate = parse_candidate(self.slot.trim(), self.root.trim())
            .ok()
            .filter(|candidate| candidate.slot > status.current.slot);
        if ui
            .add_enabled(
                actions_enabled && confirmed && candidate.is_some(),
                Button::new(label(
                    language,
                    "授权下次启动验证",
                    "Authorize next-start verification",
                )),
            )
            .clicked()
            && let Some(candidate) = candidate
        {
            *action = Some(LocalAction::new(
                "checkpoint",
                [
                    "stage".into(),
                    (&status.context).into(),
                    candidate.slot.to_string().into(),
                    alloy_primitives::hex::encode(candidate.beacon_root).into(),
                ],
            ));
            self.reviewed_context = None;
        }
    }
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}
