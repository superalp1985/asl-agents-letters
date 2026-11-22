use asl_app::checkpoint_access::{CheckpointStatus, parse_candidate};
use asl_types::error::AslError;
use eframe::egui::{Button, RichText, TextEdit, Ui};

use super::{LocalAction, MUTED};

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
        actions_enabled: bool,
        action: &mut Option<LocalAction>,
    ) {
        ui.label(RichText::new("链身份检查点").strong());
        let status = match snapshot {
            Ok(Some(status)) => status,
            Ok(None) => {
                ui.label(RichText::new("未配置链身份").color(MUTED));
                return;
            }
            Err(_) => {
                ui.label("检查点状态不可用");
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
                "已应用"
            } else {
                "未应用"
            };
            ui.label(format!("上次尝试 slot {} · {label}", last.slot));
        }
        if let Some(pending) = status.pending {
            ui.label(format!("待启动验证 · slot {}", pending.slot));
            ui.label(alloy_primitives::hex::encode_prefixed(pending.beacon_root));
            if ui
                .add_enabled(actions_enabled, Button::new("取消待验证更新"))
                .clicked()
            {
                *action = Some(LocalAction::new("checkpoint", ["cancel".into()]));
            }
            return;
        }
        if !status.snapshot_present {
            ui.label("未找到与当前检查点匹配的链快照");
            return;
        }
        let slot_edited = ui
            .add(
                TextEdit::singleline(&mut self.slot)
                    .hint_text("新 slot")
                    .char_limit(20),
            )
            .changed();
        let root_edited = ui
            .add(
                TextEdit::singleline(&mut self.root)
                    .hint_text("新 Beacon root")
                    .char_limit(66),
            )
            .changed();
        if slot_edited || root_edited {
            self.reviewed_context = None;
        }
        let mut confirmed = self.reviewed_context.as_deref() == Some(status.context.as_str());
        if ui
            .checkbox(&mut confirmed, "已从可信来源核对 slot 和根哈希")
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
                Button::new("授权下次启动验证"),
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
