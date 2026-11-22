use asl_store::inbound_observations::MAX_OBSERVATION_DAYS;
use eframe::egui::{Button, ComboBox, Ui};

use super::{LocalAction, MUTED};

#[derive(Default)]
pub(super) struct RetentionForm {
    selected: Option<u8>,
}

impl RetentionForm {
    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        current: u8,
        enabled: bool,
        action: &mut Option<LocalAction>,
    ) {
        let mut days = self.selected.unwrap_or(current);
        ui.horizontal_wrapped(|ui| {
            ui.label("直连浏览记录");
            ComboBox::from_id_salt("direct-history-days")
                .selected_text(label(days))
                .show_ui(ui, |ui| {
                    for value in 0..=MAX_OBSERVATION_DAYS {
                        ui.selectable_value(&mut days, value, label(value));
                    }
                });
            self.selected = (days != current).then_some(days);
            let can_apply = enabled && action.is_none() && self.selected.is_some();
            if ui.add_enabled(can_apply, Button::new("应用期限")).clicked() {
                *action = Some(LocalAction::new(
                    "retention",
                    ["direct".into(), days.to_string().into()],
                ));
                self.selected = None;
            }
        });
        if days < current {
            let warning = if days == 0 {
                "应用后会清空已有直连浏览记录，并停止保存新记录。".to_owned()
            } else {
                format!("应用后会立即清除早于 {days} 天的直连浏览记录。")
            };
            ui.colored_label(MUTED, warning);
        }
        ui.add_space(10.0);
    }
}

fn label(days: u8) -> String {
    match days {
        0 => "不保存".into(),
        _ => format!("{days} 天"),
    }
}
