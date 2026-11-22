use asl_store::{dashboard::Dashboard, inbound_observations::MAX_OBSERVATION_DAYS};
use eframe::egui::{Button, ComboBox, Ui};

use super::{LocalAction, MUTED};

#[derive(Default)]
pub(super) struct RetentionForm {
    direct: Option<u8>,
    group: Option<u8>,
}

impl RetentionForm {
    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        data: &Dashboard,
        enabled: bool,
        action: &mut Option<LocalAction>,
    ) {
        for (kind, name, current, selected) in [
            (
                "direct",
                "直连浏览记录",
                data.direct_observation_days,
                &mut self.direct,
            ),
            (
                "group",
                "群来信浏览记录",
                data.group_observation_days,
                &mut self.group,
            ),
        ] {
            show_days(ui, (kind, name), current, selected, enabled, action);
        }
        ui.add_space(10.0);
    }
}

fn show_days(
    ui: &mut Ui,
    (kind, name): (&str, &str),
    current: u8,
    selected: &mut Option<u8>,
    enabled: bool,
    action: &mut Option<LocalAction>,
) {
    let mut days = selected.unwrap_or(current);
    ui.horizontal_wrapped(|ui| {
        ui.label(name);
        ComboBox::from_id_salt(("history-days", kind))
            .selected_text(label(days))
            .show_ui(ui, |ui| {
                for value in 0..=MAX_OBSERVATION_DAYS {
                    ui.selectable_value(&mut days, value, label(value));
                }
            });
        *selected = (days != current).then_some(days);
        let can_apply = enabled && action.is_none() && selected.is_some();
        if ui.add_enabled(can_apply, Button::new("应用期限")).clicked() {
            *action = Some(LocalAction::new(
                "retention",
                [kind.into(), days.to_string().into()],
            ));
            *selected = None;
        }
    });
    if days < current {
        let warning = if days == 0 {
            format!("应用后清空{name}，并停止记录。")
        } else {
            format!("应用后清除早于 {days} 天的{name}。")
        };
        ui.colored_label(MUTED, warning);
    }
}

fn label(days: u8) -> String {
    match days {
        0 => "不保存".into(),
        _ => format!("{days} 天"),
    }
}
