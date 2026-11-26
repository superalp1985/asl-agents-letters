use std::collections::HashMap;

use asl_store::dashboard::{ActivityRow, Dashboard};
use eframe::egui::{CollapsingHeader, RichText, Ui};

use super::{MUTED, age, table, text};
use crate::ui::locale::Language;

type SessionKey<'a> = (&'a str, &'a str, Option<&'a str>);

fn sessions(rows: &[ActivityRow]) -> Vec<(SessionKey<'_>, Vec<&ActivityRow>)> {
    let mut positions = HashMap::new();
    let mut groups: Vec<(_, Vec<_>)> = Vec::new();
    for row in rows {
        let key = (
            row.scope.as_str(),
            row.context_id.as_str(),
            (row.scope == "direct").then_some(row.peer_id.as_str()),
        );
        let index = *positions.entry(key).or_insert_with(|| {
            groups.push((key, Vec::new()));
            groups.len() - 1
        });
        groups[index].1.push(row);
    }
    groups
}

pub(super) fn show(ui: &mut Ui, data: &Dashboard, now: i64, language: Language) {
    if data.activity.is_empty() {
        ui.label(RichText::new(label(language, "暂无活动", "No activity")).color(MUTED));
        return;
    }
    for (key @ (scope, id, peer), events) in sessions(&data.activity) {
        let short_id = || id.chars().take(12).collect::<String>();
        let session_label = match peer {
            Some(peer) => {
                let suffix = peer.get(peer.len().saturating_sub(8)..).unwrap_or(peer);
                format!("{} / {suffix}", short_id())
            }
            None => data
                .groups
                .iter()
                .find(|room| room.group_id == id && !room.name.is_empty())
                .map(|room| room.name.chars().take(24).collect())
                .unwrap_or_else(short_id),
        };
        let latest = events[0];
        let title = format!(
            "{} · {} · {} {} · {}",
            scope_text(scope, language),
            session_label,
            events.len(),
            label(language, "条", "events"),
            age(latest.created_at_ms, now, language)
        );
        CollapsingHeader::new(title).id_salt(key).show(ui, |ui| {
            let context = if peer.is_some() {
                label(language, "任务 ID", "Task ID")
            } else {
                label(language, "群组 ID", "Group ID")
            };
            ui.label(format!("{context}  {id}"));
            table(
                ui,
                [
                    label(language, "时间", "Time"),
                    label(language, "方向", "Direction"),
                    label(language, "类型", "Type"),
                    label(language, "内容", "Content"),
                    "AgentId",
                    label(language, "设备 PeerId", "Device PeerId"),
                ],
                [1.0, 0.7, 0.8, 2.4, 1.8, 1.8],
                &events,
                "",
                |row| {
                    [
                        age(row.created_at_ms, now, language),
                        match row.direction.as_deref() {
                            Some("in") => label(language, "收到", "Received"),
                            Some("out") => label(language, "发出", "Sent"),
                            _ => label(language, "群状态", "Group state"),
                        }
                        .into(),
                        text(&row.kind, language).into(),
                        row.preview
                            .as_deref()
                            .unwrap_or_default()
                            .chars()
                            .take(120)
                            .collect::<String>(),
                        row.agent_id.clone().unwrap_or_default(),
                        row.peer_id.clone(),
                    ]
                },
            );
        });
    }
}

fn scope_text(scope: &str, language: Language) -> String {
    match scope {
        "direct" => label(language, "直连", "Direct").into(),
        "group" => label(language, "群组", "Group").into(),
        _ => text(scope, language).to_owned(),
    }
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separates_direct_devices_and_rooms_with_the_same_id_and_keeps_recent_order() {
        let event = |scope: &str, peer: &str, time| ActivityRow {
            scope: scope.into(),
            context_id: "shared-id".into(),
            direction: Some("in".into()),
            kind: "query".into(),
            peer_id: peer.into(),
            agent_id: None,
            created_at_ms: time,
            preview: None,
        };
        let rows = [
            event("group", "a", 4),
            event("direct", "b", 3),
            event("group", "b", 2),
            event("direct", "a", 1),
        ];
        let groups = sessions(&rows);
        assert_eq!(groups.len(), 3);
        assert_eq!(groups[0].0, ("group", "shared-id", None));
        assert_eq!(groups[0].1[1].created_at_ms, 2);
        assert_eq!(groups[1].0.2, Some("b"));
        assert_eq!(groups[2].0.2, Some("a"));
    }
}
