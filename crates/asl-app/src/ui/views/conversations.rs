use std::collections::HashMap;

use asl_store::dashboard::{ActivityRow, Dashboard};
use eframe::egui::{CollapsingHeader, RichText, Ui};

use super::{MUTED, age, table, text};

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

pub(super) fn show(ui: &mut Ui, data: &Dashboard, now: i64) {
    if data.activity.is_empty() {
        ui.label(RichText::new("暂无活动").color(MUTED));
        return;
    }
    for (key @ (scope, id, peer), events) in sessions(&data.activity) {
        let short_id = || id.chars().take(12).collect::<String>();
        let label = match peer {
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
            "{} · {} · {} 条 · {}",
            text(scope),
            label,
            events.len(),
            age(latest.created_at_ms, now)
        );
        CollapsingHeader::new(title).id_salt(key).show(ui, |ui| {
            let context = if peer.is_some() {
                "任务 ID"
            } else {
                "群组 ID"
            };
            ui.label(format!("{context}  {id}"));
            table(
                ui,
                ["时间", "方向", "类型", "AgentId", "设备 PeerId"],
                [1.0, 0.7, 1.0, 2.0, 2.0],
                &events,
                "",
                |row| {
                    [
                        age(row.created_at_ms, now),
                        match row.direction.as_deref() {
                            Some("in") => "收到",
                            Some("out") => "发出",
                            _ => "群状态",
                        }
                        .into(),
                        text(&row.kind).into(),
                        row.agent_id.clone().unwrap_or_default(),
                        row.peer_id.clone(),
                    ]
                },
            );
        });
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
