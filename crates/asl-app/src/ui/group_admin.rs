use std::collections::BTreeSet;

use asl_app::network_settings::NetworkSettingsV1;
use asl_store::{
    dashboard::Dashboard,
    group_state::operator::{
        AdminJoinRequest, AdminMember, AdminOutcome, AdminPeer, AdminRoom, AdminSnapshot,
    },
};
use asl_types::error::AslError;
use eframe::egui::{self, RichText};

use super::{LocalAction, locale::Language};

#[derive(Default)]
pub(super) struct Form {
    tag: Option<String>,
    room: Option<(String, u64, u64)>,
    peer: Option<(String, String, String)>,
    confirmation: Option<Confirmation>,
    selection_reset: bool,
    access: Option<AccessDraft>,
}

struct AccessDraft {
    room: String,
    revision: u64,
    allow_member_text: bool,
    allow_member_files: bool,
    allow_member_invite: bool,
    admins: BTreeSet<String>,
    muted: BTreeSet<String>,
}

pub(super) struct ShowContext<'a> {
    pub(super) data: &'a Dashboard,
    pub(super) loopback_enabled: bool,
    pub(super) language: Language,
    pub(super) actions_enabled: bool,
    pub(super) now: u64,
    pub(super) action: &'a mut Option<LocalAction>,
}

struct RosterContext<'a> {
    language: Language,
    now: u64,
    ready: bool,
    action: &'a mut Option<LocalAction>,
}

enum Confirmation {
    Create,
    Invite,
    JoinRequest { room: String, connection: String },
    Remove { agent: String, device: String },
}

pub(super) fn enabled(config: &Result<NetworkSettingsV1, AslError>, _data: &Dashboard) -> bool {
    config.as_ref().is_ok_and(|cfg| cfg.loopback_groups)
}

impl Form {
    pub(super) fn observe(&mut self, snapshot: Option<&AdminSnapshot>) {
        let tag = snapshot.map(|snapshot| snapshot.tag.as_str());
        let selection_missing = snapshot.is_some_and(|snapshot| {
            let room = self.selected_room(snapshot);
            (self.room.is_some() && room.is_none())
                || (self.peer.is_some() && self.selected_peer(snapshot).is_none())
                || (matches!(self.confirmation, Some(Confirmation::Remove { .. }))
                    && room.and_then(|room| self.removal_member(room)).is_none())
                || (matches!(self.confirmation, Some(Confirmation::JoinRequest { .. }))
                    && self.join_request(snapshot).is_none())
        });
        if self.tag.as_deref() != tag || selection_missing {
            self.clear_selection();
            self.tag = tag.map(str::to_owned);
        }
    }

    pub(super) fn show(&mut self, ui: &mut egui::Ui, context: &mut ShowContext<'_>) {
        let ShowContext {
            data,
            loopback_enabled,
            language,
            actions_enabled,
            now,
            action,
        } = context;
        ui.label(
            RichText::new(label(*language, "本机群组管理", "Local group management")).strong(),
        );
        if !*loopback_enabled {
            ui.weak(label(
                *language,
                "群组网络未启用",
                "Group networking is disabled",
            ));
            return;
        }
        let status = data.group_admin_status.as_ref();
        if let Some(status) = status {
            ui.weak(outcome_text(status, *language));
        }

        let ready = *actions_enabled
            && action.is_none()
            && !matches!(status, Some(AdminOutcome::Queued | AdminOutcome::Applying));
        if ui
            .add_enabled(
                ready,
                egui::Button::new(label(*language, "刷新管理快照", "Refresh snapshot")),
            )
            .clicked()
        {
            self.observe(None);
            **action = Some(LocalAction::new("group-admin", ["refresh".into()]));
        }
        let snapshot = self.current_snapshot(data.group_admin_snapshot.as_ref(), *now);
        if self.selection_reset {
            ui.weak(label(
                *language,
                "原选择已失效，请重新选择并确认",
                "The previous selection expired. Select again.",
            ));
        }
        let Some(snapshot) = snapshot else {
            ui.weak(label(
                *language,
                "当前无有效管理快照",
                "No valid management snapshot",
            ));
            return;
        };
        identifier(ui, *language, "快照标签", "Snapshot tag", &snapshot.tag);

        let ready = ready && action.is_none();
        ui.add_enabled_ui(ready, |ui| {
            self.select_targets(ui, snapshot, *language);
        });
        self.show_join_requests(ui, snapshot, ready, *language, action);
        let room = self.selected_room(snapshot);
        let peer = self.selected_peer(snapshot);
        if let Some(room) = room {
            ui.label(format!(
                "{} · {} {} · {} {}",
                room.name,
                label(*language, "MLS 版本", "MLS epoch"),
                room.epoch,
                label(*language, "成员版本", "Membership epoch"),
                room.membership_epoch
            ));
            identifier(ui, *language, "群组 ID", "Group ID", &room.room);
            self.ensure_access(room);
        }
        if let Some(peer) = peer {
            identifier(ui, *language, "Agent ID", "Agent ID", &peer.agent);
            identifier(ui, *language, "设备 ID", "Device ID", &peer.device);
            identifier(ui, *language, "连接 ID", "Connection ID", &peer.connection);
        }

        ui.horizontal_wrapped(|ui| {
            if let Some(confirm) = &self.confirmation {
                let (prompt, command) = match confirm {
                    Confirmation::Create => (
                        label(
                            *language,
                            "确认在本机创建群组？",
                            "Create this group locally?",
                        ),
                        Some(LocalAction::new(
                            "group-admin",
                            ["create".into(), snapshot.tag.as_str().into()],
                        )),
                    ),
                    Confirmation::Invite => (
                        label(
                            *language,
                            "确认邀请所选设备？邀请不等于入群。",
                            "Invite this device? An invite does not mean membership.",
                        ),
                        room.zip(peer).map(|(room, peer)| {
                            LocalAction::new(
                                "group-admin",
                                [
                                    "invite".into(),
                                    snapshot.tag.as_str().into(),
                                    room.room.as_str().into(),
                                    peer.connection.as_str().into(),
                                ],
                            )
                        }),
                    ),
                    Confirmation::JoinRequest { room, connection } => (
                        label(
                            *language,
                            "确认批准该加入请求并发送邀请？",
                            "Approve this join request and send an invite?",
                        ),
                        Some(LocalAction::new(
                            "group-admin",
                            [
                                "invite".into(),
                                snapshot.tag.as_str().into(),
                                room.as_str().into(),
                                connection.as_str().into(),
                            ],
                        )),
                    ),
                    Confirmation::Remove { .. } => return,
                };
                ui.label(prompt);
                if ui.button(label(*language, "取消", "Cancel")).clicked() {
                    self.confirmation = None;
                } else if ui
                    .add_enabled(
                        ready && command.is_some(),
                        egui::Button::new(label(*language, "确认", "Confirm")),
                    )
                    .clicked()
                {
                    self.room = None;
                    self.peer = None;
                    self.confirmation = None;
                    **action = command;
                }
            } else {
                if ui
                    .add_enabled(
                        ready,
                        egui::Button::new(label(*language, "创建群组", "Create group")),
                    )
                    .clicked()
                {
                    self.confirmation = Some(Confirmation::Create);
                    self.selection_reset = false;
                }
                if ui
                    .add_enabled(
                        ready && room.is_some() && peer.is_some(),
                        egui::Button::new(label(*language, "邀请设备", "Invite device")),
                    )
                    .clicked()
                {
                    self.confirmation = Some(Confirmation::Invite);
                    self.selection_reset = false;
                }
            }
        });
        if let Some(room) = room {
            let mut view = RosterContext {
                language: *language,
                now: *now,
                ready,
                action,
            };
            self.show_roster(ui, room, snapshot, &mut view);
            self.show_access(ui, room, snapshot, *language, ready, action);
        }
    }

    fn current_snapshot<'a>(
        &mut self,
        snapshot: Option<&'a AdminSnapshot>,
        now: u64,
    ) -> Option<&'a AdminSnapshot> {
        let snapshot = snapshot.filter(|snapshot| self.matches_snapshot(snapshot, now));
        if snapshot.is_none() {
            self.observe(None);
        }
        snapshot
    }

    fn matches_snapshot(&self, snapshot: &AdminSnapshot, now: u64) -> bool {
        self.tag.as_deref() == Some(snapshot.tag.as_str()) && now < snapshot.expires_ms
    }

    fn clear_selection(&mut self) {
        self.selection_reset |=
            self.room.is_some() || self.peer.is_some() || self.confirmation.is_some();
        self.room = None;
        self.peer = None;
        self.confirmation = None;
        self.access = None;
    }

    fn selected_room<'a>(&self, snapshot: &'a AdminSnapshot) -> Option<&'a AdminRoom> {
        snapshot.rooms.iter().find(|room| self.matches_room(room))
    }

    fn selected_peer<'a>(&self, snapshot: &'a AdminSnapshot) -> Option<&'a AdminPeer> {
        invite_candidates(snapshot, self.selected_room(snapshot))
            .find(|peer| self.matches_peer(peer))
    }

    fn matches_room(&self, room: &AdminRoom) -> bool {
        self.room.as_ref().is_some_and(|(id, epoch, membership)| {
            room.room == *id && room.epoch == *epoch && room.membership_epoch == *membership
        })
    }

    fn matches_peer(&self, peer: &AdminPeer) -> bool {
        self.peer
            .as_ref()
            .is_some_and(|(connection, agent, device)| {
                peer.connection == *connection && peer.agent == *agent && peer.device == *device
            })
    }

    fn select_room(&mut self, room: &AdminRoom) {
        if !self.matches_room(room) {
            self.room = Some((room.room.clone(), room.epoch, room.membership_epoch));
            self.peer = None;
            self.confirmation = None;
            self.selection_reset = false;
            self.access = Some(AccessDraft {
                room: room.room.clone(),
                revision: room.policy_revision,
                allow_member_text: room.allow_member_text,
                allow_member_files: room.allow_member_files,
                allow_member_invite: room.allow_member_invite,
                admins: room
                    .members
                    .iter()
                    .filter(|member| member.role == "admin")
                    .map(|member| member.device.clone())
                    .collect(),
                muted: room
                    .members
                    .iter()
                    .filter(|member| member.muted)
                    .map(|member| member.device.clone())
                    .collect(),
            });
        }
    }

    fn ensure_access(&mut self, room: &AdminRoom) {
        if self.access.as_ref().is_none_or(|access| {
            access.room != room.room || access.revision != room.policy_revision
        }) {
            self.access = Some(AccessDraft {
                room: room.room.clone(),
                revision: room.policy_revision,
                allow_member_text: room.allow_member_text,
                allow_member_files: room.allow_member_files,
                allow_member_invite: room.allow_member_invite,
                admins: room
                    .members
                    .iter()
                    .filter(|member| member.role == "admin")
                    .map(|member| member.device.clone())
                    .collect(),
                muted: room
                    .members
                    .iter()
                    .filter(|member| member.muted)
                    .map(|member| member.device.clone())
                    .collect(),
            });
        }
    }

    fn select_peer(&mut self, peer: &AdminPeer) {
        if !self.matches_peer(peer) {
            self.peer = Some((
                peer.connection.clone(),
                peer.agent.clone(),
                peer.device.clone(),
            ));
            self.confirmation = None;
            self.selection_reset = false;
        }
    }

    fn select_targets(&mut self, ui: &mut egui::Ui, snapshot: &AdminSnapshot, language: Language) {
        ui.horizontal_wrapped(|ui| {
            ui.label(label(language, "管理群组", "Managed group"));
            let selected_room_label = self
                .selected_room(snapshot)
                .map(room_label)
                .unwrap_or_else(|| label(language, "选择群组", "Select group").into());
            egui::ComboBox::from_id_salt("group-admin-room")
                .width(190.0)
                .truncate()
                .selected_text(selected_room_label)
                .show_ui(ui, |ui| {
                    if snapshot.rooms.is_empty() {
                        ui.weak(label(language, "暂无可管理的群组", "No manageable groups"));
                    }
                    for room in &snapshot.rooms {
                        if ui
                            .selectable_label(self.matches_room(room), room_label(room))
                            .on_hover_text(&room.room)
                            .clicked()
                        {
                            self.select_room(room);
                        }
                    }
                });
            let Some(room) = self.selected_room(snapshot) else {
                return;
            };
            let selected_peer_label =
                self.selected_peer(snapshot)
                    .map(peer_label)
                    .unwrap_or_else(|| {
                        label(language, "选择已连接设备", "Select connected device").into()
                    });
            egui::ComboBox::from_id_salt("group-admin-peer")
                .width(190.0)
                .truncate()
                .selected_text(selected_peer_label)
                .show_ui(ui, |ui| {
                    let mut candidates = invite_candidates(snapshot, Some(room)).peekable();
                    if candidates.peek().is_none() {
                        ui.weak(label(
                            language,
                            "暂无可邀请的已验证连接",
                            "No verified connections",
                        ));
                    }
                    for peer in candidates {
                        if ui
                            .selectable_label(self.matches_peer(peer), peer_label(peer))
                            .on_hover_text(format!(
                                "{} {}\n{} {}\n{} {}",
                                label(language, "Agent", "Agent"),
                                peer.agent,
                                label(language, "设备", "Device"),
                                peer.device,
                                label(language, "连接", "Connection"),
                                peer.connection
                            ))
                            .clicked()
                        {
                            self.select_peer(peer);
                        }
                    }
                });
        });
    }

    fn show_join_requests(
        &mut self,
        ui: &mut egui::Ui,
        snapshot: &AdminSnapshot,
        ready: bool,
        language: Language,
        action: &mut Option<LocalAction>,
    ) {
        if snapshot.join_requests.is_empty() {
            return;
        }
        ui.separator();
        ui.label(
            RichText::new(label(language, "待审批加入请求", "Pending join requests")).strong(),
        );
        for request in &snapshot.join_requests {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{} · {} · {}",
                    short(&request.room, 12),
                    short(&request.agent, 12),
                    short(&request.device, 12)
                ));
                if request.connection.is_some() {
                    if ui
                        .add_enabled(
                            ready && action.is_none(),
                            egui::Button::new(label(language, "审批并邀请", "Review and invite")),
                        )
                        .clicked()
                    {
                        self.confirmation = Some(Confirmation::JoinRequest {
                            room: request.room.clone(),
                            connection: request.connection.clone().unwrap_or_default(),
                        });
                    }
                } else {
                    ui.weak(label(language, "目标当前不在线", "Target is offline"));
                }
            });
        }
    }

    fn join_request<'a>(&self, snapshot: &'a AdminSnapshot) -> Option<&'a AdminJoinRequest> {
        let Confirmation::JoinRequest { room, connection } = self.confirmation.as_ref()? else {
            return None;
        };
        snapshot.join_requests.iter().find(|request| {
            request.room == *room && request.connection.as_deref() == Some(connection.as_str())
        })
    }

    fn review_removal(&mut self, member: &AdminMember) {
        if !member.creator {
            self.confirmation = Some(Confirmation::Remove {
                agent: member.agent.clone(),
                device: member.device.clone(),
            });
            self.selection_reset = false;
        }
    }

    fn removal_member<'a>(&self, room: &'a AdminRoom) -> Option<&'a AdminMember> {
        let Some(Confirmation::Remove { agent, device }) = &self.confirmation else {
            return None;
        };
        room.members
            .iter()
            .find(|member| !member.creator && member.agent == *agent && member.device == *device)
    }

    fn removal_action(&self, snapshot: &AdminSnapshot, now: u64) -> Option<LocalAction> {
        if !self.matches_snapshot(snapshot, now) {
            return None;
        }
        let room = self.selected_room(snapshot)?;
        let member = self.removal_member(room)?;
        Some(LocalAction::new(
            "group-admin",
            [
                "remove".into(),
                snapshot.tag.as_str().into(),
                room.room.as_str().into(),
                member.device.as_str().into(),
            ],
        ))
    }

    fn show_roster(
        &mut self,
        ui: &mut egui::Ui,
        room: &AdminRoom,
        snapshot: &AdminSnapshot,
        view: &mut RosterContext<'_>,
    ) {
        ui.label(
            RichText::new(format!(
                "{} ({})",
                label(view.language, "已提交成员", "Submitted members"),
                room.members.len()
            ))
            .strong(),
        );
        for member in &room.members {
            ui.push_id(&member.device, |ui| {
                let reviewing = self.removal_member(room) == Some(member);
                ui.separator();
                ui.horizontal_wrapped(|ui| {
                    let role = if member.creator || member.role == "owner" {
                        label(view.language, "群主", "Owner")
                    } else if member.role == "admin" {
                        label(view.language, "管理员", "Admin")
                    } else {
                        label(view.language, "成员", "Member")
                    };
                    ui.label(role);
                    if member.muted {
                        ui.weak(label(view.language, "已禁言", "Muted"));
                    }
                    if !member.creator
                        && !reviewing
                        && ui
                            .add_enabled(
                                view.ready && view.action.is_none() && self.confirmation.is_none(),
                                egui::Button::new(label(
                                    view.language,
                                    "移除成员",
                                    "Remove member",
                                )),
                            )
                            .clicked()
                    {
                        self.review_removal(member);
                    }
                });
                identifier(ui, view.language, "Agent ID", "Agent ID", &member.agent);
                identifier(ui, view.language, "设备 ID", "Device ID", &member.device);
                ui.weak(format!(
                    "{}: {}  {}: {}  {}: {}",
                    label(view.language, "文字", "Text"),
                    if member.can_send_text {
                        label(view.language, "允许", "allowed")
                    } else {
                        label(view.language, "禁止", "blocked")
                    },
                    label(view.language, "文件", "Files"),
                    if member.can_send_files {
                        label(view.language, "允许", "allowed")
                    } else {
                        label(view.language, "禁止", "blocked")
                    },
                    label(view.language, "邀请", "Invite"),
                    if member.can_invite {
                        label(view.language, "允许", "allowed")
                    } else {
                        label(view.language, "禁止", "blocked")
                    }
                ));
                if reviewing {
                    ui.label(format!(
                        "{} \"{}\"?",
                        label(
                            view.language,
                            "确认从群组移除此设备",
                            "Remove this device from group"
                        ),
                        room.name
                    ));
                    identifier(ui, view.language, "群组 ID", "Group ID", &room.room);
                    ui.horizontal_wrapped(|ui| {
                        if ui.button(label(view.language, "取消", "Cancel")).clicked() {
                            self.confirmation = None;
                        } else if ui
                            .add_enabled(
                                view.ready && view.action.is_none(),
                                egui::Button::new(label(
                                    view.language,
                                    "确认移除",
                                    "Confirm removal",
                                )),
                            )
                            .clicked()
                            && let Some(command) = self.removal_action(snapshot, view.now)
                        {
                            self.confirmation = None;
                            self.room = None;
                            self.peer = None;
                            *view.action = Some(command);
                        }
                    });
                }
            });
        }
    }

    fn show_access(
        &mut self,
        ui: &mut egui::Ui,
        room: &AdminRoom,
        snapshot: &AdminSnapshot,
        language: Language,
        ready: bool,
        action: &mut Option<LocalAction>,
    ) {
        let Some(access) = &mut self.access else {
            return;
        };
        ui.separator();
        ui.label(RichText::new(label(language, "群成员权限", "Member permissions")).strong());
        ui.checkbox(
            &mut access.allow_member_text,
            label(language, "成员可发送文字", "Members may send text"),
        );
        ui.checkbox(
            &mut access.allow_member_files,
            label(language, "成员可发送文件", "Members may send files"),
        );
        ui.checkbox(
            &mut access.allow_member_invite,
            label(language, "成员可邀请", "Members may invite"),
        );
        for member in room.members.iter().filter(|member| !member.creator) {
            ui.push_id(format!("access-{}", member.device), |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.label(short(&member.agent, 12));
                    let mut admin = access.admins.contains(&member.device);
                    if ui
                        .checkbox(&mut admin, label(language, "管理员", "Admin"))
                        .changed()
                    {
                        if admin {
                            access.admins.insert(member.device.clone());
                        } else {
                            access.admins.remove(&member.device);
                        }
                    }
                    let mut muted = access.muted.contains(&member.device);
                    if ui
                        .checkbox(&mut muted, label(language, "禁言", "Muted"))
                        .changed()
                    {
                        if muted {
                            access.muted.insert(member.device.clone());
                        } else {
                            access.muted.remove(&member.device);
                        }
                    }
                });
            });
        }
        if ui
            .add_enabled(
                ready && action.is_none(),
                egui::Button::new(label(language, "应用群权限", "Apply group permissions")),
            )
            .clicked()
        {
            let switch = |value| if value { "on" } else { "off" };
            let admins = access.admins.iter().cloned().collect::<Vec<_>>().join(",");
            let muted = access.muted.iter().cloned().collect::<Vec<_>>().join(",");
            *action = Some(LocalAction::new(
                "group-admin",
                [
                    "access".into(),
                    snapshot.tag.as_str().into(),
                    room.room.as_str().into(),
                    access.revision.to_string().into(),
                    switch(access.allow_member_text).into(),
                    switch(access.allow_member_files).into(),
                    switch(access.allow_member_invite).into(),
                    admins.into(),
                    muted.into(),
                ],
            ));
            self.room = None;
            self.peer = None;
            self.access = None;
            self.confirmation = None;
        }
    }
}

fn invite_candidates<'a>(
    snapshot: &'a AdminSnapshot,
    room: Option<&'a AdminRoom>,
) -> impl Iterator<Item = &'a AdminPeer> {
    snapshot.peers.iter().filter(move |peer| {
        room.is_some_and(|room| {
            !room
                .members
                .iter()
                .any(|member| member.device == peer.device)
        })
    })
}

fn identifier(
    ui: &mut egui::Ui,
    language: Language,
    zh_label: &'static str,
    en_label: &'static str,
    value: &str,
) {
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::Label::new(format!("{}: {value}", label(language, zh_label, en_label)))
                .wrap()
                .selectable(true),
        );
        if ui
            .small_button(label(language, "复制", "Copy"))
            .on_hover_text(label(
                language,
                "复制完整 ID，不复制截断显示。",
                "Copy the full ID, not the shortened display.",
            ))
            .clicked()
        {
            ui.ctx().copy_text(value.to_owned());
        }
    });
}

fn room_label(room: &AdminRoom) -> String {
    format!("{} · {}", short(&room.name, 14), short(&room.room, 10))
}

fn peer_label(peer: &AdminPeer) -> String {
    format!(
        "{} · {}",
        short(&peer.agent, 10),
        short(&peer.connection, 10)
    )
}

fn short(value: &str, count: usize) -> &str {
    value
        .char_indices()
        .nth(count)
        .map_or(value, |(end, _)| &value[..end])
}

fn outcome_text(outcome: &AdminOutcome, language: Language) -> &'static str {
    match outcome {
        AdminOutcome::Queued => label(
            language,
            "上次操作：已排队，等待 Core 处理",
            "Queued, waiting for Core",
        ),
        AdminOutcome::Applying => label(language, "上次操作：Core 正在处理", "Core is processing"),
        AdminOutcome::Ready => label(
            language,
            "上次操作：管理快照已生成",
            "Management snapshot ready",
        ),
        AdminOutcome::Created => label(
            language,
            "上次操作：群组已在本机创建",
            "Group created locally",
        ),
        AdminOutcome::InviteQueued => label(
            language,
            "上次操作：邀请已排队，尚未确认送达或入群",
            "Invite queued, delivery and membership unconfirmed",
        ),
        AdminOutcome::MemberRemoved => label(
            language,
            "上次操作：成员移除已在本机提交",
            "Member removal submitted locally",
        ),
        AdminOutcome::AccessUpdated => label(
            language,
            "上次操作：群权限已提交",
            "Group permissions submitted",
        ),
        AdminOutcome::Failed => label(language, "上次操作：失败", "Failed"),
        AdminOutcome::Unconfirmed => label(
            language,
            "上次操作：未确认，不会自动重试",
            "Unconfirmed, will not retry",
        ),
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
    use std::ffi::OsString;

    fn snapshot() -> AdminSnapshot {
        AdminSnapshot {
            tag: "review-1".into(),
            expires_ms: 100,
            rooms: vec![AdminRoom {
                room: "room-1".into(),
                name: "Room one".into(),
                epoch: 8,
                membership_epoch: 5,
                policy_revision: 1,
                allow_member_text: true,
                allow_member_files: true,
                allow_member_invite: false,
                members: vec![
                    AdminMember {
                        agent: "owner-agent".into(),
                        device: "owner-device".into(),
                        creator: true,
                        role: "owner".into(),
                        muted: false,
                        can_send_text: true,
                        can_send_files: true,
                        can_invite: true,
                    },
                    AdminMember {
                        agent: "member-agent".into(),
                        device: "offline-device".into(),
                        creator: false,
                        role: "member".into(),
                        muted: true,
                        can_send_text: false,
                        can_send_files: false,
                        can_invite: false,
                    },
                ],
            }],
            peers: vec![AdminPeer {
                agent: "owner-agent".into(),
                device: "owner-device".into(),
                connection: "owner-connection".into(),
            }],
            join_requests: vec![],
        }
    }

    fn review_removal(snapshot: &AdminSnapshot) -> Form {
        let mut form = Form::default();
        form.observe(Some(snapshot));
        form.select_room(&snapshot.rooms[0]);
        form.review_removal(&snapshot.rooms[0].members[1]);
        form
    }

    #[test]
    fn room_selection_seeds_owner_policy_editor() {
        let snapshot = snapshot();
        let mut form = Form::default();
        form.observe(Some(&snapshot));
        form.select_room(&snapshot.rooms[0]);
        let access = form.access.as_ref().unwrap();
        assert_eq!(access.revision, 1);
        assert!(access.allow_member_text);
        assert!(!access.admins.contains("offline-device"));
        assert!(access.muted.contains("offline-device"));
    }

    #[test]
    fn removal_names_the_exact_offline_device_and_never_the_creator() {
        let snapshot = snapshot();
        let mut form = review_removal(&snapshot);
        let action = form.removal_action(&snapshot, 99).unwrap();
        assert_eq!(action.command, "group-admin");
        assert_eq!(
            action.args,
            ["remove", "review-1", "room-1", "offline-device"].map(OsString::from)
        );
        form.confirmation = None;
        form.review_removal(&snapshot.rooms[0].members[0]);
        assert!(form.removal_action(&snapshot, 99).is_none());
    }

    #[test]
    fn expiry_refresh_and_selection_change_cancel_removal() {
        let snapshot = snapshot();
        let mut form = review_removal(&snapshot);
        assert!(form.removal_action(&snapshot, 100).is_none());
        assert!(form.current_snapshot(Some(&snapshot), 100).is_none());
        assert!(form.confirmation.is_none());

        let mut form = review_removal(&snapshot);
        let mut refreshed = snapshot.clone();
        refreshed.tag = "review-2".into();
        form.observe(Some(&refreshed));
        assert!(form.selected_room(&refreshed).is_none());
        assert!(form.removal_action(&refreshed, 99).is_none());

        let mut form = review_removal(&snapshot);
        let mut switched = snapshot.clone();
        let mut other_room = switched.rooms[0].clone();
        other_room.room = "room-2".into();
        switched.rooms.push(other_room);
        form.select_room(&switched.rooms[1]);
        assert!(form.removal_action(&switched, 99).is_none());
    }

    #[test]
    fn changed_member_identity_invalidates_confirmation() {
        let mut snapshot = snapshot();
        let mut form = review_removal(&snapshot);
        snapshot.rooms[0].members[1].agent = "different-agent".into();
        form.observe(Some(&snapshot));
        assert!(form.removal_action(&snapshot, 99).is_none());
        assert!(form.confirmation.is_none());
    }

    #[test]
    fn invite_chooser_excludes_devices_in_the_selected_roster() {
        let mut snapshot = snapshot();
        let mut form = Form::default();
        let candidate = AdminPeer {
            agent: "member-agent".into(),
            device: "other-device".into(),
            connection: "other-connection".into(),
        };
        snapshot.peers.push(candidate.clone());
        form.observe(Some(&snapshot));
        form.select_room(&snapshot.rooms[0]);
        assert_eq!(
            invite_candidates(&snapshot, form.selected_room(&snapshot)).collect::<Vec<_>>(),
            vec![&candidate]
        );
        form.select_peer(&candidate);
        form.review_removal(&snapshot.rooms[0].members[1]);
        snapshot.peers.push(AdminPeer {
            connection: "new-connection".into(),
            ..candidate
        });
        form.select_peer(&snapshot.peers[2]);
        assert!(form.confirmation.is_none());
    }
}
