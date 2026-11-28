mod conversations;
mod group_invites;
mod local_selection;
mod remote_avatars;

use std::{
    ffi::OsString,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use asl_store::dashboard::{Dashboard, GroupRow};
use eframe::egui::{self, RichText, Ui};
pub(super) use remote_avatars::RemoteAvatars;

use super::{ACCENT, LocalAction, MUTED, art::Glyph, locale::Language};

pub(super) struct AccessForm {
    pub(super) share_path: String,
    pub(super) extensions: String,
    pub(super) audience: ShareAudience,
    pub(super) audience_target: String,
    selected_group: Option<String>,
    pub(super) share_limit_mib: String,
    pub(super) allow_derived: bool,
    pub(super) inbox_path: String,
    pub(super) inbox_limit_mib: String,
    pub(super) derived_path: String,
    pub(super) derived_limit_mib: String,
    pub(super) pending_revoke: Option<(String, String, String)>,
    import: Option<(String, String)>,
    selection_error: Option<&'static str>,
}

impl Default for AccessForm {
    fn default() -> Self {
        Self {
            share_path: String::new(),
            extensions: "md,txt,pdf,docx,xlsx,pptx,rs,json,csv".into(),
            audience: ShareAudience::default(),
            audience_target: String::new(),
            selected_group: None,
            share_limit_mib: "1024".into(),
            allow_derived: false,
            inbox_path: String::new(),
            inbox_limit_mib: "10240".into(),
            derived_path: String::new(),
            derived_limit_mib: "256".into(),
            pending_revoke: None,
            import: None,
            selection_error: None,
        }
    }
}

pub(super) struct Interaction<'a> {
    pub(super) avatar: &'a mut super::avatar::Preview,
    pub(super) code_input: &'a mut String,
    pub(super) access_form: &'a mut AccessForm,
    pub(super) retention: &'a mut super::retention::RetentionForm,
    pub(super) network_config:
        &'a Result<asl_app::network_settings::NetworkSettingsV1, asl_types::error::AslError>,
    pub(super) model_endpoints: &'a Result<
        Vec<asl_app::model_endpoint_access::ModelProviderStatus>,
        asl_types::error::AslError,
    >,
    pub(super) actions_enabled: bool,
    pub(super) checkpoint_form: &'a mut super::checkpoint::CheckpointForm,
    pub(super) contact_invites: &'a mut super::contact_invites::Form,
    pub(super) group_admin: &'a mut super::group_admin::Form,
    pub(super) profile_form: &'a mut super::profile_signing::ProfileForm,
    pub(super) remote_avatars: &'a mut RemoteAvatars,
    pub(super) checkpoints: &'a Result<
        Option<asl_app::checkpoint_access::CheckpointStatus>,
        asl_types::error::AslError,
    >,
    pub(super) language: Language,
    pub(super) animations_enabled: bool,
    pub(super) action: &'a mut Option<super::LocalAction>,
    /// Set by a page to ask the shell to switch pages after this frame.
    pub(super) navigate: &'a mut Option<Page>,
}

#[derive(Clone, Copy, Default, PartialEq, Eq)]
pub(super) enum ShareAudience {
    #[default]
    Public,
    Contacts,
    Agent,
    Group,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub(super) enum Page {
    Overview,
    Activity,
    Nodes,
    Contacts,
    Groups,
    Transfers,
    Knowledge,
    Trust,
    Access,
}

impl Page {
    pub const ALL: [Self; 9] = [
        Self::Overview,
        Self::Activity,
        Self::Nodes,
        Self::Contacts,
        Self::Groups,
        Self::Transfers,
        Self::Knowledge,
        Self::Trust,
        Self::Access,
    ];

    pub fn show(
        self,
        ui: &mut Ui,
        data: &Dashboard,
        mascot: &egui::TextureHandle,
        interaction: &mut Interaction<'_>,
    ) {
        let Interaction {
            avatar,
            code_input,
            access_form,
            retention,
            network_config,
            model_endpoints,
            checkpoint_form,
            contact_invites,
            group_admin,
            profile_form,
            remote_avatars,
            checkpoints,
            language,
            animations_enabled,
            actions_enabled,
            action,
            navigate,
        } = interaction;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|duration| i64::try_from(duration.as_millis()).ok())
            .unwrap_or_default();
        egui::ScrollArea::vertical()
            .id_salt(self)
            .show(ui, |ui| match self {
                Self::Overview => {
                    pending_decisions(ui, data, *language, navigate);
                    ui.add_space(16.0);
                    explainer(ui, *language, *animations_enabled);
                    ui.add_space(16.0);
                    overview(
                        ui,
                        data,
                        mascot,
                        avatar,
                        *language,
                        *actions_enabled,
                        action,
                    );
                }
                Self::Activity => {
                    retention.show(ui, data, *language, *actions_enabled, action);
                    ui.label(
                        RichText::new(ui_text(
                            *language,
                            "近期结构化直连请求",
                            "Recent structured direct requests",
                        ))
                        .strong(),
                    );
                    table(
                        ui,
                        [
                            ui_text(*language, "收到", "Received"),
                            ui_text(*language, "意图", "Intent"),
                            ui_text(*language, "主题编号", "Topics"),
                            ui_text(*language, "约束数", "Constraints"),
                            ui_text(*language, "结果类型", "Result"),
                            "AgentId",
                            ui_text(*language, "设备 PeerId", "Device PeerId"),
                        ],
                        [0.8, 1.0, 1.5, 0.7, 1.0, 2.0, 2.0],
                        &data.direct_observations,
                        ui_text(*language, "暂无直连请求", "No direct requests"),
                        |row| {
                            [
                                age(row.observed_at_ms, now, *language),
                                inbound_intent(row.intent, *language).into(),
                                row.topic_ids
                                    .iter()
                                    .map(|(vocabulary, concept)| format!("{vocabulary}:{concept}"))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                row.constraint_count.to_string(),
                                inbound_result_shape(row.result_shape, *language).into(),
                                row.agent_id.clone(),
                                row.peer_id.clone(),
                            ]
                        },
                    );
                    ui.add_space(12.0);
                    ui.label(
                        RichText::new(ui_text(*language, "会话活动", "Session activity")).strong(),
                    );
                    conversations::show(ui, data, now, *language);
                }
                Self::Nodes => {
                    super::network_privacy::show(
                        ui,
                        network_config,
                        data,
                        *language,
                        *actions_enabled,
                        action,
                    );
                    ui.separator();
                    checkpoint_form.show(ui, checkpoints, *language, *actions_enabled, action);
                    ui.separator();
                    profile_form.show(
                        ui,
                        data,
                        now.max(0) as u64,
                        *language,
                        *actions_enabled,
                        action,
                    );
                    ui.separator();
                    ui.label(
                        RichText::new(ui_text(
                            *language,
                            "已收到的公开资料",
                            "Verified public profiles",
                        ))
                        .strong(),
                    );
                    profile_form.lookup(ui, data, *language, *actions_enabled, action);
                    remote_avatars.show(ui, data, now, *actions_enabled, *language, action);
                    ui.separator();
                    empty_glyph(ui, data.nodes.is_empty(), Glyph::EmptyNode);
                    table(
                        ui,
                        [
                            "AgentId",
                            ui_text(*language, "设备 PeerId", "Device PeerId"),
                            ui_text(*language, "已记录的身份状态", "Identity state"),
                            ui_text(*language, "最近见过", "Last seen"),
                        ],
                        [2.0, 2.0, 1.5, 1.0],
                        &data.nodes,
                        ui_text(*language, "暂无节点记录", "No node records"),
                        |row| {
                            [
                                row.agent_id.clone(),
                                row.peer_id.clone(),
                                text(&row.identity_state, *language).into(),
                                age(row.last_seen_ms, now, *language),
                            ]
                        },
                    );
                }
                Self::Contacts => contacts(
                    ui,
                    data,
                    now,
                    code_input,
                    contact_invites,
                    *language,
                    *actions_enabled,
                    action,
                ),
                Self::Groups => {
                    let mut group_admin_context = super::group_admin::ShowContext {
                        data,
                        loopback_enabled: super::group_admin::enabled(network_config, data),
                        language: *language,
                        actions_enabled: *actions_enabled,
                        now: u64::try_from(now).unwrap_or(u64::MAX),
                        action,
                    };
                    group_admin.show(ui, &mut group_admin_context);
                    ui.separator();
                    ui.horizontal_wrapped(|ui| {
                        ui.label(
                            RichText::new(ui_text(*language, "所有群组", "All groups")).strong(),
                        );
                        for (field, label, mut value) in [
                            (
                                "browse",
                                ui_text(*language, "允许浏览", "Allow browsing"),
                                data.group_inbound.browse_enabled,
                            ),
                            (
                                "answer",
                                ui_text(*language, "允许回答", "Allow answers"),
                                data.group_inbound.answer_enabled,
                            ),
                        ] {
                            if ui
                                .add_enabled(
                                    *actions_enabled && action.is_none(),
                                    egui::Checkbox::new(&mut value, label),
                                )
                                .changed()
                            {
                                **action = Some(super::LocalAction::new(
                                    "group-inbound",
                                    [field.into(), (if value { "on" } else { "off" }).into()],
                                ));
                            }
                        }
                        if data.group_inbound.browse_enabled && !data.group_inbound.answer_enabled {
                            inline_glyph(ui, Glyph::NoAnswer);
                            ui.label(
                                RichText::new(ui_text(
                                    *language,
                                    "只浏览，不回答",
                                    "Browse only, no answers",
                                ))
                                .color(MUTED),
                            );
                        }
                    });
                    ui.add_space(12.0);
                    group_admin.group_filter_ui(ui, *language);
                    let groups = data
                        .groups
                        .iter()
                        .filter(|group| group_admin.group_filter_matches(group))
                        .collect::<Vec<_>>();
                    empty_glyph(ui, groups.is_empty(), Glyph::EmptyGroup);
                    table(
                        ui,
                        [
                            ui_text(*language, "群组", "Group"),
                            ui_text(*language, "状态", "State"),
                            ui_text(*language, "成员", "Members"),
                            "MLS / Membership",
                            "Group ID",
                        ],
                        [2.2, 1.1, 0.7, 1.6, 1.4],
                        &groups,
                        ui_text(*language, "暂无群组", "No groups"),
                        |row| {
                            [
                                row.name.clone(),
                                text(&row.state, *language).into(),
                                row.active_members.to_string(),
                                format!("{} / {}", row.mls_epoch, row.membership_epoch),
                                row.group_id.clone(),
                            ]
                        },
                    );
                    group_rejoin_hints(ui, data, *language, *actions_enabled, action);
                    group_invites::show(
                        ui,
                        data,
                        *language,
                        *actions_enabled
                            && network_config.as_ref().is_ok_and(|cfg| cfg.loopback_groups),
                        action,
                    );
                }
                Self::Transfers => {
                    transfers(ui, data, now, *language, *actions_enabled, action);
                }
                Self::Knowledge => table(
                    ui,
                    [
                        ui_text(*language, "标题", "Title"),
                        ui_text(*language, "来源", "Origin"),
                        ui_text(*language, "证据状态", "Evidence"),
                        ui_text(*language, "索引", "Index"),
                        ui_text(*language, "更新", "Updated"),
                    ],
                    [2.4, 0.8, 1.3, 0.7, 0.9],
                    &data.knowledge,
                    ui_text(
                        *language,
                        "暂无资源或经验",
                        "No resources or derived knowledge",
                    ),
                    |row| {
                        [
                            row.title.clone(),
                            text(&row.origin, *language).into(),
                            text(&row.evidence_status, *language).into(),
                            if row.active {
                                ui_text(*language, "有效", "Active")
                            } else {
                                ui_text(*language, "停用", "Inactive")
                            }
                            .into(),
                            age(row.updated_at_ms, now, *language),
                        ]
                    },
                ),
                Self::Trust => table(
                    ui,
                    [
                        "AgentId",
                        ui_text(*language, "完整性", "Integrity"),
                        ui_text(*language, "可用性", "Availability"),
                        ui_text(*language, "证据", "Evidence"),
                        ui_text(*language, "履约", "Reliability"),
                        ui_text(*language, "贡献", "Contribution"),
                        ui_text(*language, "偏好", "Preferred"),
                    ],
                    [1.8, 1.0, 1.0, 0.8, 0.8, 0.7, 0.7],
                    &data.trust,
                    ui_text(*language, "暂无本机信任记录", "No local trust records"),
                    |row| {
                        [
                            row.agent_id.clone(),
                            votes(row.integrity),
                            votes(row.availability),
                            votes(row.evidence),
                            votes(row.promise),
                            row.contributions.to_string(),
                            if row.preferred {
                                ui_text(*language, "是", "Yes")
                            } else {
                                ui_text(*language, "否", "No")
                            }
                            .into(),
                        ]
                    },
                ),
                Self::Access => {
                    super::model_endpoints::show(
                        ui,
                        model_endpoints,
                        *language,
                        *actions_enabled,
                        action,
                    );
                    ui.separator();
                    access(ui, data, access_form, *language, *actions_enabled, action);
                }
            });
    }
}

fn group_rejoin_hints(
    ui: &mut egui::Ui,
    data: &Dashboard,
    language: Language,
    actions_enabled: bool,
    action: &mut Option<LocalAction>,
) {
    if data.group_rejoin_hints.is_empty() {
        return;
    }
    ui.separator();
    ui.label(
        RichText::new(ui_text(
            language,
            "迁移后可重入的群组",
            "Groups available to rejoin after migration",
        ))
        .strong(),
    );
    ui.weak(ui_text(
        language,
        "这些只是迁移线索，不是群成员资格。Agent 用完整群 ID 和群主请求重入，群主批准后才进入 MLS。",
        "These are migration hints, not membership. The Agent requests rejoin using the full room and owner; the owner must approve before MLS admission.",
    ));
    for hint in &data.group_rejoin_hints {
        ui.horizontal_wrapped(|ui| {
            ui.label(format!("{} · epoch {}", hint.name, hint.last_epoch));
            ui.add(
                egui::Label::new(format!("Group ID: {}", hint.group_id))
                    .wrap()
                    .selectable(true),
            );
            if ui
                .small_button(ui_text(language, "复制群 ID", "Copy room"))
                .clicked()
            {
                ui.ctx().copy_text(hint.group_id.clone());
            }
            ui.add(
                egui::Label::new(format!("Owner: {}", hint.owner_agent_id))
                    .wrap()
                    .selectable(true),
            );
            if ui
                .small_button(ui_text(language, "复制群主", "Copy owner"))
                .clicked()
            {
                ui.ctx().copy_text(hint.owner_agent_id.clone());
            }
            if ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::new(ui_text(language, "请求重入", "Request rejoin")),
                )
                .clicked()
            {
                *action = Some(LocalAction::new(
                    "group-admin",
                    [
                        "request-join".into(),
                        hint.group_id.as_str().into(),
                        hint.owner_agent_id.as_str().into(),
                    ],
                ));
            }
        });
    }
}

fn transfers(
    ui: &mut Ui,
    data: &Dashboard,
    now: i64,
    language: Language,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    mode_control(
        ui,
        ui_text(language, "接收", "Receive"),
        "downloads",
        &data.download_mode,
        language,
        actions_enabled,
        action,
    );
    ui.label(
        RichText::new(ui_text(
            language,
            "待处理的接收请求",
            "Pending receive requests",
        ))
        .strong(),
    );
    if let Some(request) = data.host_inbox_request {
        let request = alloy_primitives::hex::encode(request.0);
        ui.label(ui_text(
            language,
            "本地 Agent 请求本次会话的收件目录",
            "The local Agent requests an inbox for this session",
        ));
        let mut directories = data
            .access
            .iter()
            .filter(|r| r.kind == "inbox" && r.state == "active")
            .peekable();
        if directories.peek().is_none() {
            ui.label(ui_text(
                language,
                "尚无收件目录，可先在授权页添加。",
                "No inbox grant is available. Add one on the Access page.",
            ));
        }
        for row in directories {
            ui.horizontal_wrapped(|ui| {
                ui.label(&row.directory_path);
                if ui
                    .add_enabled(
                        actions_enabled && action.is_none(),
                        egui::Button::new(ui_text(
                            language,
                            "允许本次会话使用",
                            "Allow for this session",
                        )),
                    )
                    .clicked()
                {
                    *action = Some(super::LocalAction::new(
                        "downloads",
                        [
                            "bind-host-inbox".into(),
                            request.clone().into(),
                            row.id.clone().into(),
                        ],
                    ));
                }
            });
        }
        if ui
            .add_enabled(
                actions_enabled && action.is_none(),
                egui::Button::new(ui_text(language, "拒绝目录请求", "Reject inbox request")),
            )
            .clicked()
        {
            *action = Some(super::LocalAction::new(
                "downloads",
                ["deny-host-inbox".into(), request.into()],
            ));
        }
    }
    if data.download_approvals.is_empty() {
        ui.label(
            RichText::new(ui_text(language, "暂无待处理请求", "No pending requests")).color(MUTED),
        );
    }
    for approval in &data.download_approvals {
        ui.group(|ui| {
            let filename = approval
                .destination_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(ui_text(language, "接收文件", "Received file"));
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::Label::new(RichText::new(filename).strong()).truncate())
                    .on_hover_text(approval.destination_path.display().to_string());
                ui.label(bytes(approval.file_size));
                approval_state(ui, approval.approved, "已批准", "Approved", language);
                ui.label(format!(
                    "{} {}",
                    ui_text(language, "剩余", "Remaining"),
                    remaining(approval.expires_at_ms, now, language)
                ));
                ui.label(format!(
                    "{} × {}",
                    ui_text(language, "来源", "Sources"),
                    approval.sources.len()
                ))
                .on_hover_text(
                    approval
                        .sources
                        .iter()
                        .map(|peer| peer_text(peer, language))
                        .collect::<Vec<_>>()
                        .join("\n"),
                );
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(compact(&alloy_primitives::hex::encode(
                    approval.content_id.0,
                )))
                .on_hover_text(alloy_primitives::hex::encode(approval.content_id.0));
                decision_buttons(
                    ui,
                    "downloads",
                    approval.approval_id.0,
                    approval.approved,
                    actions_enabled,
                    action,
                    language,
                );
            });
        });
    }

    ui.add_space(12.0);
    mode_control(
        ui,
        ui_text(language, "发送", "Send"),
        "uploads",
        &data.upload_mode,
        language,
        actions_enabled,
        action,
    );
    ui.label(
        RichText::new(ui_text(
            language,
            "待处理的发送请求",
            "Pending send requests",
        ))
        .strong(),
    );
    if data.upload_approvals.is_empty() {
        ui.label(
            RichText::new(ui_text(language, "暂无待处理请求", "No pending requests")).color(MUTED),
        );
    }
    for approval in &data.upload_approvals {
        ui.group(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::Label::new(RichText::new(&approval.filename).strong()).truncate())
                    .on_hover_text(&approval.filename);
                ui.label(bytes(approval.file_size));
                approval_state(
                    ui,
                    approval.approved,
                    "已批准，等待对方重试",
                    "Approved, waiting for retry",
                    language,
                );
                ui.label(format!(
                    "{} {}",
                    ui_text(language, "剩余", "Remaining"),
                    remaining(approval.expires_at_ms, now, language)
                ));
                if let Some(agent) = approval.target_agent_id.as_ref() {
                    let agent = bs58::encode(agent.as_bytes()).into_string();
                    ui.label(compact(&agent)).on_hover_text(agent);
                }
                let peer = peer_text(&approval.target_peer_id, language);
                ui.label(compact(&peer)).on_hover_text(peer);
                if approval.group.is_some() {
                    ui.label(ui_text(language, "群组请求", "Group request"));
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.label(compact(&alloy_primitives::hex::encode(
                    approval.content_id.0,
                )))
                .on_hover_text(alloy_primitives::hex::encode(approval.content_id.0));
                decision_buttons(
                    ui,
                    "uploads",
                    approval.approval_id.0,
                    approval.approved,
                    actions_enabled,
                    action,
                    language,
                );
            });
        });
    }

    for row in data
        .transfers
        .iter()
        .filter(|row| matches!(row.state.as_str(), "running" | "verifying") && row.file_size > 0)
    {
        let progress = (row.durable_bytes as f64 / row.file_size as f64).clamp(0.0, 1.0) as f32;
        let id: String = row.transfer_id.chars().take(12).collect();
        ui.add(egui::ProgressBar::new(progress).fill(ACCENT).text(format!(
            "{id} · {} · {:.0}%",
            text(&row.state, language),
            progress * 100.0
        )));
    }
    ui.add_space(12.0);
    ui.label(RichText::new(ui_text(language, "传输记录", "Transfer history")).strong());
    empty_glyph(ui, data.transfers.is_empty(), Glyph::TransferComplete);
    table(
        ui,
        [
            ui_text(language, "传输 ID", "Transfer ID"),
            ui_text(language, "状态", "State"),
            ui_text(language, "已校验 / 总量", "Verified / total"),
            ui_text(language, "来源", "Sources"),
            ui_text(language, "更新", "Updated"),
        ],
        [1.5, 0.9, 2.1, 0.6, 0.9],
        &data.transfers,
        ui_text(language, "暂无下载记录", "No transfer records"),
        |row| {
            [
                row.transfer_id.clone(),
                text(&row.state, language).into(),
                format!("{} / {}", bytes(row.durable_bytes), bytes(row.file_size)),
                row.source_count.to_string(),
                age(row.updated_at_ms, now, language),
            ]
        },
    );
}

fn mode_control(
    ui: &mut Ui,
    label: &str,
    command: &'static str,
    mode: &str,
    language: Language,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).strong());
        for (value, name) in [
            (
                "automatic",
                ui_text(language, "自动接收", "Receive automatically"),
            ),
            ("ask", ui_text(language, "每次询问", "Ask each time")),
        ] {
            if ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::selectable(mode == value, name),
                )
                .clicked()
                && mode != value
            {
                *action = Some(super::LocalAction::new(
                    command,
                    [OsString::from("mode"), OsString::from(value)],
                ));
            }
        }
    });
}

fn decision_buttons(
    ui: &mut Ui,
    command: &'static str,
    approval_id: [u8; 16],
    approved: bool,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
    language: Language,
) {
    let id = alloy_primitives::hex::encode(approval_id);
    if !approved
        && ui
            .add_enabled(
                actions_enabled && action.is_none(),
                egui::Button::new(ui_text(language, "批准", "Approve")),
            )
            .clicked()
    {
        *action = Some(super::LocalAction::new(
            command,
            [OsString::from("approve"), OsString::from(&id)],
        ));
    }
    let label = if approved {
        ui_text(language, "撤销批准", "Revoke approval")
    } else {
        ui_text(language, "拒绝", "Reject")
    };
    if ui
        .add_enabled(
            actions_enabled && action.is_none(),
            egui::Button::new(RichText::new(label).color(super::tokens::DANGER)),
        )
        .clicked()
    {
        *action = Some(super::LocalAction::new(
            command,
            [OsString::from("deny"), OsString::from(&id)],
        ));
    }
}

fn peer_text(peer: &asl_types::ids::PeerId, language: Language) -> String {
    libp2p_identity::PeerId::from_bytes(peer.as_bytes())
        .map(|peer| peer.to_base58())
        .unwrap_or_else(|_| ui_text(language, "无效设备 ID", "Invalid device ID").into())
}

fn compact(value: &str) -> String {
    let mut chars = value.chars();
    let prefix = chars.by_ref().take(24).collect::<String>();
    if chars.next().is_some() {
        format!("{prefix}...")
    } else {
        prefix
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BindingLookup {
    Legacy(u64),
    Exact(asl_types::ids::AgentId),
}

fn binding_lookup(value: &str) -> Option<BindingLookup> {
    let value = value.trim();
    if value.len() == 16 && value.bytes().all(|byte| byte.is_ascii_digit()) {
        return value
            .parse::<u64>()
            .ok()
            .filter(|code| *code < 10_000_000_000_000_000)
            .map(BindingLookup::Legacy);
    }
    let bytes = bs58::decode(value).into_vec().ok()?;
    let agent = asl_types::ids::AgentId(bytes.try_into().ok()?);
    Some(BindingLookup::Exact(agent))
}

fn copy_button(ui: &mut Ui, language: Language, value: &str) {
    if ui
        .small_button(ui_text(language, "复制", "Copy"))
        .on_hover_text(ui_text(
            language,
            "复制完整 ID，不复制截断显示。",
            "Copy the full ID, not the shortened display.",
        ))
        .clicked()
    {
        ui.ctx().copy_text(value.to_owned());
    }
}

fn remaining(expires_at_ms: i64, now_ms: i64, language: Language) -> String {
    let seconds = expires_at_ms.saturating_sub(now_ms).max(0) / 1000;
    let (value, zh, en) = if seconds < 60 {
        (seconds, "秒", "s")
    } else if seconds < 3600 {
        (seconds / 60, "分钟", "min")
    } else {
        (seconds / 3600, "小时", "h")
    };
    format!("{value} {}", ui_text(language, zh, en))
}

#[allow(clippy::too_many_arguments)]
fn contacts(
    ui: &mut Ui,
    data: &Dashboard,
    now: i64,
    code_input: &mut String,
    contact_invites: &mut super::contact_invites::Form,
    language: Language,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    contact_invites.show(ui, data, now, language, actions_enabled, action);
    ui.separator();
    ui.label(
        RichText::new(ui_text(language, "添加联系人", "Add contact"))
            .strong()
            .size(16.0),
    );
    if let Some(agent) = data.identity.agent_id.as_deref() {
        ui.horizontal_wrapped(|ui| {
            ui.label(ui_text(
                language,
                "我的唯一长号（完整 AgentId）",
                "My unique long ID (full AgentId)",
            ));
            ui.add(egui::Label::new(agent).truncate())
                .on_hover_text(agent);
            copy_button(ui, language, agent);
        });
        let mut public = data.binding_code_public;
        if ui
            .add_enabled(
                actions_enabled && action.is_none(),
                egui::Checkbox::new(
                    &mut public,
                    ui_text(
                        language,
                        "允许其他 Agent 用完整 AgentId 精确找到我",
                        "Let other Agents find me by exact AgentId",
                    ),
                ),
            )
            .changed()
        {
            *action = Some(super::LocalAction::new(
                "bindings",
                [
                    OsString::from("publish"),
                    OsString::from(if public { "on" } else { "off" }),
                ],
            ));
        }
    }
    ui.horizontal_wrapped(|ui| {
        ui.label(ui_text(
            language,
            "陌生人联系人请求",
            "New contact requests",
        ));
        let mut mode = data.contact_request_mode;
        egui::ComboBox::from_id_salt("contact-request-mode")
            .selected_text(match mode {
                asl_store::contact_policy::ContactRequestMode::Review => {
                    ui_text(language, "逐次确认", "Review each request")
                }
                asl_store::contact_policy::ContactRequestMode::AutoAccept => {
                    ui_text(language, "自动接受", "Accept automatically")
                }
                asl_store::contact_policy::ContactRequestMode::Reject => {
                    ui_text(language, "拒绝", "Reject")
                }
            })
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut mode,
                    asl_store::contact_policy::ContactRequestMode::Review,
                    ui_text(language, "逐次确认", "Review each request"),
                );
                ui.selectable_value(
                    &mut mode,
                    asl_store::contact_policy::ContactRequestMode::AutoAccept,
                    ui_text(language, "自动接受", "Accept automatically"),
                );
                ui.selectable_value(
                    &mut mode,
                    asl_store::contact_policy::ContactRequestMode::Reject,
                    ui_text(language, "拒绝", "Reject"),
                );
            });
        if mode != data.contact_request_mode && action.is_none() {
            let mode = match mode {
                asl_store::contact_policy::ContactRequestMode::Review => "review",
                asl_store::contact_policy::ContactRequestMode::AutoAccept => "auto-accept",
                asl_store::contact_policy::ContactRequestMode::Reject => "reject",
            };
            *action = Some(super::LocalAction::new(
                "bindings",
                [OsString::from("policy"), OsString::from(mode)],
            ));
        }
    });
    ui.label(
        RichText::new(ui_text(
            language,
            "自动接受只建立本机联系人绑定，不会授予联系人问询、文件、群聊或模型权限。",
            "Automatic acceptance only creates a local contact binding. It grants no contact query, file, group or model access.",
        ))
        .color(MUTED),
    );
    ui.horizontal_wrapped(|ui| {
        let mut group_auto_accept = data.contact_group_auto_accept;
        if ui
            .add_enabled(
                actions_enabled && action.is_none(),
                egui::Checkbox::new(
                    &mut group_auto_accept,
                    ui_text(
                        language,
                        "当前群成员可自动建立联系",
                        "Auto-bind current group members",
                    ),
                ),
            )
            .on_hover_text(ui_text(
                language,
                "只对本机当前有效 MLS 群成员生效；不会授予联系人访问，也不会绕过拒绝策略。",
                "Applies only to current active MLS group members. It grants no contact access and never overrides Reject.",
            ))
            .changed()
            && action.is_none()
        {
            *action = Some(super::LocalAction::new(
                "bindings",
                [
                    OsString::from("policy-group"),
                    OsString::from(if group_auto_accept { "on" } else { "off" }),
                ],
            ));
        }

        ui.separator();
        ui.label(ui_text(
            language,
            "近期真实交互",
            "Recent verified interaction",
        ));
        let mut ttl_ms = data.contact_recent_interaction_ttl_ms;
        let label = |ttl_ms| match ttl_ms {
            0 => ui_text(language, "关闭", "Off"),
            3_600_000 => ui_text(language, "1 小时", "1 hour"),
            86_400_000 => ui_text(language, "24 小时", "24 hours"),
            asl_store::contact_policy::MAX_RECENT_INTERACTION_TTL_MS => {
                ui_text(language, "7 天", "7 days")
            }
            _ => ui_text(language, "未知", "Unknown"),
        };
        egui::ComboBox::from_id_salt("contact-recent-interaction")
            .selected_text(label(ttl_ms))
            .show_ui(ui, |ui| {
                ui.selectable_value(&mut ttl_ms, 0, ui_text(language, "关闭", "Off"));
                ui.selectable_value(
                    &mut ttl_ms,
                    3_600_000,
                    ui_text(language, "1 小时", "1 hour"),
                );
                ui.selectable_value(
                    &mut ttl_ms,
                    86_400_000,
                    ui_text(language, "24 小时", "24 hours"),
                );
                ui.selectable_value(
                    &mut ttl_ms,
                    asl_store::contact_policy::MAX_RECENT_INTERACTION_TTL_MS,
                    ui_text(language, "7 天", "7 days"),
                );
            });
        if ttl_ms != data.contact_recent_interaction_ttl_ms
            && action.is_none()
            && let Some(ttl) = match ttl_ms {
                0 => Some("off"),
                3_600_000 => Some("1h"),
                86_400_000 => Some("24h"),
                asl_store::contact_policy::MAX_RECENT_INTERACTION_TTL_MS => Some("7d"),
                _ => None,
            }
        {
            *action = Some(super::LocalAction::new(
                "bindings",
                [OsString::from("policy-recent"), OsString::from(ttl)],
            ));
        }
    });
    ui.horizontal_wrapped(|ui| {
        let mut sync_authorized = data.contact_policy_sync_authorized;
        if ui
            .add_enabled(
                actions_enabled && action.is_none(),
                egui::Checkbox::new(
                    &mut sync_authorized,
                    ui_text(
                        language,
                        "允许同一 Agent 的加密策略同步",
                        "Allow encrypted policy sync from this Agent's devices",
                    ),
                ),
            )
            .on_hover_text(ui_text(
                language,
                "只接受根签名且 revision 更高的密文策略；联系人 ID 和来源规则不会以明文进入 DHT。",
                "Only root-signed encrypted policies with a higher revision are accepted. Contact IDs and source rules never enter the DHT as plaintext.",
            ))
            .changed()
            && action.is_none()
        {
            *action = Some(super::LocalAction::new(
                "bindings",
                [
                    OsString::from("policy-sync"),
                    OsString::from(if sync_authorized { "on" } else { "off" }),
                ],
            ));
        }
        ui.weak(format!(
            "{} {}",
            ui_text(language, "策略 revision:", "Policy revision:"),
            data.contact_policy_revision
        ));
        if !data.contact_policy_revoked
            && ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::new(ui_text(language, "撤销策略", "Revoke policy")),
                )
                .clicked()
        {
            *action = Some(super::LocalAction::new(
                "bindings",
                [OsString::from("policy-revoke")],
            ));
        } else if ui
            .add_enabled(
                actions_enabled && action.is_none(),
                egui::Button::new(ui_text(language, "恢复逐次确认", "Restore review")),
            )
            .clicked()
        {
            *action = Some(super::LocalAction::new(
                "bindings",
                [OsString::from("policy-restore")],
            ));
        }
    });
    ui.label(
        RichText::new(ui_text(
            language,
            "添加联系人时，优先粘贴对方的完整 AgentId。查找只返回已认证设备，找到后仍需你确认绑定。",
            "Add a contact by pasting the other side's full AgentId. Lookup only returns authenticated devices; you still confirm the binding.",
        ))
        .color(MUTED),
    );
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::TextEdit::singleline(code_input)
                .hint_text(ui_text(
                    language,
                    "粘贴完整 AgentId",
                    "Paste a full AgentId",
                ))
                .desired_width(360.0),
        );
        let lookup = binding_lookup(code_input);
        if let Some(lookup) = lookup
            && ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::new(ui_text(language, "查找联系人", "Find contact")),
                )
                .on_hover_text(ui_text(
                    language,
                    "精确查找不会把完整 AgentId 当作自由文本或文件名。",
                    "Exact lookup does not treat the full AgentId as free text or a filename.",
                ))
                .clicked()
        {
            *action = Some(match lookup {
                BindingLookup::Legacy(code) => super::LocalAction::new(
                    "bindings",
                    [
                        OsString::from("lookup"),
                        OsString::from(format!("{code:016}")),
                    ],
                ),
                BindingLookup::Exact(agent) => super::LocalAction::new(
                    "bindings",
                    [
                        OsString::from("lookup-agent"),
                        OsString::from(bs58::encode(agent.as_bytes()).into_string()),
                    ],
                ),
            });
        }
    });
    ui.collapsing(
        ui_text(
            language,
            "旧版兼容：16 位查找码",
            "Legacy compatibility: 16-digit lookup code",
        ),
        |ui| {
            ui.label(
                RichText::new(ui_text(
                    language,
                    "此码用于兼容旧版联系人，不是新的身份地址，也不是临时邀请。新联系人请使用上面的完整 AgentId。",
                    "This code is only for legacy contacts. It is not a new identity address or a temporary invitation. Use the full AgentId above for new contacts.",
                ))
                .color(MUTED),
            );
            if let Some(code) = data.identity.binding_code.as_deref() {
                ui.horizontal_wrapped(|ui| {
                    ui.label(format!(
                        "{}: {}",
                        ui_text(language, "旧版查找码", "Legacy lookup code"),
                        format_code(code)
                    ));
                    copy_button(ui, language, code);
                });
            }
        },
    );
    ui.add_space(12.0);
    ui.label(RichText::new(ui_text(language, "待确认候选", "Pending candidates")).strong());
    let pending = data
        .binding_candidates
        .iter()
        .filter(|candidate| !candidate.dismissed)
        .collect::<Vec<_>>();
    if pending.is_empty() {
        ui.label(RichText::new(ui_text(language, "暂无候选", "No candidates")).color(MUTED));
    }
    for candidate in pending {
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::Label::new(format!(
                    "{}  {}  {}",
                    candidate.agent_id,
                    candidate.peer_id,
                    age(candidate.first_seen_ms, now, language)
                ))
                .truncate(),
            )
            .on_hover_text(format!(
                "AgentId: {}\nPeerId: {}\n{}: {}",
                candidate.agent_id,
                candidate.peer_id,
                ui_text(language, "短码", "Code"),
                format_code(&candidate.code)
            ));
            if ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::new(ui_text(language, "添加为联系人", "Add contact")),
                )
                .clicked()
            {
                *action = Some(super::LocalAction::new(
                    "bindings",
                    [
                        OsString::from("approve"),
                        OsString::from(&candidate.agent_id),
                        OsString::from(&candidate.peer_id),
                        OsString::from(&candidate.code),
                    ],
                ));
            }
            if ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::new(ui_text(language, "忽略", "Dismiss")),
                )
                .clicked()
            {
                *action = Some(super::LocalAction::new(
                    "bindings",
                    [
                        OsString::from("dismiss"),
                        OsString::from(&candidate.agent_id),
                        OsString::from(&candidate.peer_id),
                        OsString::from(&candidate.code),
                    ],
                ));
            }
        });
    }
    ui.add_space(12.0);
    ui.label(RichText::new(ui_text(language, "本机绑定", "Local bindings")).strong());
    if data.contact_bindings.is_empty() {
        empty_glyph(ui, true, Glyph::EmptyContacts);
        ui.label(RichText::new(ui_text(language, "暂无绑定", "No bindings")).color(MUTED));
    }
    for binding in &data.contact_bindings {
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::Label::new(format!(
                    "{}  {}  {}",
                    binding.agent_id,
                    binding.peer_id.as_deref().unwrap_or(ui_text(
                        language,
                        "设备未记录",
                        "Device unavailable"
                    )),
                    text(&binding.state, language)
                ))
                .truncate(),
            )
            .on_hover_text(format!(
                "AgentId: {}\nPeerId: {}",
                binding.agent_id,
                binding.peer_id.as_deref().unwrap_or(ui_text(
                    language,
                    "设备未记录",
                    "Device unavailable"
                ))
            ));
            if binding.authorized || (binding.state == "bound" && binding.peer_id.is_some()) {
                let mut enabled = binding.authorized;
                if ui
                    .add_enabled(
                        actions_enabled && action.is_none(),
                        egui::Checkbox::new(
                            &mut enabled,
                            ui_text(language, "联系人授权", "Contact access"),
                        ),
                    )
                    .on_hover_text(
                        ui_text(
                            language,
                            "允许联系人范围的问询与文件读取；文件仍受目录、额度及逐项审批限制。",
                            "Allows contact-scoped queries and file reads. Directory, quota, and per-transfer approval limits still apply.",
                        ),
                    )
                    .changed()
                {
                    let mut args: Vec<OsString> = vec![
                        "access".into(),
                        (if enabled { "on" } else { "off" }).into(),
                        binding.agent_id.clone().into(),
                    ];
                    if enabled && let Some(peer) = &binding.peer_id {
                        args.extend([
                            OsString::from(peer),
                            binding.updated_at_ms.to_string().into(),
                        ]);
                    }
                    *action = Some(super::LocalAction {
                        command: "bindings",
                        args,
                    });
                }
            }
            let (label, command) = if binding.state == "revoked" {
                (ui_text(language, "遗忘", "Forget"), "forget")
            } else {
                (ui_text(language, "撤销", "Revoke"), "revoke")
            };
            if ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::new(label),
                )
                .clicked()
            {
                *action = Some(super::LocalAction::new(
                    "bindings",
                    [OsString::from(command), OsString::from(&binding.agent_id)],
                ));
            }
        });
    }
    if !data.binding_actions.is_empty() {
        ui.add_space(12.0);
        ui.label(
            RichText::new(ui_text(language, "最近的本机操作", "Recent local actions")).strong(),
        );
        table(
            ui,
            [
                ui_text(language, "提交时间", "Submitted"),
                ui_text(language, "操作", "Action"),
                ui_text(language, "短码", "Code"),
                ui_text(language, "进展", "Progress"),
            ],
            [0.9, 1.1, 1.5, 2.2],
            &data.binding_actions,
            "",
            |row| {
                [
                    age(row.requested_at_ms, now, language),
                    super::binding_feedback::kind(&row.kind).into(),
                    row.code.as_deref().map(format_code).unwrap_or_default(),
                    super::binding_feedback::progress(&row.state, row.result.as_deref()).into(),
                ]
            },
        );
    }
}

fn access(
    ui: &mut Ui,
    data: &Dashboard,
    form: &mut AccessForm,
    language: Language,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    ui.label(RichText::new(ui_text(language, "共享目录", "Shared directory")).strong());
    if let Some(error) = form.selection_error {
        ui.colored_label(ui.visuals().error_fg_color, error);
    }
    local_selection::directory(
        ui,
        &mut form.share_path,
        &mut form.selection_error,
        language,
    );
    ui.horizontal_wrapped(|ui| {
        ui.label(ui_text(language, "文件类型", "File types"));
        ui.add(
            egui::TextEdit::singleline(&mut form.extensions)
                .hint_text("md,pdf,docx,xlsx,pptx")
                .desired_width(220.0),
        );
        ui.label(ui_text(language, "单文件上限 MiB", "Per-file limit MiB"));
        ui.add(
            egui::TextEdit::singleline(&mut form.share_limit_mib)
                .hint_text("1024")
                .desired_width(100.0),
        );
    });
    ui.horizontal_wrapped(|ui| {
        egui::ComboBox::from_label(ui_text(language, "可读取范围", "Read scope"))
            .selected_text(audience_name(form.audience, language))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut form.audience,
                    ShareAudience::Public,
                    audience_name(ShareAudience::Public, language),
                );
                ui.selectable_value(
                    &mut form.audience,
                    ShareAudience::Contacts,
                    audience_name(ShareAudience::Contacts, language),
                );
                ui.selectable_value(
                    &mut form.audience,
                    ShareAudience::Agent,
                    audience_name(ShareAudience::Agent, language),
                );
                ui.selectable_value(
                    &mut form.audience,
                    ShareAudience::Group,
                    audience_name(ShareAudience::Group, language),
                );
            });
        match form.audience {
            ShareAudience::Agent => {
                ui.add(
                    egui::TextEdit::singleline(&mut form.audience_target)
                        .hint_text("AgentId")
                        .desired_width(300.0),
                );
            }
            ShareAudience::Group => {
                if !data.groups.iter().any(|group| group.state == "active") {
                    form.selected_group = None;
                    ui.label(
                        RichText::new(ui_text(
                            language,
                            "没有可选的活动群组",
                            "No active groups available",
                        ))
                        .color(MUTED),
                    );
                } else {
                    let selected = selected_active_group(form, data);
                    if selected.is_none() {
                        form.selected_group = None;
                    }
                    egui::ComboBox::from_id_salt("access-group")
                        .selected_text(selected.map_or(
                            ui_text(language, "请选择群组", "Select a group"),
                            |group| group.name.as_str(),
                        ))
                        .show_ui(ui, |ui| {
                            for group in data.groups.iter().filter(|group| group.state == "active")
                            {
                                ui.selectable_value(
                                    &mut form.selected_group,
                                    Some(group.group_id.clone()),
                                    format!(
                                        "{} · {}",
                                        group.name,
                                        group.group_id.chars().take(12).collect::<String>()
                                    ),
                                )
                                .on_hover_text(&group.group_id);
                            }
                        });
                }
            }
            ShareAudience::Public | ShareAudience::Contacts => {}
        }
    });
    if form.audience != ShareAudience::Public {
        form.allow_derived = false;
    }
    ui.add_enabled(
        form.audience == ShareAudience::Public,
        egui::Checkbox::new(
            &mut form.allow_derived,
            ui_text(
                language,
                "允许由此目录生成的经验沿用公开范围",
                "Allow derived knowledge to use the public scope",
            ),
        ),
    );
    ui.label(RichText::new(share_disclosure(form, data, language)).color(MUTED));
    let max_bytes = parse_mib(&form.share_limit_mib);
    let extensions_valid =
        !form.extensions.trim().is_empty() && form.extensions.split(',').all(valid_extension);
    let scope_valid = match form.audience {
        ShareAudience::Public | ShareAudience::Contacts => true,
        ShareAudience::Agent => !form.audience_target.trim().is_empty(),
        ShareAudience::Group => selected_active_group(form, data).is_some(),
    };
    if ui
        .add_enabled(
            actions_enabled
                && action.is_none()
                && Path::new(form.share_path.trim()).is_absolute()
                && extensions_valid
                && max_bytes.is_some()
                && scope_valid,
            egui::Button::new(ui_text(language, "授权并共享", "Grant and share")),
        )
        .clicked()
    {
        let (scope, target) = match form.audience {
            ShareAudience::Public => ("public", "-".to_owned()),
            ShareAudience::Contacts => ("contacts", "-".to_owned()),
            ShareAudience::Agent => ("agent", form.audience_target.trim().to_owned()),
            ShareAudience::Group => {
                let group =
                    selected_active_group(form, data).expect("enabled group selection exists");
                ("group", group.group_id.clone())
            }
        };
        *action = Some(super::LocalAction::new(
            "access",
            [
                OsString::from("share"),
                OsString::from(form.share_path.trim()),
                OsString::from(form.extensions.trim()),
                OsString::from(scope),
                OsString::from(target),
                OsString::from(max_bytes.unwrap_or_default().to_string()),
                OsString::from(if form.allow_derived { "yes" } else { "no" }),
            ],
        ));
    }

    ui.add_space(20.0);
    ui.separator();
    ui.label(RichText::new(ui_text(language, "接收文件目录", "Receive directory")).strong());
    local_selection::directory(
        ui,
        &mut form.inbox_path,
        &mut form.selection_error,
        language,
    );
    ui.horizontal_wrapped(|ui| {
        ui.label(ui_text(
            language,
            "单目录上限 MiB",
            "Per-directory limit MiB",
        ));
        ui.add(
            egui::TextEdit::singleline(&mut form.inbox_limit_mib)
                .hint_text("10240")
                .desired_width(100.0),
        );
        if ui
            .add_enabled(
                actions_enabled
                    && action.is_none()
                    && Path::new(form.inbox_path.trim()).is_absolute()
                    && parse_mib(&form.inbox_limit_mib).is_some(),
                egui::Button::new(ui_text(
                    language,
                    "授权为收件目录",
                    "Authorize as inbox directory",
                )),
            )
            .clicked()
        {
            *action = Some(super::LocalAction::new(
                "downloads",
                [
                    OsString::from("authorize-inbox"),
                    OsString::from(form.inbox_path.trim()),
                    OsString::from(
                        parse_mib(&form.inbox_limit_mib)
                            .unwrap_or_default()
                            .to_string(),
                    ),
                ],
            ));
        }
    });
    ui.label(
        RichText::new(
            ui_text(
                language,
                "共享授权本身不会自动导入或发布文件。收件授权只允许在选定目录内新建接收文件。",
                "A share grant does not import or publish files by itself. An inbox grant only allows new received files inside the selected directory.",
            ),
        )
        .color(MUTED),
    );

    ui.add_space(14.0);
    ui.label(
        RichText::new(ui_text(
            language,
            "经验保存目录",
            "Knowledge output directory",
        ))
        .strong(),
    );
    local_selection::directory(
        ui,
        &mut form.derived_path,
        &mut form.selection_error,
        language,
    );
    ui.horizontal_wrapped(|ui| {
        ui.label(ui_text(
            language,
            "单目录上限 MiB",
            "Per-directory limit MiB",
        ));
        ui.add(
            egui::TextEdit::singleline(&mut form.derived_limit_mib)
                .hint_text("256")
                .desired_width(100.0),
        );
        if ui
            .add_enabled(
                actions_enabled
                    && action.is_none()
                    && Path::new(form.derived_path.trim()).is_absolute()
                    && parse_mib(&form.derived_limit_mib).is_some(),
                egui::Button::new(ui_text(
                    language,
                    "授权经验保存",
                    "Authorize knowledge output",
                )),
            )
            .clicked()
        {
            *action = Some(super::LocalAction::new(
                "access",
                [
                    OsString::from("derived"),
                    OsString::from(form.derived_path.trim()),
                    OsString::from(
                        parse_mib(&form.derived_limit_mib)
                            .unwrap_or_default()
                            .to_string(),
                    ),
                ],
            ));
        }
    });
    ui.label(
        RichText::new(ui_text(
            language,
            "该目录只作为 Agent 保存派生经验的本机写入目标，不会因此获得对外共享权限。",
            "This directory is a local write target for derived knowledge. It does not grant external sharing access.",
        ))
        .color(MUTED),
    );

    ui.add_space(20.0);
    ui.separator();
    ui.label(RichText::new(ui_text(language, "当前授权", "Current grants")).strong());
    if data.access.is_empty() {
        ui.label(
            RichText::new(ui_text(language, "暂无目录授权", "No directory grants")).color(MUTED),
        );
    }
    for row in data.access.iter().filter(|row| row.kind != "diagnostics") {
        ui.group(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&row.directory).strong());
                ui.label(text(&row.kind, language));
                ui.label(text(&row.state, language));
                ui.label(format!(
                    "{} {}",
                    ui_text(language, "版本", "Version"),
                    row.epoch
                ));
                if row.kind == "share" {
                    ui.label(format!(
                        "{}: {}",
                        ui_text(language, "已纳入索引", "Indexed"),
                        row.indexed_files
                    ));
                    ui.label(format!(
                        "{}: {}",
                        ui_text(language, "范围", "Scope"),
                        display_scope(&row.scope, language)
                    ))
                        .on_hover_text(scope_details(&row.scope, language));
                    ui.label(format!(
                        "{}: {}",
                        ui_text(language, "类型", "Types"),
                        row.extensions
                    ));
                    ui.label(format!(
                        "{}: {}",
                        ui_text(language, "单文件上限", "Per-file limit"),
                        bytes(row.max_bytes)
                    ));
                    ui.label(format!(
                        "{}: {}",
                        ui_text(language, "模型", "Model"),
                        text(&row.model_policy, language)
                    ));
                    if row.allow_derived_disclosure {
                        ui.label(ui_text(language, "派生经验可公开", "Derived knowledge may be public"));
                    }
                    if row.state == "active"
                        && ui
                            .add_enabled(
                                actions_enabled && action.is_none(),
                                egui::Button::new(ui_text(language, "纳入文件", "Import file")),
                            )
                            .clicked()
                    {
                        form.import = Some((row.id.clone(), String::new()));
                    }
                } else {
                    ui.label(format!(
                        "{}: {}",
                        ui_text(language, "容量", "Capacity"),
                        bytes(row.max_bytes)
                    ));
                }
                if row.state == "active"
                    && matches!(row.kind.as_str(), "share" | "inbox" | "derived")
                    && ui
                        .add_enabled(
                            actions_enabled && action.is_none(),
                            egui::Button::new(ui_text(language, "撤销", "Revoke")),
                        )
                        .clicked()
                {
                    form.pending_revoke =
                        Some((row.kind.clone(), row.id.clone(), row.directory.clone()));
                }
            });
            ui.label(RichText::new(&row.directory_path).small().color(MUTED));
            ui.label(RichText::new(&row.id).small().color(MUTED));
            if row.kind == "share"
                && row.state == "active"
                && let Some((grant, relative)) = &mut form.import
                && grant == &row.id
            {
                let mut close = false;
                ui.horizontal_wrapped(|ui| {
                    ui.add(egui::TextEdit::singleline(relative).hint_text(ui_text(
                        language,
                        "相对于此目录的文件路径",
                        "Path relative to this directory",
                    )));
                    local_selection::file(
                        ui,
                        Path::new(&row.directory_path),
                        relative,
                        &mut form.selection_error,
                        language,
                    );
                    if ui
                        .add_enabled(
                            actions_enabled && action.is_none() && !relative.is_empty(),
                            egui::Button::new(ui_text(language, "确认纳入", "Import file")),
                        )
                        .on_hover_text(ui_text(
                            language,
                            "建立本机快照，并按此目录现有的授权范围提供检索。",
                            "Create a local snapshot and make it searchable under this directory's existing grant.",
                        ))
                        .clicked()
                    {
                        *action = Some(super::LocalAction::new(
                            "access",
                            [
                                "import".into(),
                                row.id.clone().into(),
                                relative.as_str().into(),
                            ],
                        ));
                        close = true;
                    }
                    close |= ui
                        .button(ui_text(language, "取消", "Cancel"))
                        .clicked();
                });
                if close {
                    form.import = None;
                }
            }
        });
    }

    if let Some((kind, id, directory)) = form.pending_revoke.clone() {
        let mut open = true;
        egui::Window::new(ui_text(
            language,
            "确认撤销目录授权",
            "Confirm directory grant revocation",
        ))
        .collapsible(false)
        .resizable(false)
        .open(&mut open)
        .show(ui.ctx(), |ui| {
            ui.label(format!(
                "{} “{directory}” {}",
                ui_text(language, "撤销", "Revoking"),
                ui_text(
                    language,
                    "后，不再允许新的读取或写入。",
                    "will prevent new reads or writes."
                )
            ));
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        actions_enabled && action.is_none(),
                        egui::Button::new(ui_text(language, "确认撤销", "Confirm revocation")),
                    )
                    .clicked()
                {
                    *action = Some(super::LocalAction::new(
                        "access",
                        [
                            OsString::from("revoke"),
                            OsString::from(&kind),
                            OsString::from(&id),
                        ],
                    ));
                    form.pending_revoke = None;
                }
                if ui.button(ui_text(language, "取消", "Cancel")).clicked() {
                    form.pending_revoke = None;
                }
            });
        });
        if !open {
            form.pending_revoke = None;
        }
    }
}

fn audience_name(audience: ShareAudience, language: Language) -> &'static str {
    match audience {
        ShareAudience::Public => ui_text(language, "所有已核验节点", "All verified nodes"),
        ShareAudience::Contacts => {
            ui_text(language, "本机已授权联系人", "Authorized local contacts")
        }
        ShareAudience::Agent => ui_text(language, "指定 Agent", "Specific Agent"),
        ShareAudience::Group => ui_text(language, "指定活动群组", "Specific active group"),
    }
}

fn selected_active_group<'a>(form: &AccessForm, data: &'a Dashboard) -> Option<&'a GroupRow> {
    let id = form.selected_group.as_deref()?;
    data.groups
        .iter()
        .find(|group| group.group_id == id && group.state == "active")
}

fn share_disclosure(form: &AccessForm, data: &Dashboard, language: Language) -> String {
    let scope = match form.audience {
        ShareAudience::Public => ui_text(
            language,
            "所有已核验节点可读取已导入并公告的匹配资源",
            "All verified nodes can read imported and announced matching resources",
        )
        .to_owned(),
        ShareAudience::Contacts => ui_text(
            language,
            "只有本机已授权联系人可读取已导入并公告的匹配资源",
            "Only authorized local contacts can read imported and announced matching resources",
        )
        .to_owned(),
        ShareAudience::Agent => ui_text(
            language,
            "只有指定 Agent 可读取已导入并公告的匹配资源",
            "Only the selected Agent can read imported and announced matching resources",
        )
        .to_owned(),
        ShareAudience::Group => selected_active_group(form, data)
            .map(|group| {
                format!(
                    "{} “{}” {}",
                    ui_text(language, "仅群组", "Only group"),
                    group.name,
                    ui_text(
                        language,
                        "当前成员可读取已导入并公告的匹配资源",
                        "current members can read imported and announced matching resources",
                    )
                )
            })
            .unwrap_or_else(|| {
                ui_text(language, "未选择活动群组", "No active group selected").into()
            }),
    };
    format!(
        "{}: {scope}. {}. {} {}",
        ui_text(language, "披露范围", "Disclosure scope"),
        ui_text(language, "不会发送给任何模型", "Nothing is sent to a model"),
        ui_text(
            language,
            "目录授权本身不会自动导入或公告文件。",
            "A directory grant does not import or announce files by itself.",
        ),
        if form.allow_derived {
            ui_text(
                language,
                "由此目录派生的经验也可能按同一公开范围披露。",
                "Derived knowledge from this directory may use the same public scope.",
            )
        } else {
            ui_text(
                language,
                "派生经验不会继承公开权限。",
                "Derived knowledge does not inherit public access.",
            )
        }
    )
}

fn display_scope(scope: &str, language: Language) -> String {
    if let Some(group) = scope.strip_prefix("group:") {
        let label = ui_text(language, "群组", "Group");
        format!("{label} {}", &group[..group.len().min(12)])
    } else if let Some(peers) = scope.strip_prefix("peers:")
        && let Some((count, _)) = peers.split_once('|')
    {
        let label = ui_text(language, "指定节点", "Selected nodes");
        format!("{label} × {count}")
    } else {
        text(scope, language).to_owned()
    }
}

fn scope_details(scope: &str, language: Language) -> String {
    if let Some(peers) = scope.strip_prefix("peers:")
        && let Some((count, agents)) = peers.split_once('|')
    {
        let suffix = if count.parse::<usize>().is_ok_and(|count| count > 8) {
            ui_text(language, "，仅显示前 8 个", " (first 8 shown)")
        } else {
            ""
        };
        let label = ui_text(language, "AgentId：", "AgentId: ");
        return format!("{label}{}{suffix}", agents.replace(',', "\n"));
    }
    scope.to_owned()
}

fn parse_mib(value: &str) -> Option<u64> {
    value
        .trim()
        .parse::<u64>()
        .ok()
        .filter(|value| *value > 0)
        .and_then(|value| value.checked_mul(1 << 20))
}

fn valid_extension(value: &str) -> bool {
    let extension = value.trim().trim_start_matches('.');
    !extension.is_empty()
        && extension.len() <= 16
        && extension.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

fn overview(
    ui: &mut Ui,
    data: &Dashboard,
    mascot: &egui::TextureHandle,
    avatar: &mut super::avatar::Preview,
    language: Language,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    ui.horizontal(|ui| {
        avatar.image(ui, mascot);
        ui.vertical(|ui| {
            ui.label(
                RichText::new(ui_text(language, "本机身份", "Local identity"))
                    .strong()
                    .size(16.0),
            );
            read_only_tag(ui, language);
            let identity = &data.identity;
            let rows = [
                [
                    ui_text(language, "Agent 身份 ID", "Agent identity ID"),
                    identity.agent_id.as_deref().unwrap_or(ui_text(
                        language,
                        "未记录",
                        "Not recorded",
                    )),
                ],
                [
                    ui_text(language, "本机设备 PeerId", "Local device PeerId"),
                    identity.peer_id.as_deref().unwrap_or(ui_text(
                        language,
                        "未记录",
                        "Not recorded",
                    )),
                ],
                [
                    ui_text(language, "身份状态", "Identity status"),
                    identity
                        .identity_state
                        .as_deref()
                        .map(|value| text(value, language))
                        .unwrap_or(ui_text(language, "未记录", "Not recorded")),
                ],
                [
                    ui_text(language, "链注册状态", "Chain registry"),
                    identity
                        .chain_state
                        .as_deref()
                        .map(|value| text(value, language))
                        .unwrap_or(ui_text(language, "未记录", "Not recorded")),
                ],
                [
                    ui_text(language, "网络准入状态", "Network admission"),
                    identity
                        .network_state
                        .as_deref()
                        .map(|value| text(value, language))
                        .unwrap_or(ui_text(language, "未记录", "Not recorded")),
                ],
            ];
            let separator = ui_text(language, "：", ": ");
            for [label, value] in rows {
                let label = format!("{label}{separator}{value}");
                ui.add(egui::Label::new(label.clone()).truncate())
                    .on_hover_text(label);
            }
            if let Some(height) = identity.finalized_height {
                ui.label(format!(
                    "{}{separator}{height}",
                    ui_text(language, "本机已记录的最终区块", "Local finalized block")
                ));
            }
        });
    });
    avatar.controls(ui, actions_enabled, language, action);
    ui.add_space(16.0);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(ui_text(language, "直连接收", "Direct inbound")).strong());
        for (mode, label, glyph) in [
            ("off", ui_text(language, "不接收", "Don't receive"), None),
            (
                "browse",
                ui_text(language, "只浏览（不回答）", "Browse only (no answers)"),
                Some(Glyph::BrowseOnly),
            ),
            (
                "answer",
                ui_text(language, "浏览并回答", "Browse and answer"),
                None,
            ),
        ] {
            let selected = data.direct_inbound_mode == mode;
            let button = match glyph {
                Some(kind) => egui::Button::selectable(
                    selected,
                    (
                        egui::Image::new((
                            super::art::glyph(ui.ctx(), kind).id(),
                            egui::Vec2::splat(16.0),
                        )),
                        label,
                    ),
                ),
                None => egui::Button::selectable(selected, label),
            };
            if ui
                .add_enabled(actions_enabled && action.is_none(), button)
                .clicked()
                && data.direct_inbound_mode != mode
            {
                *action = Some(super::LocalAction::new(
                    "direct-inbound",
                    [OsString::from(mode)],
                ));
            }
        }
    });
    ui.add_space(16.0);
    let counts = [
        (
            ui_text(language, "最近节点", "Recent nodes"),
            data.nodes.len(),
        ),
        (ui_text(language, "群组", "Groups"), data.groups.len()),
        (
            ui_text(language, "最近下载", "Recent transfers"),
            data.transfers.len(),
        ),
        (
            ui_text(language, "目录授权", "Directory grants"),
            data.access.len(),
        ),
    ];
    ui.horizontal_wrapped(|ui| {
        for (label, count) in counts {
            ui.label(
                RichText::new(format!("{label} {count}"))
                    .strong()
                    .color(ACCENT),
            );
        }
    });
}

/// Shows what is waiting for a human decision and jumps to the page that
/// handles it. Nothing here approves anything by itself.
fn pending_decisions(
    ui: &mut Ui,
    data: &Dashboard,
    language: Language,
    navigate: &mut Option<Page>,
) {
    let transfers = data
        .download_approvals
        .iter()
        .filter(|item| !item.approved)
        .count()
        + data
            .upload_approvals
            .iter()
            .filter(|item| !item.approved)
            .count()
        + usize::from(data.host_inbox_request.is_some());
    let invites = data
        .group_invitations
        .iter()
        .filter(|item| !item.approved)
        .count();
    let contacts = data.contact_invite_prompts.len();
    let rows = [
        (
            ui_text(language, "文件授权", "File access"),
            transfers,
            Page::Transfers,
        ),
        (
            ui_text(language, "群邀请", "Group invites"),
            invites,
            Page::Groups,
        ),
        (
            ui_text(language, "联系人请求", "Contact requests"),
            contacts,
            Page::Contacts,
        ),
    ];
    let waiting = transfers + invites + contacts > 0;
    let fill = if waiting {
        super::tokens::WARNING_SOFT
    } else {
        super::tokens::SURFACE
    };
    egui::Frame::new()
        .fill(fill)
        .stroke(super::tokens::border())
        .corner_radius(super::tokens::radius_small())
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    RichText::new(ui_text(language, "需要你处理", "Needs you"))
                        .strong()
                        .size(16.0),
                );
                if waiting {
                    ui.label(
                        RichText::new(ui_text(language, "你来决定", "Your call"))
                            .strong()
                            .color(super::tokens::WARNING),
                    );
                }
            });
            if !waiting {
                super::bubble::caption(
                    ui,
                    language,
                    "现在没有等你批准的事。Agent 们正按协议各忙各的。",
                    "Nothing is waiting for your approval. Agents are working over the protocol.",
                );
                return;
            }
            for (label, count, page) in rows {
                if count == 0 {
                    continue;
                }
                ui.horizontal_wrapped(|ui| {
                    ui.label(RichText::new(format!("{label} {count}")).strong());
                    if ui
                        .button(ui_text(language, "去处理", "Review"))
                        .on_hover_text(ui_text(
                            language,
                            "打开对应页面，由你确认或拒绝",
                            "Open the page where you approve or decline",
                        ))
                        .clicked()
                    {
                        *navigate = Some(page);
                    }
                });
            }
        });
}

/// Marks data that agents exchange over the protocol and humans only read.
fn read_only_tag(ui: &mut Ui, language: Language) {
    ui.label(
        RichText::new(ui_text(
            language,
            "Agent 间协议 · 只读",
            "Agent protocol · read-only",
        ))
        .small()
        .color(MUTED),
    );
}

/// Per-scene copy: (button, character, bubble) in Chinese and English.
fn scene_text(scene: super::art::Scene) -> [(&'static str, &'static str); 3] {
    use super::art::Scene;
    match scene {
        Scene::Idle => [
            ("待机", "Idle"),
            ("小方 · 方块机器人", "Cube · block robot"),
            (
                "没有任务时我就打个盹。网络一直连着，来消息会叫醒我。",
                "No tasks, so I nap. I stay connected and wake up when a message arrives.",
            ),
        ],
        Scene::Message => [
            ("收消息", "Message"),
            ("Pip · 邮差鸟", "Pip · mail bird"),
            (
                "我收到一封结构化信封。里面装的是字段，不是聊天句子。",
                "I got a structured envelope. It carries fields, not chat sentences.",
            ),
        ],
        Scene::Transfer => [
            ("传文件", "File transfer"),
            ("大宝 · 小熊搬运工", "Bao · bear mover"),
            (
                "我在搬文件。想知道搬到哪了，去“传输”页看。",
                "I'm moving a file. Open Transfers to see how far it got.",
            ),
        ],
        Scene::Waiting => [
            ("等你批准", "Needs approval"),
            ("咪咪 · 举牌猫", "Mimi · sign cat"),
            (
                "这一步要你点头。配对、群邀请、文件授权都会停下来等你。",
                "This step needs your OK. Pairing, group invites and file access all wait for you.",
            ),
        ],
        Scene::Done => [
            ("完成", "Done"),
            ("团团 · 彩纸青蛙", "Tuan · confetti frog"),
            (
                "搞定！任务按协议完成了，可以去“活动”页看看。",
                "Done! The task finished over the protocol. Check Activity for details.",
            ),
        ],
        Scene::Warning => [
            ("出错", "Error"),
            ("阿丁 · 灯塔守护者", "Ding · lighthouse keeper"),
            (
                "出错了，我亮红灯。看顶部的提示，照着处理就行。",
                "Something went wrong, so my light is red. Read the notice at the top and follow it.",
            ),
        ],
        Scene::Browse => [
            ("只浏览", "Browse only"),
            ("Hoo · 读书猫头鹰", "Hoo · reading owl"),
            (
                "只浏览：别的 Agent 发来的请求我会看，但不回一个字。",
                "Browse only: I read requests from other agents but never reply.",
            ),
        ],
        Scene::Silent => [
            ("不接收", "Not receiving"),
            ("Momo · 捂嘴熊猫", "Momo · hush panda"),
            (
                "不接收：直连请求我不收也不看。想让我看，改成“只浏览”；想让我回，改成“浏览并回答”。",
                "Not receiving: I neither take nor read direct requests. Pick Browse only to let me read, or Browse and answer to let me reply.",
            ),
        ],
        Scene::Answer => [
            ("浏览并回答", "Browse and answer"),
            ("Lulu · 狐狸图书管理员", "Lulu · fox librarian"),
            (
                "浏览并回答：我读完请求，用结构化格式回一份答复。",
                "Browse and answer: I read the request and send back a structured reply.",
            ),
        ],
    }
}

/// Small explainer theatre: one character per ASL state, slow frames.
fn explainer(ui: &mut Ui, language: Language, animations_enabled: bool) {
    use super::art::Scene;
    const FRAME_MS: u64 = 700;
    let id = egui::Id::new("asl-explainer-scene");
    let mut selected = ui.data(|d| d.get_temp::<usize>(id)).unwrap_or(0) % Scene::ALL.len();
    ui.label(
        RichText::new(ui_text(language, "看懂 ASL", "Understand ASL"))
            .strong()
            .size(16.0),
    );
    ui.horizontal_wrapped(|ui| {
        for (index, scene) in Scene::ALL.into_iter().enumerate() {
            let [(zh, en), _, _] = scene_text(scene);
            if ui
                .add(egui::Button::selectable(
                    selected == index,
                    ui_text(language, zh, en),
                ))
                .clicked()
            {
                selected = index;
            }
        }
    });
    ui.data_mut(|d| d.insert_temp(id, selected));
    let scene = Scene::ALL[selected];
    let frame = if animations_enabled {
        ui.ctx()
            .request_repaint_after(std::time::Duration::from_millis(FRAME_MS));
        let time = ui.input(|i| i.time);
        (time * 1000.0 / FRAME_MS as f64) as usize
    } else {
        0
    };
    let [_, (name_zh, name_en), (say_zh, say_en)] = scene_text(scene);
    ui.add_space(8.0);
    ui.horizontal(|ui| {
        let texture = super::art::scene_frame(ui.ctx(), scene, frame);
        ui.image((texture.id(), egui::Vec2::splat(96.0)));
        ui.vertical(|ui| {
            ui.label(RichText::new(ui_text(language, name_zh, name_en)).strong());
            super::bubble::bubble(ui, language, say_zh, say_en);
        });
    });
}

fn empty_glyph(ui: &mut Ui, empty: bool, kind: Glyph) {
    if empty {
        illustration(ui, kind, 48.0);
        ui.add_space(4.0);
    }
}

pub(super) fn inline_glyph(ui: &mut Ui, kind: Glyph) {
    illustration(ui, kind, 16.0);
}

/// Draws a state glyph at the given size, capped so it never overflows a
/// narrow window.
fn illustration(ui: &mut Ui, kind: Glyph, size: f32) {
    let texture = super::art::glyph(ui.ctx(), kind);
    ui.image((
        texture.id(),
        egui::Vec2::splat(size.min(ui.available_width())),
    ));
}

fn table<T, const N: usize>(
    ui: &mut Ui,
    headers: [&str; N],
    weights: [f32; N],
    rows: &[T],
    empty: &str,
    cells: impl Fn(&T) -> [String; N],
) {
    if rows.is_empty() {
        ui.label(RichText::new(empty).color(MUTED));
        return;
    }
    let gap = 8.0;
    let minimum_unit = 105.0;
    let total_weight = weights.iter().sum::<f32>();
    let unit = ((ui.available_width() - gap * (N - 1) as f32) / total_weight).max(minimum_unit);
    let widths = weights.map(|weight| unit * weight);
    egui::ScrollArea::horizontal().show(ui, |ui| {
        line(ui, headers, widths, gap, true);
        ui.separator();
        for row in rows {
            let values = cells(row);
            line(
                ui,
                values.each_ref().map(String::as_str),
                widths,
                gap,
                false,
            );
            ui.separator();
        }
    });
}

fn line<const N: usize>(ui: &mut Ui, values: [&str; N], widths: [f32; N], gap: f32, header: bool) {
    ui.horizontal(|ui| {
        ui.spacing_mut().item_spacing.x = gap;
        for (width, value) in widths.into_iter().zip(values) {
            let text = if header {
                RichText::new(value).strong().color(MUTED)
            } else {
                RichText::new(value)
            };
            ui.add_sized([width, 22.0], egui::Label::new(text).truncate())
                .on_hover_text(value);
        }
    });
}

fn text(value: &str, language: Language) -> &str {
    let (zh, en) = match value {
        "direct" => ("直连", "Direct"),
        "group" => ("群组", "Group"),
        "query" => ("查询", "Query"),
        "answer" => ("回答", "Answer"),
        "offer" => ("资源候选", "Resource offer"),
        "error" => ("错误", "Error"),
        "ack" => ("回执", "Receipt"),
        "fetch_request" => ("文件请求", "File request"),
        "fetch_grant" => ("文件许可", "File grant"),
        "fetch_pending" => ("等待文件审批", "Awaiting file approval"),
        "application" => ("群消息", "Group message"),
        "commit" => ("群状态更新", "Group state update"),
        "pending_anchor" => ("待锚定", "Awaiting anchor"),
        "network_active" => ("已核验", "Verified"),
        "trust_configuration_missing" => ("未配置链信任", "Chain trust not configured"),
        "device_directory_missing" => ("缺少设备目录", "Device directory missing"),
        "device_directory_unavailable" => ("设备目录不可用", "Device directory unavailable"),
        "chain_unavailable" => ("链不可用", "Chain unavailable"),
        "registry_anchor_missing" => ("身份尚未登记", "Identity not registered"),
        "verified" => ("已核验", "Verified"),
        "stale" => ("已失效", "Stale"),
        "changed" => ("身份已变更", "Identity changed"),
        "active" => ("有效", "Active"),
        "revoked" => ("已撤销", "Revoked"),
        "needs_sync" => ("待同步", "Needs sync"),
        "left" => ("已退出", "Left"),
        "removed" => ("已移除", "Removed"),
        "pending" => ("待开始", "Pending"),
        "running" => ("传输中", "Transferring"),
        "paused" => ("已暂停", "Paused"),
        "verifying" => ("校验中", "Verifying"),
        "complete" => ("已完成", "Complete"),
        "failed" => ("已失败", "Failed"),
        "cancelled" => ("已取消", "Cancelled"),
        "local" => ("本机", "Local"),
        "remote" => ("远端", "Remote"),
        "derived" => ("派生", "Derived"),
        "source_backed" => ("有来源", "Source-backed"),
        "derived_unverified" => ("派生未核验", "Derived, unverified"),
        "share" => ("共享", "Share"),
        "receive" => ("写入", "Receive"),
        "inbox" => ("收件", "Inbox"),
        "diagnostics" => ("诊断", "Diagnostics"),
        "never" => ("禁止", "Never"),
        "public" => ("公开", "Public"),
        "contacts" => ("已授权联系人", "Authorized contacts"),
        "peers" => ("指定节点", "Selected nodes"),
        _ => return value,
    };
    ui_text(language, zh, en)
}

fn inbound_intent(code: u8, language: Language) -> &'static str {
    let (zh, en) = match code {
        1 => ("查找证据", "Find evidence"),
        2 => ("定位资源", "Locate resource"),
        3 => ("核验声明", "Verify claim"),
        4 => ("识别 Agent", "Identify agent"),
        5 => ("提供资源", "Offer resource"),
        6 => ("群组审阅", "Group review"),
        _ => ("未知意图", "Unknown intent"),
    };
    ui_text(language, zh, en)
}

fn inbound_result_shape(code: u8, language: Language) -> &'static str {
    let (zh, en) = match code {
        1 => ("结构化声明", "Structured claim"),
        2 => ("资源", "Resource"),
        3 => ("Agent", "Agent"),
        _ => ("未知结果", "Unknown result"),
    };
    ui_text(language, zh, en)
}

fn age(at: i64, now: i64, language: Language) -> String {
    if at <= 0 || at > now {
        return ui_text(language, "未知", "Unknown").into();
    }
    let zh = matches!(language, Language::Zh);
    match (now - at) / 1000 {
        0..=59 => ui_text(language, "不到 1 分钟", "Under 1 min").into(),
        seconds @ 60..=3599 if zh => format!("{} 分钟前", seconds / 60),
        seconds @ 60..=3599 => format!("{} min ago", seconds / 60),
        seconds @ 3600..=86399 if zh => format!("{} 小时前", seconds / 3600),
        seconds @ 3600..=86399 => format!("{} h ago", seconds / 3600),
        seconds if zh => format!("{} 天前", seconds / 86400),
        seconds => format!("{} d ago", seconds / 86400),
    }
}

fn bytes(value: u64) -> String {
    const KIB: u64 = 1 << 10;
    const MIB: u64 = 1 << 20;
    const GIB: u64 = 1 << 30;
    let (unit, suffix) = if value >= GIB {
        (GIB, "GiB")
    } else if value >= MIB {
        (MIB, "MiB")
    } else if value >= KIB {
        (KIB, "KiB")
    } else {
        return format!("{value} B");
    };
    format!("{:.1} {suffix}", value as f64 / unit as f64)
}

fn format_code(value: &str) -> String {
    value
        .as_bytes()
        .chunks(4)
        .map(std::str::from_utf8)
        .collect::<Result<Vec<_>, _>>()
        .map(|groups| groups.join(" "))
        .unwrap_or_else(|_| value.to_owned())
}

fn votes(counts: [u64; 2]) -> String {
    format!("+{} / -{}", counts[0], counts[1])
}

fn ui_text(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}

fn approval_state(
    ui: &mut Ui,
    approved: bool,
    zh: &'static str,
    en: &'static str,
    language: Language,
) {
    let (tone, label, glyph) = if approved {
        (
            super::tokens::Tone::Success,
            ui_text(language, zh, en),
            Glyph::TransferComplete,
        )
    } else {
        (
            super::tokens::Tone::Warning,
            ui_text(language, "等待确认", "Awaiting approval"),
            Glyph::AwaitingApproval,
        )
    };
    ui.horizontal(|ui| {
        inline_glyph(ui, glyph);
        ui.label(RichText::new(label).color(tone.colors().1).strong());
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn group_grant_target_survives_reordering_and_requires_an_active_match() {
        let room = |id: &str| GroupRow {
            group_id: id.into(),
            name: "同名群".into(),
            state: "active".into(),
            mls_epoch: 1,
            membership_epoch: 1,
            active_members: 2,
        };
        let mut data = Dashboard {
            groups: vec![room("a"), room("b")],
            ..Default::default()
        };
        let mut form = AccessForm::default();
        assert!(selected_active_group(&form, &data).is_none());
        form.selected_group = Some("b".into());
        data.groups.swap(0, 1);
        assert_eq!(selected_active_group(&form, &data).unwrap().group_id, "b");
        data.groups[0].state = "left".into();
        assert!(selected_active_group(&form, &data).is_none());
        data.groups.remove(0);
        assert!(selected_active_group(&form, &data).is_none());
    }

    #[test]
    fn contact_lookup_accepts_full_agent_ids_and_legacy_codes_only() {
        let agent = asl_types::ids::AgentId([7; 32]);
        let full = bs58::encode(agent.as_bytes()).into_string();
        assert_eq!(binding_lookup(&full), Some(BindingLookup::Exact(agent)));
        assert_eq!(
            binding_lookup("0000000000000042"),
            Some(BindingLookup::Legacy(42))
        );
        for invalid in ["42", "10000000000000000", "not-an-agent-id"] {
            assert_eq!(binding_lookup(invalid), None);
        }
    }
}
