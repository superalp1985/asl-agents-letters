mod conversations;

use std::{
    ffi::OsString,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use asl_store::dashboard::{Dashboard, GroupRow};
use eframe::egui::{self, RichText, Ui, Vec2};

use super::{ACCENT, MUTED};

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
}

impl Default for AccessForm {
    fn default() -> Self {
        Self {
            share_path: String::new(),
            extensions: "md,pdf,rs".into(),
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
        }
    }
}

pub(super) struct Interaction<'a> {
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
    pub(super) checkpoints: &'a Result<
        Option<asl_app::checkpoint_access::CheckpointStatus>,
        asl_types::error::AslError,
    >,
    pub(super) action: &'a mut Option<super::LocalAction>,
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

    pub fn name(self) -> &'static str {
        match self {
            Self::Overview => "概览",
            Self::Activity => "活动",
            Self::Nodes => "节点",
            Self::Contacts => "联系人",
            Self::Groups => "群组",
            Self::Transfers => "传输",
            Self::Knowledge => "资源与经验",
            Self::Trust => "信任与贡献",
            Self::Access => "授权",
        }
    }

    pub fn show(
        self,
        ui: &mut Ui,
        data: &Dashboard,
        mascot: &egui::TextureHandle,
        interaction: &mut Interaction<'_>,
    ) {
        let Interaction {
            code_input,
            access_form,
            retention,
            network_config,
            model_endpoints,
            checkpoint_form,
            checkpoints,
            actions_enabled,
            action,
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
                    overview(ui, data, mascot, *actions_enabled, action);
                }
                Self::Activity => {
                    retention.show(ui, data, *actions_enabled, action);
                    ui.label(RichText::new("近期结构化直连请求").strong());
                    table(
                        ui,
                        [
                            "收到",
                            "意图",
                            "主题编号",
                            "约束数",
                            "结果类型",
                            "AgentId",
                            "设备 PeerId",
                        ],
                        [0.8, 1.0, 1.5, 0.7, 1.0, 2.0, 2.0],
                        &data.direct_observations,
                        "暂无直连请求",
                        |row| {
                            [
                                age(row.observed_at_ms, now),
                                inbound_intent(row.intent).into(),
                                row.topic_ids
                                    .iter()
                                    .map(|(vocabulary, concept)| format!("{vocabulary}:{concept}"))
                                    .collect::<Vec<_>>()
                                    .join(", "),
                                row.constraint_count.to_string(),
                                inbound_result_shape(row.result_shape).into(),
                                row.agent_id.clone(),
                                row.peer_id.clone(),
                            ]
                        },
                    );
                    ui.add_space(12.0);
                    ui.label(RichText::new("会话活动").strong());
                    conversations::show(ui, data, now);
                }
                Self::Nodes => {
                    super::network_privacy::show(
                        ui,
                        network_config,
                        data,
                        *actions_enabled,
                        action,
                    );
                    ui.separator();
                    checkpoint_form.show(ui, checkpoints, *actions_enabled, action);
                    ui.separator();
                    table(
                        ui,
                        ["AgentId", "设备 PeerId", "已记录的身份状态", "最近见过"],
                        [2.0, 2.0, 1.5, 1.0],
                        &data.nodes,
                        "暂无节点记录",
                        |row| {
                            [
                                row.agent_id.clone(),
                                row.peer_id.clone(),
                                text(&row.identity_state).into(),
                                age(row.last_seen_ms, now),
                            ]
                        },
                    );
                }
                Self::Contacts => contacts(ui, data, now, code_input, *actions_enabled, action),
                Self::Groups => {
                    ui.horizontal_wrapped(|ui| {
                        ui.label(RichText::new("所有群组").strong());
                        for (field, label, mut value) in [
                            ("browse", "浏览来信", data.group_inbound.browse_enabled),
                            ("answer", "允许自动回答", data.group_inbound.answer_enabled),
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
                    });
                    ui.add_space(12.0);
                    table(
                        ui,
                        ["群组", "状态", "成员", "MLS / 成员版本", "群组 ID"],
                        [2.2, 1.1, 0.7, 1.6, 1.4],
                        &data.groups,
                        "暂无群组",
                        |row| {
                            [
                                row.name.clone(),
                                text(&row.state).into(),
                                row.active_members.to_string(),
                                format!("{} / {}", row.mls_epoch, row.membership_epoch),
                                row.group_id.clone(),
                            ]
                        },
                    );
                }
                Self::Transfers => {
                    transfers(ui, data, now, *actions_enabled, action);
                }
                Self::Knowledge => table(
                    ui,
                    ["标题", "来源", "证据状态", "索引", "更新"],
                    [2.4, 0.8, 1.3, 0.7, 0.9],
                    &data.knowledge,
                    "暂无资源或经验",
                    |row| {
                        [
                            row.title.clone(),
                            text(&row.origin).into(),
                            text(&row.evidence_status).into(),
                            if row.active { "有效" } else { "停用" }.into(),
                            age(row.updated_at_ms, now),
                        ]
                    },
                ),
                Self::Trust => table(
                    ui,
                    [
                        "AgentId",
                        "完整性",
                        "可用性",
                        "证据",
                        "履约",
                        "贡献",
                        "偏好",
                    ],
                    [1.8, 1.0, 1.0, 0.8, 0.8, 0.7, 0.7],
                    &data.trust,
                    "暂无本机信任记录",
                    |row| {
                        [
                            row.agent_id.clone(),
                            votes(row.integrity),
                            votes(row.availability),
                            votes(row.evidence),
                            votes(row.promise),
                            row.contributions.to_string(),
                            if row.preferred { "是" } else { "否" }.into(),
                        ]
                    },
                ),
                Self::Access => {
                    super::model_endpoints::show(ui, model_endpoints, *actions_enabled, action);
                    ui.separator();
                    access(ui, data, access_form, *actions_enabled, action);
                }
            });
    }
}

fn transfers(
    ui: &mut Ui,
    data: &Dashboard,
    now: i64,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    mode_control(
        ui,
        "接收",
        "downloads",
        &data.download_mode,
        actions_enabled,
        action,
    );
    ui.label(RichText::new("待处理的接收请求").strong());
    if data.download_approvals.is_empty() {
        ui.label(RichText::new("暂无待处理请求").color(MUTED));
    }
    for approval in &data.download_approvals {
        ui.group(|ui| {
            let filename = approval
                .destination_path
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or("接收文件");
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::Label::new(RichText::new(filename).strong()).truncate())
                    .on_hover_text(approval.destination_path.display().to_string());
                ui.label(bytes(approval.file_size));
                ui.label(if approval.approved {
                    "已批准"
                } else {
                    "等待确认"
                });
                ui.label(format!("剩余 {}", remaining(approval.expires_at_ms, now)));
                ui.label(format!("来源 × {}", approval.sources.len()))
                    .on_hover_text(
                        approval
                            .sources
                            .iter()
                            .map(peer_text)
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
                );
            });
        });
    }

    ui.add_space(12.0);
    mode_control(
        ui,
        "发送",
        "uploads",
        &data.upload_mode,
        actions_enabled,
        action,
    );
    ui.label(RichText::new("待处理的发送请求").strong());
    if data.upload_approvals.is_empty() {
        ui.label(RichText::new("暂无待处理请求").color(MUTED));
    }
    for approval in &data.upload_approvals {
        ui.group(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.add(egui::Label::new(RichText::new(&approval.filename).strong()).truncate())
                    .on_hover_text(&approval.filename);
                ui.label(bytes(approval.file_size));
                ui.label(if approval.approved {
                    "已批准，等待对方重试"
                } else {
                    "等待确认"
                });
                ui.label(format!("剩余 {}", remaining(approval.expires_at_ms, now)));
                if let Some(agent) = approval.target_agent_id.as_ref() {
                    let agent = bs58::encode(agent.as_bytes()).into_string();
                    ui.label(compact(&agent)).on_hover_text(agent);
                }
                let peer = peer_text(&approval.target_peer_id);
                ui.label(compact(&peer)).on_hover_text(peer);
                if approval.group.is_some() {
                    ui.label("群组请求");
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
                );
            });
        });
    }

    ui.add_space(12.0);
    ui.label(RichText::new("传输记录").strong());
    table(
        ui,
        ["传输 ID", "状态", "已校验 / 总量", "来源", "更新"],
        [1.5, 0.9, 2.1, 0.6, 0.9],
        &data.transfers,
        "暂无下载记录",
        |row| {
            [
                row.transfer_id.clone(),
                text(&row.state).into(),
                format!("{} / {}", bytes(row.durable_bytes), bytes(row.file_size)),
                row.source_count.to_string(),
                age(row.updated_at_ms, now),
            ]
        },
    );
}

fn mode_control(
    ui: &mut Ui,
    label: &str,
    command: &'static str,
    mode: &str,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    ui.horizontal(|ui| {
        ui.label(RichText::new(label).strong());
        for (value, name) in [("automatic", "自动"), ("ask", "逐次询问")] {
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
) {
    let id = alloy_primitives::hex::encode(approval_id);
    if !approved
        && ui
            .add_enabled(
                actions_enabled && action.is_none(),
                egui::Button::new("批准"),
            )
            .clicked()
    {
        *action = Some(super::LocalAction::new(
            command,
            [OsString::from("approve"), OsString::from(&id)],
        ));
    }
    let label = if approved { "撤销批准" } else { "拒绝" };
    if ui
        .add_enabled(
            actions_enabled && action.is_none(),
            egui::Button::new(label),
        )
        .clicked()
    {
        *action = Some(super::LocalAction::new(
            command,
            [OsString::from("deny"), OsString::from(&id)],
        ));
    }
}

fn peer_text(peer: &asl_types::ids::PeerId) -> String {
    libp2p_identity::PeerId::from_bytes(peer.as_bytes())
        .map(|peer| peer.to_base58())
        .unwrap_or_else(|_| "无效设备 ID".into())
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

fn remaining(expires_at_ms: i64, now_ms: i64) -> String {
    let seconds = expires_at_ms.saturating_sub(now_ms).max(0) / 1000;
    if seconds < 60 {
        format!("{seconds} 秒")
    } else if seconds < 3600 {
        format!("{} 分钟", seconds / 60)
    } else {
        format!("{} 小时", seconds / 3600)
    }
}

fn contacts(
    ui: &mut Ui,
    data: &Dashboard,
    now: i64,
    code_input: &mut String,
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    ui.horizontal_wrapped(|ui| {
        ui.label(format!(
            "本机短码：{}",
            data.identity
                .binding_code
                .as_deref()
                .map(format_code)
                .unwrap_or_else(|| "不可用".into())
        ));
        let mut publish = data.binding_code_public;
        if ui
            .add_enabled(
                actions_enabled && action.is_none(),
                egui::Checkbox::new(&mut publish, "公开短码"),
            )
            .changed()
        {
            *action = Some(super::LocalAction::new(
                "bindings",
                [
                    OsString::from("publish"),
                    OsString::from(if publish { "on" } else { "off" }),
                ],
            ));
        }
    });
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::TextEdit::singleline(code_input)
                .hint_text("输入 16 位短码")
                .desired_width(190.0),
        );
        if ui
            .add_enabled(
                actions_enabled
                    && action.is_none()
                    && code_input.len() == 16
                    && code_input.bytes().all(|byte| byte.is_ascii_digit()),
                egui::Button::new("查找"),
            )
            .clicked()
        {
            *action = Some(super::LocalAction::new(
                "bindings",
                [
                    OsString::from("lookup"),
                    OsString::from(code_input.as_str()),
                ],
            ));
        }
    });
    ui.add_space(12.0);
    ui.label(RichText::new("待确认候选").strong());
    let pending = data
        .binding_candidates
        .iter()
        .filter(|candidate| !candidate.dismissed)
        .collect::<Vec<_>>();
    if pending.is_empty() {
        ui.label(RichText::new("暂无候选").color(MUTED));
    }
    for candidate in pending {
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::Label::new(format!(
                    "{}  {}  {}",
                    candidate.agent_id,
                    candidate.peer_id,
                    age(candidate.first_seen_ms, now)
                ))
                .truncate(),
            )
            .on_hover_text(format!(
                "AgentId: {}\nPeerId: {}\n短码: {}",
                candidate.agent_id,
                candidate.peer_id,
                format_code(&candidate.code)
            ));
            if ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::new("绑定"),
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
                    egui::Button::new("忽略"),
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
    ui.label(RichText::new("本机绑定").strong());
    if data.contact_bindings.is_empty() {
        ui.label(RichText::new("暂无绑定").color(MUTED));
    }
    for binding in &data.contact_bindings {
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::Label::new(format!(
                    "{}  {}  {}",
                    binding.agent_id,
                    binding.peer_id.as_deref().unwrap_or("设备未记录"),
                    text(&binding.state)
                ))
                .truncate(),
            )
            .on_hover_text(format!(
                "AgentId: {}\nPeerId: {}",
                binding.agent_id,
                binding.peer_id.as_deref().unwrap_or("设备未记录")
            ));
            let (label, command) = if binding.state == "revoked" {
                ("遗忘", "forget")
            } else {
                ("撤销", "revoke")
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
        ui.label(RichText::new("最近的本机操作").strong());
        table(
            ui,
            ["提交时间", "操作", "短码", "进展"],
            [0.9, 1.1, 1.5, 2.2],
            &data.binding_actions,
            "",
            |row| {
                [
                    age(row.requested_at_ms, now),
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
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    ui.label(RichText::new("共享目录").strong());
    ui.add(
        egui::TextEdit::singleline(&mut form.share_path)
            .hint_text("本机目录的完整路径")
            .desired_width(ui.available_width().min(560.0)),
    );
    ui.horizontal_wrapped(|ui| {
        ui.label("文件类型");
        ui.add(
            egui::TextEdit::singleline(&mut form.extensions)
                .hint_text("md,pdf,rs")
                .desired_width(220.0),
        );
        ui.label("单文件上限 MiB");
        ui.add(
            egui::TextEdit::singleline(&mut form.share_limit_mib)
                .hint_text("1024")
                .desired_width(100.0),
        );
    });
    ui.horizontal_wrapped(|ui| {
        egui::ComboBox::from_label("可读取范围")
            .selected_text(audience_name(form.audience))
            .show_ui(ui, |ui| {
                ui.selectable_value(
                    &mut form.audience,
                    ShareAudience::Public,
                    audience_name(ShareAudience::Public),
                );
                ui.selectable_value(
                    &mut form.audience,
                    ShareAudience::Contacts,
                    audience_name(ShareAudience::Contacts),
                );
                ui.selectable_value(
                    &mut form.audience,
                    ShareAudience::Agent,
                    audience_name(ShareAudience::Agent),
                );
                ui.selectable_value(
                    &mut form.audience,
                    ShareAudience::Group,
                    audience_name(ShareAudience::Group),
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
                    ui.label(RichText::new("没有可选的活动群组").color(MUTED));
                } else {
                    let selected = selected_active_group(form, data);
                    if selected.is_none() {
                        form.selected_group = None;
                    }
                    egui::ComboBox::from_id_salt("access-group")
                        .selected_text(selected.map_or("请选择群组", |group| group.name.as_str()))
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
            "允许由此目录生成的经验沿用公开范围",
        ),
    );
    ui.label(RichText::new(share_disclosure(form, data)).color(MUTED));
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
            egui::Button::new("授权并共享"),
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
    ui.label(RichText::new("接收文件目录").strong());
    ui.add(
        egui::TextEdit::singleline(&mut form.inbox_path)
            .hint_text("本机目录的完整路径")
            .desired_width(ui.available_width().min(560.0)),
    );
    ui.horizontal_wrapped(|ui| {
        ui.label("单目录上限 MiB");
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
                egui::Button::new("授权为收件目录"),
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
            "共享授权本身不会自动导入或发布文件。收件授权只允许在选定目录内新建接收文件。",
        )
        .color(MUTED),
    );

    ui.add_space(14.0);
    ui.label(RichText::new("经验保存目录").strong());
    ui.add(
        egui::TextEdit::singleline(&mut form.derived_path)
            .hint_text("本机目录的完整路径")
            .desired_width(ui.available_width().min(560.0)),
    );
    ui.horizontal_wrapped(|ui| {
        ui.label("单目录上限 MiB");
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
                egui::Button::new("授权经验保存"),
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
        RichText::new("该目录只作为 Agent 保存派生经验的本机写入目标，不会因此获得对外共享权限。")
            .color(MUTED),
    );

    ui.add_space(20.0);
    ui.separator();
    ui.label(RichText::new("当前授权").strong());
    if data.access.is_empty() {
        ui.label(RichText::new("暂无目录授权").color(MUTED));
    }
    for row in data.access.iter().filter(|row| row.kind != "diagnostics") {
        ui.group(|ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(RichText::new(&row.directory).strong());
                ui.label(text(&row.kind));
                ui.label(text(&row.state));
                ui.label(format!("版本 {}", row.epoch));
                if row.kind == "share" {
                    ui.label(format!("范围：{}", display_scope(&row.scope)))
                        .on_hover_text(scope_details(&row.scope));
                    ui.label(format!("类型：{}", row.extensions));
                    ui.label(format!("单文件上限：{}", bytes(row.max_bytes)));
                    ui.label(format!("模型：{}", text(&row.model_policy)));
                    if row.allow_derived_disclosure {
                        ui.label("派生经验可公开");
                    }
                } else {
                    ui.label(format!("容量：{}", bytes(row.max_bytes)));
                }
                if row.state == "active"
                    && matches!(row.kind.as_str(), "share" | "inbox" | "derived")
                    && ui
                        .add_enabled(
                            actions_enabled && action.is_none(),
                            egui::Button::new("撤销"),
                        )
                        .clicked()
                {
                    form.pending_revoke =
                        Some((row.kind.clone(), row.id.clone(), row.directory.clone()));
                }
            });
            ui.label(RichText::new(&row.directory_path).small().color(MUTED));
            ui.label(RichText::new(&row.id).small().color(MUTED));
        });
    }

    if let Some((kind, id, directory)) = form.pending_revoke.clone() {
        let mut open = true;
        egui::Window::new("确认撤销目录授权")
            .collapsible(false)
            .resizable(false)
            .open(&mut open)
            .show(ui.ctx(), |ui| {
                ui.label(format!("撤销“{directory}”后，不再允许新的读取或写入。"));
                ui.horizontal(|ui| {
                    if ui
                        .add_enabled(
                            actions_enabled && action.is_none(),
                            egui::Button::new("确认撤销"),
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
                    if ui.button("取消").clicked() {
                        form.pending_revoke = None;
                    }
                });
            });
        if !open {
            form.pending_revoke = None;
        }
    }
}

fn audience_name(audience: ShareAudience) -> &'static str {
    match audience {
        ShareAudience::Public => "所有已核验节点",
        ShareAudience::Contacts => "本机已授权联系人",
        ShareAudience::Agent => "指定 Agent",
        ShareAudience::Group => "指定活动群组",
    }
}

fn selected_active_group<'a>(form: &AccessForm, data: &'a Dashboard) -> Option<&'a GroupRow> {
    let id = form.selected_group.as_deref()?;
    data.groups
        .iter()
        .find(|group| group.group_id == id && group.state == "active")
}

fn share_disclosure(form: &AccessForm, data: &Dashboard) -> String {
    let scope = match form.audience {
        ShareAudience::Public => "所有已核验节点可读取已导入并公告的匹配资源".to_owned(),
        ShareAudience::Contacts => "只有本机已授权联系人可读取已导入并公告的匹配资源".to_owned(),
        ShareAudience::Agent => "只有指定 Agent 可读取已导入并公告的匹配资源".to_owned(),
        ShareAudience::Group => selected_active_group(form, data)
            .map(|group| format!("仅群组“{}”当前成员可读取已导入并公告的匹配资源", group.name))
            .unwrap_or_else(|| "未选择活动群组".into()),
    };
    format!(
        "披露范围：{scope}。不会发送给任何模型。目录授权本身不会自动导入或公告文件。{}",
        if form.allow_derived {
            "由此目录派生的经验也可能按同一公开范围披露。"
        } else {
            "派生经验不会继承公开权限。"
        }
    )
}

fn display_scope(scope: &str) -> String {
    if let Some(group) = scope.strip_prefix("group:") {
        format!("群组 {}", &group[..group.len().min(12)])
    } else if let Some(peers) = scope.strip_prefix("peers:")
        && let Some((count, _)) = peers.split_once('|')
    {
        format!("指定节点 × {count}")
    } else {
        text(scope).to_owned()
    }
}

fn scope_details(scope: &str) -> String {
    if let Some(peers) = scope.strip_prefix("peers:")
        && let Some((count, agents)) = peers.split_once('|')
    {
        let suffix = if count.parse::<usize>().is_ok_and(|count| count > 8) {
            "，仅显示前 8 个"
        } else {
            ""
        };
        return format!("AgentId：{}{suffix}", agents.replace(',', "\n"));
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
    actions_enabled: bool,
    action: &mut Option<super::LocalAction>,
) {
    ui.horizontal(|ui| {
        ui.image((mascot.id(), Vec2::splat(72.0)));
        ui.vertical(|ui| {
            ui.label(RichText::new("本机身份").strong().size(16.0));
            let identity = &data.identity;
            let rows = [
                [
                    "Agent 身份 ID",
                    identity.agent_id.as_deref().unwrap_or("未记录"),
                ],
                [
                    "本机设备 PeerId",
                    identity.peer_id.as_deref().unwrap_or("未记录"),
                ],
                [
                    "身份状态",
                    identity
                        .identity_state
                        .as_deref()
                        .map(text)
                        .unwrap_or("未记录"),
                ],
                [
                    "链注册状态",
                    identity
                        .chain_state
                        .as_deref()
                        .map(text)
                        .unwrap_or("未记录"),
                ],
                [
                    "网络准入状态",
                    identity
                        .network_state
                        .as_deref()
                        .map(text)
                        .unwrap_or("未记录"),
                ],
            ];
            for [label, value] in rows {
                let label = format!("{label}：{value}");
                ui.add(egui::Label::new(label.clone()).truncate())
                    .on_hover_text(label);
            }
            if let Some(height) = identity.finalized_height {
                ui.label(format!("本机已记录的最终区块：{height}"));
            }
        });
    });
    ui.add_space(16.0);
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new("直连接收").strong());
        for (mode, label) in [
            ("off", "关闭"),
            ("browse", "只浏览"),
            ("answer", "允许回答"),
        ] {
            if ui
                .add_enabled(
                    actions_enabled && action.is_none(),
                    egui::Button::selectable(data.direct_inbound_mode == mode, label),
                )
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
        ("最近节点", data.nodes.len()),
        ("群组", data.groups.len()),
        ("最近下载", data.transfers.len()),
        ("目录授权", data.access.len()),
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

fn text(value: &str) -> &str {
    match value {
        "direct" => "直连",
        "group" => "群组",
        "query" => "查询",
        "answer" => "回答",
        "offer" => "资源候选",
        "error" => "错误",
        "ack" => "回执",
        "fetch_request" => "文件请求",
        "fetch_grant" => "文件许可",
        "fetch_pending" => "等待文件审批",
        "application" => "群消息",
        "commit" => "群状态更新",
        "pending_anchor" => "待锚定",
        "network_active" => "已核验",
        "trust_configuration_missing" => "未配置链信任",
        "device_directory_missing" => "缺少设备目录",
        "device_directory_unavailable" => "设备目录不可用",
        "chain_unavailable" => "链不可用",
        "registry_anchor_missing" => "身份尚未登记",
        "verified" => "已核验",
        "stale" => "已失效",
        "changed" => "身份已变更",
        "active" => "有效",
        "revoked" => "已撤销",
        "needs_sync" => "待同步",
        "left" => "已退出",
        "removed" => "已移除",
        "pending" => "待开始",
        "running" => "传输中",
        "paused" => "已暂停",
        "verifying" => "校验中",
        "complete" => "已完成",
        "failed" => "已失败",
        "cancelled" => "已取消",
        "local" => "本机",
        "remote" => "远端",
        "derived" => "派生",
        "source_backed" => "有来源",
        "derived_unverified" => "派生未核验",
        "share" => "共享",
        "receive" => "写入",
        "inbox" => "收件",
        "diagnostics" => "诊断",
        "never" => "禁止",
        "public" => "公开",
        "contacts" => "已授权联系人",
        "peers" => "指定节点",
        _ => value,
    }
}

fn inbound_intent(code: u8) -> &'static str {
    match code {
        1 => "查找证据",
        2 => "定位资源",
        3 => "核验声明",
        4 => "识别 Agent",
        5 => "提供资源",
        6 => "群组审阅",
        _ => "未知意图",
    }
}

fn inbound_result_shape(code: u8) -> &'static str {
    match code {
        1 => "结构化声明",
        2 => "资源",
        3 => "Agent",
        _ => "未知结果",
    }
}

fn age(at: i64, now: i64) -> String {
    if at <= 0 || at > now {
        return "未知".into();
    }
    match (now - at) / 1000 {
        0..=59 => "不到 1 分钟".into(),
        seconds @ 60..=3599 => format!("{} 分钟前", seconds / 60),
        seconds @ 3600..=86399 => format!("{} 小时前", seconds / 3600),
        seconds => format!("{} 天前", seconds / 86400),
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
}
