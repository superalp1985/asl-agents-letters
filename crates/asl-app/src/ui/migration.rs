use std::{
    path::{Path, PathBuf},
    sync::mpsc::{self, Receiver, TryRecvError},
    time::{SystemTime, UNIX_EPOCH},
};

use age::secrecy::SecretString;
use asl_app::{
    migration::{
        self, IdentityMigrationPhaseV1, IdentityMigrationStatusV1, MigratedIdentity, Selection,
    },
    paths::AppPaths,
};
use asl_types::error::AslError;
use eframe::egui::{self, RichText, Ui};

use super::{locale::Language, tokens};

pub(super) struct Form {
    selection: Selection,
    export_directory: String,
    export_passphrase: String,
    export_confirmation: String,
    import_source: String,
    import_parent: String,
    import_passphrase: String,
    old_peer_id: String,
    task: Option<Receiver<Result<TaskOutcome, AslError>>>,
    busy: Option<Busy>,
    result: Option<TaskOutcome>,
    error: Option<String>,
    status: Option<IdentityMigrationStatusV1>,
    status_error: Option<String>,
    status_requested: bool,
    status_home: Option<PathBuf>,
    status_task: Option<Receiver<Result<Option<IdentityMigrationStatusV1>, AslError>>>,
}

impl Default for Form {
    fn default() -> Self {
        Self {
            selection: Selection {
                contacts: true,
                trust: true,
                history: true,
                groups: true,
            },
            export_directory: String::new(),
            export_passphrase: String::new(),
            export_confirmation: String::new(),
            import_source: String::new(),
            import_parent: String::new(),
            import_passphrase: String::new(),
            old_peer_id: String::new(),
            task: None,
            busy: None,
            result: None,
            error: None,
            status: None,
            status_error: None,
            status_requested: false,
            status_home: None,
            status_task: None,
        }
    }
}

impl Form {
    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        home: Option<&Path>,
        language: Language,
        enabled: bool,
    ) {
        self.ensure_status(ui.ctx(), home);
        self.poll();
        let interactive = enabled && self.task.is_none();

        ui.label(
            RichText::new(text(
                language,
                "迁移身份、联系人、信任、历史记录和群组线索。旧设备的 MLS 私钥不会复制；新设备必须重新加入群组。",
                "Move identity, contacts, trust, history and group hints. Old-device MLS keys are not copied; the new device must rejoin groups.",
            ))
            .color(tokens::MUTED),
        );
        ui.add_space(12.0);

        if let Some(busy) = self.busy {
            super::banner(
                ui,
                tokens::Tone::Info,
                match busy {
                    Busy::Export => text(
                        language,
                        "正在加密导出迁移包…",
                        "Encrypting the migration bundle...",
                    ),
                    Busy::Import => text(
                        language,
                        "正在解密并创建新资料目录…",
                        "Decrypting and creating the new profile...",
                    ),
                    Busy::Revoke => text(
                        language,
                        "正在签署旧设备撤销授权…",
                        "Signing the old-device revocation authorization...",
                    ),
                },
            );
            ui.add_space(8.0);
        }
        if let Some(error) = &self.error {
            super::banner(ui, tokens::Tone::Danger, error);
            ui.add_space(8.0);
        }
        if let Some(result) = &self.result {
            self.show_result(ui, result, language);
            ui.add_space(8.0);
        }

        self.show_status(ui, language);
        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        self.show_export(ui, home, language, interactive);
        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        self.show_import(ui, language, interactive);
        ui.add_space(16.0);
        ui.separator();
        ui.add_space(12.0);

        self.show_revocation(ui, home, language, interactive);
    }

    fn show_status(&self, ui: &mut Ui, language: Language) {
        ui.label(
            RichText::new(text(language, "当前迁移状态", "Current migration status")).strong(),
        );
        if let Some(status) = &self.status {
            egui::Frame::new()
                .fill(tokens::SURFACE)
                .stroke(tokens::border())
                .corner_radius(tokens::radius_small())
                .inner_margin(12)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    status_row(ui, "AgentId", &status.agent_id);
                    status_row(ui, "PeerId", &status.new_device_peer_id);
                    status_row(
                        ui,
                        text(language, "阶段", "Phase"),
                        phase_label(&status.phase, language),
                    );
                    status_row(
                        ui,
                        text(language, "来源目录已核验", "Source directory verified"),
                        yes_no(status.source_directory_verified, language),
                    );
                    status_row(
                        ui,
                        text(
                            language,
                            "旧设备撤销已授权",
                            "Old-device revocation authorized",
                        ),
                        yes_no(status.old_device_revocation_authorized, language),
                    );
                    status_row(
                        ui,
                        text(language, "下一设备序号", "Next device serial"),
                        &status.next_device_serial.to_string(),
                    );
                    status_row(
                        ui,
                        text(language, "已撤销序号", "Revoked serials"),
                        &serials(&status.previous_revoked_serials, language),
                    );
                    status_row(
                        ui,
                        text(language, "更新时间 (ms)", "Updated (ms)"),
                        &status.updated_at_ms.to_string(),
                    );
                    if let Some(source) = &status.source_device {
                        status_row(
                            ui,
                            text(language, "旧设备 PeerId", "Old-device PeerId"),
                            &source.peer_id,
                        );
                        status_row(
                            ui,
                            text(language, "旧设备证书序号", "Old-device certificate serial"),
                            &source.certificate_serial.to_string(),
                        );
                    }
                });
        } else if let Some(error) = &self.status_error {
            super::banner(
                ui,
                tokens::Tone::Danger,
                &format!(
                    "{}: {error}",
                    text(
                        language,
                        "无法读取迁移状态",
                        "Could not read migration status"
                    )
                ),
            );
        } else if self.status_task.is_some() {
            ui.label(
                RichText::new(text(
                    language,
                    "正在读取迁移状态…",
                    "Loading migration status...",
                ))
                .color(tokens::MUTED),
            );
        } else {
            ui.label(
                RichText::new(text(
                    language,
                    "当前资料目录没有迁移记录。",
                    "This profile has no migration record.",
                ))
                .color(tokens::MUTED),
            );
        }
    }

    fn show_export(&mut self, ui: &mut Ui, home: Option<&Path>, language: Language, enabled: bool) {
        ui.label(RichText::new(text(language, "导出到迁移包", "Export migration bundle")).strong());
        ui.label(
            RichText::new(text(
                language,
                "选择目录后自动生成带时间戳的迁移包。口令不会保存或写入日志。",
                "Choose a directory to create a timestamped bundle. The passphrase is never saved or logged.",
            ))
            .color(tokens::MUTED),
        );
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.export_directory)
                    .hint_text(text(
                        language,
                        "迁移包保存目录",
                        "Bundle destination directory",
                    ))
                    .desired_width((ui.available_width() - 108.0).clamp(100.0, 560.0)),
            );
            if ui
                .add_enabled(
                    enabled,
                    egui::Button::new(text(language, "选择目录", "Choose directory")),
                )
                .clicked()
            {
                self.pick_directory(DirectoryField::Export, language);
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(text(language, "口令", "Passphrase"));
            ui.add(
                egui::TextEdit::singleline(&mut self.export_passphrase)
                    .password(true)
                    .desired_width(220.0),
            );
            ui.label(text(language, "确认口令", "Confirm passphrase"));
            ui.add(
                egui::TextEdit::singleline(&mut self.export_confirmation)
                    .password(true)
                    .desired_width(220.0),
            );
        });
        ui.horizontal_wrapped(|ui| {
            selection_box(
                ui,
                &mut self.selection.contacts,
                text(language, "联系人", "Contacts"),
                enabled,
            );
            selection_box(
                ui,
                &mut self.selection.trust,
                text(language, "信任记录", "Trust"),
                enabled,
            );
            selection_box(
                ui,
                &mut self.selection.history,
                text(language, "历史与语义记录", "History and semantic records"),
                enabled,
            );
            selection_box(
                ui,
                &mut self.selection.groups,
                text(language, "群组线索", "Group hints"),
                enabled,
            );
        });
        if ui
            .add_enabled(
                enabled,
                egui::Button::new(text(language, "加密导出", "Export encrypted bundle")),
            )
            .clicked()
        {
            self.start_export(ui.ctx(), home, language);
        }
    }

    fn show_import(&mut self, ui: &mut Ui, language: Language, enabled: bool) {
        ui.label(RichText::new(text(language, "导入到新设备", "Import on a new device")).strong());
        ui.label(
            RichText::new(text(
                language,
                "选择迁移包和父目录。导入会在父目录下新建资料目录，不会覆盖现有目录。",
                "Choose a bundle and parent directory. Import creates a new profile below it and never overwrites an existing directory.",
            ))
            .color(tokens::MUTED),
        );
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.import_source)
                    .hint_text(text(language, "迁移包文件", "Migration bundle file"))
                    .desired_width((ui.available_width() - 102.0).clamp(100.0, 560.0)),
            );
            if ui
                .add_enabled(
                    enabled,
                    egui::Button::new(text(language, "选择文件", "Choose file")),
                )
                .clicked()
            {
                match asl_policy::choose_local_file() {
                    Ok(Some(path)) => {
                        self.import_source = path.to_string_lossy().into_owned();
                        self.error = None;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        self.error = Some(format!(
                            "{}: {error}",
                            text(
                                language,
                                "无法打开文件选择器",
                                "Could not open the file picker"
                            )
                        ))
                    }
                }
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.add(
                egui::TextEdit::singleline(&mut self.import_parent)
                    .hint_text(text(
                        language,
                        "新资料目录的父目录",
                        "Parent for the new profile",
                    ))
                    .desired_width((ui.available_width() - 108.0).clamp(100.0, 560.0)),
            );
            if ui
                .add_enabled(
                    enabled,
                    egui::Button::new(text(language, "选择目录", "Choose directory")),
                )
                .clicked()
            {
                self.pick_directory(DirectoryField::ImportParent, language);
            }
        });
        ui.horizontal_wrapped(|ui| {
            ui.label(text(language, "迁移包口令", "Bundle passphrase"));
            ui.add(
                egui::TextEdit::singleline(&mut self.import_passphrase)
                    .password(true)
                    .desired_width(280.0),
            );
        });
        if ui
            .add_enabled(
                enabled,
                egui::Button::new(text(language, "创建新资料目录", "Create new profile")),
            )
            .clicked()
        {
            self.start_import(ui.ctx(), language);
        }
    }

    fn show_revocation(
        &mut self,
        ui: &mut Ui,
        home: Option<&Path>,
        language: Language,
        enabled: bool,
    ) {
        ui.label(
            RichText::new(text(
                language,
                "授权撤销旧设备",
                "Authorize old-device revocation",
            ))
            .strong(),
        );
        let awaiting = self.status.as_ref().is_some_and(|status| {
            status.phase == IdentityMigrationPhaseV1::AwaitingOldDeviceRevocationAuthorization
        });
        if let Some(source) = self
            .status
            .as_ref()
            .and_then(|status| status.source_device.as_ref())
        {
            ui.add(
                egui::Label::new(
                    RichText::new(format!(
                        "{}: {}",
                        text(language, "预期完整 PeerId", "Expected full PeerId"),
                        source.peer_id
                    ))
                    .color(tokens::MUTED),
                )
                .selectable(true),
            );
        }
        ui.add(
            egui::TextEdit::singleline(&mut self.old_peer_id)
                .hint_text(text(
                    language,
                    "输入完整旧设备 PeerId，不能使用短码",
                    "Enter the full old-device PeerId; short codes are not accepted",
                ))
                .desired_width(ui.available_width().min(680.0)),
        );
        if ui
            .add_enabled(
                enabled && awaiting,
                egui::Button::new(text(
                    language,
                    "签署旧设备撤销授权",
                    "Sign old-device revocation authorization",
                )),
            )
            .clicked()
        {
            self.start_revocation(ui.ctx(), home, language);
        }
        if !awaiting {
            ui.label(
                RichText::new(text(
                    language,
                    "当前状态不需要此操作。",
                    "This operation is not required in the current state.",
                ))
                .color(tokens::MUTED),
            );
        }
    }

    fn show_result(&self, ui: &mut Ui, result: &TaskOutcome, language: Language) {
        match result {
            TaskOutcome::Exported(path) => {
                super::banner(
                    ui,
                    tokens::Tone::Success,
                    &format!(
                        "{}: {}",
                        text(language, "迁移包已导出", "Migration bundle exported"),
                        path.display()
                    ),
                );
            }
            TaskOutcome::Imported {
                destination,
                identity,
            } => {
                super::banner(
                    ui,
                    tokens::Tone::Success,
                    text(language, "新资料目录已创建", "New profile created"),
                );
                egui::Frame::new()
                    .fill(tokens::SURFACE)
                    .stroke(tokens::border())
                    .corner_radius(tokens::radius_small())
                    .inner_margin(12)
                    .show(ui, |ui| {
                        status_row(
                            ui,
                            text(language, "新资料目录", "New profile"),
                            &destination.display().to_string(),
                        );
                        status_row(
                            ui,
                            "AgentId",
                            &bs58::encode(identity.agent_id.as_bytes()).into_string(),
                        );
                        status_row(ui, "PeerId", &peer_id_text(&identity.peer_id));
                        status_row(
                            ui,
                            text(language, "迁移阶段", "Migration phase"),
                            phase_label(&identity.migration.phase, language),
                        );
                        ui.label(
                            RichText::new(text(
                                language,
                                "下一步：以新资料目录启动 ASL，完成身份目录注册与入群。旧设备只能在完整 PeerId 核对后授权撤销。",
                                "Next: start ASL with the new profile, finish identity-directory registration and rejoin groups. Authorize old-device revocation only after checking the full PeerId.",
                            ))
                            .color(tokens::MUTED),
                        );
                    });
            }
            TaskOutcome::Revoked(_) => {
                super::banner(
                    ui,
                    tokens::Tone::Success,
                    text(
                        language,
                        "旧设备撤销授权已签署。",
                        "Old-device revocation authorization was signed.",
                    ),
                );
            }
        }
    }

    fn poll(&mut self) {
        let Some(task) = &self.task else {
            return;
        };
        match task.try_recv() {
            Ok(Ok(outcome)) => {
                if let TaskOutcome::Revoked(status) = &outcome {
                    self.status = Some(status.clone());
                }
                self.result = Some(outcome);
                self.error = None;
                self.task = None;
                self.busy = None;
            }
            Ok(Err(error)) => {
                self.error = Some(format!("{error}"));
                self.task = None;
                self.busy = None;
            }
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => {
                self.error = Some("Migration worker disconnected".into());
                self.task = None;
                self.busy = None;
            }
        }
    }

    fn ensure_status(&mut self, ctx: &egui::Context, home: Option<&Path>) {
        let Some(home) = home else {
            return;
        };
        if self.status_home.as_deref() != Some(home) {
            self.status = None;
            self.status_error = None;
            self.status_requested = false;
            self.status_task = None;
            self.status_home = Some(home.to_path_buf());
        }

        let status_result = self.status_task.as_ref().map(Receiver::try_recv);
        match status_result {
            Some(Ok(Ok(status))) => {
                self.status = status;
                self.status_error = None;
                self.status_task = None;
            }
            Some(Ok(Err(error))) => {
                self.status_error = Some(error.to_string());
                self.status_task = None;
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.status_error = Some("Migration status worker disconnected".into());
                self.status_task = None;
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
        if self.status_requested {
            return;
        }

        let home = home.to_path_buf();
        let (send, receive) = mpsc::channel();
        let ctx = ctx.clone();
        self.status_requested = true;
        match std::thread::Builder::new()
            .name("asl-migration-status".into())
            .spawn(move || {
                let result =
                    AppPaths::open_existing(&home).and_then(|paths| migration::status(&paths));
                let _ = send.send(result);
                ctx.request_repaint();
            }) {
            Ok(_) => self.status_task = Some(receive),
            Err(error) => {
                self.status_requested = false;
                self.status_error = Some(error.to_string());
            }
        }
    }

    fn start_export(&mut self, ctx: &egui::Context, home: Option<&Path>, language: Language) {
        self.error = None;
        self.result = None;
        let Some(home) = home.map(Path::to_path_buf) else {
            self.error = Some(text(language, "未配置数据目录", "No profile is open").into());
            return;
        };
        if !self.selection.contacts
            && !self.selection.trust
            && !self.selection.history
            && !self.selection.groups
        {
            self.error = Some(
                text(
                    language,
                    "至少选择一类要迁移的资料。",
                    "Select at least one kind of data to migrate.",
                )
                .into(),
            );
            return;
        }
        if self.export_passphrase.is_empty() {
            self.error = Some(
                text(
                    language,
                    "迁移包口令不能为空。",
                    "The bundle passphrase cannot be empty.",
                )
                .into(),
            );
            return;
        }
        if self.export_passphrase != self.export_confirmation {
            self.error = Some(
                text(
                    language,
                    "两次输入的口令不一致。",
                    "The two passphrases do not match.",
                )
                .into(),
            );
            return;
        }
        let directory = match local_directory(&self.export_directory, language) {
            Ok(path) => path,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let destination = directory.join(migration_filename("bundle"));
        let passphrase = SecretString::from(std::mem::take(&mut self.export_passphrase));
        self.export_confirmation.clear();
        let selection = self.selection;
        self.spawn(ctx, Busy::Export, move || {
            let paths = AppPaths::open_existing(&home)?;
            migration::export(&paths, &destination, passphrase, selection)?;
            Ok(TaskOutcome::Exported(destination))
        });
    }

    fn start_import(&mut self, ctx: &egui::Context, language: Language) {
        self.error = None;
        self.result = None;
        let source = match local_file(&self.import_source, language) {
            Ok(path) => path,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let parent = match local_directory(&self.import_parent, language) {
            Ok(path) => path,
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        if self.import_passphrase.is_empty() {
            self.error = Some(
                text(
                    language,
                    "迁移包口令不能为空。",
                    "The bundle passphrase cannot be empty.",
                )
                .into(),
            );
            return;
        }
        let destination = parent.join(migration_filename("profile"));
        let passphrase = SecretString::from(std::mem::take(&mut self.import_passphrase));
        self.spawn(ctx, Busy::Import, move || {
            let identity = migration::import_new(&source, &destination, passphrase)?;
            Ok(TaskOutcome::Imported {
                destination,
                identity,
            })
        });
    }

    fn start_revocation(&mut self, ctx: &egui::Context, home: Option<&Path>, language: Language) {
        self.error = None;
        self.result = None;
        let Some(home) = home.map(Path::to_path_buf) else {
            self.error = Some(text(language, "未配置数据目录", "No profile is open").into());
            return;
        };
        let peer = self.old_peer_id.trim().to_owned();
        if peer.is_empty() {
            self.error = Some(
                text(
                    language,
                    "请输入完整旧设备 PeerId。",
                    "Enter the full old-device PeerId.",
                )
                .into(),
            );
            return;
        }
        self.spawn(ctx, Busy::Revoke, move || {
            let paths = AppPaths::open_existing(&home)?;
            let status = migration::authorize_old_device_revocation(&paths, &peer)?;
            Ok(TaskOutcome::Revoked(status))
        });
    }

    fn spawn(
        &mut self,
        ctx: &egui::Context,
        busy: Busy,
        operation: impl FnOnce() -> Result<TaskOutcome, AslError> + Send + 'static,
    ) {
        let (send, receive) = mpsc::channel();
        let ctx = ctx.clone();
        match std::thread::Builder::new()
            .name("asl-migration-ui".into())
            .spawn(move || {
                let _ = send.send(operation());
                ctx.request_repaint();
            }) {
            Ok(_) => {
                self.task = Some(receive);
                self.busy = Some(busy);
            }
            Err(error) => {
                self.error = Some(error.to_string());
                self.busy = None;
            }
        }
    }

    fn pick_directory(&mut self, field: DirectoryField, language: Language) {
        match asl_policy::choose_local_directory() {
            Ok(Some(path)) => {
                let value = path.to_string_lossy().into_owned();
                match field {
                    DirectoryField::Export => self.export_directory = value,
                    DirectoryField::ImportParent => self.import_parent = value,
                }
                self.error = None;
            }
            Ok(None) => {}
            Err(error) => {
                self.error = Some(format!(
                    "{}: {error}",
                    text(
                        language,
                        "无法打开目录选择器",
                        "Could not open the directory picker"
                    )
                ))
            }
        }
    }
}

#[derive(Clone, Copy)]
enum Busy {
    Export,
    Import,
    Revoke,
}

#[derive(Clone, Copy)]
enum DirectoryField {
    Export,
    ImportParent,
}

enum TaskOutcome {
    Exported(PathBuf),
    Imported {
        destination: PathBuf,
        identity: MigratedIdentity,
    },
    Revoked(IdentityMigrationStatusV1),
}

fn selection_box(ui: &mut Ui, value: &mut bool, label: &str, enabled: bool) {
    ui.add_enabled(enabled, egui::Checkbox::new(value, label));
}

fn status_row(ui: &mut Ui, label: &str, value: &str) {
    ui.horizontal_wrapped(|ui| {
        ui.label(RichText::new(format!("{label}:")).strong());
        ui.add(
            egui::Label::new(RichText::new(value).color(tokens::MUTED))
                .wrap()
                .selectable(true),
        );
    });
}

fn phase_label(phase: &IdentityMigrationPhaseV1, language: Language) -> &'static str {
    match phase {
        IdentityMigrationPhaseV1::AwaitingOldDeviceRevocationAuthorization => text(
            language,
            "等待授权撤销旧设备",
            "Awaiting old-device revocation authorization",
        ),
        IdentityMigrationPhaseV1::ReadyForOnboarding => text(
            language,
            "可以开始身份引导",
            "Ready for identity onboarding",
        ),
        IdentityMigrationPhaseV1::DirectoryRegistered => {
            text(language, "身份目录已注册", "Identity directory registered")
        }
        IdentityMigrationPhaseV1::ReadyToJoin => {
            text(language, "可以重新入群", "Ready to rejoin groups")
        }
    }
}

fn yes_no(value: bool, language: Language) -> &'static str {
    if value {
        text(language, "是", "Yes")
    } else {
        text(language, "否", "No")
    }
}

fn serials(values: &[u64], language: Language) -> String {
    if values.is_empty() {
        text(language, "无", "None").into()
    } else {
        values
            .iter()
            .map(u64::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn peer_id_text(peer: &asl_types::ids::PeerId) -> String {
    libp2p_identity::PeerId::from_bytes(peer.as_bytes())
        .map(|peer| peer.to_string())
        .unwrap_or_else(|_| bs58::encode(peer.as_bytes()).into_string())
}

fn local_directory(value: &str, language: Language) -> Result<PathBuf, String> {
    let path = PathBuf::from(value.trim());
    if !path.is_absolute() {
        return Err(text(
            language,
            "请选择绝对路径的本机目录。",
            "Choose an absolute local directory.",
        )
        .into());
    }
    Ok(path)
}

fn local_file(value: &str, language: Language) -> Result<PathBuf, String> {
    let path = PathBuf::from(value.trim());
    if !path.is_absolute() || !path.is_file() {
        return Err(text(
            language,
            "请选择存在的迁移包文件。",
            "Choose an existing migration bundle.",
        )
        .into());
    }
    Ok(path)
}

fn migration_filename(prefix: &str) -> String {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("ASL-{prefix}-{timestamp}.aslmig")
}

fn text(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}
