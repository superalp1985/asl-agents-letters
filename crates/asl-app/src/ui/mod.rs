mod art;
mod avatar;
mod binding_feedback;
mod bubble;
mod checkpoint;
mod group_admin;
mod locale;
mod model_endpoints;
mod nav_icon;
mod network_privacy;
mod notification_settings;
mod profile_signing;
mod retention;
mod startup_settings;
mod tokens;
mod views;

use std::{
    ffi::OsString,
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::mpsc::{Receiver, TryRecvError, channel},
    time::{Duration, Instant},
};

use asl_app::{
    checkpoint_access::{self, CheckpointStatus},
    model_endpoint_access::{ModelEndpointAccess, ModelProviderStatus},
    network_settings::NetworkSettingsV1,
    paths::AppPaths,
};
use asl_policy::snapshot_files::PinnedHome;
use asl_store::dashboard::Dashboard;
use asl_types::error::AslError;
use eframe::egui::{self, FontData, FontDefinitions, FontFamily, Layout, RichText, Vec2};
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use views::{AccessForm, Interaction, Page};

const APP_TITLE: &str = "A\u{4fe1} ASL";
use tokens::{ACCENT, MUTED, SURFACE};

pub(super) fn run(home: Option<PathBuf>) -> eframe::Result {
    eframe::run_native(
        APP_TITLE,
        eframe::NativeOptions {
            viewport: egui::ViewportBuilder::default()
                .with_inner_size([1120.0, 720.0])
                .with_min_inner_size([460.0, 300.0])
                .with_icon(art::icon()),
            ..Default::default()
        },
        Box::new(move |context| Ok(Box::new(Viewer::new(&context.egui_ctx, home)))),
    )
}

struct Viewer {
    home: Option<PathBuf>,
    page: Page,
    snapshot: Option<Snapshot>,
    loading: Option<Receiver<Result<Snapshot, AslError>>>,
    action: Option<Receiver<bool>>,
    action_success_notice: Option<&'static str>,
    notification_settings: notification_settings::Editor,
    show_notification_settings: bool,
    close_requested: bool,
    language: locale::Language,
    access_form: AccessForm,
    retention: retention::RetentionForm,
    checkpoint_form: checkpoint::CheckpointForm,
    group_admin: group_admin::Form,
    profile_form: profile_signing::ProfileForm,
    show_startup_settings: bool,
    code_input: String,
    notice: Option<&'static str>,
    error: Option<&'static str>,
    last_refresh: Instant,
    mascot: egui::TextureHandle,
    avatar: avatar::Preview,
    remote_avatars: views::RemoteAvatars,
    last_notice_marker: Option<NoticeMarker>,
    #[cfg(windows)]
    tray: Option<(asl_policy::TrayHandle, Receiver<asl_policy::TrayCommand>)>,
}

struct Snapshot {
    dashboard: Dashboard,
    avatar: Result<Option<asl_app::avatar::AvatarPreview>, AslError>,
    network_config: Result<NetworkSettingsV1, AslError>,
    model_endpoints: Result<Vec<ModelProviderStatus>, AslError>,
    checkpoints: Result<Option<CheckpointStatus>, AslError>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct NoticeMarker {
    activity: usize,
    downloads: usize,
    uploads: usize,
    invites: usize,
    host_inbox: bool,
}

impl Viewer {
    fn new(ctx: &egui::Context, home: Option<PathBuf>) -> Self {
        theme(ctx);
        let notification_settings = notification_settings::Editor::load(home.as_deref());
        let language = notification_settings.settings.language;
        #[cfg(windows)]
        asl_policy::set_tray_language(matches!(language, locale::Language::En));
        #[cfg(windows)]
        let tray = home
            .as_ref()
            .and_then(|_| asl_policy::start_tray(art::tray_icon()));
        let mut viewer = Self {
            home: home.clone(),
            page: Page::Overview,
            snapshot: None,
            loading: None,
            action: None,
            action_success_notice: None,
            notification_settings,
            show_notification_settings: false,
            close_requested: false,
            language,
            access_form: AccessForm::default(),
            retention: retention::RetentionForm::default(),
            checkpoint_form: checkpoint::CheckpointForm::default(),
            group_admin: group_admin::Form::default(),
            profile_form: profile_signing::ProfileForm::default(),
            show_startup_settings: true,
            code_input: String::new(),
            notice: None,
            error: None,
            last_refresh: Instant::now(),
            mascot: ctx.load_texture("asl-mascot", art::mascot(), egui::TextureOptions::NEAREST),
            avatar: avatar::Preview::default(),
            remote_avatars: views::RemoteAvatars::default(),
            last_notice_marker: None,
            #[cfg(windows)]
            tray,
        };
        viewer.refresh(ctx);
        viewer
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        self.last_refresh = Instant::now();
        let Some(home) = self.home.clone() else {
            self.error = Some(label(
                self.language,
                "未配置数据目录。请用 Start-ASL.ps1 -DataDirectory 启动，或用 asl-ui.exe --home 指定已有资料目录。",
                "No data directory configured. Use Start-ASL.ps1 -DataDirectory or open an existing profile with asl-ui.exe --home.",
            ));
            return;
        };
        let (send, receive) = channel();
        let ctx = ctx.clone();
        self.error = None;
        match std::thread::Builder::new()
            .name("asl-dashboard".into())
            .spawn(move || {
                let _ = send.send(load(&home));
                ctx.request_repaint();
            }) {
            Ok(_) => self.loading = Some(receive),
            Err(_) => {
                self.error = Some(label(
                    self.language,
                    "无法读取本机状态",
                    "Could not read local state",
                ))
            }
        }
    }

    fn submit_local_action(&mut self, ctx: &egui::Context, action: LocalAction) {
        let Some(home) = self.home.clone() else {
            self.error = Some(label(
                self.language,
                "未配置数据目录",
                "Data directory is not configured",
            ));
            return;
        };
        let executable = match std::env::current_exe() {
            Ok(executable) => executable.with_file_name("asl-core.exe"),
            Err(_) => {
                self.error = Some(label(
                    self.language,
                    "无法启动本机操作",
                    "Could not start local operation",
                ));
                return;
            }
        };
        let (send, receive) = channel();
        let ctx = ctx.clone();
        let language = self.language;
        let success_notice = match action.command {
            "avatar" if action.args.first().is_some_and(|v| v == "fetch") => label(
                language,
                "已提交头像下载请求",
                "Avatar download request queued",
            ),
            "avatar" if action.args.first().is_some_and(|v| v == "cancel-fetch") => label(
                language,
                "已取消头像下载请求",
                "Avatar download request cancelled",
            ),
            "avatar" if action.args.first().is_some_and(|v| v == "approve") => {
                label(language, "已允许头像引用", "Avatar reference approved")
            }
            "avatar" if action.args.first().is_some_and(|v| v == "withdraw") => label(
                language,
                "已撤回头像引用授权",
                "Avatar reference approval withdrawn",
            ),
            "avatar" => label(language, "本机头像已更新", "Local avatar updated"),
            "bindings" if action.args.first().is_some_and(|v| v == "access") => {
                label(language, "联系人授权已更新", "Contact access updated")
            }
            "access" if action.args.first().is_some_and(|v| v == "import") => {
                label(language, "文件已纳入本机索引", "File added to local index")
            }
            "profile" if action.args.first().is_some_and(|v| v == "lookup") => label(
                language,
                "已处理资料查找请求",
                "Profile lookup request processed",
            ),
            "bindings" => label(language, "本机操作已排队", "Local operation queued"),
            "group-admin" => label(language, "群组操作已排队", "Group operation queued"),
            "group-invites" => label(
                language,
                "群邀请决定已排队",
                "Group invitation decision queued",
            ),
            "downloads" | "uploads" => {
                label(language, "传输审批已更新", "Transfer approval updated")
            }
            "direct-inbound" => label(
                language,
                "直连接收策略已更新",
                "Direct inbound policy updated",
            ),
            "group-inbound" => label(
                language,
                "群组接收策略已更新",
                "Group inbound policy updated",
            ),
            "retention" => label(
                language,
                "浏览记录保留期限已更新",
                "Activity retention updated",
            ),
            "providers" => label(
                language,
                "模型端点授权已更新",
                "Model endpoint access updated",
            ),
            "checkpoint" => label(language, "检查点请求已更新", "Checkpoint request updated"),
            "profile" => label(language, "资料授权已更新", "Profile access updated"),
            "network" => label(
                language,
                "已保存，待后台重新启动",
                "Saved, pending background restart",
            ),
            _ => label(language, "本机授权已更新", "Local authorization updated"),
        };
        match std::thread::Builder::new()
            .name("asl-local-action".into())
            .spawn(move || {
                let mut command = Command::new(executable);
                command
                    .arg(format!("--{}", action.command))
                    .args(action.args)
                    .env("ASL_HOME", home)
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null());
                #[cfg(windows)]
                command.creation_flags(0x08000000);
                let succeeded = command.status().is_ok_and(|status| status.success());
                let _ = send.send(succeeded);
                ctx.request_repaint();
            }) {
            Ok(_) => {
                self.notice = None;
                self.error = None;
                self.action_success_notice = Some(success_notice);
                self.action = Some(receive);
            }
            Err(_) => {
                self.error = Some(label(
                    self.language,
                    "无法启动本机操作",
                    "Could not start local operation",
                ))
            }
        }
    }

    fn nav(&mut self, ui: &mut egui::Ui, compact: bool) {
        for page in Page::ALL {
            let selected = self.page == page;
            let icon = nav_icon::texture(ui.ctx(), page);
            let icon = egui::Image::new((icon.id(), Vec2::splat(16.0))).tint(if selected {
                ACCENT
            } else {
                MUTED
            });
            let button = egui::Button::selectable(selected, (icon, self.language.page(page)))
                .min_size(Vec2::new(if compact { 48.0 } else { 120.0 }, 29.0));
            if ui.add(button).clicked() {
                self.page = page;
            }
        }
    }

    fn play_notification_sound(&self) {
        if self.notification_settings.should_play_sound() {
            #[cfg(windows)]
            asl_policy::play_notification_sound();
        }
    }

    fn mascot_mood(&self) -> art::Mood {
        use art::Mood;

        if self.error.is_some() {
            return Mood::Warning;
        }
        if let Some(snapshot) = &self.snapshot {
            let data = &snapshot.dashboard;
            if data.download_approvals.iter().any(|item| !item.approved)
                || data.upload_approvals.iter().any(|item| !item.approved)
                || data.group_invitations.iter().any(|item| !item.approved)
                || data.host_inbox_request.is_some()
            {
                return Mood::Waiting;
            }
            if data
                .transfers
                .iter()
                .any(|row| matches!(row.state.as_str(), "running" | "verifying"))
            {
                return Mood::Transfer;
            }
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as i64;
            if data.activity.iter().any(|row| {
                row.direction.as_deref() == Some("in")
                    && (0..10_000).contains(&now.saturating_sub(row.created_at_ms))
            }) {
                return Mood::Message;
            }
        }
        if self.notice.is_some() {
            Mood::Done
        } else {
            Mood::Idle
        }
    }

    #[cfg(windows)]
    fn poll_tray(&mut self, ctx: &egui::Context) {
        let Some((_, commands)) = &self.tray else {
            return;
        };
        loop {
            match commands.try_recv() {
                Ok(asl_policy::TrayCommand::Restore) => {
                    self.close_requested = false;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
                    ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
                }
                Ok(asl_policy::TrayCommand::Exit) => {
                    self.close_requested = true;
                    ctx.send_viewport_cmd(egui::ViewportCommand::Close);
                }
                Err(std::sync::mpsc::TryRecvError::Empty) => break,
                Err(std::sync::mpsc::TryRecvError::Disconnected) => break,
            }
        }
    }
}

impl eframe::App for Viewer {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        #[cfg(windows)]
        self.poll_tray(ctx);
        if ctx.input(|input| input.viewport().close_requested()) {
            #[cfg(windows)]
            let tray_available = self.tray.is_some();
            #[cfg(not(windows))]
            let tray_available = false;
            if tray_available
                && self.notification_settings.settings.minimize_on_close
                && !self.close_requested
            {
                self.close_requested = true;
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
                ctx.send_viewport_cmd(egui::ViewportCommand::Visible(false));
            }
        }
        #[cfg(windows)]
        if self
            .tray
            .as_ref()
            .is_some_and(|_| ctx.input(|input| input.viewport().visible() == Some(false)))
        {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
        let dashboard_result = self.loading.as_ref().map(Receiver::try_recv);
        let dashboard_finished = match dashboard_result {
            Some(Ok(Ok(mut snapshot))) => {
                let marker = NoticeMarker::from(&snapshot.dashboard);
                if self
                    .last_notice_marker
                    .is_some_and(|previous| previous != marker)
                {
                    self.play_notification_sound();
                }
                self.last_notice_marker = Some(marker);
                self.avatar
                    .update(ctx, std::mem::replace(&mut snapshot.avatar, Ok(None)));
                let dashboard = &snapshot.dashboard;
                self.group_admin.observe(
                    dashboard
                        .group_admin_snapshot
                        .as_ref()
                        .filter(|_| group_admin::enabled(&snapshot.network_config, dashboard)),
                );
                if self.snapshot.is_none() && self.notification_settings.first_launch {
                    self.show_notification_settings = true;
                }
                self.snapshot = Some(snapshot);
                true
            }
            Some(Ok(Err(error))) => {
                self.group_admin.observe(None);
                self.avatar.update(ctx, Ok(None));
                self.remote_avatars.clear();
                self.error = Some(match error {
                    AslError::UnsupportedSchemaVersion => {
                        label(self.language, "数据版本不兼容", "Incompatible data version")
                    }
                    AslError::NotFound | AslError::InvalidStorageRoot => {
                        label(self.language, "未找到本机数据", "Local data not found")
                    }
                    AslError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        label(self.language, "未找到本机数据", "Local data not found")
                    }
                    _ => label(
                        self.language,
                        "无法读取本机状态",
                        "Could not read local state",
                    ),
                });
                true
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.group_admin.observe(None);
                self.avatar.update(ctx, Ok(None));
                self.remote_avatars.clear();
                self.error = Some(label(
                    self.language,
                    "无法读取本机状态",
                    "Could not read local state",
                ));
                true
            }
            Some(Err(TryRecvError::Empty)) | None => false,
        };
        if dashboard_finished {
            self.loading = None;
        }
        if self.page != Page::Nodes || self.show_startup_settings {
            self.remote_avatars.clear();
        }
        self.remote_avatars.poll(ctx, self.home.as_deref());

        let action_result = self.action.as_ref().map(Receiver::try_recv);
        match action_result {
            Some(Ok(true)) => {
                self.action = None;
                self.notice = self.action_success_notice.take();
                self.play_notification_sound();
                self.refresh(ctx);
            }
            Some(Ok(false)) | Some(Err(TryRecvError::Disconnected)) => {
                self.action = None;
                self.action_success_notice = None;
                self.error = Some(label(
                    self.language,
                    "本机操作未能完成",
                    "Local operation failed",
                ));
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
        if matches!(
            self.page,
            Page::Overview
                | Page::Activity
                | Page::Transfers
                | Page::Groups
                | Page::Contacts
                | Page::Nodes
                | Page::Access
        ) {
            ctx.request_repaint_after(Duration::from_secs(1));
            if self.snapshot.is_some()
                && self.loading.is_none()
                && self.action.is_none()
                && self.last_refresh.elapsed() >= Duration::from_secs(5)
            {
                self.refresh(ctx);
            }
        }
    }

    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        let compact = ui.available_width() < 700.0;
        let reviewing = self.show_startup_settings && self.snapshot.is_some();
        egui::Panel::top("asl-top")
            .exact_size(48.0)
            .frame(
                egui::Frame::new()
                    .fill(SURFACE)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(
                        RichText::new(self.language.app_title())
                            .strong()
                            .size(20.0)
                            .color(ACCENT),
                    );
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        let refresh = egui::Button::new("\u{21bb}").min_size(Vec2::splat(30.0));
                        if ui
                            .add_enabled(
                                self.home.is_some()
                                    && self.loading.is_none()
                                    && self.action.is_none()
                                    && !reviewing,
                                refresh,
                            )
                            .on_hover_text(self.language.refresh())
                            .clicked()
                        {
                            self.refresh(ui.ctx());
                        }
                        let status = if self.action.is_some() {
                            label(self.language, "处理中", "Working")
                        } else if self.loading.is_some() {
                            label(self.language, "读取中", "Loading")
                        } else if self.error.is_some() && self.snapshot.is_some() {
                            label(self.language, "上次快照", "Last snapshot")
                        } else if self.snapshot.is_none() {
                            label(self.language, "未就绪", "Not ready")
                        } else {
                            label(self.language, "就绪", "Ready")
                        };
                        let mood = art::mascot_state(ui.ctx(), self.mascot_mood());
                        ui.image((mood.id(), Vec2::splat(26.0)))
                            .on_hover_text(status);
                        if !compact {
                            ui.label(RichText::new(status).color(MUTED));
                        }
                        if ui
                            .add_enabled(
                                !reviewing
                                    && self.snapshot.is_some()
                                    && self.loading.is_none()
                                    && self.action.is_none()
                                    && self.error.is_none(),
                                egui::Button::new(match self.language {
                                    locale::Language::Zh => "启动设置",
                                    locale::Language::En => "Startup settings",
                                }),
                            )
                            .clicked()
                        {
                            self.show_startup_settings = true;
                        }
                        if ui
                            .add_enabled(
                                self.snapshot.is_some(),
                                egui::Button::new(self.language.settings()),
                            )
                            .on_hover_text(match self.language {
                                locale::Language::Zh => "提醒音、窗口和语言",
                                locale::Language::En => "Sound, window and language",
                            })
                            .clicked()
                        {
                            self.show_notification_settings = true;
                        }
                        #[cfg(windows)]
                        let tray_available = self.tray.is_some();
                        #[cfg(not(windows))]
                        let tray_available = false;
                        if tray_available {
                            // Hiding keeps the agents running; only the tray menu exits.
                            if ui
                                .button(label(self.language, "隐藏到托盘", "Hide to tray"))
                                .on_hover_text(label(
                                    self.language,
                                    "只隐藏窗口，不停止后台。可在托盘菜单中退出界面。",
                                    "Hide the window without stopping the background service. Use the tray menu to quit the interface.",
                                ))
                                .clicked()
                            {
                                ui.ctx()
                                    .send_viewport_cmd(egui::ViewportCommand::Visible(false));
                            }
                        } else if ui
                            .button(self.language.quit())
                            .on_hover_text(match self.language {
                                locale::Language::Zh => "停止 ASL 界面进程",
                                locale::Language::En => "Stop the ASL interface",
                            })
                            .clicked()
                        {
                            self.close_requested = true;
                            ui.ctx().send_viewport_cmd(egui::ViewportCommand::Close);
                        }
                    });
                });
            });
        if compact {
            egui::Panel::top("asl-tabs").show(ui, |ui| {
                ui.horizontal_wrapped(|ui| self.nav(ui, true));
            });
        } else {
            egui::Panel::left("asl-nav")
                .exact_size(144.0)
                .resizable(false)
                .frame(egui::Frame::new().fill(tokens::NAV_BG).inner_margin(12))
                .show(ui, |ui| self.nav(ui, false));
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(SURFACE).inner_margin(16))
            .show(ui, |ui| {
                ui.heading(self.language.page(self.page));
                if let Some(error) = self.error {
                    banner(ui, tokens::Tone::Danger, error);
                }
                if let Some(notice) = self.notice {
                    banner(ui, tokens::Tone::Info, notice);
                }
                ui.add_space(10.0);
                if let Some(snapshot) = &self.snapshot {
                    let mut action = None;
                    let mut navigate = None;
                    let animations_enabled = self.notification_settings.animations_enabled();
                    {
                        let mut interaction = Interaction {
                            avatar: &mut self.avatar,
                            code_input: &mut self.code_input,
                            access_form: &mut self.access_form,
                            retention: &mut self.retention,
                            network_config: &snapshot.network_config,
                            model_endpoints: &snapshot.model_endpoints,
                            checkpoint_form: &mut self.checkpoint_form,
                            group_admin: &mut self.group_admin,
                            profile_form: &mut self.profile_form,
                            remote_avatars: &mut self.remote_avatars,
                            checkpoints: &snapshot.checkpoints,
                            language: self.language,
                            actions_enabled: !self.show_startup_settings
                                && !self.show_notification_settings
                                && self.action.is_none()
                                && self.loading.is_none(),
                            animations_enabled,
                            action: &mut action,
                            navigate: &mut navigate,
                        };
                        self.page
                            .show(ui, &snapshot.dashboard, &self.mascot, &mut interaction);
                    }
                    if let Some(page) = navigate {
                        self.page = page;
                    }
                    if let Some(action) = action {
                        self.submit_local_action(ui.ctx(), action);
                    }
                } else if self.loading.is_none() {
                    ui.image((self.mascot.id(), Vec2::splat(72.0)));
                }
            });
        if self.show_startup_settings
            && !self.show_notification_settings
            && let Some(snapshot) = &self.snapshot
            && let Some(decision) = startup_settings::show(ui.ctx(), snapshot, self.language)
        {
            self.show_startup_settings = false;
            if let startup_settings::Decision::Open(page) = decision {
                self.page = page;
            }
        }
        if self.show_notification_settings
            && let Some(decision) = self.notification_settings.show(ui.ctx())
        {
            match decision {
                notification_settings::Decision::Save => {
                    if self.notification_settings.persist(self.home.as_deref()) {
                        self.language = self.notification_settings.settings.language;
                        #[cfg(windows)]
                        asl_policy::set_tray_language(matches!(
                            self.language,
                            locale::Language::En
                        ));
                        self.show_notification_settings = false;
                        self.notice = Some(label(
                            self.language,
                            "界面设置已保存",
                            "Interface settings saved",
                        ));
                    }
                }
                notification_settings::Decision::Cancel => {
                    self.show_notification_settings = false;
                }
            }
        }
    }
}

pub(super) struct LocalAction {
    command: &'static str,
    args: Vec<OsString>,
}

impl LocalAction {
    fn new<const N: usize>(command: &'static str, args: [OsString; N]) -> Self {
        Self {
            command,
            args: args.into(),
        }
    }
}

fn label(language: locale::Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        locale::Language::Zh => zh,
        locale::Language::En => en,
    }
}

fn load(home: &Path) -> Result<Snapshot, AslError> {
    let paths = AppPaths::open_existing(home)?;
    let _pin = PinnedHome::open(home)?;
    let database = paths.state().join("asl.sqlite3");
    if !database.is_file() {
        return Err(AslError::NotFound);
    }
    Ok(Snapshot {
        dashboard: Dashboard::load(&database)?,
        avatar: asl_app::avatar::preview(&paths),
        network_config: NetworkSettingsV1::load(&paths.network_settings_configuration()),
        model_endpoints: ModelEndpointAccess::new(&paths).list(),
        checkpoints: checkpoint_access::status(&paths),
    })
}

impl From<&Dashboard> for NoticeMarker {
    fn from(dashboard: &Dashboard) -> Self {
        Self {
            activity: dashboard.activity.len(),
            downloads: dashboard.download_approvals.len(),
            uploads: dashboard.upload_approvals.len(),
            invites: dashboard.group_invitations.len(),
            host_inbox: dashboard.host_inbox_request.is_some(),
        }
    }
}

/// Inline notification strip used for page level notices and errors.
fn banner(ui: &mut egui::Ui, tone: tokens::Tone, text: &str) {
    let (fill, stroke) = tone.colors();
    egui::Frame::new()
        .fill(fill)
        .stroke(egui::Stroke::new(1.0, stroke.gamma_multiply(0.35)))
        .corner_radius(tokens::radius_small())
        .inner_margin(egui::Margin::symmetric(10, 6))
        .show(ui, |ui| {
            ui.set_width(ui.available_width());
            ui.label(RichText::new(text).color(stroke));
        });
}

fn theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::light();
    let small = tokens::radius_small();
    visuals.panel_fill = tokens::BG;
    visuals.window_fill = SURFACE;
    visuals.window_stroke = tokens::border();
    visuals.window_corner_radius = tokens::radius();
    visuals.menu_corner_radius = tokens::radius();
    visuals.faint_bg_color = tokens::DIVIDER;
    visuals.extreme_bg_color = SURFACE;
    visuals.override_text_color = None;
    visuals.hyperlink_color = ACCENT;
    visuals.error_fg_color = tokens::DANGER;
    visuals.warn_fg_color = tokens::WARNING;

    let widgets = &mut visuals.widgets;
    widgets.noninteractive.bg_fill = SURFACE;
    widgets.noninteractive.weak_bg_fill = SURFACE;
    widgets.noninteractive.bg_stroke = egui::Stroke::new(1.0, tokens::DIVIDER);
    widgets.noninteractive.fg_stroke.color = tokens::TEXT;
    widgets.noninteractive.corner_radius = small;

    widgets.inactive.bg_fill = tokens::BUTTON;
    widgets.inactive.weak_bg_fill = tokens::BUTTON;
    widgets.inactive.bg_stroke = tokens::border();
    widgets.inactive.fg_stroke.color = tokens::TEXT;
    widgets.inactive.corner_radius = small;

    widgets.hovered.bg_fill = tokens::BUTTON_HOVER;
    widgets.hovered.weak_bg_fill = tokens::BUTTON_HOVER;
    widgets.hovered.bg_stroke = egui::Stroke::new(1.0, ACCENT.gamma_multiply(0.6));
    widgets.hovered.fg_stroke.color = tokens::TEXT;
    widgets.hovered.corner_radius = small;
    widgets.hovered.expansion = 0.0;

    widgets.active.bg_fill = tokens::BUTTON_PRESSED;
    widgets.active.weak_bg_fill = tokens::BUTTON_PRESSED;
    widgets.active.bg_stroke = egui::Stroke::new(1.0, ACCENT);
    widgets.active.fg_stroke.color = tokens::TEXT;
    widgets.active.corner_radius = small;
    widgets.active.expansion = 0.0;

    widgets.open = widgets.active;

    visuals.selection.bg_fill = tokens::ACCENT_SOFT;
    visuals.selection.stroke = egui::Stroke::new(1.0, ACCENT);
    ctx.set_visuals(visuals);
    ctx.style_mut_of(egui::Theme::Light, |style| {
        style.spacing.item_spacing = Vec2::new(10.0, 8.0);
        style.spacing.button_padding = Vec2::new(12.0, 7.0);
        style.spacing.interact_size.y = 26.0;
        style.visuals.window_fill = SURFACE;
        style.visuals.disabled_alpha = 0.55;
        style.visuals.widgets.noninteractive.fg_stroke.color = tokens::TEXT;
    });

    let Some(windows) = std::env::var_os("WINDIR").map(PathBuf::from) else {
        return;
    };
    if let Ok(bytes) = std::fs::read(windows.join("Fonts").join("msyh.ttc")) {
        let mut fonts = FontDefinitions::default();
        fonts
            .font_data
            .insert("system-cjk".into(), FontData::from_owned(bytes).into());
        for family in [FontFamily::Proportional, FontFamily::Monospace] {
            fonts
                .families
                .entry(family)
                .or_default()
                .push("system-cjk".into());
        }
        ctx.set_fonts(fonts);
    }
}
