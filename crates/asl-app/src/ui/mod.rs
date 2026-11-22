mod art;
mod binding_feedback;
mod checkpoint;
mod model_endpoints;
mod network_privacy;
mod retention;
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
use eframe::egui::{self, Color32, FontData, FontDefinitions, FontFamily, Layout, RichText, Vec2};
#[cfg(windows)]
use std::os::windows::process::CommandExt;

use views::{AccessForm, Interaction, Page};

const APP_TITLE: &str = "A\u{4fe1} ASL";
const ACCENT: Color32 = Color32::from_rgb(18, 99, 90);
const MUTED: Color32 = Color32::from_rgb(84, 100, 104);
const SURFACE: Color32 = Color32::from_rgb(252, 253, 252);

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
    access_form: AccessForm,
    retention: retention::RetentionForm,
    checkpoint_form: checkpoint::CheckpointForm,
    code_input: String,
    notice: Option<&'static str>,
    error: Option<&'static str>,
    last_refresh: Instant,
    mascot: egui::TextureHandle,
}

struct Snapshot {
    dashboard: Dashboard,
    network_config: Result<NetworkSettingsV1, AslError>,
    model_endpoints: Result<Vec<ModelProviderStatus>, AslError>,
    checkpoints: Result<Option<CheckpointStatus>, AslError>,
}

impl Viewer {
    fn new(ctx: &egui::Context, home: Option<PathBuf>) -> Self {
        theme(ctx);
        let mut viewer = Self {
            home,
            page: Page::Overview,
            snapshot: None,
            loading: None,
            action: None,
            action_success_notice: None,
            access_form: AccessForm::default(),
            retention: retention::RetentionForm::default(),
            checkpoint_form: checkpoint::CheckpointForm::default(),
            code_input: String::new(),
            notice: None,
            error: None,
            last_refresh: Instant::now(),
            mascot: ctx.load_texture("asl-mascot", art::mascot(), egui::TextureOptions::NEAREST),
        };
        viewer.refresh(ctx);
        viewer
    }

    fn refresh(&mut self, ctx: &egui::Context) {
        self.last_refresh = Instant::now();
        let Some(home) = self.home.clone() else {
            self.error = Some("未配置数据目录");
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
            Err(_) => self.error = Some("无法读取本机状态"),
        }
    }

    fn submit_local_action(&mut self, ctx: &egui::Context, action: LocalAction) {
        let Some(home) = self.home.clone() else {
            self.error = Some("未配置数据目录");
            return;
        };
        let executable = match std::env::current_exe() {
            Ok(executable) => executable.with_file_name("asl-core.exe"),
            Err(_) => {
                self.error = Some("无法启动本机操作");
                return;
            }
        };
        let (send, receive) = channel();
        let ctx = ctx.clone();
        let success_notice = match action.command {
            "bindings" => "本机操作已排队",
            "downloads" | "uploads" => "传输审批已更新",
            "direct-inbound" => "直连接收策略已更新",
            "group-inbound" => "群组接收策略已更新",
            "retention" => "浏览记录保留期限已更新",
            "providers" => "模型端点授权已更新",
            "checkpoint" => "检查点请求已更新",
            "network" => "已保存，待后台重新启动",
            _ => "本机授权已更新",
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
            Err(_) => self.error = Some("无法启动本机操作"),
        }
    }

    fn nav(&mut self, ui: &mut egui::Ui, compact: bool) {
        for page in Page::ALL {
            let button = egui::Button::selectable(self.page == page, page.name())
                .min_size(Vec2::new(if compact { 48.0 } else { 120.0 }, 29.0));
            if ui.add(button).clicked() {
                self.page = page;
            }
        }
    }
}

impl eframe::App for Viewer {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        let dashboard_result = self.loading.as_ref().map(Receiver::try_recv);
        let dashboard_finished = match dashboard_result {
            Some(Ok(Ok(snapshot))) => {
                self.snapshot = Some(snapshot);
                true
            }
            Some(Ok(Err(error))) => {
                self.error = Some(match error {
                    AslError::UnsupportedSchemaVersion => "数据版本不兼容",
                    AslError::NotFound | AslError::InvalidStorageRoot => "未找到本机数据",
                    AslError::Io(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        "未找到本机数据"
                    }
                    _ => "无法读取本机状态",
                });
                true
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.error = Some("无法读取本机状态");
                true
            }
            Some(Err(TryRecvError::Empty)) | None => false,
        };
        if dashboard_finished {
            self.loading = None;
        }

        let action_result = self.action.as_ref().map(Receiver::try_recv);
        match action_result {
            Some(Ok(true)) => {
                self.action = None;
                self.notice = self.action_success_notice.take();
                self.refresh(ctx);
            }
            Some(Ok(false)) | Some(Err(TryRecvError::Disconnected)) => {
                self.action = None;
                self.action_success_notice = None;
                self.error = Some("本机操作未能完成");
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
        if matches!(
            self.page,
            Page::Activity
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
        egui::Panel::top("asl-top")
            .exact_size(48.0)
            .frame(
                egui::Frame::new()
                    .fill(SURFACE)
                    .inner_margin(egui::Margin::symmetric(16, 8)),
            )
            .show(ui, |ui| {
                ui.horizontal_centered(|ui| {
                    ui.label(RichText::new(APP_TITLE).strong().size(20.0).color(ACCENT));
                    ui.with_layout(Layout::right_to_left(egui::Align::Center), |ui| {
                        let refresh = egui::Button::new("\u{21bb}").min_size(Vec2::splat(30.0));
                        if ui
                            .add_enabled(
                                self.home.is_some()
                                    && self.loading.is_none()
                                    && self.action.is_none(),
                                refresh,
                            )
                            .on_hover_text("刷新")
                            .clicked()
                        {
                            self.refresh(ui.ctx());
                        }
                        let status = if self.action.is_some() {
                            "处理中"
                        } else if self.loading.is_some() {
                            "读取中"
                        } else if self.error.is_some() && self.snapshot.is_some() {
                            "上次快照"
                        } else {
                            "就绪"
                        };
                        ui.label(RichText::new(status).color(MUTED));
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
                .frame(
                    egui::Frame::new()
                        .fill(Color32::from_rgb(233, 242, 239))
                        .inner_margin(12),
                )
                .show(ui, |ui| self.nav(ui, false));
        }
        egui::CentralPanel::default()
            .frame(egui::Frame::new().fill(SURFACE).inner_margin(16))
            .show(ui, |ui| {
                ui.heading(self.page.name());
                if let Some(error) = self.error {
                    ui.label(RichText::new(error).color(Color32::from_rgb(144, 61, 38)));
                }
                if let Some(notice) = self.notice {
                    ui.label(RichText::new(notice).color(ACCENT));
                }
                ui.add_space(10.0);
                if let Some(snapshot) = &self.snapshot {
                    let mut action = None;
                    {
                        let mut interaction = Interaction {
                            code_input: &mut self.code_input,
                            access_form: &mut self.access_form,
                            retention: &mut self.retention,
                            network_config: &snapshot.network_config,
                            model_endpoints: &snapshot.model_endpoints,
                            checkpoint_form: &mut self.checkpoint_form,
                            checkpoints: &snapshot.checkpoints,
                            actions_enabled: self.action.is_none() && self.loading.is_none(),
                            action: &mut action,
                        };
                        self.page
                            .show(ui, &snapshot.dashboard, &self.mascot, &mut interaction);
                    }
                    if let Some(action) = action {
                        self.submit_local_action(ui.ctx(), action);
                    }
                } else if self.loading.is_none() {
                    ui.image((self.mascot.id(), Vec2::splat(72.0)));
                }
            });
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

fn load(home: &Path) -> Result<Snapshot, AslError> {
    let paths = AppPaths::open_existing(home)?;
    let _pin = PinnedHome::open(home)?;
    let database = paths.state().join("asl.sqlite3");
    if !database.is_file() {
        return Err(AslError::NotFound);
    }
    Ok(Snapshot {
        dashboard: Dashboard::load(&database)?,
        network_config: NetworkSettingsV1::load(&paths.network_settings_configuration()),
        model_endpoints: ModelEndpointAccess::new(&paths).list(),
        checkpoints: checkpoint_access::status(&paths),
    })
}

fn theme(ctx: &egui::Context) {
    let mut visuals = egui::Visuals::light();
    visuals.selection.bg_fill = Color32::from_rgb(197, 231, 222);
    visuals.selection.stroke.color = ACCENT;
    ctx.set_visuals(visuals);

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
