use std::{
    path::Path,
    sync::mpsc::{Receiver, TryRecvError, channel},
    time::{Duration, Instant},
};

use asl_app::{
    avatar::{self, MAX_AVATAR_EDGE},
    paths::AppPaths,
};
use asl_store::dashboard::{Dashboard, RemoteProfileRow};
use asl_types::{
    error::AslError,
    ids::{AgentId, Hash32},
};
use eframe::egui::{self, Button, RichText, TextureHandle, Ui, Vec2};

use super::{line, remaining};
use crate::ui::{LocalAction, MUTED, locale::Language, profile_signing::topic_labels};

const CHECK_INTERVAL: Duration = Duration::from_secs(1);
const MAX_CHECK_AGE: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct Target {
    owner: AgentId,
    content: Hash32,
}

impl Target {
    fn from_row(row: &RemoteProfileRow, now_ms: i64) -> Option<Self> {
        if now_ms <= 0 || row.expires_at_ms <= now_ms {
            return None;
        }
        let mut owner = [0; 32];
        if bs58::decode(row.agent_id.as_str())
            .onto(&mut owner[..])
            .ok()?
            != owner.len()
        {
            return None;
        }
        let content =
            alloy_primitives::hex::decode_to_array(row.avatar_content_id.as_deref()?).ok()?;
        Some(Self {
            owner: AgentId(owner),
            content: Hash32(content),
        })
    }

    fn fetch_action(self) -> LocalAction {
        LocalAction::new(
            "avatar",
            [
                "fetch".into(),
                bs58::encode(self.owner.as_bytes()).into_string().into(),
                alloy_primitives::hex::encode(self.content.as_bytes()).into(),
            ],
        )
    }
}

enum CacheState {
    Ready(TextureHandle),
    Missing,
    Unavailable,
}

struct Checked {
    target: Target,
    started: Instant,
    state: CacheState,
}

impl Checked {
    fn current(&self, target: Target, now: Instant) -> bool {
        self.target == target && now.saturating_duration_since(self.started) < MAX_CHECK_AGE
    }
}

struct CacheRead {
    target: Target,
    started: Instant,
    image: Result<Option<image::RgbaImage>, AslError>,
}

impl CacheRead {
    fn current(&self, selected: Option<Target>, now: Instant) -> bool {
        selected == Some(self.target) && now.saturating_duration_since(self.started) < MAX_CHECK_AGE
    }
}

#[derive(Default)]
pub(in crate::ui) struct RemoteAvatars {
    selected: Option<Target>,
    checked: Option<Checked>,
    loading: Option<Receiver<CacheRead>>,
    last_started: Option<Instant>,
}

impl RemoteAvatars {
    pub(in crate::ui) fn clear(&mut self) {
        self.select(None);
    }

    fn select(&mut self, target: Option<Target>) {
        if self.selected != target {
            self.selected = target;
            self.checked = None;
            self.last_started = None;
        }
    }

    fn retain_live_selection(&mut self, rows: &[RemoteProfileRow], now_ms: i64) {
        if self.selected.is_some_and(|target| {
            !rows
                .iter()
                .any(|row| Target::from_row(row, now_ms) == Some(target))
        }) {
            self.clear();
        }
    }

    pub(in crate::ui) fn poll(&mut self, ctx: &egui::Context, home: Option<&Path>) {
        match self.loading.as_ref().map(Receiver::try_recv) {
            Some(Ok(read)) => {
                self.loading = None;
                if read.current(self.selected, Instant::now()) {
                    self.checked = Some(self.finish_read(ctx, read));
                }
            }
            Some(Err(TryRecvError::Disconnected)) => {
                self.loading = None;
                self.checked = None;
            }
            Some(Err(TryRecvError::Empty)) | None => {}
        }
        let (Some(home), Some(target)) = (home, self.selected) else {
            return;
        };
        if self.loading.is_some() {
            return;
        }
        let started = Instant::now();
        if let Some(last) = self.last_started {
            let wait = CHECK_INTERVAL.saturating_sub(started.saturating_duration_since(last));
            if !wait.is_zero() {
                ctx.request_repaint_after(wait);
                return;
            }
        }
        let home = home.to_owned();
        let worker_ctx = ctx.clone();
        let (send, receive) = channel();
        self.last_started = Some(started);
        if std::thread::Builder::new()
            .name("asl-remote-avatar".into())
            .spawn(move || {
                let image = AppPaths::open_existing(&home)
                    .and_then(|paths| avatar::received(&paths, target.owner, target.content));
                let _ = send.send(CacheRead {
                    target,
                    started,
                    image,
                });
                worker_ctx.request_repaint();
            })
            .is_ok()
        {
            self.loading = Some(receive);
        } else {
            self.checked = None;
            ctx.request_repaint_after(CHECK_INTERVAL);
        }
    }

    fn finish_read(&self, ctx: &egui::Context, read: CacheRead) -> Checked {
        let state = match read.image {
            Ok(Some(image))
                if (1..=MAX_AVATAR_EDGE).contains(&image.width())
                    && (1..=MAX_AVATAR_EDGE).contains(&image.height()) =>
            {
                let existing = self.checked.as_ref().and_then(|checked| {
                    if checked.target == read.target
                        && let CacheState::Ready(texture) = &checked.state
                    {
                        return Some(texture.clone());
                    }
                    None
                });
                CacheState::Ready(existing.unwrap_or_else(|| {
                    ctx.load_texture(
                        "asl-remote-avatar",
                        egui::ColorImage::from_rgba_unmultiplied(
                            [image.width() as usize, image.height() as usize],
                            image.as_raw(),
                        ),
                        egui::TextureOptions::LINEAR,
                    )
                }))
            }
            Ok(None) => CacheState::Missing,
            Ok(Some(_)) | Err(_) => CacheState::Unavailable,
        };
        Checked {
            target: read.target,
            started: read.started,
            state,
        }
    }

    pub(super) fn show(
        &mut self,
        ui: &mut Ui,
        data: &Dashboard,
        now_ms: i64,
        enabled: bool,
        language: Language,
        action: &mut Option<LocalAction>,
    ) {
        if ui
            .add_enabled(
                enabled && action.is_none(),
                Button::new(label(language, "取消头像下载", "Cancel avatar download")),
            )
            .clicked()
        {
            *action = Some(LocalAction::new("avatar", ["cancel-fetch".into()]));
        }

        let rows = &data.remote_profiles;
        self.retain_live_selection(rows, now_ms);
        if now_ms <= 0 || !rows.iter().any(|row| row.expires_at_ms > now_ms) {
            ui.weak(label(
                language,
                "暂无已验签的公开资料",
                "No verified public profiles",
            ));
            return;
        }

        let widths = [175.0, 145.0, 160.0, 105.0];
        egui::ScrollArea::horizontal()
            .id_salt("remote-avatar-references")
            .show(ui, |ui| {
                line(
                    ui,
                    [
                        "AgentId",
                        label(language, "自报主题", "Declared topics"),
                        label(language, "头像内容 ID", "Avatar content ID"),
                        label(language, "资料有效期", "Profile expiry"),
                    ],
                    widths,
                    8.0,
                    true,
                );
                ui.separator();
                for row in rows.iter().filter(|row| row.expires_at_ms > now_ms) {
                    let target = Target::from_row(row, now_ms);
                    let topics = topic_labels()
                        .filter_map(|(id, label)| row.topics.contains(&id).then_some(label))
                        .collect::<Vec<_>>()
                        .join("、");
                    ui.push_id((&row.agent_id, &row.avatar_content_id), |ui| {
                        ui.horizontal(|ui| {
                            line(
                                ui,
                                [
                                    &row.agent_id,
                                    &topics,
                                    row.avatar_content_id.as_deref().unwrap_or(label(
                                        language,
                                        "无引用",
                                        "No reference",
                                    )),
                                    &remaining(row.expires_at_ms, now_ms, language),
                                ],
                                widths,
                                8.0,
                                false,
                            );
                            if let Some(target) = target
                                && ui
                                    .add(Button::selectable(
                                        self.selected == Some(target),
                                        label(language, "查看头像引用", "View avatar reference"),
                                    ))
                                    .clicked()
                            {
                                self.select((self.selected != Some(target)).then_some(target));
                                ui.ctx().request_repaint();
                            }
                        });
                        if let Some(target) = target.filter(|target| self.selected == Some(*target))
                        {
                            ui.ctx().request_repaint_after(Duration::from_millis(
                                (row.expires_at_ms - now_ms) as u64,
                            ));
                            self.show_preview(
                                ui,
                                target,
                                row,
                                enabled && !data.network_pause_requested,
                                language,
                                action,
                            );
                        }
                    });
                    ui.separator();
                }
            });
    }

    fn show_preview(
        &self,
        ui: &mut Ui,
        target: Target,
        row: &RemoteProfileRow,
        enabled: bool,
        language: Language,
        action: &mut Option<LocalAction>,
    ) {
        let now = Instant::now();
        let state = self.checked.as_ref().and_then(|checked| {
            checked.current(target, now).then(|| {
                ui.ctx().request_repaint_after(
                    MAX_CHECK_AGE.saturating_sub(now.saturating_duration_since(checked.started)),
                );
                &checked.state
            })
        });
        ui.horizontal(|ui| {
            let (rect, _) = ui.allocate_exact_size(Vec2::splat(56.0), egui::Sense::hover());
            ui.painter().rect_filled(
                rect,
                crate::ui::tokens::radius(),
                crate::ui::tokens::AVATAR_BG,
            );
            let caption = match state {
                Some(CacheState::Ready(texture)) => {
                    let size = texture.size_vec2();
                    let fitted = size * (56.0 / size.x.max(size.y));
                    egui::Image::new((texture.id(), fitted))
                        .paint_at(ui, egui::Rect::from_center_size(rect.center(), fitted));
                    label(language, "本机已验证缓存", "Verified local cache")
                }
                Some(CacheState::Missing) => label(
                    language,
                    "无可显示的已验证缓存",
                    "No verified cache to display",
                ),
                Some(CacheState::Unavailable) => label(
                    language,
                    "无法读取已验证缓存",
                    "Could not read verified cache",
                ),
                None => label(language, "正在核对本机缓存", "Checking local cache"),
            };
            ui.label(RichText::new(caption).color(MUTED));
            if !matches!(state, Some(CacheState::Ready(_)))
                && ui
                    .add_enabled(
                        enabled && action.is_none(),
                        Button::new(label(language, "下载此头像", "Download avatar")),
                    )
                    .on_hover_text(format!(
                        "AgentId: {}\n内容 ID: {}",
                        row.agent_id,
                        row.avatar_content_id.as_deref().unwrap_or_default()
                    ))
                    .clicked()
            {
                *action = Some(target.fetch_action());
            }
        });
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
    use std::ffi::OsString;

    use super::*;

    fn row(owner: u8, content: u8) -> RemoteProfileRow {
        RemoteProfileRow {
            agent_id: bs58::encode([owner; 32]).into_string(),
            topics: vec![101],
            avatar_content_id: Some(alloy_primitives::hex::encode([content; 32])),
            expires_at_ms: 200,
        }
    }

    #[test]
    fn remote_avatar_fetch_uses_the_exact_reviewed_profile_reference() {
        let mut row = row(3, 4);
        let target = Target::from_row(&row, 199).unwrap();
        let action = target.fetch_action();
        assert_eq!(action.command, "avatar");
        assert_eq!(
            action.args,
            [
                OsString::from("fetch"),
                row.agent_id.clone().into(),
                row.avatar_content_id.clone().unwrap().into(),
            ]
        );
        assert!(Target::from_row(&row, 200).is_none());
        row.avatar_content_id = None;
        assert!(Target::from_row(&row, 199).is_none());
    }

    #[test]
    fn remote_avatar_preview_rejects_other_references_and_lapsed_checks() {
        let started = Instant::now();
        let target = Target::from_row(&row(3, 4), 199).unwrap();
        let checked = Checked {
            target,
            started,
            state: CacheState::Missing,
        };
        assert!(checked.current(target, started));
        for changed in [row(9, 4), row(3, 9)] {
            assert!(!checked.current(Target::from_row(&changed, 199).unwrap(), started));
        }
        assert!(!checked.current(target, started + MAX_CHECK_AGE));
        for (rows, now_ms) in [
            (vec![], 199),
            (vec![row(3, 9)], 199),
            (vec![row(3, 4)], 200),
        ] {
            let mut state = RemoteAvatars {
                selected: Some(target),
                checked: Some(Checked {
                    target,
                    started,
                    state: CacheState::Missing,
                }),
                ..RemoteAvatars::default()
            };
            state.retain_live_selection(&rows, now_ms);
            assert!(state.selected.is_none());
            assert!(state.checked.is_none());
        }
    }

    #[test]
    fn remote_avatar_late_read_cannot_restore_a_cleared_preview() {
        let started = Instant::now();
        let target = Target::from_row(&row(3, 4), 199).unwrap();
        let read = CacheRead {
            target,
            started,
            image: Ok(Some(image::RgbaImage::new(1, 1))),
        };
        assert!(read.current(Some(target), started));
        assert!(!read.current(None, started));
        assert!(!read.current(Some(target), started + MAX_CHECK_AGE));
    }
}
