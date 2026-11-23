use asl_app::avatar::AvatarPreview;
use asl_types::error::AslError;
use eframe::egui::{self, RichText, TextureHandle, Vec2};

use super::{ACCENT, LocalAction, MUTED, locale::Language};

#[derive(Default)]
pub(super) struct Preview {
    displayed: Option<DisplayedAvatar>,
    invalid: bool,
    picker_failed: bool,
    show_presets: bool,
}

struct DisplayedAvatar {
    texture: TextureHandle,
    token: Option<String>,
    approved: bool,
}

impl Preview {
    pub(super) fn update(
        &mut self,
        ctx: &egui::Context,
        result: Result<Option<AvatarPreview>, AslError>,
    ) {
        self.invalid = result.is_err();
        self.displayed = result.ok().flatten().map(|preview| {
            let AvatarPreview {
                image,
                token,
                approved,
            } = preview;
            let size = [image.width() as usize, image.height() as usize];
            let texture = ctx.load_texture(
                "asl-local-avatar",
                egui::ColorImage::from_rgba_unmultiplied(size, image.as_raw()),
                egui::TextureOptions::LINEAR,
            );
            DisplayedAvatar {
                texture,
                token,
                approved,
            }
        });
    }

    pub(super) fn image(&self, ui: &mut egui::Ui, mascot: &TextureHandle) {
        let texture = self
            .displayed
            .as_ref()
            .map_or(mascot, |avatar| &avatar.texture);
        let size = texture.size_vec2();
        let fitted = size * (72.0 / size.x.max(size.y));
        let (rect, _) = ui.allocate_exact_size(Vec2::splat(72.0), egui::Sense::hover());
        ui.painter()
            .rect_filled(rect, super::tokens::radius(), super::tokens::AVATAR_BG);
        egui::Image::new((texture.id(), fitted))
            .paint_at(ui, egui::Rect::from_center_size(rect.center(), fitted));
        let status = self
            .displayed
            .as_ref()
            .map(|avatar| avatar.approved)
            .unwrap_or(false);
        let dot = egui::Rect::from_center_size(
            rect.right_bottom() - Vec2::new(7.0, 7.0),
            Vec2::splat(10.0),
        );
        ui.painter().circle_filled(
            dot.center(),
            5.0,
            if status {
                ACCENT
            } else {
                super::tokens::WARNING
            },
        );
    }

    pub(super) fn controls(
        &mut self,
        ui: &mut egui::Ui,
        enabled: bool,
        language: Language,
        action: &mut Option<LocalAction>,
    ) {
        ui.add_space(6.0);
        ui.horizontal_wrapped(|ui| {
            ui.label(
                RichText::new(label(language, "本机头像", "Local avatar"))
                    .strong()
                    .color(MUTED),
            );
            if ui
                .add_enabled(
                    enabled,
                    egui::Button::new(label(language, "预设头像", "Preset avatars")),
                )
                .clicked()
            {
                self.show_presets = !self.show_presets;
            }
            if ui
                .add_enabled(
                    enabled,
                    egui::Button::new(label(language, "选择图片", "Choose image")),
                )
                .clicked()
            {
                self.picker_failed = false;
                match asl_policy::choose_avatar_file() {
                    Ok(Some(path)) => {
                        *action = Some(LocalAction::new("avatar", ["set".into(), path.into()]));
                    }
                    Ok(None) => {}
                    Err(_) => self.picker_failed = true,
                }
            }
            if ui
                .add_enabled(
                    enabled && action.is_none() && (self.displayed.is_some() || self.invalid),
                    egui::Button::new(label(language, "移除头像", "Remove avatar")),
                )
                .clicked()
            {
                self.picker_failed = false;
                *action = Some(LocalAction::new("avatar", ["clear".into()]));
            }
        });
        if self.show_presets {
            ui.horizontal_wrapped(|ui| {
                ui.spacing_mut().item_spacing = Vec2::splat(8.0);
                for index in 0..asl_app::avatar::presets::PNGS.len() {
                    let texture = super::art::preset(ui.ctx(), index);
                    let title = format!("{} {}", label(language, "头像", "Avatar"), index + 1);
                    let image = egui::Image::new((texture.id(), Vec2::splat(42.0)));
                    if ui
                        .add_enabled(enabled && action.is_none(), egui::Button::image(image))
                        .on_hover_text(title)
                        .clicked()
                    {
                        self.picker_failed = false;
                        self.show_presets = false;
                        *action = Some(LocalAction::new(
                            "avatar",
                            ["preset".into(), (index + 1).to_string().into()],
                        ));
                    }
                }
            });
        }
        if let Some(avatar) = &self.displayed {
            match (&avatar.token, avatar.approved) {
                (None, _) => {
                    ui.weak(label(
                        language,
                        "仅本机可见。请初始化身份并重新选择图片后再授权引用。",
                        "Visible only locally. Initialize identity and choose the image again before approving its reference.",
                    ));
                }
                (Some(token), approved) => {
                    ui.horizontal_wrapped(|ui| {
                        ui.weak(if approved {
                            label(
                                language,
                                "已允许在公开资料中引用（不发送图片）",
                                "Approved for public profile reference (image not sent)",
                            )
                        } else {
                            label(language, "仅本机可见", "Visible only locally")
                        });
                        let button = if approved {
                            egui::Button::new(label(
                                language,
                                "撤回头像引用授权",
                                "Withdraw avatar reference",
                            ))
                        } else {
                            egui::Button::new(label(
                                language,
                                "允许引用此头像",
                                "Approve avatar reference",
                            ))
                        };
                        if ui
                            .push_id(("avatar-reference", token), |ui| {
                                ui.add_enabled(enabled && action.is_none(), button)
                                    .on_hover_text(if approved {
                                        label(
                                            language,
                                            "撤回后不再允许附上头像内容 ID，已收到的引用无法撤回。",
                                            "New profiles will no longer include the avatar content ID. References already received cannot be recalled.",
                                        )
                                    } else {
                                        label(
                                            language,
                                            "仅允许公开资料附上此预览的内容 ID，不发送图片，也不启用资料公开。",
                                            "Allows public profiles to include this preview's content ID. It does not send the image or enable profile publication.",
                                        )
                                    })
                                    .clicked()
                            })
                            .inner
                        {
                            *action = if approved {
                                Some(LocalAction::new("avatar", ["withdraw".into()]))
                            } else {
                                self.approval_action()
                            };
                        }
                    });
                }
            }
        }
        if self.picker_failed {
            ui.label(label(
                language,
                "无法打开图片选择器",
                "Could not open the image picker",
            ));
        } else if self.invalid {
            ui.label(label(
                language,
                "无法读取本机头像",
                "Could not read the local avatar",
            ));
        }
    }

    fn approval_action(&self) -> Option<LocalAction> {
        let avatar = self.displayed.as_ref().filter(|avatar| !avatar.approved)?;
        Some(LocalAction::new(
            "avatar",
            ["approve".into(), avatar.token.as_deref()?.into()],
        ))
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
    fn avatar_approval_uses_only_the_displayed_preview_token() {
        let ctx = egui::Context::default();
        let mut view = Preview::default();
        let preview = |color, token: Option<&str>, approved| {
            Ok(Some(AvatarPreview {
                image: image::RgbaImage::from_pixel(1, 1, image::Rgba([color; 4])),
                token: token.map(str::to_owned),
                approved,
            }))
        };
        assert!(view.approval_action().is_none());
        view.update(&ctx, preview(123, None, false));
        assert!(view.displayed.is_some());
        assert!(view.approval_action().is_none());
        view.update(&ctx, preview(123, Some("first"), false));
        let first = view.approval_action().unwrap();
        view.update(&ctx, preview(246, Some("replacement"), false));
        let replacement = view.approval_action().unwrap();
        assert_eq!(first.command, "avatar");
        assert_eq!(first.args, ["approve", "first"]);
        assert_eq!(replacement.args, ["approve", "replacement"]);
        view.update(&ctx, preview(246, Some("replacement"), true));
        assert!(view.approval_action().is_none());
        view.update(&ctx, Ok(None));
        assert!(view.displayed.is_none());
        assert!(view.approval_action().is_none());
        view.update(&ctx, preview(123, Some("first"), false));
        view.update(&ctx, Err(AslError::InvalidDatabase));
        assert!(view.displayed.is_none());
        assert!(view.approval_action().is_none());
    }
}
