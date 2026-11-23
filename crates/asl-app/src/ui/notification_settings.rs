use std::{fs, path::Path};

use asl_app::paths::AppPaths;
use eframe::egui::{self, Context, RichText, Ui};
use serde::{Deserialize, Serialize};

use super::locale::Language;
use super::{ACCENT, MUTED};

const VERSION: u8 = 1;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(super) struct Settings {
    pub(super) version: u8,
    #[serde(default)]
    pub(super) language: Language,
    pub(super) minimize_on_close: bool,
    pub(super) sound_enabled: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            version: VERSION,
            language: Language::Zh,
            minimize_on_close: true,
            sound_enabled: true,
        }
    }
}

#[derive(Default)]
pub(super) struct Editor {
    pub(super) settings: Settings,
    saved: Settings,
    error: Option<&'static str>,
    pub(super) first_launch: bool,
}

impl Editor {
    pub(super) fn load(home: Option<&Path>) -> Self {
        let stored = home
            .and_then(|home| AppPaths::open_existing(home).ok())
            .and_then(|paths| fs::read(paths.ui_configuration()).ok())
            .and_then(|bytes| serde_json::from_slice::<Settings>(&bytes).ok())
            .filter(|settings| settings.version == VERSION);
        let settings = stored.clone().unwrap_or_default();
        Self {
            saved: settings.clone(),
            settings,
            error: None,
            first_launch: stored.is_none(),
        }
    }

    pub(super) fn persist(&mut self, home: Option<&Path>) -> bool {
        let Some(home) = home else {
            self.error = Some(label(
                self.settings.language,
                "未配置数据目录，无法保存界面设置",
                "Data directory is not configured. Interface settings were not saved.",
            ));
            return false;
        };
        let Ok(paths) = AppPaths::open_existing(home) else {
            self.error = Some(label(
                self.settings.language,
                "无法打开本机数据目录",
                "Could not open the local data directory",
            ));
            return false;
        };
        let Ok(bytes) = serde_json::to_vec_pretty(&self.settings) else {
            self.error = Some(label(
                self.settings.language,
                "无法编码界面设置",
                "Could not encode interface settings",
            ));
            return false;
        };
        if fs::write(paths.ui_configuration(), bytes).is_err() {
            self.error = Some(label(
                self.settings.language,
                "无法保存界面设置",
                "Could not save interface settings",
            ));
            return false;
        }
        self.saved = self.settings.clone();
        self.first_launch = false;
        self.error = None;
        true
    }

    pub(super) fn show(&mut self, ctx: &Context) -> Option<Decision> {
        let mut decision = None;
        egui::Modal::new(egui::Id::new("notification-settings")).show(ctx, |ui| {
            let available = ctx.content_rect();
            ui.set_width((available.width() - 40.0).clamp(280.0, 500.0));
            ui.heading(if self.first_launch {
                "选择语言 / Choose language"
            } else {
                match self.settings.language {
                    Language::Zh => "提醒与窗口",
                    Language::En => "Sound and window",
                }
            });
            if self.first_launch {
                ui.label(
                    RichText::new(match self.settings.language {
                        Language::Zh => "中文是默认语言，之后可在设置中切换。",
                        Language::En => "Chinese is the default. You can switch later in Settings.",
                    })
                    .color(MUTED),
                );
            }
            ui.label(RichText::new(self.settings.language.choose_language()).strong());
            ui.horizontal(|ui| {
                for language in [Language::Zh, Language::En] {
                    if ui
                        .add(egui::Button::selectable(
                            self.settings.language == language,
                            language.label(),
                        ))
                        .clicked()
                    {
                        self.settings.language = language;
                    }
                }
            });
            ui.label(
                RichText::new(match self.settings.language {
                    Language::Zh => "这些选项只影响本机界面，不会改变 Agent 间协议或网络授权。",
                    Language::En => {
                        "These options affect this interface only, not protocol or network grants."
                    }
                })
                .color(MUTED),
            );
            ui.separator();

            setting_row(
                ui,
                &mut self.settings.minimize_on_close,
                match self.settings.language {
                    Language::Zh => "关闭窗口时隐藏",
                    Language::En => "Hide when the window closes",
                },
                match self.settings.language {
                    Language::Zh => "Agent 在后台继续运行；只有托盘菜单“退出”才会真正退出。",
                    Language::En => "The Agent keeps running in the background. Only Exit in the tray menu quits.",
                },
            );
            setting_row(
                ui,
                &mut self.settings.sound_enabled,
                match self.settings.language {
                    Language::Zh => "播放提醒音",
                    Language::En => "Play notification sound",
                },
                match self.settings.language {
                    Language::Zh => "收到消息或文件时播放 Windows 系统提示音，可随时关闭。",
                    Language::En => "Play the Windows system sound when a message or file arrives. You can turn it off at any time.",
                },
            );

            if let Some(error) = self.error {
                super::banner(ui, super::tokens::Tone::Danger, error);
            }
            ui.separator();
            ui.horizontal(|ui| {
                if ui
                    .button(match self.settings.language {
                        Language::Zh => "保存",
                        Language::En => "Save",
                    })
                    .clicked()
                {
                    decision = Some(Decision::Save);
                }
                if ui
                    .button(match self.settings.language {
                        Language::Zh => "取消",
                        Language::En => "Cancel",
                    })
                    .clicked()
                {
                    self.settings = self.saved.clone();
                    self.error = None;
                    decision = Some(Decision::Cancel);
                }
                ui.label(
                    RichText::new(if self.settings == self.saved {
                        match self.settings.language {
                            Language::Zh => "已保存",
                            Language::En => "Saved",
                        }
                    } else {
                        match self.settings.language {
                            Language::Zh => "有未保存变更",
                            Language::En => "Unsaved changes",
                        }
                    })
                    .color(ACCENT),
                );
            });
        });
        decision
    }

    pub(super) fn should_play_sound(&self) -> bool {
        self.settings.sound_enabled
    }
}

pub(super) enum Decision {
    Save,
    Cancel,
}

fn setting_row(ui: &mut Ui, value: &mut bool, label: &str, detail: &str) {
    ui.horizontal(|ui| {
        ui.checkbox(value, label);
        ui.label(RichText::new(detail).color(MUTED));
    });
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
    fn missing_language_in_an_older_settings_file_defaults_to_chinese() {
        let settings: Settings =
            serde_json::from_str(r#"{"version":1,"minimize_on_close":true,"sound_enabled":false}"#)
                .unwrap();
        assert_eq!(settings.language, Language::Zh);
        assert!(settings.minimize_on_close);
        assert!(!settings.sound_enabled);
    }

    #[test]
    fn default_settings_start_in_chinese_and_hide_on_close() {
        let settings = Settings::default();
        assert_eq!(settings.language, Language::Zh);
        assert!(settings.minimize_on_close);
        assert!(settings.sound_enabled);
    }
}
