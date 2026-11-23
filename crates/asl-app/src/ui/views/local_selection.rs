use std::path::Path;

use eframe::egui::{self, Ui};

use crate::ui::locale::Language;

pub(super) fn directory(
    ui: &mut Ui,
    path: &mut String,
    error: &mut Option<&'static str>,
    language: Language,
) {
    ui.horizontal_wrapped(|ui| {
        ui.add(
            egui::TextEdit::singleline(path)
                .hint_text(label(
                    language,
                    "本机目录的完整路径",
                    "Full local directory path",
                ))
                .desired_width((ui.available_width() - 92.0).clamp(80.0, 540.0)),
        );
        if ui
            .button(label(language, "选择目录", "Choose directory"))
            .clicked()
        {
            *error = None;
            match asl_policy::choose_local_directory() {
                Ok(Some(p)) => match p.to_str() {
                    Some(value) => *path = value.to_owned(),
                    None => {
                        *error = Some(label(
                            language,
                            "目录名无法表示，请选择其他目录",
                            "Directory name cannot be represented",
                        ))
                    }
                },
                Ok(None) => {}
                Err(_) => {
                    *error = Some(label(
                        language,
                        "无法打开目录选择器，可手动输入路径",
                        "Directory picker failed, enter the path manually",
                    ))
                }
            }
        }
    });
}

pub(super) fn file(
    ui: &mut Ui,
    root: &Path,
    relative: &mut String,
    error: &mut Option<&'static str>,
    language: Language,
) {
    if !ui
        .button(label(language, "选择文件", "Choose file"))
        .clicked()
    {
        return;
    }
    *error = None;
    match asl_policy::choose_local_file() {
        Ok(Some(p)) => match p.strip_prefix(root).ok().and_then(Path::to_str) {
            Some(value) if !value.is_empty() => *relative = value.to_owned(),
            _ => {
                relative.clear();
                *error = Some(label(
                    language,
                    "请选择当前授权目录内的文件",
                    "Choose a file inside the granted directory",
                ));
            }
        },
        Ok(None) => {}
        Err(_) => {
            *error = Some(label(
                language,
                "无法打开文件选择器，可手动输入相对路径",
                "File picker failed, enter a relative path manually",
            ))
        }
    }
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}
