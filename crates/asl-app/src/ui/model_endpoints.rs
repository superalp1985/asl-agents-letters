use asl_agent::gateway::ProviderMode;
use asl_app::model_endpoint_access::ModelProviderStatus;
use asl_types::error::AslError;
use eframe::egui::{RichText, Ui};

use super::{LocalAction, MUTED, locale::Language};

pub(super) fn show(
    ui: &mut Ui,
    snapshot: &Result<Vec<ModelProviderStatus>, AslError>,
    language: Language,
    actions_enabled: bool,
    action: &mut Option<LocalAction>,
) {
    ui.label(RichText::new(label(language, "模型端点", "Model endpoints")).strong());
    let endpoints = match snapshot {
        Ok(endpoints) if endpoints.is_empty() => {
            ui.label(
                RichText::new(label(
                    language,
                    "未配置模型端点",
                    "No model endpoints configured",
                ))
                .color(MUTED),
            );
            return;
        }
        Ok(endpoints) => endpoints,
        Err(_) => {
            ui.label(label(
                language,
                "无法读取模型端点配置或授权",
                "Unable to read model endpoint configuration or grants",
            ));
            return;
        }
    };

    for endpoint in endpoints {
        let config = &endpoint.config;
        ui.push_id(&config.id.0, |ui| {
            let location = match config.mode {
                ProviderMode::Local => label(language, "本机回环", "Local loopback"),
                ProviderMode::Remote => "Remote HTTPS",
            };
            let status = if endpoint.authorized {
                label(language, "已授权", "Authorized")
            } else if !config.enabled_by_user {
                label(language, "配置已停用", "Disabled")
            } else {
                label(language, "未授权", "Not authorized")
            };
            ui.label(
                RichText::new(format!("{}  ·  {location}  ·  {status}", config.id.0)).strong(),
            );
            ui.label(format!("模型：{}", config.model));
            ui.label(format!("地址：{}", config.endpoint));
            ui.horizontal_wrapped(|ui| {
                if ui
                    .add_enabled(
                        actions_enabled && config.enabled_by_user && !endpoint.authorized,
                        eframe::egui::Button::new(label(
                            language,
                            "授权此端点",
                            "Authorize endpoint",
                        )),
                    )
                    .on_hover_text("允许向此地址发送已另获模型披露许可的内容")
                    .clicked()
                {
                    *action = Some(LocalAction::new(
                        "providers",
                        [
                            "allow".into(),
                            (&config.id.0).into(),
                            (&endpoint.fingerprint).into(),
                        ],
                    ));
                }
                if ui
                    .add_enabled(
                        actions_enabled,
                        eframe::egui::Button::new(label(language, "撤销", "Revoke")),
                    )
                    .on_hover_text("阻止后续发送；无法收回已发出的数据")
                    .clicked()
                {
                    *action = Some(LocalAction::new(
                        "providers",
                        ["revoke".into(), (&config.id.0).into()],
                    ));
                }
            });
            ui.add_space(8.0);
        });
    }
}

fn label(language: Language, zh: &'static str, en: &'static str) -> &'static str {
    match language {
        Language::Zh => zh,
        Language::En => en,
    }
}
