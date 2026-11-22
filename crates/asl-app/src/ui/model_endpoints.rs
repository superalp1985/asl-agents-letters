use asl_agent::gateway::ProviderMode;
use asl_app::model_endpoint_access::ModelProviderStatus;
use asl_types::error::AslError;
use eframe::egui::{RichText, Ui};

use super::{LocalAction, MUTED};

pub(super) fn show(
    ui: &mut Ui,
    snapshot: &Result<Vec<ModelProviderStatus>, AslError>,
    actions_enabled: bool,
    action: &mut Option<LocalAction>,
) {
    ui.label(RichText::new("模型端点").strong());
    let endpoints = match snapshot {
        Ok(endpoints) if endpoints.is_empty() => {
            ui.label(RichText::new("未配置模型端点").color(MUTED));
            return;
        }
        Ok(endpoints) => endpoints,
        Err(_) => {
            ui.label("无法读取模型端点配置或授权");
            return;
        }
    };

    for endpoint in endpoints {
        let config = &endpoint.config;
        ui.push_id(&config.id.0, |ui| {
            let location = match config.mode {
                ProviderMode::Local => "本机回环",
                ProviderMode::Remote => "远端 HTTPS",
            };
            let status = if endpoint.authorized {
                "已授权"
            } else if !config.enabled_by_user {
                "配置已停用"
            } else {
                "未授权"
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
                        eframe::egui::Button::new("授权此端点"),
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
                    .add_enabled(actions_enabled, eframe::egui::Button::new("撤销"))
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
