use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};

use ksni::blocking::{Handle, TrayMethods};
use ksni::menu::{MenuItem, StandardItem};

static ENGLISH_MENU: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TrayCommand {
    Restore,
    Exit,
}

pub fn set_tray_language(english: bool) {
    ENGLISH_MENU.store(english, Ordering::Relaxed);
}

pub struct TrayHandle {
    handle: Handle<LinuxTray>,
}

impl Drop for TrayHandle {
    fn drop(&mut self) {
        self.handle.shutdown().wait();
    }
}

struct LinuxTray {
    commands: Sender<TrayCommand>,
    icon: Option<ksni::Icon>,
}

impl ksni::Tray for LinuxTray {
    fn id(&self) -> String {
        "asl.desktop".to_owned()
    }

    fn title(&self) -> String {
        "ASL".to_owned()
    }

    fn icon_name(&self) -> String {
        "dialog-information".to_owned()
    }

    fn icon_pixmap(&self) -> Vec<ksni::Icon> {
        self.icon.iter().cloned().collect()
    }

    fn activate(&mut self, _x: i32, _y: i32) {
        let _ = self.commands.send(TrayCommand::Restore);
    }

    fn menu(&self) -> Vec<MenuItem<Self>> {
        let (restore_label, exit_label) = if ENGLISH_MENU.load(Ordering::Relaxed) {
            ("Show ASL", "Quit ASL")
        } else {
            ("显示 ASL", "退出 ASL")
        };
        let restore = self.commands.clone();
        let exit = self.commands.clone();
        vec![
            StandardItem {
                label: restore_label.to_owned(),
                activate: Box::new(move |_| {
                    let _ = restore.send(TrayCommand::Restore);
                }),
                ..Default::default()
            }
            .into(),
            MenuItem::Separator,
            StandardItem {
                label: exit_label.to_owned(),
                activate: Box::new(move |_| {
                    let _ = exit.send(TrayCommand::Exit);
                }),
                ..Default::default()
            }
            .into(),
        ]
    }
}

pub fn start_tray(icon_png: &'static [u8]) -> Option<(TrayHandle, Receiver<TrayCommand>)> {
    let (sender, receiver) = channel();
    let tray = LinuxTray {
        commands: sender,
        icon: decode_icon(icon_png),
    };
    let handle = tray.assume_sni_available(true).spawn().ok()?;
    Some((TrayHandle { handle }, receiver))
}

fn decode_icon(bytes: &[u8]) -> Option<ksni::Icon> {
    let image = image::load_from_memory(bytes).ok()?.into_rgba8();
    let (width, height) = image.dimensions();
    let mut data = Vec::with_capacity(
        (width as usize)
            .checked_mul(height as usize)?
            .checked_mul(4)?,
    );
    for pixel in image.pixels() {
        let [red, green, blue, alpha] = pixel.0;
        data.extend_from_slice(&[alpha, red, green, blue]);
    }
    Some(ksni::Icon {
        width: i32::try_from(width).ok()?,
        height: i32::try_from(height).ok()?,
        data,
    })
}
