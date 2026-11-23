use std::{
    mem::size_of,
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{Receiver, Sender, SyncSender, channel, sync_channel},
    },
    thread,
    time::Duration,
};

use windows::{
    Win32::{
        Foundation::{HWND, LPARAM, POINT, WPARAM},
        System::Threading::GetCurrentThreadId,
        UI::{
            Shell::{
                NIF_ICON, NIF_MESSAGE, NIF_TIP, NIM_ADD, NIM_DELETE, NOTIFYICONDATAW,
                Shell_NotifyIconW,
            },
            WindowsAndMessaging::{
                AppendMenuW, CS_HREDRAW, CS_VREDRAW, CreateIconFromResourceEx, CreatePopupMenu,
                CreateWindowExW, DefWindowProcW, DestroyIcon, DestroyMenu, DestroyWindow,
                GetCursorPos, HICON, IDC_ARROW, IDI_APPLICATION, LR_DEFAULTSIZE, LoadCursorW,
                LoadIconW, MF_STRING, PostQuitMessage, PostThreadMessageW, RegisterClassW,
                SetForegroundWindow, TPM_RIGHTBUTTON, TRACK_POPUP_MENU_FLAGS, WINDOW_EX_STYLE,
                WINDOW_STYLE, WM_APP, WM_COMMAND, WM_DESTROY, WM_LBUTTONDBLCLK, WM_LBUTTONUP,
                WM_QUIT, WM_RBUTTONUP, WNDCLASSW,
            },
        },
    },
    core::w,
};

const TRAY_MESSAGE: u32 = WM_APP + 41;
const RESTORE_COMMAND: usize = 1;
const EXIT_COMMAND: usize = 2;

static COMMANDS: OnceLock<Mutex<Option<Sender<TrayCommand>>>> = OnceLock::new();
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
    thread_id: u32,
}

impl Drop for TrayHandle {
    fn drop(&mut self) {
        let _ = unsafe { PostThreadMessageW(self.thread_id, WM_QUIT, WPARAM(0), LPARAM(0)) };
        if let Some(commands) = COMMANDS.get()
            && let Ok(mut commands) = commands.lock()
        {
            *commands = None;
        }
    }
}

pub fn start_tray(icon_png: &'static [u8]) -> Option<(TrayHandle, Receiver<TrayCommand>)> {
    let (command_tx, command_rx) = channel();
    let commands = COMMANDS.get_or_init(|| Mutex::new(None));
    *commands.lock().ok()? = Some(command_tx);

    let (ready_tx, ready_rx) = sync_channel(1);
    thread::Builder::new()
        .name("asl-windows-tray".into())
        .spawn(move || run(ready_tx, icon_png))
        .ok()?;
    let thread_id = ready_rx
        .recv_timeout(Duration::from_secs(2))
        .ok()
        .flatten()?;
    Some((TrayHandle { thread_id }, command_rx))
}

struct OwnedIcon(HICON);

impl Drop for OwnedIcon {
    fn drop(&mut self) {
        let _ = unsafe { DestroyIcon(self.0) };
    }
}

fn run(ready: SyncSender<Option<u32>>, icon_png: &[u8]) {
    let thread_id = unsafe { GetCurrentThreadId() };
    let class_name = w!("ASL.Tray");
    let Ok(cursor) = (unsafe { LoadCursorW(None, IDC_ARROW) }) else {
        let _ = ready.send(None);
        return;
    };
    let custom_icon =
        unsafe { CreateIconFromResourceEx(icon_png, true, 0x0003_0000, 0, 0, LR_DEFAULTSIZE) }
            .ok()
            .map(OwnedIcon);
    let Ok(icon) = custom_icon.as_ref().map_or_else(
        || unsafe { LoadIconW(None, IDI_APPLICATION) },
        |icon| Ok(icon.0),
    ) else {
        let _ = ready.send(None);
        return;
    };
    let class = WNDCLASSW {
        style: CS_HREDRAW | CS_VREDRAW,
        lpfnWndProc: Some(tray_window_proc),
        hCursor: cursor,
        lpszClassName: class_name,
        ..Default::default()
    };
    unsafe {
        RegisterClassW(&class);
    }
    let Ok(window) = (unsafe {
        CreateWindowExW(
            WINDOW_EX_STYLE(0),
            class_name,
            w!("ASL"),
            WINDOW_STYLE(0),
            0,
            0,
            0,
            0,
            None,
            None,
            None,
            None,
        )
    }) else {
        let _ = ready.send(None);
        return;
    };

    let mut data = NOTIFYICONDATAW {
        cbSize: size_of::<NOTIFYICONDATAW>() as u32,
        hWnd: window,
        uID: 1,
        uFlags: NIF_MESSAGE | NIF_ICON | NIF_TIP,
        uCallbackMessage: TRAY_MESSAGE,
        hIcon: icon,
        ..Default::default()
    };
    let tip = "ASL".encode_utf16().chain(std::iter::once(0));
    for (slot, value) in data.szTip.iter_mut().zip(tip) {
        *slot = value;
    }
    let added = unsafe { Shell_NotifyIconW(NIM_ADD, &data).as_bool() };
    if !added {
        let _ = unsafe { DestroyWindow(window) };
        let _ = ready.send(None);
        return;
    }
    let _ = ready.send(Some(thread_id));

    let mut message = windows::Win32::UI::WindowsAndMessaging::MSG::default();
    loop {
        let result = unsafe {
            windows::Win32::UI::WindowsAndMessaging::GetMessageW(&mut message, None, 0, 0)
        };
        if result.0 <= 0 || message.message == WM_QUIT {
            break;
        }
        unsafe {
            windows::Win32::UI::WindowsAndMessaging::DispatchMessageW(&message);
        }
    }
    unsafe {
        let _ = Shell_NotifyIconW(NIM_DELETE, &data);
        let _ = DestroyWindow(window);
        PostQuitMessage(0);
    }
}

unsafe extern "system" fn tray_window_proc(
    window: HWND,
    message: u32,
    wparam: WPARAM,
    lparam: LPARAM,
) -> windows::Win32::Foundation::LRESULT {
    if message == TRAY_MESSAGE {
        match lparam.0 as u32 {
            WM_LBUTTONUP | WM_LBUTTONDBLCLK => send_command(TrayCommand::Restore),
            WM_RBUTTONUP => show_menu(window),
            _ => {}
        }
        return windows::Win32::Foundation::LRESULT(0);
    }
    if message == WM_COMMAND {
        match wparam.0 & 0xffff {
            RESTORE_COMMAND => send_command(TrayCommand::Restore),
            EXIT_COMMAND => send_command(TrayCommand::Exit),
            _ => {}
        }
        return windows::Win32::Foundation::LRESULT(0);
    }
    if message == WM_DESTROY {
        unsafe { PostQuitMessage(0) };
        return windows::Win32::Foundation::LRESULT(0);
    }
    unsafe { DefWindowProcW(window, message, wparam, lparam) }
}

fn send_command(command: TrayCommand) {
    if let Some(commands) = COMMANDS.get()
        && let Ok(commands) = commands.lock()
        && let Some(sender) = commands.as_ref()
    {
        let _ = sender.send(command);
    }
}

fn show_menu(window: HWND) {
    let Ok(menu) = (unsafe { CreatePopupMenu() }) else {
        return;
    };
    unsafe {
        if ENGLISH_MENU.load(Ordering::Relaxed) {
            let _ = AppendMenuW(menu, MF_STRING, RESTORE_COMMAND, w!("Show ASL"));
            let _ = AppendMenuW(menu, MF_STRING, EXIT_COMMAND, w!("Quit ASL"));
        } else {
            let _ = AppendMenuW(menu, MF_STRING, RESTORE_COMMAND, w!("显示 ASL"));
            let _ = AppendMenuW(menu, MF_STRING, EXIT_COMMAND, w!("退出 ASL"));
        }
        let _ = SetForegroundWindow(window);
        let mut point = POINT::default();
        if GetCursorPos(&mut point).is_ok() {
            let _ = windows::Win32::UI::WindowsAndMessaging::TrackPopupMenu(
                menu,
                TRACK_POPUP_MENU_FLAGS(TPM_RIGHTBUTTON.0),
                point.x,
                point.y,
                Some(0),
                window,
                None,
            );
        }
        let _ = DestroyMenu(menu);
    }
}
