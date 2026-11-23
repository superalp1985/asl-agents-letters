use windows::Win32::{System::Diagnostics::Debug::MessageBeep, UI::WindowsAndMessaging::MB_OK};

pub fn play_notification_sound() {
    // The system sound respects the user's Windows volume and mute settings.
    let _ = unsafe { MessageBeep(MB_OK) };
}
