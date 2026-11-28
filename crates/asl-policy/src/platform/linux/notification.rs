use std::io::Write;

pub fn play_notification_sound() {
    let mut stderr = std::io::stderr().lock();
    let _ = stderr.write_all(b"\x07");
    let _ = stderr.flush();
}

pub fn send_notification(summary: &str, body: &str) -> bool {
    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    else {
        return false;
    };
    runtime.block_on(async {
        notify_rust::Notification::new()
            .appname("ASL")
            .summary(summary)
            .body(body)
            .timeout(5_000)
            .show_async()
            .await
            .is_ok()
    })
}
