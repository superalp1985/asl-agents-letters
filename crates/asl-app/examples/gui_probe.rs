use std::time::Duration;

use egui;
use rmcp::transport::stdio;
use rusqlite::Connection;

#[derive(serde::Serialize)]
struct ProbeState {
    ready: bool,
}

#[derive(Default)]
struct ProbeApp;

impl eframe::App for ProbeApp {
    fn ui(&mut self, ui: &mut egui::Ui, _frame: &mut eframe::Frame) {
        egui::CentralPanel::default().show(ui, |ui| {
            ui.label("A信 ASL");
        });
        ui.ctx().request_repaint_after(Duration::from_secs(60));
    }
}

fn sqlite_fts5_probe() -> rusqlite::Result<()> {
    let connection = Connection::open_in_memory()?;
    connection.execute_batch(
        "CREATE VIRTUAL TABLE probe USING fts5(content, tokenize = 'unicode61');
         INSERT INTO probe(content) VALUES ('asl permissioned knowledge');",
    )?;
    let _: i64 = connection.query_row(
        "SELECT count(*) FROM probe WHERE probe MATCH ?1",
        ["permissioned"],
        |row| row.get(0),
    )?;
    Ok(())
}

fn main() {
    let _ = std::any::type_name::<eframe::NativeOptions>();
    let _ = std::any::type_name::<Connection>();
    let _stdio: fn() -> (tokio::io::Stdin, tokio::io::Stdout) = stdio;
    let _ = std::any::type_name::<tokio::runtime::Runtime>();
    let _ = serde_json::to_string(&ProbeState { ready: true });
    let _ = blake3::hash(b"probe");
    sqlite_fts5_probe().expect("bundled SQLite FTS5 is unavailable");
    let _ = ProbeApp;
}
