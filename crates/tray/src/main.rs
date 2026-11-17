//! `tunnel-tray` — значок в области уведомлений Windows (этап 7.5).
#![cfg_attr(windows, windows_subsystem = "windows")]

mod backend;
mod model;
#[cfg(windows)]
mod win;

#[cfg(windows)]
fn main() {
    // IPC-клиент демона подключается при интеграции; пока — заглушка.
    let backend = backend::StubBackend::demo();
    if let Err(e) = win::run(&backend, model::NotifyMode::default()) {
        win::error_box(&format!("tunnel-tray: {e}"));
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("tunnel-tray: только Windows");
    std::process::exit(1);
}
