//! `tunnel-tray` — значок в области уведомлений Windows (этап 7.5).
//!
//! По умолчанию — IPC-клиент службы-демона; `--demo` — заглушка в памяти
//! (ручная проверка меню и уведомлений без демона).
#![cfg_attr(windows, windows_subsystem = "windows")]

mod backend;
mod model;
mod remote;
#[cfg(windows)]
mod win;

#[cfg(windows)]
fn main() {
    let demo = std::env::args().skip(1).any(|a| a == "--demo");
    let backend: Box<dyn backend::TrayBackend> = if demo {
        Box::new(backend::StubBackend::demo())
    } else {
        Box::new(remote::IpcTrayBackend::start())
    };
    if let Err(e) = win::run(backend.as_ref(), model::NotifyMode::default()) {
        win::error_box(&format!("tunnel-tray: {e}"));
        std::process::exit(1);
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("tunnel-tray: только Windows");
    std::process::exit(1);
}
