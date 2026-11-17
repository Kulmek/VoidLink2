//! Режимы демона. `console` — рабочий (лог, замок, хаб); `service`,
//! `install`, `uninstall` — заглушки до 7.6 (`windows-service`, SCM, SDDL).

#![allow(dead_code)] // подключается при интеграции

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use crate::hub::{Backend, Hub};
use crate::lock::InstanceLock;
use crate::log::{Level, LogFn, Logger};

/// Бэкенд без движка: пока `tunnel-engine` не подключён, `console`
/// поднимает хаб на нём (пустой снимок, команды отклоняются).
pub struct NullBackend;

impl Backend for NullBackend {
    fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({ "engine": null })
    }
    fn poll_events(&self) -> Vec<serde_json::Value> {
        Vec::new()
    }
    fn send(&self, _cmd: serde_json::Value) -> Result<(), String> {
        Err("движок не подключён".into())
    }
    fn me(&self) -> serde_json::Value {
        serde_json::Value::Null
    }
    fn changed(&self) -> bool {
        false
    }
}

/// `tunnel-daemon console`: замок, лог (файл + stderr), цикл хаба до `stop`.
/// `make_backend` получает колбэк лога — интеграция отдаёт его движку
/// (вместо `eprintln!`); тот же лог получает хаб (переполнения подписчиков).
pub fn run_console<B: Backend>(
    data_dir: &Path,
    debug: bool,
    make_backend: impl FnOnce(LogFn) -> B,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let _lock = InstanceLock::acquire(data_dir).map_err(|e| e.to_string())?;
    let level = if debug { Level::Debug } else { Level::Info };
    let log = Logger::open(&crate::log_dir(data_dir), level, true)
        .map_err(|e| format!("лог {}: {e}", crate::log_dir(data_dir).display()))?;
    log.log(Level::Info, &format!("демон запущен (console), данные: {}", data_dir.display()));
    let hub = Hub::with_log(make_backend(log.callback()), log.callback());
    hub.run(&stop);
    log.log(Level::Info, "демон остановлен");
    Ok(())
}

static STOP: OnceLock<Arc<AtomicBool>> = OnceLock::new();

/// Ctrl+C (и SIGTERM на Unix, закрытие консоли на Windows) взводит `stop`,
/// чтобы [`run_console`] вышел штатно: лог «демон остановлен», drop замка.
/// Повторный вызов ничего не меняет (флаг — первый переданный).
pub fn install_ctrl_handler(stop: Arc<AtomicBool>) {
    if STOP.set(stop).is_err() {
        return;
    }
    #[cfg(unix)]
    {
        extern "C" fn on_signal(_: libc::c_int) {
            // Только атомарная запись — async-signal-safe.
            if let Some(s) = STOP.get() {
                s.store(true, Ordering::Relaxed);
            }
        }
        let h = on_signal as extern "C" fn(libc::c_int) as libc::sighandler_t;
        // SAFETY: обработчик лишь пишет в атомик, инициализированный выше.
        unsafe {
            libc::signal(libc::SIGINT, h);
            libc::signal(libc::SIGTERM, h);
        }
    }
    #[cfg(windows)]
    {
        unsafe extern "system" fn on_ctrl(_: u32) -> windows_sys::core::BOOL {
            if let Some(s) = STOP.get() {
                s.store(true, Ordering::Relaxed);
            }
            1 // обработано: процесс не убивается сразу
        }
        // SAFETY: обработчик лишь пишет в атомик, инициализированный выше.
        unsafe { windows_sys::Win32::System::Console::SetConsoleCtrlHandler(Some(on_ctrl), 1) };
    }
}

/// `tunnel-daemon service`: точка входа SCM (7.6).
pub fn run_service(_data_dir: &Path) -> Result<(), String> {
    Err("режим service ещё не реализован (этап 7.6)".into())
}

/// `tunnel-daemon install` (7.6).
pub fn install() -> Result<(), String> {
    Err("install ещё не реализован (этап 7.6)".into())
}

/// `tunnel-daemon uninstall [--purge]` (7.6).
pub fn uninstall(_purge: bool) -> Result<(), String> {
    Err("uninstall ещё не реализован (этап 7.6)".into())
}
