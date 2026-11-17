//! Режимы демона. `console` — рабочий (лог, замок, хаб, IPC); `service`,
//! `install`, `uninstall` — заглушки до 7.6 (`windows-service`, SCM, SDDL).

#![allow(dead_code)] // подключается при интеграции

use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};

use crate::hub::{Backend, Hub};
use crate::lock::InstanceLock;
use crate::log::{Level, LogFn, Logger};
use crate::server::IpcServer;

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

/// Где демон слушает фронтендов.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcMode {
    /// Без IPC (Windows `console`: пайп поднимает только служба, PLAN.md 7.2).
    None,
    /// Unix-сокет `<данные>/daemon.sock`.
    #[cfg(unix)]
    Unix,
    /// Named pipe службы: имя и SID владельца (из `owner.sid`).
    #[cfg(windows)]
    Pipe { name: String, owner_sid: Option<String> },
}

impl IpcMode {
    /// IPC режима `console`: на Unix — сокет, на Windows — нет.
    pub fn console_default() -> Self {
        #[cfg(unix)]
        {
            IpcMode::Unix
        }
        #[cfg(not(unix))]
        {
            IpcMode::None
        }
    }
}

/// Параметры запуска ядра демона.
#[derive(Debug, Clone)]
pub struct RunOpts {
    pub data_dir: std::path::PathBuf,
    pub debug: bool,
    /// Дублировать лог в stderr.
    pub console_log: bool,
    pub ipc: IpcMode,
    /// Причина в `Shutdown` фронтендам при остановке.
    pub stop_reason: String,
}

impl RunOpts {
    pub fn console(data_dir: &Path, debug: bool) -> Self {
        RunOpts {
            data_dir: data_dir.to_path_buf(),
            debug,
            console_log: true,
            ipc: IpcMode::console_default(),
            stop_reason: "демон остановлен".into(),
        }
    }
}

/// `tunnel-daemon console`: замок, лог (файл + stderr), IPC (Unix-сокет;
/// на Windows без пайпа), цикл хаба до `stop`.
/// `make_backend` получает колбэк лога — интеграция отдаёт его движку
/// (вместо `eprintln!`); тот же лог получает хаб (переполнения подписчиков).
pub fn run_console<B: Backend + 'static>(
    data_dir: &Path,
    debug: bool,
    make_backend: impl FnOnce(LogFn) -> B,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    run_daemon(&RunOpts::console(data_dir, debug), make_backend, stop)
}

/// Ядро демона для любого режима: замок single-instance, лог, хаб, IPC-сервер;
/// блокирует до `stop`, затем `Shutdown` фронтендам и выход. Второй экземпляр
/// на том же каталоге данных (Windows — на той же машине) получает ошибку замка.
pub fn run_daemon<B: Backend + 'static>(
    opts: &RunOpts,
    make_backend: impl FnOnce(LogFn) -> B,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let data_dir = opts.data_dir.as_path();
    let _lock = InstanceLock::acquire(data_dir).map_err(|e| e.to_string())?;
    let level = if opts.debug { Level::Debug } else { Level::Info };
    let log = Logger::open(&crate::log_dir(data_dir), level, opts.console_log)
        .map_err(|e| format!("лог {}: {e}", crate::log_dir(data_dir).display()))?;
    log.log(Level::Info, &format!("демон запущен, данные: {}", data_dir.display()));
    let hub = Arc::new(Hub::with_log(make_backend(log.callback()), log.callback()));
    let server = match &opts.ipc {
        IpcMode::None => {
            log.log(Level::Info, "IPC выключен (фронтенды не подключатся)");
            None
        }
        #[cfg(unix)]
        IpcMode::Unix => Some(IpcServer::start_unix(hub.clone(), data_dir, Some(log.callback())).map_err(|e| {
            log.log(Level::Error, &format!("IPC: {e}"));
            format!("IPC: {e}")
        })?),
        #[cfg(windows)]
        IpcMode::Pipe { name, owner_sid } => Some(
            IpcServer::start_pipe(hub.clone(), name, owner_sid.as_deref(), Some(log.callback())).map_err(|e| {
                log.log(Level::Error, &format!("IPC: пайп {name}: {e}"));
                format!("IPC: пайп {name}: {e}")
            })?,
        ),
    };
    hub.run(&stop);
    if let Some(s) = server {
        s.shutdown(&opts.stop_reason);
    }
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
