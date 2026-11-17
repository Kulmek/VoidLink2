//! tunnel-daemon: кроссплатформенное ядро демона (PLAN.md, этап 7.3).
//!
//! Хаб и IPC знают о движке только через трейт [`hub::Backend`]
//! (JSON-снимки и события); [`engine_backend::EngineBackend`] — бэкенд на
//! настоящем движке `tunnel-client`. IPC — [`server`] поверх `tunnel-ipc`;
//! [`fake::FakeBackend`] — бэкенд в памяти для тестов и `console --fake`.

pub mod cli;
pub mod engine_backend;
pub mod fake;
pub mod hub;
pub mod lock;
pub mod log;
pub mod server;
pub mod service;

pub use engine_backend::EngineBackend;
pub use fake::FakeBackend;
pub use hub::{Backend, Hub, HubMsg, Subscription};
pub use lock::{InstanceLock, LockError};
pub use log::{Level, LogFn, Logger};
pub use server::IpcServer;
pub use service::{IpcMode, ResumeSignal, RunOpts, ServiceEnv, run_daemon};

use std::path::{Path, PathBuf};

/// Каталог данных демона: `%ProgramData%\tunnel` (Windows — identity
/// принадлежит машине, см. PLAN.md 7), иначе `~/.tunnel-client` — тот же
/// каталог, что у клиента, чтобы фронтенды на Unix нашли сокет.
pub fn default_data_dir() -> PathBuf {
    if cfg!(windows) {
        if let Ok(pd) = std::env::var("ProgramData") {
            return Path::new(&pd).join("tunnel");
        }
        return PathBuf::from(r"C:\ProgramData\tunnel");
    }
    if let Ok(home) = std::env::var("HOME") {
        return Path::new(&home).join(".tunnel-client");
    }
    PathBuf::from("tunnel-client-data")
}

/// Каталог логов: `<данные>/logs`.
pub fn log_dir(data_dir: &Path) -> PathBuf {
    data_dir.join("logs")
}
