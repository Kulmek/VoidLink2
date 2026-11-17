//! tunnel-daemon: кроссплатформенное ядро демона (PLAN.md, этап 7.3).
//!
//! Движок и IPC сюда не подключены — они собираются в своих крейтах; демон
//! знает о движке только через трейт [`hub::Backend`] (JSON-снимки и события),
//! интеграция заменит JSON на типы `tunnel-engine` / `ipc`.

pub mod cli;
pub mod hub;
pub mod lock;
pub mod log;
pub mod service;

pub use hub::{Backend, Hub, HubMsg, Subscription};
pub use lock::{InstanceLock, LockError};
pub use log::{Level, LogFn, Logger};

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
