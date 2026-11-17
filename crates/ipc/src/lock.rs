//! Single-instance замок движка (PLAN.md 7.3): его берёт любой, кто
//! поднимает движок (демон, embedded TUI, `run`). Живёт в `tunnel-ipc`, а не в
//! демоне: клиенту он тоже нужен, а `tunnel-client` от `tunnel-daemon`
//! зависеть не может (обратная зависимость уже есть).
//!
//! - Unix — `flock` (через `File::try_lock`) на `daemon.lock` в каталоге
//!   данных. Замок привязан к открытому файлу, поэтому два замка из одного
//!   процесса (разные fd) тоже исключают друг друга; падение процесса снимает
//!   замок само. Устаревший сокет удаляется только под этим замком.
//! - Windows — именованный мьютекс `Global\TunnelEngine`: занятость —
//!   `ERROR_ALREADY_EXISTS` при создании (владение потоком не нужно, важен
//!   сам объект, живущий, пока открыт хоть один хэндл). `ERROR_ACCESS_DENIED`
//!   при существующем объекте (его держит служба) — тоже занятость.

use std::fmt;
use std::path::Path;

/// Имя файла замка в каталоге данных (Unix).
pub const LOCK_FILE: &str = "daemon.lock";
/// Имя мьютекса (Windows).
pub const MUTEX_NAME: &str = r"Global\TunnelEngine";

#[derive(Debug)]
pub enum LockError {
    /// Движок уже запущен (демон, embedded TUI или `run`).
    Busy,
    Io(std::io::Error),
}

impl fmt::Display for LockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockError::Busy => write!(f, "движок уже запущен (демон, TUI или run)"),
            LockError::Io(e) => write!(f, "замок single-instance: {e}"),
        }
    }
}

impl std::error::Error for LockError {}

impl From<std::io::Error> for LockError {
    fn from(e: std::io::Error) -> Self {
        LockError::Io(e)
    }
}

/// Взятый замок; освобождается при drop.
pub struct InstanceLock {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(windows)]
    handle: windows_sys::Win32::Foundation::HANDLE,
}

// HANDLE мьютекса можно закрыть из любого потока.
#[cfg(windows)]
unsafe impl Send for InstanceLock {}
#[cfg(windows)]
unsafe impl Sync for InstanceLock {}

impl InstanceLock {
    /// Взять замок движка. На Windows `data_dir` не используется.
    pub fn acquire(data_dir: &Path) -> Result<Self, LockError> {
        #[cfg(windows)]
        {
            let _ = data_dir;
            Self::acquire_named(MUTEX_NAME)
        }
        #[cfg(not(windows))]
        {
            Self::acquire_file(&data_dir.join(LOCK_FILE))
        }
    }

    /// Занят ли замок кем-то другим — без попытки его держать (CLI: «движок
    /// уже запущен без IPC — свой HELLO вытеснил бы его сессию»). Ошибки
    /// (нет прав, нет каталога) — «не занят»: проверка лишь подсказка.
    pub fn is_held(data_dir: &Path) -> bool {
        #[cfg(windows)]
        {
            let _ = data_dir;
            Self::is_held_named(MUTEX_NAME)
        }
        #[cfg(not(windows))]
        {
            Self::is_held_file(&data_dir.join(LOCK_FILE))
        }
    }

    /// Unix: занят ли `flock` на `path` (файла нет — не занят, файл не создаётся).
    #[cfg(not(windows))]
    pub fn is_held_file(path: &Path) -> bool {
        use std::fs::{OpenOptions, TryLockError};
        let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
            return false;
        };
        // Взяли — значит свободен; замок снимется вместе с `file`.
        matches!(file.try_lock(), Err(TryLockError::WouldBlock))
    }

    /// Windows: существует ли мьютекс `name` (его держит движок).
    #[cfg(windows)]
    pub fn is_held_named(name: &str) -> bool {
        use windows_sys::Win32::Foundation::{CloseHandle, ERROR_ACCESS_DENIED, GetLastError};
        use windows_sys::Win32::System::Threading::{OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: строка нуль-терминирована.
        let h = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide.as_ptr()) };
        if !h.is_null() {
            // SAFETY: хэндл получен выше и больше нигде не используется.
            unsafe { CloseHandle(h) };
            return true;
        }
        // Объект есть, но открыть не дали (служба, DACL по умолчанию) — тоже занят.
        // SAFETY: GetLastError сразу после OpenMutexW в том же потоке.
        unsafe { GetLastError() == ERROR_ACCESS_DENIED }
    }

    /// Unix: замок на произвольном файле (создаётся с каталогами).
    #[cfg(not(windows))]
    pub fn acquire_file(path: &Path) -> Result<Self, LockError> {
        use std::fs::{OpenOptions, TryLockError};
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        let file = OpenOptions::new().read(true).write(true).create(true).truncate(false).open(path)?;
        match file.try_lock() {
            Ok(()) => {}
            Err(TryLockError::WouldBlock) => return Err(LockError::Busy),
            Err(TryLockError::Error(e)) => return Err(LockError::Io(e)),
        }
        // PID — только для людей (кто держит замок); ошибки записи не важны.
        let _ = file.set_len(0);
        let _ = std::io::Write::write_all(&mut &file, format!("{}\n", std::process::id()).as_bytes());
        Ok(Self { _file: file })
    }

    /// Windows: замок на именованном мьютексе (для тестов — своё имя).
    #[cfg(windows)]
    pub fn acquire_named(name: &str) -> Result<Self, LockError> {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_FILE_NOT_FOUND, GetLastError,
        };
        use windows_sys::Win32::System::Threading::{CreateMutexW, OpenMutexW, SYNCHRONIZATION_SYNCHRONIZE};
        let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
        // SAFETY: строка нуль-терминирована, атрибуты безопасности по умолчанию.
        let handle = unsafe { CreateMutexW(std::ptr::null(), 0, wide.as_ptr()) };
        if handle.is_null() {
            // SAFETY: GetLastError сразу после CreateMutexW в том же потоке.
            let err = unsafe { GetLastError() };
            if err != ERROR_ACCESS_DENIED {
                return Err(LockError::Io(std::io::Error::from_raw_os_error(err as i32)));
            }
            // ACCESS_DENIED: мьютекс держит служба (LocalSystem, DACL по
            // умолчанию) — или у нас нет SeCreateGlobalPrivilege. Различаем
            // попыткой открыть существующий объект.
            // SAFETY: строка нуль-терминирована.
            let h = unsafe { OpenMutexW(SYNCHRONIZATION_SYNCHRONIZE, 0, wide.as_ptr()) };
            if !h.is_null() {
                // SAFETY: хэндл получен выше и больше нигде не используется.
                unsafe { CloseHandle(h) };
                return Err(LockError::Busy);
            }
            // SAFETY: GetLastError сразу после OpenMutexW в том же потоке.
            return Err(match unsafe { GetLastError() } {
                ERROR_ACCESS_DENIED => LockError::Busy,
                ERROR_FILE_NOT_FOUND => LockError::Io(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "нужны права администратора (создание Global\\-мьютекса)",
                )),
                e => LockError::Io(std::io::Error::from_raw_os_error(e as i32)),
            });
        }
        // SAFETY: GetLastError сразу после CreateMutexW в том же потоке.
        if unsafe { GetLastError() } == ERROR_ALREADY_EXISTS {
            // SAFETY: хэндл получен выше и больше нигде не используется.
            unsafe { CloseHandle(handle) };
            return Err(LockError::Busy);
        }
        Ok(Self { handle })
    }
}

#[cfg(windows)]
impl Drop for InstanceLock {
    fn drop(&mut self) {
        // SAFETY: хэндл наш и закрывается один раз.
        unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(windows))]
    #[test]
    fn lock_is_exclusive_within_process() {
        let dir = std::env::temp_dir().join(format!("tunnel-ipc-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        assert!(!InstanceLock::is_held(&dir), "файла замка ещё нет");
        let a = InstanceLock::acquire(&dir).expect("первый замок");
        assert!(matches!(InstanceLock::acquire(&dir), Err(LockError::Busy)));
        assert!(InstanceLock::is_held(&dir));
        drop(a);
        assert!(!InstanceLock::is_held(&dir), "проверка замок не держит");
        let b = InstanceLock::acquire(&dir).expect("замок после освобождения");
        drop(b);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn lock_is_exclusive_within_process() {
        let name = format!(r"Local\TunnelEngineTest{}", std::process::id());
        assert!(!InstanceLock::is_held_named(&name));
        let a = InstanceLock::acquire_named(&name).expect("первый замок");
        assert!(matches!(InstanceLock::acquire_named(&name), Err(LockError::Busy)));
        assert!(InstanceLock::is_held_named(&name));
        drop(a);
        let b = InstanceLock::acquire_named(&name).expect("замок после освобождения");
        drop(b);
    }
}
