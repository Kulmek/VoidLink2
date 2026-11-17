//! Single-instance замок движка (PLAN.md 7.3): его берёт любой, кто
//! поднимает движок (демон, embedded TUI, `run`). Живёт в `tunnel-ipc`, а не в
//! демоне: клиенту он тоже нужен, а `tunnel-client` от `tunnel-daemon`
//! зависеть не может (обратная зависимость уже есть).
//!
//! - Unix — `flock` (через `File::try_lock`) на `daemon.lock` в каталоге
//!   данных. Замок привязан к открытому файлу, поэтому два замка из одного
//!   процесса (разные fd) тоже исключают друг друга; падение процесса снимает
//!   замок само. Устаревший сокет удаляется только под этим замком. Файл
//!   открывается с `O_NOFOLLOW` и только если это обычный файл без других
//!   жёстких ссылок, каталог не должен быть доступен на запись группе/всем
//!   (демон от root иначе обрезал бы подложенный по ссылке чужой файл).
//!   Проверка [`InstanceLock::is_held`] берёт *общий* замок на миг, а
//!   [`InstanceLock::acquire`] при занятости коротко повторяет попытку — так
//!   проверка из CLI не даёт ложного «занято» одновременному запуску.
//! - Windows — именованный мьютекс `Global\TunnelEngine`. Создать объект в
//!   `Global\` может любой пользователь (`SeCreateGlobalPrivilege` нужен для
//!   file mapping, а не для мьютексов), поэтому существующий мьютекс считается
//!   «занятым» только если его владелец — SYSTEM, Administrators или текущий
//!   пользователь: мьютекс постороннего (захват имени) игнорируется. Наш
//!   мьютекс создаётся с DACL, дающим всем аутентифицированным
//!   `READ_CONTROL | SYNCHRONIZE`, — его владельца может проверить и CLI без
//!   прав администратора; объект, который открыть нельзя, — чужой.
//!   Единственность самой службы гарантирует SCM, единственность сервера
//!   пайпа — `FILE_FLAG_FIRST_PIPE_INSTANCE`; мьютекс исключает лишь
//!   одновременную работу службы и embedded TUI / `run` / `console`.

use std::fmt;
use std::path::Path;

/// Имя файла замка в каталоге данных (Unix).
pub const LOCK_FILE: &str = "daemon.lock";
/// Имя мьютекса (Windows).
pub const MUTEX_NAME: &str = r"Global\TunnelEngine";

/// Сколько раз `acquire` повторяет попытку при занятом замке (Unix) и пауза
/// между попытками: проверка `is_held` держит общий замок микросекунды.
#[cfg(not(windows))]
const ACQUIRE_RETRIES: u32 = 10;
#[cfg(not(windows))]
const ACQUIRE_RETRY_PAUSE: std::time::Duration = std::time::Duration::from_millis(10);

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
    /// Хэндл нашего мьютекса; `null` — имя занято посторонним объектом
    /// (захват имени), работаем без исключения.
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
    /// (нет прав, нет каталога) и чужой захваченный мьютекс — «не занят»:
    /// проверка лишь подсказка, CLI сначала пробует IPC демона.
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

    /// Unix: занят ли `flock` на `path` (файла нет — не занят, файл не
    /// создаётся). Берётся общий замок: две проверки друг другу не мешают, а
    /// одновременный [`InstanceLock::acquire_file`] повторит попытку.
    #[cfg(not(windows))]
    pub fn is_held_file(path: &Path) -> bool {
        use std::fs::{OpenOptions, TryLockError};
        use std::os::unix::fs::OpenOptionsExt;
        let Ok(file) = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
        else {
            return false;
        };
        // Взяли — значит свободен; замок снимется вместе с `file`.
        matches!(file.try_lock_shared(), Err(TryLockError::WouldBlock))
    }

    /// Windows: держит ли мьютекс `name` доверенный владелец (движок).
    /// Объект постороннего пользователя или неоткрываемый объект — не занят.
    #[cfg(windows)]
    pub fn is_held_named(name: &str) -> bool {
        matches!(win::probe(&win::wide(name)), win::Probe::Trusted)
    }

    /// Unix: замок на произвольном файле (каталог создаётся с `0700`).
    #[cfg(not(windows))]
    pub fn acquire_file(path: &Path) -> Result<Self, LockError> {
        use std::fs::{OpenOptions, TryLockError};
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
            ensure_private_dir(dir)?;
        }
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)
            .map_err(|e| {
                std::io::Error::new(
                    e.kind(),
                    format!("{} (символическая ссылка?): {e}", path.display()),
                )
            })?;
        let md = file.metadata()?;
        if !md.file_type().is_file() || md.nlink() != 1 {
            return Err(LockError::Io(std::io::Error::other(format!(
                "{}: не обычный файл или есть другие жёсткие ссылки — удалите его",
                path.display()
            ))));
        }
        let mut tries = 0;
        loop {
            match file.try_lock() {
                Ok(()) => break,
                // Возможно, это лишь мгновенная проверка `is_held_file`.
                Err(TryLockError::WouldBlock) if tries < ACQUIRE_RETRIES => {
                    tries += 1;
                    std::thread::sleep(ACQUIRE_RETRY_PAUSE);
                }
                Err(TryLockError::WouldBlock) => return Err(LockError::Busy),
                Err(TryLockError::Error(e)) => return Err(LockError::Io(e)),
            }
        }
        // PID — только для людей (кто держит замок); ошибки записи не важны.
        let _ = file.set_len(0);
        let _ =
            std::io::Write::write_all(&mut &file, format!("{}\n", std::process::id()).as_bytes());
        Ok(Self { _file: file })
    }

    /// Windows: замок на именованном мьютексе (для тестов — своё имя).
    /// Мьютекс постороннего владельца (захват имени) не мешает: замок
    /// выдаётся без исключения.
    #[cfg(windows)]
    pub fn acquire_named(name: &str) -> Result<Self, LockError> {
        use windows_sys::Win32::Foundation::{
            CloseHandle, ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_INVALID_HANDLE,
            GetLastError,
        };
        use windows_sys::Win32::Security::SECURITY_ATTRIBUTES;
        use windows_sys::Win32::System::Threading::CreateMutexW;
        let wide = win::wide(name);
        let sd = win::SecDesc::from_sddl(win::MUTEX_SDDL)?;
        let sa = SECURITY_ATTRIBUTES {
            nLength: std::mem::size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: sd.0,
            bInheritHandle: 0,
        };
        // Объект мог исчезнуть между попытками — несколько кругов.
        for _ in 0..3 {
            // SAFETY: строка нуль-терминирована, `sa` и дескриптор живы.
            let handle = unsafe { CreateMutexW(&sa, 0, wide.as_ptr()) };
            // SAFETY: GetLastError сразу после CreateMutexW в том же потоке.
            let err = unsafe { GetLastError() };
            if !handle.is_null() {
                if err != ERROR_ALREADY_EXISTS {
                    return Ok(Self { handle });
                }
                // Мьютекс уже есть, и нам дали к нему доступ: чей он?
                let trusted = win::owner_trusted(handle);
                // SAFETY: хэндл получен выше и больше нигде не используется.
                unsafe { CloseHandle(handle) };
                return match trusted {
                    Ok(true) => Err(LockError::Busy),
                    Ok(false) => Ok(Self::squatted()),
                    Err(e) => Err(LockError::Io(e)),
                };
            }
            match err {
                // Существующий объект, доступ к которому закрыт DACL.
                ERROR_ACCESS_DENIED => match win::probe(&wide) {
                    win::Probe::Trusted => return Err(LockError::Busy),
                    win::Probe::Foreign => return Ok(Self::squatted()),
                    win::Probe::Gone => continue,
                    win::Probe::Error(e) => return Err(LockError::Io(e)),
                },
                // Имя занято объектом другого типа (событие, семафор…).
                ERROR_INVALID_HANDLE => return Ok(Self::squatted()),
                e => return Err(LockError::Io(std::io::Error::from_raw_os_error(e as i32))),
            }
        }
        Err(LockError::Io(std::io::Error::other(
            "мьютекс single-instance то появляется, то исчезает",
        )))
    }

    /// Имя мьютекса захвачено посторонним — работаем без исключения.
    #[cfg(windows)]
    fn squatted() -> Self {
        Self {
            handle: std::ptr::null_mut(),
        }
    }
}

/// Unix: каталог замка — создать с `0700`; существующий не должен быть
/// доступен на запись группе/всем (свой — права исправляются).
#[cfg(not(windows))]
fn ensure_private_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    if !dir.exists() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let md = std::fs::metadata(dir)?;
    if !md.is_dir() {
        return Err(std::io::Error::other(format!(
            "{}: не каталог",
            dir.display()
        )));
    }
    if md.mode() & 0o022 == 0 {
        return Ok(());
    }
    // SAFETY: geteuid не имеет предусловий.
    if md.uid() == unsafe { libc::geteuid() } {
        let mode = md.mode() & 0o7777 & !0o022;
        return std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode));
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::PermissionDenied,
        format!(
            "каталог данных {} доступен на запись группе/всем (права {:o}) и принадлежит \
другому пользователю — замок в нём небезопасен",
            dir.display(),
            md.mode() & 0o777
        ),
    ))
}

#[cfg(windows)]
mod win {
    use std::io;
    use std::ptr;

    use windows_sys::Win32::Foundation::{
        CloseHandle, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_INVALID_HANDLE, GetLastError,
        HANDLE, LocalFree,
    };
    use windows_sys::Win32::Security::Authorization::{
        ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
        SE_KERNEL_OBJECT,
    };
    use windows_sys::Win32::Security::{
        EqualSid, GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WinBuiltinAdministratorsSid, WinLocalSystemSid,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenMutexW, OpenProcessToken};

    /// DACL мьютекса: SYSTEM и Administrators — всё, аутентифицированным —
    /// `READ_CONTROL | SYNCHRONIZE` (проверить владельца без прав админа).
    pub const MUTEX_SDDL: &str = "D:(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x120000;;;AU)";
    const READ_CONTROL: u32 = 0x0002_0000;

    pub fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Security descriptor (или любой буфер `LocalAlloc`), освобождается `LocalFree`.
    pub struct SecDesc(pub PSECURITY_DESCRIPTOR);

    impl SecDesc {
        pub fn from_sddl(sddl: &str) -> io::Result<SecDesc> {
            let w = wide(sddl);
            let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
            // SAFETY: строка NUL-терминирована, `sd` — выходной параметр.
            let ok = unsafe {
                ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    w.as_ptr(),
                    SDDL_REVISION_1,
                    &mut sd,
                    ptr::null_mut(),
                )
            };
            if ok == 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(SecDesc(sd))
        }
    }

    impl Drop for SecDesc {
        fn drop(&mut self) {
            // SAFETY: буфер выделен системой через LocalAlloc.
            unsafe { LocalFree(self.0 as _) };
        }
    }

    /// Состояние существующего объекта с именем мьютекса.
    pub enum Probe {
        /// Мьютекс доверенного владельца — движок запущен.
        Trusted,
        /// Посторонний объект (чужой владелец, не открыть, другой тип).
        Foreign,
        /// Объекта нет.
        Gone,
        Error(io::Error),
    }

    /// Открыть объект с `READ_CONTROL` и проверить владельца.
    pub fn probe(name: &[u16]) -> Probe {
        // SAFETY: строка нуль-терминирована.
        let h = unsafe { OpenMutexW(READ_CONTROL, 0, name.as_ptr()) };
        if h.is_null() {
            // SAFETY: GetLastError сразу после OpenMutexW в том же потоке.
            return match unsafe { GetLastError() } {
                ERROR_FILE_NOT_FOUND => Probe::Gone,
                // Наш мьютекс даёт READ_CONTROL всем аутентифицированным:
                // закрытый объект — чужой; другой тип объекта — тоже.
                ERROR_ACCESS_DENIED | ERROR_INVALID_HANDLE => Probe::Foreign,
                e => Probe::Error(io::Error::from_raw_os_error(e as i32)),
            };
        }
        let r = owner_trusted(h);
        // SAFETY: хэндл получен выше и больше нигде не используется.
        unsafe { CloseHandle(h) };
        match r {
            Ok(true) => Probe::Trusted,
            Ok(false) => Probe::Foreign,
            Err(e) => Probe::Error(e),
        }
    }

    /// Владелец объекта — SYSTEM, Administrators или пользователь этого
    /// процесса (создать объект с таким владельцем посторонний не может).
    pub fn owner_trusted(h: HANDLE) -> io::Result<bool> {
        let mut owner: PSID = ptr::null_mut();
        let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
        // SAFETY: выходные указатели валидны; sd освобождается SecDesc.
        let rc = unsafe {
            GetSecurityInfo(
                h,
                SE_KERNEL_OBJECT,
                OWNER_SECURITY_INFORMATION,
                &mut owner,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
                &mut sd,
            )
        };
        if rc != 0 {
            return Err(io::Error::from_raw_os_error(rc as i32));
        }
        let _guard = SecDesc(sd);
        if owner.is_null() {
            return Ok(false);
        }
        // SAFETY: owner указывает внутрь живого sd.
        let well_known = unsafe {
            IsWellKnownSid(owner, WinLocalSystemSid) != 0
                || IsWellKnownSid(owner, WinBuiltinAdministratorsSid) != 0
        };
        Ok(well_known || is_current_user(owner)?)
    }

    /// `sid` — пользователь токена текущего процесса.
    fn is_current_user(sid: PSID) -> io::Result<bool> {
        // SAFETY: псевдохэндл процесса; токен закрывается ниже.
        unsafe {
            let mut token: HANDLE = ptr::null_mut();
            if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
                return Err(io::Error::last_os_error());
            }
            let mut len = 0u32;
            GetTokenInformation(token, TokenUser, ptr::null_mut(), 0, &mut len);
            // u64 — выравнивание под TOKEN_USER.
            let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
            let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
            let err = io::Error::last_os_error();
            CloseHandle(token);
            if ok == 0 {
                return Err(err);
            }
            let tu = &*(buf.as_ptr() as *const TOKEN_USER);
            Ok(EqualSid(tu.User.Sid, sid) != 0)
        }
    }
}

#[cfg(windows)]
impl Drop for InstanceLock {
    fn drop(&mut self) {
        if !self.handle.is_null() {
            // SAFETY: хэндл наш и закрывается один раз.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(self.handle) };
        }
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

    /// Проверка `is_held` в цикле не даёт ложного Busy одновременному acquire.
    #[cfg(not(windows))]
    #[test]
    fn probe_does_not_block_acquire() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicBool, Ordering};
        let dir = std::env::temp_dir().join(format!("tunnel-ipc-probe-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        drop(InstanceLock::acquire(&dir).expect("файл замка"));
        let stop = Arc::new(AtomicBool::new(false));
        let probes: Vec<_> = (0..2)
            .map(|_| {
                let (d, s) = (dir.clone(), stop.clone());
                std::thread::spawn(move || {
                    while !s.load(Ordering::Relaxed) {
                        let _ = InstanceLock::is_held(&d);
                    }
                })
            })
            .collect();
        for _ in 0..200 {
            let l = InstanceLock::acquire(&dir).expect("ложное «занято» из-за проверки");
            drop(l);
        }
        stop.store(true, Ordering::Relaxed);
        for p in probes {
            p.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Символическая ссылка и жёсткая ссылка вместо файла замка — отказ,
    /// цель не обрезается.
    #[cfg(not(windows))]
    #[test]
    fn lock_file_links_refused() {
        let dir = std::env::temp_dir().join(format!("tunnel-ipc-link-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let victim = dir.join("victim");
        std::fs::write(&victim, b"secret").unwrap();
        let lock = dir.join("lockdir");
        std::fs::create_dir_all(&lock).unwrap();
        std::os::unix::fs::symlink(&victim, lock.join(LOCK_FILE)).unwrap();
        assert!(matches!(
            InstanceLock::acquire(&lock),
            Err(LockError::Io(_))
        ));
        assert!(!InstanceLock::is_held(&lock));
        std::fs::remove_file(lock.join(LOCK_FILE)).unwrap();
        std::fs::hard_link(&victim, lock.join(LOCK_FILE)).unwrap();
        assert!(matches!(
            InstanceLock::acquire(&lock),
            Err(LockError::Io(_))
        ));
        assert_eq!(std::fs::read(&victim).unwrap(), b"secret");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Свой каталог с правами на запись группе — права закрываются; новый
    /// каталог создаётся `0700`.
    #[cfg(not(windows))]
    #[test]
    fn lock_dir_made_private() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("tunnel-ipc-priv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let l = InstanceLock::acquire(&dir).unwrap();
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700);
        drop(l);
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();
        drop(InstanceLock::acquire(&dir).unwrap());
        let mode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o022, 0, "{mode:o}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn lock_is_exclusive_within_process() {
        let name = format!(r"Local\TunnelEngineTest{}", std::process::id());
        assert!(!InstanceLock::is_held_named(&name));
        let a = InstanceLock::acquire_named(&name).expect("первый замок");
        assert!(matches!(
            InstanceLock::acquire_named(&name),
            Err(LockError::Busy)
        ));
        assert!(InstanceLock::is_held_named(&name));
        drop(a);
        let b = InstanceLock::acquire_named(&name).expect("замок после освобождения");
        drop(b);
    }

    /// Имя занято объектом другого типа (захват) — замок выдаётся, но
    /// «занятым» имя не считается.
    #[cfg(windows)]
    #[test]
    fn foreign_object_ignored() {
        use windows_sys::Win32::Foundation::CloseHandle;
        use windows_sys::Win32::System::Threading::CreateEventW;
        let name = format!(r"Local\TunnelEngineSquat{}", std::process::id());
        let w = win::wide(&name);
        // SAFETY: строка нуль-терминирована.
        let ev = unsafe { CreateEventW(std::ptr::null(), 1, 0, w.as_ptr()) };
        assert!(!ev.is_null());
        assert!(!InstanceLock::is_held_named(&name));
        let l = InstanceLock::acquire_named(&name).expect("захват имени не мешает");
        drop(l);
        // SAFETY: хэндл получен выше.
        unsafe { CloseHandle(ev) };
    }
}
