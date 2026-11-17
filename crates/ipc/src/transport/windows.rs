//! Windows: named pipe через `windows-sys`, overlapped-ввод-вывод.
//!
//! Безопасность (PLAN.md 7.2):
//! - `PIPE_REJECT_REMOTE_CLIENTS` — только локальные клиенты;
//! - `FILE_FLAG_FIRST_PIPE_INSTANCE` на первом экземпляре — если пайп с таким
//!   именем уже кто-то поднял, `bind` падает, а не подключается к чужому;
//! - явный SDDL `O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;<SID владельца>)`:
//!   владелец объекта — SYSTEM (поставить так может только SYSTEM), DACL без
//!   наследования; SID владельца-пользователя пишется при установке. Маска
//!   пользователя — `FILE_GENERIC_READ | FILE_GENERIC_WRITE` без бита `0x4`
//!   (`FILE_APPEND_DATA` = `FILE_CREATE_PIPE_INSTANCE` для пайпа): с `GW` любой
//!   процесс пользователя мог бы поднять свой экземпляр серверной стороны;
//! - следующий экземпляр создаётся до ожидания клиента, так что пока жив
//!   [`Listener`], хотя бы один наш экземпляр существует и имя не освобождается;
//! - клиент проверяет, что сервер пайпа работает от SYSTEM
//!   (`GetNamedPipeServerProcessId` → токен процесса → `S-1-5-18`); если токен
//!   службы непривилегированному пользователю не открыть — по владельцу
//!   объекта пайпа (тоже должен быть SYSTEM, см. `O:SY`).
//!
//! Хэндлы открыты с `FILE_FLAG_OVERLAPPED`: синхронный ввод-вывод на одном
//! файловом объекте Windows сериализует, и блокирующее чтение в одном потоке
//! не давало бы писать из другого. Каждый клон [`Conn`] — свой event и свой
//! `OVERLAPPED` на каждую операцию. [`Conn::shutdown`] ставит общий флаг
//! `closed` и отменяет операции: чтение после этого даёт EOF (кодек вернёт
//! `Closed`, как на unix), запись — `BrokenPipe`.

use std::ffi::OsStr;
use std::io::{self, Read, Write};
use std::mem::{size_of, zeroed};
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_BROKEN_PIPE, ERROR_INSUFFICIENT_BUFFER, ERROR_IO_PENDING,
    ERROR_OPERATION_ABORTED, ERROR_PIPE_BUSY, ERROR_PIPE_CONNECTED, ERROR_PIPE_NOT_CONNECTED,
    GetLastError, HANDLE, INVALID_HANDLE_VALUE, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertStringSecurityDescriptorToSecurityDescriptorW, GetSecurityInfo, SDDL_REVISION_1,
    SE_KERNEL_OBJECT,
};
use windows_sys::Win32::Security::{
    GetTokenInformation, IsWellKnownSid, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
    SECURITY_ATTRIBUTES, TOKEN_QUERY, TOKEN_USER, TokenUser, WinLocalSystemSid,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_FIRST_PIPE_INSTANCE, FILE_FLAG_OVERLAPPED, FILE_SHARE_NONE,
    OPEN_EXISTING, PIPE_ACCESS_DUPLEX, ReadFile, SECURITY_IDENTIFICATION, SECURITY_SQOS_PRESENT,
    WriteFile,
};
use windows_sys::Win32::System::IO::{CancelIoEx, GetOverlappedResult, OVERLAPPED};
use windows_sys::Win32::System::Pipes::{
    ConnectNamedPipe, CreateNamedPipeW, GetNamedPipeServerProcessId, PIPE_READMODE_BYTE,
    PIPE_REJECT_REMOTE_CLIENTS, PIPE_TYPE_BYTE, PIPE_UNLIMITED_INSTANCES, PIPE_WAIT,
    WaitNamedPipeW,
};
use windows_sys::Win32::System::Threading::{
    CreateEventW, OpenProcess, OpenProcessToken, PROCESS_QUERY_LIMITED_INFORMATION,
};

/// Размер буферов пайпа в каждую сторону.
const PIPE_BUF: u32 = 64 * 1024;
/// Сколько раз ждать свободный экземпляр пайпа при `ERROR_PIPE_BUSY`.
const BUSY_RETRIES: u32 = 5;
const BUSY_WAIT_MS: u32 = 2000;
/// Права пользователя на пайп: `FILE_GENERIC_READ | FILE_GENERIC_WRITE`
/// (`0x120089 | 0x120116`) без `FILE_CREATE_PIPE_INSTANCE` (`0x4`).
/// Этой же маской клиент открывает пайп: `GENERIC_WRITE` включал бы `0x4`
/// и упёрся бы в DACL.
const PIPE_CLIENT_ACCESS: u32 = 0x0012_019b;

fn wide(s: &OsStr) -> Vec<u16> {
    s.encode_wide().chain(Some(0)).collect()
}

fn last_err() -> io::Error {
    io::Error::last_os_error()
}

/// Владеет хэндлом сразу после успешного Win32-вызова.
fn owned(h: HANDLE) -> io::Result<OwnedHandle> {
    if h.is_null() || h == INVALID_HANDLE_VALUE {
        Err(last_err())
    } else {
        // SAFETY: хэндл валиден и больше никем не владеется.
        Ok(unsafe { OwnedHandle::from_raw_handle(h) })
    }
}

fn new_event() -> io::Result<OwnedHandle> {
    // Event с ручным сбросом: так требует overlapped-ввод-вывод.
    owned(unsafe { CreateEventW(ptr::null(), 1, 0, ptr::null()) })
}

/// Выполняет overlapped-операцию и ждёт её завершения.
/// `start` получает `OVERLAPPED` и возвращает BOOL Win32-вызова.
/// Если задан `closed` и он выставлен, пока операция висит, — отменяем её
/// сами: [`Conn::shutdown`] мог вызвать `CancelIoEx` до её старта.
fn overlapped(
    h: HANDLE,
    ev: HANDLE,
    closed: Option<&AtomicBool>,
    start: impl FnOnce(*mut OVERLAPPED) -> i32,
) -> io::Result<u32> {
    // SAFETY: OVERLAPPED — POD, нули — валидное начальное состояние.
    let mut ov: OVERLAPPED = unsafe { zeroed() };
    ov.hEvent = ev;
    if start(&mut ov) == 0 {
        let err = unsafe { GetLastError() };
        if err != ERROR_IO_PENDING {
            return Err(io::Error::from_raw_os_error(err as i32));
        }
        // Флаг ставится до CancelIoEx (SeqCst): либо видим его здесь, либо
        // shutdown отменит уже запущенную операцию.
        if closed.is_some_and(|c| c.load(Ordering::SeqCst)) {
            unsafe { CancelIoEx(h, &ov) };
        }
    }
    let mut n = 0u32;
    // SAFETY: `ov` живёт до завершения операции — ждём с bWait = TRUE.
    if unsafe { GetOverlappedResult(h, &ov, &mut n, 1) } == 0 {
        return Err(last_err());
    }
    Ok(n)
}

/// Security descriptor из SDDL, освобождается `LocalFree`.
struct SecDesc(PSECURITY_DESCRIPTOR);

// SAFETY: дескриптор только читается после создания.
unsafe impl Send for SecDesc {}
unsafe impl Sync for SecDesc {}

impl SecDesc {
    fn from_sddl(sddl: &str) -> io::Result<SecDesc> {
        let w = wide(OsStr::new(sddl));
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
            return Err(last_err());
        }
        Ok(SecDesc(sd))
    }
}

impl Drop for SecDesc {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0 as _) };
    }
}

/// SID в строковой форме `S-1-…` без посторонних символов (защита от
/// инъекции в SDDL).
fn valid_sid(s: &str) -> bool {
    s.len() > 4
        && s.starts_with("S-1-")
        && s[1..].bytes().all(|b| b.is_ascii_digit() || b == b'-')
        && !s.contains("--")
        && !s.ends_with('-')
}

/// SDDL пайпа: SYSTEM и Administrators — полный доступ, владелец-пользователь —
/// чтение/запись без права создавать экземпляры пайпа. Остальным — ничего.
pub fn pipe_sddl(owner_sid: Option<&str>) -> io::Result<String> {
    let mut s = String::from("O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)");
    if let Some(sid) = owner_sid {
        if !valid_sid(sid) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("неверный SID владельца: {sid}"),
            ));
        }
        s.push_str(&format!("(A;;{PIPE_CLIENT_ACCESS:#x};;;{sid})"));
    }
    Ok(s)
}

/// Сервер пайпа (только служба, от SYSTEM).
pub struct Listener {
    name: Vec<u16>,
    sd: SecDesc,
    /// Экземпляр, ждущий следующего клиента.
    next: Mutex<Option<OwnedHandle>>,
}

impl Listener {
    /// Поднимает пайп без доступа для пользователя (только SY и BA).
    pub fn bind(name: impl AsRef<OsStr>) -> io::Result<Listener> {
        Self::bind_with_owner(name, None)
    }

    /// Поднимает пайп; `owner_sid` — SID пользователя, записанный при установке.
    /// Падает, если пайп с таким именем уже существует (`FIRST_PIPE_INSTANCE`).
    pub fn bind_with_owner(
        name: impl AsRef<OsStr>,
        owner_sid: Option<&str>,
    ) -> io::Result<Listener> {
        let sd = SecDesc::from_sddl(&pipe_sddl(owner_sid)?)?;
        let l = Listener {
            name: wide(name.as_ref()),
            sd,
            next: Mutex::new(None),
        };
        let first = l.create_instance(true)?;
        *l.next.lock().unwrap_or_else(|e| e.into_inner()) = Some(first);
        Ok(l)
    }

    fn create_instance(&self, first: bool) -> io::Result<OwnedHandle> {
        let sa = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: self.sd.0,
            bInheritHandle: 0,
        };
        let mut open = PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED;
        if first {
            open |= FILE_FLAG_FIRST_PIPE_INSTANCE;
        }
        // SAFETY: имя NUL-терминировано, `sa` живёт на время вызова.
        let h = unsafe {
            CreateNamedPipeW(
                self.name.as_ptr(),
                open,
                PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
                PIPE_UNLIMITED_INSTANCES,
                PIPE_BUF,
                PIPE_BUF,
                0,
                &sa,
            )
        };
        owned(h)
    }

    /// Ждёт следующего клиента. Экземпляр для следующего `accept` создаётся
    /// до ожидания: пока ждём на текущем, второй уже есть, и имя пайпа не
    /// освобождается ни на миг. Если создать его не вышло — текущий
    /// возвращается в `next`, а ошибка — вызывающему.
    pub fn accept(&self) -> io::Result<Conn> {
        let pipe = {
            let mut next = self.next.lock().unwrap_or_else(|e| e.into_inner());
            let cur = match next.take() {
                Some(p) => p,
                // Инвариант `next.is_some()` держится всегда; если всё же
                // пусто — только FIRST_PIPE_INSTANCE: не присоединяемся к чужому.
                None => self.create_instance(true)?,
            };
            match self.create_instance(false) {
                Ok(n) => *next = Some(n),
                Err(e) => {
                    *next = Some(cur);
                    return Err(e);
                }
            }
            cur
        };
        let ev = new_event()?;
        let h = pipe.as_raw_handle();
        let res = overlapped(h, ev.as_raw_handle(), None, |ov| unsafe {
            ConnectNamedPipe(h, ov)
        });
        match res {
            Ok(_) => {}
            // Клиент подключился между CreateNamedPipe и ConnectNamedPipe.
            Err(e) if e.raw_os_error() == Some(ERROR_PIPE_CONNECTED as i32) => {}
            Err(e) => return Err(e),
        }
        Ok(Conn {
            handle: Arc::new(pipe),
            closed: Arc::new(AtomicBool::new(false)),
            event: ev,
        })
    }
}

/// Подключается к пайпу демона и проверяет, что его сервер — процесс от SYSTEM.
/// Исключений для разработки нет (PLAN.md 7.2).
pub fn connect(name: impl AsRef<OsStr>) -> io::Result<Conn> {
    let w = wide(name.as_ref());
    let mut tries = 0;
    let h = loop {
        // SECURITY_IDENTIFICATION: сервер может узнать, кто мы, но не действовать от нашего имени.
        let h = unsafe {
            CreateFileW(
                w.as_ptr(),
                PIPE_CLIENT_ACCESS,
                FILE_SHARE_NONE,
                ptr::null(),
                OPEN_EXISTING,
                FILE_FLAG_OVERLAPPED | SECURITY_SQOS_PRESENT | SECURITY_IDENTIFICATION,
                ptr::null_mut(),
            )
        };
        if h != INVALID_HANDLE_VALUE {
            break owned(h)?;
        }
        let err = unsafe { GetLastError() };
        if err == ERROR_PIPE_BUSY && tries < BUSY_RETRIES {
            tries += 1;
            unsafe { WaitNamedPipeW(w.as_ptr(), BUSY_WAIT_MS) };
            continue;
        }
        return Err(io::Error::from_raw_os_error(err as i32));
    };
    if !server_is_system(h.as_raw_handle())? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "сервер пайпа работает не от SYSTEM — возможна подмена демона",
        ));
    }
    Ok(Conn {
        handle: Arc::new(h),
        closed: Arc::new(AtomicBool::new(false)),
        event: new_event()?,
    })
}

/// Работает ли процесс-сервер пайпа от LocalSystem.
fn server_is_system(pipe: HANDLE) -> io::Result<bool> {
    let mut pid = 0u32;
    if unsafe { GetNamedPipeServerProcessId(pipe, &mut pid) } == 0 {
        return Err(last_err());
    }
    match process_is_system(pid) {
        Ok(v) => Ok(v),
        // Токен службы непривилегированному пользователю обычно не открыть.
        Err(e) if e.raw_os_error() == Some(ERROR_ACCESS_DENIED as i32) => {
            pipe_owner_is_system(pipe)
        }
        Err(e) => Err(e),
    }
}

fn process_is_system(pid: u32) -> io::Result<bool> {
    let proc = owned(unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) })?;
    let mut tok: HANDLE = ptr::null_mut();
    if unsafe { OpenProcessToken(proc.as_raw_handle(), TOKEN_QUERY, &mut tok) } == 0 {
        return Err(last_err());
    }
    let tok = owned(tok)?;
    let mut len = 0u32;
    unsafe { GetTokenInformation(tok.as_raw_handle(), TokenUser, ptr::null_mut(), 0, &mut len) };
    let err = unsafe { GetLastError() };
    if len == 0 || err != ERROR_INSUFFICIENT_BUFFER {
        return Err(io::Error::from_raw_os_error(err as i32));
    }
    // u64 — выравнивание под TOKEN_USER.
    let mut buf = vec![0u64; (len as usize).div_ceil(8)];
    if unsafe {
        GetTokenInformation(
            tok.as_raw_handle(),
            TokenUser,
            buf.as_mut_ptr().cast(),
            len,
            &mut len,
        )
    } == 0
    {
        return Err(last_err());
    }
    // SAFETY: буфер заполнен структурой TOKEN_USER и выровнен.
    let tu = unsafe { &*(buf.as_ptr() as *const TOKEN_USER) };
    Ok(unsafe { IsWellKnownSid(tu.User.Sid, WinLocalSystemSid) } != 0)
}

fn pipe_owner_is_system(pipe: HANDLE) -> io::Result<bool> {
    let mut owner: PSID = ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = ptr::null_mut();
    let rc = unsafe {
        GetSecurityInfo(
            pipe,
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
    Ok(!owner.is_null() && unsafe { IsWellKnownSid(owner, WinLocalSystemSid) } != 0)
}

/// Соединение по пайпу. `try_clone()` даёт вторую половину для другого потока
/// (общий хэндл, свой event).
pub struct Conn {
    handle: Arc<OwnedHandle>,
    /// Общий для всех клонов флаг `shutdown`.
    closed: Arc<AtomicBool>,
    event: OwnedHandle,
}

impl Conn {
    pub fn try_clone(&self) -> io::Result<Conn> {
        Ok(Conn {
            handle: self.handle.clone(),
            closed: self.closed.clone(),
            event: new_event()?,
        })
    }

    /// Закрывает соединение для всех клонов: текущие операции отменяются,
    /// новые не начинаются (чтение — EOF, запись — `BrokenPipe`).
    pub fn shutdown(&self) -> io::Result<()> {
        self.closed.store(true, Ordering::SeqCst);
        // ERROR_NOT_FOUND — висящих операций нет, это не ошибка: следующие
        // увидят флаг.
        unsafe { CancelIoEx(self.handle.as_raw_handle(), ptr::null()) };
        Ok(())
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }
}

fn closed_err() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "соединение закрыто (shutdown)")
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.is_closed() {
            return Ok(0);
        }
        let h = self.handle.as_raw_handle();
        let len = buf.len().min(u32::MAX as usize) as u32;
        let ptr = buf.as_mut_ptr();
        match overlapped(
            h,
            self.event.as_raw_handle(),
            Some(&self.closed),
            |ov| unsafe { ReadFile(h, ptr, len, ptr::null_mut(), ov) },
        ) {
            Ok(n) => Ok(n as usize),
            // Отменено нашим shutdown — EOF, как на unix.
            Err(e)
                if e.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) && self.is_closed() =>
            {
                Ok(0)
            }
            // Пир закрыл пайп — это EOF.
            Err(e)
                if e.raw_os_error() == Some(ERROR_BROKEN_PIPE as i32)
                    || e.raw_os_error() == Some(ERROR_PIPE_NOT_CONNECTED as i32) =>
            {
                Ok(0)
            }
            Err(e) => Err(e),
        }
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        if self.is_closed() {
            return Err(closed_err());
        }
        let h = self.handle.as_raw_handle();
        let len = buf.len().min(u32::MAX as usize) as u32;
        let ptr = buf.as_ptr();
        match overlapped(
            h,
            self.event.as_raw_handle(),
            Some(&self.closed),
            |ov| unsafe { WriteFile(h, ptr, len, ptr::null_mut(), ov) },
        ) {
            Ok(n) => Ok(n as usize),
            Err(e)
                if e.raw_os_error() == Some(ERROR_OPERATION_ABORTED as i32) && self.is_closed() =>
            {
                Err(closed_err())
            }
            Err(e) => Err(e),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sddl_shape() {
        assert_eq!(
            pipe_sddl(Some("S-1-5-21-1-2-3-1001")).unwrap(),
            "O:SYD:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;0x12019b;;;S-1-5-21-1-2-3-1001)"
        );
        assert!(pipe_sddl(Some("S-1-5)(A;;GA;;;WD")).is_err());
        assert!(pipe_sddl(Some("WD")).is_err());
        // Без FILE_CREATE_PIPE_INSTANCE (0x4) и с полными чтением/записью.
        assert_eq!(PIPE_CLIENT_ACCESS & 0x4, 0);
        assert_eq!(PIPE_CLIENT_ACCESS | 0x4, 0x0012_0089 | 0x0012_0116);
    }
}
