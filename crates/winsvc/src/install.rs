//! Установка и удаление службы (запуск от администратора).

use std::ffi::{OsStr, OsString};
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use windows_service::service::{
    ServiceAccess, ServiceAction, ServiceActionType, ServiceErrorControl, ServiceFailureActions,
    ServiceFailureResetPeriod, ServiceInfo, ServiceStartType, ServiceState, ServiceType,
};
use windows_service::service_manager::{ServiceManager, ServiceManagerAccess};
use windows_sys::Win32::Foundation::{
    CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree,
};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
    SDDL_REVISION_1, SE_FILE_OBJECT, SetNamedSecurityInfoW,
};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetSecurityDescriptorDacl, GetTokenInformation,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, TOKEN_QUERY, TOKEN_USER, TokenUser,
};
use windows_sys::Win32::System::Registry::{
    HKEY_CURRENT_USER, REG_SZ, RegDeleteKeyValueW, RegSetKeyValueW,
};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

use crate::common::*;

const ERROR_SERVICE_DOES_NOT_EXIST: i32 = 1060;
const ERROR_SERVICE_EXISTS: i32 = 1073;

fn wide(s: impl AsRef<OsStr>) -> Vec<u16> {
    s.as_ref().encode_wide().chain(Some(0)).collect()
}

fn win_err(code: i32) -> impl Fn(&windows_service::Error) -> bool {
    move |e| matches!(e, windows_service::Error::Winapi(io) if io.raw_os_error() == Some(code))
}

/// Устанавливает (или обновляет) службу и всё окружение. Порядок: каталог
/// данных и ACL → импорт конфига → SID владельца → служба → Run → ярлык →
/// старт. Ошибка ярлыка/Run-ключа не валит установку службы — она в отчёте
/// не нужна, но и туннель без неё работает; ошибку возвращаем в конце.
pub fn install(opts: &InstallOptions) -> Result<InstallReport> {
    if !opts.daemon_exe.is_absolute() {
        bail!("путь службы должен быть абсолютным: {}", opts.daemon_exe.display());
    }
    let dir = data_dir();
    std::fs::create_dir_all(&dir).with_context(|| format!("создание {}", dir.display()))?;
    set_dir_acl(&dir, DATA_DIR_SDDL).with_context(|| format!("ACL на {}", dir.display()))?;

    let config_imported = import_user_config(&dir)?;
    let owner_sid = current_user_sid()?;
    write_secure(&owner_sid_path(&dir), format!("{owner_sid}\n").as_bytes())?;

    let service_updated = install_service(opts)?;

    let mut soft_errors = Vec::new();
    if let Some(tray) = &opts.tray_exe
        && let Err(e) = set_run_value(&run_value(tray))
    {
        soft_errors.push(format!("Run-ключ трея: {e:#}"));
    }
    if let Some(sc) = &opts.shortcut
        && let Err(e) = create_shortcut(sc)
    {
        soft_errors.push(format!("ярлык {}: {e:#}", sc.lnk.display()));
    }
    if opts.start {
        start_service(&opts.service_name)?;
    }
    if !soft_errors.is_empty() {
        bail!("служба установлена, но: {}", soft_errors.join("; "));
    }
    Ok(InstallReport { data_dir: dir, config_imported, owner_sid, service_updated })
}

/// Удаляет службу: стоп → `remove_adapter` (Wintun-адаптер) → удаление из
/// SCM → Run-ключ → ярлык → (с `purge`) `%ProgramData%\tunnel`. Шаги не
/// прерываются ошибкой предыдущих; все ошибки — одной в конце.
pub fn uninstall<F>(opts: &UninstallOptions, remove_adapter: F) -> Result<()>
where
    F: FnOnce() -> Result<()>,
{
    let mut errors = Vec::new();
    match stop_and_delete(&opts.service_name, remove_adapter) {
        Ok(errs) => errors.extend(errs),
        Err(e) => errors.push(format!("служба: {e:#}")),
    }
    if opts.remove_run_key
        && let Err(e) = delete_run_value()
    {
        errors.push(format!("Run-ключ: {e:#}"));
    }
    if let Some(lnk) = &opts.shortcut_lnk {
        match std::fs::remove_file(lnk) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("ярлык {}: {e}", lnk.display())),
        }
    }
    if opts.purge {
        let dir = data_dir();
        match std::fs::remove_dir_all(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => errors.push(format!("{}: {e}", dir.display())),
        }
    }
    if errors.is_empty() { Ok(()) } else { Err(anyhow!(errors.join("; "))) }
}

fn install_service(opts: &InstallOptions) -> Result<bool> {
    let mgr = ServiceManager::local_computer(
        None::<&str>,
        ServiceManagerAccess::CONNECT | ServiceManagerAccess::CREATE_SERVICE,
    )
    .context("OpenSCManager (нужны права администратора)")?;
    let info = ServiceInfo {
        name: OsString::from(&opts.service_name),
        display_name: OsString::from(&opts.display_name),
        service_type: ServiceType::OWN_PROCESS,
        start_type: ServiceStartType::AutoStart,
        error_control: ServiceErrorControl::Normal,
        executable_path: opts.daemon_exe.clone(),
        launch_arguments: opts.service_args.iter().map(OsString::from).collect(),
        dependencies: vec![],
        account_name: None, // LocalSystem
        account_password: None,
    };
    let access = ServiceAccess::CHANGE_CONFIG | ServiceAccess::QUERY_STATUS | ServiceAccess::START;
    let (svc, updated) = match mgr.create_service(&info, access) {
        Ok(s) => (s, false),
        Err(e) if win_err(ERROR_SERVICE_EXISTS)(&e) => {
            let s = mgr.open_service(&opts.service_name, access).context("OpenService")?;
            s.change_config(&info).context("ChangeServiceConfig")?;
            (s, true)
        }
        Err(e) => return Err(e).context("CreateService"),
    };
    svc.set_description(&opts.description).context("описание службы")?;
    let actions = RECOVERY_DELAYS
        .iter()
        .map(|&delay| ServiceAction { action_type: ServiceActionType::Restart, delay })
        .collect();
    svc.update_failure_actions(ServiceFailureActions {
        reset_period: ServiceFailureResetPeriod::After(RECOVERY_RESET),
        reboot_msg: None,
        command: None,
        actions: Some(actions),
    })
    .context("политика восстановления")?;
    // рестарт и при выходе с ненулевым кодом, а не только при падении процесса
    svc.set_failure_actions_on_non_crash_failures(true)
        .context("восстановление при ошибке выхода")?;
    Ok(updated)
}

fn start_service(name: &str) -> Result<()> {
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("OpenSCManager")?;
    let svc = mgr
        .open_service(name, ServiceAccess::START | ServiceAccess::QUERY_STATUS)
        .context("OpenService")?;
    if svc.query_status()?.current_state == ServiceState::Stopped {
        svc.start::<&OsStr>(&[]).context("StartService")?;
    }
    Ok(())
}

/// Стоп и удаление службы; ошибки адаптера — во втором векторе.
fn stop_and_delete<F>(name: &str, remove_adapter: F) -> Result<Vec<String>>
where
    F: FnOnce() -> Result<()>,
{
    let mut errs = Vec::new();
    let mgr = ServiceManager::local_computer(None::<&str>, ServiceManagerAccess::CONNECT)
        .context("OpenSCManager (нужны права администратора)")?;
    let svc = match mgr.open_service(
        name,
        ServiceAccess::STOP | ServiceAccess::DELETE | ServiceAccess::QUERY_STATUS,
    ) {
        Ok(s) => Some(s),
        Err(e) if win_err(ERROR_SERVICE_DOES_NOT_EXIST)(&e) => None,
        Err(e) => return Err(e).context("OpenService"),
    };
    if let Some(svc) = &svc
        && svc.query_status()?.current_state != ServiceState::Stopped
    {
        let _ = svc.stop();
        let deadline = Instant::now() + Duration::from_secs(20);
        while svc.query_status()?.current_state != ServiceState::Stopped {
            if Instant::now() > deadline {
                errs.push("служба не остановилась за 20 с".to_string());
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    }
    // адаптер — после остановки службы (она держит его открытым)
    if let Err(e) = remove_adapter() {
        errs.push(format!("адаптер: {e:#}"));
    }
    if let Some(svc) = svc {
        svc.delete().context("DeleteService")?;
    }
    Ok(errs)
}

/// Импорт `%APPDATA%\tunnel\client.json` установившего пользователя, если
/// у службы конфига ещё нет. Возвращает, был ли импорт.
fn import_user_config(dir: &Path) -> Result<bool> {
    let dst = service_config_path(dir);
    if dst.exists() {
        return Ok(false);
    }
    let Some(appdata) = std::env::var_os("APPDATA") else {
        return Ok(false);
    };
    let src = user_config_path(Path::new(&appdata));
    let data = match std::fs::read(&src) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e).with_context(|| format!("чтение {}", src.display())),
    };
    write_secure(&dst, &data)?;
    Ok(true)
}

/// Запись файла в каталог данных: создаётся заново (не копируется), чтобы
/// он унаследовал ACL каталога, а не исходника из профиля.
fn write_secure(path: &PathBuf, data: &[u8]) -> Result<()> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, data).with_context(|| format!("запись {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("запись {}", path.display()))
}

/// Ставит защищённый DACL из SDDL на каталог (дети получат наследуемые ACE).
fn set_dir_acl(dir: &Path, sddl: &str) -> Result<()> {
    let sddl_w = wide(sddl);
    let path_w = wide(dir);
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: указатели валидны на время вызовов; sd освобождается LocalFree.
    unsafe {
        if ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl_w.as_ptr(),
            SDDL_REVISION_1,
            &mut sd,
            std::ptr::null_mut(),
        ) == 0
        {
            return Err(std::io::Error::last_os_error()).context("разбор SDDL");
        }
        let mut present = 0;
        let mut defaulted = 0;
        let mut dacl: *mut ACL = std::ptr::null_mut();
        let ok = GetSecurityDescriptorDacl(sd, &mut present, &mut dacl, &mut defaulted);
        let res = if ok == 0 || present == 0 {
            Err(anyhow!("в SDDL нет DACL"))
        } else {
            let rc = SetNamedSecurityInfoW(
                path_w.as_ptr(),
                SE_FILE_OBJECT,
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                dacl,
                std::ptr::null(),
            );
            if rc == ERROR_SUCCESS {
                Ok(())
            } else {
                Err(std::io::Error::from_raw_os_error(rc as i32)).context("SetNamedSecurityInfo")
            }
        };
        LocalFree(sd as HLOCAL);
        res
    }
}

/// Строковый SID пользователя текущего процесса (установщик под UAC
/// работает с тем же пользователем, что и его сеанс).
fn current_user_sid() -> Result<String> {
    // SAFETY: буфер достаточного размера, хэндл токена закрывается.
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return Err(std::io::Error::last_os_error()).context("OpenProcessToken");
        }
        let mut len = 0u32;
        GetTokenInformation(token, TokenUser, std::ptr::null_mut(), 0, &mut len);
        // u64 — выравнивание под TOKEN_USER
        let mut buf = vec![0u64; (len as usize).div_ceil(8).max(1)];
        let ok = GetTokenInformation(token, TokenUser, buf.as_mut_ptr().cast(), len, &mut len);
        let err = std::io::Error::last_os_error();
        CloseHandle(token);
        if ok == 0 {
            return Err(err).context("GetTokenInformation(TokenUser)");
        }
        let user = &*(buf.as_ptr() as *const TOKEN_USER);
        let mut s: windows_sys::core::PWSTR = std::ptr::null_mut();
        if ConvertSidToStringSidW(user.User.Sid, &mut s) == 0 {
            return Err(std::io::Error::last_os_error()).context("ConvertSidToStringSid");
        }
        let n = (0..).take_while(|&i| *s.add(i) != 0).count();
        let sid = String::from_utf16_lossy(std::slice::from_raw_parts(s, n));
        LocalFree(s as HLOCAL);
        validate_sid(&sid)?;
        Ok(sid)
    }
}

fn set_run_value(value: &str) -> Result<()> {
    let key = wide(RUN_KEY);
    let name = wide(RUN_VALUE);
    let data = wide(value);
    // SAFETY: буферы с нулём на конце живут до конца вызова.
    let rc = unsafe {
        RegSetKeyValueW(
            HKEY_CURRENT_USER,
            key.as_ptr(),
            name.as_ptr(),
            REG_SZ,
            data.as_ptr().cast(),
            (data.len() * 2) as u32,
        )
    };
    if rc != ERROR_SUCCESS {
        return Err(std::io::Error::from_raw_os_error(rc as i32)).context("RegSetKeyValue");
    }
    Ok(())
}

fn delete_run_value() -> Result<()> {
    let key = wide(RUN_KEY);
    let name = wide(RUN_VALUE);
    // SAFETY: буферы с нулём на конце живут до конца вызова.
    let rc = unsafe { RegDeleteKeyValueW(HKEY_CURRENT_USER, key.as_ptr(), name.as_ptr()) };
    if rc != ERROR_SUCCESS && rc != ERROR_FILE_NOT_FOUND {
        return Err(std::io::Error::from_raw_os_error(rc as i32)).context("RegDeleteKeyValue");
    }
    Ok(())
}

fn create_shortcut(spec: &ShortcutSpec) -> Result<()> {
    let out = Command::new("powershell.exe")
        .args(powershell_args(&shortcut_script(spec)))
        .output()
        .context("запуск powershell.exe")?;
    if !out.status.success() {
        bail!(
            "powershell: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}
