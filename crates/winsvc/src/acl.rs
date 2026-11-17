//! Проверка ACL на Windows: каталог установки службы (exe и `wintun.dll`
//! грузятся от SYSTEM) и каталог данных режима `console`. Разбор DACL —
//! здесь, решение — чистая [`check_admin_only`] из `common`.

use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, anyhow, bail};
use windows_sys::Win32::Foundation::{ERROR_SUCCESS, HLOCAL, LocalFree};
use windows_sys::Win32::Security::Authorization::{GetNamedSecurityInfoW, SE_FILE_OBJECT};
use windows_sys::Win32::Security::{
    ACL, DACL_SECURITY_INFORMATION, GetAce, OWNER_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
};

use crate::common::*;
use crate::install::{create_fresh_dir, set_dir_acl, sid_to_string};

const INHERIT_ONLY_ACE: u8 = 0x08;

fn wide(p: &Path) -> Vec<u16> {
    p.as_os_str().encode_wide().chain(Some(0)).collect()
}

/// Владелец и DACL файла/каталога (`None` — NULL DACL).
fn read_security(path: &Path) -> Result<(String, Option<Vec<Ace>>)> {
    let path_w = wide(path);
    let mut owner: PSID = std::ptr::null_mut();
    let mut dacl: *mut ACL = std::ptr::null_mut();
    let mut sd: PSECURITY_DESCRIPTOR = std::ptr::null_mut();
    // SAFETY: выходные указатели валидны; owner и dacl указывают внутрь sd,
    // sd освобождается LocalFree.
    unsafe {
        let rc = GetNamedSecurityInfoW(
            path_w.as_ptr(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            &mut owner,
            std::ptr::null_mut(),
            &mut dacl,
            std::ptr::null_mut(),
            &mut sd,
        );
        if rc != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32))
                .with_context(|| format!("права {}", path.display()));
        }
        let res = (|| {
            if owner.is_null() {
                bail!("у {} нет владельца", path.display());
            }
            let owner = sid_to_string(owner)?;
            if dacl.is_null() {
                return Ok((owner, None));
            }
            let mut aces = Vec::new();
            for i in 0..u32::from((*dacl).AceCount) {
                let mut p: *mut core::ffi::c_void = std::ptr::null_mut();
                if GetAce(dacl, i, &mut p) == 0 || p.is_null() {
                    return Err(std::io::Error::last_os_error()).context("GetAce");
                }
                let b = p as *const u8;
                let (ace_type, flags) = (*b, *b.add(1));
                // ACCESS_{ALLOWED,DENIED}[_CALLBACK]_ACE: заголовок, маска, SID.
                let mask = std::ptr::read_unaligned(b.add(4) as *const u32);
                let inherit_only = flags & INHERIT_ONLY_ACE != 0;
                let (kind, sid) = match ace_type {
                    0 | 9 => (AceKind::Allow, sid_to_string(b.add(8) as PSID)?),
                    5 | 11 => (AceKind::UnknownAllow, String::new()),
                    1 | 6 | 10 | 12 => (AceKind::Deny, String::new()),
                    _ => (AceKind::Other, String::new()),
                };
                aces.push(Ace {
                    kind,
                    sid,
                    mask,
                    inherit_only,
                });
            }
            Ok((owner, Some(aces)))
        })();
        LocalFree(sd as HLOCAL);
        res
    }
}

/// Объект доступен на запись (по `mask`) только SYSTEM/Administrators/
/// TrustedInstaller и принадлежит одному из них.
pub fn check_path(path: &Path, mask: u32) -> Result<()> {
    let (owner, dacl) = read_security(path)?;
    check_admin_only(path, &owner, dacl.as_deref(), mask)
}

/// Каталог установки службы безопасен: каталог exe, сам exe и
/// `wintun.dll` (если есть) никто, кроме SYSTEM/Administrators/
/// TrustedInstaller, изменить не может, а каталоги выше — переименовать или
/// подменить. Иначе — ошибка с подсказкой (install.ps1, `%ProgramFiles%`).
pub fn verify_install_dir(exe: &Path) -> Result<()> {
    let exe: PathBuf =
        std::fs::canonicalize(exe).with_context(|| format!("путь exe {}", exe.display()))?;
    let dir = exe
        .parent()
        .with_context(|| format!("у пути exe нет каталога: {}", exe.display()))?
        .to_path_buf();
    let fail = |e: anyhow::Error| anyhow!(unsafe_install_dir_msg(&dir, &format!("{e:#}")));
    check_path(&dir, WRITE_MASK).map_err(fail)?;
    check_path(&exe, WRITE_MASK).map_err(fail)?;
    let dll = dir.join(WINTUN_DLL);
    if dll.exists() {
        check_path(&dll, WRITE_MASK).map_err(fail)?;
    }
    for up in dir.ancestors().skip(1) {
        check_path(up, REPLACE_MASK).map_err(fail)?;
    }
    Ok(())
}

/// Каталог данных `console`: нет — создаётся с [`DATA_DIR_SDDL`]; есть —
/// должен быть закрыт так же (владелец SYSTEM/Administrators, запись — только
/// им), иначе отказ: содержимое мог подложить обычный пользователь.
pub fn secure_data_dir(dir: &Path) -> Result<()> {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() || !m.is_dir() => {
            bail!("каталог данных {} — ссылка или файл", dir.display())
        }
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            create_fresh_dir(dir)?;
            set_dir_acl(dir, DATA_DIR_SDDL).with_context(|| format!("ACL на {}", dir.display()))?;
        }
        Err(e) => return Err(e).with_context(|| format!("{}", dir.display())),
    }
    check_path(dir, WRITE_MASK).map_err(|e| {
        anyhow!(
            "каталог данных {} не защищён ({e:#}): client.json и identity в нём мог подложить \
обычный пользователь. Выполните «tunnel-daemon install» (выставит ACL службы), удалите каталог \
или укажите другой через --data-dir",
            dir.display()
        )
    })
}
