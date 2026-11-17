//! Кроссплатформенная (чистая) часть: имена, пути, SDDL, сборка аргументов
//! и PowerShell-скрипта ярлыка. Покрыта тестами на любой ОС.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result, bail};

/// Имя службы в SCM.
pub const SERVICE_NAME: &str = "TunnelDaemon";
/// Отображаемое имя службы.
pub const SERVICE_DISPLAY_NAME: &str = "Tunnel daemon";
/// Описание службы (services.msc).
pub const SERVICE_DESCRIPTION: &str =
    "Владелец туннеля Tunnel: Wintun-адаптер, соединение с сервером, IPC для трея и TUI";
/// Аргументы, с которыми SCM запускает `tunnel-daemon.exe`.
pub const SERVICE_ARGS: &[&str] = &["service"];
/// Задержки рестарта службы после сбоев (1-й, 2-й, последующие).
pub const RECOVERY_DELAYS: [Duration; 3] = [
    Duration::from_secs(5),
    Duration::from_secs(10),
    Duration::from_secs(30),
];
/// Через сколько без сбоев счётчик сбоев SCM обнуляется.
pub const RECOVERY_RESET: Duration = Duration::from_secs(24 * 60 * 60);

/// Каталог данных службы внутри `%ProgramData%`.
pub const DATA_DIR_NAME: &str = "tunnel";
/// Конфиг службы (и пользовательский конфиг в `%APPDATA%\tunnel`).
pub const CONFIG_FILE: &str = "client.json";
/// Файл с SID установившего пользователя (для SDDL пайпа).
pub const OWNER_SID_FILE: &str = "owner.sid";
/// DLL Wintun рядом с exe.
pub const WINTUN_DLL: &str = "wintun.dll";

/// Ключ автозапуска в HKCU.
pub const RUN_KEY: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
/// Имя значения автозапуска трея.
pub const RUN_VALUE: &str = "TunnelTray";
/// Имена exe в каталоге установки.
pub const DAEMON_EXE: &str = "tunnel-daemon.exe";
pub const TRAY_EXE: &str = "tunnel-tray.exe";
pub const CLIENT_EXE: &str = "tunnel-client.exe";
/// AppUserModelID трея (нужен для toast-уведомлений).
pub const AUMID: &str = "Tunnel.Tray";
/// Имя ярлыка в меню «Пуск» (без `.lnk`).
pub const SHORTCUT_NAME: &str = "Tunnel";

/// DACL каталога данных: SYSTEM и Administrators — полный доступ
/// (наследуется файлами и подкаталогами), остальным — ничего; `P` — без
/// наследования от `%ProgramData%`.
/// Владелец — Administrators (`O:BA`): иначе создавший каталог заранее
/// обычный пользователь остался бы владельцем с неявным WRITE_DAC.
pub const DATA_DIR_SDDL: &str = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
/// Владельцы каталога данных, которым можно доверять (SYSTEM, Administrators).
pub const TRUSTED_OWNER_SIDS: [&str; 2] = ["S-1-5-18", "S-1-5-32-544"];

/// Событие SCM, переданное телу службы.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceEvent {
    /// `sc stop` / services.msc — корректно остановиться.
    Stop,
    /// Выключение системы — остановиться как можно быстрее.
    Shutdown,
    /// Выход из сна (PBT_APMRESUMEAUTOMATIC / RESUMESUSPEND) — переподключиться.
    Resume,
}

/// Ярлык в меню «Пуск» с AppUserModelID.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShortcutSpec {
    /// Полный путь к `.lnk`.
    pub lnk: PathBuf,
    pub target: PathBuf,
    pub args: String,
    pub workdir: PathBuf,
    pub description: String,
    pub aumid: String,
}

/// Параметры установки.
#[derive(Debug, Clone)]
pub struct InstallOptions {
    pub service_name: String,
    pub display_name: String,
    pub description: String,
    /// Полный путь к `tunnel-daemon.exe` (в каталоге, куда пишет только админ).
    pub daemon_exe: PathBuf,
    pub service_args: Vec<String>,
    /// Трей для `HKCU\…\Run`; `None` — ключ не трогаем.
    pub tray_exe: Option<PathBuf>,
    /// Ярлык с AUMID; `None` — без ярлыка.
    pub shortcut: Option<ShortcutSpec>,
    /// Запустить службу сразу после установки.
    pub start: bool,
    /// SID настоящего пользователя рабочего стола (пайп, `Run`-ключ).
    /// `None` — определить по владельцу оболочки (explorer.exe); при
    /// over-the-shoulder UAC токен установщика — это админ, а не он.
    pub owner_sid: Option<String>,
    /// `%APPDATA%` этого пользователя (импорт `client.json`); `None` —
    /// переменная окружения установщика.
    pub user_appdata: Option<PathBuf>,
}

impl InstallOptions {
    /// Стандартная раскладка: все exe лежат в `install_dir`
    /// (`%ProgramFiles%\Tunnel`); ярлык — в меню «Пуск» пользователя
    /// (`appdata` — его `%APPDATA%`).
    pub fn for_layout(install_dir: &Path, appdata: Option<&Path>) -> Self {
        let tray = install_dir.join(TRAY_EXE);
        let shortcut = appdata.map(|a| ShortcutSpec {
            lnk: start_menu_shortcut(a, SHORTCUT_NAME),
            target: tray.clone(),
            args: String::new(),
            workdir: install_dir.to_path_buf(),
            description: "Tunnel — значок в трее".into(),
            aumid: AUMID.into(),
        });
        Self {
            service_name: SERVICE_NAME.into(),
            display_name: SERVICE_DISPLAY_NAME.into(),
            description: SERVICE_DESCRIPTION.into(),
            daemon_exe: install_dir.join(DAEMON_EXE),
            service_args: SERVICE_ARGS.iter().map(|s| s.to_string()).collect(),
            tray_exe: Some(tray),
            shortcut,
            start: true,
            owner_sid: None,
            user_appdata: appdata.map(Path::to_path_buf),
        }
    }
}

/// Итог установки.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub data_dir: PathBuf,
    /// `true` — пользовательский `client.json` скопирован в ProgramData.
    pub config_imported: bool,
    pub owner_sid: String,
    /// `true` — служба уже была и её конфигурация обновлена.
    pub service_updated: bool,
    /// Некритичные ошибки (Run-ключ, ярлык, старт службы): служба при этом
    /// установлена.
    pub warnings: Vec<String>,
}

/// Параметры удаления.
#[derive(Debug, Clone)]
pub struct UninstallOptions {
    pub service_name: String,
    /// Удалить и `%ProgramData%\tunnel` (identity, друзья, owner.sid).
    pub purge: bool,
    /// Ярлык для удаления (`None` — не трогать).
    pub shortcut_lnk: Option<PathBuf>,
    /// Удалять ли значение `Run` трея.
    pub remove_run_key: bool,
}

impl UninstallOptions {
    pub fn standard(purge: bool, appdata: Option<&Path>) -> Self {
        Self {
            service_name: SERVICE_NAME.into(),
            purge,
            shortcut_lnk: appdata.map(|a| start_menu_shortcut(a, SHORTCUT_NAME)),
            remove_run_key: true,
        }
    }
}

/// `%ProgramData%\tunnel`; без переменной — `C:\ProgramData\tunnel`.
pub fn data_dir_from(programdata: Option<&OsStr>) -> PathBuf {
    let base = match programdata {
        Some(p) if !p.is_empty() => PathBuf::from(p),
        _ => PathBuf::from(r"C:\ProgramData"),
    };
    base.join(DATA_DIR_NAME)
}

/// Каталог данных службы. В Windows — через `SHGetKnownFolderPath`
/// (переменную `ProgramData` пользователь может переопределить в
/// `HKCU\Environment`, и повышенный установщик её унаследует).
#[cfg(windows)]
pub fn data_dir() -> PathBuf {
    use windows_sys::Win32::System::Com::CoTaskMemFree;
    use windows_sys::Win32::UI::Shell::{FOLDERID_ProgramData, SHGetKnownFolderPath};
    let mut p: windows_sys::core::PWSTR = std::ptr::null_mut();
    // SAFETY: p выделяет shell, освобождаем CoTaskMemFree в любом случае.
    unsafe {
        let hr = SHGetKnownFolderPath(&FOLDERID_ProgramData, 0, std::ptr::null_mut(), &mut p);
        let base = if hr >= 0 && !p.is_null() {
            let n = (0..).take_while(|&i| *p.add(i) != 0).count();
            Some(String::from_utf16_lossy(std::slice::from_raw_parts(p, n)))
        } else {
            None
        };
        CoTaskMemFree(p as *const _);
        // без known folder — системный путь, но не переменная окружения
        data_dir_from(base.as_deref().map(OsStr::new))
    }
}

/// Каталог данных службы по текущему окружению (не Windows).
#[cfg(not(windows))]
pub fn data_dir() -> PathBuf {
    data_dir_from(std::env::var_os("ProgramData").as_deref())
}

/// `%APPDATA%\tunnel\client.json` пользователя.
pub fn user_config_path(appdata: &Path) -> PathBuf {
    appdata.join(DATA_DIR_NAME).join(CONFIG_FILE)
}

/// Конфиг службы в каталоге данных.
pub fn service_config_path(data_dir: &Path) -> PathBuf {
    data_dir.join(CONFIG_FILE)
}

/// Файл SID владельца в каталоге данных.
pub fn owner_sid_path(data_dir: &Path) -> PathBuf {
    data_dir.join(OWNER_SID_FILE)
}

/// Ярлык в меню «Пуск» пользователя.
pub fn start_menu_shortcut(appdata: &Path, name: &str) -> PathBuf {
    appdata
        .join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join(format!("{name}.lnk"))
}

/// Проверка строкового SID (`S-1-5-21-…`): только цифры и дефисы, чтобы его
/// можно было безопасно подставить в SDDL.
pub fn validate_sid(sid: &str) -> Result<()> {
    let rest = sid
        .strip_prefix("S-1-")
        .with_context(|| format!("неверный SID «{sid}»: ожидается S-1-…"))?;
    if rest.is_empty()
        || rest
            .split('-')
            .any(|p| p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()))
    {
        bail!("неверный SID «{sid}»");
    }
    Ok(())
}

/// SDDL пайпа демона: SYSTEM и Administrators — полный доступ, владелец —
/// чтение/запись; `P` — без наследования.
pub fn pipe_sddl(owner_sid: &str) -> Result<String> {
    validate_sid(owner_sid)?;
    Ok(format!(
        "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;{owner_sid})"
    ))
}

/// Разбор содержимого `owner.sid` (пробелы/перевод строки по краям допустимы).
pub fn parse_owner_sid(text: &str) -> Result<String> {
    let sid = text.trim();
    validate_sid(sid)?;
    Ok(sid.to_string())
}

/// Чтение `owner.sid` из каталога данных.
pub fn read_owner_sid(data_dir: &Path) -> Result<String> {
    let path = owner_sid_path(data_dir);
    let text = std::fs::read_to_string(&path).with_context(|| {
        format!(
            "нет SID владельца ({}): служба не установлена?",
            path.display()
        )
    })?;
    parse_owner_sid(&text)
}

/// Значение `Run`-ключа: путь в кавычках (пробелы в `Program Files`).
pub fn run_value(exe: &Path) -> String {
    format!("\"{}\"", exe.display())
}

/// DLL Wintun рядом с `exe`. Других мест поиска нет (никакого PATH и
/// системных каталогов): каталог установки пишет только администратор,
/// иначе подмена DLL = код от SYSTEM.
pub fn wintun_dll_beside(exe: &Path) -> Result<PathBuf> {
    let dir = exe
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .with_context(|| format!("у пути exe нет каталога: {}", exe.display()))?;
    if !dir.is_absolute() {
        bail!("каталог exe должен быть абсолютным: {}", dir.display());
    }
    let dll = dir.join(WINTUN_DLL);
    if !dll.is_file() {
        bail!(
            "нет {WINTUN_DLL} рядом с {} (ожидается {}); положите DLL в каталог установки",
            exe.display(),
            dll.display()
        );
    }
    Ok(dll)
}

/// Путь к `wintun.dll` для службы: только `current_exe().parent()`. На
/// Windows каталог, exe и DLL должны быть доступны на запись только
/// администраторам ([`verify_install_dir`]) — иначе DLL не грузится.
pub fn service_wintun_dll() -> Result<PathBuf> {
    let exe = std::env::current_exe().context("не удалось узнать путь exe")?;
    #[cfg(windows)]
    crate::acl::verify_install_dir(&exe)?;
    wintun_dll_beside(&exe)
}

// ---------- ACL: кому можно писать в каталог установки ----------

/// TrustedInstaller (`NT SERVICE\TrustedInstaller`).
pub const TRUSTED_INSTALLER_SID: &str =
    "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464";
/// Кому разрешено владеть и писать в каталог установки службы и её файлы.
pub const TRUSTED_WRITER_SIDS: [&str; 3] = ["S-1-5-18", "S-1-5-32-544", TRUSTED_INSTALLER_SID];

/// Права, дающие подменить содержимое файла/каталога: `FILE_WRITE_DATA`
/// (`ADD_FILE`), `FILE_APPEND_DATA` (`ADD_SUBDIRECTORY`), `FILE_DELETE_CHILD`,
/// `DELETE`, `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_ALL`, `GENERIC_WRITE`,
/// `MAXIMUM_ALLOWED`.
pub const WRITE_MASK: u32 =
    0x2 | 0x4 | 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x4000_0000 | 0x0200_0000;
/// Для каталогов-предков: права, дающие переименовать/удалить потомка или
/// сам каталог (подменить путь целиком): `FILE_DELETE_CHILD`, `DELETE`,
/// `WRITE_DAC`, `WRITE_OWNER`, `GENERIC_ALL`, `MAXIMUM_ALLOWED`. Создавать
/// новые подкаталоги (как в `C:\` у Users) — можно.
pub const REPLACE_MASK: u32 = 0x40 | 0x1_0000 | 0x4_0000 | 0x8_0000 | 0x1000_0000 | 0x0200_0000;

/// Тип ACE в DACL.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AceKind {
    Allow,
    Deny,
    /// Разрешающий ACE, SID которого не разобран (объектные ACE и т. п.) —
    /// считается разрешением неизвестному.
    UnknownAllow,
    /// Аудит, метки и прочее — на доступ не влияет.
    Other,
}

/// ACE в разобранном виде.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ace {
    pub kind: AceKind,
    /// Строковый SID (`S-1-…`), пусто для `UnknownAllow`.
    pub sid: String,
    pub mask: u32,
    /// `INHERIT_ONLY_ACE`: к самому объекту не применяется.
    pub inherit_only: bool,
}

/// Владелец и DACL объекта не дают записи никому, кроме SYSTEM,
/// Administrators и TrustedInstaller (по маске `mask`). `dacl = None` —
/// NULL DACL (полный доступ всем). Ошибка — с причиной.
pub fn check_admin_only(path: &Path, owner: &str, dacl: Option<&[Ace]>, mask: u32) -> Result<()> {
    if !TRUSTED_WRITER_SIDS.contains(&owner) {
        bail!(
            "владелец {} — {owner}, а не SYSTEM/Administrators/TrustedInstaller",
            path.display()
        );
    }
    let Some(dacl) = dacl else {
        bail!("у {} нет DACL — запись разрешена всем", path.display());
    };
    for ace in dacl {
        if ace.inherit_only || ace.mask & mask == 0 {
            continue;
        }
        match ace.kind {
            AceKind::Allow if TRUSTED_WRITER_SIDS.contains(&ace.sid.as_str()) => {}
            AceKind::Allow => bail!(
                "{} доступен на запись {} (права {:#x})",
                path.display(),
                ace.sid,
                ace.mask
            ),
            AceKind::UnknownAllow => bail!(
                "{}: неразобранный разрешающий ACE (права {:#x})",
                path.display(),
                ace.mask
            ),
            AceKind::Deny | AceKind::Other => {}
        }
    }
    Ok(())
}

/// Текст отказа установки/запуска из небезопасного каталога.
pub fn unsafe_install_dir_msg(dir: &Path, why: &str) -> String {
    format!(
        "каталог {} небезопасен для службы: {why}. Служба работает от SYSTEM и грузит \
отсюда exe и {WINTUN_DLL} — подмена файла обычным пользователем = его код от SYSTEM. \
Установите через infrastructure\\windows\\install.ps1 (копирует файлы в %ProgramFiles%\\Tunnel) \
или скопируйте {DAEMON_EXE} и {WINTUN_DLL} в %ProgramFiles%\\Tunnel и запустите \
«tunnel-daemon install» оттуда",
        dir.display()
    )
}

/// Строка PowerShell в одинарных кавычках (подстановок нет). Удваиваются
/// все символы, которые PowerShell считает одинарной кавычкой: `'` и
/// U+2018..U+201B (иначе `O’Brien` закрыл бы строку раньше).
pub fn ps_quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for c in s.chars() {
        if matches!(c, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}') {
            out.push(c);
        }
        out.push(c);
    }
    out.push('\'');
    out
}

/// C#-код создания `.lnk` с `System.AppUserModel.ID` (IShellLinkW +
/// IPropertyStore): WScript.Shell свойство AUMID выставить не умеет.
const SHORTCUT_CS: &str = r#"
using System;
using System.Runtime.InteropServices;
using System.Text;
namespace TunnelLnk {
  [ComImport, Guid("000214F9-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IShellLinkW {
    void GetPath([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder f, int c, IntPtr fd, uint fl);
    void GetIDList(out IntPtr p);
    void SetIDList(IntPtr p);
    void GetDescription([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int c);
    void SetDescription([MarshalAs(UnmanagedType.LPWStr)] string s);
    void GetWorkingDirectory([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int c);
    void SetWorkingDirectory([MarshalAs(UnmanagedType.LPWStr)] string s);
    void GetArguments([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int c);
    void SetArguments([MarshalAs(UnmanagedType.LPWStr)] string s);
    void GetHotkey(out short h);
    void SetHotkey(short h);
    void GetShowCmd(out int c);
    void SetShowCmd(int c);
    void GetIconLocation([Out, MarshalAs(UnmanagedType.LPWStr)] StringBuilder s, int c, out int i);
    void SetIconLocation([MarshalAs(UnmanagedType.LPWStr)] string s, int i);
    void SetRelativePath([MarshalAs(UnmanagedType.LPWStr)] string s, uint r);
    void Resolve(IntPtr h, uint f);
    void SetPath([MarshalAs(UnmanagedType.LPWStr)] string s);
  }
  [StructLayout(LayoutKind.Sequential, Pack = 4)]
  public struct PROPERTYKEY { public Guid fmtid; public uint pid; }
  [StructLayout(LayoutKind.Explicit)]
  public struct PROPVARIANT {
    [FieldOffset(0)] public ushort vt;
    [FieldOffset(8)] public IntPtr p;
    [FieldOffset(16)] public IntPtr pad;
  }
  [ComImport, Guid("886D8EEB-8CF2-4446-8D02-CDBA1DBDCF99"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IPropertyStore {
    void GetCount(out uint c);
    void GetAt(uint i, out PROPERTYKEY k);
    void GetValue(ref PROPERTYKEY k, out PROPVARIANT v);
    void SetValue(ref PROPERTYKEY k, ref PROPVARIANT v);
    void Commit();
  }
  [ComImport, Guid("0000010b-0000-0000-C000-000000000046"), InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
  public interface IPersistFile {
    void GetClassID(out Guid g);
    [PreserveSig] int IsDirty();
    void Load([MarshalAs(UnmanagedType.LPWStr)] string f, uint m);
    void Save([MarshalAs(UnmanagedType.LPWStr)] string f, [MarshalAs(UnmanagedType.Bool)] bool r);
    void SaveCompleted([MarshalAs(UnmanagedType.LPWStr)] string f);
    void GetCurFile([MarshalAs(UnmanagedType.LPWStr)] out string f);
  }
  [ComImport, Guid("00021401-0000-0000-C000-000000000046")]
  public class CShellLink {}
  public static class Maker {
    public static void Make(string lnk, string target, string args, string workdir, string desc, string aumid) {
      var link = (IShellLinkW)new CShellLink();
      link.SetPath(target);
      link.SetArguments(args);
      link.SetWorkingDirectory(workdir);
      link.SetDescription(desc);
      link.SetIconLocation(target, 0);
      var store = (IPropertyStore)link;
      var key = new PROPERTYKEY { fmtid = new Guid("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"), pid = 5 };
      var pv = new PROPVARIANT { vt = 31, p = Marshal.StringToCoTaskMemUni(aumid) };
      try { store.SetValue(ref key, ref pv); store.Commit(); }
      finally { Marshal.FreeCoTaskMem(pv.p); }
      ((IPersistFile)link).Save(lnk, true);
    }
  }
}
"#;

/// PowerShell-скрипт создания ярлыка: каталог ярлыка создаётся, старый
/// `.lnk` перезаписывается.
pub fn shortcut_script(spec: &ShortcutSpec) -> String {
    let lnk = spec.lnk.display().to_string();
    let dir = spec
        .lnk
        .parent()
        .map(|d| d.display().to_string())
        .unwrap_or_default();
    format!(
        "$ErrorActionPreference = 'Stop'\n\
         Add-Type -TypeDefinition @'\n{cs}\n'@\n\
         New-Item -ItemType Directory -Force -Path {dir} | Out-Null\n\
         [TunnelLnk.Maker]::Make({lnk}, {target}, {args}, {workdir}, {desc}, {aumid})\n",
        cs = SHORTCUT_CS.trim(),
        dir = ps_quote(&dir),
        lnk = ps_quote(&lnk),
        target = ps_quote(&spec.target.display().to_string()),
        args = ps_quote(&spec.args),
        workdir = ps_quote(&spec.workdir.display().to_string()),
        desc = ps_quote(&spec.description),
        aumid = ps_quote(&spec.aumid),
    )
}

/// Аргументы `powershell.exe` для скрипта через `-EncodedCommand`
/// (base64 от UTF-16LE): никаких проблем с кавычками командной строки.
pub fn powershell_args(script: &str) -> Vec<String> {
    let utf16: Vec<u8> = script
        .encode_utf16()
        .flat_map(|u| u.to_le_bytes())
        .collect();
    vec![
        "-NoProfile".into(),
        "-NonInteractive".into(),
        "-ExecutionPolicy".into(),
        "Bypass".into(),
        "-EncodedCommand".into(),
        base64(&utf16),
    ]
}

/// Стандартный base64 с паддингом (ради одного места не тянем крейт).
pub fn base64(data: &[u8]) -> String {
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(T[(n >> 18) as usize & 63] as char);
        out.push(T[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            T[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            T[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_dir_env_and_fallback() {
        assert_eq!(
            data_dir_from(Some(OsStr::new("D:\\PD"))),
            PathBuf::from("D:\\PD").join("tunnel")
        );
        assert_eq!(
            data_dir_from(None),
            PathBuf::from(r"C:\ProgramData").join("tunnel")
        );
        assert_eq!(data_dir_from(Some(OsStr::new(""))), data_dir_from(None));
    }

    #[test]
    fn file_paths() {
        let d = Path::new("/pd/tunnel");
        assert_eq!(service_config_path(d), d.join("client.json"));
        assert_eq!(owner_sid_path(d), d.join("owner.sid"));
        let a = Path::new("/home/u/AppData/Roaming");
        assert_eq!(user_config_path(a), a.join("tunnel").join("client.json"));
        let lnk = start_menu_shortcut(a, "Tunnel");
        assert!(lnk.ends_with("Microsoft/Windows/Start Menu/Programs/Tunnel.lnk"));
    }

    #[test]
    fn sid_validation() {
        validate_sid("S-1-5-18").unwrap();
        validate_sid("S-1-5-21-1004336348-1177238915-682003330-1001").unwrap();
        for bad in [
            "",
            "S-1-",
            "S-1-5-",
            "S-1-5--1",
            "s-1-5-18",
            "S-1-5-18)(A;;GA;;;WD",
            "X-1-5",
        ] {
            assert!(validate_sid(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn pipe_sddl_format() {
        assert_eq!(
            pipe_sddl("S-1-5-21-1-2-3-1001").unwrap(),
            "D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;S-1-5-21-1-2-3-1001)"
        );
        assert!(pipe_sddl("S-1-5-18)(A;;GA;;;WD)").is_err());
    }

    #[test]
    fn owner_sid_parse() {
        assert_eq!(
            parse_owner_sid(" S-1-5-21-7-1001\r\n").unwrap(),
            "S-1-5-21-7-1001"
        );
        assert!(parse_owner_sid("мусор").is_err());
    }

    #[test]
    fn owner_sid_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!("winsvc-sid-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_owner_sid(&dir).is_err());
        std::fs::write(owner_sid_path(&dir), "S-1-5-21-9-1001\n").unwrap();
        assert_eq!(read_owner_sid(&dir).unwrap(), "S-1-5-21-9-1001");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_value_quoted() {
        assert_eq!(
            run_value(Path::new(r"C:\Program Files\Tunnel\tunnel-tray.exe")),
            r#""C:\Program Files\Tunnel\tunnel-tray.exe""#
        );
    }

    #[test]
    fn wintun_only_beside_exe() {
        let dir = std::env::temp_dir().join(format!("winsvc-dll-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("tunnel-daemon.exe");
        let err = wintun_dll_beside(&exe).unwrap_err().to_string();
        assert!(err.contains("wintun.dll"), "{err}");
        std::fs::write(dir.join(WINTUN_DLL), b"x").unwrap();
        assert_eq!(wintun_dll_beside(&exe).unwrap(), dir.join(WINTUN_DLL));
        // относительный путь и голое имя — отказ
        assert!(wintun_dll_beside(Path::new("tunnel-daemon.exe")).is_err());
        assert!(wintun_dll_beside(Path::new("rel/tunnel-daemon.exe")).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    fn ace(kind: AceKind, sid: &str, mask: u32, inherit_only: bool) -> Ace {
        Ace {
            kind,
            sid: sid.into(),
            mask,
            inherit_only,
        }
    }

    #[test]
    fn admin_only_acl() {
        let p = Path::new(r"C:\Program Files\Tunnel");
        const FA: u32 = 0x1f_01ff;
        const RX: u32 = 0x12_00a9;
        let users = "S-1-5-32-545";
        let me = "S-1-5-21-1-2-3-1001";
        // Раскладка install.ps1: SY/BA — всё, Users — чтение; CREATOR OWNER
        // только наследуемый.
        let good = vec![
            ace(AceKind::Allow, "S-1-5-18", FA, false),
            ace(AceKind::Allow, "S-1-5-32-544", FA, false),
            ace(AceKind::Allow, users, RX, false),
            ace(AceKind::Allow, "S-1-3-0", 0x1000_0000, true),
            ace(AceKind::Allow, TRUSTED_INSTALLER_SID, FA, false),
            ace(AceKind::Deny, "", FA, false),
        ];
        check_admin_only(p, "S-1-5-32-544", Some(&good), WRITE_MASK).unwrap();
        check_admin_only(p, TRUSTED_INSTALLER_SID, Some(&good), WRITE_MASK).unwrap();
        // Владелец — пользователь (неявный WRITE_DAC).
        let e = check_admin_only(p, me, Some(&good), WRITE_MASK).unwrap_err();
        assert!(e.to_string().contains(me), "{e}");
        // NULL DACL.
        assert!(check_admin_only(p, "S-1-5-18", None, WRITE_MASK).is_err());
        // Запись для Users / Authenticated Users / Everyone / самого пользователя.
        for (sid, mask) in [
            (users, 0x2),
            ("S-1-5-11", 0x1_0000),
            ("S-1-1-0", 0x4000_0000),
            (me, 0x4_0000),
        ] {
            let mut bad = good.clone();
            bad.push(ace(AceKind::Allow, sid, mask, false));
            let e = check_admin_only(p, "S-1-5-18", Some(&bad), WRITE_MASK).unwrap_err();
            assert!(e.to_string().contains(sid), "{e}");
        }
        let mut bad = good.clone();
        bad.push(ace(AceKind::UnknownAllow, "", 0x2, false));
        assert!(check_admin_only(p, "S-1-5-18", Some(&bad), WRITE_MASK).is_err());
        // Предок: создавать подкаталоги (как Users в C:\) можно, удалять детей — нет.
        let mut root = good.clone();
        root.push(ace(AceKind::Allow, users, 0x4 | 0x2, false));
        check_admin_only(Path::new(r"C:\"), "S-1-5-18", Some(&root), REPLACE_MASK).unwrap();
        root.push(ace(AceKind::Allow, users, 0x40, false));
        assert!(
            check_admin_only(Path::new(r"C:\"), "S-1-5-18", Some(&root), REPLACE_MASK).is_err()
        );
        let m = unsafe_install_dir_msg(p, "x");
        assert!(
            m.contains("install.ps1") && m.contains("%ProgramFiles%"),
            "{m}"
        );
    }

    #[test]
    fn ps_quoting() {
        assert_eq!(ps_quote("a"), "'a'");
        assert_eq!(ps_quote("O'Brien $x"), "'O''Brien $x'");
        assert_eq!(ps_quote("O\u{2019}Brien"), "'O\u{2019}\u{2019}Brien'");
        assert_eq!(
            ps_quote("\u{2018}a\u{201A}b\u{201B}"),
            "'\u{2018}\u{2018}a\u{201A}\u{201A}b\u{201B}\u{201B}'"
        );
    }

    #[test]
    fn base64_vectors() {
        for (i, o) in [
            ("", ""),
            ("f", "Zg=="),
            ("fo", "Zm8="),
            ("foo", "Zm9v"),
            ("foob", "Zm9vYg=="),
            ("fooba", "Zm9vYmE="),
            ("foobar", "Zm9vYmFy"),
        ] {
            assert_eq!(base64(i.as_bytes()), o);
        }
    }

    #[test]
    fn powershell_encoded() {
        let a = powershell_args("dir");
        assert_eq!(a[4], "-EncodedCommand");
        // "dir" в UTF-16LE
        assert_eq!(a[5], base64(&[b'd', 0, b'i', 0, b'r', 0]));
    }

    #[test]
    fn shortcut_script_content() {
        let spec = ShortcutSpec {
            lnk: PathBuf::from("/a/Programs/Tun'nel.lnk"),
            target: PathBuf::from("/pf/tunnel-tray.exe"),
            args: String::new(),
            workdir: PathBuf::from("/pf"),
            description: "d".into(),
            aumid: AUMID.into(),
        };
        let s = shortcut_script(&spec);
        assert!(s.starts_with("$ErrorActionPreference = 'Stop'"));
        assert!(s.contains("9F4C2855-9F79-4B39-A8D0-E1D42DE1D5F3"));
        assert!(s.contains("[TunnelLnk.Maker]::Make('/a/Programs/Tun''nel.lnk', '/pf/tunnel-tray.exe', '', '/pf', 'd', 'Tunnel.Tray')"));
        assert!(s.contains("New-Item -ItemType Directory -Force -Path '/a/Programs'"));
        // here-string закрывается ровно один раз, в начале строки
        assert_eq!(s.matches("\n'@").count(), 1);
    }

    #[test]
    fn layout_defaults() {
        let o = InstallOptions::for_layout(Path::new("/pf/Tunnel"), Some(Path::new("/ad")));
        assert_eq!(o.service_name, SERVICE_NAME);
        assert_eq!(o.daemon_exe, Path::new("/pf/Tunnel").join(DAEMON_EXE));
        assert_eq!(o.service_args, ["service"]);
        assert_eq!(
            o.tray_exe.as_deref(),
            Some(Path::new("/pf/Tunnel").join(TRAY_EXE).as_path())
        );
        let sc = o.shortcut.unwrap();
        assert_eq!(sc.aumid, AUMID);
        assert_eq!(sc.lnk, start_menu_shortcut(Path::new("/ad"), SHORTCUT_NAME));
        assert_eq!(o.user_appdata.as_deref(), Some(Path::new("/ad")));
        assert!(o.owner_sid.is_none());
        assert!(
            InstallOptions::for_layout(Path::new("/pf"), None)
                .shortcut
                .is_none()
        );
        let u = UninstallOptions::standard(true, Some(Path::new("/ad")));
        assert!(u.purge && u.remove_run_key);
        assert_eq!(u.shortcut_lnk, Some(sc.lnk));
    }

    #[test]
    fn recovery_plan() {
        let secs: Vec<u64> = RECOVERY_DELAYS.iter().map(|d| d.as_secs()).collect();
        assert_eq!(secs, [5, 10, 30]);
    }
}
