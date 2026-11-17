//! Windows-часть трея: `tray-icon` + `muda` (реэкспорт `tray_icon::menu`),
//! свой цикл `GetMessageW` без winit, toast через `tauri-winrt-notification`.

use std::path::PathBuf;
use std::process::Command;
use std::ptr::null_mut;
use std::time::Instant;

use tauri_winrt_notification::Toast;
use tray_icon::menu::{CheckMenuItem, IsMenuItem, Menu, MenuEvent, MenuItem, PredefinedMenuItem, Submenu};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use windows_sys::Win32::UI::Shell::ShellExecuteW;
use windows_sys::Win32::UI::WindowsAndMessaging::{
    DispatchMessageW, GetMessageW, KillTimer, MB_ICONERROR, MB_OK, MSG, MessageBoxW, PostQuitMessage,
    RegisterWindowMessageW, SW_HIDE, SetTimer, TranslateMessage, WM_TIMER,
};

use crate::backend::TrayBackend;
use crate::model::{self, Action, IconColor, MenuEntry, Notice, Notifier, NotifyMode, TrayState};

/// Период опроса бэкенда.
const POLL_MS: u32 = 500;
/// Имя службы демона (7.6).
const SERVICE_NAME: &str = "TunnelDaemon";
/// AUMID для toast. Ярлык «Пуск» с собственным AUMID создаёт установщик (7.6);
/// до него — общий AUMID PowerShell, иначе Windows молча не покажет toast.
const TOAST_APP_ID: &str = Toast::POWERSHELL_APP_ID;

fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

pub fn error_box(text: &str) {
    let (t, c) = (wide(text), wide("Tunnel"));
    unsafe { MessageBoxW(null_mut(), t.as_ptr(), c.as_ptr(), MB_OK | MB_ICONERROR) };
}

/// Главный цикл трея; возвращается по «Выход».
pub fn run(backend: &dyn TrayBackend, mode: NotifyMode) -> Result<(), String> {
    // Explorer рассылает TaskbarCreated всем окнам верхнего уровня после
    // перезапуска; скрытое окно tray-icon получает его через наш цикл.
    let taskbar_created = unsafe { RegisterWindowMessageW(wide("TaskbarCreated").as_ptr()) };
    let mut ui = Ui::new(backend, mode);
    ui.refresh();
    ui.recreate()?;

    let timer = unsafe { SetTimer(null_mut(), 0, POLL_MS, None) };
    let mut msg: MSG = unsafe { std::mem::zeroed() };
    loop {
        let r = unsafe { GetMessageW(&mut msg, null_mut(), 0, 0) };
        if r == 0 || r == -1 {
            break;
        }
        unsafe {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
        if taskbar_created != 0 && msg.message == taskbar_created {
            // tray-icon сам перерегистрирует значок, но после перезапуска
            // explorer он мог стартовать раньше панели — пересоздаём целиком.
            let _ = ui.recreate();
        }
        let clicked = ui.drain_menu_events();
        if msg.message == WM_TIMER || clicked {
            ui.refresh();
        }
        if ui.quit {
            unsafe { PostQuitMessage(0) };
            ui.quit = false;
        }
    }
    unsafe { KillTimer(null_mut(), timer) };
    Ok(())
}

struct Ui<'a> {
    backend: &'a dyn TrayBackend,
    tray: Option<TrayIcon>,
    state: TrayState,
    menu: Vec<MenuEntry>,
    color: Option<IconColor>,
    tip: String,
    notifier: Notifier,
    quit: bool,
}

impl<'a> Ui<'a> {
    fn new(backend: &'a dyn TrayBackend, mode: NotifyMode) -> Self {
        Self {
            backend,
            tray: None,
            state: TrayState::default(),
            menu: Vec::new(),
            color: None,
            tip: String::new(),
            notifier: Notifier::new(mode),
            quit: false,
        }
    }

    /// Создать значок заново из текущего состояния (старт, TaskbarCreated).
    fn recreate(&mut self) -> Result<(), String> {
        self.tray = None; // Drop снимает старый значок
        let color = model::icon_color(self.state.conn);
        self.menu = model::build_menu(&self.state);
        self.tip = model::tooltip(&self.state);
        let tray = TrayIconBuilder::new()
            .with_icon(make_icon(color)?)
            .with_tooltip(&self.tip)
            .with_menu(Box::new(build_muda(&self.menu)))
            .build()
            .map_err(|e| format!("значок трея: {e}"))?;
        self.tray = Some(tray);
        self.color = Some(color);
        Ok(())
    }

    /// Опросить бэкенд, обновить значок/меню/подсказку, показать уведомления.
    fn refresh(&mut self) {
        let st = self.backend.state();
        for n in self.notifier.observe(&st, Instant::now()) {
            show_toast(&n);
        }
        self.state = st;
        let Some(tray) = &self.tray else { return };

        let menu = model::build_menu(&self.state);
        if menu != self.menu {
            tray.set_menu(Some(Box::new(build_muda(&menu))));
            self.menu = menu;
        }
        let tip = model::tooltip(&self.state);
        if tip != self.tip {
            let _ = tray.set_tooltip(Some(&tip));
            self.tip = tip;
        }
        let color = model::icon_color(self.state.conn);
        if self.color != Some(color)
            && let Ok(icon) = make_icon(color)
        {
            let _ = tray.set_icon(Some(icon));
            self.color = Some(color);
        }
    }

    /// Разобрать клики меню; `true` — был хотя бы один.
    fn drain_menu_events(&mut self) -> bool {
        let mut any = false;
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            any = true;
            let Some(a) = Action::from_id(ev.id().as_ref()) else { continue };
            self.notifier.on_action(a);
            if a.is_local() {
                self.local(a);
            } else {
                self.backend.act(a);
            }
        }
        any
    }

    fn local(&mut self, a: Action) {
        match a {
            Action::OpenTui => {
                if let Err(e) = open_tui() {
                    error_box(&format!("Не удалось открыть Tunnel: {e}"));
                }
            }
            Action::CopyIp => {
                if let Some(ip) = self.state.my_ips.first() {
                    copy(ip);
                }
            }
            Action::CopyCode => {
                if let Some(code) = &self.state.my_code {
                    copy(code);
                }
            }
            Action::StopTunnel => stop_service(),
            Action::Exit => self.quit = true,
            _ => {}
        }
    }
}

fn make_icon(c: IconColor) -> Result<Icon, String> {
    Icon::from_rgba(model::icon_rgba(c), model::ICON_SIZE, model::ICON_SIZE).map_err(|e| format!("иконка: {e}"))
}

/// `&` в Win32-меню — мнемоника; в именах групп экранируем.
fn esc(s: &str) -> String {
    s.replace('&', "&&")
}

fn build_items(entries: &[MenuEntry]) -> Vec<Box<dyn IsMenuItem>> {
    entries
        .iter()
        .map(|e| -> Box<dyn IsMenuItem> {
            match e {
                MenuEntry::Item { action, label, enabled } => {
                    Box::new(MenuItem::with_id(action.to_id(), esc(label), *enabled, None))
                }
                MenuEntry::Check { action, label, checked, enabled } => {
                    Box::new(CheckMenuItem::with_id(action.to_id(), esc(label), *enabled, *checked, None))
                }
                MenuEntry::Label(text) => Box::new(MenuItem::new(esc(text), false, None)),
                MenuEntry::Separator => Box::new(PredefinedMenuItem::separator()),
                MenuEntry::Submenu { label, enabled, items } => {
                    let sub = Submenu::new(esc(label), *enabled);
                    for it in build_items(items) {
                        let _ = sub.append(it.as_ref());
                    }
                    Box::new(sub)
                }
            }
        })
        .collect()
}

fn build_muda(entries: &[MenuEntry]) -> Menu {
    let menu = Menu::new();
    for it in build_items(entries) {
        let _ = menu.append(it.as_ref());
    }
    menu
}

fn show_toast(n: &Notice) {
    let (title, body) = n.text();
    let _ = Toast::new(TOAST_APP_ID).title(&title).text1(&body).show();
}

fn copy(text: &str) {
    if let Err(e) = arboard::Clipboard::new().and_then(|mut c| c.set_text(text.to_string())) {
        error_box(&format!("Буфер обмена: {e}"));
    }
}

/// `tunnel-client.exe` рядом с треем, иначе — поиск по PATH.
fn client_exe() -> PathBuf {
    std::env::current_exe()
        .ok()
        .and_then(|p| p.parent().map(|d| d.join("tunnel-client.exe")))
        .filter(|p| p.exists())
        .unwrap_or_else(|| PathBuf::from("tunnel-client.exe"))
}

/// «Открыть Tunnel»: Windows Terminal, нет его — conhost.
fn open_tui() -> std::io::Result<()> {
    let exe = client_exe();
    match Command::new("wt.exe").arg(&exe).arg("tui").spawn() {
        Ok(_) => Ok(()),
        Err(_) => Command::new("conhost.exe").arg(&exe).arg("tui").spawn().map(|_| ()),
    }
}

/// «Остановить туннель»: `sc stop` от администратора через UAC.
fn stop_service() {
    let (verb, file, args) = (wide("runas"), wide("sc.exe"), wide(&format!("stop {SERVICE_NAME}")));
    let r = unsafe { ShellExecuteW(null_mut(), verb.as_ptr(), file.as_ptr(), args.as_ptr(), std::ptr::null(), SW_HIDE) };
    // ShellExecuteW: значение <= 32 — ошибка (в т.ч. отказ в UAC).
    if (r as isize) <= 32 {
        error_box("Не удалось остановить службу (нужны права администратора)");
    }
}
