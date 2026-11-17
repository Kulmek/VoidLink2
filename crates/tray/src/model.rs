//! Кроссплатформенная модель трея: состояние → меню, подсказка, цвет иконки,
//! политика уведомлений. Без зависимостей от ОС — всё покрыто тестами;
//! `win.rs` только переводит модель в `tray-icon`/`muda`.
#![allow(dead_code)] // подключается при интеграции (на не-Windows используется только в тестах)

use std::collections::HashSet;
use std::time::{Duration, Instant};

/// Состояние связи с демоном и сервером.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Conn {
    /// Демон работает, сервер на связи.
    Connected,
    /// Демон работает, связь с сервером восстанавливается.
    Reconnecting,
    /// Демон работает, сервера нет (не настроен / недоступен).
    Offline,
    /// Демон (служба) недоступен по IPC.
    DaemonDown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayGroup {
    pub gid: u32,
    pub name: String,
    pub joined: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayInvite {
    pub gid: u32,
    pub group_name: String,
    /// Кто пригласил (имя или короткий ключ).
    pub from: String,
}

/// Событие «группа недоступна» от демона.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayKick {
    pub gid: u32,
    pub group_name: String,
}

/// Снимок для трея; его отдаёт `TrayBackend::state()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrayState {
    pub conn: Conn,
    /// Мои адреса в группах (`10.x.y.z`), первый — основной.
    pub my_ips: Vec<String>,
    /// Подпись текущего сервера (label или адрес).
    pub server_label: Option<String>,
    /// Мой friend code (нет — пункт меню неактивен).
    pub my_code: Option<String>,
    pub groups: Vec<TrayGroup>,
    pub invites: Vec<TrayInvite>,
    /// Группы, из которых нас исключили или которые удалили, — события демона
    /// (Kicked / GroupDeleted) с прошлого вызова `state()`. Бэкенд отдаёт каждое
    /// один раз; свой выход (меню, CLI, TUI) сюда не попадает.
    pub kicked: Vec<TrayKick>,
    /// Ошибки, о которых надо сказать пользователю (отказ демона в `Ack` на
    /// действие из трея, несовместимая версия IPC), с прошлого вызова `state()`;
    /// бэкенд отдаёт каждую один раз.
    pub errors: Vec<String>,
    /// Открыт ли сейчас TUI (для политики уведомлений).
    pub tui_open: bool,
}

impl Default for TrayState {
    fn default() -> Self {
        Self {
            conn: Conn::DaemonDown,
            my_ips: Vec::new(),
            server_label: None,
            my_code: None,
            groups: Vec::new(),
            invites: Vec::new(),
            kicked: Vec::new(),
            errors: Vec::new(),
            tui_open: false,
        }
    }
}

/// Действие по клику в меню.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Action {
    OpenTui,
    CopyIp,
    CopyCode,
    /// Войти (`join = true`) или выйти из группы.
    ToggleGroup {
        gid: u32,
        join: bool,
    },
    AcceptInvite(u32),
    DeclineInvite(u32),
    StopTunnel,
    Exit,
}

impl Action {
    /// Строковый id пункта меню (`muda::MenuId`).
    pub fn to_id(self) -> String {
        match self {
            Action::OpenTui => "open".into(),
            Action::CopyIp => "copy-ip".into(),
            Action::CopyCode => "copy-code".into(),
            Action::ToggleGroup { gid, join } => {
                format!("group:{gid}:{}", if join { 1 } else { 0 })
            }
            Action::AcceptInvite(gid) => format!("accept:{gid}"),
            Action::DeclineInvite(gid) => format!("decline:{gid}"),
            Action::StopTunnel => "stop".into(),
            Action::Exit => "exit".into(),
        }
    }

    pub fn from_id(id: &str) -> Option<Action> {
        Some(match id {
            "open" => Action::OpenTui,
            "copy-ip" => Action::CopyIp,
            "copy-code" => Action::CopyCode,
            "stop" => Action::StopTunnel,
            "exit" => Action::Exit,
            _ => {
                let (kind, rest) = id.split_once(':')?;
                match kind {
                    "group" => {
                        let (gid, join) = rest.split_once(':')?;
                        let join = match join {
                            "1" => true,
                            "0" => false,
                            _ => return None,
                        };
                        Action::ToggleGroup {
                            gid: gid.parse().ok()?,
                            join,
                        }
                    }
                    "accept" => Action::AcceptInvite(rest.parse().ok()?),
                    "decline" => Action::DeclineInvite(rest.parse().ok()?),
                    _ => return None,
                }
            }
        })
    }

    /// Действие выполняет сам трей (буфер обмена, запуск TUI, остановка
    /// службы через UAC `sc stop`, выход), а не демон через `TrayBackend::act`.
    pub fn is_local(self) -> bool {
        matches!(
            self,
            Action::OpenTui | Action::CopyIp | Action::CopyCode | Action::StopTunnel | Action::Exit
        )
    }
}

/// Пункт меню — независимое от `muda` описание.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MenuEntry {
    Item {
        action: Action,
        label: String,
        enabled: bool,
    },
    Check {
        action: Action,
        label: String,
        checked: bool,
        enabled: bool,
    },
    /// Неактивная строка-подпись (статус, «нет групп»).
    Label(String),
    Submenu {
        label: String,
        enabled: bool,
        items: Vec<MenuEntry>,
    },
    Separator,
}

pub fn conn_text(c: Conn) -> &'static str {
    match c {
        Conn::Connected => "подключён",
        Conn::Reconnecting => "переподключение…",
        Conn::Offline => "нет связи с сервером",
        Conn::DaemonDown => "служба недоступна",
    }
}

/// Меню трея по состоянию.
pub fn build_menu(s: &TrayState) -> Vec<MenuEntry> {
    let daemon = s.conn != Conn::DaemonDown;
    let online = s.conn == Conn::Connected;
    let mut m = vec![
        MenuEntry::Label(format!("Tunnel: {}", conn_text(s.conn))),
        MenuEntry::Item {
            action: Action::OpenTui,
            label: "Открыть Tunnel".into(),
            enabled: true,
        },
        MenuEntry::Separator,
    ];

    // Группы с галочкой: клик по отмеченной — выйти, по пустой — войти.
    if s.groups.is_empty() {
        m.push(MenuEntry::Label("Групп нет".into()));
    } else {
        for g in &s.groups {
            m.push(MenuEntry::Check {
                action: Action::ToggleGroup {
                    gid: g.gid,
                    join: !g.joined,
                },
                label: g.name.clone(),
                checked: g.joined,
                enabled: online,
            });
        }
    }

    // Приглашения (N) → по подменю на каждое: Принять / Отклонить.
    let n = s.invites.len();
    let items = s
        .invites
        .iter()
        .map(|i| MenuEntry::Submenu {
            label: format!("{} (от {})", i.group_name, i.from),
            enabled: true,
            items: vec![
                MenuEntry::Item {
                    action: Action::AcceptInvite(i.gid),
                    label: "Принять".into(),
                    enabled: online,
                },
                MenuEntry::Item {
                    action: Action::DeclineInvite(i.gid),
                    label: "Отклонить".into(),
                    enabled: online,
                },
            ],
        })
        .collect();
    m.push(MenuEntry::Submenu {
        label: format!("Приглашения ({n})"),
        enabled: n > 0,
        items,
    });
    m.push(MenuEntry::Separator);

    m.push(MenuEntry::Item {
        action: Action::CopyIp,
        label: match s.my_ips.first() {
            Some(ip) => format!("Скопировать мой IP ({ip})"),
            None => "Скопировать мой IP".into(),
        },
        enabled: !s.my_ips.is_empty(),
    });
    m.push(MenuEntry::Item {
        action: Action::CopyCode,
        label: "Скопировать friend code".into(),
        enabled: s.my_code.is_some(),
    });
    m.push(MenuEntry::Separator);
    m.push(MenuEntry::Item {
        action: Action::StopTunnel,
        label: "Остановить туннель".into(),
        enabled: daemon,
    });
    m.push(MenuEntry::Item {
        action: Action::Exit,
        label: "Выход".into(),
        enabled: true,
    });
    m
}

/// Лимит подсказки `NOTIFYICONDATAW::szTip` — 128 UTF-16 с нулём.
pub const TOOLTIP_MAX: usize = 127;

/// Подсказка: статус, мой IP, сервер.
pub fn tooltip(s: &TrayState) -> String {
    let mut t = format!("Tunnel — {}", conn_text(s.conn));
    if let Some(ip) = s.my_ips.first() {
        t.push_str(&format!("\nIP: {ip}"));
        if s.my_ips.len() > 1 {
            t.push_str(&format!(" (+{})", s.my_ips.len() - 1));
        }
    }
    if let Some(srv) = &s.server_label {
        t.push_str(&format!("\nСервер: {srv}"));
    }
    truncate_utf16(&t, TOOLTIP_MAX)
}

fn truncate_utf16(s: &str, max: usize) -> String {
    if s.encode_utf16().count() <= max {
        return s.to_string();
    }
    let mut out = String::new();
    let mut n = 0;
    for ch in s.chars() {
        let w = ch.len_utf16();
        if n + w > max - 1 {
            break;
        }
        out.push(ch);
        n += w;
    }
    out.push('…');
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IconColor {
    Green,
    Yellow,
    Grey,
}

impl IconColor {
    pub fn rgb(self) -> [u8; 3] {
        match self {
            IconColor::Green => [0x2e, 0xcc, 0x71],
            IconColor::Yellow => [0xf1, 0xc4, 0x0f],
            IconColor::Grey => [0x95, 0xa5, 0xa6],
        }
    }
}

pub fn icon_color(c: Conn) -> IconColor {
    match c {
        Conn::Connected => IconColor::Green,
        Conn::Reconnecting => IconColor::Yellow,
        Conn::Offline | Conn::DaemonDown => IconColor::Grey,
    }
}

pub const ICON_SIZE: u32 = 32;

/// RGBA-круг `ICON_SIZE`×`ICON_SIZE` со сглаженным краем и тёмной обводкой.
pub fn icon_rgba(color: IconColor) -> Vec<u8> {
    let n = ICON_SIZE as usize;
    let [r, g, b] = color.rgb();
    let c = (n as f32 - 1.0) / 2.0;
    let radius = n as f32 / 2.0 - 1.0;
    let mut px = Vec::with_capacity(n * n * 4);
    for y in 0..n {
        for x in 0..n {
            let d = ((x as f32 - c).powi(2) + (y as f32 - c).powi(2)).sqrt();
            let alpha = (radius + 0.5 - d).clamp(0.0, 1.0);
            // обводка 2 px темнее основного цвета
            let k = if d > radius - 2.0 { 0.65 } else { 1.0 };
            px.extend_from_slice(&[
                (r as f32 * k) as u8,
                (g as f32 * k) as u8,
                (b as f32 * k) as u8,
                (alpha * 255.0) as u8,
            ]);
        }
    }
    px
}

/// Когда показывать уведомления.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NotifyMode {
    Always,
    /// Только когда TUI закрыт (иначе дублирует окно приглашения в TUI).
    #[default]
    WhenTuiClosed,
}

/// Через сколько без связи сообщать «Нет связи».
pub const DISCONNECT_NOTIFY_AFTER: Duration = Duration::from_secs(30);

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Notice {
    Invite {
        gid: u32,
        group_name: String,
        from: String,
    },
    /// Группа пропала без нашего выхода: исключили или удалили.
    /// Источник — только `TrayState::kicked` (события демона), не разница снимков.
    Kicked {
        gid: u32,
        group_name: String,
    },
    Disconnected,
    /// Ответ на своё действие из трея (`Ack` с ошибкой) и т.п. — показывается
    /// при любом `NotifyMode`: в TUI об этом никто не скажет.
    Error(String),
}

impl Notice {
    /// Заголовок и текст toast.
    pub fn text(&self) -> (String, String) {
        match self {
            Notice::Invite {
                group_name, from, ..
            } => (
                "Приглашение в группу".into(),
                format!("{from} приглашает в «{group_name}»"),
            ),
            Notice::Kicked { group_name, .. } => (
                "Группа недоступна".into(),
                format!("Вы больше не в группе «{group_name}»"),
            ),
            Notice::Disconnected => (
                "Нет связи".into(),
                "Tunnel не на связи больше 30 секунд".into(),
            ),
            Notice::Error(text) => ("Tunnel: ошибка".into(), text.clone()),
        }
    }
}

/// Сравнивает соседние снимки и решает, о чём уведомить.
#[derive(Debug, Default)]
pub struct Notifier {
    pub mode: NotifyMode,
    /// Ещё не было ни одного снимка с живым демоном.
    first: bool,
    seen_invites: HashSet<u32>,
    /// С какого момента нет связи (только после того, как она была).
    down_since: Option<Instant>,
    was_connected: bool,
    down_notified: bool,
}

impl Notifier {
    pub fn new(mode: NotifyMode) -> Self {
        Self {
            mode,
            first: true,
            ..Default::default()
        }
    }

    /// Отметить своё действие (вызывать при клике до `act`/локального выполнения).
    pub fn on_action(&mut self, a: Action) {
        match a {
            // Остановку пользователь запросил сам — обрыв после неё не «Нет связи».
            Action::StopTunnel | Action::Exit => {
                self.was_connected = false;
                self.down_since = None;
                self.down_notified = false;
            }
            _ => {}
        }
    }

    /// Новый снимок → уведомления, прошедшие политику `mode`.
    pub fn observe(&mut self, s: &TrayState, now: Instant) -> Vec<Notice> {
        let mut out = Vec::new();
        // Приглашения: новые gid (на первом живом снимке — молча запоминаем).
        // Без демона список пуст не по-настоящему — не сверяем и базу не
        // ставим, иначе после старта/возврата службы старые приглашения
        // всплывут как новые.
        if s.conn != Conn::DaemonDown {
            let first = std::mem::replace(&mut self.first, false);
            if !first {
                for i in &s.invites {
                    if !self.seen_invites.contains(&i.gid) {
                        out.push(Notice::Invite {
                            gid: i.gid,
                            group_name: i.group_name.clone(),
                            from: i.from.clone(),
                        });
                    }
                }
            }
            self.seen_invites = s.invites.iter().map(|i| i.gid).collect();
        }

        // Исключение/удаление группы — только по событиям демона: по разнице
        // снимков нельзя отличить kick от своего выхода через CLI/TUI.
        for k in &s.kicked {
            out.push(Notice::Kicked {
                gid: k.gid,
                group_name: k.group_name.clone(),
            });
        }

        // Обрыв > 30 с: один раз за эпизод, только если связь была.
        if s.conn == Conn::Connected {
            self.was_connected = true;
            self.down_since = None;
            self.down_notified = false;
        } else if self.was_connected {
            let since = *self.down_since.get_or_insert(now);
            if !self.down_notified && now.duration_since(since) >= DISCONNECT_NOTIFY_AFTER {
                self.down_notified = true;
                out.push(Notice::Disconnected);
            }
        }

        if !should_show(self.mode, s.tui_open) {
            out.clear();
        }
        // Ошибки своих действий — мимо политики.
        out.extend(s.errors.iter().map(|e| Notice::Error(e.clone())));
        out
    }
}

pub fn should_show(mode: NotifyMode, tui_open: bool) -> bool {
    match mode {
        NotifyMode::Always => true,
        NotifyMode::WhenTuiClosed => !tui_open,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st() -> TrayState {
        TrayState {
            conn: Conn::Connected,
            my_ips: vec!["10.1.0.5".into(), "10.2.0.7".into()],
            server_label: Some("home".into()),
            my_code: Some("ABCD-EFGH".into()),
            groups: vec![
                TrayGroup {
                    gid: 1,
                    name: "дом".into(),
                    joined: true,
                },
                TrayGroup {
                    gid: 2,
                    name: "работа".into(),
                    joined: false,
                },
            ],
            invites: vec![TrayInvite {
                gid: 7,
                group_name: "игры".into(),
                from: "петя".into(),
            }],
            kicked: Vec::new(),
            errors: Vec::new(),
            tui_open: false,
        }
    }

    fn find<'a>(m: &'a [MenuEntry], pred: &dyn Fn(&MenuEntry) -> bool) -> Option<&'a MenuEntry> {
        for e in m {
            if pred(e) {
                return Some(e);
            }
            if let MenuEntry::Submenu { items, .. } = e
                && let Some(x) = find(items, pred)
            {
                return Some(x);
            }
        }
        None
    }

    fn by_action(m: &[MenuEntry], a: Action) -> Option<&MenuEntry> {
        find(
            m,
            &|e| matches!(e, MenuEntry::Item { action, .. } | MenuEntry::Check { action, .. } if *action == a),
        )
    }

    #[test]
    fn action_id_roundtrip() {
        let all = [
            Action::OpenTui,
            Action::CopyIp,
            Action::CopyCode,
            Action::ToggleGroup {
                gid: 42,
                join: true,
            },
            Action::ToggleGroup {
                gid: u32::MAX,
                join: false,
            },
            Action::AcceptInvite(3),
            Action::DeclineInvite(0),
            Action::StopTunnel,
            Action::Exit,
        ];
        for a in all {
            assert_eq!(Action::from_id(&a.to_id()), Some(a), "{a:?}");
        }
        for bad in [
            "",
            "group:1",
            "group:x:1",
            "group:1:2",
            "accept:",
            "zzz:1",
            "accept:-1",
        ] {
            assert_eq!(Action::from_id(bad), None, "{bad}");
        }
        assert!(Action::Exit.is_local() && Action::StopTunnel.is_local());
        assert!(!Action::AcceptInvite(1).is_local());
    }

    #[test]
    fn menu_groups_checks_and_toggle_direction() {
        let m = build_menu(&st());
        match by_action(
            &m,
            Action::ToggleGroup {
                gid: 1,
                join: false,
            },
        )
        .unwrap()
        {
            MenuEntry::Check {
                checked,
                enabled,
                label,
                ..
            } => {
                assert!(*checked && *enabled);
                assert_eq!(label, "дом");
            }
            e => panic!("{e:?}"),
        }
        match by_action(&m, Action::ToggleGroup { gid: 2, join: true }).unwrap() {
            MenuEntry::Check { checked, .. } => assert!(!checked),
            e => panic!("{e:?}"),
        }
    }

    #[test]
    fn menu_invites_submenu() {
        let m = build_menu(&st());
        let sub = find(
            &m,
            &|e| matches!(e, MenuEntry::Submenu { label, .. } if label == "Приглашения (1)"),
        )
        .unwrap();
        let MenuEntry::Submenu { enabled, items, .. } = sub else {
            unreachable!()
        };
        assert!(*enabled);
        assert_eq!(items.len(), 1);
        assert!(by_action(items, Action::AcceptInvite(7)).is_some());
        assert!(by_action(items, Action::DeclineInvite(7)).is_some());

        let mut s = st();
        s.invites.clear();
        let m = build_menu(&s);
        assert!(find(&m, &|e| matches!(e, MenuEntry::Submenu { label, enabled: false, .. } if label == "Приглашения (0)")).is_some());
    }

    #[test]
    fn menu_fixed_items_and_enabling() {
        let m = build_menu(&st());
        for a in [
            Action::OpenTui,
            Action::CopyIp,
            Action::CopyCode,
            Action::StopTunnel,
            Action::Exit,
        ] {
            assert!(
                matches!(
                    by_action(&m, a),
                    Some(MenuEntry::Item { enabled: true, .. })
                ),
                "{a:?}"
            );
        }
        assert!(
            matches!(by_action(&m, Action::CopyIp), Some(MenuEntry::Item { label, .. }) if label.contains("10.1.0.5"))
        );
        assert!(matches!(
            m.last(),
            Some(MenuEntry::Item {
                action: Action::Exit,
                ..
            })
        ));

        // Служба недоступна: «Открыть» и «Выход» живы, остальное серое.
        let s = TrayState {
            groups: st().groups,
            ..Default::default()
        };
        let m = build_menu(&s);
        assert!(matches!(
            by_action(&m, Action::OpenTui),
            Some(MenuEntry::Item { enabled: true, .. })
        ));
        assert!(matches!(
            by_action(&m, Action::Exit),
            Some(MenuEntry::Item { enabled: true, .. })
        ));
        for a in [Action::CopyIp, Action::CopyCode, Action::StopTunnel] {
            assert!(
                matches!(
                    by_action(&m, a),
                    Some(MenuEntry::Item { enabled: false, .. })
                ),
                "{a:?}"
            );
        }
        assert!(matches!(
            by_action(
                &m,
                Action::ToggleGroup {
                    gid: 1,
                    join: false
                }
            ),
            Some(MenuEntry::Check { enabled: false, .. })
        ));
        assert!(matches!(&m[0], MenuEntry::Label(t) if t.contains("служба недоступна")));
        assert!(
            find(
                &build_menu(&TrayState::default()),
                &|e| matches!(e, MenuEntry::Label(t) if t == "Групп нет")
            )
            .is_some()
        );
    }

    #[test]
    fn tooltip_text_and_limit() {
        let t = tooltip(&st());
        assert_eq!(t, "Tunnel — подключён\nIP: 10.1.0.5 (+1)\nСервер: home");
        assert_eq!(tooltip(&TrayState::default()), "Tunnel — служба недоступна");
        let s = TrayState {
            server_label: Some("я".repeat(300)),
            ..st()
        };
        let t = tooltip(&s);
        assert!(t.encode_utf16().count() <= TOOLTIP_MAX);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn icon_colors_and_pixels() {
        assert_eq!(icon_color(Conn::Connected), IconColor::Green);
        assert_eq!(icon_color(Conn::Reconnecting), IconColor::Yellow);
        assert_eq!(icon_color(Conn::Offline), IconColor::Grey);
        assert_eq!(icon_color(Conn::DaemonDown), IconColor::Grey);
        let px = icon_rgba(IconColor::Green);
        assert_eq!(px.len(), (ICON_SIZE * ICON_SIZE * 4) as usize);
        let at = |x: usize, y: usize| &px[(y * ICON_SIZE as usize + x) * 4..][..4];
        assert_eq!(at(0, 0)[3], 0, "угол прозрачный");
        assert_eq!(at(16, 16), &[0x2e, 0xcc, 0x71, 255], "центр — цвет");
        assert_ne!(icon_rgba(IconColor::Yellow), icon_rgba(IconColor::Grey));
    }

    #[test]
    fn notify_invites_only_new_and_not_on_first_snapshot() {
        let t0 = Instant::now();
        let mut n = Notifier::new(NotifyMode::Always);
        assert!(
            n.observe(&st(), t0).is_empty(),
            "стартовые приглашения молча"
        );
        let mut s = st();
        s.invites.push(TrayInvite {
            gid: 8,
            group_name: "кино".into(),
            from: "оля".into(),
        });
        assert_eq!(
            n.observe(&s, t0),
            vec![Notice::Invite {
                gid: 8,
                group_name: "кино".into(),
                from: "оля".into()
            }]
        );
        assert!(n.observe(&s, t0).is_empty(), "повтор не уведомляет");
        let (title, body) = Notice::Invite {
            gid: 8,
            group_name: "кино".into(),
            from: "оля".into(),
        }
        .text();
        assert!(title.contains("Приглашение") && body.contains("кино") && body.contains("оля"));
    }

    #[test]
    fn notify_kicked_only_from_daemon_events() {
        let t0 = Instant::now();
        let mut n = Notifier::new(NotifyMode::Always);
        n.observe(&st(), t0);

        // Группа пропала из снимка (свой выход через CLI/TUI) — молча.
        let mut s = st();
        s.groups.remove(0);
        assert!(n.observe(&s, t0).is_empty());

        // Событие демона — уведомляем.
        s.kicked.push(TrayKick {
            gid: 2,
            group_name: "работа".into(),
        });
        assert_eq!(
            n.observe(&s, t0),
            vec![Notice::Kicked {
                gid: 2,
                group_name: "работа".into()
            }]
        );
    }

    #[test]
    fn notify_no_disconnect_after_own_stop() {
        let t0 = Instant::now();
        let mut n = Notifier::new(NotifyMode::Always);
        n.observe(&st(), t0);
        n.on_action(Action::StopTunnel);
        let down = TrayState {
            conn: Conn::DaemonDown,
            ..Default::default()
        };
        assert!(n.observe(&down, t0).is_empty());
        assert!(n.observe(&down, t0 + Duration::from_secs(31)).is_empty());
        assert!(n.observe(&down, t0 + Duration::from_secs(120)).is_empty());
    }

    #[test]
    fn notify_no_old_invites_when_daemon_starts_later() {
        let t0 = Instant::now();
        let mut n = Notifier::new(NotifyMode::Always);
        let down = TrayState {
            conn: Conn::DaemonDown,
            ..Default::default()
        };
        assert!(n.observe(&down, t0).is_empty());
        assert!(
            n.observe(&st(), t0).is_empty(),
            "первый живой снимок — база"
        );
        let mut s = st();
        s.invites.push(TrayInvite {
            gid: 8,
            group_name: "кино".into(),
            from: "оля".into(),
        });
        assert_eq!(n.observe(&s, t0).len(), 1);
    }

    #[test]
    fn notify_disconnect_after_30s_once() {
        let t0 = Instant::now();
        let mut n = Notifier::new(NotifyMode::Always);
        // Без связи с самого старта — не уведомляем.
        let off = TrayState {
            conn: Conn::Offline,
            ..st()
        };
        assert!(n.observe(&off, t0).is_empty());
        assert!(n.observe(&off, t0 + Duration::from_secs(60)).is_empty());

        n.observe(&st(), t0 + Duration::from_secs(61));
        let rec = TrayState {
            conn: Conn::Reconnecting,
            ..st()
        };
        let base = t0 + Duration::from_secs(62);
        assert!(n.observe(&rec, base).is_empty());
        assert!(n.observe(&rec, base + Duration::from_secs(29)).is_empty());
        assert_eq!(
            n.observe(&rec, base + Duration::from_secs(30)),
            vec![Notice::Disconnected]
        );
        assert!(
            n.observe(&rec, base + Duration::from_secs(90)).is_empty(),
            "один раз за эпизод"
        );

        // Связь вернулась и снова пропала — новый эпизод.
        n.observe(&st(), base + Duration::from_secs(100));
        let b2 = base + Duration::from_secs(101);
        assert!(n.observe(&rec, b2).is_empty());
        assert_eq!(
            n.observe(&rec, b2 + Duration::from_secs(31)),
            vec![Notice::Disconnected]
        );
    }

    #[test]
    fn notify_mode_when_tui_closed() {
        assert!(should_show(NotifyMode::Always, true));
        assert!(should_show(NotifyMode::WhenTuiClosed, false));
        assert!(!should_show(NotifyMode::WhenTuiClosed, true));
        assert_eq!(NotifyMode::default(), NotifyMode::WhenTuiClosed);

        let t0 = Instant::now();
        let mut n = Notifier::new(NotifyMode::WhenTuiClosed);
        n.observe(&st(), t0);
        let mut s = st();
        s.tui_open = true;
        s.invites.push(TrayInvite {
            gid: 9,
            group_name: "x".into(),
            from: "y".into(),
        });
        assert!(n.observe(&s, t0).is_empty(), "TUI открыт — молчим");
        // Уже увиденное при открытом TUI не всплывает после закрытия.
        s.tui_open = false;
        assert!(n.observe(&s, t0).is_empty());
    }

    #[test]
    fn notify_errors_bypass_mode() {
        let t0 = Instant::now();
        let mut n = Notifier::new(NotifyMode::WhenTuiClosed);
        let mut s = st();
        s.tui_open = true;
        s.errors.push("нет сервера".into());
        assert_eq!(n.observe(&s, t0), vec![Notice::Error("нет сервера".into())]);
        let down = TrayState {
            errors: vec!["служба недоступна".into()],
            ..Default::default()
        };
        assert_eq!(n.observe(&down, t0).len(), 1);
        assert_eq!(Notice::Error("x".into()).text().1, "x");
    }
}
