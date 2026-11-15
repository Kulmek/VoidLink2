//! Состояние TUI: фокус, списки, попапы, тосты, лог, обработка клавиш.

use std::collections::HashSet;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use tunnel_protocol as proto;

use crate::engine::{Cmd, Engine};
use crate::store::{self, Config, StoredFriend, StoredServer};
use crate::tui::theme::ThemeKind;

pub const TOAST_TTL: Duration = Duration::from_secs(5);
pub const LOG_MAX: usize = 400;

// ---------------------------------------------------------------- фокус

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Focus {
    Groups,
    Friends,
    Peers,
    Log,
}

impl Focus {
    pub fn next(self) -> Self {
        match self {
            Focus::Groups => Focus::Friends,
            Focus::Friends => Focus::Peers,
            Focus::Peers => Focus::Log,
            Focus::Log => Focus::Groups,
        }
    }
    pub fn prev(self) -> Self {
        match self {
            Focus::Groups => Focus::Log,
            Focus::Friends => Focus::Groups,
            Focus::Peers => Focus::Friends,
            Focus::Log => Focus::Peers,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Focus::Groups => "группы",
            Focus::Friends => "друзья",
            Focus::Peers => "участники",
            Focus::Log => "лог",
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Sort {
    Name,
    Online,
    Rtt,
}

impl Sort {
    pub fn next(self) -> Self {
        match self {
            Sort::Name => Sort::Online,
            Sort::Online => Sort::Rtt,
            Sort::Rtt => Sort::Name,
        }
    }
    pub fn label(self) -> &'static str {
        match self {
            Sort::Name => "имя",
            Sort::Online => "онлайн",
            Sort::Rtt => "RTT",
        }
    }
}

// ---------------------------------------------------------------- модели

#[derive(Clone)]
pub struct PeerView {
    pub pubkey: [u8; 32],
    pub name: String,
    pub ip: u32,
    pub online: bool,
    pub direct: bool,
    pub rtt_ms: Option<u64>,
    pub status: String,
}

#[derive(Clone)]
pub struct GroupView {
    pub gid: u32,
    pub name: String,
    pub private: bool,
    pub mine: bool,
    pub online: u32,
    pub total: u32,
    pub my_ip: Option<u32>,
    pub owner_is_me: bool,
    pub peers: Vec<PeerView>,
}

#[derive(Clone)]
pub struct FriendView {
    pub alias: String,
    pub pubkey: [u8; 32],
    pub online: bool,
    pub shared_groups: usize,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum MsgKind {
    Info,
    Ok,
    Warn,
    Error,
}

pub struct Toast {
    pub text: String,
    pub kind: MsgKind,
    pub at: Instant,
}

pub struct LogLine {
    pub text: String,
    pub kind: MsgKind,
    pub at: Instant,
}

// ---------------------------------------------------------------- попапы

pub enum InputAction {
    CreateGroup,
    RenameGroup(u32),
    AddFriend,
    SetName,
    SetStatus,
    InviteCode(u32),
    /// Командная строка «:».
    Command,
}

pub struct InputPopup {
    pub title: String,
    pub hint: String,
    pub value: String,
    pub action: InputAction,
    /// Для создания группы: флаг «приватная».
    pub private: bool,
}

pub enum ConfirmAction {
    DeleteGroup(u32),
    LeaveGroup(u32),
    DeleteFriend(String),
}

pub struct ConfirmPopup {
    pub title: String,
    pub message: String,
    pub action: ConfirmAction,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum PickMode {
    Invite,
    Kick,
    Ban,
}

#[derive(Clone)]
pub struct PeerChoice {
    pub pubkey: [u8; 32],
    pub label: String,
    pub sub: String,
    pub online: bool,
}

pub struct PeerPickPopup {
    pub gid: u32,
    pub title: String,
    pub mode: PickMode,
    pub items: Vec<PeerChoice>,
    pub sel: usize,
}

pub struct FriendCardPopup {
    pub alias: String,
    pub pubkey: [u8; 32],
    pub groups: Vec<proto::payloads::FriendGroup>,
    pub loading: bool,
}

pub struct ListItem {
    pub label: String,
    pub checked: bool,
    pub value: String,
}

pub enum ListAction {
    PickServer,
    ToggleAutojoin,
}

pub struct ListPickPopup {
    pub title: String,
    pub items: Vec<ListItem>,
    pub sel: usize,
    pub action: ListAction,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum SettingRow {
    Name,
    Status,
    Server,
    Autojoin,
    Theme,
}

pub const SETTING_ROWS: [SettingRow; 5] = [
    SettingRow::Name,
    SettingRow::Status,
    SettingRow::Server,
    SettingRow::Autojoin,
    SettingRow::Theme,
];

pub struct SettingsPopup {
    pub sel: usize,
}

pub enum Popup {
    Help,
    Input(InputPopup),
    Confirm(ConfirmPopup),
    PeerPick(PeerPickPopup),
    FriendCard(FriendCardPopup),
    ListPick(ListPickPopup),
    Settings(SettingsPopup),
    Profile,
}

// ---------------------------------------------------------------- приложение

pub struct App {
    pub focus: Focus,
    pub sel_group: Option<u32>,
    pub sel_friend: Option<[u8; 32]>,
    pub sel_peer: Option<[u8; 32]>,
    pub filter: String,
    /// Режим фильтрации (ввод идёт в строку фильтра).
    pub filtering: bool,
    pub sort: Sort,
    pub stack: Vec<Popup>,
    pub toasts: Vec<Toast>,
    pub log: Vec<LogLine>,
    pub groups: Vec<GroupView>,
    pub friends: Vec<FriendView>,
    pub peers: Vec<PeerView>,
    /// История скорости трафика (байт/с) для спарклайна.
    pub rx_hist: Vec<u64>,
    pub tx_hist: Vec<u64>,
    /// Момент старта TUI (для «время в сети»).
    pub started: Instant,
    pub my_pub: [u8; 32],
    pub my_code: String,
    pub my_name: String,
    pub my_status: String,
    pub servers: Vec<StoredServer>,
    pub autojoin: Vec<u32>,
    pub theme_kind: ThemeKind,
    /// Состояние соединения с сервером.
    pub connected: bool,
    pub server_addr: String,
    pub server_label: String,
    /// Накопленные счётчики трафика.
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub rx_pkts: u64,
    pub tx_pkts: u64,
    pub status_msg: String,
    pub log_scroll: usize,
    pub quit: bool,
}

impl App {
    pub fn new(my_pub: [u8; 32], my_code: &str, cfg: &Config) -> Self {
        let theme_kind = ThemeKind::from_str(&cfg.theme).unwrap_or(ThemeKind::Dark);
        Self {
            focus: Focus::Groups,
            sel_group: None,
            sel_friend: None,
            sel_peer: None,
            filter: String::new(),
            filtering: false,
            sort: Sort::Name,
            stack: Vec::new(),
            toasts: Vec::new(),
            log: Vec::new(),
            groups: Vec::new(),
            friends: Vec::new(),
            peers: Vec::new(),
            rx_hist: Vec::new(),
            tx_hist: Vec::new(),
            started: Instant::now(),
            my_pub,
            my_code: my_code.to_string(),
            my_name: cfg.name.clone(),
            my_status: cfg.status.clone(),
            servers: cfg.servers.clone(),
            autojoin: cfg.autojoin.clone(),
            theme_kind,
            connected: false,
            server_addr: String::new(),
            server_label: String::new(),
            rx_bytes: 0,
            tx_bytes: 0,
            rx_pkts: 0,
            tx_pkts: 0,
            status_msg: String::new(),
            log_scroll: 0,
            quit: false,
        }
    }

    // ---------- синхронизация с движком ----------

    /// Забирает свежее состояние движка, события, чистит тосты.
    pub fn sync(&mut self, eng: &Engine) {
        self.drain_events(eng);

        {
            let meta = eng.meta.lock().unwrap();
            self.rx_hist = meta.rx_hist.iter().copied().collect();
            self.tx_hist = meta.tx_hist.iter().copied().collect();
            self.connected = meta.connected;
            self.server_addr = meta.server.to_string();
            self.server_label = meta.server_label.clone();
            self.started = meta.started;
        }
        {
            let st = &eng.stats;
            self.rx_bytes = st.rx_bytes.load(std::sync::atomic::Ordering::Relaxed);
            self.tx_bytes = st.tx_bytes.load(std::sync::atomic::Ordering::Relaxed);
            self.rx_pkts = st.rx_pkts.load(std::sync::atomic::Ordering::Relaxed);
            self.tx_pkts = st.tx_pkts.load(std::sync::atomic::Ordering::Relaxed);
        }

        let mut groups: Vec<GroupView> = Vec::new();
        {
            let live = eng.groups.lock().unwrap();
            for (gid, gs) in live.iter() {
                let mut peers: Vec<PeerView> = gs
                    .members
                    .values()
                    .map(|p| PeerView {
                        pubkey: p.pubkey,
                        name: p.name.clone(),
                        ip: p.ip,
                        online: p.online,
                        direct: p.direct,
                        rtt_ms: p.rtt_ms,
                        status: p.status.clone(),
                    })
                    .collect();
                peers.sort_by(|a, b| a.name.cmp(&b.name));
                let online = peers.iter().filter(|p| p.online).count() as u32 + 1;
                groups.push(GroupView {
                    gid: *gid,
                    name: gs.name.clone(),
                    private: gs.private,
                    mine: true,
                    online,
                    total: peers.len() as u32 + 1,
                    my_ip: Some(gs.my_ip),
                    owner_is_me: gs.owner == self.my_pub,
                    peers,
                });
            }
        }
        {
            let meta = eng.meta.lock().unwrap();
            for s in meta.group_list.iter() {
                if !groups.iter().any(|g| g.gid == s.gid) {
                    groups.push(GroupView {
                        gid: s.gid,
                        name: s.name.clone(),
                        private: s.private,
                        mine: s.mine,
                        online: s.online,
                        total: s.total,
                        my_ip: None,
                        owner_is_me: false,
                        peers: Vec::new(),
                    });
                }
            }
        }
        groups.sort_by(|a, b| {
            b.mine
                .cmp(&a.mine)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
                .then_with(|| a.gid.cmp(&b.gid))
        });
        self.groups = groups;

        {
            let live = eng.groups.lock().unwrap();
            let known: HashSet<[u8; 32]> = live
                .values()
                .flat_map(|g| g.members.values().map(|p| p.pubkey))
                .collect();
            let cfg = eng.cfg.lock().unwrap();
            let mut friends: Vec<FriendView> = Vec::new();
            for f in cfg.friends.iter() {
                let pk = hex32(&f.pubkey).unwrap_or([0; 32]);
                let shared = live
                    .values()
                    .filter(|g| g.members.values().any(|p| p.pubkey == pk))
                    .count();
                friends.push(FriendView {
                    alias: f.alias.clone(),
                    pubkey: pk,
                    online: known.contains(&pk),
                    shared_groups: shared,
                });
            }
            friends.sort_by(|a, b| a.alias.to_lowercase().cmp(&b.alias.to_lowercase()));
            self.friends = friends;
            self.my_name = cfg.name.clone();
            self.my_status = cfg.status.clone();
            self.servers = cfg.servers.clone();
            self.autojoin = cfg.autojoin.clone();
            self.theme_kind = ThemeKind::from_str(&cfg.theme).unwrap_or(ThemeKind::Dark);
        }

        // Выбор группы: держим актуальный gid, иначе — первая своя.
        let group_gone = match self.sel_group {
            Some(g) => self.groups.iter().all(|x| x.gid != g),
            None => true,
        };
        if group_gone {
            self.sel_group = self
                .groups
                .iter()
                .find(|g| g.mine)
                .or_else(|| self.groups.first())
                .map(|g| g.gid);
        }
        // Выбор друга.
        let friend_gone = match self.sel_friend {
            Some(f) => self.friends.iter().all(|x| x.pubkey != f),
            None => true,
        };
        if friend_gone {
            self.sel_friend = self.friends.first().map(|f| f.pubkey);
        }

        // Участники выбранной группы + сортировка.
        self.peers = match self
            .sel_group
            .and_then(|g| self.groups.iter().find(|x| x.gid == g))
        {
            Some(g) => {
                let mut peers = g.peers.clone();
                match self.sort {
                    Sort::Name => peers.sort_by(|a, b| a.name.cmp(&b.name)),
                    Sort::Online => peers
                        .sort_by(|a, b| b.online.cmp(&a.online).then_with(|| a.name.cmp(&b.name))),
                    Sort::Rtt => peers.sort_by(|a, b| {
                        let ra = a.rtt_ms.unwrap_or(u64::MAX);
                        let rb = b.rtt_ms.unwrap_or(u64::MAX);
                        ra.cmp(&rb).then_with(|| a.name.cmp(&b.name))
                    }),
                }
                peers
            }
            None => Vec::new(),
        };
        let peer_gone = match self.sel_peer {
            Some(p) => self.peers.iter().all(|x| x.pubkey != p),
            None => true,
        };
        if peer_gone {
            self.sel_peer = self.peers.first().map(|p| p.pubkey);
        }

        self.expire_toasts();
    }

    fn drain_events(&mut self, eng: &Engine) {
        use crate::engine::Event as E;
        loop {
            let ev = match eng.events.try_recv() {
                Ok(e) => e,
                Err(_) => break,
            };
            match ev {
                E::Connected(s) => {
                    self.log(MsgKind::Ok, format!("подключено к {s}"));
                }
                E::Disconnected(r) => {
                    self.log(MsgKind::Error, format!("{r}; переподключение…"));
                    self.toast(MsgKind::Error, r);
                }
                E::GroupJoined { gid, name, my_ip } => {
                    let msg = format!(
                        "вошли в группу {gid} «{name}» (мой IP {})",
                        proto::ip_str(my_ip)
                    );
                    self.log(MsgKind::Ok, msg.clone());
                    self.toast(MsgKind::Ok, msg);
                }
                E::GroupLeft { gid, name } => {
                    let msg = format!("вышли из группы {gid} «{name}»");
                    self.log(MsgKind::Info, msg.clone());
                    self.toast(MsgKind::Info, msg);
                }
                E::GroupDeleted { gid, name } => {
                    let msg = format!("группа {gid} «{name}» удалена");
                    self.log(MsgKind::Warn, msg.clone());
                    self.toast(MsgKind::Warn, msg);
                }
                E::Kicked { gid, name } => {
                    let msg = format!("вас исключили из группы {gid} «{name}»");
                    self.log(MsgKind::Error, msg.clone());
                    self.toast(MsgKind::Error, msg);
                }
                E::PeerOnline { gid, ip, name } => {
                    self.log(
                        MsgKind::Ok,
                        format!("{name} ({}) онлайн в {gid}", proto::ip_str(ip)),
                    );
                }
                E::PeerOffline { gid, ip, name } => {
                    self.log(
                        MsgKind::Info,
                        format!("{name} ({}) офлайн в {gid}", proto::ip_str(ip)),
                    );
                }
                E::Direct { gid, ip, name } => {
                    let msg = format!(
                        "прямой канал с {name} ({}) в {gid}",
                        proto::ip_str(ip)
                    );
                    self.log(MsgKind::Ok, msg.clone());
                    self.toast(MsgKind::Ok, msg);
                }
                E::Invite { gid, group_name, from_name } => {
                    let msg = format!("приглашение в «{group_name}» ({gid}) от {from_name}");
                    self.log(MsgKind::Warn, msg.clone());
                    self.toast(MsgKind::Warn, msg);
                }
                E::FriendGroups { pubkey, items } => {
                    let alias = self
                        .friends
                        .iter()
                        .find(|f| f.pubkey == pubkey)
                        .map(|f| f.alias.clone())
                        .unwrap_or_else(|| proto::hex_of(&pubkey));
                    let mut updated = false;
                    if let Some(Popup::FriendCard(card)) = self.stack.last_mut() {
                        if card.pubkey == pubkey {
                            card.groups = items.clone();
                            card.loading = false;
                            updated = true;
                        }
                    }
                    if !updated {
                        self.stack.push(Popup::FriendCard(FriendCardPopup {
                            alias,
                            pubkey,
                            groups: items,
                            loading: false,
                        }));
                    }
                }
                E::Error(e) => {
                    self.log(MsgKind::Error, e.clone());
                    self.toast(MsgKind::Error, e);
                }
                E::Notice(n) => {
                    self.log(MsgKind::Info, n);
                }
            }
        }
    }

    pub fn expire_toasts(&mut self) {
        let now = Instant::now();
        self.toasts.retain(|t| now.duration_since(t.at) < TOAST_TTL);
    }

    pub fn toast(&mut self, kind: MsgKind, text: String) {
        self.toasts.push(Toast {
            text,
            kind,
            at: Instant::now(),
        });
        if self.toasts.len() > 5 {
            self.toasts.remove(0);
        }
    }

    pub fn log(&mut self, kind: MsgKind, text: String) {
        self.log.push(LogLine {
            text,
            kind,
            at: Instant::now(),
        });
        if self.log.len() > LOG_MAX {
            self.log.remove(0);
        }
    }

    // ---------- выборки ----------

    pub fn visible_groups(&self) -> Vec<&GroupView> {
        let f = self.filter.to_lowercase();
        self.groups
            .iter()
            .filter(|g| f.is_empty() || g.name.to_lowercase().contains(&f) || g.gid.to_string() == f)
            .collect()
    }

    pub fn visible_friends(&self) -> Vec<&FriendView> {
        let f = self.filter.to_lowercase();
        self.friends
            .iter()
            .filter(|x| f.is_empty() || x.alias.to_lowercase().contains(&f))
            .collect()
    }

    pub fn visible_peers(&self) -> Vec<&PeerView> {
        let f = self.filter.to_lowercase();
        self.peers
            .iter()
            .filter(|p| f.is_empty() || p.name.to_lowercase().contains(&f))
            .collect()
    }

    pub fn selected_group(&self) -> Option<&GroupView> {
        self.sel_group.and_then(|g| self.groups.iter().find(|x| x.gid == g))
    }

    pub fn selected_friend(&self) -> Option<&FriendView> {
        self.sel_friend.and_then(|f| self.friends.iter().find(|x| x.pubkey == f))
    }

    pub fn selected_peer(&self) -> Option<&PeerView> {
        self.sel_peer.and_then(|p| self.peers.iter().find(|x| x.pubkey == p))
    }

    // ---------- клавиши ----------

    pub fn handle_key(&mut self, key: KeyEvent, eng: &Engine) {
        if !self.stack.is_empty() {
            self.handle_popup_key(key, eng);
            return;
        }
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.quit = true;
            let _ = eng.cmds.send(Cmd::Quit);
            return;
        }
        if self.filtering {
            self.handle_filter_key(key);
            return;
        }
        match key.code {
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.prev(),
            KeyCode::F(1) => self.stack.push(Popup::Help),
            KeyCode::F(2) => self.open_create_group(),
            KeyCode::F(3) | KeyCode::F(10) => {
                self.stack.push(Popup::Settings(SettingsPopup { sel: 0 }))
            }
            KeyCode::F(6) => self.open_rename(),
            KeyCode::F(8) => self.open_delete_group(),
            KeyCode::Char('?') => self.stack.push(Popup::Help),
            KeyCode::Char(':') => self.open_command(),
            KeyCode::Char('/') => {
                self.filtering = true;
            }
            KeyCode::Esc => {
                self.filter.clear();
                self.filtering = false;
                self.log_scroll = 0;
            }
            KeyCode::Up => self.move_sel(-1),
            KeyCode::Down => self.move_sel(1),
            KeyCode::PageUp => self.log_scroll = (self.log_scroll + 5).min(self.log.len()),
            KeyCode::PageDown => self.log_scroll = self.log_scroll.saturating_sub(5),
            KeyCode::Home => self.move_sel(-1000),
            KeyCode::End => self.move_sel(1000),
            KeyCode::Enter => self.activate(eng),
            KeyCode::Char('i') => self.open_pick(PickMode::Invite),
            KeyCode::Char('k') => self.open_pick(PickMode::Kick),
            KeyCode::Char('b') => self.open_pick(PickMode::Ban),
            KeyCode::Char('j') => self.join_selected(eng),
            KeyCode::Char('x') => self.open_leave_group(),
            KeyCode::Char('a') => self.open_add_friend(),
            KeyCode::Char('d') => self.open_del_friend(),
            KeyCode::Char('c') => self.copy_context(),
            KeyCode::Char('p') => self.stack.push(Popup::Profile),
            KeyCode::Char('s') => {
                self.sort = self.sort.next();
                self.status_msg = format!("сортировка: {}", self.sort.label());
            }
            KeyCode::Char('r') => {
                let _ = eng.cmds.send(Cmd::RefreshList);
                self.status_msg = "обновляем список групп".into();
            }
            KeyCode::Char(c) if !c.is_control() => {
                // Буквы вне режима фильтра — неизвестные команды.
                self.status_msg = format!("«{c}» — неизвестная команда; F1 — справка, / — поиск");
            }
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => {
                self.filter.clear();
                self.filtering = false;
            }
            KeyCode::Enter => self.filtering = false,
            KeyCode::Backspace => {
                self.filter.pop();
                if self.filter.is_empty() {
                    self.filtering = false;
                }
            }
            KeyCode::Tab => self.focus = self.focus.next(),
            KeyCode::BackTab => self.focus = self.focus.prev(),
            KeyCode::Up => self.move_sel(-1),
            KeyCode::Down => self.move_sel(1),
            KeyCode::Char(c) if !c.is_control() => self.filter.push(c),
            _ => {}
        }
    }

    fn move_sel(&mut self, delta: i32) {
        match self.focus {
            Focus::Groups => {
                let list = self.visible_groups();
                if list.is_empty() {
                    return;
                }
                let cur = list
                    .iter()
                    .position(|g| Some(g.gid) == self.sel_group)
                    .unwrap_or(0) as i32;
                let next = (cur + delta).rem_euclid(list.len() as i32) as usize;
                self.sel_group = Some(list[next].gid);
            }
            Focus::Friends => {
                let list = self.visible_friends();
                if list.is_empty() {
                    return;
                }
                let cur = list
                    .iter()
                    .position(|f| Some(f.pubkey) == self.sel_friend)
                    .unwrap_or(0) as i32;
                let next = (cur + delta).rem_euclid(list.len() as i32) as usize;
                self.sel_friend = Some(list[next].pubkey);
            }
            Focus::Peers => {
                let list = self.visible_peers();
                if list.is_empty() {
                    return;
                }
                let cur = list
                    .iter()
                    .position(|p| Some(p.pubkey) == self.sel_peer)
                    .unwrap_or(0) as i32;
                let next = (cur + delta).rem_euclid(list.len() as i32) as usize;
                self.sel_peer = Some(list[next].pubkey);
            }
            Focus::Log => {
                let max = self.log.len();
                if delta < 0 {
                    self.log_scroll = (self.log_scroll + (-delta) as usize).min(max);
                } else {
                    self.log_scroll = self.log_scroll.saturating_sub(delta as usize);
                }
            }
        }
    }

    fn activate(&mut self, eng: &Engine) {
        match self.focus {
            Focus::Friends => {
                if let Some(f) = self.selected_friend() {
                    let pk = f.pubkey;
                    let alias = f.alias.clone();
                    self.stack.push(Popup::FriendCard(FriendCardPopup {
                        alias,
                        pubkey: pk,
                        groups: Vec::new(),
                        loading: true,
                    }));
                    let _ = eng.cmds.send(Cmd::FriendGroups(pk));
                }
            }
            Focus::Groups => {
                if let Some(g) = self.selected_group() {
                    if !g.mine {
                        let gid = g.gid;
                        let _ = eng.cmds.send(Cmd::Join(gid));
                        self.toast(MsgKind::Info, format!("входим в группу {gid}"));
                    }
                }
            }
            Focus::Peers | Focus::Log => {}
        }
    }

    // ---------- попапы ----------

    fn handle_popup_key(&mut self, key: KeyEvent, eng: &Engine) {
        let popup = match self.stack.pop() {
            Some(p) => p,
            None => return,
        };
        match popup {
            Popup::Help => {
                if !matches!(key.code, KeyCode::Esc | KeyCode::Enter | KeyCode::F(1)) {
                    self.stack.push(Popup::Help);
                }
            }
            Popup::Input(inp) => self.input_key(inp, key, eng),
            Popup::Confirm(c) => match key.code {
                KeyCode::Char('y') | KeyCode::Char('Y') | KeyCode::Enter => {
                    self.confirm_action(c.action, eng)
                }
                _ => {}
            },
            Popup::PeerPick(mut p) => match key.code {
                KeyCode::Up => {
                    if !p.items.is_empty() {
                        p.sel = (p.sel + p.items.len() - 1) % p.items.len();
                    }
                    self.stack.push(Popup::PeerPick(p));
                }
                KeyCode::Down => {
                    if !p.items.is_empty() {
                        p.sel = (p.sel + 1) % p.items.len();
                    }
                    self.stack.push(Popup::PeerPick(p));
                }
                KeyCode::Enter => {
                    if let Some(item) = p.items.get(p.sel).cloned() {
                        if item.pubkey == [0; 32] {
                            // Ручной ввод friend code.
                            self.stack.push(Popup::Input(InputPopup {
                                title: format!("Пригласить в группу {}", p.gid),
                                hint: "friend code (TUN-…) · Enter — отправить".into(),
                                value: String::new(),
                                action: InputAction::InviteCode(p.gid),
                                private: false,
                            }));
                            return;
                        }
                        match p.mode {
                            PickMode::Invite => {
                                let _ = eng.cmds.send(Cmd::Invite(p.gid, item.pubkey));
                                self.toast(
                                    MsgKind::Ok,
                                    format!("приглашение отправлено: {}", item.label),
                                );
                            }
                            PickMode::Kick => {
                                let _ = eng.cmds.send(Cmd::Kick(p.gid, item.pubkey));
                                self.toast(MsgKind::Warn, format!("исключён: {}", item.label));
                            }
                            PickMode::Ban => {
                                let _ = eng.cmds.send(Cmd::Ban(p.gid, item.pubkey));
                                self.toast(MsgKind::Warn, format!("забанен: {}", item.label));
                            }
                        }
                    }
                }
                _ => {}
            },
            Popup::FriendCard(card) => match key.code {
                KeyCode::Char('c') => {
                    copy_to_clipboard(&proto::hex_of(&card.pubkey));
                    self.toast(MsgKind::Ok, "pubkey друга скопирован".into());
                    self.stack.push(Popup::FriendCard(card));
                }
                _ => {}
            },
            Popup::ListPick(mut p) => match key.code {
                KeyCode::Up => {
                    if !p.items.is_empty() {
                        p.sel = (p.sel + p.items.len() - 1) % p.items.len();
                    }
                    self.stack.push(Popup::ListPick(p));
                }
                KeyCode::Down => {
                    if !p.items.is_empty() {
                        p.sel = (p.sel + 1) % p.items.len();
                    }
                    self.stack.push(Popup::ListPick(p));
                }
                KeyCode::Enter => {
                    match p.action {
                        ListAction::PickServer => {
                            // Выбранный сервер становится первым в client.json:
                            // `run`/`tui` без --server берут первый. Раньше выбор
                            // только показывал тост и нигде не сохранялся.
                            let idx = p.items.get(p.sel).and_then(|i| i.value.parse::<usize>().ok());
                            let mut cfg = eng.cfg.lock().unwrap().clone();
                            match idx.filter(|i| *i < cfg.servers.len()) {
                                Some(i) => {
                                    let picked = cfg.servers.remove(i);
                                    let addr = picked.addr.clone();
                                    cfg.servers.insert(0, picked);
                                    match save_cfg(eng, cfg) {
                                        Ok(()) => {
                                            self.status_msg = format!("сервер: {addr}");
                                            self.toast(
                                                MsgKind::Ok,
                                                format!("сервер {addr} — применится после перезапуска"),
                                            );
                                        }
                                        Err(e) => self
                                            .toast(MsgKind::Error, format!("не сохранить сервер: {e}")),
                                    }
                                }
                                None => self.toast(MsgKind::Warn, "сервер не выбран".into()),
                            }
                        }
                        ListAction::ToggleAutojoin => {
                            // gid берём из выбранной строки: в действии лежит
                            // заглушка 0, из-за которой переключалась «группа 0».
                            let gid = p.items.get(p.sel).and_then(|i| i.value.parse::<u32>().ok());
                            if let Some(gid) = gid {
                                let _ = eng.cmds.send(Cmd::ToggleAutojoin(gid));
                                if let Some(item) = p.items.get_mut(p.sel) {
                                    item.checked = !item.checked;
                                }
                                // Список остаётся открытым: можно отметить несколько групп.
                                self.stack.push(Popup::ListPick(p));
                            }
                        }
                    }
                }
                _ => {}
            },
            Popup::Settings(mut s) => match key.code {
                KeyCode::Up => {
                    s.sel = (s.sel + SETTING_ROWS.len() - 1) % SETTING_ROWS.len();
                    self.stack.push(Popup::Settings(s));
                }
                KeyCode::Down => {
                    s.sel = (s.sel + 1) % SETTING_ROWS.len();
                    self.stack.push(Popup::Settings(s));
                }
                KeyCode::Enter => {
                    let row = SETTING_ROWS[s.sel];
                    self.stack.push(Popup::Settings(s));
                    self.open_setting(row, eng);
                }
                _ => {}
            },
            Popup::Profile => {
                if let KeyCode::Char('c') = key.code {
                    copy_to_clipboard(&self.my_code);
                    self.toast(MsgKind::Ok, "friend code скопирован".into());
                    self.stack.push(Popup::Profile);
                }
            }
        }
    }

    fn input_key(&mut self, mut inp: InputPopup, key: KeyEvent, eng: &Engine) {
        match key.code {
            KeyCode::Esc => {}
            KeyCode::Tab => {
                if matches!(inp.action, InputAction::CreateGroup) {
                    inp.private = !inp.private;
                }
                self.stack.push(Popup::Input(inp));
            }
            KeyCode::Backspace => {
                inp.value.pop();
                self.stack.push(Popup::Input(inp));
            }
            KeyCode::Char(c) if !c.is_control() => {
                inp.value.push(c);
                self.stack.push(Popup::Input(inp));
            }
            KeyCode::Enter => {
                let value = inp.value.trim().to_string();
                let action = inp.action;
                let private = inp.private;
                self.submit_input(action, value, private, eng);
            }
            _ => self.stack.push(Popup::Input(inp)),
        }
    }

    fn submit_input(&mut self, action: InputAction, value: String, private: bool, eng: &Engine) {
        match action {
            InputAction::CreateGroup => {
                if value.is_empty() {
                    self.toast(MsgKind::Error, "пустое имя группы".into());
                    return;
                }
                let _ = eng.cmds.send(Cmd::Create {
                    name: value,
                    private,
                });
            }
            InputAction::RenameGroup(gid) => {
                if value.is_empty() {
                    return;
                }
                let _ = eng.cmds.send(Cmd::Rename(gid, value));
            }
            InputAction::SetName => {
                let _ = eng.cmds.send(Cmd::SetName(value.clone()));
                self.my_name = value;
            }
            InputAction::SetStatus => {
                let _ = eng.cmds.send(Cmd::SetStatus(value.clone()));
                self.my_status = value;
            }
            InputAction::AddFriend => {
                let mut it = value.splitn(2, char::is_whitespace);
                let code = it.next().unwrap_or("").trim().to_string();
                let alias = it
                    .next()
                    .map(|s| s.trim().to_string())
                    .filter(|s| !s.is_empty())
                    .unwrap_or_else(|| code.clone());
                match proto::Identity::parse_friend_code(&code) {
                    Ok(pk) => {
                        let hex = proto::hex_of(&pk);
                        let mut cfg = eng.cfg.lock().unwrap().clone();
                        if cfg.friends.iter().any(|f| f.pubkey == hex) {
                            self.toast(MsgKind::Warn, "друг уже есть".into());
                            return;
                        }
                        cfg.friends.push(StoredFriend {
                            pubkey: hex,
                            alias: alias.clone(),
                        });
                        if let Err(e) = save_cfg(eng, cfg) {
                            self.toast(MsgKind::Error, format!("не сохранить конфиг: {e}"));
                            return;
                        }
                        self.toast(MsgKind::Ok, format!("друг добавлен: {alias}"));
                    }
                    Err(e) => {
                        self.toast(MsgKind::Error, format!("неверный friend code: {e}"));
                    }
                }
            }
            InputAction::InviteCode(gid) => match proto::Identity::parse_friend_code(&value) {
                Ok(pk) => {
                    let _ = eng.cmds.send(Cmd::Invite(gid, pk));
                    self.toast(MsgKind::Ok, "приглашение отправлено".into());
                }
                Err(e) => self.toast(MsgKind::Error, format!("неверный friend code: {e}")),
            },
            InputAction::Command => {
                if let Err(e) = self.run_command(&value, eng) {
                    self.toast(MsgKind::Error, e.to_string());
                }
            }
        }
    }

    fn confirm_action(&mut self, action: ConfirmAction, eng: &Engine) {
        match action {
            ConfirmAction::DeleteGroup(gid) => {
                let _ = eng.cmds.send(Cmd::Delete(gid));
                self.toast(MsgKind::Warn, format!("группа {gid} удаляется"));
            }
            ConfirmAction::LeaveGroup(gid) => {
                let _ = eng.cmds.send(Cmd::Leave(gid));
                self.toast(MsgKind::Info, format!("выходим из {gid}"));
            }
            ConfirmAction::DeleteFriend(alias) => {
                let mut cfg = eng.cfg.lock().unwrap().clone();
                let before = cfg.friends.len();
                cfg.friends.retain(|f| f.alias != alias);
                if cfg.friends.len() == before {
                    self.toast(MsgKind::Warn, format!("друг {alias} не найден"));
                    return;
                }
                if let Err(e) = save_cfg(eng, cfg) {
                    self.toast(MsgKind::Error, format!("не сохранить конфиг: {e}"));
                    return;
                }
                self.toast(MsgKind::Ok, format!("друг {alias} удалён"));
            }
        }
    }

    // ---------- открытие попапов ----------

    fn open_create_group(&mut self) {
        self.stack.push(Popup::Input(InputPopup {
            title: "Новая группа".into(),
            hint: "имя группы · Tab — приватная · Enter — создать".into(),
            value: String::new(),
            action: InputAction::CreateGroup,
            private: false,
        }));
    }

    fn open_rename(&mut self) {
        match self.selected_group() {
            Some(g) => {
                let gid = g.gid;
                let name = g.name.clone();
                self.stack.push(Popup::Input(InputPopup {
                    title: format!("Переименовать группу {gid}"),
                    hint: "новое имя · Enter — применить".into(),
                    value: name,
                    action: InputAction::RenameGroup(gid),
                    private: false,
                }));
            }
            None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
        }
    }

    fn open_delete_group(&mut self) {
        match self.selected_group() {
            Some(g) if g.owner_is_me => {
                let gid = g.gid;
                let name = g.name.clone();
                self.stack.push(Popup::Confirm(ConfirmPopup {
                    title: "Удалить группу?".into(),
                    message: format!("группа {gid} «{name}» будет удалена у всех участников"),
                    action: ConfirmAction::DeleteGroup(gid),
                }));
            }
            Some(_) => self.toast(MsgKind::Warn, "удалить может только владелец".into()),
            None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
        }
    }

    fn open_leave_group(&mut self) {
        match self.selected_group() {
            Some(g) if g.mine => {
                let gid = g.gid;
                let name = g.name.clone();
                self.stack.push(Popup::Confirm(ConfirmPopup {
                    title: "Покинуть группу?".into(),
                    message: format!("выйти из группы {gid} «{name}»"),
                    action: ConfirmAction::LeaveGroup(gid),
                }));
            }
            Some(_) => self.toast(MsgKind::Warn, "вы не состоите в группе".into()),
            None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
        }
    }

    fn open_add_friend(&mut self) {
        self.stack.push(Popup::Input(InputPopup {
            title: "Добавить друга".into(),
            hint: "friend code (TUN-…) [алиас] · Enter — добавить".into(),
            value: String::new(),
            action: InputAction::AddFriend,
            private: false,
        }));
    }

    fn open_del_friend(&mut self) {
        match self.selected_friend() {
            Some(f) => {
                let alias = f.alias.clone();
                self.stack.push(Popup::Confirm(ConfirmPopup {
                    title: "Удалить друга?".into(),
                    message: format!("друг «{alias}» будет удалён из локального списка"),
                    action: ConfirmAction::DeleteFriend(alias),
                }));
            }
            None => self.toast(MsgKind::Warn, "не выбран друг".into()),
        }
    }

    fn open_pick(&mut self, mode: PickMode) {
        let gid = match self.selected_group() {
            Some(g) => g.gid,
            None => {
                self.toast(MsgKind::Warn, "не выбрана группа".into());
                return;
            }
        };
        let mut items: Vec<PeerChoice> = Vec::new();
        match mode {
            PickMode::Invite => {
                for f in self.friends.iter() {
                    items.push(PeerChoice {
                        pubkey: f.pubkey,
                        label: f.alias.clone(),
                        sub: "друг".into(),
                        online: f.online,
                    });
                }
                if let Some(g) = self.groups.iter().find(|g| g.gid == gid) {
                    for p in g.peers.iter() {
                        items.push(PeerChoice {
                            pubkey: p.pubkey,
                            label: p.name.clone(),
                            sub: proto::ip_str(p.ip),
                            online: p.online,
                        });
                    }
                }
                let mut seen = HashSet::new();
                items.retain(|i| seen.insert(i.pubkey));
                // Ручной ввод friend code (для тех, кто ещё не в друзьях).
                items.push(PeerChoice {
                    pubkey: [0; 32],
                    label: "ввести friend code вручную…".into(),
                    sub: "TUN-…".into(),
                    online: false,
                });
            }
            PickMode::Kick | PickMode::Ban => {
                if let Some(g) = self.groups.iter().find(|g| g.gid == gid) {
                    for p in g.peers.iter() {
                        items.push(PeerChoice {
                            pubkey: p.pubkey,
                            label: p.name.clone(),
                            sub: proto::ip_str(p.ip),
                            online: p.online,
                        });
                    }
                }
            }
        }
        if items.is_empty() {
            self.toast(MsgKind::Warn, "некого выбирать".into());
            return;
        }
        let title = match mode {
            PickMode::Invite => format!("Пригласить в группу {gid}"),
            PickMode::Kick => format!("Исключить из группы {gid}"),
            PickMode::Ban => format!("Забанить в группе {gid}"),
        };
        self.stack.push(Popup::PeerPick(PeerPickPopup {
            gid,
            title,
            mode,
            items,
            sel: 0,
        }));
    }

    fn open_setting(&mut self, row: SettingRow, eng: &Engine) {
        match row {
            SettingRow::Name => self.stack.push(Popup::Input(InputPopup {
                title: "Имя профиля".into(),
                hint: "как вас видят другие · Enter — сохранить".into(),
                value: self.my_name.clone(),
                action: InputAction::SetName,
                private: false,
            })),
            SettingRow::Status => self.stack.push(Popup::Input(InputPopup {
                title: "Статус".into(),
                hint: "короткий текст · Enter — сохранить".into(),
                value: self.my_status.clone(),
                action: InputAction::SetStatus,
                private: false,
            })),
            SettingRow::Server => {
                let items: Vec<ListItem> = self
                    .servers
                    .iter()
                    .enumerate()
                    .map(|(i, s)| ListItem {
                        label: if s.label.is_empty() {
                            format!("{}: {}", i, s.addr)
                        } else {
                            format!("{}: {} ({})", i, s.addr, s.label)
                        },
                        // Отмечен сервер, к которому подключены сейчас.
                        checked: s.addr.parse::<std::net::SocketAddr>().ok()
                            == Some(eng.meta.lock().unwrap().server),
                        value: i.to_string(),
                    })
                    .collect();
                if items.is_empty() {
                    self.toast(MsgKind::Warn, "нет серверов".into());
                    return;
                }
                self.stack.push(Popup::ListPick(ListPickPopup {
                    title: "Сервер (влияет на перезапуск)".into(),
                    items,
                    sel: 0,
                    action: ListAction::PickServer,
                }));
            }
            SettingRow::Autojoin => {
                let items: Vec<ListItem> = self
                    .groups
                    .iter()
                    .filter(|g| g.mine)
                    .map(|g| ListItem {
                        label: format!("{} «{}»", g.gid, g.name),
                        checked: self.autojoin.contains(&g.gid),
                        value: g.gid.to_string(),
                    })
                    .collect();
                if items.is_empty() {
                    self.toast(MsgKind::Warn, "нет групп".into());
                    return;
                }
                self.stack.push(Popup::ListPick(ListPickPopup {
                    title: "Автовход (Enter — переключить)".into(),
                    items,
                    sel: 0,
                    action: ListAction::ToggleAutojoin,
                }));
            }
            SettingRow::Theme => {
                let kind = self.theme_kind.next();
                self.theme_kind = kind;
                self.status_msg = format!("тема: {}", kind.label());
                self.toast(MsgKind::Ok, format!("тема: {}", kind.label()));
                // Сохраняем выбор в конфиге.
                let mut cfg = eng.cfg.lock().unwrap().clone();
                cfg.theme = kind.as_str().to_string();
                if let Err(e) = save_cfg(eng, cfg) {
                    self.toast(MsgKind::Error, format!("не сохранить тему: {e}"));
                }
            }
        }
    }

    fn open_command(&mut self) {
        self.stack.push(Popup::Input(InputPopup {
            title: "Команда".into(),
            hint: ":join 1 · :create имя · :help — список команд".into(),
            value: String::new(),
            action: InputAction::Command,
            private: false,
        }));
    }

    fn join_selected(&mut self, eng: &Engine) {
        match self.selected_group() {
            Some(g) if !g.mine => {
                let gid = g.gid;
                let _ = eng.cmds.send(Cmd::Join(gid));
                self.toast(MsgKind::Info, format!("входим в группу {gid}"));
            }
            Some(_) => self.toast(MsgKind::Info, "уже в группе".into()),
            None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
        }
    }

    fn copy_context(&mut self) {
        match self.focus {
            Focus::Peers => match self.selected_peer() {
                Some(p) => {
                    copy_to_clipboard(&proto::ip_str(p.ip));
                    self.toast(MsgKind::Ok, format!("IP скопирован: {}", proto::ip_str(p.ip)));
                }
                None => self.toast(MsgKind::Warn, "не выбран участник".into()),
            },
            Focus::Groups => match self.selected_group() {
                Some(g) => {
                    let txt = match g.my_ip {
                        Some(ip) => proto::ip_str(ip),
                        None => g.gid.to_string(),
                    };
                    copy_to_clipboard(&txt);
                    self.toast(MsgKind::Ok, format!("скопировано: {txt}"));
                }
                None => self.toast(MsgKind::Warn, "не выбрана группа".into()),
            },
            Focus::Friends => match self.selected_friend() {
                Some(f) => {
                    copy_to_clipboard(&proto::hex_of(&f.pubkey));
                    self.toast(MsgKind::Ok, format!("pubkey скопирован: {}", f.alias));
                }
                None => self.toast(MsgKind::Warn, "не выбран друг".into()),
            },
            Focus::Log => {}
        }
    }

    // ---------- командная строка ----------

    /// Выполняет команду из строки «:».
    pub fn run_command(&mut self, line: &str, eng: &Engine) -> Result<()> {
        match parse_command(line)? {
            Command::Help => self.stack.push(Popup::Help),
            Command::Join(gid) => {
                let _ = eng.cmds.send(Cmd::Join(gid));
            }
            Command::Leave(gid) => {
                let _ = eng.cmds.send(Cmd::Leave(gid));
            }
            Command::Create { name, private } => {
                let _ = eng.cmds.send(Cmd::Create { name, private });
            }
            Command::Rename(gid, name) => {
                let _ = eng.cmds.send(Cmd::Rename(gid, name));
            }
            Command::Delete(gid) => {
                let _ = eng.cmds.send(Cmd::Delete(gid));
            }
            Command::Invite(gid, peer) => {
                let pk = self.resolve_peer(eng, &peer)?;
                let _ = eng.cmds.send(Cmd::Invite(gid, pk));
            }
            Command::Kick(gid, peer) => {
                let pk = self.resolve_peer(eng, &peer)?;
                let _ = eng.cmds.send(Cmd::Kick(gid, pk));
            }
            Command::Ban(gid, peer) => {
                let pk = self.resolve_peer(eng, &peer)?;
                let _ = eng.cmds.send(Cmd::Ban(gid, pk));
            }
            Command::AddFriend { code, alias } => {
                let pk = proto::Identity::parse_friend_code(&code)?;
                let hex = proto::hex_of(&pk);
                let mut cfg = eng.cfg.lock().unwrap().clone();
                if cfg.friends.iter().any(|f| f.pubkey == hex) {
                    return Err(anyhow!("друг уже добавлен"));
                }
                cfg.friends.push(StoredFriend { pubkey: hex, alias });
                save_cfg(eng, cfg)?;
            }
            Command::DelFriend(alias) => {
                let mut cfg = eng.cfg.lock().unwrap().clone();
                let before = cfg.friends.len();
                cfg.friends.retain(|f| f.alias != alias);
                if cfg.friends.len() == before {
                    return Err(anyhow!("друг не найден"));
                }
                save_cfg(eng, cfg)?;
            }
            Command::SetName(name) => {
                let _ = eng.cmds.send(Cmd::SetName(name));
            }
            Command::SetStatus(text) => {
                let _ = eng.cmds.send(Cmd::SetStatus(text));
            }
            Command::Sort(sort) => {
                self.sort = sort;
            }
            Command::Copy(what) => {
                let txt = match what.as_str() {
                    "code" => self.my_code.clone(),
                    "ip" => self
                        .selected_group()
                        .and_then(|g| g.my_ip)
                        .map(proto::ip_str)
                        .unwrap_or_default(),
                    _ => return Err(anyhow!("copy ip|code")),
                };
                if txt.is_empty() {
                    return Err(anyhow!("нечего копировать"));
                }
                copy_to_clipboard(&txt);
                self.toast(MsgKind::Ok, format!("скопировано: {txt}"));
            }
            Command::Quit => {
                self.quit = true;
                let _ = eng.cmds.send(Cmd::Quit);
            }
        }
        Ok(())
    }

    /// Friend code / hex / alias → pubkey.
    fn resolve_peer(&self, eng: &Engine, token: &str) -> Result<[u8; 32]> {
        let cfg = eng.cfg.lock().unwrap().clone();
        store::resolve_peer(&cfg, token)
    }
}

/// Команда командной строки (разбирается независимо от движка).
#[derive(Debug, PartialEq)]
pub enum Command {
    Help,
    Join(u32),
    Leave(u32),
    Create { name: String, private: bool },
    Rename(u32, String),
    Delete(u32),
    Invite(u32, String),
    Kick(u32, String),
    Ban(u32, String),
    AddFriend { code: String, alias: String },
    DelFriend(String),
    SetName(String),
    SetStatus(String),
    Sort(Sort),
    Copy(String),
    Quit,
}

/// Разбирает строку командной строки (без ведущего «:»).
pub fn parse_command(line: &str) -> Result<Command> {
    let mut it = line.trim().split_whitespace();
    let cmd = it.next().unwrap_or("").to_lowercase();
    let rest: Vec<&str> = it.collect();
    let gid_of = |i: usize| -> Result<u32> {
        rest.get(i)
            .ok_or_else(|| anyhow!("нужен gid"))?
            .parse::<u32>()
            .map_err(|_| anyhow!("gid должен быть числом"))
    };
    Ok(match cmd.as_str() {
        "" => Command::Help,
        "help" | "?" => Command::Help,
        "join" => Command::Join(gid_of(0)?),
        "leave" => Command::Leave(gid_of(0)?),
        "create" => {
            let private = rest.iter().any(|a| *a == "--private");
            let name = rest
                .iter()
                .filter(|a| **a != "--private")
                .cloned()
                .collect::<Vec<_>>()
                .join(" ");
            if name.is_empty() {
                return Err(anyhow!("нужно имя группы"));
            }
            Command::Create { name, private }
        }
        "rename" => {
            let gid = gid_of(0)?;
            let name = rest[1.min(rest.len())..].join(" ");
            if name.is_empty() {
                return Err(anyhow!("нужно новое имя"));
            }
            Command::Rename(gid, name)
        }
        "delete" => Command::Delete(gid_of(0)?),
        "invite" => Command::Invite(
            gid_of(0)?,
            rest.get(1)
                .ok_or_else(|| anyhow!("нужен peer (friend code | hex | alias)"))?
                .to_string(),
        ),
        "kick" => Command::Kick(
            gid_of(0)?,
            rest.get(1)
                .ok_or_else(|| anyhow!("нужен peer (friend code | hex | alias)"))?
                .to_string(),
        ),
        "ban" => Command::Ban(
            gid_of(0)?,
            rest.get(1)
                .ok_or_else(|| anyhow!("нужен peer (friend code | hex | alias)"))?
                .to_string(),
        ),
        "friend" => {
            let code = rest
                .first()
                .ok_or_else(|| anyhow!("нужен friend code"))?
                .to_string();
            let alias = rest
                .get(1)
                .map(|s| s.to_string())
                .unwrap_or_else(|| code.clone());
            Command::AddFriend { code, alias }
        }
        "delfriend" => Command::DelFriend(
            rest.first()
                .ok_or_else(|| anyhow!("нужен alias друга"))?
                .to_string(),
        ),
        "name" => {
            let name = rest.join(" ");
            if name.is_empty() {
                return Err(anyhow!("нужно имя"));
            }
            Command::SetName(name)
        }
        "status" => Command::SetStatus(rest.join(" ")),
        "sort" => {
            let mode = rest.first().copied().unwrap_or("name").to_lowercase();
            Command::Sort(match mode.as_str() {
                "online" => Sort::Online,
                "rtt" => Sort::Rtt,
                _ => Sort::Name,
            })
        }
        "copy" => Command::Copy(
            rest.first()
                .copied()
                .unwrap_or("ip")
                .to_lowercase(),
        ),
        "quit" | "q" => Command::Quit,
        other => return Err(anyhow!("неизвестная команда: {other}")),
    })
}

// ---------------------------------------------------------------- утилиты

pub fn hex32(s: &str) -> Option<[u8; 32]> {
    let v = proto::hex_to_bytes(s).ok()?;
    if v.len() != 32 {
        return None;
    }
    Some(v.try_into().unwrap())
}

/// Сохраняет конфиг и обновляет его копию в движке (иначе UI откатит правку).
pub fn save_cfg(eng: &Engine, cfg: Config) -> Result<()> {
    *eng.cfg.lock().unwrap() = cfg.clone();
    eng.save_config(&cfg)?;
    Ok(())
}

/// Копирование в системный буфер обмена.
pub fn copy_to_clipboard(text: &str) {
    #[cfg(windows)]
    {
        use std::io::Write;
        if let Ok(mut child) = std::process::Command::new("clip")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
    #[cfg(not(windows))]
    {
        use std::io::Write;
        if let Ok(mut child) = std::process::Command::new("pbcopy")
            .stdin(std::process::Stdio::piped())
            .spawn()
        {
            if let Some(stdin) = child.stdin.as_mut() {
                let _ = stdin.write_all(text.as_bytes());
            }
            let _ = child.wait();
        }
    }
}

// ---------------------------------------------------------------- тесты

#[cfg(test)]
mod tests {
    use super::*;

    fn app() -> App {
        let mut cfg = Config::default();
        cfg.name = "alpha".into();
        cfg.status = "тест".into();
        App::new([7; 32], "TUN-TEST-CODE", &cfg)
    }

    #[test]
    fn парс_команд_базовые() {
        assert_eq!(parse_command("help").unwrap(), Command::Help);
        assert_eq!(parse_command("join 3").unwrap(), Command::Join(3));
        assert_eq!(parse_command("leave 4").unwrap(), Command::Leave(4));
        assert_eq!(
            parse_command("create gamers").unwrap(),
            Command::Create {
                name: "gamers".into(),
                private: false
            }
        );
        assert_eq!(
            parse_command("create secret --private").unwrap(),
            Command::Create {
                name: "secret".into(),
                private: true
            }
        );
        assert_eq!(
            parse_command("rename 2 my net").unwrap(),
            Command::Rename(2, "my net".into())
        );
        assert_eq!(parse_command("quit").unwrap(), Command::Quit);
        assert_eq!(parse_command("sort rtt").unwrap(), Command::Sort(Sort::Rtt));
        assert_eq!(parse_command("copy code").unwrap(), Command::Copy("code".into()));
    }

    #[test]
    fn парс_команд_ошибки() {
        assert!(parse_command("join").is_err());
        assert!(parse_command("join x").is_err());
        assert!(parse_command("create").is_err());
        assert!(parse_command("бла").is_err());
    }

    #[test]
    fn фильтр_групп_и_друзей() {
        let mut a = app();
        a.groups = vec![
            GroupView {
                gid: 1,
                name: "gamers".into(),
                private: false,
                mine: true,
                online: 2,
                total: 3,
                my_ip: Some(0x6442_0002),
                owner_is_me: true,
                peers: vec![],
            },
            GroupView {
                gid: 2,
                name: "work".into(),
                private: true,
                mine: false,
                online: 0,
                total: 1,
                my_ip: None,
                owner_is_me: false,
                peers: vec![],
            },
        ];
        a.friends = vec![FriendView {
            alias: "bravo".into(),
            pubkey: [1; 32],
            online: true,
            shared_groups: 1,
        }];
        a.filter = "game".into();
        assert_eq!(a.visible_groups().len(), 1);
        assert_eq!(a.visible_groups()[0].gid, 1);
        assert_eq!(a.visible_friends().len(), 0);
        a.filter = "bra".into();
        assert_eq!(a.visible_groups().len(), 0);
        assert_eq!(a.visible_friends().len(), 1);
    }

    #[test]
    fn сортировка_переключается_по_кругу() {
        assert_eq!(Sort::Name.next(), Sort::Online);
        assert_eq!(Sort::Online.next(), Sort::Rtt);
        assert_eq!(Sort::Rtt.next(), Sort::Name);
    }
}
