//! IPC-бэкенд трея (PLAN.md 7.5 поверх 7.2/7.3): фоновый поток держит
//! соединение с демоном через [`tunnel_ipc::IpcClient`] — `Hello{kind: Tray}`
//! → `Welcome` → `Subscribe`, дальше читает `Snapshot`/`Event`/`Ack`. Нет
//! демона или связь оборвалась — `Conn::DaemonDown` и новая попытка раз в
//! [`RETRY`]. Соединением владеет только этот поток: `act` кладёт команду в
//! канал, поток отправляет её между чтениями — UI-поток трея не ждёт пайп.
//!
//! Снимок (`crates/client/src/snapshot.rs`) и события движка приходят как
//! JSON; трей не зависит от `tunnel-client` и читает только нужные поля
//! (имена полей — оттуда же). Команды — `Cmd` движка в externally-tagged
//! JSON serde: `{"Join": 3}`, `{"Leave": 3}`, `{"DeclineInvite": 3}`.
#![cfg_attr(not(windows), allow(dead_code))] // вне Windows трей не собирается в бинарь

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use serde_json::{Value, json};
use tunnel_ipc::{AckResult, ClientError, ClientKind, DaemonMsg, IpcClient};

use crate::backend::TrayBackend;
use crate::model::{Action, Conn, TrayGroup, TrayInvite, TrayKick, TrayState};

/// Пауза между попытками подключиться к демону.
pub const RETRY: Duration = Duration::from_secs(1);
/// Сколько ждать `Welcome` после `Hello`.
pub const HELLO_TIMEOUT: Duration = Duration::from_secs(3);
/// Такт потока: сколько ждать сообщение демона, прежде чем отправить
/// накопившиеся команды и проверить остановку.
const POLL: Duration = Duration::from_millis(50);
/// Желаемый период снимков (хаб всё равно шлёт их сразу после изменений).
pub const SNAPSHOTS_MS: u32 = 1000;
/// Текст для `act`, когда демона нет.
const DAEMON_DOWN_TEXT: &str = "Служба Tunnel недоступна — действие не выполнено";

/// Почему не удалось открыть сессию.
#[derive(Debug)]
pub enum OpenError {
    /// Демона нет / соединение не установлено.
    Down(String),
    /// Демон отказал в `Hello` (версия) — сказать пользователю.
    Rejected(String),
}

/// Установленная сессия с демоном (после `Welcome`).
pub trait Link: Send {
    /// `me` из `Welcome`.
    fn me(&self) -> Value;
    fn subscribe(&mut self, snapshots_ms: u32) -> Result<(), String>;
    /// Отправить `Req`, вернуть его `id`.
    fn send_req(&mut self, cmd: Value) -> Result<u64, String>;
    /// Следующее сообщение; `Ok(None)` — за `timeout` ничего не пришло.
    fn recv(&mut self, timeout: Duration) -> Result<Option<DaemonMsg>, String>;
    /// Вежливое закрытие.
    fn bye(self: Box<Self>);
}

/// Как подключиться к демону (в тестах — поддельный транспорт).
pub trait Transport: Send + Sync + 'static {
    fn open(&self) -> Result<Box<dyn Link>, OpenError>;
}

impl Link for IpcClient {
    fn me(&self) -> Value {
        IpcClient::me(self).clone()
    }
    fn subscribe(&mut self, snapshots_ms: u32) -> Result<(), String> {
        IpcClient::subscribe(self, snapshots_ms).map_err(|e| e.to_string())
    }
    fn send_req(&mut self, cmd: Value) -> Result<u64, String> {
        IpcClient::send_req(self, cmd).map_err(|e| e.to_string())
    }
    fn recv(&mut self, timeout: Duration) -> Result<Option<DaemonMsg>, String> {
        match IpcClient::recv(self, Some(timeout)) {
            Ok(m) => Ok(Some(m)),
            Err(ClientError::Timeout) => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }
    fn bye(self: Box<Self>) {
        IpcClient::bye(*self)
    }
}

/// Настоящий транспорт `tunnel-ipc`: named pipe на Windows (с проверкой,
/// что сервер пайпа — служба от SYSTEM, см. 7.2), Unix-сокет в каталоге данных.
pub struct IpcTransport {
    pub name: PathBuf,
}

impl IpcTransport {
    pub fn new(name: impl Into<PathBuf>) -> Self {
        Self { name: name.into() }
    }
}

impl Default for IpcTransport {
    fn default() -> Self {
        Self::new(default_endpoint())
    }
}

impl Transport for IpcTransport {
    fn open(&self) -> Result<Box<dyn Link>, OpenError> {
        match IpcClient::connect(&self.name, ClientKind::Tray, env!("CARGO_PKG_VERSION"), HELLO_TIMEOUT) {
            Ok(c) => Ok(Box::new(c)),
            Err(ClientError::Rejected(r)) => Err(OpenError::Rejected(r)),
            Err(e) => Err(OpenError::Down(e.to_string())),
        }
    }
}

/// Адрес демона: пайп службы на Windows; на Unix — `daemon.sock` в каталоге
/// данных демона (`~/.tunnel-client`, как `tunnel_daemon::default_data_dir`) —
/// для разработки с `tunnel-daemon console`.
pub fn default_endpoint() -> PathBuf {
    if cfg!(windows) {
        return PathBuf::from(tunnel_ipc::transport::DEFAULT_PIPE_NAME);
    }
    let dir = match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".tunnel-client"),
        None => PathBuf::from("tunnel-client-data"),
    };
    dir.join(tunnel_ipc::transport::DEFAULT_SOCKET_FILE)
}

// ---------------------------------------------------------------------------
// Чистые преобразования: снимок → TrayState, действие → команда.

/// `Cmd` движка для действия трея; `None` — действие локальное.
/// Принять приглашение — это `Join` (сервер сам снимает приглашение).
pub fn action_cmd(a: Action) -> Option<Value> {
    Some(match a {
        Action::ToggleGroup { gid, join: true } | Action::AcceptInvite(gid) => json!({ "Join": gid }),
        Action::ToggleGroup { gid, join: false } => json!({ "Leave": gid }),
        Action::DeclineInvite(gid) => json!({ "DeclineInvite": gid }),
        Action::OpenTui | Action::CopyIp | Action::CopyCode | Action::StopTunnel | Action::Exit => return None,
    })
}

/// Что делали — для текста ошибки из `Ack`.
fn action_text(a: Action) -> &'static str {
    match a {
        Action::ToggleGroup { join: true, .. } => "Не удалось войти в группу",
        Action::ToggleGroup { join: false, .. } => "Не удалось выйти из группы",
        Action::AcceptInvite(_) => "Не удалось принять приглашение",
        Action::DeclineInvite(_) => "Не удалось отклонить приглашение",
        _ => "Команда не выполнена",
    }
}

fn str_of<'a>(v: &'a Value, key: &str) -> &'a str {
    v.get(key).and_then(Value::as_str).unwrap_or("")
}

fn u32_of(v: &Value, key: &str) -> Option<u32> {
    v.get(key).and_then(Value::as_u64).and_then(|n| u32::try_from(n).ok())
}

fn arr<'a>(v: &'a Value, key: &str) -> &'a [Value] {
    v.get(key).and_then(Value::as_array).map(Vec::as_slice).unwrap_or(&[])
}

/// `[u8; 32]` в JSON serde — массив чисел; в hex.
fn hex_key(v: &Value) -> String {
    match v.as_array() {
        Some(a) => a.iter().filter_map(Value::as_u64).map(|b| format!("{:02x}", b as u8)).collect(),
        None => v.as_str().unwrap_or("").to_lowercase(),
    }
}

/// Отправитель приглашения: имя из приглашения, алиас друга, короткий ключ.
fn inviter(inv: &Value, friends: &[Value]) -> String {
    let name = str_of(inv, "from_name").trim();
    if !name.is_empty() {
        return name.to_string();
    }
    let key = hex_key(inv.get("from_pubkey").unwrap_or(&Value::Null));
    if let Some(f) = friends.iter().find(|f| !key.is_empty() && str_of(f, "pubkey").eq_ignore_ascii_case(&key)) {
        let alias = str_of(f, "alias");
        if !alias.is_empty() {
            return alias.to_string();
        }
    }
    if key.is_empty() { "неизвестный".into() } else { key.chars().take(8).collect() }
}

/// Снимок демона (`Snapshot` из `snapshot.rs`) → состояние трея. `kicked`,
/// `errors`, `my_code`, `tui_open` снимок не несёт — их заполняет бэкенд.
pub fn map_snapshot(snap: &Value) -> TrayState {
    let meta = snap.get("meta").unwrap_or(&Value::Null);
    let cfg = snap.get("cfg").unwrap_or(&Value::Null);

    let connected = meta.get("connected").and_then(Value::as_bool).unwrap_or(false);
    let has_server = !str_of(meta, "server").is_empty() || !arr(cfg, "servers").is_empty();
    let conn = if connected {
        Conn::Connected
    } else if has_server {
        Conn::Reconnecting
    } else {
        Conn::Offline
    };

    // Свои группы (`groups`) — с галочкой; остальное из списка сервера.
    let mut groups: Vec<TrayGroup> = Vec::new();
    let mut my_ips: Vec<String> = Vec::new();
    let mut mine: Vec<(u32, &Value)> =
        arr(snap, "groups").iter().filter_map(|g| Some((u32_of(g, "gid")?, g))).collect();
    mine.sort_by_key(|(gid, _)| *gid);
    for (gid, g) in mine {
        if let Some(ip) = u32_of(g, "my_ip").filter(|ip| *ip != 0) {
            let ip = Ipv4Addr::from(ip).to_string();
            if !my_ips.contains(&ip) {
                my_ips.push(ip);
            }
        }
        if !groups.iter().any(|x| x.gid == gid) {
            groups.push(TrayGroup { gid, name: str_of(g, "name").to_string(), joined: true });
        }
    }
    for g in arr(meta, "group_list") {
        let Some(gid) = u32_of(g, "gid") else { continue };
        if !groups.iter().any(|x| x.gid == gid) {
            groups.push(TrayGroup { gid, name: str_of(g, "name").to_string(), joined: false });
        }
    }
    groups.sort_by_key(|g| g.gid);
    for g in &mut groups {
        if g.name.is_empty() {
            g.name = format!("группа {}", g.gid);
        }
    }

    let friends = arr(cfg, "friends");
    let mut invites: Vec<TrayInvite> = Vec::new();
    for i in arr(snap, "pending_invites") {
        let Some(gid) = u32_of(i, "gid") else { continue };
        if invites.iter().any(|x| x.gid == gid) {
            continue;
        }
        let name = str_of(i, "group_name");
        invites.push(TrayInvite {
            gid,
            group_name: if name.is_empty() { format!("группа {gid}") } else { name.to_string() },
            from: inviter(i, friends),
        });
    }

    let label = str_of(meta, "server_label");
    let server_label = if !label.is_empty() {
        Some(label.to_string())
    } else {
        Some(str_of(meta, "server").to_string()).filter(|s| !s.is_empty())
    };

    TrayState { conn, my_ips, server_label, my_code: None, groups, invites, ..Default::default() }
}

/// Friend code из `Welcome.me` (`my_code`; `code` — как в тестовом бэкенде хаба).
pub fn me_code(me: &Value) -> Option<String> {
    ["my_code", "code"]
        .iter()
        .find_map(|k| me.get(*k).and_then(Value::as_str))
        .filter(|s| !s.is_empty())
        .map(str::to_string)
}

/// Событие движка в externally-tagged JSON: `{"Kicked": {..}}` или `"Quit"`.
fn event_tag(ev: &Value) -> Option<(&str, &Value)> {
    match ev {
        Value::String(s) => Some((s.as_str(), &Value::Null)),
        Value::Object(m) if m.len() == 1 => m.iter().next().map(|(k, v)| (k.as_str(), v)),
        _ => None,
    }
}

/// `Kicked` / `GroupDeleted` → группа недоступна.
pub fn event_kick(ev: &Value) -> Option<TrayKick> {
    let (tag, body) = event_tag(ev)?;
    if tag != "Kicked" && tag != "GroupDeleted" {
        return None;
    }
    let gid = u32_of(body, "gid")?;
    let name = str_of(body, "name");
    Some(TrayKick { gid, group_name: if name.is_empty() { format!("группа {gid}") } else { name.to_string() } })
}

// ---------------------------------------------------------------------------
// Общее состояние потока связи и `TrayBackend`.

#[derive(Default)]
struct Inner {
    /// Последний снимок этой сессии (`None` — демона нет или снимка ещё не было).
    view: Option<TrayState>,
    /// `seq` первого снимка сессии: события с `seq` не больше — история кольца
    /// хаба (уже учтены в снимке), по ним не уведомляем.
    base_seq: Option<u64>,
    my_code: Option<String>,
    kicked: Vec<TrayKick>,
    errors: Vec<String>,
    /// Ждут `Ack`: id → действие (для текста ошибки).
    pending: HashMap<u64, Action>,
    /// Последний `Reject` — не повторять одно и то же уведомление раз в секунду.
    last_reject: Option<String>,
}

#[derive(Default)]
struct Shared {
    inner: Mutex<Inner>,
    stop: AtomicBool,
}

impl Shared {
    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn on_welcome(&self, me: &Value) {
        let mut s = self.lock();
        s.my_code = me_code(me);
        s.last_reject = None;
    }

    fn on_reject(&self, reason: String) {
        let mut s = self.lock();
        if s.last_reject.as_deref() != Some(reason.as_str()) {
            s.errors.push(format!("Служба Tunnel отказала в подключении: {reason}"));
            s.last_reject = Some(reason);
        }
    }

    fn on_msg(&self, m: DaemonMsg) {
        let mut s = self.lock();
        match m {
            DaemonMsg::Snapshot { seq, snap } => {
                s.base_seq.get_or_insert(seq);
                s.view = Some(map_snapshot(&snap));
            }
            DaemonMsg::Event { seq, ev } => {
                // История до первого снимка или из кольца — уже прошлое.
                let live = s.base_seq.is_some_and(|b| seq > b);
                if live && let Some(k) = event_kick(&ev) {
                    s.kicked.push(k);
                }
            }
            DaemonMsg::Ack { id, result } => {
                let a = s.pending.remove(&id);
                if let AckResult::Err(e) = result {
                    let what = a.map(action_text).unwrap_or("Команда не выполнена");
                    s.errors.push(format!("{what}: {e}"));
                }
            }
            DaemonMsg::Welcome { .. } | DaemonMsg::Reject { .. } | DaemonMsg::Shutdown { .. } => {}
        }
    }

    fn on_sent(&self, id: u64, a: Action) {
        self.lock().pending.insert(id, a);
    }

    fn on_error(&self, text: String) {
        self.lock().errors.push(text);
    }

    /// Связь потеряна (или не установлена).
    fn on_down(&self) {
        let mut s = self.lock();
        s.view = None;
        s.base_seq = None;
        s.my_code = None;
        // Дошли ли команды — неизвестно; итог придёт снимком после реконнекта.
        s.pending.clear();
    }

    fn online(&self) -> bool {
        self.lock().view.is_some()
    }

    fn state(&self) -> TrayState {
        let mut s = self.lock();
        let mut st = s.view.clone().unwrap_or_default();
        st.my_code = if s.view.is_some() { s.my_code.clone() } else { None };
        st.kicked = std::mem::take(&mut s.kicked);
        st.errors = std::mem::take(&mut s.errors);
        // TODO(7.4): открыт ли TUI — демон пока не сообщает о своих клиентах.
        st.tui_open = false;
        st
    }
}

/// Одна сессия с демоном: до обрыва, `Shutdown` или остановки.
fn session(t: &dyn Transport, sh: &Shared, cmds: &Receiver<(Action, Value)>) -> Result<(), String> {
    let mut link = match t.open() {
        Ok(l) => l,
        Err(OpenError::Rejected(r)) => {
            sh.on_reject(r.clone());
            return Err(format!("отказ: {r}"));
        }
        Err(OpenError::Down(e)) => return Err(e),
    };
    sh.on_welcome(&link.me());
    link.subscribe(SNAPSHOTS_MS)?;
    loop {
        if sh.stop.load(Ordering::Relaxed) {
            link.bye();
            return Ok(());
        }
        // Команды из `act` — только этот поток пишет в соединение.
        while let Ok((a, cmd)) = cmds.try_recv() {
            match link.send_req(cmd) {
                Ok(id) => sh.on_sent(id, a),
                Err(e) => {
                    sh.on_error(format!("{}: {e}", action_text(a)));
                    return Err(e);
                }
            }
        }
        match link.recv(POLL)? {
            None => {}
            Some(DaemonMsg::Shutdown { .. }) => return Ok(()),
            Some(m) => sh.on_msg(m),
        }
    }
}

/// Цикл потока: сессия → `DaemonDown` → пауза `retry` → снова.
fn run_loop(t: &dyn Transport, sh: &Shared, cmds: &Receiver<(Action, Value)>, retry: Duration) {
    while !sh.stop.load(Ordering::Relaxed) {
        let _ = session(t, sh, cmds);
        sh.on_down();
        // Не отправленное до обрыва — не выполнено.
        while let Ok((a, _)) = cmds.try_recv() {
            sh.on_error(format!("{}: {DAEMON_DOWN_TEXT}", action_text(a)));
        }
        if sh.stop.load(Ordering::Relaxed) {
            break;
        }
        std::thread::sleep(retry);
    }
}

/// `TrayBackend` поверх IPC демона.
pub struct IpcTrayBackend {
    shared: Arc<Shared>,
    cmds: Mutex<Sender<(Action, Value)>>,
}

impl IpcTrayBackend {
    /// Поднять поток связи с демоном по адресу по умолчанию.
    pub fn start() -> Self {
        Self::with_transport(IpcTransport::default(), RETRY)
    }

    pub fn with_transport(t: impl Transport, retry: Duration) -> Self {
        let shared = Arc::new(Shared::default());
        let (tx, rx) = mpsc::channel();
        let sh = shared.clone();
        std::thread::Builder::new()
            .name("tray-ipc".into())
            .spawn(move || run_loop(&t, &sh, &rx, retry))
            .expect("поток IPC трея");
        Self { shared, cmds: Mutex::new(tx) }
    }
}

impl TrayBackend for IpcTrayBackend {
    fn state(&self) -> TrayState {
        self.shared.state()
    }

    fn act(&self, a: Action) {
        let Some(cmd) = action_cmd(a) else { return };
        if !self.shared.online() {
            self.shared.on_error(DAEMON_DOWN_TEXT.into());
            return;
        }
        let tx = self.cmds.lock().unwrap_or_else(|e| e.into_inner());
        if tx.send((a, cmd)).is_err() {
            self.shared.on_error(DAEMON_DOWN_TEXT.into());
        }
    }
}

impl Drop for IpcTrayBackend {
    fn drop(&mut self) {
        // Поток на ближайшем такте пошлёт `Bye` и выйдет; не ждём его.
        self.shared.stop.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn fixture() -> Value {
        json!({
            "groups": [{
                "gid": 7, "name": "игра", "owner": (vec![9u8; 32]), "private": true,
                "my_ip": 0x0A00_0002u32, "joined_s_ago": 42, "members": []
            }, {
                "gid": 3, "name": "дом", "owner": (vec![1u8; 32]), "private": false,
                "my_ip": 0x0A01_0005u32, "joined_s_ago": 1, "members": []
            }],
            "meta": {
                "connected": true, "server": "5.6.7.8:9000", "server_label": "дом-сервер",
                "group_list": [
                    {"gid": 7, "name": "игра", "private": true, "mine": false, "online": 2, "total": 3},
                    {"gid": 5, "name": "работа", "private": false, "mine": true, "online": 1, "total": 1}
                ],
                "rx_hist": [1, 2], "tx_hist": [3], "uptime_s": 3600
            },
            "stats": {"rx_bytes": 10, "tx_bytes": 20, "rx_pkts": 1, "tx_pkts": 2},
            "cfg": {
                "name": "alpha", "status": "",
                "servers": [{"addr": "5.6.7.8:9000", "pubkey": "ab", "label": "дом-сервер"}],
                "friends": [{"pubkey": "0303030303030303030303030303030303030303030303030303030303030303", "alias": "чарли"}],
                "autojoin": [7]
            },
            "pending_invites": [
                {"gid": 11, "group_name": "чат", "from_pubkey": (vec![3u8; 32]), "from_name": "charlie",
                 "received_ms_ago": 1500, "expires_in_s": 604800},
                {"gid": 12, "group_name": "", "from_pubkey": (vec![3u8; 32]), "from_name": "",
                 "received_ms_ago": 1, "expires_in_s": null},
                {"gid": 13, "group_name": "кино", "from_pubkey": (vec![0xabu8; 32]), "from_name": " ",
                 "received_ms_ago": 1, "expires_in_s": null}
            ]
        })
    }

    #[test]
    fn snapshot_maps_to_tray_state() {
        let s = map_snapshot(&fixture());
        assert_eq!(s.conn, Conn::Connected);
        assert_eq!(s.my_ips, vec!["10.1.0.5".to_string(), "10.0.0.2".to_string()], "по возрастанию gid");
        assert_eq!(s.server_label.as_deref(), Some("дом-сервер"));
        assert_eq!(s.my_code, None);
        assert_eq!(
            s.groups,
            vec![
                TrayGroup { gid: 3, name: "дом".into(), joined: true },
                TrayGroup { gid: 5, name: "работа".into(), joined: false },
                TrayGroup { gid: 7, name: "игра".into(), joined: true },
            ]
        );
        assert_eq!(
            s.invites,
            vec![
                TrayInvite { gid: 11, group_name: "чат".into(), from: "charlie".into() },
                TrayInvite { gid: 12, group_name: "группа 12".into(), from: "чарли".into() },
                TrayInvite { gid: 13, group_name: "кино".into(), from: "abababab".into() },
            ]
        );
        assert!(s.kicked.is_empty() && s.errors.is_empty());
    }

    #[test]
    fn snapshot_conn_states_and_empty() {
        let mut f = fixture();
        f["meta"]["connected"] = json!(false);
        assert_eq!(map_snapshot(&f).conn, Conn::Reconnecting);
        f["meta"]["server"] = json!("");
        f["cfg"]["servers"] = json!([]);
        assert_eq!(map_snapshot(&f).conn, Conn::Offline);
        // Пустой снимок (`Snapshot::default()`) и мусор — без паники.
        let empty = json!({"groups": [], "meta": {"connected": false, "server": "", "server_label": "",
            "group_list": [], "rx_hist": [], "tx_hist": [], "uptime_s": 0},
            "stats": {}, "cfg": {"servers": [], "friends": []}, "pending_invites": []});
        let s = map_snapshot(&empty);
        assert_eq!(s.conn, Conn::Offline);
        assert!(s.groups.is_empty() && s.invites.is_empty() && s.my_ips.is_empty());
        assert_eq!(s.server_label, None);
        assert_eq!(map_snapshot(&json!(null)).conn, Conn::Offline);
        assert_eq!(map_snapshot(&json!({"groups": "x"})).groups, vec![]);
        // Без label — адрес сервера.
        f["meta"]["server"] = json!("1.2.3.4:5");
        f["meta"]["server_label"] = json!("");
        assert_eq!(map_snapshot(&f).server_label.as_deref(), Some("1.2.3.4:5"));
    }

    #[test]
    fn actions_map_to_engine_cmds() {
        assert_eq!(action_cmd(Action::ToggleGroup { gid: 3, join: true }), Some(json!({"Join": 3})));
        assert_eq!(action_cmd(Action::ToggleGroup { gid: 3, join: false }), Some(json!({"Leave": 3})));
        assert_eq!(action_cmd(Action::AcceptInvite(9)), Some(json!({"Join": 9})));
        assert_eq!(action_cmd(Action::DeclineInvite(9)), Some(json!({"DeclineInvite": 9})));
        for a in [Action::OpenTui, Action::CopyIp, Action::CopyCode, Action::StopTunnel, Action::Exit] {
            assert!(a.is_local());
            assert_eq!(action_cmd(a), None);
        }
        // Ровно такой JSON даёт serde для `Cmd::Join(u32)` (newtype-вариант).
        assert_eq!(serde_json::to_string(&action_cmd(Action::AcceptInvite(1)).unwrap()).unwrap(), r#"{"Join":1}"#);
    }

    #[test]
    fn events_and_me() {
        assert_eq!(
            event_kick(&json!({"Kicked": {"gid": 4, "name": "x"}})),
            Some(TrayKick { gid: 4, group_name: "x".into() })
        );
        assert_eq!(
            event_kick(&json!({"GroupDeleted": {"gid": 5, "name": ""}})),
            Some(TrayKick { gid: 5, group_name: "группа 5".into() })
        );
        assert_eq!(event_kick(&json!({"GroupLeft": {"gid": 4, "name": "x"}})), None);
        assert_eq!(event_kick(&json!({"Connected": "1.2.3.4:5"})), None);
        assert_eq!(event_kick(&json!("Quit")), None);
        assert_eq!(me_code(&json!({"my_pub": "aa", "my_code": "ABCD"})).as_deref(), Some("ABCD"));
        assert_eq!(me_code(&json!({"code": "ME"})).as_deref(), Some("ME"));
        assert_eq!(me_code(&json!({})), None);
    }

    // --- поддельный транспорт -------------------------------------------

    /// Что трей отправил «демону».
    #[derive(Debug, PartialEq)]
    enum Sent {
        Subscribe(u32),
        Req(u64, Value),
        Bye,
    }

    /// Поддельная сессия: сообщения демона из канала, отправленное — в канал.
    /// Закрытый входной канал — обрыв.
    struct FakeLink {
        me: Value,
        rx: Receiver<DaemonMsg>,
        tx: Sender<Sent>,
        next_id: u64,
    }

    impl Link for FakeLink {
        fn me(&self) -> Value {
            self.me.clone()
        }
        fn subscribe(&mut self, ms: u32) -> Result<(), String> {
            self.tx.send(Sent::Subscribe(ms)).map_err(|e| e.to_string())
        }
        fn send_req(&mut self, cmd: Value) -> Result<u64, String> {
            self.next_id += 1;
            self.tx.send(Sent::Req(self.next_id, cmd)).map_err(|e| e.to_string())?;
            Ok(self.next_id)
        }
        fn recv(&mut self, t: Duration) -> Result<Option<DaemonMsg>, String> {
            match self.rx.recv_timeout(t) {
                Ok(m) => Ok(Some(m)),
                Err(mpsc::RecvTimeoutError::Timeout) => Ok(None),
                Err(mpsc::RecvTimeoutError::Disconnected) => Err("обрыв".into()),
            }
        }
        fn bye(self: Box<Self>) {
            let _ = self.tx.send(Sent::Bye);
        }
    }

    /// Результат очередной попытки подключения.
    enum Next {
        Link(FakeLink),
        Reject(String),
    }

    /// Пустая очередь — «демона нет».
    struct FakeTransport {
        attempts: Arc<Mutex<u32>>,
        next: Mutex<Receiver<Next>>,
    }

    impl Transport for FakeTransport {
        fn open(&self) -> Result<Box<dyn Link>, OpenError> {
            *self.attempts.lock().unwrap() += 1;
            match self.next.lock().unwrap().try_recv() {
                Ok(Next::Link(l)) => Ok(Box::new(l)),
                Ok(Next::Reject(r)) => Err(OpenError::Rejected(r)),
                Err(_) => Err(OpenError::Down("нет пайпа".into())),
            }
        }
    }

    /// Сторона «демона» одной сессии.
    struct DaemonEnd {
        tx: Sender<DaemonMsg>,
        rx: Receiver<Sent>,
    }

    impl DaemonEnd {
        fn send(&self, m: DaemonMsg) {
            self.tx.send(m).unwrap();
        }
        fn recv(&self) -> Sent {
            self.rx.recv_timeout(Duration::from_secs(5)).expect("сообщение от трея")
        }
    }

    fn link(code: &str) -> (Next, DaemonEnd) {
        let (dtx, drx) = mpsc::channel();
        let (stx, srx) = mpsc::channel();
        let l = FakeLink { me: json!({"my_pub": "aa", "my_code": code}), rx: drx, tx: stx, next_id: 0 };
        (Next::Link(l), DaemonEnd { tx: dtx, rx: srx })
    }

    fn fake(retry_ms: u64) -> (IpcTrayBackend, Sender<Next>, Arc<Mutex<u32>>) {
        let (tx, rx) = mpsc::channel();
        let attempts = Arc::new(Mutex::new(0));
        let t = FakeTransport { attempts: attempts.clone(), next: Mutex::new(rx) };
        (IpcTrayBackend::with_transport(t, Duration::from_millis(retry_ms)), tx, attempts)
    }

    fn wait(b: &IpcTrayBackend, what: &str, pred: impl Fn(&TrayState) -> bool) -> TrayState {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let s = b.state();
            if pred(&s) {
                return s;
            }
            assert!(Instant::now() < deadline, "не дождались: {what}; состояние {s:?}");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn reconnect_state_machine() {
        let (b, next, attempts) = fake(10);

        // Демона нет: DaemonDown, попытки повторяются.
        assert_eq!(b.state().conn, Conn::DaemonDown);
        let deadline = Instant::now() + Duration::from_secs(5);
        while *attempts.lock().unwrap() < 3 {
            assert!(Instant::now() < deadline, "нет повторных попыток");
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(b.state().conn, Conn::DaemonDown);
        // Действие без демона — ошибка-уведомление, не паника.
        b.act(Action::AcceptInvite(11));
        assert_eq!(b.state().errors, vec![DAEMON_DOWN_TEXT.to_string()]);
        // Локальные действия в демон не идут и ошибок не дают.
        b.act(Action::CopyIp);
        assert!(b.state().errors.is_empty());

        // Демон появился: Subscribe, история, снимок.
        let (l, d) = link("ABCD");
        next.send(l).unwrap();
        assert_eq!(d.recv(), Sent::Subscribe(SNAPSHOTS_MS));
        assert_eq!(b.state().conn, Conn::DaemonDown, "до снимка — ещё не на связи");
        // История кольца до снимка — не уведомляем.
        d.send(DaemonMsg::Event { seq: 4, ev: json!({"Kicked": {"gid": 1, "name": "старое"}}) });
        d.send(DaemonMsg::Snapshot { seq: 5, snap: fixture() });
        let s = wait(&b, "снимок", |s| s.conn == Conn::Connected);
        assert_eq!(s.my_code.as_deref(), Some("ABCD"));
        assert_eq!(s.invites.len(), 3);
        assert!(s.kicked.is_empty());

        // Живое событие → kicked, один раз; seq ≤ снимка — история.
        d.send(DaemonMsg::Event { seq: 5, ev: json!({"Kicked": {"gid": 2, "name": "повтор"}}) });
        d.send(DaemonMsg::Event { seq: 6, ev: json!({"GroupDeleted": {"gid": 7, "name": "игра"}}) });
        let s = wait(&b, "kicked", |s| !s.kicked.is_empty());
        assert_eq!(s.kicked, vec![TrayKick { gid: 7, group_name: "игра".into() }]);
        assert!(b.state().kicked.is_empty(), "отдаётся один раз");

        // Действие → Req с командой движка; Ack Err → уведомление.
        b.act(Action::DeclineInvite(11));
        let Sent::Req(id, cmd) = d.recv() else { panic!("ожидался Req") };
        assert_eq!(cmd, json!({"DeclineInvite": 11}));
        b.act(Action::ToggleGroup { gid: 5, join: true });
        let Sent::Req(id2, cmd) = d.recv() else { panic!("ожидался Req") };
        assert_eq!(cmd, json!({"Join": 5}));
        d.send(DaemonMsg::Ack { id, result: AckResult::Ok });
        d.send(DaemonMsg::Ack { id: id2, result: AckResult::Err("нет сервера".into()) });
        let s = wait(&b, "ошибка Ack", |s| !s.errors.is_empty());
        assert_eq!(s.errors, vec!["Не удалось войти в группу: нет сервера".to_string()]);

        // Обрыв → DaemonDown, затем переподключение к новому «демону».
        drop(d);
        wait(&b, "DaemonDown после обрыва", |s| s.conn == Conn::DaemonDown && s.my_code.is_none());
        let (l, d) = link("NEW");
        next.send(l).unwrap();
        assert_eq!(d.recv(), Sent::Subscribe(SNAPSHOTS_MS));
        let mut f = fixture();
        f["meta"]["connected"] = json!(false);
        d.send(DaemonMsg::Snapshot { seq: 1, snap: f });
        let s = wait(&b, "второй снимок", |s| s.conn == Conn::Reconnecting);
        assert_eq!(s.my_code.as_deref(), Some("NEW"));

        // Shutdown демона — тоже DaemonDown.
        d.send(DaemonMsg::Shutdown { reason: "стоп".into() });
        wait(&b, "DaemonDown после Shutdown", |s| s.conn == Conn::DaemonDown);

        // Остановка бэкенда — `Bye` демону.
        let (l, d) = link("X");
        next.send(l).unwrap();
        assert_eq!(d.recv(), Sent::Subscribe(SNAPSHOTS_MS));
        drop(b);
        assert_eq!(d.recv(), Sent::Bye);
    }

    #[test]
    fn reject_reported_once() {
        let (b, next, attempts) = fake(1);
        next.send(Next::Reject("версия".into())).unwrap();
        next.send(Next::Reject("версия".into())).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while *attempts.lock().unwrap() < 3 {
            assert!(Instant::now() < deadline, "нет повторных попыток");
            std::thread::sleep(Duration::from_millis(2));
        }
        let s = b.state();
        assert_eq!(s.conn, Conn::DaemonDown);
        assert_eq!(s.errors.len(), 1, "{:?}", s.errors);
        assert!(s.errors[0].contains("версия"));
    }

    /// Настоящий Unix-сокет `tunnel-ipc` и `IpcClient`: рукопожатие, снимок, команда.
    #[cfg(unix)]
    #[test]
    fn real_unix_socket_end_to_end() {
        use tunnel_ipc::{ClientMsg, Listener, read_msg, write_msg};
        let dir = std::env::temp_dir().join(format!("tray-ipc-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let path = dir.join("d.sock");
        let _ = std::fs::remove_file(&path);
        let l = Listener::bind(&path).unwrap();
        let daemon = std::thread::spawn(move || {
            let mut c = l.accept().unwrap();
            let hello: ClientMsg = read_msg(&mut c).unwrap();
            assert!(matches!(hello, ClientMsg::Hello { kind: ClientKind::Tray, .. }));
            write_msg(&mut c, &DaemonMsg::Welcome { proto: 1, daemon_ver: "t".into(), me: json!({"my_code": "SOCK"}) })
                .unwrap();
            let sub: ClientMsg = read_msg(&mut c).unwrap();
            assert!(matches!(sub, ClientMsg::Subscribe { .. }));
            write_msg(&mut c, &DaemonMsg::Snapshot { seq: 1, snap: fixture() }).unwrap();
            let req: ClientMsg = read_msg(&mut c).unwrap();
            let ClientMsg::Req { id, cmd } = req else { panic!("ожидался Req: {req:?}") };
            assert_eq!(cmd, json!({"Leave": 3}));
            write_msg(&mut c, &DaemonMsg::Ack { id, result: AckResult::Err("занято".into()) }).unwrap();
            // Держим соединение, пока трей не закроется.
            let _ = read_msg::<_, ClientMsg>(&mut c);
        });
        let b = IpcTrayBackend::with_transport(IpcTransport::new(&path), Duration::from_millis(20));
        let s = wait(&b, "снимок по сокету", |s| s.conn == Conn::Connected);
        assert_eq!(s.my_code.as_deref(), Some("SOCK"));
        b.act(Action::ToggleGroup { gid: 3, join: false });
        let s = wait(&b, "Ack по сокету", |s| !s.errors.is_empty());
        assert_eq!(s.errors, vec!["Не удалось выйти из группы: занято".to_string()]);
        drop(b);
        daemon.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
