//! Движок клиента v2: управляющее соединение с сервером + туннель групп.
//!
//! Движок ничего не знает о UI: он публикует состояние (groups/meta/stats)
//! и шлёт события в канал; команды UI → движок идут через канал Cmd.
//! При потере сервера переподключается с нарастающим интервалом.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tunnel_protocol as proto;
use proto::ctrl;
use proto::payloads;

use crate::store::Config;

const MTU: usize = 1400;
const RING_CAPACITY: u32 = 0x40_0000; // 4 MiB
const TICK: Duration = Duration::from_millis(250);
const RTT_EVERY: Duration = Duration::from_secs(1);
const NAT_EVERY: Duration = Duration::from_secs(5);
const LIST_EVERY: Duration = Duration::from_secs(10);
const SERVER_TIMEOUT: Duration = Duration::from_secs(20);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
const HISTORY_LEN: usize = 60;
const NEW_GROUP_GRACE: Duration = Duration::from_secs(10);

static DEBUG: AtomicBool = AtomicBool::new(false);
pub fn set_debug(on: bool) {
    DEBUG.store(on, Ordering::Relaxed);
}
fn debug() -> bool {
    DEBUG.load(Ordering::Relaxed)
}

// ---------- состояние, открытое для UI ----------

#[derive(Clone)]
pub struct PeerSess {
    pub pubkey: [u8; 32],
    pub name: String,
    pub status: String,
    pub online: bool,
    pub ip: u32,
    pub endpoint: Option<SocketAddr>,
    pub direct: bool,
    pub last_rx: Instant,
    pub rtt_ms: Option<u64>,
}

#[derive(Clone)]
pub struct GroupSess {
    pub key: proto::SymKey,
    pub name: String,
    pub owner: [u8; 32],
    pub private: bool,
    pub my_ip: u32,
    pub since: Instant,
    /// ip → пир.
    pub members: HashMap<u32, PeerSess>,
}

pub type Groups = Arc<Mutex<HashMap<u32, GroupSess>>>;

/// Глобальные счётчики туннеля (атомарные, читаются UI в любой момент).
pub struct Stats {
    pub rx_bytes: AtomicU64,
    pub tx_bytes: AtomicU64,
    pub rx_pkts: AtomicU64,
    pub tx_pkts: AtomicU64,
}

impl Stats {
    fn new() -> Self {
        Self {
            rx_bytes: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            rx_pkts: AtomicU64::new(0),
            tx_pkts: AtomicU64::new(0),
        }
    }
}

/// Метаданные для статус-бара UI.
pub struct Meta {
    pub connected: bool,
    pub server: SocketAddr,
    pub server_label: String,
    pub group_list: Vec<payloads::GroupSummary>,
    /// Байт/с по последним секундам (для спарклайна).
    pub rx_hist: VecDeque<u64>,
    pub tx_hist: VecDeque<u64>,
    pub started: Instant,
}

impl Meta {
    fn push_hist(&mut self, rx: u64, tx: u64) {
        self.rx_hist.push_back(rx);
        self.tx_hist.push_back(tx);
        while self.rx_hist.len() > HISTORY_LEN {
            self.rx_hist.pop_front();
        }
        while self.tx_hist.len() > HISTORY_LEN {
            self.tx_hist.pop_front();
        }
    }
}

/// События движок → UI.
#[derive(Clone)]
pub enum Event {
    Connected(SocketAddr),
    Disconnected(String),
    GroupJoined { gid: u32, name: String, my_ip: u32 },
    GroupLeft { gid: u32, name: String },
    GroupDeleted { gid: u32, name: String },
    Kicked { gid: u32, name: String },
    PeerOnline { gid: u32, ip: u32, name: String },
    PeerOffline { gid: u32, ip: u32, name: String },
    /// Установлен прямой p2p-канал с пиром.
    Direct { gid: u32, ip: u32, name: String },
    Invite { gid: u32, group_name: String, from_name: String },
    FriendGroups { pubkey: [u8; 32], items: Vec<payloads::FriendGroup> },
    Error(String),
    Notice(String),
}

/// Команды UI → движок.
#[derive(Clone)]
pub enum Cmd {
    RefreshList,
    Create { name: String, private: bool },
    Join(u32),
    Leave(u32),
    Delete(u32),
    Rename(u32, String),
    Invite(u32, [u8; 32]),
    Kick(u32, [u8; 32]),
    Ban(u32, [u8; 32]),
    SetName(String),
    SetStatus(String),
    /// Переключить автовход в группу (локальная настройка).
    ToggleAutojoin(u32),
    FriendGroups([u8; 32]),
    Quit,
}

/// Всё, что нужно UI от движка.
pub struct Engine {
    pub groups: Groups,
    pub meta: Arc<Mutex<Meta>>,
    pub stats: Arc<Stats>,
    pub my_pub: [u8; 32],
    pub my_code: String,
    pub events: mpsc::Receiver<Event>,
    pub cmds: mpsc::Sender<Cmd>,
    pub cfg: Arc<Mutex<Config>>,
    /// Колбэк сохранения конфига (UI может править client.json напрямую).
    save: Arc<dyn Fn(&Config) + Send + Sync>,
}

impl Engine {
    /// Сохраняет конфиг через колбэк движка.
    pub fn save_config(&self, cfg: &Config) -> Result<()> {
        (self.save)(cfg);
        Ok(())
    }
}

// ---------- общий контекст потоков ----------

struct Env {
    groups: Groups,
    meta: Arc<Mutex<Meta>>,
    stats: Arc<Stats>,
    ev: mpsc::Sender<Event>,
    cfg: Arc<Mutex<Config>>,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
    identity: proto::Identity,
    server: SocketAddr,
    /// Кому адресован ответ FRIEND_GROUPS_RESP.
    pending_friend: Mutex<Option<[u8; 32]>>,
}

impl Env {
    fn emit(&self, e: Event) {
        let _ = self.ev.send(e);
    }

    fn autojoin_add(&self, gid: u32) {
        let mut cfg = self.cfg.lock().unwrap();
        if !cfg.autojoin.contains(&gid) {
            cfg.autojoin.push(gid);
            (self.save)(&cfg);
        }
    }

    fn autojoin_remove(&self, gid: u32) {
        let mut cfg = self.cfg.lock().unwrap();
        let before = cfg.autojoin.len();
        cfg.autojoin.retain(|g| *g != gid);
        if cfg.autojoin.len() != before {
            (self.save)(&cfg);
        }
    }

    fn set_name(&self, name: String) {
        let mut cfg = self.cfg.lock().unwrap();
        cfg.name = name;
        (self.save)(&cfg);
    }

    fn set_status(&self, text: String) {
        let mut cfg = self.cfg.lock().unwrap();
        cfg.status = text;
        (self.save)(&cfg);
    }
}

fn epoch_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Имя группы в кавычках (из текста ERROR).
fn quoted(s: &str) -> Option<String> {
    let a = s.find('"')?;
    let rest = &s[a + 1..];
    let b = rest.find('"')?;
    Some(rest[..b].to_string())
}

// ---------- управляющее соединение ----------

pub struct CtrlConn {
    pub sock: Arc<UdpSocket>,
    pub ctrl_key: proto::SymKey,
    pub server: SocketAddr,
}

impl CtrlConn {
    /// HELLO (открытый текст + подпись) → WELCOME (открытый текст: x_pub
    /// сервера + подпись ed25519; клиент pinned ed-ключ → канал защищён).
    pub fn connect(
        cfg: &Config,
        server: SocketAddr,
        server_pub: &[u8; 32],
        identity: &proto::Identity,
    ) -> Result<Self> {
        let sock = Arc::new(UdpSocket::bind("0.0.0.0:0").context("bind udp")?);
        let sign_msg = payloads::hello_sign_bytes(
            &identity.ed_pub(),
            &identity.x_pub(),
            &cfg.name,
            proto::PROTOCOL_VERSION,
        );
        let sig = identity.sign(&sign_msg);
        let hello = payloads::enc_hello(
            &identity.ed_pub(),
            &identity.x_pub(),
            &cfg.name,
            proto::PROTOCOL_VERSION,
            &sig,
        );
        sock.send_to(&proto::plain_frame(ctrl::HELLO, &hello), server)?;

        sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let deadline = Instant::now() + Duration::from_secs(10);
        let ctrl_key;
        loop {
            if Instant::now() > deadline {
                anyhow::bail!("нет WELCOME от сервера (адрес/код сервера верны?)");
            }
            let mut buf = vec![0u8; 65_535];
            let (n, src) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if src != server {
                continue;
            }
            let (typ, body) = match proto::split_frame(&buf[..n]) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if typ != ctrl::WELCOME {
                continue;
            }
            let (x_pub, w_sig) = payloads::dec_welcome(body)?;
            proto::Identity::verify(server_pub, &x_pub, &w_sig).context("WELCOME signature")?;
            ctrl_key = identity.ctrl_key_with(&x_pub);
            break;
        }
        Ok(Self {
            ctrl_key,
            server,
            sock,
        })
    }

    pub fn send_ctrl(&self, typ: u8, payload: &[u8]) {
        let _ = self
            .sock
            .send_to(&proto::seal_ctrl(&self.ctrl_key, typ, payload), self.server);
    }

    /// Повторный HELLO (та же identity, новое имя) — сервер обновит имя.
    pub fn resend_hello(&self, cfg: &Config, identity: &proto::Identity) {
        let sign_msg = payloads::hello_sign_bytes(
            &identity.ed_pub(),
            &identity.x_pub(),
            &cfg.name,
            proto::PROTOCOL_VERSION,
        );
        let sig = identity.sign(&sign_msg);
        let hello = payloads::enc_hello(
            &identity.ed_pub(),
            &identity.x_pub(),
            &cfg.name,
            proto::PROTOCOL_VERSION,
            &sig,
        );
        let _ = self.sock.send_to(&proto::plain_frame(ctrl::HELLO, &hello), self.server);
    }

    /// Ждёт фрейм конкретного типа; ERROR превращает в Err; прочее игнорируется.
    pub fn wait_for(&self, expect: u8, timeout: Duration) -> Result<Vec<u8>> {
        let deadline = Instant::now() + timeout;
        self.sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
        loop {
            if Instant::now() > deadline {
                anyhow::bail!("таймаут ожидания {expect:#04x} от сервера");
            }
            let mut buf = vec![0u8; 65_535];
            let (n, src) = match self.sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if src != self.server {
                continue;
            }
            let (typ, body) = match proto::split_frame(&buf[..n]) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if (proto::grp::DATA..=proto::grp::KEEPALIVE).contains(&typ) {
                continue;
            }
            let payload = match proto::open_ctrl(&self.ctrl_key, typ, body) {
                Ok(p) => p,
                Err(_) => continue,
            };
            if typ == ctrl::ERROR {
                anyhow::bail!("сервер: {}", payloads::dec_error(&payload).unwrap_or_default());
            }
            if typ == expect {
                return Ok(payload);
            }
        }
    }
}

// ---------- запуск ----------

/// Заглушка дата-сокета до первого подключения: tun-поток читает текущий
/// сокет сам, поэтому значение заменяется при успешном connect.
fn conn_sock_placeholder() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind("0.0.0.0:0").expect("bind placeholder socket"))
}

/// Загружает Wintun, создаёт адаптер, запускает потоки и возвращает дескриптор
/// движка. Первое подключение выполняется синхронно (ошибка видна вызывающему).
pub fn start(
    cfg: Arc<Mutex<Config>>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    adapter_name: &str,
    dll: Option<String>,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
) -> Result<Engine> {
    let (ev_tx, ev_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel();

    let stats = Arc::new(Stats::new());
    let server_label = cfg
        .lock()
        .unwrap()
        .servers
        .iter()
        .find(|s| s.addr.parse::<SocketAddr>().as_ref() == Ok(&server))
        .map(|s| s.label.clone())
        .unwrap_or_default();
    let meta = Arc::new(Mutex::new(Meta {
        connected: false,
        server,
        server_label,
        group_list: Vec::new(),
        rx_hist: VecDeque::new(),
        tx_hist: VecDeque::new(),
        started: Instant::now(),
    }));

    // --- адаптер (один на все группы) ---
    let wintun = crate::tun::load_wintun_dll(dll.as_deref())?;
    let adapter = crate::tun::create_adapter(&wintun, adapter_name)?;
    crate::tun::set_mtu(&adapter, MTU)?;
    crate::tun::allow_firewall(adapter_name);
    let session = Arc::new(adapter.start_session(RING_CAPACITY)?);
    *TUN_SESSION.lock().unwrap() = Some(session.clone());
    let configured: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

    let groups: Groups = Arc::new(Mutex::new(HashMap::new()));
    // Текущий дата-сокет (меняется при реконнекте); tun-поток берёт его сам.
    let cur_sock: Arc<RwLock<Arc<UdpSocket>>> = Arc::new(RwLock::new(conn_sock_placeholder()));

    let save_arc = save.clone();
    let env = Arc::new(Env {
        groups: groups.clone(),
        meta: meta.clone(),
        stats: stats.clone(),
        ev: ev_tx,
        cfg: cfg.clone(),
        save,
        identity,
        server,
        pending_friend: Mutex::new(None),
    });
    let my_pub = env.identity.ed_pub();
    let my_code = env.identity.friend_code();

    // Первое подключение — синхронно. Событие Connected эмитится один раз —
    // из engine_loop (иначе «подключено» дублируется в логе TUI).
    let cfg_snap = env.cfg.lock().unwrap().clone();
    let conn = CtrlConn::connect(&cfg_snap, server, &server_pub, &env.identity)?;
    *cur_sock.write().unwrap() = conn.sock.clone();
    env.meta.lock().unwrap().connected = true;

    spawn_tun_thread(
        session.clone(),
        groups.clone(),
        cur_sock.clone(),
        server,
        stats.clone(),
    );
    spawn_sampler(env.clone());

    let env2 = env.clone();
    thread::Builder::new()
        .name("engine".into())
        .spawn(
            move || engine_loop(env2, cmd_rx, conn, server_pub, adapter, configured, session, cur_sock),
        )
        .expect("spawn engine thread");

    Ok(Engine {
        groups,
        meta,
        stats,
        my_pub,
        my_code,
        events: ev_rx,
        cmds: cmd_tx,
        cfg,
        save: save_arc,
    })
}

// Сессия TUN, общая для recv-потока (вброс) и tun-потока (чтение).
static TUN_SESSION: Mutex<Option<Arc<wintun::Session>>> = Mutex::new(None);

#[derive(Clone, Copy)]
enum Flow {
    Continue,
    Quit,
}

/// Главный цикл: подключение → сессия → потеря → пауза → снова.
fn engine_loop(
    env: Arc<Env>,
    cmd_rx: mpsc::Receiver<Cmd>,
    conn: CtrlConn,
    server_pub: [u8; 32],
    adapter: Arc<wintun::Adapter>,
    configured: Arc<Mutex<HashSet<u32>>>,
    session: Arc<wintun::Session>,
    cur_sock: Arc<RwLock<Arc<UdpSocket>>>,
) {
    let mut backoff = Duration::from_secs(1);
    let mut cur: Option<CtrlConn> = Some(conn);
    loop {
        if cur.is_none() {
            if !sleep_with_quit(&env, &cmd_rx, backoff) {
                return;
            }
            backoff = (backoff * 2).min(RECONNECT_MAX);
            let cfg_snap = env.cfg.lock().unwrap().clone();
            match CtrlConn::connect(&cfg_snap, env.server, &server_pub, &env.identity) {
                Ok(c) => {
                    backoff = Duration::from_secs(1);
                    // Новый дата-сокет — tun-поток должен писать в него.
                    *cur_sock.write().unwrap() = c.sock.clone();
                    cur = Some(c);
                }
                Err(e) => {
                    env.emit(Event::Error(format!("сервер недоступен: {e}")));
                }
            }
            continue;
        }
        let c = cur.as_ref().unwrap();
        env.meta.lock().unwrap().connected = true;
        env.emit(Event::Connected(env.server));

        // Приветствие: статус, авто-джойн, список групп.
        let cfg_snap = env.cfg.lock().unwrap().clone();
        if !cfg_snap.status.is_empty() {
            c.send_ctrl(ctrl::STATUS, &payloads::enc_status(&cfg_snap.status));
        }
        for gid in &cfg_snap.autojoin {
            c.send_ctrl(ctrl::JOIN_GROUP, &payloads::enc_gid(*gid));
        }
        c.send_ctrl(ctrl::LIST_GROUPS, &payloads::enc_gid(0));

        match session_loop(&env, &cmd_rx, c, &adapter, &configured, &session) {
            Flow::Quit => return,
            Flow::Continue => {}
        }
        env.meta.lock().unwrap().connected = false;
        env.emit(Event::Disconnected("сервер не отвечает".into()));
        cur = None;
    }
}

/// Пауза между попытками реконнекта; false = получен Quit.
fn sleep_with_quit(_env: &Env, cmd_rx: &mpsc::Receiver<Cmd>, d: Duration) -> bool {
    let end = Instant::now() + d;
    loop {
        let now = Instant::now();
        if now >= end {
            return true;
        }
        if let Ok(Cmd::Quit) = cmd_rx.try_recv() {
            return false;
        }
        thread::sleep((Duration::from_millis(100)).min(end - now));
    }
}

// ---------- цикл сессии ----------

fn session_loop(
    env: &Env,
    cmd_rx: &mpsc::Receiver<Cmd>,
    conn: &CtrlConn,
    adapter: &wintun::Adapter,
    configured: &Mutex<HashSet<u32>>,
    session: &Arc<wintun::Session>,
) -> Flow {
    let mut buf = vec![0u8; 65_535];
    conn.sock.set_read_timeout(Some(TICK)).ok();
    let mut last_rx = Instant::now();
    let mut last_rtt = Instant::now();
    let mut last_nat = Instant::now();
    let mut last_list = Instant::now();

    loop {
        // 1. Команды UI.
        loop {
            match cmd_rx.try_recv() {
                Ok(cmd) => {
                    if let Flow::Quit = do_cmd(env, conn, cmd) {
                        return Flow::Quit;
                    }
                }
                Err(_) => break,
            }
        }
        // 2. Приём.
        let (n, src) = match conn.sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                let now = Instant::now();
                if now.duration_since(last_rx) > SERVER_TIMEOUT {
                    return Flow::Continue; // реконнект
                }
                if now.duration_since(last_rtt) >= RTT_EVERY {
                    last_rtt = now;
                    rtt_round(env, &conn.sock);
                }
                if now.duration_since(last_nat) >= NAT_EVERY {
                    last_nat = now;
                    nat_round(env, conn);
                }
                if now.duration_since(last_list) >= LIST_EVERY {
                    last_list = now;
                    conn.send_ctrl(ctrl::LIST_GROUPS, &payloads::enc_gid(0));
                }
                continue;
            }
            Err(e) if e.kind() == std::io::ErrorKind::ConnectionReset => {
                // Windows: send_to в мёртвый эндпоинт (NAT-punch офлайн-пиру,
                // PING по устаревшему endpoint) даёт ICMP unreachable, и
                // следующий recv_from возвращает WSAECONNRESET. Это не потеря
                // связи с сервером — съедаем ошибку и продолжаем сессию.
                // (Несколько reset'ов = несколько ошибок, каждая съедается
                // своим recv_from.) Без этого сессия рвалась бы и клиент
                // переподключался каждые NAT_EVERY.
                continue;
            }
            Err(e) => {
                env.emit(Event::Error(format!("recv: {e}")));
                return Flow::Continue;
            }
        };
        last_rx = Instant::now();
        let datagram = &buf[..n];
        let (typ, body) = match proto::split_frame(datagram) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if (proto::grp::DATA..=proto::grp::KEEPALIVE).contains(&typ) {
            handle_group_frame(env, session, &conn.sock, src, env.server, datagram);
            continue;
        }
        let payload = match proto::open_ctrl(&conn.ctrl_key, typ, body) {
            Ok(p) => p,
            Err(_) => continue, // например, WELCOME на resend_hello (открытый текст)
        };
        on_ctrl(env, conn, adapter, configured, typ, &payload);
    }
}

fn do_cmd(env: &Env, conn: &CtrlConn, cmd: Cmd) -> Flow {
    match cmd {
        Cmd::Quit => return Flow::Quit,
        Cmd::RefreshList => conn.send_ctrl(ctrl::LIST_GROUPS, &payloads::enc_gid(0)),
        Cmd::Create { name, private } => {
            conn.send_ctrl(ctrl::CREATE_GROUP, &payloads::enc_create_group(&name, private))
        }
        Cmd::Join(gid) => conn.send_ctrl(ctrl::JOIN_GROUP, &payloads::enc_gid(gid)),
        Cmd::Leave(gid) => {
            conn.send_ctrl(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
            let name = env.groups.lock().unwrap().get(&gid).map(|g| g.name.clone());
            if let Some(name) = name {
                env.groups.lock().unwrap().remove(&gid);
                env.autojoin_remove(gid);
                env.emit(Event::GroupLeft { gid, name });
            }
        }
        Cmd::Delete(gid) => conn.send_ctrl(ctrl::DELETE_GROUP, &payloads::enc_gid(gid)),
        Cmd::Rename(gid, name) => {
            conn.send_ctrl(ctrl::RENAME_GROUP, &payloads::enc_rename(gid, &name))
        }
        Cmd::Invite(gid, pk) => {
            conn.send_ctrl(ctrl::INVITE, &payloads::enc_gid_target(gid, &pk))
        }
        Cmd::Kick(gid, pk) => conn.send_ctrl(ctrl::KICK, &payloads::enc_gid_target(gid, &pk)),
        Cmd::Ban(gid, pk) => conn.send_ctrl(ctrl::BAN, &payloads::enc_gid_target(gid, &pk)),
        Cmd::SetName(name) => {
            env.set_name(name);
            let cfg = env.cfg.lock().unwrap().clone();
            conn.resend_hello(&cfg, &env.identity);
        }
        Cmd::SetStatus(text) => {
            env.set_status(text);
            let cfg = env.cfg.lock().unwrap().clone();
            if !cfg.status.is_empty() {
                conn.send_ctrl(ctrl::STATUS, &payloads::enc_status(&cfg.status));
            }
        }
        Cmd::ToggleAutojoin(gid) => {
            let on = env.cfg.lock().unwrap().autojoin.contains(&gid);
            if on {
                env.autojoin_remove(gid);
            } else {
                env.autojoin_add(gid);
            }
        }
        Cmd::FriendGroups(pk) => {
            *env.pending_friend.lock().unwrap() = Some(pk);
            conn.send_ctrl(ctrl::FRIEND_GROUPS, &payloads::enc_pubkey(&pk));
        }
    }
    Flow::Continue
}

fn on_ctrl(
    env: &Env,
    conn: &CtrlConn,
    adapter: &wintun::Adapter,
    configured: &Mutex<HashSet<u32>>,
    typ: u8,
    payload: &[u8],
) {
    match typ {
        ctrl::GROUP_STATE => {
            if let Ok(st) = payloads::dec_group_state(payload) {
                apply_group_state(env, adapter, configured, &st);
            }
        }
        ctrl::GROUP_LIST => {
            if let Ok(items) = payloads::dec_group_list(payload) {
                env.meta.lock().unwrap().group_list = items.clone();
                reconcile(env, &items);
            }
        }
        ctrl::INVITE_RCVD => {
            if let Ok(inv) = payloads::dec_invite(payload) {
                env.emit(Event::Invite {
                    gid: inv.gid,
                    group_name: inv.group_name.clone(),
                    from_name: inv.from_name.clone(),
                });
                let in_autojoin = env.cfg.lock().unwrap().autojoin.contains(&inv.gid);
                if in_autojoin {
                    conn.send_ctrl(ctrl::JOIN_GROUP, &payloads::enc_gid(inv.gid));
                }
            }
        }
        ctrl::ERROR => {
            if let Ok(text) = payloads::dec_error(payload) {
                handle_error(env, text);
            }
        }
        ctrl::FRIEND_GROUPS_RESP => {
            if let Ok(items) = payloads::dec_friend_groups(payload) {
                let pk = env.pending_friend.lock().unwrap().take().unwrap_or([0; 32]);
                env.emit(Event::FriendGroups { pubkey: pk, items });
            }
        }
        _ => {}
    }
}

/// Ошибка от сервера. «Кик» парсим по тексту и убираем группу локально
/// (сервер кикнутому GROUP_STATE не шлёт).
fn handle_error(env: &Env, text: String) {
    if text.contains("кикнул") {
        if let Some(name) = quoted(&text) {
            let found = {
                let g = env.groups.lock().unwrap();
                g.iter().find(|(_, gs)| gs.name == name).map(|(gid, gs)| (*gid, gs.name.clone()))
            };
            if let Some((gid, gname)) = found {
                env.groups.lock().unwrap().remove(&gid);
                env.autojoin_remove(gid);
                env.emit(Event::Kicked { gid, name: gname });
                return;
            }
        }
    }
    env.emit(Event::Error(text));
}

/// Локальные группы, которых больше нет на сервере (могли кикнуть/удалить,
/// пока нас не было) — убрать.
fn reconcile(env: &Env, items: &[payloads::GroupSummary]) {
    let mine: HashSet<u32> = items.iter().filter(|g| g.mine).map(|g| g.gid).collect();
    let now = Instant::now();
    let stale: Vec<(u32, String)> = {
        let g = env.groups.lock().unwrap();
        g.iter()
            .filter(|(gid, gs)| !mine.contains(gid) && now.duration_since(gs.since) > NEW_GROUP_GRACE)
            .map(|(gid, gs)| (*gid, gs.name.clone()))
            .collect()
    };
    for (gid, name) in stale {
        env.groups.lock().unwrap().remove(&gid);
        env.autojoin_remove(gid);
        env.emit(Event::Notice(format!("группа {name} больше недоступна")));
    }
}

// ---------- состояние групп ----------

fn apply_group_state(
    env: &Env,
    adapter: &wintun::Adapter,
    configured: &Mutex<HashSet<u32>>,
    st: &payloads::GroupState,
) {
    let my_pub = env.identity.ed_pub();
    if st.deleted {
        let removed = { env.groups.lock().unwrap().remove(&st.gid).map(|g| g.name) };
        if let Some(name) = removed {
            env.autojoin_remove(st.gid);
            env.emit(Event::GroupDeleted { gid: st.gid, name });
        }
        return;
    }
    let mut events: Vec<Event> = Vec::new();
    let (need_addr, is_new) = {
        let mut g = env.groups.lock().unwrap();
        let is_new = !g.contains_key(&st.gid);
        let entry = g.entry(st.gid).or_insert_with(|| GroupSess {
            key: st.key,
            name: st.name.clone(),
            owner: st.owner,
            private: st.private,
            my_ip: st.my_ip,
            since: Instant::now(),
            members: HashMap::new(),
        });
        entry.key = st.key;
        entry.name = st.name.clone();
        entry.owner = st.owner;
        entry.private = st.private;
        entry.my_ip = st.my_ip;
        // Пересобрать members, сохранив direct/rtt по pubkey.
        let old: HashMap<[u8; 32], PeerSess> = entry
            .members
            .drain()
            .map(|(_ip, p)| (p.pubkey, p))
            .collect();
        entry.members = HashMap::new();
        for m in &st.members {
            if m.pubkey == my_pub {
                continue;
            }
            let prev = old.get(&m.pubkey);
            let direct = prev.map(|p| p.direct).unwrap_or(false);
            let rtt = prev.and_then(|p| p.rtt_ms);
            let endpoint = m
                .endpoint
                .as_deref()
                .and_then(|e| e.parse().ok())
                .or_else(|| prev.and_then(|p| p.endpoint));
            if prev.map(|p| p.online) != Some(m.online) {
                if m.online {
                    events.push(Event::PeerOnline { gid: st.gid, ip: m.ip, name: m.name.clone() });
                } else if prev.is_some() {
                    events.push(Event::PeerOffline { gid: st.gid, ip: m.ip, name: m.name.clone() });
                }
            }
            entry.members.insert(
                m.ip,
                PeerSess {
                    pubkey: m.pubkey,
                    name: m.name.clone(),
                    status: m.status.clone(),
                    online: m.online,
                    ip: m.ip,
                    endpoint,
                    direct,
                    last_rx: prev.map(|p| p.last_rx).unwrap_or_else(Instant::now),
                    rtt_ms: rtt,
                },
            );
        }
        let cfg = configured.lock().unwrap();
        (!cfg.contains(&st.my_ip), is_new)
    };
    if is_new {
        env.emit(Event::GroupJoined {
            gid: st.gid,
            name: st.name.clone(),
            my_ip: st.my_ip,
        });
        env.autojoin_add(st.gid);
    }
    if need_addr {
        let mut cfg = configured.lock().unwrap();
        if let Err(e) = crate::tun::ensure_address(adapter, &mut cfg, st.my_ip) {
            if debug() {
                env.emit(Event::Error(format!("netsh address: {e}")));
            }
        }
    }
    for ev in events {
        env.emit(ev);
    }
}

// ---------- групповые фреймы ----------

fn handle_group_frame(
    env: &Env,
    session: &Arc<wintun::Session>,
    sock: &UdpSocket,
    src: SocketAddr,
    server: SocketAddr,
    datagram: &[u8],
) {
    env.stats.rx_pkts.fetch_add(1, Ordering::Relaxed);
    env.stats.rx_bytes.fetch_add(datagram.len() as u64, Ordering::Relaxed);
    let (gid, _src_ip, _dst_ip) = match proto::parse_group_header(datagram) {
        Ok(x) => x,
        Err(_) => return,
    };
    let (key, my_ip) = {
        let g = env.groups.lock().unwrap();
        match g.get(&gid) {
            Some(gs) => (gs.key, gs.my_ip),
            None => return,
        }
    };
    let (typ, _gid, src_ip, dst_ip, payload) = match proto::open_group(&key, datagram) {
        Ok(x) => x,
        Err(_) => return,
    };
    let is_relay = src == server;
    {
        // Атрибуция отправителя по src_ip из заголовка.
        let mut g = env.groups.lock().unwrap();
        if let Some(gs) = g.get_mut(&gid) {
            if let Some(peer) = gs.members.get_mut(&src_ip) {
                if !is_relay {
                    if !peer.direct {
                        peer.direct = true;
                        peer.endpoint = Some(src);
                        env.emit(Event::Direct {
                            gid,
                            ip: src_ip,
                            name: peer.name.clone(),
                        });
                    } else {
                        peer.endpoint = Some(src);
                    }
                }
                peer.last_rx = Instant::now();
            }
        }
    }
    match typ {
        proto::grp::DATA => {
            if dst_ip == my_ip {
                if let Err(e) = inject_packet(session, &payload) {
                    if debug() {
                        env.emit(Event::Error(format!("inject: {e}")));
                    }
                }
            }
        }
        proto::grp::PING => {
            let frame = proto::seal_group(&key, proto::grp::PONG, gid, my_ip, src_ip, &payload);
            let _ = sock.send_to(&frame, src);
        }
        proto::grp::PONG => {
            if let Ok(sent_ms) = payloads::dec_ping(&payload) {
                let rtt = epoch_ms().saturating_sub(sent_ms);
                let mut g = env.groups.lock().unwrap();
                if let Some(gs) = g.get_mut(&gid) {
                    if let Some(peer) = gs.members.get_mut(&src_ip) {
                        peer.rtt_ms = Some(rtt);
                    }
                }
                if debug() {
                    env.emit(Event::Notice(format!(
                        "rtt {gid}/{}: {rtt} мс",
                        proto::ip_str(src_ip)
                    )));
                }
            }
        }
        proto::grp::PUNCH => {
            let frame = proto::seal_group(&key, proto::grp::PUNCH, gid, my_ip, src_ip, &[]);
            let _ = sock.send_to(&frame, src);
        }
        _ => {}
    }
}

fn inject_packet(session: &Arc<wintun::Session>, packet: &[u8]) -> Result<()> {
    let mut p = session
        .allocate_send_packet(packet.len().try_into().unwrap())
        .context("allocate_send_packet")?;
    p.bytes_mut().copy_from_slice(packet);
    session.send_packet(p);
    Ok(())
}

// ---------- раунды RTT и NAT ----------

/// Раз в секунду: RTT-зонд каждому пиру (direct — напрямую, иначе через релей).
fn rtt_round(env: &Env, sock: &UdpSocket) {
    let now_ms = epoch_ms();
    let tasks: Vec<(u32, proto::SymKey, u32, u32, SocketAddr)> = {
        let g = env.groups.lock().unwrap();
        let mut out = Vec::new();
        for (gid, gs) in g.iter() {
            for (ip, peer) in &gs.members {
                let Some(ep) = peer.endpoint else { continue };
                let target = if peer.direct { ep } else { env.server };
                out.push((*gid, gs.key, gs.my_ip, *ip, target));
            }
        }
        out
    };
    for (gid, key, my_ip, peer_ip, target) in tasks {
        let ping = proto::seal_group(
            &key,
            proto::grp::PING,
            gid,
            my_ip,
            peer_ip,
            &payloads::enc_ping(now_ms),
        );
        let _ = sock.send_to(&ping, target);
    }
}

/// Раз в 5 секунд: CTRL_PING серверу + PUNCH/KEEPALIVE пирам (NAT-маппинги).
fn nat_round(env: &Env, conn: &CtrlConn) {
    conn.send_ctrl(ctrl::CTRL_PING, &[]);
    let tasks: Vec<(u32, proto::SymKey, u32, u32, SocketAddr)> = {
        let g = env.groups.lock().unwrap();
        let mut out = Vec::new();
        for (gid, gs) in g.iter() {
            for (ip, peer) in &gs.members {
                if let Some(ep) = peer.endpoint {
                    out.push((*gid, gs.key, gs.my_ip, *ip, ep));
                }
            }
        }
        out
    };
    for (gid, key, my_ip, peer_ip, ep) in tasks {
        let punch = proto::seal_group(&key, proto::grp::PUNCH, gid, my_ip, peer_ip, &[]);
        let _ = conn.sock.send_to(&punch, ep);
        let ka = proto::seal_group(&key, proto::grp::KEEPALIVE, gid, my_ip, peer_ip, &[]);
        let _ = conn.sock.send_to(&ka, ep);
    }
}

// ---------- фоновые потоки ----------

fn spawn_tun_thread(
    session: Arc<wintun::Session>,
    groups: Groups,
    cur_sock: Arc<RwLock<Arc<UdpSocket>>>,
    server: SocketAddr,
    stats: Arc<Stats>,
) {
    thread::Builder::new()
        .name("tun".into())
        .spawn(move || loop {
            let pkt = match session.receive_blocking() {
                Ok(p) => p,
                Err(_) => break,
            };
            let bytes = pkt.bytes();
            let dst = match proto::ipv4_dst(bytes) {
                Ok(d) => d,
                Err(_) => continue,
            };
            let gid = proto::group_of_ip(dst);
            let (key, my_ip, target) = {
                let g = groups.lock().unwrap();
                let Some(gs) = g.get(&gid) else { continue };
                if dst == gs.my_ip {
                    continue;
                }
                let target = match gs.members.get(&dst) {
                    Some(p) if p.direct => p.endpoint,
                    Some(p) => p.endpoint.or(Some(server)), // endpoint неизвестен → релей
                    None => Some(server),                   // не наш пир — пусть релей решит
                };
                match target {
                    Some(t) => (gs.key, gs.my_ip, t),
                    None => continue,
                }
            };
            let frame = proto::seal_group(&key, proto::grp::DATA, gid, my_ip, dst, bytes);
            stats.tx_pkts.fetch_add(1, Ordering::Relaxed);
            stats.tx_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
            // Сокет меняется при реконнекте — берём текущий на каждый пакет.
            let sock = cur_sock.read().unwrap().clone();
            let _ = sock.send_to(&frame, target);
        })
        .expect("spawn tun thread");
}

/// Раз в секунду: дельта счётчиков → история для спарклайна.
fn spawn_sampler(env: Arc<Env>) {
    thread::Builder::new()
        .name("sampler".into())
        .spawn(move || {
            let mut prev_rx = 0u64;
            let mut prev_tx = 0u64;
            loop {
                thread::sleep(Duration::from_secs(1));
                let rx = env.stats.rx_bytes.load(Ordering::Relaxed);
                let tx = env.stats.tx_bytes.load(Ordering::Relaxed);
                let d_rx = rx.saturating_sub(prev_rx);
                let d_tx = tx.saturating_sub(prev_tx);
                prev_rx = rx;
                prev_tx = tx;
                env.meta.lock().unwrap().push_hist(d_rx, d_tx);
            }
        })
        .expect("spawn sampler thread");
}

// ---------- CLI-режим (run): движок + печать событий ----------

pub fn run(
    cfg: Arc<Config>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    adapter_name: &str,
    dll: Option<String>,
) -> Result<()> {
    let shared = Arc::new(Mutex::new((*cfg).clone()));
    let eng = start(
        shared,
        server,
        server_pub,
        identity,
        adapter_name,
        dll,
        Arc::new(|_| {}),
    )?;
    while let Ok(ev) = eng.events.recv() {
        match ev {
            Event::Connected(s) => eprintln!("[engine] connected to {s}"),
            Event::Disconnected(r) => eprintln!("[engine] {r}; переподключение…"),
            Event::GroupJoined { gid, name, my_ip } => eprintln!(
                "[engine] группа {gid} ({}): мой IP {}",
                name,
                proto::ip_str(my_ip)
            ),
            Event::GroupLeft { gid, name } => eprintln!("[engine] вышли из {gid} ({name})"),
            Event::GroupDeleted { gid, name } => {
                eprintln!("[engine] группа {gid} ({name}) удалена")
            }
            Event::Kicked { name, .. } => eprintln!("[engine] вас кикнули из группы \"{name}\""),
            Event::PeerOnline { ip, name, .. } => {
                eprintln!("[engine] peer {} ({}) онлайн", proto::ip_str(ip), name)
            }
            Event::PeerOffline { ip, name, .. } => {
                eprintln!("[engine] peer {} ({}) офлайн", proto::ip_str(ip), name)
            }
            Event::Direct { gid, ip, name } => eprintln!(
                "[engine] peer {} ({}), группа {gid}: direct p2p",
                proto::ip_str(ip),
                name
            ),
            Event::Invite { gid, group_name, from_name } => eprintln!(
                "[engine] приглашение: {from_name} приглашает в группу {group_name} (gid {gid})"
            ),
            Event::FriendGroups { .. } => {}
            Event::Error(e) => eprintln!("[engine] {e}"),
            Event::Notice(n) => eprintln!("[engine] {n}"),
        }
    }
    Ok(())
}





