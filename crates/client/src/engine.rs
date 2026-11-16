//! Движок клиента v2: управляющее соединение с сервером + туннель групп.
//!
//! Движок ничего не знает о UI: он публикует состояние (groups/meta/stats)
//! и шлёт события в канал; команды UI → движок идут через канал Cmd.
//!
//! Потоки:
//! - `rx` — блокирующий приём с единственного UDP-сокета. Групповые фреймы
//!   (DATA/PING/PONG/PUNCH/KEEPALIVE) обрабатывает сам, сразу; управляющие
//!   фреймы сервера передаёт движку. P2P работает и пока сервер недоступен.
//! - `engine` — состояние соединения с сервером, команды UI, таймеры (RTT,
//!   NAT, CTRL_PING, список групп, повтор LEAVE). Таймеры идут по часам, а
//!   не по паузам в приёме: под нагрузкой они не «замерзают».
//! - `tun` — пакеты из адаптера → пирам (напрямую или через релей).
//! - `sampler` — раз в секунду скорость трафика для спарклайна.
//!
//! Сокет один на всё время работы: при реконнекте шлётся новый HELLO с того
//! же адреса, NAT-маппинги и прямые каналы с пирами не рвутся.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{SocketAddr, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use proto::ctrl;
use proto::payloads;
use tunnel_protocol as proto;

use crate::store::Config;

const MTU: usize = 1400;
const RING_CAPACITY: u32 = 0x40_0000; // 4 MiB
/// Шаг цикла движка (верхняя граница задержки таймеров).
const TICK: Duration = Duration::from_millis(100);
/// RTT-зонд онлайн-пирам. Для прямых каналов он же держит NAT-маппинг.
const RTT_EVERY: Duration = Duration::from_secs(2);
/// PUNCH онлайн-пирам без прямого канала.
const PUNCH_EVERY: Duration = Duration::from_secs(5);
/// CTRL_PING серверу (сервер держит сессию 30 с без пакетов).
const PING_EVERY: Duration = Duration::from_secs(5);
const LIST_EVERY: Duration = Duration::from_secs(15);
const SERVER_TIMEOUT: Duration = Duration::from_secs(20);
const RECONNECT_MAX: Duration = Duration::from_secs(30);
/// Нет прямых фреймов от пира столько — прямой канал считается потерянным,
/// трафик идёт через релей (пир сменил порт, NAT закрыл маппинг…).
const DIRECT_TIMEOUT: Duration = Duration::from_secs(12);
/// LEAVE повторяется, пока сервер не подтвердит выход списком групп.
const LEAVE_RETRY: Duration = Duration::from_secs(1);
const LEAVE_GIVE_UP: Duration = Duration::from_secs(20);
/// Окно INVITE_LIST, которого ждём (после HELLO или запрошенное
/// LIST_INVITES), запрашивается снова, пока не придёт: потерянное окно
/// иначе прятало бы приглашения до переподключения.
const INVITE_SYNC_RETRY: Duration = Duration::from_secs(3);
/// Старый сервер LIST_INVITES не знает и не отвечает — не спрашивать вечно.
const INVITE_SYNC_GIVE_UP: Duration = Duration::from_secs(20);
/// DECLINE_INVITE повторяется, пока сервер не подтвердит отказ окном списка.
const DECLINE_RETRY: Duration = Duration::from_secs(1);
const DECLINE_GIVE_UP: Duration = Duration::from_secs(20);
const HISTORY_LEN: usize = 60;
const NEW_GROUP_GRACE: Duration = Duration::from_secs(10);
/// Таймаут чтения rx-потока (как часто он проверяет флаг выхода).
const RX_POLL: Duration = Duration::from_millis(250);

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
    /// Последний фрейм пира, пришедший напрямую (не через релей).
    pub last_direct: Option<Instant>,
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
#[derive(Clone, Debug)]
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
    /// Приглашение в группу (в т.ч. повторная доставка неотвеченного после
    /// HELLO — UI должен убирать дубликаты по gid).
    Invite { gid: u32, group_name: String, from_pubkey: [u8; 32], from_name: String },
    /// Приглашённый отклонил наше приглашение (мы — владелец группы).
    InviteDeclined { gid: u32, group_name: String, by_pubkey: [u8; 32], by_name: String },
    /// Приглашение больше недействительно: группу удалили до ответа.
    InviteRevoked { gid: u32 },
    /// Сервер прислал окно списка неотвеченных приглашений (после HELLO,
    /// отказа, входа, отзыва BAN/KICK): приглашения с gid ≥ `from`, не больше
    /// 16. Других gid в покрытом окне уже нет — UI снимает их окна.
    /// `complete == false` — хвост не влез: окно достоверно только до
    /// последнего gid в нём, следующее движок дочитывает сам
    /// (LIST_INVITES). Каждое из `gids` перед этим пришло как
    /// [`Event::Invite`].
    InvitesSynced { gids: Vec<u32>, from: u32, complete: bool },
    FriendGroups { pubkey: [u8; 32], items: Vec<payloads::FriendGroup> },
    Error(String),
    Notice(String),
}

/// Команды UI → движок.
#[derive(Clone, Debug)]
pub enum Cmd {
    RefreshList,
    Create { name: String, private: bool },
    Join(u32),
    Leave(u32),
    Delete(u32),
    Rename(u32, String),
    Invite(u32, [u8; 32]),
    /// Отклонить приглашение в группу.
    DeclineInvite(u32),
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
    env: Arc<Env>,
}

impl Engine {
    /// Сохраняет конфиг через колбэк движка.
    pub fn save_config(&self, cfg: &Config) -> Result<()> {
        (self.save)(cfg);
        Ok(())
    }

    /// Локальный адрес UDP-сокета движка.
    #[allow(dead_code)]
    pub fn local_addr(&self) -> Option<SocketAddr> {
        self.env.sock.local_addr().ok()
    }

    /// Отправить IP-пакет в туннель так же, как это делает tun-поток
    /// (для тестов и отладки без адаптера).
    #[allow(dead_code)]
    pub fn send_ip_packet(&self, packet: &[u8]) {
        route_packet(&self.env, packet);
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Останавливаем потоки rx/engine (tun-поток завершится вместе с
        // сессией адаптера).
        self.env.quit.store(true, Ordering::Relaxed);
        let _ = self.cmds.send(Cmd::Quit);
    }
}

// ---------- устройство туннеля ----------

/// То, что движку нужно от сетевого адаптера. Реальная реализация — Wintun;
/// в тестах — заглушка, которая просто запоминает пакеты.
pub trait TunDev: Send + Sync {
    /// Вбросить IP-пакет «из сети» в систему.
    fn inject(&self, packet: &[u8]) -> Result<()>;
    /// Назначить адаптеру IP группы (идемпотентно).
    fn ensure_address(&self, ip: u32) -> Result<()>;
}

struct WintunDev {
    adapter: Arc<wintun::Adapter>,
    session: Arc<wintun::Session>,
    configured: Mutex<HashSet<u32>>,
}

impl TunDev for WintunDev {
    fn inject(&self, packet: &[u8]) -> Result<()> {
        let len: u16 = packet.len().try_into().context("packet too large")?;
        let mut p = self
            .session
            .allocate_send_packet(len)
            .context("allocate_send_packet")?;
        p.bytes_mut().copy_from_slice(packet);
        self.session.send_packet(p);
        Ok(())
    }

    fn ensure_address(&self, ip: u32) -> Result<()> {
        let mut cfg = self.configured.lock().unwrap();
        crate::tun::ensure_address(&self.adapter, &mut cfg, ip)
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
    /// Единственный UDP-сокет: и сервер, и пиры.
    sock: Arc<UdpSocket>,
    tun: Arc<dyn TunDev>,
    quit: AtomicBool,
    /// Кому адресован ответ FRIEND_GROUPS_RESP.
    pending_friend: Mutex<Option<[u8; 32]>>,
}

impl Env {
    fn emit(&self, e: Event) {
        let _ = self.ev.send(e);
    }

    fn quitting(&self) -> bool {
        self.quit.load(Ordering::Relaxed)
    }

    fn send(&self, frame: &[u8], to: SocketAddr) {
        if self.sock.send_to(frame, to).is_ok() {
            self.stats.tx_pkts.fetch_add(1, Ordering::Relaxed);
            self.stats.tx_bytes.fetch_add(frame.len() as u64, Ordering::Relaxed);
        }
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

fn hello_frame(cfg: &Config, identity: &proto::Identity) -> Vec<u8> {
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
    proto::plain_frame(ctrl::HELLO, &hello)
}

// ---------- однократное управляющее соединение (CLI-команды) ----------

pub struct CtrlConn {
    pub sock: Arc<UdpSocket>,
    pub ctrl_key: proto::SymKey,
    pub server: SocketAddr,
    /// HELLO этого соединения — для повтора (сервер заново шлёт ответ на
    /// HELLO, в т.ч. INVITE_LIST).
    hello: Vec<u8>,
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
        let hello = hello_frame(cfg, identity);
        sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut next_hello = Instant::now();
        let mut buf = vec![0u8; 65_535];
        loop {
            let now = Instant::now();
            if now > deadline {
                anyhow::bail!("нет WELCOME от сервера (адрес/код сервера верны?)");
            }
            // HELLO повторяется: UDP может его потерять.
            if now >= next_hello {
                sock.send_to(&hello, server)?;
                next_hello = now + Duration::from_secs(1);
            }
            let (n, src) = match sock.recv_from(&mut buf) {
                Ok(x) => x,
                Err(_) => continue,
            };
            if src != server {
                continue;
            }
            let Ok((typ, body)) = proto::split_frame(&buf[..n]) else {
                continue;
            };
            if typ != ctrl::WELCOME {
                continue;
            }
            let (x_pub, w_sig) = payloads::dec_welcome(body)?;
            proto::Identity::verify(server_pub, &x_pub, &w_sig).context("WELCOME signature")?;
            return Ok(Self {
                ctrl_key: identity.ctrl_key_with(&x_pub),
                server,
                sock,
                hello,
            });
        }
    }

    /// Список неотвеченных приглашений, который сервер шлёт после HELLO:
    /// (приглашения, список полный). PONG раньше списка — список потерян
    /// (UDP, крупная фрагментированная датаграмма) или переставлен раньше
    /// WELCOME, либо сервер старый: HELLO повторяется на том же сокете
    /// (сервер пришлёт список заново). `None` — списка нет и после повторов.
    pub fn invite_list(&self) -> Result<Option<payloads::InviteList>> {
        self.send_ctrl(ctrl::CTRL_PING, &[]);
        let (typ, p) = self.wait_any(&[ctrl::INVITE_LIST, ctrl::CTRL_PONG], Duration::from_secs(5))?;
        if typ == ctrl::INVITE_LIST {
            return Ok(Some(payloads::dec_invite_list(&p)?));
        }
        // Ответ на повторный HELLO ждём без PING: на другом потоке сервера
        // PING обогнал бы более дорогой HELLO.
        for _ in 0..2 {
            let _ = self.sock.send_to(&self.hello, self.server);
            match self.wait_for(ctrl::INVITE_LIST, Duration::from_secs(2)) {
                Ok(p) => return Ok(Some(payloads::dec_invite_list(&p)?)),
                Err(e) if e.to_string().starts_with("сервер:") => return Err(e),
                Err(_) => {}
            }
        }
        Ok(None)
    }

    /// Окно неотвеченных приглашений с gid ≥ `from` (LIST_INVITES, без
    /// побочных эффектов). Запоздавшие окна с другим началом (ответ на
    /// повторный HELLO или прошлый запрос) пропускаются; при потере —
    /// повтор. `None` — ответа нет (старый сервер или потеря пакетов).
    pub fn invite_page(&self, from: u32) -> Result<Option<payloads::InviteList>> {
        for _ in 0..3 {
            self.send_ctrl(ctrl::LIST_INVITES, &payloads::enc_gid(from));
            let deadline = Instant::now() + Duration::from_secs(2);
            while let Some(left) = deadline.checked_duration_since(Instant::now()) {
                match self.wait_for(ctrl::INVITE_LIST, left) {
                    Ok(p) => {
                        let l = payloads::dec_invite_list(&p)?;
                        if l.from == from {
                            return Ok(Some(l));
                        }
                    }
                    Err(e) if e.to_string().starts_with("сервер:") => return Err(e),
                    Err(_) => break,
                }
            }
        }
        Ok(None)
    }

    pub fn send_ctrl(&self, typ: u8, payload: &[u8]) {
        let _ = self
            .sock
            .send_to(&proto::seal_ctrl(&self.ctrl_key, typ, payload), self.server);
    }

    /// Ждёт фрейм конкретного типа; ERROR превращает в Err; прочее игнорируется.
    pub fn wait_for(&self, expect: u8, timeout: Duration) -> Result<Vec<u8>> {
        self.wait_any(&[expect], timeout).map(|(_, p)| p)
    }

    /// Ждёт фрейм одного из типов `expect`: (тип, payload). ERROR → Err.
    pub fn wait_any(&self, expect: &[u8], timeout: Duration) -> Result<(u8, Vec<u8>)> {
        let deadline = Instant::now() + timeout;
        self.sock.set_read_timeout(Some(Duration::from_millis(200))).ok();
        let mut buf = vec![0u8; 65_535];
        loop {
            if Instant::now() > deadline {
                anyhow::bail!("таймаут ожидания {expect:02x?} от сервера");
            }
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
            if expect.contains(&typ) {
                return Ok((typ, payload));
            }
        }
    }
}

// ---------- запуск ----------

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
    let wintun = crate::tun::load_wintun_dll(dll.as_deref())?;
    let adapter = crate::tun::create_adapter(&wintun, adapter_name)?;
    crate::tun::set_mtu(&adapter, MTU)?;
    crate::tun::allow_firewall(adapter_name);
    let session = Arc::new(adapter.start_session(RING_CAPACITY)?);
    let dev = Arc::new(WintunDev {
        adapter,
        session: session.clone(),
        configured: Mutex::new(HashSet::new()),
    });
    let eng = start_with_tun(cfg, server, server_pub, identity, dev, save)?;
    spawn_tun_reader(session, eng.env.clone());
    Ok(eng)
}

/// Запуск движка поверх произвольного TUN-устройства (без чтения из него:
/// исходящие пакеты подаются через [`Engine::send_ip_packet`] или tun-поток).
pub fn start_with_tun(
    cfg: Arc<Mutex<Config>>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    tun: Arc<dyn TunDev>,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
) -> Result<Engine> {
    let (ev_tx, ev_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel::<Cmd>();
    let (in_tx, in_rx) = mpsc::channel::<Input>();

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

    let bind: SocketAddr = if server.is_ipv6() {
        "[::]:0".parse().unwrap()
    } else {
        "0.0.0.0:0".parse().unwrap()
    };
    let sock = Arc::new(UdpSocket::bind(bind).context("bind udp")?);
    sock.set_read_timeout(Some(RX_POLL)).ok();

    let groups: Groups = Arc::new(Mutex::new(HashMap::new()));
    let env = Arc::new(Env {
        groups: groups.clone(),
        meta: meta.clone(),
        stats: Arc::new(Stats::new()),
        ev: ev_tx,
        cfg: cfg.clone(),
        save: save.clone(),
        identity,
        server,
        sock,
        tun,
        quit: AtomicBool::new(false),
        pending_friend: Mutex::new(None),
    });
    let my_pub = env.identity.ed_pub();
    let my_code = env.identity.friend_code();

    // Приём — отдельный поток с самого начала: он же доставит WELCOME.
    {
        let env = env.clone();
        let in_tx = in_tx.clone();
        thread::Builder::new()
            .name("rx".into())
            .spawn(move || rx_loop(env, in_tx))
            .context("spawn rx thread")?;
    }
    // Команды UI → общий входной канал движка.
    {
        let in_tx = in_tx.clone();
        thread::Builder::new()
            .name("cmd".into())
            .spawn(move || {
                for c in cmd_rx {
                    if in_tx.send(Input::Cmd(c)).is_err() {
                        break;
                    }
                }
            })
            .context("spawn cmd thread")?;
    }
    drop(in_tx);

    // Первое подключение — синхронно, чтобы ошибка была видна сразу.
    let mut st = State::new(server_pub);
    if let Err(e) = first_connect(&env, &in_rx, &mut st) {
        env.quit.store(true, Ordering::Relaxed);
        return Err(e);
    }

    spawn_sampler(env.clone());
    {
        let env = env.clone();
        thread::Builder::new()
            .name("engine".into())
            .spawn(move || engine_loop(env, in_rx, st))
            .context("spawn engine thread")?;
    }

    Ok(Engine {
        groups,
        meta,
        stats: env.stats.clone(),
        my_pub,
        my_code,
        events: ev_rx,
        cmds: cmd_tx,
        cfg,
        save,
        env,
    })
}

// ---------- поток приёма ----------

/// Входы цикла движка.
enum Input {
    Cmd(Cmd),
    /// Не групповой фрейм от сервера (WELCOME/RESET — открытые, прочее — шифр).
    Server { typ: u8, body: Vec<u8> },
}

fn rx_loop(env: Arc<Env>, in_tx: mpsc::Sender<Input>) {
    let mut buf = vec![0u8; 65_535];
    while !env.quitting() {
        let (n, src) = match env.sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    // Таймаут чтения — проверить флаг выхода.
                    // ConnectionReset — Windows: ICMP unreachable после
                    // send_to в мёртвый эндпоинт (офлайн-пир, старый порт).
                    // Это не потеря связи — пропускаем.
                    WouldBlock | TimedOut | ConnectionReset | Interrupted => {}
                    _ => {
                        if debug() {
                            env.emit(Event::Error(format!("recv: {e}")));
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                }
                continue;
            }
        };
        let datagram = &buf[..n];
        let Ok((typ, body)) = proto::split_frame(datagram) else {
            continue;
        };
        if (proto::grp::DATA..=proto::grp::KEEPALIVE).contains(&typ) {
            handle_group_frame(&env, src, datagram);
        } else if src == env.server
            && in_tx
                .send(Input::Server {
                    typ,
                    body: body.to_vec(),
                })
                .is_err()
        {
            break;
        }
    }
}

// ---------- цикл движка ----------

/// Состояние цикла движка (живёт только в потоке engine).
struct State {
    server_pub: [u8; 32],
    ctrl_key: Option<proto::SymKey>,
    connected: bool,
    /// Последний подлинный (расшифрованный) фрейм от сервера.
    last_server_rx: Instant,
    next_hello: Instant,
    backoff: Duration,
    /// Группы, из которых вышли, но сервер ещё не подтвердил: gid → начало.
    leaving: HashMap<u32, Instant>,
    /// Ожидаемое окно приглашений: (from, с какого момента ждём).
    invite_sync: Option<(u32, Instant)>,
    last_invite_req: Instant,
    /// Отклонённые приглашения, отказ ещё не подтверждён: gid → начало.
    declining: HashMap<u32, Instant>,
    last_decline: Instant,
    last_ping: Instant,
    last_list: Instant,
    last_rtt: Instant,
    last_punch: Instant,
    last_leave: Instant,
}

impl State {
    fn new(server_pub: [u8; 32]) -> Self {
        let now = Instant::now();
        Self {
            server_pub,
            ctrl_key: None,
            connected: false,
            last_server_rx: now,
            next_hello: now,
            backoff: Duration::from_secs(1),
            leaving: HashMap::new(),
            invite_sync: None,
            last_invite_req: now,
            declining: HashMap::new(),
            last_decline: now,
            last_ping: now,
            last_list: now,
            last_rtt: now,
            last_punch: now,
            last_leave: now,
        }
    }

    fn send_ctrl(&self, env: &Env, typ: u8, payload: &[u8]) {
        if let Some(key) = &self.ctrl_key {
            env.send(&proto::seal_ctrl(key, typ, payload), env.server);
        }
    }

    fn send_hello(&mut self, env: &Env) {
        let cfg = env.cfg.lock().unwrap().clone();
        env.send(&hello_frame(&cfg, &env.identity), env.server);
    }
}

/// Синхронное первое подключение: HELLO с повтором раз в секунду, до 10 с.
fn first_connect(env: &Env, in_rx: &mpsc::Receiver<Input>, st: &mut State) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut next = Instant::now();
    let mut early: Vec<Cmd> = Vec::new();
    // Фреймы сервера, обогнавшие WELCOME (UDP не держит порядок): без
    // канального ключа их не расшифровать — разобрать после подключения.
    // Иначе терялись, например, приглашения, которые сервер шлёт сразу за
    // WELCOME.
    let mut early_frames: Vec<(u8, Vec<u8>)> = Vec::new();
    loop {
        let now = Instant::now();
        if now > deadline {
            anyhow::bail!("нет WELCOME от сервера (адрес/код сервера верны?)");
        }
        if now >= next {
            st.send_hello(env);
            next = now + Duration::from_secs(1);
        }
        match in_rx.recv_timeout(Duration::from_millis(100)) {
            Ok(Input::Server { typ: ctrl::WELCOME, body }) => {
                let (x_pub, w_sig) = payloads::dec_welcome(&body)?;
                proto::Identity::verify(&st.server_pub, &x_pub, &w_sig)
                    .context("WELCOME: подпись не от того сервера (неверный код сервера?)")?;
                st.ctrl_key = Some(env.identity.ctrl_key_with(&x_pub));
                on_connected(env, st);
                for (typ, body) in early_frames {
                    on_server_frame(env, st, typ, &body);
                }
                // Команды, пришедшие до подключения, — после него.
                for c in early {
                    do_cmd(env, st, c);
                }
                return Ok(());
            }
            Ok(Input::Cmd(Cmd::Quit)) => anyhow::bail!("остановлено"),
            Ok(Input::Cmd(c)) => early.push(c),
            Ok(Input::Server { typ, body }) => {
                if typ != ctrl::WELCOME && typ != ctrl::RESET && early_frames.len() < 64 {
                    early_frames.push((typ, body));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => anyhow::bail!("rx-поток остановлен"),
        }
    }
}

fn engine_loop(env: Arc<Env>, in_rx: mpsc::Receiver<Input>, mut st: State) {
    loop {
        match in_rx.recv_timeout(TICK) {
            Ok(Input::Cmd(Cmd::Quit)) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                env.quit.store(true, Ordering::Relaxed);
                return;
            }
            Ok(Input::Cmd(c)) => do_cmd(&env, &mut st, c),
            Ok(Input::Server { typ, body }) => on_server_frame(&env, &mut st, typ, &body),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
        }
        if env.quitting() {
            return;
        }
        tick(&env, &mut st, Instant::now());
    }
}

/// Сервер принял HELLO: приветствие и восстановление состояния.
fn on_connected(env: &Env, st: &mut State) {
    let now = Instant::now();
    st.connected = true;
    st.last_server_rx = now;
    st.backoff = Duration::from_secs(1);
    st.last_ping = now;
    st.last_list = now;
    // Сервер шлёт окно приглашений сразу за WELCOME — ждём его (см. tick).
    st.invite_sync = Some((0, now));
    st.last_invite_req = now;
    st.last_decline = now;
    env.meta.lock().unwrap().connected = true;
    env.emit(Event::Connected(env.server));

    let cfg = env.cfg.lock().unwrap().clone();
    if !cfg.status.is_empty() {
        st.send_ctrl(env, ctrl::STATUS, &payloads::enc_status(&cfg.status));
    }
    for gid in &cfg.autojoin {
        if !st.leaving.contains_key(gid) {
            st.send_ctrl(env, ctrl::JOIN_GROUP, &payloads::enc_gid(*gid));
        }
    }
    for gid in st.leaving.keys() {
        st.send_ctrl(env, ctrl::LEAVE_GROUP, &payloads::enc_gid(*gid));
    }
    for gid in st.declining.keys() {
        st.send_ctrl(env, ctrl::DECLINE_INVITE, &payloads::enc_gid(*gid));
    }
    st.send_ctrl(env, ctrl::LIST_GROUPS, &payloads::enc_gid(0));
}

fn lose_server(env: &Env, st: &mut State, reason: &str) {
    if !st.connected {
        return;
    }
    st.connected = false;
    st.backoff = Duration::from_secs(1);
    st.next_hello = Instant::now();
    env.meta.lock().unwrap().connected = false;
    env.emit(Event::Disconnected(reason.to_string()));
}

fn on_server_frame(env: &Env, st: &mut State, typ: u8, body: &[u8]) {
    match typ {
        ctrl::WELCOME => {
            let Ok((x_pub, w_sig)) = payloads::dec_welcome(body) else {
                return;
            };
            if proto::Identity::verify(&st.server_pub, &x_pub, &w_sig).is_err() {
                return;
            }
            st.ctrl_key = Some(env.identity.ctrl_key_with(&x_pub));
            if st.connected {
                // Ответ на повторный HELLO (смена имени) — сессия та же.
                st.last_server_rx = Instant::now();
            } else {
                on_connected(env, st);
            }
        }
        ctrl::RESET => {
            // Сервер не знает нашу сессию (перезапуск/истекла) — сразу HELLO.
            if st.connected {
                lose_server(env, st, "сервер сбросил сессию");
            }
            if Instant::now() >= st.next_hello {
                st.send_hello(env);
                st.next_hello = Instant::now() + st.backoff;
            }
        }
        _ => {
            let Some(key) = st.ctrl_key else { return };
            let Ok(payload) = proto::open_ctrl(&key, typ, body) else {
                return;
            };
            st.last_server_rx = Instant::now();
            on_ctrl(env, st, typ, &payload);
        }
    }
}

/// Таймеры: идут по часам на каждой итерации цикла.
fn tick(env: &Env, st: &mut State, now: Instant) {
    if st.connected && now.duration_since(st.last_server_rx) > SERVER_TIMEOUT {
        lose_server(env, st, "сервер не отвечает");
    }
    if !st.connected {
        if now >= st.next_hello {
            st.send_hello(env);
            st.next_hello = now + st.backoff;
            st.backoff = (st.backoff * 2).min(RECONNECT_MAX);
        }
    } else {
        if now.duration_since(st.last_ping) >= PING_EVERY {
            st.last_ping = now;
            st.send_ctrl(env, ctrl::CTRL_PING, &[]);
        }
        if now.duration_since(st.last_list) >= LIST_EVERY {
            st.last_list = now;
            st.send_ctrl(env, ctrl::LIST_GROUPS, &payloads::enc_gid(0));
        }
        if !st.leaving.is_empty() && now.duration_since(st.last_leave) >= LEAVE_RETRY {
            st.last_leave = now;
            st.leaving
                .retain(|_, started| now.duration_since(*started) < LEAVE_GIVE_UP);
            for gid in st.leaving.keys() {
                st.send_ctrl(env, ctrl::LEAVE_GROUP, &payloads::enc_gid(*gid));
            }
        }
        if let Some((from, since)) = st.invite_sync
            && now.duration_since(st.last_invite_req) >= INVITE_SYNC_RETRY
        {
            st.last_invite_req = now;
            if now.duration_since(since) < INVITE_SYNC_GIVE_UP {
                st.send_ctrl(env, ctrl::LIST_INVITES, &payloads::enc_gid(from));
            } else {
                st.invite_sync = None;
            }
        }
        if !st.declining.is_empty() && now.duration_since(st.last_decline) >= DECLINE_RETRY {
            st.last_decline = now;
            st.declining
                .retain(|_, started| now.duration_since(*started) < DECLINE_GIVE_UP);
            for gid in st.declining.keys() {
                st.send_ctrl(env, ctrl::DECLINE_INVITE, &payloads::enc_gid(*gid));
            }
        }
    }
    // P2P-таймеры работают и без сервера: прямые каналы живут сами.
    if now.duration_since(st.last_rtt) >= RTT_EVERY {
        st.last_rtt = now;
        rtt_round(env, st.connected, now);
    }
    if now.duration_since(st.last_punch) >= PUNCH_EVERY {
        st.last_punch = now;
        punch_round(env);
    }
}

fn do_cmd(env: &Env, st: &mut State, cmd: Cmd) {
    // Локальные команды — всегда, независимо от связи с сервером.
    match cmd {
        Cmd::Quit => return,
        Cmd::ToggleAutojoin(gid) => {
            let on = env.cfg.lock().unwrap().autojoin.contains(&gid);
            if on {
                env.autojoin_remove(gid);
            } else {
                env.autojoin_add(gid);
            }
            return;
        }
        Cmd::SetName(name) => {
            env.set_name(name);
            if st.connected {
                // Повторный HELLO — сервер обновит имя (сессия сохранится).
                st.send_hello(env);
            }
            return;
        }
        Cmd::SetStatus(text) => {
            env.set_status(text.clone());
            if st.connected {
                st.send_ctrl(env, ctrl::STATUS, &payloads::enc_status(&text));
            }
            return;
        }
        Cmd::Leave(gid) => {
            // Выход — сразу локально; LEAVE повторяется, пока сервер не
            // подтвердит (иначе потерянный LEAVE или запоздавший
            // GROUP_STATE возвращали группу обратно).
            let name = env.groups.lock().unwrap().remove(&gid).map(|g| g.name);
            env.autojoin_remove(gid);
            st.leaving.insert(gid, Instant::now());
            if st.connected {
                st.send_ctrl(env, ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
            }
            if let Some(name) = name {
                env.emit(Event::GroupLeft { gid, name });
            }
            return;
        }
        _ => {}
    }
    if !st.connected {
        env.emit(Event::Error("нет связи с сервером — команда не отправлена".into()));
        return;
    }
    match cmd {
        Cmd::RefreshList => st.send_ctrl(env, ctrl::LIST_GROUPS, &payloads::enc_gid(0)),
        Cmd::Create { name, private } => st.send_ctrl(
            env,
            ctrl::CREATE_GROUP,
            &payloads::enc_create_group(&name, private),
        ),
        Cmd::Join(gid) => {
            st.leaving.remove(&gid);
            st.declining.remove(&gid);
            st.send_ctrl(env, ctrl::JOIN_GROUP, &payloads::enc_gid(gid))
        }
        Cmd::Delete(gid) => st.send_ctrl(env, ctrl::DELETE_GROUP, &payloads::enc_gid(gid)),
        Cmd::Rename(gid, name) => {
            st.send_ctrl(env, ctrl::RENAME_GROUP, &payloads::enc_rename(gid, &name))
        }
        Cmd::Invite(gid, pk) => {
            st.send_ctrl(env, ctrl::INVITE, &payloads::enc_gid_target(gid, &pk))
        }
        // Повторяется, пока окно списка не подтвердит отказ (см. on_ctrl):
        // потерянный DECLINE оставил бы приглашение на сервере, а владелец
        // не узнал бы об отказе. Старый сервер тип не знает и молча
        // игнорирует — это не ошибка, повторы кончатся по DECLINE_GIVE_UP.
        Cmd::DeclineInvite(gid) => {
            let now = Instant::now();
            st.declining.insert(gid, now);
            st.last_decline = now;
            st.send_ctrl(env, ctrl::DECLINE_INVITE, &payloads::enc_gid(gid))
        }
        Cmd::Kick(gid, pk) => st.send_ctrl(env, ctrl::KICK, &payloads::enc_gid_target(gid, &pk)),
        Cmd::Ban(gid, pk) => st.send_ctrl(env, ctrl::BAN, &payloads::enc_gid_target(gid, &pk)),
        Cmd::FriendGroups(pk) => {
            *env.pending_friend.lock().unwrap() = Some(pk);
            st.send_ctrl(env, ctrl::FRIEND_GROUPS, &payloads::enc_pubkey(&pk));
        }
        Cmd::Quit
        | Cmd::ToggleAutojoin(_)
        | Cmd::SetName(_)
        | Cmd::SetStatus(_)
        | Cmd::Leave(_) => {}
    }
}

fn on_ctrl(env: &Env, st: &mut State, typ: u8, payload: &[u8]) {
    match typ {
        ctrl::GROUP_STATE => {
            if let Ok(gs) = payloads::dec_group_state(payload) {
                if st.leaving.contains_key(&gs.gid) && !gs.deleted {
                    // Запоздавшее состояние группы, из которой мы вышли.
                    return;
                }
                apply_group_state(env, &gs);
            }
        }
        ctrl::GROUP_LIST => {
            if let Ok(items) = payloads::dec_group_list(payload) {
                let mine: HashSet<u32> = items.iter().filter(|g| g.mine).map(|g| g.gid).collect();
                // Сервер подтвердил выход — больше не повторяем LEAVE.
                st.leaving.retain(|gid, _| mine.contains(gid));
                reconcile(env, &mine);
                env.meta.lock().unwrap().group_list = items;
            }
        }
        ctrl::INVITE_RCVD => {
            if let Ok(inv) = payloads::dec_invite(payload) {
                on_invite(env, st, inv);
            }
        }
        ctrl::INVITE_LIST => {
            if let Ok(list) = payloads::dec_invite_list(payload) {
                // Неполное окно — дочитать следующее: сервер шлёт не больше
                // 16 за раз (ответ не должен расти), а показать нужно все.
                // gid растут, так что цепочка конечна.
                let now = Instant::now();
                let next = list.next_from();
                if let Some(next) = next {
                    st.send_ctrl(env, ctrl::LIST_INVITES, &payloads::enc_gid(next));
                }
                // Ждали окно с `want` — это его покрывает: ждём следующее
                // (если есть). Окно не о том (ответ на отказ, вход) ожидание
                // не снимает.
                match st.invite_sync {
                    Some((want, _)) if !list.covers(want) => {}
                    _ => {
                        st.invite_sync = next.map(|n| (n, now));
                        st.last_invite_req = now;
                    }
                }
                // Отказ подтверждён: окно покрывает gid, а приглашения в нём нет.
                st.declining.retain(|gid, _| {
                    !list.covers(*gid) || list.items.iter().any(|i| i.gid == *gid)
                });
                let (from, complete) = (list.from, list.complete);
                let gids: Vec<u32> = list.items.iter().map(|i| i.gid).collect();
                for inv in list.items {
                    // Отказ ещё повторяется — список собран до него.
                    if !st.declining.contains_key(&inv.gid) {
                        on_invite(env, st, inv);
                    }
                }
                env.emit(Event::InvitesSynced { gids, from, complete });
            }
        }
        ctrl::INVITE_DECLINED => {
            if let Ok(d) = payloads::dec_invite_declined(payload) {
                env.emit(Event::InviteDeclined {
                    gid: d.gid,
                    group_name: d.group_name,
                    by_pubkey: d.by_pubkey,
                    by_name: d.by_name,
                });
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

/// Приглашение (одиночное или из INVITE_LIST): событие UI; группа из
/// автовхода — войти сразу.
fn on_invite(env: &Env, st: &mut State, inv: payloads::InviteInfo) {
    let gid = inv.gid;
    env.emit(Event::Invite {
        gid,
        group_name: inv.group_name,
        from_pubkey: inv.from_pubkey,
        from_name: inv.from_name,
    });
    let in_autojoin = env.cfg.lock().unwrap().autojoin.contains(&gid);
    if in_autojoin {
        st.send_ctrl(env, ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
    }
}

/// Ошибка от сервера. «Кик» парсим по тексту и убираем группу локально
/// (сервер кикнутому GROUP_STATE не шлёт).
fn handle_error(env: &Env, text: String) {
    if (text.contains("кикнут") || text.contains("забанен"))
        && let Some(name) = quoted(&text)
    {
        let found = {
            let g = env.groups.lock().unwrap();
            g.iter()
                .find(|(_, gs)| gs.name == name)
                .map(|(gid, gs)| (*gid, gs.name.clone()))
        };
        if let Some((gid, gname)) = found {
            env.groups.lock().unwrap().remove(&gid);
            env.autojoin_remove(gid);
            env.emit(Event::Kicked { gid, name: gname });
            return;
        }
    }
    env.emit(Event::Error(text));
}

/// Локальные группы, которых больше нет на сервере (могли кикнуть/удалить,
/// пока нас не было) — убрать.
fn reconcile(env: &Env, mine: &HashSet<u32>) {
    let now = Instant::now();
    let stale: Vec<(u32, String)> = {
        let mut g = env.groups.lock().unwrap();
        let stale: Vec<(u32, String)> = g
            .iter()
            .filter(|(gid, gs)| {
                !mine.contains(gid) && now.duration_since(gs.since) > NEW_GROUP_GRACE
            })
            .map(|(gid, gs)| (*gid, gs.name.clone()))
            .collect();
        for (gid, _) in &stale {
            g.remove(gid);
        }
        stale
    };
    for (gid, name) in stale {
        env.autojoin_remove(gid);
        env.emit(Event::Notice(format!("группа {name} больше недоступна")));
    }
}

// ---------- состояние групп ----------

fn apply_group_state(env: &Env, st: &payloads::GroupState) {
    let my_pub = env.identity.ed_pub();
    if st.deleted {
        let removed = { env.groups.lock().unwrap().remove(&st.gid).map(|g| g.name) };
        match removed {
            Some(name) => {
                env.autojoin_remove(st.gid);
                env.emit(Event::GroupDeleted { gid: st.gid, name });
            }
            // Не наша группа — сервер сообщает приглашённому, что группы нет.
            None => env.emit(Event::InviteRevoked { gid: st.gid }),
        }
        return;
    }
    let mut events: Vec<Event> = Vec::new();
    let is_new = {
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
        for m in &st.members {
            if m.pubkey == my_pub {
                continue;
            }
            let prev = old.get(&m.pubkey);
            let server_ep: Option<SocketAddr> = m.endpoint.as_deref().and_then(|e| e.parse().ok());
            let endpoint = server_ep.or_else(|| prev.and_then(|p| p.endpoint));
            // Пир переподключился с другого адреса или ушёл офлайн — старый
            // прямой канал недействителен.
            let same_ep = prev.and_then(|p| p.endpoint) == endpoint;
            let keep_direct = m.online && same_ep;
            let direct = keep_direct && prev.map(|p| p.direct).unwrap_or(false);
            if prev.map(|p| p.online) != Some(m.online) {
                if m.online {
                    events.push(Event::PeerOnline {
                        gid: st.gid,
                        ip: m.ip,
                        name: m.name.clone(),
                    });
                } else if prev.is_some() {
                    events.push(Event::PeerOffline {
                        gid: st.gid,
                        ip: m.ip,
                        name: m.name.clone(),
                    });
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
                    last_direct: if keep_direct { prev.and_then(|p| p.last_direct) } else { None },
                    rtt_ms: if m.online { prev.and_then(|p| p.rtt_ms) } else { None },
                },
            );
        }
        is_new
    };
    if is_new {
        env.emit(Event::GroupJoined {
            gid: st.gid,
            name: st.name.clone(),
            my_ip: st.my_ip,
        });
        env.autojoin_add(st.gid);
    }
    if let Err(e) = env.tun.ensure_address(st.my_ip) {
        env.emit(Event::Error(format!(
            "адрес {} на адаптере: {e}",
            proto::ip_str(st.my_ip)
        )));
    }
    for ev in events {
        env.emit(ev);
    }
}

// ---------- групповые фреймы ----------

fn handle_group_frame(env: &Env, src: SocketAddr, datagram: &[u8]) {
    env.stats.rx_pkts.fetch_add(1, Ordering::Relaxed);
    env.stats.rx_bytes.fetch_add(datagram.len() as u64, Ordering::Relaxed);
    let Ok((gid, _src_ip, _dst_ip)) = proto::parse_group_header(datagram) else {
        return;
    };
    let (key, my_ip) = {
        let g = env.groups.lock().unwrap();
        match g.get(&gid) {
            Some(gs) => (gs.key, gs.my_ip),
            None => return,
        }
    };
    let Ok((typ, _gid, src_ip, dst_ip, payload)) = proto::open_group(&key, datagram) else {
        return;
    };
    if dst_ip != my_ip {
        return;
    }
    let is_relay = src == env.server;
    let now = Instant::now();
    let mut became_direct: Option<String> = None;
    {
        // Атрибуция отправителя по src_ip (подлинность — ключ группы).
        let mut g = env.groups.lock().unwrap();
        if let Some(peer) = g.get_mut(&gid).and_then(|gs| gs.members.get_mut(&src_ip)) {
            peer.last_rx = now;
            if !is_relay {
                peer.endpoint = Some(src);
                peer.last_direct = Some(now);
                if !peer.direct {
                    peer.direct = true;
                    became_direct = Some(peer.name.clone());
                }
            }
        }
    }
    if let Some(name) = became_direct {
        env.emit(Event::Direct { gid, ip: src_ip, name });
    }
    match typ {
        proto::grp::DATA => {
            if let Err(e) = env.tun.inject(&payload)
                && debug()
            {
                env.emit(Event::Error(format!("inject: {e}")));
            }
        }
        proto::grp::PING => {
            let frame = proto::seal_group(&key, proto::grp::PONG, gid, my_ip, src_ip, &payload);
            env.send(&frame, src);
        }
        proto::grp::PONG => {
            if let Ok(sent_ms) = payloads::dec_ping(&payload) {
                let rtt = epoch_ms().saturating_sub(sent_ms);
                let mut g = env.groups.lock().unwrap();
                if let Some(peer) = g.get_mut(&gid).and_then(|gs| gs.members.get_mut(&src_ip)) {
                    peer.rtt_ms = Some(rtt);
                }
            }
        }
        proto::grp::PUNCH if !is_relay => {
            // Ответ — KEEPALIVE, не PUNCH: на PUNCH отвечают, на KEEPALIVE —
            // нет, поэтому пинг-понга PUNCH↔PUNCH (бесконечного спама между
            // двумя клиентами) больше не возникает. Через релей не отвечаем:
            // PUNCH нужен только для прямого канала.
            let frame = proto::seal_group(&key, proto::grp::KEEPALIVE, gid, my_ip, src_ip, &[]);
            env.send(&frame, src);
        }
        _ => {}
    }
}

/// IP-пакет из адаптера → пиру. Напрямую — только если прямой канал жив;
/// иначе через релей сервера (раньше пакеты шли на endpoint пира ещё до
/// пробития NAT и терялись).
fn route_packet(env: &Env, bytes: &[u8]) {
    let Ok(dst) = proto::ipv4_dst(bytes) else {
        return;
    };
    let gid = proto::group_of_ip(dst);
    let (key, my_ip, target) = {
        let g = env.groups.lock().unwrap();
        let Some(gs) = g.get(&gid) else { return };
        if dst == gs.my_ip {
            return;
        }
        let target = match gs.members.get(&dst) {
            Some(p) if p.direct => p.endpoint.unwrap_or(env.server),
            _ => env.server,
        };
        (gs.key, gs.my_ip, target)
    };
    let frame = proto::seal_group(&key, proto::grp::DATA, gid, my_ip, dst, bytes);
    env.send(&frame, target);
}

// ---------- раунды RTT и NAT ----------

/// RTT-зонд онлайн-пирам: прямым — напрямую (это же держит NAT-маппинг),
/// остальным — через релей. Заодно гасит протухшие прямые каналы.
fn rtt_round(env: &Env, connected: bool, now: Instant) {
    let now_ms = epoch_ms();
    let mut tasks: Vec<(u32, proto::SymKey, u32, u32, SocketAddr)> = Vec::new();
    {
        let mut g = env.groups.lock().unwrap();
        for (gid, gs) in g.iter_mut() {
            for (ip, peer) in gs.members.iter_mut() {
                if !peer.online {
                    continue;
                }
                if peer.direct
                    && peer
                        .last_direct
                        .is_none_or(|t| now.duration_since(t) > DIRECT_TIMEOUT)
                {
                    peer.direct = false;
                    peer.rtt_ms = None;
                }
                let target = match (peer.direct, peer.endpoint) {
                    (true, Some(ep)) => ep,
                    _ if connected => env.server,
                    _ => continue,
                };
                tasks.push((*gid, gs.key, gs.my_ip, *ip, target));
            }
        }
    }
    let payload = payloads::enc_ping(now_ms);
    for (gid, key, my_ip, peer_ip, target) in tasks {
        let ping = proto::seal_group(&key, proto::grp::PING, gid, my_ip, peer_ip, &payload);
        env.send(&ping, target);
    }
}

/// PUNCH онлайн-пирам без прямого канала, чей адрес известен. Пирам с прямым
/// каналом не шлём ничего: их маппинг держат RTT-зонды.
fn punch_round(env: &Env) {
    let tasks: Vec<(u32, proto::SymKey, u32, u32, SocketAddr)> = {
        let g = env.groups.lock().unwrap();
        let mut out = Vec::new();
        for (gid, gs) in g.iter() {
            for (ip, peer) in &gs.members {
                if peer.online
                    && !peer.direct
                    && let Some(ep) = peer.endpoint
                {
                    out.push((*gid, gs.key, gs.my_ip, *ip, ep));
                }
            }
        }
        out
    };
    for (gid, key, my_ip, peer_ip, ep) in tasks {
        let punch = proto::seal_group(&key, proto::grp::PUNCH, gid, my_ip, peer_ip, &[]);
        env.send(&punch, ep);
    }
}

// ---------- фоновые потоки ----------

fn spawn_tun_reader(session: Arc<wintun::Session>, env: Arc<Env>) {
    thread::Builder::new()
        .name("tun".into())
        .spawn(move || {
            while !env.quitting() {
                let pkt = match session.receive_blocking() {
                    Ok(p) => p,
                    Err(_) => break,
                };
                route_packet(&env, pkt.bytes());
            }
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
            while !env.quitting() {
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
            // Ответить на месте нельзя: CLI join/decline и TUI — свой HELLO
            // той же identity, он вытесняет этот сеанс (а реконнект run —
            // их), поэтому — только после остановки run.
            Event::Invite { gid, group_name, from_name, .. } => eprintln!(
                "[engine] приглашение: {from_name} приглашает в группу {group_name} (gid {gid}); \
                 ответить — остановив run: командой join {gid} / decline {gid} или в TUI"
            ),
            Event::InviteDeclined { gid, group_name, by_name, .. } => eprintln!(
                "[engine] {by_name} отклонил приглашение в группу {group_name} (gid {gid})"
            ),
            Event::InviteRevoked { gid } => {
                eprintln!("[engine] приглашение в группу {gid} больше недействительно")
            }
            Event::InvitesSynced { .. } => {}
            Event::FriendGroups { .. } => {}
            Event::Error(e) => eprintln!("[engine] {e}"),
            Event::Notice(n) => eprintln!("[engine] {n}"),
        }
    }
    Ok(())
}
