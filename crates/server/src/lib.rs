//! Рандеву-сервер v2: identity, группы, lease IP, инвайты, kick/ban, presence.
//!
//! HELLO приходит открытым текстом, но подписан ed25519-ключом клиента
//! (подмена с другого IP невозможна). Все остальные управляющие фреймы
//! шифруются канальным ключом static-static X25519.
//! Фреймы групп релеятся без расшифровки payload'а — сервер читает только
//! открытый заголовок (group_id, src_ip, dst_ip).
//!
//! Многопоточность: несколько воркеров читают один UDP-сокет параллельно.
//! Состояние — под `RwLock`: релей и частые запросы (PING, LIST) берут
//! блокировку на чтение и не мешают друг другу, изменения (JOIN, LEAVE, …)
//! — на запись. Ответы собираются в «исходящие» и отправляются уже после
//! снятия блокировки.
//!
//! Защита от лишней нагрузки:
//! - релей только от установленной сессии, только участнику той же группы и
//!   только со своим IP группы в заголовке (подмена src_ip отбрасывается);
//! - лимиты (token bucket): релей и управляющие фреймы на сессию, HELLO и
//!   RESET на IP-адрес;
//! - мусор и чужие фреймы отбрасываются молча, без записи в лог.

pub mod persist;

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use proto::ctrl;
use proto::payloads::{GroupState, GroupSummary, MemberInfo};
use rand::Rng;
use tunnel_protocol as proto;

const GID_MIN: u32 = 1;
const GID_MAX: u32 = 254; // 100.66.<gid>.0/24
const HOST_MIN: u32 = 2;
const HOST_MAX: u32 = 254;
/// Сессия без единого пакета столько — офлайн (клиент пингует раз в 5 с).
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);
const HOUSEKEEPING_EVERY: Duration = Duration::from_secs(2);
const SAVE_EVERY: Duration = Duration::from_secs(3);
const STATS_EVERY: Duration = Duration::from_secs(300);
/// Как часто воркер проверяет флаг остановки.
const RECV_POLL: Duration = Duration::from_millis(250);

/// Релей: пакетов в секунду на сессию (игровой трафик + RTT-зонды) и запас.
const RELAY_RATE: f64 = 4000.0;
const RELAY_BURST: f64 = 8000.0;
/// Управляющие фреймы на сессию.
const CTRL_RATE: f64 = 50.0;
const CTRL_BURST: f64 = 100.0;
/// HELLO и RESET на IP-адрес (HELLO — проверка подписи и DH, дорого).
const PER_IP_RATE: f64 = 5.0;
const PER_IP_BURST: f64 = 20.0;

const NAME_MAX_CHARS: usize = 32;
const STATUS_MAX_CHARS: usize = 100;
const GROUP_NAME_MAX_CHARS: usize = 48;

// ---------- конфигурация и запуск ----------

pub struct Config {
    pub listen: SocketAddr,
    pub data_dir: PathBuf,
    /// Число потоков-воркеров (0 — по числу ядер, но не больше 8).
    pub workers: usize,
    /// Не печатать события (для тестов).
    pub quiet: bool,
}

/// Запущенный сервер. Останавливается через [`Server::stop`] или при drop.
pub struct Server {
    pub addr: SocketAddr,
    /// Friend code сервера (клиент пиннит его ed25519-ключ).
    pub code: String,
    pub pubkey: [u8; 32],
    shared: Arc<Shared>,
    threads: Vec<JoinHandle<()>>,
}

impl Server {
    pub fn start(cfg: Config) -> Result<Server> {
        let store = persist::Store::new(&cfg.data_dir);
        let (identity, next_gid, groups) = load_state(&store)?;
        let fresh = groups.is_empty();
        let sock = UdpSocket::bind(cfg.listen).with_context(|| format!("bind {}", cfg.listen))?;
        sock.set_read_timeout(Some(RECV_POLL)).ok();
        let addr = sock.local_addr()?;
        let code = identity.friend_code();
        let pubkey = identity.ed_pub();
        let x_pub = identity.x_pub();
        let welcome_sig = identity.sign(&x_pub);

        let shared = Arc::new(Shared {
            sock,
            state: RwLock::new(State {
                identity,
                sessions: HashMap::new(),
                by_pub: HashMap::new(),
                groups,
                next_gid,
            }),
            welcome: proto::payloads::enc_welcome(&x_pub, &welcome_sig),
            started: Instant::now(),
            stop: AtomicBool::new(false),
            dirty: AtomicBool::new(true),
            per_ip: Mutex::new(HashMap::new()),
            quiet: cfg.quiet,
            store,
            relayed: AtomicU64::new(0),
            dropped: AtomicU64::new(0),
        });
        if !cfg.quiet {
            if fresh {
                eprintln!("[server] новое состояние в {}", cfg.data_dir.display());
            } else {
                let n = shared.state.read().unwrap().groups.len();
                eprintln!("[server] загружено: {n} групп(ы) из {}", cfg.data_dir.display());
            }
        }

        let workers = if cfg.workers == 0 {
            thread::available_parallelism().map(|n| n.get()).unwrap_or(2).clamp(2, 8)
        } else {
            cfg.workers
        };
        let mut threads = Vec::new();
        for i in 0..workers {
            let sh = shared.clone();
            threads.push(
                thread::Builder::new()
                    .name(format!("worker-{i}"))
                    .spawn(move || worker(sh))?,
            );
        }
        {
            let sh = shared.clone();
            threads.push(
                thread::Builder::new()
                    .name("housekeeping".into())
                    .spawn(move || housekeeping(sh))?,
            );
        }
        shared.log(format!("listening on {addr}, воркеров: {workers}"));
        shared.log(format!("Server code: {code}"));
        Ok(Server {
            addr,
            code,
            pubkey,
            shared,
            threads,
        })
    }

    /// Останавливает потоки и сохраняет состояние.
    pub fn stop(mut self) {
        self.shutdown();
    }

    /// Блокирует до остановки (Ctrl-C завершает процесс).
    pub fn wait(mut self) {
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
    }

    fn shutdown(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        for t in self.threads.drain(..) {
            let _ = t.join();
        }
        save_now(&self.shared);
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        if !self.threads.is_empty() {
            self.shutdown();
        }
    }
}

// ---------- состояние ----------

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn new(burst: f64) -> Self {
        Self {
            tokens: burst,
            last: Instant::now(),
        }
    }

    fn take(&mut self, rate: f64, burst: f64) -> bool {
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * rate).min(burst);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

struct Session {
    ed_pub: [u8; 32],
    name: String,
    status: String,
    ctrl_key: proto::SymKey,
    /// Последний пакет, мс от старта сервера (обновляется под read-lock).
    last_seen: AtomicU64,
    relay: Mutex<Bucket>,
    ctrl: Mutex<Bucket>,
}

struct Member {
    ip: u32,
    name: String,
    status: String,
}

struct Group {
    id: u32,
    name: String,
    owner: [u8; 32],
    private: bool,
    key: proto::SymKey,
    /// lease: ed25519 pubkey → ip (офлайн-участники IP сохраняют).
    members: HashMap<[u8; 32], Member>,
    /// Индекс для релея: ip → pubkey.
    by_ip: HashMap<u32, [u8; 32]>,
    banned: HashSet<[u8; 32]>,
    invites: HashSet<[u8; 32]>,
}

impl Group {
    fn insert_member(&mut self, pk: [u8; 32], m: Member) {
        if let Some(old) = self.members.get(&pk) {
            self.by_ip.remove(&old.ip);
        }
        self.by_ip.insert(m.ip, pk);
        self.members.insert(pk, m);
    }

    fn remove_member(&mut self, pk: &[u8; 32]) -> bool {
        match self.members.remove(pk) {
            Some(m) => {
                self.by_ip.remove(&m.ip);
                true
            }
            None => false,
        }
    }

    fn next_free_ip(&self) -> Option<u32> {
        (HOST_MIN..=HOST_MAX)
            .map(|h| gid_subnet_base(self.id) + h)
            .find(|ip| !self.by_ip.contains_key(ip))
    }
}

struct State {
    identity: proto::Identity,
    sessions: HashMap<SocketAddr, Session>,
    /// Индекс: identity → адрес её сессии.
    by_pub: HashMap<[u8; 32], SocketAddr>,
    groups: HashMap<u32, Group>,
    next_gid: u32,
}

impl State {
    /// Сессия identity: адрес и сама сессия.
    fn session_of(&self, pk: &[u8; 32]) -> Option<(SocketAddr, &Session)> {
        let addr = *self.by_pub.get(pk)?;
        self.sessions.get(&addr).map(|ses| (addr, ses))
    }

    fn online(&self, pk: &[u8; 32]) -> bool {
        self.by_pub.contains_key(pk)
    }

    fn remove_session(&mut self, addr: &SocketAddr) -> Option<Session> {
        let ses = self.sessions.remove(addr)?;
        if self.by_pub.get(&ses.ed_pub) == Some(addr) {
            self.by_pub.remove(&ses.ed_pub);
        }
        Some(ses)
    }

    fn groups_of(&self, pk: &[u8; 32]) -> Vec<u32> {
        self.groups
            .values()
            .filter(|g| g.members.contains_key(pk))
            .map(|g| g.id)
            .collect()
    }

    /// Свободный gid: начиная с next_gid по кругу (удалённые gid переиспользуются;
    /// раньше после 254 созданий сервер не мог создать ни одной группы).
    fn alloc_gid(&mut self) -> Option<u32> {
        let span = GID_MAX - GID_MIN + 1;
        let start = self.next_gid.clamp(GID_MIN, GID_MAX);
        for i in 0..span {
            let gid = GID_MIN + (start - GID_MIN + i) % span;
            if !self.groups.contains_key(&gid) {
                self.next_gid = if gid == GID_MAX { GID_MIN } else { gid + 1 };
                return Some(gid);
            }
        }
        None
    }
}

struct Shared {
    sock: UdpSocket,
    state: RwLock<State>,
    /// Готовый WELCOME (подпись x_pub сервера считается один раз).
    welcome: Vec<u8>,
    started: Instant,
    stop: AtomicBool,
    dirty: AtomicBool,
    per_ip: Mutex<HashMap<IpAddr, Bucket>>,
    quiet: bool,
    store: persist::Store,
    relayed: AtomicU64,
    dropped: AtomicU64,
}

impl Shared {
    fn log(&self, msg: String) {
        if !self.quiet {
            eprintln!("[server] {msg}");
        }
    }

    fn now_ms(&self) -> u64 {
        self.started.elapsed().as_millis() as u64
    }

    fn allow_ip(&self, ip: IpAddr) -> bool {
        let mut m = self.per_ip.lock().unwrap();
        m.entry(ip)
            .or_insert_with(|| Bucket::new(PER_IP_BURST))
            .take(PER_IP_RATE, PER_IP_BURST)
    }

    fn flush(&self, out: Outbox) {
        for (addr, frame) in out {
            let _ = self.sock.send_to(&frame, addr);
        }
    }
}

/// Исходящие датаграммы, собранные под блокировкой и отправляемые после неё.
type Outbox = Vec<(SocketAddr, Vec<u8>)>;

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn short(pk: &[u8; 32]) -> String {
    hex(&pk[..4])
}

fn unhex(s: &str) -> Result<[u8; 32]> {
    let v = proto::hex_to_bytes(s)?;
    anyhow::ensure!(v.len() == 32, "bad hex");
    Ok(v.try_into().unwrap())
}

fn ip_str(ip: u32) -> String {
    std::net::Ipv4Addr::from(ip).to_string()
}

fn gid_subnet_base(gid: u32) -> u32 {
    (100 << 24) | (66 << 16) | (gid << 8)
}

/// Обрезка до `max` символов, без управляющих символов и пробелов по краям.
fn clean(s: &str, max: usize) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .collect::<String>()
        .trim()
        .chars()
        .take(max)
        .collect()
}

// ---------- загрузка/сохранение ----------

fn load_state(store: &persist::Store) -> Result<(proto::Identity, u32, HashMap<u32, Group>)> {
    let Some(p) = store.load()? else {
        return Ok((proto::Identity::generate(), GID_MIN, HashMap::new()));
    };
    let mut groups = HashMap::new();
    for g in p.groups {
        let mut group = Group {
            id: g.id,
            name: g.name,
            owner: unhex(&g.owner)?,
            private: g.private,
            key: g.key,
            members: HashMap::new(),
            by_ip: HashMap::new(),
            banned: g.banned.iter().map(|b| unhex(b)).collect::<Result<HashSet<_>>>()?,
            invites: g.invites.iter().map(|b| unhex(b)).collect::<Result<HashSet<_>>>()?,
        };
        for (k, ip) in g.members {
            if let Ok(pk) = unhex(&k) {
                group.insert_member(
                    pk,
                    Member {
                        ip,
                        name: "…".into(),
                        status: String::new(),
                    },
                );
            }
        }
        groups.insert(g.id, group);
    }
    Ok((
        proto::Identity {
            ed_seed: p.ed_seed,
            x_seed: p.x_seed,
        },
        p.next_gid.clamp(GID_MIN, GID_MAX),
        groups,
    ))
}

fn snapshot(s: &State) -> persist::Persisted {
    persist::Persisted {
        ed_seed: s.identity.ed_seed,
        x_seed: s.identity.x_seed,
        next_gid: s.next_gid,
        groups: s
            .groups
            .values()
            .map(|g| persist::PGroup {
                id: g.id,
                name: g.name.clone(),
                owner: hex(&g.owner),
                private: g.private,
                key: g.key,
                members: g.members.iter().map(|(k, m)| (hex(k), m.ip)).collect(),
                banned: g.banned.iter().map(|b| hex(b)).collect(),
                invites: g.invites.iter().map(|b| hex(b)).collect(),
            })
            .collect(),
    }
}

fn save_now(sh: &Shared) {
    if !sh.dirty.swap(false, Ordering::Relaxed) {
        return;
    }
    let snap = snapshot(&sh.state.read().unwrap());
    if let Err(e) = sh.store.save(&snap) {
        sh.dirty.store(true, Ordering::Relaxed);
        eprintln!("[server] save error: {e}");
    }
}

// ---------- фоновые задачи ----------

fn housekeeping(sh: Arc<Shared>) {
    let mut last_save = Instant::now();
    let mut last_stats = Instant::now();
    let mut last_relayed = 0u64;
    while !sh.stop.load(Ordering::Relaxed) {
        thread::sleep(HOUSEKEEPING_EVERY);
        // Presence: сессии без пакетов дольше SESSION_TIMEOUT.
        let now = sh.now_ms();
        let timeout = SESSION_TIMEOUT.as_millis() as u64;
        let dead: Vec<SocketAddr> = {
            let s = sh.state.read().unwrap();
            s.sessions
                .iter()
                .filter(|(_, ses)| now.saturating_sub(ses.last_seen.load(Ordering::Relaxed)) > timeout)
                .map(|(a, _)| *a)
                .collect()
        };
        if !dead.is_empty() {
            let mut out = Outbox::new();
            {
                let mut s = sh.state.write().unwrap();
                let mut changed: HashSet<u32> = HashSet::new();
                for a in dead {
                    if let Some(ses) = s.remove_session(&a) {
                        changed.extend(s.groups_of(&ses.ed_pub));
                        sh.log(format!("offline: {} ({})", ses.name, short(&ses.ed_pub)));
                    }
                }
                for gid in changed {
                    broadcast_group(&s, gid, &mut out);
                }
                broadcast_group_list(&s, &mut out);
            }
            sh.flush(out);
        }
        // Лимитер по IP: забыть давно молчащих.
        {
            let mut m = sh.per_ip.lock().unwrap();
            m.retain(|_, b| b.last.elapsed() < Duration::from_secs(60));
        }
        if last_save.elapsed() >= SAVE_EVERY {
            last_save = Instant::now();
            save_now(&sh);
        }
        if last_stats.elapsed() >= STATS_EVERY {
            let secs = last_stats.elapsed().as_secs().max(1);
            last_stats = Instant::now();
            let relayed = sh.relayed.load(Ordering::Relaxed);
            let (ses, grp) = {
                let s = sh.state.read().unwrap();
                (s.sessions.len(), s.groups.len())
            };
            sh.log(format!(
                "сессий {ses}, групп {grp}, релей {} пак/с, отброшено всего {}",
                (relayed - last_relayed) / secs,
                sh.dropped.load(Ordering::Relaxed)
            ));
            last_relayed = relayed;
        }
    }
}

// ---------- приём ----------

fn worker(sh: Arc<Shared>) {
    let mut buf = vec![0u8; 65_535];
    while !sh.stop.load(Ordering::Relaxed) {
        let (n, src) = match sh.sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                use std::io::ErrorKind::*;
                match e.kind() {
                    // ConnectionReset — Windows: ICMP unreachable после
                    // отправки ушедшему клиенту. Не ошибка сервера.
                    WouldBlock | TimedOut | ConnectionReset | Interrupted => {}
                    _ => {
                        sh.log(format!("recv: {e}"));
                        thread::sleep(Duration::from_millis(10));
                    }
                }
                continue;
            }
        };
        handle_datagram(&sh, src, &buf[..n]);
    }
}

fn handle_datagram(sh: &Shared, src: SocketAddr, datagram: &[u8]) {
    let Ok((typ, body)) = proto::split_frame(datagram) else {
        sh.dropped.fetch_add(1, Ordering::Relaxed);
        return;
    };
    if (proto::grp::DATA..=proto::grp::KEEPALIVE).contains(&typ) {
        relay_group(sh, src, datagram);
    } else if typ == ctrl::HELLO {
        if !sh.allow_ip(src.ip()) {
            sh.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        if let Err(e) = handle_hello(sh, src, body) {
            sh.log(format!("hello {src}: {e:#}"));
        }
    } else {
        handle_ctrl_frame(sh, src, typ, body);
    }
}

/// Неизвестный адрес шлёт управляющие/групповые фреймы — скорее всего, сервер
/// перезапустился или сессия истекла. Подсказать клиенту переподключиться.
fn send_reset(sh: &Shared, src: SocketAddr) {
    if sh.allow_ip(src.ip()) {
        let _ = sh.sock.send_to(&proto::plain_frame(ctrl::RESET, &[]), src);
    }
}

// ---------- relay ----------

fn relay_group(sh: &Shared, src: SocketAddr, datagram: &[u8]) {
    let Ok((gid, src_ip, dst_ip)) = proto::parse_group_header(datagram) else {
        return;
    };
    let target = {
        let s = sh.state.read().unwrap();
        let Some(ses) = s.sessions.get(&src) else {
            drop(s);
            sh.dropped.fetch_add(1, Ordering::Relaxed);
            send_reset(sh, src);
            return;
        };
        ses.last_seen.store(sh.now_ms(), Ordering::Relaxed);
        let Some(g) = s.groups.get(&gid) else { return };
        // Отправитель — участник группы и пишет от своего IP.
        match g.members.get(&ses.ed_pub) {
            Some(m) if m.ip == src_ip => {}
            _ => {
                sh.dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
        let Some(dst_pk) = g.by_ip.get(&dst_ip) else { return };
        let Some(addr) = s.by_pub.get(dst_pk).copied() else { return };
        if !ses.relay.lock().unwrap().take(RELAY_RATE, RELAY_BURST) {
            sh.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        addr
    };
    sh.relayed.fetch_add(1, Ordering::Relaxed);
    let _ = sh.sock.send_to(datagram, target);
}

// ---------- helpers ----------

fn member_infos(s: &State, g: &Group) -> Vec<MemberInfo> {
    let mut out: Vec<MemberInfo> = g
        .members
        .iter()
        .map(|(pk, m)| {
            let addr = s.by_pub.get(pk);
            MemberInfo {
                pubkey: *pk,
                name: m.name.clone(),
                ip: m.ip,
                online: addr.is_some(),
                status: m.status.clone(),
                endpoint: addr.map(|a| a.to_string()),
            }
        })
        .collect();
    out.sort_by_key(|m| m.ip);
    out
}

fn ctrl_frame(key: &proto::SymKey, typ: u8, payload: &[u8]) -> Vec<u8> {
    proto::seal_ctrl(key, typ, payload)
}

fn push_error(out: &mut Outbox, addr: SocketAddr, key: &proto::SymKey, text: &str) {
    out.push((addr, ctrl_frame(key, ctrl::ERROR, &proto::payloads::enc_error(text))));
}

fn push_group_state(s: &State, gid: u32, addr: SocketAddr, ses: &Session, out: &mut Outbox) {
    let Some(g) = s.groups.get(&gid) else { return };
    let my_ip = g.members.get(&ses.ed_pub).map(|m| m.ip).unwrap_or(0);
    let st = GroupState {
        gid: g.id,
        name: g.name.clone(),
        owner: g.owner,
        private: g.private,
        key: g.key,
        deleted: false,
        my_ip,
        members: member_infos(s, g),
    };
    out.push((
        addr,
        ctrl_frame(&ses.ctrl_key, ctrl::GROUP_STATE, &proto::payloads::enc_group_state(&st)),
    ));
}

/// Состояние группы — всем её онлайн-участникам.
fn broadcast_group(s: &State, gid: u32, out: &mut Outbox) {
    let Some(g) = s.groups.get(&gid) else { return };
    for pk in g.members.keys() {
        if let Some((addr, ses)) = s.session_of(pk) {
            push_group_state(s, gid, addr, ses, out);
        }
    }
}

fn group_summaries_for(s: &State, me: &[u8; 32]) -> Vec<GroupSummary> {
    let mut out = Vec::new();
    for g in s.groups.values() {
        let mine = g.members.contains_key(me);
        if g.private && !mine {
            continue;
        }
        let online = g.members.keys().filter(|pk| s.online(pk)).count() as u32;
        out.push(GroupSummary {
            gid: g.id,
            name: g.name.clone(),
            private: g.private,
            mine,
            online,
            total: g.members.len() as u32,
        });
    }
    out.sort_by_key(|g| g.gid);
    out
}

fn push_group_list(s: &State, addr: SocketAddr, ses: &Session, out: &mut Outbox) {
    let items = group_summaries_for(s, &ses.ed_pub);
    out.push((
        addr,
        ctrl_frame(&ses.ctrl_key, ctrl::GROUP_LIST, &proto::payloads::enc_group_list(&items)),
    ));
}

fn broadcast_group_list(s: &State, out: &mut Outbox) {
    for (a, ses) in &s.sessions {
        push_group_list(s, *a, ses, out);
    }
}

// ---------- HELLO ----------

fn handle_hello(sh: &Shared, src: SocketAddr, body: &[u8]) -> Result<()> {
    let (ed_pub, x_pub, name, version) = proto::payloads::dec_hello(body)?; // проверяет подпись
    let name = match clean(&name, NAME_MAX_CHARS) {
        n if n.is_empty() => "anon".to_string(),
        n => n,
    };
    let mut out = Outbox::new();
    {
        let mut s = sh.state.write().unwrap();
        // Старые сессии этого identity (переподключение с другого адреса) и
        // чужая сессия на этом адресе — убрать.
        let mut status = String::new();
        if let Some(old_addr) = s.by_pub.get(&ed_pub).copied()
            && let Some(old) = s.remove_session(&old_addr)
        {
            status = old.status;
        }
        if let Some(other) = s.remove_session(&src)
            && other.ed_pub == ed_pub
        {
            status = other.status;
        }
        let ctrl_key = s.identity.ctrl_key_with(&x_pub);
        s.sessions.insert(
            src,
            Session {
                ed_pub,
                name: name.clone(),
                status,
                ctrl_key,
                last_seen: AtomicU64::new(sh.now_ms()),
                relay: Mutex::new(Bucket::new(RELAY_BURST)),
                ctrl: Mutex::new(Bucket::new(CTRL_BURST)),
            },
        );
        s.by_pub.insert(ed_pub, src);
        sh.log(format!("online: {name} ({}) @ {src} (v{version})", short(&ed_pub)));
        let gids = s.groups_of(&ed_pub);
        for gid in &gids {
            if let Some(m) = s.groups.get_mut(gid).and_then(|g| g.members.get_mut(&ed_pub)) {
                m.name = name.clone();
            }
        }
        // WELCOME — открытым текстом (x_pub сервера + подпись ed25519).
        out.push((src, proto::plain_frame(ctrl::WELCOME, &sh.welcome)));
        let ses = s.sessions.get(&src).unwrap();
        push_group_list(&s, src, ses, &mut out);
        // Остальные участники групп узнают новый адрес и статус онлайн.
        for gid in gids {
            broadcast_group(&s, gid, &mut out);
        }
    }
    sh.flush(out);
    Ok(())
}

// ---------- остальные команды ----------

fn handle_ctrl_frame(sh: &Shared, src: SocketAddr, typ: u8, body: &[u8]) {
    // Быстрый путь — под блокировкой на чтение: сессия, расшифровка, лимит.
    let (payload, ctrl_key, ed_pub) = {
        let s = sh.state.read().unwrap();
        let Some(ses) = s.sessions.get(&src) else {
            drop(s);
            sh.dropped.fetch_add(1, Ordering::Relaxed);
            send_reset(sh, src);
            return;
        };
        let Ok(payload) = proto::open_ctrl(&ses.ctrl_key, typ, body) else {
            sh.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        };
        ses.last_seen.store(sh.now_ms(), Ordering::Relaxed);
        if !ses.ctrl.lock().unwrap().take(CTRL_RATE, CTRL_BURST) {
            sh.dropped.fetch_add(1, Ordering::Relaxed);
            return;
        }
        (payload, ses.ctrl_key, ses.ed_pub)
    };
    let mut out = Outbox::new();
    let res = match typ {
        ctrl::CTRL_PING => {
            out.push((src, ctrl_frame(&ctrl_key, ctrl::CTRL_PONG, &[])));
            Ok(())
        }
        ctrl::LIST_GROUPS => {
            let s = sh.state.read().unwrap();
            if let Some(ses) = s.sessions.get(&src) {
                push_group_list(&s, src, ses, &mut out);
            }
            Ok(())
        }
        ctrl::FRIEND_GROUPS => friend_groups(sh, src, &ctrl_key, &ed_pub, &payload, &mut out),
        _ => {
            let mut s = sh.state.write().unwrap();
            if s.sessions.contains_key(&src) {
                handle_mutation(sh, &mut s, src, typ, &ctrl_key, &ed_pub, &payload, &mut out)
            } else {
                Ok(())
            }
        }
    };
    if let Err(e) = res {
        sh.log(format!("ctrl {typ:#04x} from {src}: {e:#}"));
        push_error(&mut out, src, &ctrl_key, &format!("{e:#}"));
    }
    sh.flush(out);
}

fn friend_groups(
    sh: &Shared,
    src: SocketAddr,
    key: &proto::SymKey,
    me: &[u8; 32],
    payload: &[u8],
    out: &mut Outbox,
) -> Result<()> {
    let target = proto::payloads::dec_pubkey(payload)?;
    let s = sh.state.read().unwrap();
    let mut items = Vec::new();
    for g in s.groups.values() {
        let i_am = g.members.contains_key(me);
        let he_is = g.members.contains_key(&target);
        if !(he_is && (!g.private || i_am)) {
            continue;
        }
        items.push(proto::payloads::FriendGroup {
            gid: g.id,
            name: g.name.clone(),
            private: g.private,
            shared: i_am && he_is,
        });
    }
    items.sort_by_key(|g| g.gid);
    out.push((
        src,
        ctrl_frame(key, ctrl::FRIEND_GROUPS_RESP, &proto::payloads::enc_friend_groups(&items)),
    ));
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn handle_mutation(
    sh: &Shared,
    s: &mut State,
    src: SocketAddr,
    typ: u8,
    ctrl_key: &proto::SymKey,
    ed_pub: &[u8; 32],
    payload: &[u8],
    out: &mut Outbox,
) -> Result<()> {
    let uname = s.sessions.get(&src).map(|x| x.name.clone()).unwrap_or_default();
    let ustatus = s.sessions.get(&src).map(|x| x.status.clone()).unwrap_or_default();
    match typ {
        ctrl::STATUS => {
            let text = clean(&proto::payloads::dec_status(payload)?, STATUS_MAX_CHARS);
            if let Some(ses) = s.sessions.get_mut(&src) {
                ses.status = text.clone();
            }
            let gids = s.groups_of(ed_pub);
            for gid in &gids {
                if let Some(m) = s.groups.get_mut(gid).and_then(|g| g.members.get_mut(ed_pub)) {
                    m.status = text.clone();
                }
            }
            for gid in gids {
                broadcast_group(s, gid, out);
            }
        }
        ctrl::CREATE_GROUP => {
            let (name, private) = proto::payloads::dec_create_group(payload)?;
            let name = clean(&name, GROUP_NAME_MAX_CHARS);
            anyhow::ensure!(!name.is_empty(), "пустое имя группы");
            let gid = s
                .alloc_gid()
                .context("нет свободных подсетей (все 254 группы заняты)")?;
            let mut key = [0u8; 32];
            rand::rng().fill_bytes(&mut key);
            let mut g = Group {
                id: gid,
                name: name.clone(),
                owner: *ed_pub,
                private,
                key,
                members: HashMap::new(),
                by_ip: HashMap::new(),
                banned: HashSet::new(),
                invites: HashSet::new(),
            };
            g.insert_member(
                *ed_pub,
                Member {
                    ip: gid_subnet_base(gid) + HOST_MIN,
                    name: uname.clone(),
                    status: ustatus,
                },
            );
            s.groups.insert(gid, g);
            sh.dirty.store(true, Ordering::Relaxed);
            sh.log(format!("created group {gid} \"{name}\" by {uname}"));
            let ses = s.sessions.get(&src).unwrap();
            push_group_state(s, gid, src, ses, out);
            broadcast_group_list(s, out);
        }
        ctrl::JOIN_GROUP => {
            let gid = proto::payloads::dec_gid(payload)?;
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(!g.banned.contains(ed_pub), "вы забанены в этой группе");
            let is_member = g.members.contains_key(ed_pub);
            if g.private && !is_member && g.owner != *ed_pub {
                anyhow::ensure!(g.invites.contains(ed_pub), "группа приватная, нужно приглашение");
                g.invites.remove(ed_pub);
            }
            let ip = match g.members.get(ed_pub) {
                Some(m) => m.ip, // lease сохраняется
                None => g.next_free_ip().context("группа заполнена")?,
            };
            let gname = g.name.clone();
            g.insert_member(
                *ed_pub,
                Member {
                    ip,
                    name: uname.clone(),
                    status: ustatus,
                },
            );
            if !is_member {
                sh.dirty.store(true, Ordering::Relaxed);
                sh.log(format!("join: {uname} → {gid} \"{gname}\" as {}", ip_str(ip)));
            }
            // broadcast_group включает и самого вошедшего.
            broadcast_group(s, gid, out);
            if !is_member {
                broadcast_group_list(s, out);
            }
        }
        ctrl::LEAVE_GROUP => {
            let gid = proto::payloads::dec_gid(payload)?;
            let left = s
                .groups
                .get_mut(&gid)
                .map(|g| g.remove_member(ed_pub))
                .unwrap_or(false);
            if left {
                sh.dirty.store(true, Ordering::Relaxed);
                sh.log(format!("leave: {uname} ← {gid}"));
                broadcast_group(s, gid, out);
                broadcast_group_list(s, out);
            } else {
                // Повторный LEAVE (клиент повторяет до подтверждения) —
                // подтвердить списком только ему.
                let ses = s.sessions.get(&src).unwrap();
                push_group_list(s, src, ses, out);
            }
        }
        ctrl::INVITE => {
            let (gid, target) = proto::payloads::dec_gid_target(payload)?;
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == *ed_pub, "приглашать может только владелец");
            anyhow::ensure!(!g.banned.contains(&target), "цель забанена");
            g.invites.insert(target);
            let invite = proto::payloads::InviteInfo {
                gid,
                group_name: g.name.clone(),
                from_pubkey: *ed_pub,
                from_name: uname,
            };
            sh.dirty.store(true, Ordering::Relaxed);
            sh.log(format!("invite: {gid} → {}", short(&target)));
            if let Some((addr, ses)) = s.session_of(&target) {
                out.push((
                    addr,
                    ctrl_frame(&ses.ctrl_key, ctrl::INVITE_RCVD, &proto::payloads::enc_invite(&invite)),
                ));
            }
        }
        ctrl::KICK | ctrl::BAN => {
            let (gid, target) = proto::payloads::dec_gid_target(payload)?;
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == *ed_pub, "может только владелец");
            anyhow::ensure!(target != g.owner, "нельзя исключить владельца");
            let kicked = g.remove_member(&target);
            if typ == ctrl::BAN {
                g.banned.insert(target);
                g.invites.remove(&target);
            }
            let msg = if typ == ctrl::BAN { "забанен в" } else { "кикнут из" };
            let gname = g.name.clone();
            sh.dirty.store(true, Ordering::Relaxed);
            sh.log(format!("{msg} {gid}: {}", short(&target)));
            if kicked && let Some((addr, ses)) = s.session_of(&target) {
                push_error(out, addr, &ses.ctrl_key, &format!("вас {msg} группу \"{gname}\""));
            }
            broadcast_group(s, gid, out);
            broadcast_group_list(s, out);
        }
        ctrl::RENAME_GROUP => {
            let (gid, name) = proto::payloads::dec_rename(payload)?;
            let name = clean(&name, GROUP_NAME_MAX_CHARS);
            let g = s.groups.get_mut(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == *ed_pub, "может только владелец");
            anyhow::ensure!(!name.is_empty(), "пустое имя группы");
            g.name = name.clone();
            sh.dirty.store(true, Ordering::Relaxed);
            sh.log(format!("renamed {gid} → \"{name}\""));
            broadcast_group(s, gid, out);
            broadcast_group_list(s, out);
        }
        ctrl::DELETE_GROUP => {
            let gid = proto::payloads::dec_gid(payload)?;
            let g = s.groups.get(&gid).context("группа не найдена")?;
            anyhow::ensure!(g.owner == *ed_pub, "может только владелец");
            let removed = s.groups.remove(&gid).unwrap();
            sh.dirty.store(true, Ordering::Relaxed);
            sh.log(format!("deleted group {gid}"));
            let st = GroupState {
                gid,
                name: String::new(),
                owner: [0; 32],
                private: false,
                key: [0; 32],
                deleted: true,
                my_ip: 0,
                members: vec![],
            };
            let frame = proto::payloads::enc_group_state(&st);
            for pk in removed.members.keys() {
                if let Some((addr, ses)) = s.session_of(pk) {
                    out.push((addr, ctrl_frame(&ses.ctrl_key, ctrl::GROUP_STATE, &frame)));
                }
            }
            broadcast_group_list(s, out);
        }
        _ => {
            let _ = ctrl_key;
        }
    }
    Ok(())
}

/// Путь к данным по умолчанию.
pub fn default_data_dir() -> &'static Path {
    Path::new("tunnel-data")
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::payloads;

    fn empty_group(id: u32) -> Group {
        Group {
            id,
            name: String::new(),
            owner: [0; 32],
            private: false,
            key: [0; 32],
            members: HashMap::new(),
            by_ip: HashMap::new(),
            banned: HashSet::new(),
            invites: HashSet::new(),
        }
    }

    #[test]
    fn gid_переиспользуется_после_удаления() {
        let mut s = State {
            identity: proto::Identity::generate(),
            sessions: HashMap::new(),
            by_pub: HashMap::new(),
            groups: HashMap::new(),
            next_gid: GID_MAX,
        };
        // Последний gid, затем по кругу с начала.
        assert_eq!(s.alloc_gid(), Some(GID_MAX));
        assert_eq!(s.alloc_gid(), Some(GID_MIN));
        // Заняты все, кроме 7, — выдаётся 7; заняты все — None.
        for gid in GID_MIN..=GID_MAX {
            if gid != 7 {
                s.groups.insert(gid, empty_group(gid));
            }
        }
        assert_eq!(s.alloc_gid(), Some(7));
        s.groups.insert(7, empty_group(7));
        assert_eq!(s.alloc_gid(), None);
    }

    #[test]
    fn имена_чистятся_и_обрезаются() {
        assert_eq!(clean("  ok\u{0}\n ", 10), "ok");
        assert_eq!(clean(&"я".repeat(50), 5), "яяяяя");
    }

    /// «Сырой» клиент поверх протокола — без движка клиента.
    struct Raw {
        sock: UdpSocket,
        key: proto::SymKey,
        srv: SocketAddr,
    }

    impl Raw {
        fn connect(srv: SocketAddr, name: &str) -> Raw {
            let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
            sock.set_read_timeout(Some(Duration::from_millis(300))).unwrap();
            let id = proto::Identity::generate();
            let sig = id.sign(&payloads::hello_sign_bytes(
                &id.ed_pub(),
                &id.x_pub(),
                name,
                proto::PROTOCOL_VERSION,
            ));
            let hello =
                payloads::enc_hello(&id.ed_pub(), &id.x_pub(), name, proto::PROTOCOL_VERSION, &sig);
            sock.send_to(&proto::plain_frame(ctrl::HELLO, &hello), srv).unwrap();
            let end = Instant::now() + Duration::from_secs(5);
            let mut buf = [0u8; 65_535];
            while Instant::now() < end {
                let Ok((n, _)) = sock.recv_from(&mut buf) else { continue };
                let (typ, body) = proto::split_frame(&buf[..n]).unwrap();
                if typ == ctrl::WELCOME {
                    let (x_pub, _sig) = payloads::dec_welcome(body).unwrap();
                    let key = id.ctrl_key_with(&x_pub);
                    return Raw { sock, key, srv };
                }
            }
            panic!("нет WELCOME");
        }

        fn send(&self, typ: u8, payload: &[u8]) {
            self.sock
                .send_to(&proto::seal_ctrl(&self.key, typ, payload), self.srv)
                .unwrap();
        }

        /// Следующий управляющий фрейм нужного типа (прочие пропускаются).
        fn expect(&self, want: u8) -> Vec<u8> {
            let end = Instant::now() + Duration::from_secs(5);
            let mut buf = [0u8; 65_535];
            while Instant::now() < end {
                let Ok((n, _)) = self.sock.recv_from(&mut buf) else { continue };
                let Ok((typ, body)) = proto::split_frame(&buf[..n]) else { continue };
                if typ != want {
                    continue;
                }
                return proto::open_ctrl(&self.key, typ, body).unwrap();
            }
            panic!("не дождались фрейма {want:#04x}");
        }

        /// Ждёт групповой фрейм; None — ничего не пришло за `wait`.
        fn group_frame(&self, wait: Duration) -> Option<Vec<u8>> {
            let end = Instant::now() + wait;
            let mut buf = [0u8; 65_535];
            while Instant::now() < end {
                let Ok((n, _)) = self.sock.recv_from(&mut buf) else { continue };
                let Ok((typ, _)) = proto::split_frame(&buf[..n]) else { continue };
                if (proto::grp::DATA..=proto::grp::KEEPALIVE).contains(&typ) {
                    return Some(buf[..n].to_vec());
                }
            }
            None
        }
    }

    #[test]
    fn сервер_релеит_только_своим_и_сохраняет_состояние() {
        let dir = std::env::temp_dir().join(format!("voidlink-srv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let server = Server::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.clone(),
            workers: 2,
            quiet: true,
        })
        .unwrap();
        let srv = server.addr;

        let a = Raw::connect(srv, "alpha");
        a.expect(ctrl::GROUP_LIST);
        a.send(ctrl::CTRL_PING, &[]);
        a.expect(ctrl::CTRL_PONG);

        a.send(ctrl::CREATE_GROUP, &payloads::enc_create_group("  game\n", false));
        let st = payloads::dec_group_state(&a.expect(ctrl::GROUP_STATE)).unwrap();
        assert_eq!(st.name, "game", "имя группы очищено");
        let (gid, key, ip_a) = (st.gid, st.key, st.my_ip);

        let b = Raw::connect(srv, "bravo");
        b.send(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
        let st_b = payloads::dec_group_state(&b.expect(ctrl::GROUP_STATE)).unwrap();
        let ip_b = st_b.my_ip;
        assert_ne!(ip_a, ip_b);

        // Свой src_ip — релеится.
        let ok = proto::seal_group(&key, proto::grp::DATA, gid, ip_a, ip_b, b"hi");
        a.sock.send_to(&ok, srv).unwrap();
        let got = b.group_frame(Duration::from_secs(3)).expect("релей своего фрейма");
        assert_eq!(got, ok);

        // Чужой src_ip (подмена) — отбрасывается.
        let spoof = proto::seal_group(&key, proto::grp::DATA, gid, ip_b, ip_b, b"spoof");
        a.sock.send_to(&spoof, srv).unwrap();
        assert!(
            b.group_frame(Duration::from_millis(700)).is_none(),
            "подмена src_ip релеится"
        );

        // Выход; повторный LEAVE тоже подтверждается списком.
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
        b.expect(ctrl::GROUP_LIST);
        b.send(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
        b.expect(ctrl::GROUP_LIST);
        a.sock.send_to(&ok, srv).unwrap();
        assert!(
            b.group_frame(Duration::from_millis(700)).is_none(),
            "релей после выхода"
        );

        // Сохранение и повторная загрузка: identity и группа на месте.
        let code = server.code.clone();
        server.stop();
        let again = Server::start(Config {
            listen: "127.0.0.1:0".parse().unwrap(),
            data_dir: dir.clone(),
            workers: 1,
            quiet: true,
        })
        .unwrap();
        assert_eq!(again.code, code, "identity сервера сохранилась");
        assert!(again.shared.state.read().unwrap().groups.contains_key(&gid));
        again.stop();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
