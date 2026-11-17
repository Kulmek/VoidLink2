//! `EngineBackend` — бэкенд демона поверх настоящего движка `tunnel-client`
//! (PLAN.md 7.1/7.3).
//!
//! - снимок — [`tunnel_client::snapshot::Snapshot`] из состояния движка
//!   (группы, meta, счётчики, `CfgView` без identity) плюс неотвеченные
//!   приглашения — всё это строит `tunnel_client::api::LocalEngine` (тот же
//!   код, что у embedded TUI, поэтому снимки совпадают — PLAN.md 7.7);
//! - события — `Event` движка в JSON (serde, внешний тег);
//! - команды — JSON-форма `Cmd` движка; правки конфига (`AddFriend`,
//!   `DelServer`…) проверяются до отправки, отказ уходит клиенту в `Ack`.
//!
//! [`start_from_dir`] поднимает движок по `client.json` каталога данных
//! демона с настоящим TUN (Wintun / utun / Linux TUN — нужны права
//! администратора); тесты собирают движок сами и отдают его в
//! [`EngineBackend::new`].

use std::net::SocketAddr;
use std::path::Path;
use std::sync::{Arc, Mutex};

use serde_json::{Value, json};
use tunnel_client::api::{EngineApi, LocalEngine};
use tunnel_client::engine::{self, Cmd, Engine};
use tunnel_client::snapshot::Snapshot;
use tunnel_client::store::{self, Config};
use tunnel_protocol as proto;

use crate::hub::Backend;
use crate::log::{Level, LogFn};

/// Имя адаптера Wintun службы.
pub const ADAPTER_NAME: &str = "TunnelVPN";

/// Бэкенд на живом движке: [`LocalEngine`] (снимок, приглашения, проверка
/// команд — тот же код, что у embedded TUI) в JSON-обёртке.
pub struct EngineBackend {
    local: LocalEngine,
    /// Что ещё живёт вместе с движком (tun-поток демона).
    _guard: Mutex<Option<Box<dyn Send>>>,
}

impl EngineBackend {
    /// Обернуть запущенный движок.
    pub fn new(eng: Engine) -> Self {
        Self::with_guard(eng, None)
    }

    fn with_guard(eng: Engine, guard: Option<Box<dyn Send>>) -> Self {
        EngineBackend { local: LocalEngine::new(eng), _guard: Mutex::new(guard) }
    }

    /// Типизированный снимок (то же, что [`Backend::snapshot`] до JSON).
    pub fn snapshot_typed(&self) -> Snapshot {
        self.local.snapshot_now()
    }

    /// Движок как [`EngineApi`].
    pub fn local(&self) -> &LocalEngine {
        &self.local
    }
}

impl Backend for EngineBackend {
    fn snapshot(&self) -> Value {
        serde_json::to_value(self.snapshot_typed()).unwrap_or(Value::Null)
    }

    fn poll_events(&self) -> Vec<Value> {
        self.local.poll_events().into_iter().filter_map(|e| serde_json::to_value(e).ok()).collect()
    }

    fn send(&self, cmd: Value) -> Result<(), String> {
        let cmd: Cmd = serde_json::from_value(cmd).map_err(|e| format!("неверная команда: {e}"))?;
        if matches!(cmd, Cmd::Quit) {
            return Err("демон не завершается по команде фронтенда".into());
        }
        self.local.send(cmd).map_err(|e| e.to_string())
    }

    fn me(&self) -> Value {
        self.local.me().to_json()
    }

    fn changed(&self) -> bool {
        self.local.changed()
    }
}

/// Сервер для запуска: текущий (`active_server`), иначе первый в списке.
pub fn pick_server(cfg: &Config) -> Result<(SocketAddr, [u8; 32]), String> {
    let entry = cfg
        .servers
        .iter()
        .find(|s| s.addr.parse::<SocketAddr>().is_ok_and(|a| a.to_string() == cfg.active_server))
        .or(cfg.servers.first())
        .ok_or("в конфиге нет серверов (добавьте: tunnel-client --dir <каталог данных> add-server …)")?;
    let addr: SocketAddr = entry.addr.parse().map_err(|_| format!("неверный адрес сервера «{}»", entry.addr))?;
    let pk = proto::hex_to_bytes(&entry.pubkey)
        .ok()
        .and_then(|v| <[u8; 32]>::try_from(v).ok())
        .ok_or(format!("неверный ключ сервера {addr}"))?;
    Ok((addr, pk))
}

/// Движок по `client.json` каталога данных демона с настоящим TUN.
pub fn start_from_dir(data_dir: &Path, log: LogFn) -> Result<EngineBackend, String> {
    let st = Arc::new(store::Store::new(data_dir));
    let mut cfg = st.load().map_err(|e| format!("чтение конфига: {e:#}"))?;
    if cfg.identity.is_none() {
        let id = store::ensure_identity(&mut cfg);
        st.save(&cfg).map_err(|e| format!("запись конфига: {e:#}"))?;
        log(Level::Info, &format!("создана новая identity: {}", id.friend_code()));
    }
    let identity = store::ensure_identity(&mut cfg);
    let (server, server_pub) = pick_server(&cfg)?;
    let mtu = cfg.mtu();
    let cfg = Arc::new(Mutex::new(cfg));
    let save: Arc<dyn Fn(&Config) + Send + Sync> = {
        let log = log.clone();
        Arc::new(move |c: &Config| {
            if let Err(e) = st.save(c) {
                log(Level::Error, &format!("запись конфига: {e:#}"));
            }
        })
    };
    log(Level::Info, &format!("движок: сервер {server}"));
    platform_start(cfg, server, server_pub, identity, save, mtu).map_err(|e| format!("движок: {e:#}"))
}

#[cfg(windows)]
fn platform_start(
    cfg: Arc<Mutex<Config>>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
    _mtu: usize,
) -> anyhow::Result<EngineBackend> {
    let eng = engine::start(cfg, server, server_pub, identity, ADAPTER_NAME, None, save)?;
    Ok(EngineBackend::new(eng))
}

#[cfg(target_os = "macos")]
fn platform_start(
    cfg: Arc<Mutex<Config>>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
    mtu: usize,
) -> anyhow::Result<EngineBackend> {
    use tunnel_client::tun_macos::Utun;

    struct Dev(Arc<Utun>);
    impl engine::TunDev for Dev {
        fn inject(&self, packet: &[u8]) -> anyhow::Result<()> {
            self.0.write(packet)?;
            Ok(())
        }
        fn ensure_address(&self, ip: u32) -> anyhow::Result<()> {
            self.0.ensure_address(ip)
        }
    }

    let tun = Arc::new(Utun::open(mtu)?);
    let eng = engine::start_with_tun(cfg, server, server_pub, identity, Arc::new(Dev(tun.clone())), save)?;
    let sink = eng.ip_sink();
    // read() блокирующий: поток живёт до конца процесса демона.
    std::thread::Builder::new().name("tun".into()).spawn(move || {
        let mut buf = vec![0u8; 65536];
        loop {
            match tun.read(&mut buf) {
                Ok(n) => sink(&buf[..n]),
                Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {}
                Err(_) => break,
            }
        }
    })?;
    Ok(EngineBackend::new(eng))
}

#[cfg(target_os = "linux")]
fn platform_start(
    cfg: Arc<Mutex<Config>>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    save: Arc<dyn Fn(&Config) + Send + Sync>,
    mtu: usize,
) -> anyhow::Result<EngineBackend> {
    use tunnel_client::tun_linux::{LinuxTun, spawn_reader};

    struct Dev(Arc<LinuxTun>);
    impl engine::TunDev for Dev {
        fn inject(&self, packet: &[u8]) -> anyhow::Result<()> {
            self.0.write(packet)
        }
        fn ensure_address(&self, ip: u32) -> anyhow::Result<()> {
            self.0.ensure_address(ip)
        }
    }

    let tun = Arc::new(LinuxTun::open("tunnel0", mtu)?);
    let eng = engine::start_with_tun(cfg, server, server_pub, identity, Arc::new(Dev(tun.clone())), save)?;
    let sink = eng.ip_sink();
    let reader = spawn_reader(tun, move |p| {
        sink(p);
        true
    })?;
    Ok(EngineBackend::with_guard(eng, Some(Box::new(reader))))
}

#[cfg(not(any(windows, target_os = "macos", target_os = "linux")))]
fn platform_start(
    _cfg: Arc<Mutex<Config>>,
    _server: SocketAddr,
    _server_pub: [u8; 32],
    _identity: proto::Identity,
    _save: Arc<dyn Fn(&Config) + Send + Sync>,
    _mtu: usize,
) -> anyhow::Result<EngineBackend> {
    anyhow::bail!("TUN на этой ОС не поддерживается")
}

/// Бэкенд `console`: живой движок или ошибка запуска (демон тогда сразу
/// останавливается, а ошибка возвращается из `main`).
pub enum ConsoleBackend {
    Live(Box<EngineBackend>),
    Failed(String),
}

impl Backend for ConsoleBackend {
    fn snapshot(&self) -> Value {
        match self {
            ConsoleBackend::Live(b) => b.snapshot(),
            ConsoleBackend::Failed(e) => json!({ "engine": null, "error": e }),
        }
    }
    fn poll_events(&self) -> Vec<Value> {
        match self {
            ConsoleBackend::Live(b) => b.poll_events(),
            ConsoleBackend::Failed(_) => Vec::new(),
        }
    }
    fn send(&self, cmd: Value) -> Result<(), String> {
        match self {
            ConsoleBackend::Live(b) => b.send(cmd),
            ConsoleBackend::Failed(e) => Err(e.clone()),
        }
    }
    fn me(&self) -> Value {
        match self {
            ConsoleBackend::Live(b) => b.me(),
            ConsoleBackend::Failed(_) => Value::Null,
        }
    }
    fn changed(&self) -> bool {
        match self {
            ConsoleBackend::Live(b) => b.changed(),
            ConsoleBackend::Failed(_) => false,
        }
    }
}
