//! Клиент туннеля (аналог Hamachi): виртуальный адаптер Wintun + UDP.
//!
//! Подключается к рандеву-серверу, получает виртуальный IP 10.66.0.x,
//! настраивает адаптер и гоняет IP-пакеты до других пиров: сначала через
//! релей сервера (ping работает сразу), затем напрямую после UDP hole
//! punching.

use std::collections::HashMap;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tunnel_protocol as proto;

const ADAPTER_DEFAULT: &str = "TunnelVPN";
const MTU: usize = 1400;
const RING_CAPACITY: u32 = 0x40_0000; // 4 MiB

struct Peer {
    name: String,
    endpoint: SocketAddr,
    direct: bool,
    last_rx: Instant,
}

struct Shared {
    server: SocketAddr,
    own_ip: u32,
    /// Ключ — виртуальный IP пира.
    peers: HashMap<u32, Peer>,
}

type SharedRef = Arc<Mutex<Shared>>;

/// Сессия TUN, общая для recv-потока (вброс пакетов) и tun-потока (чтение).
static TUN_SESSION: Mutex<Option<Arc<wintun::Session>>> = Mutex::new(None);

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

fn main() -> Result<()> {
    let mut server: Option<SocketAddr> = None;
    let mut key_str: Option<String> = None;
    let mut name: Option<String> = None;
    let mut adapter_name = ADAPTER_DEFAULT.to_string();
    let mut dll: Option<String> = None;

    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                eprintln!("Usage: tunnel-client --server <ip:port> --key <room-key> --name <name> [--adapter <name>] [--dll <path>]");
                return Ok(());
            }
            "--server" => { server = Some(args.get(i + 1).context("--server requires value")?.parse().context("bad server addr")?); i += 1; }
            "--key" => { key_str = Some(args.get(i + 1).context("--key requires value")?.clone()); i += 1; }
            "--name" => { name = Some(args.get(i + 1).context("--name requires value")?.clone()); i += 1; }
            "--adapter" => { adapter_name = args.get(i + 1).context("--adapter requires value")?.clone(); i += 1; }
            "--dll" => { dll = Some(args.get(i + 1).context("--dll requires value")?.clone()); i += 1; }
            other => anyhow::bail!("unknown arg {other:?}, see --help"),
        }
        i += 1;
    }
    let server = server.context("--server is required")?;
    let key_str = key_str.context("--key is required")?;
    let name = name.unwrap_or_else(|| "pc".to_string());
    DEBUG.store(std::env::var("TUNNEL_DEBUG").is_ok(), std::sync::atomic::Ordering::Relaxed);

    let key = proto::derive_key(&key_str);
    let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").context("bind udp")?);

    let shared: SharedRef = Arc::new(Mutex::new(Shared {
        server,
        own_ip: 0,
        peers: HashMap::new(),
    }));

    // --- регистрация на сервере ---
    let (tx_welcome, rx_welcome) = mpsc::channel::<u32>();
    let reg = proto::seal(&key, proto::msg::REG, &proto::enc_reg(&key_str, &name));
    socket.send_to(&reg, server)?;

    let _recv_thread = spawn_recv_thread(socket.clone(), key, shared.clone(), tx_welcome);

    let own_ip = rx_welcome
        .recv_timeout(Duration::from_secs(10))
        .context("нет WELCOME от сервера (сервер доступен? ключ совпадает?)")?;
    shared.lock().unwrap().own_ip = own_ip;
    eprintln!("[client] registered as {} ({name})", fmt_ip(own_ip));

    // --- виртуальный адаптер ---
    let wintun = load_wintun_dll(dll.as_deref())?;
    let adapter = match wintun::Adapter::create(&wintun, &adapter_name, "Tunnel", None) {
        Ok(a) => {
            eprintln!("[client] adapter {adapter_name} created");
            a
        }
        Err(_) => {
            let a = wintun::Adapter::open(&wintun, &adapter_name)
                .context("не удалось создать/открыть wintun-адаптер (запуск от администратора?)")?;
            eprintln!("[client] adapter {adapter_name} reused");
            a
        }
    };
    let ip: Ipv4Addr = own_ip.into();
    adapter
        .set_network_addresses_tuple(ip.into(), "255.255.255.0".parse().unwrap(), None)
        .context("failed to set adapter address")?;
    adapter.set_mtu(MTU).context("failed to set mtu")?;
    allow_firewall(&adapter_name);
    eprintln!("[client] adapter configured: {}/24, mtu {MTU}", fmt_ip(own_ip));

    let session = Arc::new(adapter.start_session(RING_CAPACITY)?);
    *TUN_SESSION.lock().unwrap() = Some(session.clone());

    // --- поток чтения TUN: IP-пакеты наружу ---
    spawn_tun_thread(session.clone(), socket.clone(), key, shared.clone());

    // --- keepalive + punch, навсегда ---
    loop {
        thread::sleep(Duration::from_secs(5));
        let now = Instant::now();
        let mut targets: Vec<SocketAddr> = vec![server];
        let mut lines = Vec::new();
        {
            let sh = shared.lock().unwrap();
            for (ip, p) in &sh.peers {
                targets.push(p.endpoint);
                if now.duration_since(p.last_rx) <= Duration::from_secs(30) {
                    lines.push(format!(
                        "[client] peer {} ({}) via {}",
                        fmt_ip(*ip),
                        p.name,
                        if p.direct { "direct p2p" } else { "relay" }
                    ));
                }
            }
        }
        for l in lines {
            eprintln!("{l}");
        }
        for addr in targets {
            let is_server = addr == server;
            let typ = if is_server { proto::msg::KEEPALIVE } else { proto::msg::PUNCH };
            let frame = proto::seal(&key, typ, &proto::enc_sender_ip(own_ip));
            let _ = socket.send_to(&frame, addr);
            if !is_server {
                let ka = proto::seal(&key, proto::msg::KEEPALIVE, &proto::enc_sender_ip(own_ip));
                let _ = socket.send_to(&ka, addr);
            }
        }
    }
}

fn fmt_ip(ip: u32) -> String {
    Ipv4Addr::from(ip).to_string()
}

fn load_wintun_dll(explicit: Option<&str>) -> Result<wintun::Wintun> {
    // SAFETY: загрузка подписанного драйвера wintun.
    if let Some(p) = explicit {
        return unsafe { wintun::load_from_path(p) }.context(format!("cannot load {p}"));
    }
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let p = dir.join("wintun.dll");
            if p.exists() {
                return unsafe { wintun::load_from_path(&p) }
                    .context(format!("cannot load {}", p.display()));
            }
        }
    }
    unsafe { wintun::load_from_path("wintun.dll") }
        .context("wintun.dll not found (положи рядом с exe или укажи --dll)")
}

/// Разово разрешает входящий трафик на интерфейсе (best effort).
fn allow_firewall(adapter_name: &str) {
    let rule = format!("name=\"{adapter_name} Allow\"");
    let _ = Command::new("netsh")
        .args(["advfirewall", "firewall", "delete", "rule", &rule])
        .output();
    let _ = Command::new("netsh")
        .args([
            "advfirewall", "firewall", "add", "rule", &rule,
            "dir=in", "action=allow", &format!("interface={adapter_name}"),
        ])
        .output();
}

fn spawn_recv_thread(
    socket: Arc<UdpSocket>,
    key: proto::SymKey,
    shared: SharedRef,
    tx_welcome: mpsc::Sender<u32>,
) -> Result<thread::JoinHandle<()>> {
    thread::Builder::new()
        .name("recv".into())
        .spawn(move || {
            let mut buf = vec![0u8; 65_535];
            loop {
                let (n, src) = match socket.recv_from(&mut buf) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("[client] recv error: {e}");
                        continue;
                    }
                };
                let (typ, payload) = match proto::open(&key, &buf[..n]) {
                    Ok(x) => x,
                    Err(_) => continue,
                };
                match typ {
                    proto::msg::WELCOME => {
                        if let Ok(ip) = proto::dec_welcome(&payload) {
                            let _ = tx_welcome.send(ip);
                        }
                    }
                    proto::msg::ROSTER => {
                        let entries = match proto::dec_roster(&payload) {
                            Ok(e) => e,
                            Err(_) => continue,
                        };
                        let own_ip = shared.lock().unwrap().own_ip;
                        let mut to_punch: Vec<SocketAddr> = Vec::new();
                        {
                            let mut s = shared.lock().unwrap();
                            let known: std::collections::HashSet<u32> =
                                entries.iter().map(|e| e.ip).collect();
                            s.peers.retain(|ip, _| known.contains(ip) && *ip != own_ip);
                            for e in entries {
                                if e.ip == own_ip {
                                    continue;
                                }
                                let endpoint: SocketAddr = match e.endpoint.parse() {
                                    Ok(a) => a,
                                    Err(_) => continue,
                                };
                                let entry = s.peers.entry(e.ip).or_insert_with(|| Peer {
                                    name: e.name.clone(),
                                    endpoint,
                                    direct: false,
                                    last_rx: Instant::now(),
                                });
                                entry.name = e.name;
                                entry.endpoint = endpoint;
                                to_punch.push(endpoint);
                            }
                        }
                        // Сразу пробиваем NAT к каждому пиру.
                        for addr in to_punch {
                            let frame =
                                proto::seal(&key, proto::msg::PUNCH, &proto::enc_sender_ip(own_ip));
                            let _ = socket.send_to(&frame, addr);
                        }
                    }
                    proto::msg::PUNCH | proto::msg::KEEPALIVE => {
                        let sender_ip = match proto::dec_sender_ip(&payload) {
                            Ok(ip) => ip,
                            Err(_) => continue,
                        };
                        let mut s = shared.lock().unwrap();
                        let server_addr2 = s.server;
                        if sender_ip != s.own_ip {
                            if let Some(p) = s.peers.get_mut(&sender_ip) {
                                if src != server_addr2 && !p.direct {
                                    p.direct = true;
                                    p.endpoint = src;
                                    eprintln!(
                                        "[client] peer {} ({}) established direct p2p",
                                        fmt_ip(sender_ip),
                                        p.name
                                    );
                                }
                                p.last_rx = Instant::now();
                            }
                        }
                        if typ == proto::msg::PUNCH {
                            let own = s.own_ip;
                            drop(s);
                            let frame =
                                proto::seal(&key, proto::msg::PUNCH, &proto::enc_sender_ip(own));
                            let _ = socket.send_to(&frame, src);
                        }
                    }
                    proto::msg::DATA => {
                        let (dst, packet) = match proto::dec_data(&payload) {
                            Ok(x) => x,
                            Err(_) => continue,
                        };
                        if packet.len() >= 20 && packet[9] == 1
                            && DEBUG.load(std::sync::atomic::Ordering::Relaxed)
                        {
                            eprintln!(
                                "[client recv] DATA icmp: {} -> {} len {}",
                                Ipv4Addr::from(proto::ipv4_src(packet).unwrap_or(0)),
                                Ipv4Addr::from(dst),
                                packet.len()
                            );
                        }
                        let server_addr = shared.lock().unwrap().server;
                        if src != server_addr {
                            // Пакет пришёл напрямую: запоминаем endpoint пира.
                            if let Ok(src_ip) = proto::ipv4_src(packet) {
                                let mut s = shared.lock().unwrap();
                                if src_ip != s.own_ip {
                                    if let Some(p) = s.peers.get_mut(&src_ip) {
                                        if !p.direct {
                                            p.direct = true;
                                            p.endpoint = src;
                                            eprintln!(
                                                "[client] peer {} ({}) established direct p2p",
                                                fmt_ip(src_ip),
                                                p.name
                                            );
                                        }
                                        p.last_rx = Instant::now();
                                    }
                                }
                            }
                        }
                        // Вбрасываем пакет в TUN, если адресат — мы.
                        let own_ip = shared.lock().unwrap().own_ip;
                        if dst == own_ip {
                            if let Err(e) = inject_packet(packet) {
                                eprintln!("[client] inject error: {e}");
                            }
                        }
                    }
                    _ => {}
                }
            }
        })
        .context("spawn recv thread")
}

fn inject_packet(packet: &[u8]) -> Result<()> {
    let session = TUN_SESSION.lock().unwrap().clone();
    let Some(session) = session else {
        return Ok(()); // TUN ещё не поднят — пакеты рано
    };
    let mut p = session
        .allocate_send_packet(packet.len().try_into().unwrap())
        .context("allocate_send_packet")?;
    p.bytes_mut().copy_from_slice(packet);
    session.send_packet(p);
    Ok(())
}

fn spawn_tun_thread(
    session: Arc<wintun::Session>,
    socket: Arc<UdpSocket>,
    key: proto::SymKey,
    shared: SharedRef,
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
            let is_icmp = bytes[9] == 1;
            if is_icmp && DEBUG.load(std::sync::atomic::Ordering::Relaxed) {
                eprintln!(
                    "[client tun] ipv4 packet: {} -> {} len {} proto {}",
                    Ipv4Addr::from(proto::ipv4_src(bytes).unwrap_or(0)),
                    Ipv4Addr::from(dst),
                    bytes.len(),
                    bytes[9]
                );
            }
            let target: SocketAddr = {
                let s = shared.lock().unwrap();
                match s.peers.get(&dst) {
                    Some(p) if p.direct => p.endpoint,
                    Some(_) => s.server, // релей через сервер
                    None => continue,    // не наш пир
                }
            };
            let frame = proto::seal(&key, proto::msg::DATA, &proto::enc_data(dst, bytes));
            let _ = socket.send_to(&frame, target);
        })
        .expect("spawn tun thread");
}
