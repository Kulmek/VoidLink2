//! Движок клиента v2: управляющее соединение с сервером + туннель групп.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use tunnel_protocol as proto;
use proto::ctrl;
use proto::payloads;

use crate::store::Config;

const MTU: usize = 1400;
const RING_CAPACITY: u32 = 0x40_0000; // 4 MiB
const KEEPALIVE_EVERY: Duration = Duration::from_secs(5);

static DEBUG: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
pub fn set_debug(on: bool) {
    DEBUG.store(on, std::sync::atomic::Ordering::Relaxed);
}
fn debug() -> bool {
    DEBUG.load(std::sync::atomic::Ordering::Relaxed)
}

// ---------- состояние групп ----------

struct PeerSess {
    pubkey: [u8; 32],
    name: String,
    endpoint: Option<SocketAddr>,
    direct: bool,
    last_rx: Instant,
}

struct GroupSess {
    key: proto::SymKey,
    name: String,
    my_ip: u32,
    /// ip → пир.
    members: HashMap<u32, PeerSess>,
}

type Groups = Arc<Mutex<HashMap<u32, GroupSess>>>;

/// Сессия TUN, общая для recv-потока (вброс) и tun-потока (чтение).
static TUN_SESSION: Mutex<Option<Arc<wintun::Session>>> = Mutex::new(None);

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

// ---------- run: полноценный туннель ----------

pub fn run(
    cfg: Arc<Config>,
    server: SocketAddr,
    server_pub: [u8; 32],
    identity: proto::Identity,
    adapter_name: &str,
    dll: Option<String>,
) -> Result<()> {
    let conn = CtrlConn::connect(&cfg, server, &server_pub, &identity)?;
    eprintln!("[engine] connected to {server}");
    if !cfg.status.is_empty() {
        conn.send_ctrl(ctrl::STATUS, &payloads::enc_status(&cfg.status));
    }
    for gid in &cfg.autojoin {
        conn.send_ctrl(ctrl::JOIN_GROUP, &payloads::enc_gid(*gid));
        eprintln!("[engine] autojoin → {gid}");
    }

    // --- адаптер ---
    let wintun = crate::tun::load_wintun_dll(dll.as_deref())?;
    let adapter = crate::tun::create_adapter(&wintun, adapter_name)?;
    crate::tun::set_mtu(&adapter, MTU)?;
    crate::tun::allow_firewall(adapter_name);
    let session = Arc::new(adapter.start_session(RING_CAPACITY)?);
    *TUN_SESSION.lock().unwrap() = Some(session.clone());
    let configured: Arc<Mutex<HashSet<u32>>> = Arc::new(Mutex::new(HashSet::new()));

    let groups: Groups = Arc::new(Mutex::new(HashMap::new()));

    // --- TUN-поток: пакеты наружу ---
    spawn_tun_thread(session.clone(), conn.sock.clone(), groups.clone(), server);

    // --- keepalive: ctrl-ping + punch + peer-keepalive + rtt ---
    spawn_keepalive_thread(conn.sock.clone(), conn.ctrl_key, server, groups.clone());

    // --- основной recv-цикл ---
    let mut buf = vec![0u8; 65_535];
    conn.sock.set_read_timeout(Some(Duration::from_millis(500))).ok();
    loop {
        let (n, src) = match conn.sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::TimedOut
                {
                    eprintln!("[engine] recv: {e}");
                }
                continue;
            }
        };
        let datagram = &buf[..n];
        let (typ, _body) = match proto::split_frame(datagram) {
            Ok(x) => x,
            Err(_) => continue,
        };
        if (proto::grp::DATA..=proto::grp::KEEPALIVE).contains(&typ) {
            handle_group_frame(&groups, &session, conn.sock.as_ref(), src, server, datagram);
            continue;
        }
        let payload = match proto::open_ctrl(&conn.ctrl_key, typ, _body) {
            Ok(p) => p,
            Err(_) => continue,
        };
        match typ {
            ctrl::GROUP_STATE => {
                let st = match payloads::dec_group_state(&payload) {
                    Ok(s) => s,
                    Err(_) => continue,
                };
                apply_group_state(&groups, &adapter, &configured, &st, &identity.ed_pub());
            }
            ctrl::GROUP_LIST => { /* для TUI позже */ }
            ctrl::INVITE_RCVD => {
                if let Ok(inv) = payloads::dec_invite(&payload) {
                    eprintln!(
                        "[engine] приглашение: {} приглашает в группу {} (gid {})",
                        inv.from_name, inv.group_name, inv.gid
                    );
                    if cfg.autojoin.contains(&inv.gid) {
                        conn.send_ctrl(ctrl::JOIN_GROUP, &payloads::enc_gid(inv.gid));
                    }
                }
            }
            ctrl::ERROR => {
                if let Ok(text) = payloads::dec_error(&payload) {
                    eprintln!("[engine] сервер: {text}");
                }
            }
            _ => {}
        }
    }
}

fn apply_group_state(
    groups: &Groups,
    adapter: &wintun::Adapter,
    configured: &Mutex<HashSet<u32>>,
    st: &payloads::GroupState,
    my_pub: &[u8; 32],
) {
    if st.deleted {
        let mut g = groups.lock().unwrap();
        if g.remove(&st.gid).is_some() {
            eprintln!("[engine] группа {} ({}) удалена", st.gid, st.name);
        }
        return;
    }
    let my_ip = st.my_ip;
    let need_addr = {
        let mut g = groups.lock().unwrap();
        let entry = g.entry(st.gid).or_insert_with(|| GroupSess {
            key: st.key,
            name: st.name.clone(),
            my_ip: st.my_ip,
            members: HashMap::new(),
        });
        entry.key = st.key;
        entry.name = st.name.clone();
        entry.my_ip = st.my_ip;
        // Пересобрать members, сохранив direct-состояние по pubkey.
        let old: HashMap<[u8; 32], PeerSess> = entry
            .members
            .drain()
            .map(|(_ip, p)| (p.pubkey, p))
            .collect();
        entry.members = HashMap::new();
        for m in &st.members {
            if m.pubkey == *my_pub {
                continue;
            }
            let prev = old.get(&m.pubkey);
            let direct = prev.map(|p| p.direct).unwrap_or(false);
            let endpoint = m
                .endpoint
                .as_deref()
                .and_then(|e| e.parse().ok())
                .or_else(|| prev.and_then(|p| p.endpoint));
            entry.members.insert(
                m.ip,
                PeerSess {
                    pubkey: m.pubkey,
                    name: m.name.clone(),
                    endpoint,
                    direct,
                    last_rx: prev.map(|p| p.last_rx).unwrap_or(Instant::now()),
                },
            );
        }
        let configured = configured.lock().unwrap();
        !configured.contains(&my_ip)
    };
    if need_addr {
        let mut cfg = configured.lock().unwrap();
        match crate::tun::ensure_address(adapter, &mut cfg, my_ip) {
            Ok(()) => eprintln!(
                "[engine] группа {} ({}): мой IP {}",
                st.gid,
                st.name,
                proto::ip_str(my_ip)
            ),
            Err(e) => eprintln!("[engine] netsh address: {e}"),
        }
    }
}

fn handle_group_frame(
    groups: &Groups,
    session: &Arc<wintun::Session>,
    sock: &UdpSocket,
    src: SocketAddr,
    server: SocketAddr,
    datagram: &[u8],
) {
    // Открытый заголовок: gid, src_ip, dst_ip (нужен для выбора ключа).
    let (gid, _src_ip, _dst_ip) = match proto::parse_group_header(datagram) {
        Ok(x) => x,
        Err(_) => return,
    };
    let key = {
        let g = groups.lock().unwrap();
        match g.get(&gid) {
            Some(gs) => gs.key,
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
        let mut g = groups.lock().unwrap();
        if let Some(gs) = g.get_mut(&gid) {
            if let Some(peer) = gs.members.get_mut(&src_ip) {
                if !is_relay {
                    if !peer.direct {
                        peer.direct = true;
                        peer.endpoint = Some(src);
                        eprintln!(
                            "[engine] peer {} ({}), группа {gid}: direct p2p",
                            proto::ip_str(src_ip),
                            peer.name
                        );
                    } else {
                        peer.endpoint = Some(src);
                    }
                }
                peer.last_rx = Instant::now();
            }
        }
    }
    let my_ip = groups.lock().unwrap().get(&gid).map(|gs| gs.my_ip).unwrap_or(0);
    match typ {
        proto::grp::DATA => {
            if dst_ip == my_ip {
                if let Err(e) = inject_packet(session, &payload) {
                    eprintln!("[engine] inject: {e}");
                }
            }
        }
        proto::grp::PING => {
            let frame = proto::seal_group(&key, proto::grp::PONG, gid, my_ip, src_ip, &payload);
            let _ = sock.send_to(&frame, src);
        }
        proto::grp::PONG => {
            if let Ok(sent_ms) = payloads::dec_ping(&payload) {
                if debug() {
                    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
                    let rtt = now.as_millis().saturating_sub(sent_ms as u128);
                    eprintln!("[engine] rtt {gid}/{}: {rtt} мс", proto::ip_str(src_ip));
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

fn spawn_tun_thread(
    session: Arc<wintun::Session>,
    sock: Arc<UdpSocket>,
    groups: Groups,
    server: SocketAddr,
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
            let _ = sock.send_to(&frame, target);
        })
        .expect("spawn tun thread");
}

fn spawn_keepalive_thread(
    sock: Arc<UdpSocket>,
    ctrl_key: proto::SymKey,
    server: SocketAddr,
    groups: Groups,
) {
    thread::Builder::new()
        .name("keepalive".into())
        .spawn(move || loop {
            thread::sleep(KEEPALIVE_EVERY);
            let _ = sock.send_to(&proto::seal_ctrl(&ctrl_key, ctrl::CTRL_PING, &[]), server);
            let tasks: Vec<(u32, proto::SymKey, u32, u32, SocketAddr)> = {
                let g = groups.lock().unwrap();
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
                let _ = sock.send_to(&punch, ep);
                let ka = proto::seal_group(&key, proto::grp::KEEPALIVE, gid, my_ip, peer_ip, &[]);
                let _ = sock.send_to(&ka, ep);
                let now_ms = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_millis() as u64;
                let ping = proto::seal_group(&key, proto::grp::PING, gid, my_ip, peer_ip, &payloads::enc_ping(now_ms));
                let _ = sock.send_to(&ping, ep);
            }
        })
        .expect("spawn keepalive thread");
}
