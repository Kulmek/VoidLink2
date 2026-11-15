//! Рандеву-сервер туннеля: комнаты по ключу, выдача виртуальных IP,
//! рассылка ростера и релей трафика, если прямой P2P не пробился.

use std::collections::HashMap;
use std::net::{SocketAddr, UdpSocket};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use tunnel_protocol as proto;

const IP_BASE: u32 = 0x0A42_0000; // 10.66.0.0
const IP_MIN: u32 = 2; // 10.66.0.2
const IP_MAX: u32 = 254; // 10.66.0.254
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(30);

struct Member {
    name: String,
    ip: u32,
    last: Instant,
}

#[derive(Default)]
struct Room {
    /// Ключ — публичный адрес клиента.
    members: HashMap<SocketAddr, Member>,
}

type Rooms = Arc<Mutex<HashMap<String, Room>>>;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() < 2 || args.iter().any(|a| a == "-h" || a == "--help") {
        eprintln!("Usage: tunnel-server <listen=0.0.0.0:5555> <room-key>");
        eprintln!("Пример: tunnel-server 0.0.0.0:5555 mysecret");
        std::process::exit(2);
    }
    let listen: SocketAddr = args[0].parse().with_context(|| format!("bad listen {}", args[0]))?;
    let room_key = args[1].clone();
    let key = proto::derive_key(&room_key);

    let socket = Arc::new(UdpSocket::bind(listen).with_context(|| format!("bind {listen}"))?);
    eprintln!("[server] listening on {listen}");

    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));

    // Фоновая чистка мёртвых участников.
    {
        let socket = socket.clone();
        let rooms = rooms.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let now = Instant::now();
            let mut rooms = rooms.lock().unwrap();
            let mut changed = Vec::new();
            rooms.retain(|name, room| {
                let before = room.members.len();
                room.members.retain(|_, m| now.duration_since(m.last) < KEEPALIVE_TIMEOUT);
                if room.members.len() != before {
                    eprintln!("[server] room {name:?}: {} member(s) dropped by timeout", before - room.members.len());
                    changed.push((name.clone(), room.members.len()));
                    room.members.len() > 0
                } else {
                    room.members.len() > 0
                }
            });
            for (name, _len) in changed {
                if let Some(room) = rooms.get(&name) {
                    broadcast_roster(&socket, &key, room);
                }
            }
        });
    }

    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, src) = match socket.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[server] recv error: {e}");
                continue;
            }
        };
        let (typ, payload) = match proto::open(&key, &buf[..n]) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[server] bad frame from {src}: {e}");
                continue;
            }
        };
        match typ {
            proto::msg::REG => {
                let (room, name) = match proto::dec_reg(&payload) {
                    Ok(x) => x,
                    Err(e) => {
                        eprintln!("[server] bad REG from {src}: {e}");
                        continue;
                    }
                };
                let mut rooms = rooms.lock().unwrap();
                let r = rooms.entry(room).or_default();
                // Если имя уже занято (перезапуск клиента) — переиспользуем его IP.
                let old = r
                    .members
                    .iter()
                    .find(|(_, m)| m.name == name)
                    .map(|(a, m)| (*a, m.ip));
                let ip = match old {
                    Some((old_addr, ip)) => {
                        if old_addr != src {
                            r.members.remove(&old_addr);
                        }
                        ip
                    }
                    None => match next_free_ip(r) {
                        Some(ip) => ip,
                        None => {
                            eprintln!("[server] room full, rejecting {src}");
                            continue;
                        }
                    },
                };
                eprintln!("[server] {name} ({src}) joined as {}", fmt_ip(ip));
                r.members.insert(src, Member { name, ip, last: Instant::now() });
                let _ = socket.send_to(&proto::seal(&key, proto::msg::WELCOME, &proto::enc_welcome(ip)), src);
                broadcast_roster(&socket, &key, r);
            }
            proto::msg::KEEPALIVE => {
                let mut rooms = rooms.lock().unwrap();
                for r in rooms.values_mut() {
                    if let Some(m) = r.members.get_mut(&src) {
                        m.last = Instant::now();
                        break;
                    }
                }
            }
            proto::msg::DATA => {
                // Релей: читаем dst из payload (сервер знает ключ), пересылаем фрейм как есть.
                let dst = match proto::dec_data(&payload) {
                    Ok((dst, _)) => dst,
                    Err(_) => continue,
                };
                let mut rooms = rooms.lock().unwrap();
                if let Some(room) = rooms.values_mut().find(|r| r.members.contains_key(&src)) {
                    let peer_addr = room
                        .members
                        .iter()
                        .find(|(_, m)| m.ip == dst)
                        .map(|(a, _)| *a);
                    if let Some(peer_addr) = peer_addr {
                        let _ = socket.send_to(&buf[..n], peer_addr);
                    }
                }
            }
            _ => {}
        }
    }
}

fn fmt_ip(ip: u32) -> String {
    std::net::Ipv4Addr::from(ip).to_string()
}

fn next_free_ip(r: &Room) -> Option<u32> {
    (IP_MIN..=IP_MAX)
        .map(|c| IP_BASE + c)
        .find(|ip| !r.members.values().any(|m| m.ip == *ip))
}

fn broadcast_roster(socket: &UdpSocket, key: &proto::SymKey, room: &Room) {
    let entries: Vec<proto::RosterEntry> = room
        .members
        .iter()
        .map(|(addr, m)| proto::RosterEntry {
            ip: m.ip,
            endpoint: addr.to_string(),
            name: m.name.clone(),
        })
        .collect();
    let frame = proto::seal(key, proto::msg::ROSTER, &proto::enc_roster(&entries));
    for addr in room.members.keys() {
        let _ = socket.send_to(&frame, addr);
    }
}
