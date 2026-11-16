//! Рандеву-сервер v2: identity, группы, lease IP, инвайты, kick/ban, presence.
//!
//! HELLO приходит открытым текстом, но подписан ed25519-ключом клиента
//! (подмена с другого IP невозможна). Все остальные управляющие фреймы
//! шифруются канальным ключом static-static X25519.
//! Фреймы групп релеятся без расшифровки payload'а — сервер читает только
//! открытый заголовок (group_id, src_ip, dst_ip).

mod persist;

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use rand::RngCore;
use tunnel_protocol as proto;
use proto::ctrl;
use proto::payloads::{GroupState, GroupSummary, MemberInfo};

const GID_MIN: u32 = 1;
const GID_MAX: u32 = 254; // 100.66.<gid>.0/24
const HOST_MIN: u32 = 2;
const HOST_MAX: u32 = 254;
const SESSION_TIMEOUT: Duration = Duration::from_secs(30);

struct Session {
    ed_pub: [u8; 32],
    name: String,
    status: String,
    ctrl_key: proto::SymKey,
    last_seen: Instant,
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
    banned: HashSet<[u8; 32]>,
    invites: HashSet<[u8; 32]>,
}

struct State {
    identity: proto::Identity,
    sessions: HashMap<SocketAddr, Session>,
    groups: HashMap<u32, Group>,
    next_gid: u32,
    dirty: bool,
}

fn ip_str(ip: u32) -> String {
    std::net::Ipv4Addr::from(ip).to_string()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Result<[u8; 32]> {
    let v = proto::hex_to_bytes(s)?;
    anyhow::ensure!(v.len() == 32, "bad hex");
    Ok(v.try_into().unwrap())
}

fn gid_subnet_base(gid: u32) -> u32 {
    (100 << 24) | (66 << 16) | (gid << 8)
}

fn next_free_ip(g: &Group) -> Option<u32> {
    (HOST_MIN..=HOST_MAX)
        .map(|h| gid_subnet_base(g.id) + h)
        .find(|ip| !g.members.values().any(|m| m.ip == *ip))
}

fn main() -> Result<()> {
    let mut listen = "0.0.0.0:5555".to_string();
    let mut data_dir = PathBuf::from("tunnel-data");
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "-h" | "--help" => {
                eprintln!("Usage: tunnel-server [listen=0.0.0.0:5555] [--data <dir>=tunnel-data]");
                return Ok(());
            }
            "--data" => { data_dir = args.get(i + 1).context("--data requires value")?.into(); i += 1; }
            other => { listen = other.to_string(); }
        }
        i += 1;
    }
    let listen: SocketAddr = listen.parse().context("bad listen addr")?;

    let store = persist::Store::new(&data_dir);
    let (identity, next_gid, groups) = load_state(&store)?;
    if groups.is_empty() {
        eprintln!("[server] новое состояние в {}", data_dir.display());
    } else {
        eprintln!("[server] загружено: {} групп(ы) из {}", groups.len(), data_dir.display());
    }

    let state = Arc::new(Mutex::new(State {
        identity,
        sessions: HashMap::new(),
        groups,
        next_gid,
        dirty: true,
    }));

    let sock = Arc::new(UdpSocket::bind(listen)?);
    eprintln!("[server] listening on {listen}");
    eprintln!("[server] Server code: {}", state.lock().unwrap().identity.friend_code());

    // Персистентность при изменениях.
    {
        let state = state.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(3));
            let snap = {
                let mut s = state.lock().unwrap();
                if !s.dirty {
                    continue;
                }
                s.dirty = false;
                snapshot(&s)
            };
            if let Err(e) = store.save(&snap) {
                eprintln!("[server] save error: {e}");
            }
        });
    }

    // Presence: чистка мёртвых сессий.
    {
        let sock = sock.clone();
        let state = state.clone();
        std::thread::spawn(move || loop {
            std::thread::sleep(Duration::from_secs(5));
            let changed: Vec<u32> = {
                let mut s = state.lock().unwrap();
                let dead: Vec<SocketAddr> = s
                    .sessions
                    .iter()
                    .filter(|(_, ses)| ses.last_seen.elapsed() > SESSION_TIMEOUT)
                    .map(|(a, _)| *a)
                    .collect();
                if dead.is_empty() {
                    continue;
                }
                let mut changed: HashSet<u32> = HashSet::new();
                for a in dead {
                    let ses = s.sessions.remove(&a).unwrap();
                    for g in s.groups.values() {
                        if g.members.contains_key(&ses.ed_pub) {
                            changed.insert(g.id);
                        }
                    }
                    eprintln!("[server] offline: {} ({})", ses.name, hex(&ses.ed_pub));
                }
                changed.into_iter().collect()
            };
            {
                let s = state.lock().unwrap();
                for gid in &changed {
                    broadcast_group(&sock, &s, *gid);
                }
                broadcast_group_list(&sock, &s);
            }
        });
    }

    let mut buf = vec![0u8; 65_535];
    loop {
        let (n, src) = match sock.recv_from(&mut buf) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[server] recv: {e}");
                continue;
            }
        };
        let datagram = buf[..n].to_vec();
        let (typ, body) = match proto::split_frame(&datagram) {
            Ok(x) => x,
            Err(e) => {
                eprintln!("[server] bad frame {src}: {e}");
                continue;
            }
        };
        // Фреймы группы — релей (без расшифровки payload'а).
        if (proto::grp::DATA..=proto::grp::KEEPALIVE).contains(&typ) {
            relay_group(&sock, &state, &datagram);
            continue;
        }
        // HELLO — открытый текст с подписью (до установления сессии).
        if typ == ctrl::HELLO {
            if let Err(e) = handle_hello(&sock, &state, src, body) {
                eprintln!("[server] hello {src}: {e}");
            }
            continue;
        }
        // Остальное — только для установленных сессий.
        if let Err(e) = handle_ctrl(&sock, &state, typ, src, body) {
            eprintln!("[server] ctrl {typ:#04x} from {src}: {e}");
            // Сообщить клиенту об ошибке (если сессия ещё жива).
            let err = format!("{e:#}");
            let key = {
                let s = state.lock().unwrap();
                s.sessions.get(&src).map(|ses| ses.ctrl_key)
            };
            if let Some(key) = key {
                send_error(&sock, src, &key, &err);
            }
        }
    }
}

fn load_state(store: &persist::Store) -> Result<(proto::Identity, u32, HashMap<u32, Group>)> {
    let Some(p) = store.load() else {
        return Ok((proto::Identity::generate(), GID_MIN, HashMap::new()));
    };
    let mut groups = HashMap::new();
    for g in p.groups {
        let mut members = HashMap::new();
        for (k, ip) in g.members {
            if let Ok(pk) = unhex(&k) {
                members.insert(pk, Member { ip, name: "…".into(), status: String::new() });
            }
        }
        groups.insert(
            g.id,
            Group {
                id: g.id,
                name: g.name,
                owner: unhex(&g.owner)?,
                private: g.private,
                key: g.key,
                members,
                banned: g.banned.iter().map(|b| unhex(b)).collect::<Result<HashSet<_>>>()?,
                invites: g.invites.iter().map(|b| unhex(b)).collect::<Result<HashSet<_>>>()?,
            },
        );
    }
    Ok((
        proto::Identity { ed_seed: p.ed_seed, x_seed: p.x_seed },
        p.next_gid.max(GID_MIN),
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

// ---------- relay ----------

fn relay_group(sock: &UdpSocket, state: &Arc<Mutex<State>>, datagram: &[u8]) {
    let (gid, _src, dst) = match proto::parse_group_header(datagram) {
        Ok(x) => x,
        Err(_) => return,
    };
    let s = state.lock().unwrap();
    let Some(group) = s.groups.get(&gid) else { return };
    let mut targets: Vec<SocketAddr> = Vec::new();
    for (pk, m) in &group.members {
        if m.ip != dst {
            continue;
        }
        for (a, ses) in &s.sessions {
            if ses.ed_pub == *pk {
                targets.push(*a);
            }
        }
    }
    drop(s);
    for a in targets {
        let _ = sock.send_to(datagram, a);
    }
}

// ---------- helpers ----------

fn member_infos(s: &State, g: &Group) -> Vec<MemberInfo> {
    let mut out = Vec::new();
    for (pk, m) in &g.members {
        let online = s.sessions.values().any(|ses| ses.ed_pub == *pk);
        let endpoint = s
            .sessions
            .iter()
            .find(|(_, ses)| ses.ed_pub == *pk)
            .map(|(a, _)| a.to_string());
        out.push(MemberInfo {
            pubkey: *pk,
            name: m.name.clone(),
            ip: m.ip,
            online,
            status: m.status.clone(),
            endpoint,
        });
    }
    out.sort_by_key(|m| m.ip);
    out
}

fn send_ctrl(sock: &UdpSocket, addr: SocketAddr, ctrl_key: &proto::SymKey, typ: u8, payload: &[u8]) {
    let _ = sock.send_to(&proto::seal_ctrl(ctrl_key, typ, payload), addr);
}

fn send_error(sock: &UdpSocket, addr: SocketAddr, key: &proto::SymKey, text: &str) {
    send_ctrl(sock, addr, key, ctrl::ERROR, &proto::payloads::enc_error(text));
}

fn send_group_state(sock: &UdpSocket, s: &State, gid: u32, addr: SocketAddr, ses: &Session) {
    if let Some(g) = s.groups.get(&gid) {
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
        send_ctrl(sock, addr, &ses.ctrl_key, ctrl::GROUP_STATE, &proto::payloads::enc_group_state(&st));
    }
}

fn broadcast_group(sock: &UdpSocket, s: &State, gid: u32) {
    let Some(g) = s.groups.get(&gid) else { return };
    let recipients: Vec<(SocketAddr, proto::SymKey, [u8; 32])> = s
        .sessions
        .iter()
        .filter(|(_, ses)| g.members.contains_key(&ses.ed_pub))
        .map(|(a, ses)| (*a, ses.ctrl_key, ses.ed_pub))
        .collect();
    for (a, _key, _pk) in recipients {
        if let Some(ses) = s.sessions.get(&a) {
            send_group_state(sock, s, gid, a, ses);
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
        let online = s.sessions.values().filter(|ses| g.members.contains_key(&ses.ed_pub)).count() as u32;
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

fn broadcast_group_list(sock: &UdpSocket, s: &State) {
    let sessions: Vec<(SocketAddr, proto::SymKey, [u8; 32])> = s
        .sessions
        .iter()
        .map(|(a, ses)| (*a, ses.ctrl_key, ses.ed_pub))
        .collect();
    for (a, key, ed) in sessions {
        let items = group_summaries_for(s, &ed);
        send_ctrl(sock, a, &key, ctrl::GROUP_LIST, &proto::payloads::enc_group_list(&items));
    }
}

// ---------- HELLO ----------

fn handle_hello(
    sock: &UdpSocket,
    state: &Arc<Mutex<State>>,
    src: SocketAddr,
    body: &[u8],
) -> Result<()> {
    let (ed_pub, x_pub, name, version) = proto::payloads::dec_hello(body)?; // проверяет подпись
    let mut s = state.lock().unwrap();
    // Убить старые сессии этого identity (переподключение с нового порта).
    let old: Vec<SocketAddr> = s
        .sessions
        .iter()
        .filter(|(_, ses)| ses.ed_pub == ed_pub)
        .map(|(a, _)| *a)
        .collect();
    for a in old {
        s.sessions.remove(&a);
    }
    let ctrl_key = s.identity.ctrl_key_with(&x_pub);
    s.sessions.insert(
        src,
        Session {
            ed_pub,
            name: name.clone(),
            status: String::new(),
            ctrl_key,
            last_seen: Instant::now(),
        },
    );
    eprintln!("[server] online: {name} ({}) @ {src} (v{version})", hex(&ed_pub));
    // Обновить имя/статус в группах, где он состоит.
    for g in s.groups.values_mut() {
        if let Some(m) = g.members.get_mut(&ed_pub) {
            m.name = name.clone();
        }
    }
    // WELCOME — открытым текстом: x_pub сервера + подпись ed25519 (клиент
    // pinned ed-ключ сервера → подмена невозможна). Остальные фреймы — шифром.
    let x_pub = s.identity.x_pub();
    let sig = s.identity.sign(&x_pub);
    let _ = sock.send_to(
        &proto::plain_frame(ctrl::WELCOME, &proto::payloads::enc_welcome(&x_pub, &sig)),
        src,
    );
    // GROUP_STATE здесь не шлём: однострочные команды ждут состояние именно
    // своей группы (получат её из ответа CREATE/JOIN), а сессии run получают
    // состояния в ответ на JOIN_GROUP.
    let items = group_summaries_for(&s, &ed_pub);
    let ses = s.sessions.get(&src).unwrap();
    send_ctrl(sock, src, &ses.ctrl_key, ctrl::GROUP_LIST, &proto::payloads::enc_group_list(&items));
    Ok(())
}

// ---------- остальные команды ----------

fn handle_ctrl(
    sock: &UdpSocket,
    state: &Arc<Mutex<State>>,
    typ: u8,
    src: SocketAddr,
    body: &[u8],
) -> Result<()> {
    let mut s = state.lock().unwrap();
    let Some(ses) = s.sessions.get(&src) else { return Ok(()) };
    let ctrl_key = ses.ctrl_key;
    let ed_pub = ses.ed_pub;
    let payload = proto::open_ctrl(&ctrl_key, typ, body)?;
    match typ {
        ctrl::CTRL_PING => {
            s.sessions.get_mut(&src).unwrap().last_seen = Instant::now();
            send_ctrl(sock, src, &ctrl_key, ctrl::CTRL_PONG, &[]);
        }
        ctrl::STATUS => {
            let text = proto::payloads::dec_status(&payload)?;
            let mut gids = Vec::new();
            s.sessions.get_mut(&src).unwrap().status = text.clone();
            for g in s.groups.values_mut() {
                if let Some(m) = g.members.get_mut(&ed_pub) {
                    m.status = text.clone();
                    gids.push(g.id);
                }
            }
            let name = s.sessions.get(&src).unwrap().name.clone();
            eprintln!("[server] status: {name} → {text:?}");
            for gid in gids {
                broadcast_group(sock, &s, gid);
            }
        }
        ctrl::LIST_GROUPS => {
            let items = group_summaries_for(&s, &ed_pub);
            send_ctrl(sock, src, &ctrl_key, ctrl::GROUP_LIST, &proto::payloads::enc_group_list(&items));
        }
        ctrl::CREATE_GROUP => {
            let (name, private) = proto::payloads::dec_create_group(&payload)?;
            anyhow::ensure!(!name.is_empty() && name.len() < 64, "bad group name");
            anyhow::ensure!(s.next_gid <= GID_MAX, "нет свободных подсетей (все 254 группы заняты)");
            let gid = s.next_gid.max(GID_MIN);
            s.next_gid = gid + 1;
            let mut key = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut key);
            let mut members = HashMap::new();
            let owner_name = s.sessions.get(&src).unwrap().name.clone();
            members.insert(ed_pub, Member { ip: gid_subnet_base(gid) + HOST_MIN, name: owner_name.clone(), status: String::new() });
            s.groups.insert(
                gid,
                Group { id: gid, name: name.clone(), owner: ed_pub, private, key, members, banned: HashSet::new(), invites: HashSet::new() },
            );
            s.dirty = true;
            eprintln!("[server] created group {gid} \"{name}\" by {owner_name}");
            let ses = s.sessions.get(&src).unwrap();
            send_group_state(sock, &s, gid, src, ses);
            broadcast_group_list(sock, &s);
        }
        ctrl::JOIN_GROUP => {
            let gid = proto::payloads::dec_gid(&payload)?;
            anyhow::ensure!(s.groups.contains_key(&gid), "group not found");
            let uname = s.sessions.get(&src).unwrap().name.clone();
            let g = s.groups.get_mut(&gid).unwrap();
            anyhow::ensure!(!g.banned.contains(&ed_pub), "вы забанены в этой группе");
            let is_member = g.members.contains_key(&ed_pub);
            if g.private && !is_member && g.owner != ed_pub {
                anyhow::ensure!(g.invites.contains(&ed_pub), "группа приватная, нужно приглашение");
                g.invites.remove(&ed_pub);
            }
            let ip = match g.members.get(&ed_pub) {
                Some(m) => m.ip, // lease сохраняется
                None => next_free_ip(g).context("группа заполнена")?,
            };
            let gname = g.name.clone();
            let ip_s = ip_str(ip);
            g.members.insert(ed_pub, Member { ip, name: uname.clone(), status: String::new() });
            s.dirty = true;
            eprintln!("[server] join: {uname} → {gid} \"{gname}\" as {ip_s}");
            let ses = s.sessions.get(&src).unwrap();
            send_group_state(sock, &s, gid, src, ses);
            broadcast_group(sock, &s, gid);
            broadcast_group_list(sock, &s);
        }
        ctrl::LEAVE_GROUP => {
            let gid = proto::payloads::dec_gid(&payload)?;
            if let Some(g) = s.groups.get_mut(&gid) {
                g.members.remove(&ed_pub);
                s.dirty = true;
                let uname = s.sessions.get(&src).unwrap().name.clone();
                eprintln!("[server] leave: {uname} ← {gid}");
            }
            broadcast_group(sock, &s, gid);
            broadcast_group_list(sock, &s);
        }
        ctrl::INVITE => {
            let (gid, target) = proto::payloads::dec_gid_target(&payload)?;
            let g = s.groups.get_mut(&gid).context("group not found")?;
            anyhow::ensure!(g.owner == ed_pub, "приглашать может только владелец");
            anyhow::ensure!(!g.banned.contains(&target), "цель забанена");
            g.invites.insert(target);
            let invite = proto::payloads::InviteInfo {
                gid,
                group_name: g.name.clone(),
                from_pubkey: ed_pub,
                from_name: s.sessions.get(&src).unwrap().name.clone(),
            };
            s.dirty = true;
            let targets: Vec<(SocketAddr, proto::SymKey)> = s
                .sessions
                .iter()
                .filter(|(_, ses)| ses.ed_pub == target)
                .map(|(a, ses)| (*a, ses.ctrl_key))
                .collect();
            drop(s);
            for (a, key) in targets {
                send_ctrl(sock, a, &key, ctrl::INVITE_RCVD, &proto::payloads::enc_invite(&invite));
            }
            eprintln!("[server] invite: {gid} → {}", hex(&target));
        }
        ctrl::KICK | ctrl::BAN => {
            let (gid, target) = proto::payloads::dec_gid_target(&payload)?;
            let g = s.groups.get_mut(&gid).context("group not found")?;
            anyhow::ensure!(g.owner == ed_pub, "может только владелец");
            anyhow::ensure!(target != g.owner, "нельзя кикнуть владельца");
            let kicked = g.members.remove(&target).is_some();
            if typ == ctrl::BAN {
                g.banned.insert(target);
            }
            let msg = if typ == ctrl::BAN { "забанен в" } else { "кикнут из" };
            let gname = g.name.clone();
            s.dirty = true;
            eprintln!("[server] {msg} {gid}: {}", hex(&target));
            if kicked
                && let Some((a, ses)) = s.sessions.iter().find(|(_, ses)| ses.ed_pub == target)
            {
                let (a, key) = (*a, ses.ctrl_key);
                send_error(sock, a, &key, &format!("вас {msg} группу \"{gname}\""));
            }
            broadcast_group(sock, &s, gid);
        }
        ctrl::RENAME_GROUP => {
            let (gid, name) = proto::payloads::dec_rename(&payload)?;
            let g = s.groups.get_mut(&gid).context("group not found")?;
            anyhow::ensure!(g.owner == ed_pub, "может только владелец");
            anyhow::ensure!(!name.is_empty() && name.len() < 64, "bad name");
            g.name = name.clone();
            s.dirty = true;
            eprintln!("[server] renamed {gid} → \"{name}\"");
            broadcast_group(sock, &s, gid);
            broadcast_group_list(sock, &s);
        }
        ctrl::DELETE_GROUP => {
            let gid = proto::payloads::dec_gid(&payload)?;
            let g = s.groups.get_mut(&gid).context("group not found")?;
            anyhow::ensure!(g.owner == ed_pub, "может только владелец");
            let removed = s.groups.remove(&gid).unwrap();
            s.dirty = true;
            eprintln!("[server] deleted group {gid}");
            let members: Vec<[u8; 32]> = removed.members.keys().copied().collect();
            for pk in members {
                if let Some((a, ses)) = s.sessions.iter().find(|(_, ses)| ses.ed_pub == pk) {
                    let (a, key) = (*a, ses.ctrl_key);
                    let st = GroupState { gid, name: String::new(), owner: [0; 32], private: false, key: [0; 32], deleted: true, my_ip: 0, members: vec![] };
                    send_ctrl(sock, a, &key, ctrl::GROUP_STATE, &proto::payloads::enc_group_state(&st));
                }
            }
            broadcast_group_list(sock, &s);
        }
        ctrl::FRIEND_GROUPS => {
            let target = proto::payloads::dec_pubkey(&payload)?;
            let mut items = Vec::new();
            for g in s.groups.values() {
                let i_am = g.members.contains_key(&ed_pub);
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
            send_ctrl(sock, src, &ctrl_key, ctrl::FRIEND_GROUPS_RESP, &proto::payloads::enc_friend_groups(&items));
        }
        _ => {}
    }
    Ok(())
}
