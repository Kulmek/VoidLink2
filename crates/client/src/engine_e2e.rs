//! E2E-тесты движка: настоящий сервер (крейт tunnel-server) и настоящие
//! движки на localhost. TUN заменён заглушкой, поэтому права администратора
//! и Wintun не нужны.

use std::collections::{HashMap, HashSet};
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tunnel_protocol as proto;
use tunnel_protocol::ctrl;

use crate::engine::{self, Cmd, Engine, Event, TunDev};
use crate::store::Config;

#[derive(Default)]
struct TestTun {
    injected: Mutex<Vec<Vec<u8>>>,
    addrs: Mutex<HashSet<u32>>,
}

impl TunDev for TestTun {
    fn inject(&self, packet: &[u8]) -> anyhow::Result<()> {
        self.injected.lock().unwrap().push(packet.to_vec());
        Ok(())
    }
    fn ensure_address(&self, ip: u32) -> anyhow::Result<()> {
        self.addrs.lock().unwrap().insert(ip);
        Ok(())
    }
}

struct Node {
    eng: Engine,
    tun: Arc<TestTun>,
    /// Все события, полученные за тест (для диагностики).
    seen: Vec<Event>,
}

impl Node {
    fn start(name: &str, server: &tunnel_server::Server) -> Node {
        Node::start_as(name, server, proto::Identity::generate())
    }

    /// Запуск с заданной identity (её pubkey известен заранее).
    fn start_as(name: &str, server: &tunnel_server::Server, identity: proto::Identity) -> Node {
        Node::start_via(name, local(server.addr), server.pubkey, identity)
    }

    /// Запуск через заданный адрес сервера (например, [`LossyProxy`]).
    fn start_via(
        name: &str,
        addr: SocketAddr,
        server_pub: [u8; 32],
        identity: proto::Identity,
    ) -> Node {
        let cfg = Config {
            name: name.into(),
            ..Config::default()
        };
        let tun = Arc::new(TestTun::default());
        let eng = engine::start_with_tun(
            Arc::new(Mutex::new(cfg)),
            addr,
            server_pub,
            identity,
            tun.clone(),
            Arc::new(|_| {}),
        )
        .expect("движок подключается");
        Node {
            eng,
            tun,
            seen: Vec::new(),
        }
    }

    /// Ждёт событие, подходящее под `pred`.
    fn wait(&mut self, what: &str, timeout: Duration, pred: impl Fn(&Event) -> bool) -> Event {
        let end = Instant::now() + timeout;
        loop {
            let left = end.saturating_duration_since(Instant::now());
            match self.eng.events.recv_timeout(left.min(Duration::from_millis(100))) {
                Ok(ev) => {
                    self.seen.push(ev.clone());
                    if pred(&ev) {
                        return ev;
                    }
                }
                Err(_) if Instant::now() >= end => {
                    panic!("не дождались: {what}; события: {:?}", self.seen)
                }
                Err(_) => {}
            }
        }
    }

    fn drain(&mut self) {
        while let Ok(ev) = self.eng.events.try_recv() {
            self.seen.push(ev);
        }
    }

    fn has_group(&self, gid: u32) -> bool {
        self.eng.groups.lock().unwrap().contains_key(&gid)
    }

    fn members(&self, gid: u32) -> usize {
        self.eng
            .groups
            .lock()
            .unwrap()
            .get(&gid)
            .map(|g| g.members.len())
            .unwrap_or(0)
    }

    fn my_ip(&self, gid: u32) -> u32 {
        self.eng.groups.lock().unwrap()[&gid].my_ip
    }

    fn tx_pkts(&self) -> u64 {
        self.eng.stats.tx_pkts.load(Ordering::Relaxed)
    }
}

/// Сервер слушает 0.0.0.0 — клиентам нужен 127.0.0.1 с тем же портом.
fn local(addr: SocketAddr) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], addr.port()))
}

fn temp_dir(tag: &str) -> PathBuf {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let d = std::env::temp_dir().join(format!("voidlink-e2e-{tag}-{}-{nanos}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn start_server(dir: &std::path::Path, port: u16) -> tunnel_server::Server {
    tunnel_server::Server::start(tunnel_server::Config {
        listen: SocketAddr::from(([127, 0, 0, 1], port)),
        data_dir: dir.to_path_buf(),
        workers: 4,
        quiet: true,
    })
    .expect("сервер стартует")
}

/// Минимальный IPv4-пакет (заголовок 20 байт + данные).
fn ipv4(src: u32, dst: u32, data: &[u8]) -> Vec<u8> {
    let mut p = vec![0u8; 20];
    p[0] = 0x45;
    let len = (20 + data.len()) as u16;
    p[2..4].copy_from_slice(&len.to_be_bytes());
    p[8] = 64;
    p[9] = 17;
    p[12..16].copy_from_slice(&src.to_be_bytes());
    p[16..20].copy_from_slice(&dst.to_be_bytes());
    p.extend_from_slice(data);
    p
}

const T: Duration = Duration::from_secs(10);

/// Правило потерь посредника: (к серверу?, тип фрейма, сколько фреймов
/// каждого типа клиент отправил, включая этот) → потерять.
type DropRule = Box<dyn FnMut(bool, u8, &HashMap<u8, usize>) -> bool + Send>;

/// UDP-посредник между одним клиентом и сервером: теряет фреймы по правилу
/// (тип фрейма в заголовке открыт) и считает отправленное клиентом.
struct LossyProxy {
    addr: SocketAddr,
    sent: Arc<Mutex<HashMap<u8, usize>>>,
    stop: Arc<AtomicBool>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl LossyProxy {
    fn start(server: SocketAddr, mut drop_rule: DropRule) -> LossyProxy {
        let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
        sock.set_read_timeout(Some(Duration::from_millis(50))).unwrap();
        let addr = sock.local_addr().unwrap();
        let sent = Arc::new(Mutex::new(HashMap::new()));
        let stop = Arc::new(AtomicBool::new(false));
        let (sent2, stop2) = (sent.clone(), stop.clone());
        let thread = std::thread::spawn(move || {
            let mut buf = vec![0u8; 65_535];
            let mut client: Option<SocketAddr> = None;
            while !stop2.load(Ordering::Relaxed) {
                let Ok((n, src)) = sock.recv_from(&mut buf) else { continue };
                let to_server = src != server;
                if to_server {
                    client = Some(src);
                }
                let Some(dst) = (if to_server { Some(server) } else { client }) else {
                    continue;
                };
                let typ = proto::split_frame(&buf[..n]).map(|(t, _)| t).unwrap_or(0);
                let lost = {
                    let mut sent = sent2.lock().unwrap();
                    if to_server {
                        *sent.entry(typ).or_insert(0) += 1;
                    }
                    drop_rule(to_server, typ, &sent)
                };
                if !lost {
                    let _ = sock.send_to(&buf[..n], dst);
                }
            }
        });
        LossyProxy { addr, sent, stop, thread: Some(thread) }
    }

    /// Сколько фреймов типа `typ` клиент отправил серверу.
    fn sent(&self, typ: u8) -> usize {
        self.sent.lock().unwrap().get(&typ).copied().unwrap_or(0)
    }
}

impl Drop for LossyProxy {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }
}

#[test]
fn e2e_группа_прямой_канал_без_спама_выход_кик_рестарт() {
    let dir = temp_dir("main");
    let server = start_server(&dir, 0);
    let port = server.addr.port();

    let mut a = Node::start("alpha", &server);
    let mut b = Node::start("bravo", &server);
    a.wait("A подключён", T, |e| matches!(e, Event::Connected(_)));
    b.wait("B подключён", T, |e| matches!(e, Event::Connected(_)));

    // A создаёт группу, B входит.
    a.eng.cmds.send(Cmd::Create { name: "game".into(), private: false }).unwrap();
    let gid = match a.wait("A создал группу", T, |e| matches!(e, Event::GroupJoined { .. })) {
        Event::GroupJoined { gid, .. } => gid,
        _ => unreachable!(),
    };
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait("B вошёл", T, |e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid));
    a.wait("A видит B онлайн", T, |e| matches!(e, Event::PeerOnline { .. }));
    assert!(a.tun.addrs.lock().unwrap().contains(&a.my_ip(gid)), "адрес группы назначен");

    // Прямой канал (localhost: PUNCH доходит сразу).
    a.wait("A: прямой канал", T, |e| matches!(e, Event::Direct { .. }));
    b.wait("B: прямой канал", T, |e| matches!(e, Event::Direct { .. }));

    // Данные A → B доходят до TUN B.
    let pkt = ipv4(a.my_ip(gid), b.my_ip(gid), b"hello");
    a.eng.send_ip_packet(&pkt);
    let end = Instant::now() + T;
    while !b.tun.injected.lock().unwrap().contains(&pkt) {
        assert!(Instant::now() < end, "пакет A→B не дошёл");
        std::thread::sleep(Duration::from_millis(20));
    }

    // Нет спама: в простое пакетов единицы в секунду (раньше PUNCH↔PUNCH
    // отражался бесконечно — тысячи пакетов в секунду).
    let (a0, b0) = (a.tx_pkts(), b.tx_pkts());
    std::thread::sleep(Duration::from_secs(6));
    let rate_a = (a.tx_pkts() - a0) as f64 / 6.0;
    let rate_b = (b.tx_pkts() - b0) as f64 / 6.0;
    assert!(rate_a < 5.0 && rate_b < 5.0, "спам пакетами: A {rate_a:.1}/с, B {rate_b:.1}/с");
    // RTT меряется.
    let rtt = a.eng.groups.lock().unwrap()[&gid].members.values().next().unwrap().rtt_ms;
    assert!(rtt.is_some(), "нет RTT");

    // Выход: группа пропадает и не возвращается.
    b.eng.cmds.send(Cmd::Leave(gid)).unwrap();
    b.wait("B вышел", T, |e| matches!(e, Event::GroupLeft { .. }));
    let end = Instant::now() + T;
    while a.members(gid) != 0 {
        assert!(Instant::now() < end, "A всё ещё видит B в группе");
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_secs(3));
    b.drain();
    assert!(!b.has_group(gid), "группа вернулась к B после выхода");

    // Кик: B снова входит, A исключает.
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait("B вошёл снова", T, |e| matches!(e, Event::GroupJoined { gid: g, .. } if *g == gid));
    let b_pub = b.eng.my_pub;
    a.eng.cmds.send(Cmd::Kick(gid, b_pub)).unwrap();
    b.wait("B кикнут", T, |e| matches!(e, Event::Kicked { gid: g, .. } if *g == gid));
    assert!(!b.has_group(gid));

    // Рестарт сервера на том же порту и с теми же данными: клиенты
    // получают RESET на первый же пакет и переподключаются быстро.
    server.stop();
    a.drain();
    let server = start_server(&dir, port);
    let t0 = Instant::now();
    a.wait("A переподключился", Duration::from_secs(15), |e| matches!(e, Event::Connected(_)));
    assert!(t0.elapsed() < Duration::from_secs(12), "переподключение заняло {:?}", t0.elapsed());
    // Группа восстановилась из автовхода.
    let end = Instant::now() + T;
    while !a.has_group(gid) {
        assert!(Instant::now() < end, "A не вернулся в группу после рестарта");
        std::thread::sleep(Duration::from_millis(50));
    }
    drop(a);
    drop(b);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_приглашение_офлайн_цели_и_отказ() {
    let dir = temp_dir("invite");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| matches!(e, Event::Connected(_)));
    a.eng.cmds.send(Cmd::Create { name: "secret".into(), private: true }).unwrap();
    let gid = match a.wait("A создал группу", T, |e| matches!(e, Event::GroupJoined { .. })) {
        Event::GroupJoined { gid, .. } => gid,
        _ => unreachable!(),
    };

    // B ещё не запущен: приглашение ждёт на сервере.
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
    std::thread::sleep(Duration::from_millis(500));

    // B подключается — приглашение приходит после HELLO, с pubkey владельца.
    let mut b = Node::start_as("bravo", &server, b_id);
    let a_pub = a.eng.my_pub;
    b.wait("B получил приглашение", T, |e| {
        matches!(e, Event::Invite { gid: g, from_pubkey, from_name, .. }
            if *g == gid && *from_pubkey == a_pub && from_name == "alpha")
    });
    // Список полный — UI может снять всё, чего в нём нет.
    b.wait("B: список приглашений сверен", T, |e| {
        matches!(e, Event::InvitesSynced { gids, from: 0, complete: true } if gids == &vec![gid])
    });

    // Отказ — владелец узнаёт, кто и куда.
    b.eng.cmds.send(Cmd::DeclineInvite(gid)).unwrap();
    a.wait("A: приглашение отклонено", T, |e| {
        matches!(e, Event::InviteDeclined { gid: g, by_pubkey, by_name, group_name }
            if *g == gid && *by_pubkey == b_pub && by_name == "bravo" && group_name == "secret")
    });
    // Отказавшему сервер отвечает свежим списком — уже без этого gid.
    b.wait("B: отказ подтверждён списком", T, |e| {
        matches!(e, Event::InvitesSynced { gids, from: 0, complete: true } if gids.is_empty())
    });
    // После отказа в приватную группу не войти.
    b.eng.cmds.send(Cmd::Join(gid)).unwrap();
    b.wait("B: вход без приглашения отклонён", T, |e| {
        matches!(e, Event::Error(t) if t.contains("приглашение"))
    });
    assert!(!b.has_group(gid));

    drop(a);
    drop(b);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_больше_16_приглашений_движок_дочитывает_окнами() {
    let dir = temp_dir("invite-pages");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| matches!(e, Event::Connected(_)));
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    let mut gids = HashSet::new();
    for i in 0..20 {
        a.eng.cmds.send(Cmd::Create { name: format!("g{i}"), private: true }).unwrap();
        let gid = match a.wait("A создал группу", T, |e| matches!(e, Event::GroupJoined { .. })) {
            Event::GroupJoined { gid, .. } => gid,
            _ => unreachable!(),
        };
        a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
        gids.insert(gid);
    }
    std::thread::sleep(Duration::from_millis(500));

    // После HELLO сервер шлёт первые 16 — движок сам дочитывает остальное
    // (LIST_INVITES), без ответа на приглашения.
    let mut b = Node::start_as("bravo", &server, b_id.clone());
    b.wait("B: последнее окно списка", T, |e| {
        matches!(e, Event::InvitesSynced { from, complete: true, .. } if *from > 0)
    });
    let got: HashSet<u32> = b
        .seen
        .iter()
        .filter_map(|e| match e {
            Event::Invite { gid, .. } => Some(*gid),
            _ => None,
        })
        .collect();
    assert_eq!(got, gids, "показаны все 20 приглашений");
    drop(b);

    // CLI (`decline`): окно после HELLO не покрывает gid дальше 16-го —
    // окно с самого gid говорит, есть ли приглашение.
    let mut sorted: Vec<u32> = gids.iter().copied().collect();
    sorted.sort();
    let conn =
        engine::CtrlConn::connect(&Config::default(), local(server.addr), &server.pubkey, &b_id)
            .unwrap();
    let first = conn.invite_list().unwrap().expect("окно после HELLO");
    assert_eq!(first.items.len(), 16);
    assert!(!first.complete && !first.covers(sorted[19]) && !first.covers(250));
    let page = conn.invite_page(sorted[19]).unwrap().expect("окно с gid");
    assert!(page.covers(sorted[19]) && page.items.iter().any(|i| i.gid == sorted[19]));
    let none = conn.invite_page(250).unwrap().expect("окно с gid");
    assert!(none.covers(250) && none.items.is_empty(), "приглашения в 250 нет");

    drop(a);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_потерянные_окна_приглашений_движок_запрашивает_снова() {
    let dir = temp_dir("invite-loss");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| matches!(e, Event::Connected(_)));
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    let mut gids = HashSet::new();
    for i in 0..20 {
        a.eng.cmds.send(Cmd::Create { name: format!("g{i}"), private: true }).unwrap();
        let gid = match a.wait("A создал группу", T, |e| matches!(e, Event::GroupJoined { .. })) {
            Event::GroupJoined { gid, .. } => gid,
            _ => unreachable!(),
        };
        a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
        gids.insert(gid);
    }
    std::thread::sleep(Duration::from_millis(500));

    // Теряется окно после HELLO (все INVITE_LIST, пока движок сам не
    // спросил), затем запрос второй страницы (второй LIST_INVITES): без
    // повторов B не увидел бы ни одного приглашения до реконнекта.
    let proxy = LossyProxy::start(
        local(server.addr),
        Box::new(|to_server, typ, sent| {
            let asked = sent.get(&ctrl::LIST_INVITES).copied().unwrap_or(0);
            if to_server {
                typ == ctrl::LIST_INVITES && asked == 2
            } else {
                typ == ctrl::INVITE_LIST && asked == 0
            }
        }),
    );
    let mut b = Node::start_via("bravo", proxy.addr, server.pubkey, b_id);
    b.wait("B: последнее окно списка", Duration::from_secs(25), |e| {
        matches!(e, Event::InvitesSynced { from, complete: true, .. } if *from > 0)
    });
    let got: HashSet<u32> = b
        .seen
        .iter()
        .filter_map(|e| match e {
            Event::Invite { gid, .. } => Some(*gid),
            _ => None,
        })
        .collect();
    assert_eq!(got, gids, "показаны все 20 приглашений");
    assert!(proxy.sent(ctrl::LIST_INVITES) >= 3, "окно и страница перезапрошены");

    drop(a);
    drop(b);
    drop(proxy);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_потерянный_отказ_от_приглашения_повторяется() {
    let dir = temp_dir("decline-loss");
    let server = start_server(&dir, 0);
    let mut a = Node::start("alpha", &server);
    a.wait("A подключён", T, |e| matches!(e, Event::Connected(_)));
    a.eng.cmds.send(Cmd::Create { name: "secret".into(), private: true }).unwrap();
    let gid = match a.wait("A создал группу", T, |e| matches!(e, Event::GroupJoined { .. })) {
        Event::GroupJoined { gid, .. } => gid,
        _ => unreachable!(),
    };
    let b_id = proto::Identity::generate();
    let b_pub = b_id.ed_pub();
    a.eng.cmds.send(Cmd::Invite(gid, b_pub)).unwrap();
    std::thread::sleep(Duration::from_millis(300));

    // Первый DECLINE_INVITE теряется.
    let proxy = LossyProxy::start(
        local(server.addr),
        Box::new(|to_server, typ, sent| {
            to_server && typ == ctrl::DECLINE_INVITE && sent[&typ] == 1
        }),
    );
    let mut b = Node::start_via("bravo", proxy.addr, server.pubkey, b_id);
    b.wait("B получил приглашение", T, |e| matches!(e, Event::Invite { gid: g, .. } if *g == gid));
    b.eng.cmds.send(Cmd::DeclineInvite(gid)).unwrap();
    a.wait("A: приглашение отклонено (повтором)", T, |e| {
        matches!(e, Event::InviteDeclined { gid: g, by_pubkey, .. } if *g == gid && *by_pubkey == b_pub)
    });
    b.wait("B: отказ подтверждён списком", T, |e| {
        matches!(e, Event::InvitesSynced { gids, complete: true, .. } if !gids.contains(&gid))
    });
    // Подтверждённый отказ больше не повторяется.
    std::thread::sleep(Duration::from_millis(2500));
    assert_eq!(proxy.sent(ctrl::DECLINE_INVITE), 2, "один потерянный + один повтор");

    drop(a);
    drop(b);
    drop(proxy);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_сервер_не_релеит_чужим_и_шлёт_reset() {
    let dir = temp_dir("relay");
    let server = start_server(&dir, 0);
    let srv = local(server.addr);

    // Посторонний сокет без сессии: групповой фрейм не релеится, в ответ RESET.
    let sock = UdpSocket::bind("127.0.0.1:0").unwrap();
    sock.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let frame = proto::seal_group(&[1; 32], proto::grp::DATA, 1, 0x6442_0102, 0x6442_0103, b"x");
    sock.send_to(&frame, srv).unwrap();
    let mut buf = [0u8; 1500];
    let (n, from) = sock.recv_from(&mut buf).expect("ответ сервера");
    assert_eq!(from, srv);
    let (typ, body) = proto::split_frame(&buf[..n]).unwrap();
    assert_eq!(typ, proto::ctrl::RESET);
    assert!(body.is_empty());

    // Мусор не роняет сервер: после него обычный клиент подключается.
    for len in [0usize, 3, 7, 8, 30, 200] {
        let _ = sock.send_to(&vec![0xAB; len], srv);
    }
    let mut c = Node::start("charlie", &server);
    c.wait("подключение после мусора", T, |e| matches!(e, Event::Connected(_)));
    drop(c);
    server.stop();
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn e2e_битый_server_json_не_затирается() {
    let dir = temp_dir("corrupt");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("server.json");
    std::fs::write(&path, b"{ not json").unwrap();
    let r = tunnel_server::Server::start(tunnel_server::Config {
        listen: "127.0.0.1:0".parse().unwrap(),
        data_dir: dir.clone(),
        workers: 1,
        quiet: true,
    });
    assert!(r.is_err(), "сервер не должен стартовать с битым server.json");
    assert_eq!(std::fs::read(&path).unwrap(), b"{ not json", "файл не тронут");
    let _ = std::fs::remove_dir_all(&dir);
}
