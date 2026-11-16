//! E2E-тесты движка: настоящий сервер (крейт tunnel-server) и настоящие
//! движки на localhost. TUN заменён заглушкой, поэтому права администратора
//! и Wintun не нужны.

use std::collections::HashSet;
use std::net::{SocketAddr, UdpSocket};
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use tunnel_protocol as proto;

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
        let cfg = Config {
            name: name.into(),
            ..Config::default()
        };
        let tun = Arc::new(TestTun::default());
        let eng = engine::start_with_tun(
            Arc::new(Mutex::new(cfg)),
            local(server.addr),
            server.pubkey,
            proto::Identity::generate(),
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
