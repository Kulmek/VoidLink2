//! Демон целиком (замок, лог, хаб, IPC-сервер) на `FakeBackend` поверх
//! настоящего Unix-сокета (PLAN.md 7.7).
#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::json;
use tunnel_daemon::server::socket_path;
use tunnel_daemon::{FakeBackend, IpcMode, RunOpts, run_daemon};
use tunnel_ipc::{
    AckResult, ClientError, ClientKind, ClientMsg, CodecError, Conn, DaemonMsg, IpcClient,
    PROTO_VERSION, read_msg, write_msg,
};

const T: Duration = Duration::from_secs(5);

/// Свежий каталог данных (короткий путь: лимит sun_path ~104 байта на macOS).
fn data_dir() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("tde-{}-{n}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    d
}

fn opts(dir: &Path) -> RunOpts {
    RunOpts {
        data_dir: dir.to_path_buf(),
        debug: true,
        console_log: false,
        ipc: IpcMode::Unix,
        stop_reason: "тест окончен".into(),
    }
}

struct Daemon {
    dir: PathBuf,
    backend: FakeBackend,
    stop: Arc<AtomicBool>,
    th: Option<JoinHandle<Result<(), String>>>,
}

impl Daemon {
    fn start_in(dir: PathBuf) -> Daemon {
        let backend = FakeBackend::new();
        let stop = Arc::new(AtomicBool::new(false));
        let (b, s, o) = (backend.clone(), stop.clone(), opts(&dir));
        let th = std::thread::spawn(move || run_daemon(&o, move |_| b, s));
        let d = Daemon {
            dir,
            backend,
            stop,
            th: Some(th),
        };
        // Ждём, пока сокет начнёт принимать.
        let t0 = Instant::now();
        loop {
            if let Ok(c) = IpcClient::connect(d.sock(), ClientKind::Cli, "probe", T) {
                c.bye();
                break;
            }
            if d.th.as_ref().unwrap().is_finished() || t0.elapsed() > T {
                panic!("демон не поднялся");
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        d
    }

    fn start() -> Daemon {
        Self::start_in(data_dir())
    }

    fn sock(&self) -> PathBuf {
        socket_path(&self.dir)
    }

    fn client(&self) -> IpcClient {
        IpcClient::connect(self.sock(), ClientKind::Tui, "test", T).expect("подключение")
    }

    fn subscribed(&self) -> IpcClient {
        let mut c = self.client();
        c.subscribe(0).unwrap();
        c
    }

    fn raw(&self) -> Conn {
        tunnel_ipc::connect(self.sock()).expect("подключение")
    }

    fn alive(&self) -> bool {
        !self.th.as_ref().unwrap().is_finished()
    }

    fn stop(mut self) -> Result<(), String> {
        self.stop.store(true, Ordering::SeqCst);
        let r = self.th.take().unwrap().join().unwrap();
        let _ = std::fs::remove_dir_all(&self.dir);
        r
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        if let Some(t) = self.th.take() {
            let _ = t.join();
        }
    }
}

/// Читать, пока не придёт подходящее сообщение; возвращает его.
fn wait_for(c: &mut IpcClient, what: &str, mut pred: impl FnMut(&DaemonMsg) -> bool) -> DaemonMsg {
    let deadline = Instant::now() + T;
    loop {
        let left = deadline.saturating_duration_since(Instant::now());
        match c.recv(Some(left)) {
            Ok(m) if pred(&m) => return m,
            Ok(_) => {}
            Err(e) => panic!("ждали {what}: {e}"),
        }
    }
}

fn joined_event(gid: u32) -> impl FnMut(&DaemonMsg) -> bool {
    move |m| matches!(m, DaemonMsg::Event { ev, .. } if ev["GroupJoined"]["gid"] == gid)
}

fn snapshot_with_groups(n: usize) -> impl FnMut(&DaemonMsg) -> bool {
    move |m| matches!(m, DaemonMsg::Snapshot { snap, .. } if snap["groups"].as_array().map(Vec::len) == Some(n))
}

fn hello(c: &mut Conn) {
    write_msg(c, &ClientMsg::hello(ClientKind::Cli, "raw")).unwrap();
    assert!(matches!(
        read_msg::<_, DaemonMsg>(c).unwrap(),
        DaemonMsg::Welcome { .. }
    ));
}

/// Пир закрыл соединение (EOF или сброс), а не прислал что-то.
fn expect_closed(c: &mut Conn) {
    // macOS: на уже закрытом пиром сокете setsockopt даёт EINVAL — не важно.
    let _ = c.set_read_timeout(Some(T));
    loop {
        match read_msg::<_, DaemonMsg>(c) {
            Err(CodecError::Closed | CodecError::Truncated) => return,
            Err(CodecError::Io(e))
                if e.kind() != std::io::ErrorKind::WouldBlock
                    && e.kind() != std::io::ErrorKind::TimedOut =>
            {
                return;
            }
            Err(e) => panic!("ждали закрытия, получили {e}"),
            Ok(DaemonMsg::Event { .. } | DaemonMsg::Snapshot { .. }) => {}
            Ok(m) => panic!("ждали закрытия, пришло {m:?}"),
        }
    }
}

#[test]
fn welcome_history_and_initial_snapshot() {
    let d = Daemon::start();
    let mut c = d.client();
    assert_eq!(c.me()["my_code"], "FAKE-0000");
    c.subscribe(0).unwrap();
    // История: Connected (seq 1), затем снимок с seq ≥ 1.
    match c.recv(Some(T)).unwrap() {
        DaemonMsg::Event { seq: 1, ev } => assert!(ev.get("Connected").is_some()),
        m => panic!("ждали Connected, пришло {m:?}"),
    }
    match c.recv(Some(T)).unwrap() {
        DaemonMsg::Snapshot { seq, snap } => {
            assert!(seq >= 1);
            assert_eq!(snap["meta"]["server_label"], "fake");
        }
        m => panic!("ждали снимок, пришло {m:?}"),
    }
    drop(c);
    d.stop().unwrap();
}

#[test]
fn two_clients_see_same_events_and_join() {
    let d = Daemon::start();
    let mut a = d.subscribed();
    let mut b = d.subscribed();
    assert_eq!(a.request(json!({ "Join": 2 }), T).unwrap(), AckResult::Ok);
    let ea = wait_for(&mut a, "GroupJoined у A", joined_event(2));
    let eb = wait_for(&mut b, "GroupJoined у B", joined_event(2));
    assert_eq!(ea, eb, "одно и то же событие с одним seq");
    wait_for(&mut a, "снимок с группой у A", snapshot_with_groups(1));
    wait_for(&mut b, "снимок с группой у B", snapshot_with_groups(1));
    // Неверный gid — Err в Ack, а не разрыв.
    assert!(matches!(
        b.request(json!({ "Join": 99 }), T).unwrap(),
        AckResult::Err(_)
    ));
    assert!(matches!(
        b.request(json!("Quit"), T).unwrap(),
        AckResult::Err(_)
    ));
    // Событие из бэкенда — обоим.
    d.backend.push_event(json!({ "Notice": "привет" }));
    let na = wait_for(
        &mut a,
        "Notice у A",
        |m| matches!(m, DaemonMsg::Event { ev, .. } if ev["Notice"] == "привет"),
    );
    let nb = wait_for(
        &mut b,
        "Notice у B",
        |m| matches!(m, DaemonMsg::Event { ev, .. } if ev["Notice"] == "привет"),
    );
    assert_eq!(na, nb);
    assert_eq!(d.backend.joined(), vec![2]);
    drop((a, b));
    d.stop().unwrap();
}

#[test]
fn client_disconnect_does_not_affect_other() {
    let d = Daemon::start();
    let a = d.subscribed();
    let mut b = d.subscribed();
    let c = d.subscribed();
    drop(a); // обрыв без Bye
    c.bye(); // вежливо
    assert_eq!(b.request(json!({ "Join": 1 }), T).unwrap(), AckResult::Ok);
    wait_for(&mut b, "GroupJoined после ухода других", joined_event(1));
    d.backend.push_event(json!({ "Notice": "после" }));
    wait_for(
        &mut b,
        "Notice",
        |m| matches!(m, DaemonMsg::Event { ev, .. } if ev["Notice"] == "после"),
    );
    // Движок ничего не заметил: группа на месте, новый клиент её видит.
    assert_eq!(d.backend.joined(), vec![1]);
    let mut n = d.subscribed();
    wait_for(&mut n, "снимок с группой у нового", snapshot_with_groups(1));
    drop((b, n));
    d.stop().unwrap();
}

#[test]
fn slow_subscriber_does_not_block() {
    let d = Daemon::start();
    // Медленный: подписался и никогда не читает.
    let mut slow = d.raw();
    hello(&mut slow);
    write_msg(&mut slow, &ClientMsg::Subscribe { snapshots_ms: 0 }).unwrap();
    let mut fast = d.subscribed();
    let big = "x".repeat(4096);
    const N: u64 = 3000;
    let t0 = Instant::now();
    let mut last = 0u64;
    let mut batch = 0;
    while last < N + 1 {
        if batch * 50 < N as usize {
            for _ in 0..50 {
                d.backend.push_event(json!({ "Notice": big }));
            }
            batch += 1;
        }
        // seq 1 — Connected, дальше наши N событий.
        match fast.recv(Some(Duration::from_millis(20))) {
            Ok(DaemonMsg::Event { seq, .. } | DaemonMsg::Snapshot { seq, .. }) => {
                last = last.max(seq)
            }
            Ok(_) | Err(ClientError::Timeout) => {}
            Err(e) => panic!("быстрый клиент: {e}"),
        }
        assert!(
            t0.elapsed() < Duration::from_secs(20),
            "быстрый застрял на seq {last}"
        );
    }
    // Демон отвечает, хотя медленный висит с полным буфером.
    let t1 = Instant::now();
    assert_eq!(
        fast.request(json!({ "Join": 3 }), T).unwrap(),
        AckResult::Ok
    );
    assert!(t1.elapsed() < Duration::from_secs(1));
    assert!(d.alive());
    drop((fast, slow));
    // Остановка не виснет на медленном (Shutdown ему не влезает).
    let t2 = Instant::now();
    d.stop().unwrap();
    assert!(
        t2.elapsed() < Duration::from_secs(5),
        "остановка ждала медленного"
    );
}

#[test]
fn slow_subscriber_still_connected_does_not_block_stop() {
    let d = Daemon::start();
    let mut slow = d.raw();
    hello(&mut slow);
    write_msg(&mut slow, &ClientMsg::Subscribe { snapshots_ms: 0 }).unwrap();
    let big = "y".repeat(8192);
    for _ in 0..2000 {
        d.backend.push_event(json!({ "Notice": big }));
    }
    std::thread::sleep(Duration::from_millis(300));
    let t0 = Instant::now();
    d.stop().unwrap();
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "остановка ждала медленного"
    );
    drop(slow);
}

#[test]
fn wrong_version_rejected_and_closed() {
    let d = Daemon::start();
    let mut c = d.raw();
    write_msg(
        &mut c,
        &ClientMsg::Hello {
            proto: PROTO_VERSION + 1,
            kind: ClientKind::Tray,
            ver: "9".into(),
        },
    )
    .unwrap();
    match read_msg::<_, DaemonMsg>(&mut c).unwrap() {
        DaemonMsg::Reject { reason } => assert!(reason.contains("версия"), "{reason}"),
        m => panic!("ждали Reject, пришло {m:?}"),
    }
    expect_closed(&mut c);
    // Через IpcClient — понятная ошибка.
    let mut raw = d.raw();
    write_msg(&mut raw, &ClientMsg::Subscribe { snapshots_ms: 0 }).unwrap();
    assert!(
        matches!(
            read_msg::<_, DaemonMsg>(&mut raw).unwrap(),
            DaemonMsg::Reject { .. }
        ),
        "не Hello первым"
    );
    expect_closed(&mut raw);
    assert!(d.alive());
    d.stop().unwrap();
}

#[test]
fn garbage_and_huge_length_disconnect_daemon_alive() {
    let d = Daemon::start();
    let mut keep = d.subscribed();

    // Мусорный JSON до Hello.
    let mut g = d.raw();
    let body = b"\xff\xfe not json";
    let mut f = (body.len() as u32).to_le_bytes().to_vec();
    f.extend_from_slice(body);
    g.write_all(&f).unwrap();
    expect_closed(&mut g);

    // Огромная длина после Hello.
    let mut h = d.raw();
    hello(&mut h);
    h.write_all(&u32::MAX.to_le_bytes()).unwrap();
    expect_closed(&mut h);

    // Длина чуть больше лимита.
    let mut h2 = d.raw();
    hello(&mut h2);
    h2.write_all(&((tunnel_ipc::MAX_FRAME + 1) as u32).to_le_bytes())
        .unwrap();
    expect_closed(&mut h2);

    // Нулевая длина и обрыв посреди фрейма.
    let mut z = d.raw();
    z.write_all(&[0, 0, 0, 0]).unwrap();
    expect_closed(&mut z);
    let mut t = d.raw();
    t.write_all(&[10, 0, 0, 0, b'{']).unwrap();
    drop(t);

    // Неизвестный тип сообщения после Hello.
    let mut u = d.raw();
    hello(&mut u);
    let body = br#"{"t":"frobnicate"}"#;
    let mut f = (body.len() as u32).to_le_bytes().to_vec();
    f.extend_from_slice(body);
    u.write_all(&f).unwrap();
    expect_closed(&mut u);

    // Демон жив, старый клиент работает, новый подключается.
    assert!(d.alive());
    assert_eq!(
        keep.request(json!({ "Join": 1 }), T).unwrap(),
        AckResult::Ok
    );
    wait_for(&mut keep, "GroupJoined", joined_event(1));
    let mut n = d.client();
    assert_eq!(n.request(json!("RefreshList"), T).unwrap(), AckResult::Ok);
    drop((keep, n));
    d.stop().unwrap();
}

#[test]
fn second_instance_refused_by_lock() {
    let d = Daemon::start();
    let stop = Arc::new(AtomicBool::new(true));
    let err = run_daemon(&opts(&d.dir), |_| FakeBackend::new(), stop).unwrap_err();
    assert!(err.contains("уже запущен"), "{err}");
    // Первый не пострадал: сокет его, клиенты работают.
    let mut c = d.client();
    assert_eq!(c.request(json!("RefreshList"), T).unwrap(), AckResult::Ok);
    drop(c);
    d.stop().unwrap();
}

#[test]
fn stale_socket_after_crash_does_not_prevent_start() {
    let dir = data_dir();
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    // «Упавший» демон: сокет остался, никто не слушает.
    let sock = socket_path(&dir);
    drop(std::os::unix::net::UnixListener::bind(&sock).unwrap());
    assert!(sock.exists());
    let d = Daemon::start_in(dir);
    let mut c = d.client();
    assert_eq!(c.request(json!("RefreshList"), T).unwrap(), AckResult::Ok);
    drop(c);
    d.stop().unwrap();
}

#[test]
fn data_dir_is_private_and_socket_0600() {
    let dir = data_dir();
    // Открытый каталог (как у старого клиента) — демон закрывает его.
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o755)).unwrap();
    let d = Daemon::start_in(dir);
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&d.dir), 0o700);
    assert_eq!(mode(&d.sock()), 0o600);
    d.stop().unwrap();
}

#[test]
fn shutdown_broadcast_on_stop() {
    let d = Daemon::start();
    let mut a = d.subscribed();
    let mut b = d.client(); // без подписки — Shutdown всё равно приходит
    let sock = d.sock();
    let stopper = {
        let stop = d.stop.clone();
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(100));
            stop.store(true, Ordering::SeqCst);
        })
    };
    for c in [&mut a, &mut b] {
        match wait_for(c, "Shutdown", |m| matches!(m, DaemonMsg::Shutdown { .. })) {
            DaemonMsg::Shutdown { reason } => assert_eq!(reason, "тест окончен"),
            _ => unreachable!(),
        }
        assert!(matches!(c.recv(Some(T)), Err(ClientError::Closed(_))));
    }
    stopper.join().unwrap();
    d.stop().unwrap();
    assert!(!sock.exists(), "сокет убран при остановке");
}

#[test]
fn snapshots_ms_throttles_periodic_snapshots() {
    let d = Daemon::start();
    let mut c = d.client();
    c.subscribe(60_000).unwrap();
    // Начальный снимок приходит всегда.
    wait_for(&mut c, "начальный снимок", |m| {
        matches!(m, DaemonMsg::Snapshot { .. })
    });
    // Изменения без событий (touch) — снимки хаба не чаще 60 с: их нет.
    d.backend.touch();
    let t0 = Instant::now();
    while t0.elapsed() < Duration::from_millis(1500) {
        match c.recv(Some(Duration::from_millis(100))) {
            Ok(DaemonMsg::Snapshot { .. }) => panic!("снимок вопреки snapshots_ms"),
            Ok(_) | Err(ClientError::Timeout) => {}
            Err(e) => panic!("{e}"),
        }
    }
    drop(c);
    d.stop().unwrap();
}

#[test]
fn throttled_subscriber_gets_snapshot_right_after_change() {
    // Трей подписан с snapshots_ms=1000 и строит вид только из снимков:
    // снимок с итогом Join должен прийти сразу, а не через период.
    let d = Daemon::start();
    let mut c = d.client();
    c.subscribe(1000).unwrap();
    wait_for(&mut c, "начальный снимок", |m| {
        matches!(m, DaemonMsg::Snapshot { .. })
    });
    assert_eq!(c.request(json!({ "Join": 1 }), T).unwrap(), AckResult::Ok);
    let t0 = Instant::now();
    loop {
        let left = Duration::from_millis(300).saturating_sub(t0.elapsed());
        match c.recv(Some(left)) {
            Ok(m) if snapshot_with_groups(1)(&m) => break,
            Ok(_) => {}
            Err(ClientError::Timeout) => panic!("снимок с группой не пришёл за 300 мс"),
            Err(e) => panic!("{e}"),
        }
    }
    drop(c);
    d.stop().unwrap();
}
