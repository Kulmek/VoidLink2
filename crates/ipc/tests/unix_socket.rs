//! Кодек и транспорт поверх настоящего Unix-сокета.
#![cfg(unix)]

use std::io::Write;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::thread;

use serde_json::json;
use tunnel_ipc::codec::read_frame;
use tunnel_ipc::transport::cleanup_stale;
use tunnel_ipc::{
    AckResult, ClientKind, ClientMsg, CodecError, DaemonMsg, Listener, MAX_FRAME, PROTO_VERSION,
    check_hello, connect, read_msg, write_msg,
};

/// Короткий путь (лимит sun_path ~104 байта на macOS).
fn sock_path() -> PathBuf {
    static N: AtomicU32 = AtomicU32::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("tipc-{}-{n}.sock", std::process::id()))
}

#[test]
fn hello_req_ack_roundtrip() {
    let path = sock_path();
    let l = Listener::bind(&path).unwrap();
    let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);

    let srv = thread::spawn(move || {
        let mut c = l.accept().unwrap();
        let mut w = c.try_clone().unwrap();
        let ClientMsg::Hello { proto, kind, .. } = read_msg(&mut c).unwrap() else {
            panic!("ждали Hello");
        };
        assert_eq!(kind, ClientKind::Tui);
        check_hello(proto).unwrap();
        write_msg(
            &mut w,
            &DaemonMsg::Welcome {
                proto: PROTO_VERSION,
                daemon_ver: "test".into(),
                me: json!({"my_code": "ABC"}),
            },
        )
        .unwrap();
        let ClientMsg::Req { id, cmd } = read_msg(&mut c).unwrap() else {
            panic!("ждали Req");
        };
        assert_eq!(cmd, json!({"SetName": "вася"}));
        write_msg(&mut w, &DaemonMsg::Ack { id, result: AckResult::Ok }).unwrap();
        assert_eq!(read_msg::<_, ClientMsg>(&mut c).unwrap(), ClientMsg::Bye);
        assert!(matches!(read_msg::<_, ClientMsg>(&mut c), Err(CodecError::Closed)));
        l
    });

    let mut c = connect(&path).unwrap();
    write_msg(&mut c, &ClientMsg::hello(ClientKind::Tui, "0.1")).unwrap();
    let DaemonMsg::Welcome { me, .. } = read_msg(&mut c).unwrap() else {
        panic!("ждали Welcome");
    };
    assert_eq!(me["my_code"], "ABC");
    write_msg(&mut c, &ClientMsg::Req { id: 42, cmd: json!({"SetName": "вася"}) }).unwrap();
    assert_eq!(
        read_msg::<_, DaemonMsg>(&mut c).unwrap(),
        DaemonMsg::Ack { id: 42, result: AckResult::Ok }
    );
    write_msg(&mut c, &ClientMsg::Bye).unwrap();
    drop(c);
    let l = srv.join().unwrap();
    drop(l);
    assert!(!path.exists(), "сокет удаляется при drop слушателя");
}

/// Сервер принимает одно соединение, клиент шлёт сырые байты и закрывается;
/// возвращает, что прочитал сервер.
fn server_reads(raw: Vec<u8>) -> Result<ClientMsg, CodecError> {
    let path = sock_path();
    let l = Listener::bind(&path).unwrap();
    let srv = thread::spawn(move || {
        let mut c = l.accept().unwrap();
        read_msg::<_, ClientMsg>(&mut c)
    });
    let mut c = connect(&path).unwrap();
    // Запись может упасть, если сервер уже разорвал соединение, — это нормально.
    let _ = c.write_all(&raw);
    drop(c);
    srv.join().expect("сервер не должен паниковать")
}

#[test]
fn bad_length_zero() {
    assert!(matches!(server_reads(vec![0, 0, 0, 0]), Err(CodecError::BadLength)));
}

#[test]
fn oversize_frame() {
    let mut raw = ((MAX_FRAME + 1) as u32).to_le_bytes().to_vec();
    raw.extend_from_slice(b"{}");
    assert!(matches!(server_reads(raw), Err(CodecError::TooLarge(_))));
}

#[test]
fn garbage_json() {
    let body = b"\x00\x01not json at all";
    let mut raw = (body.len() as u32).to_le_bytes().to_vec();
    raw.extend_from_slice(body);
    assert!(matches!(server_reads(raw), Err(CodecError::Json(_))));
}

#[test]
fn peer_disconnect_mid_frame_and_clean() {
    let mut raw = 100u32.to_le_bytes().to_vec();
    raw.extend_from_slice(b"{\"t\":");
    assert!(matches!(server_reads(raw), Err(CodecError::Truncated)));
    assert!(matches!(server_reads(Vec::new()), Err(CodecError::Closed)));
}

#[test]
fn shutdown_wakes_blocked_reader() {
    let path = sock_path();
    let l = Listener::bind(&path).unwrap();
    let _client = connect(&path).unwrap();
    let c = l.accept().unwrap();
    let mut r = c.try_clone().unwrap();
    let t = thread::spawn(move || read_frame(&mut r));
    thread::sleep(std::time::Duration::from_millis(50));
    c.shutdown().unwrap();
    assert!(matches!(t.join().unwrap(), Err(CodecError::Closed)));
}

#[test]
fn stale_socket_cleanup() {
    let path = sock_path();
    // Живой сокет не трогаем.
    let l = Listener::bind(&path).unwrap();
    assert!(Listener::bind(&path).is_err());
    assert_eq!(
        cleanup_stale(&path).unwrap_err().kind(),
        std::io::ErrorKind::AddrInUse
    );
    drop(l);
    // Устаревший: файл остался, слушателя нет (std не удаляет файл при drop).
    let stale = sock_path();
    {
        let _ul = std::os::unix::net::UnixListener::bind(&stale).unwrap();
    }
    assert!(std::fs::symlink_metadata(&stale).unwrap().file_type().is_socket());
    assert!(cleanup_stale(&stale).unwrap());
    assert!(!stale.exists());
    assert!(!cleanup_stale(&stale).unwrap());
    let l2 = Listener::bind(&stale).unwrap();
    drop(l2);
    // Обычный файл не удаляем.
    let f = sock_path();
    std::fs::write(&f, b"x").unwrap();
    assert_eq!(
        cleanup_stale(&f).unwrap_err().kind(),
        std::io::ErrorKind::InvalidInput
    );
    std::fs::remove_file(&f).unwrap();
}
