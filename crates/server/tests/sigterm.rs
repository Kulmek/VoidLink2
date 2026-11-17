//! Корректная остановка бинарника по SIGTERM: финальное сохранение и код 0.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

#[test]
fn sigterm_сохраняет_состояние_и_выходит_с_кодом_0() {
    let dir = std::env::temp_dir().join(format!("voidlink-srv-sigterm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut child = Command::new(env!("CARGO_BIN_EXE_tunnel-server"))
        .args(["127.0.0.1:0", "--workers", "1", "--data"])
        .arg(&dir)
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    // Строка «Server code» печатается последней при старте.
    let mut err = BufReader::new(child.stderr.take().unwrap());
    let mut line = String::new();
    loop {
        line.clear();
        assert!(err.read_line(&mut line).unwrap() > 0, "сервер завершился до старта");
        if line.contains("Server code") {
            break;
        }
    }
    // Стартовое сохранение уже было; удаляем файл — его должно вернуть
    // финальное сохранение при остановке (периодическое — раз в 3 с).
    let state = dir.join("server.json");
    assert!(state.exists());
    std::fs::remove_file(&state).unwrap();
    let t0 = Instant::now();
    let st = Command::new("kill").args(["-TERM", &child.id().to_string()]).status().unwrap();
    assert!(st.success());
    std::thread::spawn(move || for _ in err.lines() {});
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        assert!(t0.elapsed() < Duration::from_secs(10), "сервер не остановился по SIGTERM");
        std::thread::sleep(Duration::from_millis(20));
    };
    assert_eq!(status.code(), Some(0), "код выхода");
    assert!(t0.elapsed() < Duration::from_secs(3), "остановка заняла {:?}", t0.elapsed());
    assert!(state.exists(), "состояние сохранено при остановке");
    let _ = std::fs::remove_dir_all(&dir);
}
