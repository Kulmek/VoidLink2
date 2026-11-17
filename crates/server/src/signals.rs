//! Корректное завершение по сигналу ОС.
//!
//! Unix: SIGTERM, SIGINT (и SIGHUP — тоже как «остановиться»).
//! Windows: Ctrl+C (SIGINT), Ctrl+Break (SIGBREAK) и SIGTERM через CRT,
//! их регистрирует signal-hook.
//!
//! Обработчик сигнала только выставляет атомарный флаг (async-signal-safe),
//! главный цикл проверяет `requested()` или блокируется в `wait()`.

#![allow(dead_code)] // подключается при интеграции

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Шаг опроса флага в `wait()`.
const POLL: Duration = Duration::from_millis(50);

#[cfg(windows)]
const SIGBREAK: i32 = 21;

/// Хэндл завершения: клонируется и передаётся в воркеры.
#[derive(Clone)]
pub struct Shutdown {
    flag: Arc<AtomicBool>,
}

impl Shutdown {
    /// Хэндл без обработчиков сигналов (для тестов и ручного `trigger()`).
    pub fn new() -> Self {
        Self { flag: Arc::new(AtomicBool::new(false)) }
    }

    /// Поставить обработчики сигналов завершения.
    pub fn install() -> Result<Self> {
        let s = Self::new();
        for sig in signals() {
            signal_hook::flag::register(sig, s.flag.clone())
                .with_context(|| format!("не удалось поставить обработчик сигнала {sig}"))?;
        }
        Ok(s)
    }

    /// Запрошено ли завершение.
    pub fn requested(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Запросить завершение программно.
    pub fn trigger(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Сам флаг — для кода, который уже принимает `Arc<AtomicBool>`
    /// (например, `stop` у сервера).
    pub fn flag(&self) -> Arc<AtomicBool> {
        self.flag.clone()
    }

    /// Блокироваться до запроса завершения.
    pub fn wait(&self) {
        while !self.requested() {
            thread::sleep(POLL);
        }
    }

    /// Ждать не дольше `timeout`; `true` — завершение запрошено.
    pub fn wait_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while !self.requested() {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            thread::sleep(POLL.min(deadline - now));
        }
        true
    }
}

impl Default for Shutdown {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(unix)]
fn signals() -> Vec<i32> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    vec![SIGTERM, SIGINT, SIGHUP]
}

#[cfg(windows)]
fn signals() -> Vec<i32> {
    use signal_hook::consts::{SIGINT, SIGTERM};
    vec![SIGINT, SIGTERM, SIGBREAK]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trigger_and_wait() {
        let s = Shutdown::new();
        assert!(!s.wait_timeout(Duration::from_millis(60)));
        let s2 = s.clone();
        let t = thread::spawn(move || s2.wait());
        s.trigger();
        t.join().unwrap();
        assert!(s.requested());
        assert!(s.flag().load(Ordering::SeqCst));
    }

    #[cfg(unix)]
    #[test]
    fn sigterm_sets_flag() {
        let s = Shutdown::install().unwrap();
        signal_hook::low_level::raise(signal_hook::consts::SIGTERM).unwrap();
        assert!(s.wait_timeout(Duration::from_secs(2)));
    }
}
