//! Корректное завершение по сигналу ОС.
//!
//! Unix: SIGTERM, SIGINT (и SIGHUP — тоже как «остановиться»).
//! Windows: Ctrl+C (SIGINT), Ctrl+Break (SIGBREAK) и SIGTERM через CRT,
//! их регистрирует signal-hook.
//!
//! Windows: закрытие окна консоли, выход из системы и выключение
//! (CTRL_CLOSE/LOGOFF/SHUTDOWN_EVENT) CRT в сигналы не переводит — их ловит
//! отдельный `SetConsoleCtrlHandler`, который выставляет тот же флаг и даёт
//! главному циклу несколько секунд на финальный persist.
//!
//! Обработчик сигнала только выставляет атомарный флаг (async-signal-safe),
//! главный цикл проверяет `requested()` или блокируется в `wait()`.
//! Повторный сигнал, пришедший, когда флаг уже стоит (корректное завершение
//! зависло), завершает процесс сразу с кодом 1.

#![allow(dead_code)] // подключается при интеграции

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

/// Шаг опроса флага в `wait()`.
const POLL: Duration = Duration::from_millis(50);

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
            // Порядок важен: условный выход регистрируется первым и видит флаг
            // ещё не выставленным при первом сигнале, а при втором — уже
            // выставленным, и тогда завершает процесс.
            signal_hook::flag::register_conditional_shutdown(sig, 1, s.flag.clone())
                .with_context(|| format!("не удалось поставить обработчик сигнала {sig}"))?;
            signal_hook::flag::register(sig, s.flag.clone())
                .with_context(|| format!("не удалось поставить обработчик сигнала {sig}"))?;
        }
        #[cfg(windows)]
        console::install(s.flag.clone())?;
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
    use signal_hook::consts::{SIGBREAK, SIGINT, SIGTERM};
    vec![SIGINT, SIGTERM, SIGBREAK]
}

/// Закрытие консоли / выход из системы / выключение на Windows.
#[cfg(windows)]
mod console {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::thread;
    use std::time::Duration;

    use anyhow::{Result, bail};
    use windows_sys::Win32::Foundation::{FALSE, TRUE};
    use windows_sys::core::BOOL;
    use windows_sys::Win32::System::Console::{
        CTRL_CLOSE_EVENT, CTRL_LOGOFF_EVENT, CTRL_SHUTDOWN_EVENT, SetConsoleCtrlHandler,
    };

    /// Сколько ждать после выставления флага. Windows даёт ~5 с на
    /// CTRL_CLOSE_EVENT, после возврата из обработчика процесс убивается.
    const GRACE: Duration = Duration::from_secs(4);

    static FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();

    unsafe extern "system" fn handler(ctrl: u32) -> BOOL {
        match ctrl {
            CTRL_CLOSE_EVENT | CTRL_LOGOFF_EVENT | CTRL_SHUTDOWN_EVENT => {
                if let Some(f) = FLAG.get() {
                    f.store(true, Ordering::SeqCst);
                }
                // Обработчик выполняется в отдельном потоке — можно спать,
                // пока главный цикл завершается.
                thread::sleep(GRACE);
                TRUE
            }
            // Ctrl+C / Ctrl+Break отдаём дальше — их обрабатывает CRT/signal-hook.
            _ => FALSE,
        }
    }

    pub fn install(flag: Arc<AtomicBool>) -> Result<()> {
        if FLAG.set(flag).is_err() {
            // Уже установлен ранее (повторный `install()`): обработчик один на процесс.
            return Ok(());
        }
        // SAFETY: `handler` — корректная функция с сигнатурой PHANDLER_ROUTINE.
        if unsafe { SetConsoleCtrlHandler(Some(handler), TRUE) } == FALSE {
            bail!("не удалось поставить обработчик событий консоли");
        }
        Ok(())
    }
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
