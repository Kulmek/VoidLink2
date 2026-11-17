//! Файловый лог демона с ротацией (PLAN.md 7.3): `logs/daemon.log`,
//! 1 МиБ × 5 файлов (`daemon.log`, `daemon.log.1` … `daemon.log.4`, чем
//! больше номер — тем старше). Движок пишет сюда через [`LogFn`] вместо
//! `eprintln!`; в режиме `console` строки дублируются в stderr.

use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

/// Размер файла, после которого лог ротируется.
pub const MAX_BYTES: u64 = 1024 * 1024;
/// Сколько файлов хранится всего (текущий + архивные).
pub const MAX_FILES: usize = 5;
/// Имя текущего файла лога.
pub const LOG_FILE: &str = "daemon.log";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Level {
    Debug,
    Info,
    Warn,
    Error,
}

impl Level {
    fn tag(self) -> &'static str {
        match self {
            Level::Debug => "DEBUG",
            Level::Info => "INFO",
            Level::Warn => "WARN",
            Level::Error => "ERROR",
        }
    }
}

/// Колбэк лога для движка (вместо `eprintln!`).
pub type LogFn = Arc<dyn Fn(Level, &str) + Send + Sync>;

struct State {
    file: Option<File>,
    size: u64,
}

pub struct Logger {
    path: PathBuf,
    max_bytes: u64,
    max_files: usize,
    min_level: Level,
    console: bool,
    state: Mutex<State>,
}

impl Logger {
    /// Лог в `dir/daemon.log` с параметрами по умолчанию.
    pub fn open(dir: &Path, min_level: Level, console: bool) -> std::io::Result<Arc<Self>> {
        Self::open_with(dir, LOG_FILE, MAX_BYTES, MAX_FILES, min_level, console)
    }

    pub fn open_with(
        dir: &Path,
        name: &str,
        max_bytes: u64,
        max_files: usize,
        min_level: Level,
        console: bool,
    ) -> std::io::Result<Arc<Self>> {
        std::fs::create_dir_all(dir)?;
        let path = dir.join(name);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        let size = file.metadata()?.len();
        Ok(Arc::new(Self {
            path,
            max_bytes: max_bytes.max(1),
            max_files: max_files.max(1),
            min_level,
            console,
            state: Mutex::new(State {
                file: Some(file),
                size,
            }),
        }))
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Записать строку. Ошибки файла не роняют демон — строка теряется.
    pub fn log(&self, level: Level, msg: &str) {
        if level < self.min_level {
            return;
        }
        let line = format!(
            "{} {:<5} {}\n",
            timestamp(SystemTime::now()),
            level.tag(),
            msg.trim_end()
        );
        if self.console {
            eprint!("{line}");
        }
        let mut st = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if st.size > 0 && st.size + line.len() as u64 > self.max_bytes {
            st.file = None; // закрыть перед переименованием (Windows)
            let rotated = self.rotate();
            st.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
            // Не вышло (файл держит другой процесс без FILE_SHARE_DELETE) —
            // пишем дальше в тот же файл, следующая попытка через max_bytes.
            st.size = if rotated {
                st.file
                    .as_ref()
                    .and_then(|f| f.metadata().ok())
                    .map_or(0, |m| m.len())
            } else {
                0
            };
        }
        if st.file.is_none() {
            st.file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
                .ok();
            st.size = st
                .file
                .as_ref()
                .and_then(|f| f.metadata().ok())
                .map_or(0, |m| m.len());
        }
        if let Some(f) = st.file.as_mut()
            && f.write_all(line.as_bytes()).is_ok()
        {
            st.size += line.len() as u64;
        }
    }

    /// Колбэк для движка.
    pub fn callback(self: &Arc<Self>) -> LogFn {
        let me = self.clone();
        Arc::new(move |level, msg| me.log(level, msg))
    }

    fn archived(&self, n: usize) -> PathBuf {
        let mut s = self.path.as_os_str().to_owned();
        s.push(format!(".{n}"));
        PathBuf::from(s)
    }

    /// Временное имя текущего файла на время сдвига архивов.
    fn rotating(&self) -> PathBuf {
        let mut s = self.path.as_os_str().to_owned();
        s.push(".rotating");
        PathBuf::from(s)
    }

    /// Сначала текущий файл уводится во временное имя; только если это
    /// удалось — daemon.log.(N-1) удаляется, остальные сдвигаются на один
    /// номер, временный становится `.1`. `false` — ротация не удалась,
    /// архивы не тронуты.
    fn rotate(&self) -> bool {
        if self.max_files == 1 {
            return std::fs::remove_file(&self.path).is_ok();
        }
        let tmp = self.rotating();
        if std::fs::rename(&self.path, &tmp).is_err() {
            return false;
        }
        let _ = std::fs::remove_file(self.archived(self.max_files - 1));
        for n in (1..self.max_files - 1).rev() {
            let _ = std::fs::rename(self.archived(n), self.archived(n + 1));
        }
        let _ = std::fs::rename(&tmp, self.archived(1));
        true
    }
}

/// `2026-11-17 12:34:56.789Z` (UTC, без зависимостей).
fn timestamp(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = (secs / 86_400, secs % 86_400);
    let (y, m, dd) = civil_from_days(days as i64);
    format!(
        "{y:04}-{m:02}-{dd:02} {:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

/// Дни от 1970-01-01 → (год, месяц, день); алгоритм Howard Hinnant.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("tunnel-daemon-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn rotates_and_keeps_n_files() {
        let dir = tmp("logrot");
        let log = Logger::open_with(&dir, "daemon.log", 200, 3, Level::Info, false).unwrap();
        for i in 0..40 {
            log.log(Level::Info, &format!("строка {i:03} xxxxxxxxxxxxxxxxxxxx"));
        }
        log.log(Level::Debug, "не должно попасть");
        let mut names: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        names.sort();
        assert_eq!(names, vec!["daemon.log", "daemon.log.1", "daemon.log.2"]);
        for n in &names {
            let len = std::fs::metadata(dir.join(n)).unwrap().len();
            assert!(len > 0 && len <= 200, "{n}: {len}");
        }
        let cur = std::fs::read_to_string(dir.join("daemon.log")).unwrap();
        assert!(cur.contains("строка 039"));
        assert!(!cur.contains("не должно попасть"));
        let old = std::fs::read_to_string(dir.join("daemon.log.2")).unwrap();
        assert!(!old.contains("строка 039") && !old.contains("строка 000"));
        // Колбэк пишет туда же; повторное открытие дописывает, а не затирает.
        drop(log);
        let log = Logger::open_with(&dir, "daemon.log", 200, 3, Level::Debug, false).unwrap();
        (log.callback())(Level::Debug, "через колбэк");
        assert!(
            std::fs::read_to_string(log.path())
                .unwrap()
                .contains("через колбэк")
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_rotation_keeps_archives() {
        let dir = tmp("logrotfail");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("daemon.log.1"), "архив 1\n").unwrap();
        std::fs::write(dir.join("daemon.log.2"), "архив 2\n").unwrap();
        // Каталог на месте временного имени — переименование текущего
        // файла не удаётся (как на Windows, когда файл держит редактор).
        std::fs::create_dir_all(dir.join("daemon.log.rotating")).unwrap();
        let log = Logger::open_with(&dir, "daemon.log", 100, 3, Level::Info, false).unwrap();
        for i in 0..30 {
            log.log(Level::Info, &format!("строка {i:03} xxxxxxxxxxxxxxxxxxxx"));
        }
        assert_eq!(
            std::fs::read_to_string(dir.join("daemon.log.1")).unwrap(),
            "архив 1\n"
        );
        assert_eq!(
            std::fs::read_to_string(dir.join("daemon.log.2")).unwrap(),
            "архив 2\n"
        );
        let cur = std::fs::read_to_string(dir.join("daemon.log")).unwrap();
        assert!(cur.contains("строка 000") && cur.contains("строка 029"));
        // Препятствие ушло — ротация снова работает.
        std::fs::remove_dir(dir.join("daemon.log.rotating")).unwrap();
        for i in 0..10 {
            log.log(
                Level::Info,
                &format!("после {i:03} xxxxxxxxxxxxxxxxxxxxxxxxxxx"),
            );
        }
        assert!(
            !std::fs::read_to_string(dir.join("daemon.log"))
                .unwrap()
                .contains("строка 000")
        );
        assert!(!dir.join("daemon.log.rotating").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn timestamp_format() {
        let t = UNIX_EPOCH + Duration::from_millis(1_779_000_000_123);
        assert_eq!(timestamp(t), "2026-05-17 06:40:00.123Z");
        assert_eq!(timestamp(UNIX_EPOCH), "1970-01-01 00:00:00.000Z");
    }
}
