//! Локальные часы для TUI: «HH:MM:SS», а для не сегодняшних моментов — с датой.
//!
//! Смещение от UTC вычисляется один раз при старте ([`init`]) и дальше не
//! меняется: `localtime_r` не потокобезопасен относительно `setenv`, поэтому
//! зовём его до запуска потоков. Если определить смещение не удалось — UTC.
#![allow(dead_code)] // подключается при интеграции

use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

static OFFSET: OnceLock<i64> = OnceLock::new();

/// Определяет смещение локального времени (в секундах). Вызывать при старте,
/// до запуска потоков. Повторные вызовы ничего не меняют.
pub fn init() -> i64 {
    *OFFSET.get_or_init(detect_offset)
}

/// Текущее смещение (определяет его при первом обращении).
///
/// `main()` обязан заранее вызвать [`init`] до запуска потоков; иначе первый
/// `localtime_r` случится на рабочем потоке (в отладочной сборке — паника).
pub fn offset() -> i64 {
    debug_assert!(
        OFFSET.get().is_some() || cfg!(test),
        "clock::init() не вызван в main() до запуска потоков"
    );
    init()
}

/// Форматирует момент в локальном времени: «HH:MM:SS», если это сегодня,
/// иначе «DD.MM HH:MM:SS» (с годом, если год не текущий).
///
/// Требует предварительного [`init`] в `main()` (см. [`offset`]).
pub fn format_local(t: SystemTime) -> String {
    format_with_offset(t, SystemTime::now(), offset())
}

/// То же, что [`format_local`], но с явными «сейчас» и смещением (для тестов).
pub fn format_with_offset(t: SystemTime, now: SystemTime, offset_secs: i64) -> String {
    let local = unix_secs(t) + offset_secs;
    let now_local = unix_secs(now) + offset_secs;
    let (days, sod) = (local.div_euclid(86_400), local.rem_euclid(86_400));
    let time = format!("{:02}:{:02}:{:02}", sod / 3600, sod / 60 % 60, sod % 60);
    let today = now_local.div_euclid(86_400);
    if days == today {
        return time;
    }
    let (y, m, d) = civil_from_days(days);
    let (ny, _, _) = civil_from_days(today);
    if y == ny {
        format!("{d:02}.{m:02} {time}")
    } else {
        format!("{d:02}.{m:02}.{y} {time}")
    }
}

/// Секунды Unix (отрицательные — до 1970).
fn unix_secs(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => d.as_secs() as i64,
        Err(e) => -(e.duration().as_secs_f64().ceil() as i64),
    }
}

/// Дни от 1970-01-01 → (год, месяц, день). Алгоритм Говарда Хиннанта.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(windows)]
fn detect_offset() -> i64 {
    use windows_sys::Win32::System::Time::{GetTimeZoneInformation, TIME_ZONE_INFORMATION};
    // SAFETY: структура POD, функция только заполняет её.
    let mut tz: TIME_ZONE_INFORMATION = unsafe { std::mem::zeroed() };
    let kind = unsafe { GetTimeZoneInformation(&mut tz) };
    // UTC = local + bias (минуты); 1 — стандартное время, 2 — летнее.
    let bias = match kind {
        1 => tz.Bias + tz.StandardBias,
        2 => tz.Bias + tz.DaylightBias,
        0 => tz.Bias,
        _ => return 0,
    };
    -(bias as i64) * 60
}

#[cfg(unix)]
fn detect_offset() -> i64 {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as libc::time_t)
        .unwrap_or(0);
    // SAFETY: tm — POD; localtime_r пишет только в него.
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    let res = unsafe { libc::localtime_r(&now, &mut tm) };
    if res.is_null() {
        return tz_env_offset().unwrap_or(0);
    }
    tm.tm_gmtoff as i64
}

#[cfg(not(any(unix, windows)))]
fn detect_offset() -> i64 {
    tz_env_offset().unwrap_or(0)
}

/// Запасной путь: POSIX-строка вида `UTC-3`/`MSK-3`/`EST+5` в `TZ`.
/// Знак в POSIX обратный: `MSK-3` значит UTC+3.
#[cfg(not(windows))]
fn tz_env_offset() -> Option<i64> {
    parse_posix_tz(&std::env::var("TZ").ok()?)
}

fn parse_posix_tz(s: &str) -> Option<i64> {
    let s = s.trim_start_matches(':');
    let rest = s.trim_start_matches(|c: char| c.is_ascii_alphabetic());
    if rest.len() == s.len() && !s.is_empty() && !s.starts_with(['+', '-']) {
        return None;
    }
    if rest.is_empty() {
        return Some(0); // «UTC», «GMT»
    }
    let (sign, num) = match rest.as_bytes()[0] {
        b'-' => (1, &rest[1..]),
        b'+' => (-1, &rest[1..]),
        _ => (-1, rest),
    };
    let num: String = num
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == ':')
        .collect();
    let mut parts = num.split(':');
    let h: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next().map_or(Ok(0), str::parse).ok()?;
    (h <= 24 && m < 60).then_some(sign * (h * 3600 + m * 60))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    // 2026-11-17 12:34:56 UTC
    const T: u64 = 1_794_918_896;

    #[test]
    fn civil_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(T as i64 / 86_400), (2026, 11, 17));
        assert_eq!(civil_from_days(-1), (1969, 12, 31));
        assert_eq!(civil_from_days(11_016), (2000, 2, 29));
    }

    #[test]
    fn today_time_only() {
        assert_eq!(format_with_offset(at(T), at(T), 0), "12:34:56");
        assert_eq!(format_with_offset(at(T), at(T), 3 * 3600), "15:34:56");
        assert_eq!(format_with_offset(at(T), at(T), -5 * 3600), "07:34:56");
        assert_eq!(
            format_with_offset(at(T), at(T), 5 * 3600 + 1800),
            "18:04:56"
        );
    }

    #[test]
    fn offset_crosses_midnight() {
        // 12:34 UTC + 12ч = 00:34 следующего дня; «сейчас» тоже сдвигается.
        assert_eq!(format_with_offset(at(T), at(T), 12 * 3600), "00:34:56");
        // Событие вчера по местному времени.
        let now = at(T + 12 * 3600); // 00:34:56 18.11 UTC
        assert_eq!(format_with_offset(at(T), now, 0), "17.11 12:34:56");
        // С offset -1ч «сейчас» = 23:34 17.11 → то же сутки.
        assert_eq!(format_with_offset(at(T), now, -3600), "11:34:56");
    }

    #[test]
    fn other_year_has_year() {
        let old = at(T - 400 * 86_400);
        assert_eq!(format_with_offset(old, at(T), 0), "13.10.2025 12:34:56");
    }

    #[test]
    fn posix_tz() {
        assert_eq!(parse_posix_tz("UTC"), Some(0));
        assert_eq!(parse_posix_tz("MSK-3"), Some(3 * 3600));
        assert_eq!(parse_posix_tz("EST5EDT"), Some(-5 * 3600));
        assert_eq!(parse_posix_tz("IST-5:30"), Some(5 * 3600 + 1800));
        assert_eq!(parse_posix_tz("Europe/Moscow"), None);
    }

    #[test]
    fn init_is_stable() {
        assert_eq!(init(), offset());
        assert!(offset().abs() <= 14 * 3600);
    }
}
