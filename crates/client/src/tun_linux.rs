//! Linux TUN-устройство через /dev/net/tun (аналог wintun-адаптера на Windows).
//!
//! Открываем /dev/net/tun, делаем TUNSETIFF с IFF_TUN|IFF_NO_PI (сырые IP-пакеты
//! без 4-байтового заголовка), выставляем MTU и поднимаем интерфейс через `ip link`,
//! адреса групп (/24) добавляем идемпотентно через `ip addr replace`.
//! Чтение/запись — блокирующие, по одному IP-пакету за вызов.

// подключается при интеграции
#![allow(dead_code)]

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::AsRawFd;
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use anyhow::{Context, Result, anyhow, bail};

/// Путь к клонирующему устройству TUN.
const TUN_CLONE_PATH: &str = "/dev/net/tun";
/// _IOW('T', 202, int) — одинаково на x86_64/aarch64.
const TUNSETIFF: libc::c_ulong = 0x4004_54ca;
const IFF_TUN: libc::c_short = 0x0001;
const IFF_NO_PI: libc::c_short = 0x1000;
/// Максимальная длина имени интерфейса с завершающим нулём.
const IFNAMSIZ: usize = 16;

/// struct ifreq для TUNSETIFF: имя + флаги, остаток union добит нулями
/// (полный размер ifreq на 64-битном Linux — 40 байт).
#[repr(C)]
#[derive(Clone, Copy)]
struct IfReqFlags {
    name: [u8; IFNAMSIZ],
    flags: libc::c_short,
    _pad: [u8; 22],
}

/// Собирает ifreq для TUNSETIFF. Имя должно быть непустым ASCII без '/', пробелов
/// и NUL, длиной не больше 15 байт (ограничение ядра).
fn build_ifreq(name: &str) -> Result<IfReqFlags> {
    validate_ifname(name)?;
    let mut req = IfReqFlags {
        name: [0; IFNAMSIZ],
        flags: IFF_TUN | IFF_NO_PI,
        _pad: [0; 22],
    };
    req.name[..name.len()].copy_from_slice(name.as_bytes());
    Ok(req)
}

/// Проверка имени интерфейса по правилам ядра (dev_valid_name).
fn validate_ifname(name: &str) -> Result<()> {
    if name.is_empty() || name.len() >= IFNAMSIZ {
        bail!("имя интерфейса должно быть 1..{} байт: {name:?}", IFNAMSIZ - 1);
    }
    if name == "." || name == ".." {
        bail!("недопустимое имя интерфейса: {name:?}");
    }
    if name
        .bytes()
        .any(|b| b == b'/' || b == b':' || b == 0 || b.is_ascii_whitespace() || !b.is_ascii())
    {
        bail!("недопустимые символы в имени интерфейса: {name:?}");
    }
    Ok(())
}

/// Достаёт имя из ifreq (ядро может вернуть другое, если в имени был шаблон %d).
fn ifreq_name(req: &IfReqFlags) -> String {
    let end = req.name.iter().position(|&b| b == 0).unwrap_or(IFNAMSIZ);
    String::from_utf8_lossy(&req.name[..end]).into_owned()
}

/// Аргументы `ip link set dev <name> mtu <mtu> up`.
fn link_up_args(name: &str, mtu: usize) -> Vec<String> {
    vec![
        "link".into(),
        "set".into(),
        "dev".into(),
        name.into(),
        "mtu".into(),
        mtu.to_string(),
        "up".into(),
    ]
}

/// Аргументы `ip -4 addr replace <ip>/24 dev <name>` — replace идемпотентен,
/// повторный вызов с тем же адресом не падает с «File exists».
fn addr4_args(name: &str, ip: u32) -> Vec<String> {
    let addr = Ipv4Addr::from(ip);
    vec![
        "-4".into(),
        "addr".into(),
        "replace".into(),
        format!("{addr}/24"),
        "dev".into(),
        name.into(),
    ]
}

/// Аргументы `ip -6 addr replace <ip>/<prefix> dev <name> nodad`
/// (nodad — адрес сразу пригоден, без ожидания Duplicate Address Detection).
fn addr6_args(name: &str, ip: Ipv6Addr, prefix: u8) -> Vec<String> {
    vec![
        "-6".into(),
        "addr".into(),
        "replace".into(),
        format!("{ip}/{prefix}"),
        "dev".into(),
        name.into(),
        "nodad".into(),
    ]
}

/// Запускает `ip` с аргументами, ошибка содержит stderr.
fn run_ip(args: &[String]) -> Result<()> {
    let out = Command::new("ip")
        .args(args)
        .output()
        .with_context(|| format!("запуск ip {}", args.join(" ")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        return Err(anyhow!("ip {} завершился с ошибкой: {}", args.join(" "), err.trim()));
    }
    Ok(())
}

/// TUN-интерфейс Linux. Потокобезопасен: чтение и запись можно вести из разных
/// потоков одновременно (через `Arc<LinuxTun>`).
pub struct LinuxTun {
    file: File,
    name: String,
    mtu: usize,
    /// Уже назначенные IPv4-адреса групп (чтобы не дёргать `ip` повторно).
    used4: Mutex<HashSet<u32>>,
    used6: Mutex<HashSet<(Ipv6Addr, u8)>>,
}

impl LinuxTun {
    /// Создаёт (или подключается к существующему) TUN-интерфейсу `name`,
    /// выставляет MTU и поднимает его. Нужны root или CAP_NET_ADMIN.
    pub fn open(name: &str, mtu: usize) -> Result<Self> {
        let mut req = build_ifreq(name)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(TUN_CLONE_PATH)
            .with_context(|| format!("открытие {TUN_CLONE_PATH} (нужны root/CAP_NET_ADMIN)"))?;
        // SAFETY: fd валиден, req — корректно выровненная структура размера ifreq.
        let rc = unsafe { libc::ioctl(file.as_raw_fd(), TUNSETIFF as _, &mut req as *mut IfReqFlags) };
        if rc < 0 {
            return Err(std::io::Error::last_os_error()).context("ioctl TUNSETIFF");
        }
        let name = ifreq_name(&req);
        run_ip(&link_up_args(&name, mtu)).context("установка MTU и подъём интерфейса")?;
        Ok(Self {
            file,
            name,
            mtu,
            used4: Mutex::new(HashSet::new()),
            used6: Mutex::new(HashSet::new()),
        })
    }

    /// Фактическое имя интерфейса.
    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn mtu(&self) -> usize {
        self.mtu
    }

    /// Блокирующее чтение одного IP-пакета. Возвращает его длину.
    pub fn read(&self, buf: &mut [u8]) -> Result<usize> {
        loop {
            match (&self.file).read(buf) {
                Ok(n) => return Ok(n),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("чтение из TUN"),
            }
        }
    }

    /// Запись одного IP-пакета целиком.
    pub fn write(&self, packet: &[u8]) -> Result<()> {
        loop {
            match (&self.file).write(packet) {
                Ok(n) if n == packet.len() => return Ok(()),
                Ok(n) => bail!("TUN принял {n} из {} байт", packet.len()),
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(e).context("запись в TUN"),
            }
        }
    }

    /// Назначает IPv4-адрес группы с маской /24 (идемпотентно).
    pub fn ensure_address(&self, ip: u32) -> Result<()> {
        let mut used = self.used4.lock().unwrap_or_else(|e| e.into_inner());
        if used.contains(&ip) {
            return Ok(());
        }
        run_ip(&addr4_args(&self.name, ip)).context("назначение IPv4-адреса")?;
        used.insert(ip);
        Ok(())
    }

    /// Назначает IPv6-адрес с заданным префиксом (идемпотентно).
    pub fn ensure_address6(&self, ip: Ipv6Addr, prefix: u8) -> Result<()> {
        if prefix > 128 {
            bail!("недопустимый префикс IPv6: {prefix}");
        }
        let mut used = self.used6.lock().unwrap_or_else(|e| e.into_inner());
        if used.contains(&(ip, prefix)) {
            return Ok(());
        }
        run_ip(&addr6_args(&self.name, ip, prefix)).context("назначение IPv6-адреса")?;
        used.insert((ip, prefix));
        Ok(())
    }
}

/// Запускает поток-читатель: каждый пакет из TUN передаётся в `on_packet`.
/// Поток завершается, когда `on_packet` вернёт false или чтение упадёт с ошибкой
/// (ошибка возвращается из join).
pub fn spawn_reader<F>(tun: Arc<LinuxTun>, mut on_packet: F) -> Result<JoinHandle<Result<()>>>
where
    F: FnMut(&[u8]) -> bool + Send + 'static,
{
    let buf_len = tun.mtu().max(1500) + 64;
    std::thread::Builder::new()
        .name("tun-linux-rx".into())
        .spawn(move || {
            let mut buf = vec![0u8; buf_len];
            loop {
                let n = tun.read(&mut buf)?;
                if n == 0 {
                    continue;
                }
                if !on_packet(&buf[..n]) {
                    return Ok(());
                }
            }
        })
        .context("запуск потока чтения TUN")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_size_matches_kernel() {
        assert_eq!(std::mem::size_of::<IfReqFlags>(), 40);
        assert_eq!(std::mem::size_of::<IfReqFlags>(), std::mem::size_of::<libc::ifreq>());
    }

    #[test]
    fn ifreq_building() {
        let req = build_ifreq("voidlink0").unwrap();
        assert_eq!(&req.name[..9], b"voidlink0");
        assert!(req.name[9..].iter().all(|&b| b == 0));
        assert_eq!(req.flags, IFF_TUN | IFF_NO_PI);
        assert_eq!(ifreq_name(&req), "voidlink0");
        // 15 байт — максимум.
        assert!(build_ifreq("abcdefghijklmno").is_ok());
    }

    #[test]
    fn ifname_validation() {
        for bad in ["", "abcdefghijklmnop", "a/b", "a b", "a:b", ".", "..", "имя"] {
            assert!(build_ifreq(bad).is_err(), "{bad:?} должно отклоняться");
        }
    }

    #[test]
    fn command_args() {
        assert_eq!(
            link_up_args("vl0", 1400).join(" "),
            "link set dev vl0 mtu 1400 up"
        );
        let ip = u32::from(Ipv4Addr::new(10, 66, 3, 7));
        assert_eq!(
            addr4_args("vl0", ip).join(" "),
            "-4 addr replace 10.66.3.7/24 dev vl0"
        );
        let ip6: Ipv6Addr = "fd00:766c::1".parse().unwrap();
        assert_eq!(
            addr6_args("vl0", ip6, 64).join(" "),
            "-6 addr replace fd00:766c::1/64 dev vl0 nodad"
        );
    }

    /// Требует root: `sudo -E cargo test -p tunnel-client tun_linux -- --ignored`.
    #[test]
    #[ignore]
    fn open_real_device() {
        let tun = Arc::new(LinuxTun::open("vltest0", 1400).expect("open"));
        assert_eq!(tun.name(), "vltest0");
        let ip = u32::from(Ipv4Addr::new(10, 250, 1, 2));
        tun.ensure_address(ip).unwrap();
        tun.ensure_address(ip).unwrap(); // повтор — без ошибки
        tun.ensure_address6("fd00:766c::2".parse().unwrap(), 64).unwrap();
        // Минимальный IPv4/UDP-пакет на соседний адрес подсети должен приниматься ядром.
        let mut pkt = [0u8; 28];
        pkt[0] = 0x45;
        pkt[3] = 28;
        pkt[8] = 64;
        pkt[9] = 17;
        pkt[12..16].copy_from_slice(&[10, 250, 1, 3]);
        pkt[16..20].copy_from_slice(&[10, 250, 1, 2]);
        let _ = tun.write(&pkt);
    }
}
