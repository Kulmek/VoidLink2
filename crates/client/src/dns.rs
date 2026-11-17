//! Крошечный DNS-ответчик внутри туннеля для имён пиров.
//!
//! Клиент перехватывает IPv4/UDP-пакеты, адресованные `100.66.0.53:53`,
//! и сам отвечает на запросы вида `<member>.vl` или `<member>.<group>.vl`
//! (регистр не важен). Разрешение имени делегируется замыканию, так что
//! модуль ничего не знает о движке.
//!
//! Плюс: нормализатор меток из отображаемых имён и генераторы команд
//! настройки split-DNS для Windows (NRPT), Linux (resolvectl) и macOS
//! (`/etc/resolver/vl`).

// подключается при интеграции
#![allow(dead_code)]

use std::net::Ipv4Addr;

/// Адрес встроенного DNS-сервера внутри туннеля.
pub const DNS_ADDR: Ipv4Addr = Ipv4Addr::new(100, 66, 0, 53);
/// Порт DNS.
pub const DNS_PORT: u16 = 53;
/// Корневой домен для имён пиров.
pub const DNS_SUFFIX: &str = "vl";
/// TTL ответов, секунд.
pub const ANSWER_TTL: u32 = 30;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const TYPE_ANY: u16 = 255;
const CLASS_IN: u16 = 1;

const RCODE_NOERROR: u8 = 0;
const RCODE_FORMERR: u8 = 1;
const RCODE_NXDOMAIN: u8 = 3;
const RCODE_NOTIMP: u8 = 4;
const RCODE_REFUSED: u8 = 5;

/// Результат резолва: (IPv4 как u32 в host order, IPv6).
pub type Resolved = (Option<u32>, Option<[u8; 16]>);

/// Обработать сырой IPv4-пакет из TUN.
///
/// Возвращает `Some(ответный IPv4-пакет)`, если пакет — DNS-запрос к
/// `100.66.0.53:53`, на который нужно ответить. `None` — пакет не наш
/// (другой адрес/порт/протокол, фрагмент, ответ, мусор без заголовка DNS).
///
/// `resolve(member, group)` получает метки уже в нижнем регистре.
pub fn handle_packet<F>(pkt: &[u8], resolve: F) -> Option<Vec<u8>>
where
    F: Fn(&str, Option<&str>) -> Option<Resolved>,
{
    let ip = parse_ipv4_udp(pkt)?;
    let dns_resp = answer_query(ip.payload, &resolve)?;
    Some(build_ipv4_udp(
        DNS_ADDR,
        ip.src,
        DNS_PORT,
        ip.src_port,
        &dns_resp,
    ))
}

/// Разобранный IPv4+UDP-пакет к нашему DNS.
struct UdpIn<'a> {
    src: Ipv4Addr,
    src_port: u16,
    payload: &'a [u8],
}

fn be16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}

fn parse_ipv4_udp(pkt: &[u8]) -> Option<UdpIn<'_>> {
    if pkt.len() < 20 || pkt[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((pkt[0] & 0x0f) as usize) * 4;
    let total = be16(pkt, 2) as usize;
    if ihl < 20 || total < ihl + 8 || total > pkt.len() {
        return None;
    }
    // фрагменты не собираем: MF или ненулевое смещение — игнор
    let frag = be16(pkt, 6);
    if frag & 0x2000 != 0 || frag & 0x1fff != 0 {
        return None;
    }
    if pkt[9] != 17 {
        return None;
    }
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    if dst != DNS_ADDR {
        return None;
    }
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let udp = &pkt[ihl..total];
    let src_port = be16(udp, 0);
    let dst_port = be16(udp, 2);
    let ulen = be16(udp, 4) as usize;
    if dst_port != DNS_PORT || ulen < 8 || ulen > udp.len() {
        return None;
    }
    Some(UdpIn {
        src,
        src_port,
        payload: &udp[8..ulen],
    })
}

/// Сформировать DNS-ответ на запрос. `None` — отвечать не нужно.
fn answer_query<F>(q: &[u8], resolve: &F) -> Option<Vec<u8>>
where
    F: Fn(&str, Option<&str>) -> Option<Resolved>,
{
    // без заголовка не знаем ID — молча игнорируем
    if q.len() < 12 {
        return None;
    }
    let id = be16(q, 0);
    let flags = be16(q, 2);
    // QR=1 — это ответ, не запрос
    if flags & 0x8000 != 0 {
        return None;
    }
    let opcode = ((flags >> 11) & 0x0f) as u8;
    let rd = flags & 0x0100 != 0;
    if opcode != 0 {
        return Some(header_only(id, opcode, rd, RCODE_NOTIMP));
    }
    let qdcount = be16(q, 4);
    if qdcount != 1 {
        return Some(header_only(id, 0, rd, RCODE_FORMERR));
    }
    let Some((labels, qend)) = parse_qname(q, 12) else {
        return Some(header_only(id, 0, rd, RCODE_FORMERR));
    };
    if qend + 4 > q.len() {
        return Some(header_only(id, 0, rd, RCODE_FORMERR));
    }
    let qtype = be16(q, qend);
    let qclass = be16(q, qend + 2);
    // вопрос эхом — в исходном виде (с исходным регистром)
    let question = &q[12..qend + 4];
    if qclass != CLASS_IN {
        return Some(response(id, rd, RCODE_REFUSED, question, &[]));
    }

    let (v4, v6) = match lookup(&labels, resolve) {
        Lookup::Found(r) => r,
        // имя-узел существует (apex или возможная группа) — NOERROR без ответов
        Lookup::NoData => return Some(response(id, rd, RCODE_NOERROR, question, &[])),
        Lookup::NxDomain => return Some(response(id, rd, RCODE_NXDOMAIN, question, &[])),
    };
    let mut answers: Vec<(u16, Vec<u8>)> = Vec::new();
    if let (TYPE_A | TYPE_ANY, Some(a)) = (qtype, v4) {
        answers.push((TYPE_A, a.to_be_bytes().to_vec()));
    }
    if let (TYPE_AAAA | TYPE_ANY, Some(a)) = (qtype, v6) {
        answers.push((TYPE_AAAA, a.to_vec()));
    }
    // имя существует, но записи нужного типа нет — NOERROR без ответов
    Some(response(id, rd, RCODE_NOERROR, question, &answers))
}

/// Разобрать QNAME начиная с `off`: метки в нижнем регистре и смещение
/// за нулевой меткой. Сжатие (указатели) в запросе не поддерживаем.
fn parse_qname(q: &[u8], mut off: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut total = 0usize;
    loop {
        let len = *q.get(off)? as usize;
        off += 1;
        if len == 0 {
            break;
        }
        if len > 63 {
            return None; // указатель сжатия или зарезервированные биты
        }
        let raw = q.get(off..off + len)?;
        off += len;
        total += len + 1;
        if total > 255 {
            return None;
        }
        if !raw.is_ascii() {
            // не-ASCII метки не наши, но формально запрос корректен
            labels.push(String::from_utf8_lossy(raw).to_lowercase());
        } else {
            labels.push(String::from_utf8_lossy(raw).to_ascii_lowercase());
        }
    }
    Some((labels, off))
}

/// Результат сопоставления имени.
enum Lookup {
    Found(Resolved),
    /// Узел может существовать (apex `vl`, `<group>.vl`) — NOERROR без ответов.
    /// NXDOMAIN здесь недопустим: по RFC 8020 резолвер закэширует «ниже ничего
    /// нет» и перестанет спрашивать `<member>.<group>.vl`.
    NoData,
    NxDomain,
}

/// Сопоставить метки с `<member>.vl` / `<member>.<group>.vl`.
fn lookup<F>(labels: &[String], resolve: &F) -> Lookup
where
    F: Fn(&str, Option<&str>) -> Option<Resolved>,
{
    let found = |r: Option<Resolved>, miss: Lookup| r.map_or(miss, Lookup::Found);
    match labels {
        [suffix] if suffix == DNS_SUFFIX => Lookup::NoData,
        // двухметочное имя может оказаться группой — не NXDOMAIN
        [member, suffix] if suffix == DNS_SUFFIX => found(resolve(member, None), Lookup::NoData),
        [member, group, suffix] if suffix == DNS_SUFFIX => {
            found(resolve(member, Some(group)), Lookup::NxDomain)
        }
        _ => Lookup::NxDomain,
    }
}

fn header(id: u16, opcode: u8, rd: bool, rcode: u8, qd: u16, an: u16) -> Vec<u8> {
    // QR=1, AA=1, RA=0
    let mut flags: u16 = 0x8000 | 0x0400 | ((opcode as u16 & 0x0f) << 11) | rcode as u16;
    if rd {
        flags |= 0x0100;
    }
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&qd.to_be_bytes());
    out.extend_from_slice(&an.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NS
    out.extend_from_slice(&0u16.to_be_bytes()); // AR
    out
}

fn header_only(id: u16, opcode: u8, rd: bool, rcode: u8) -> Vec<u8> {
    header(id, opcode, rd, rcode, 0, 0)
}

fn response(id: u16, rd: bool, rcode: u8, question: &[u8], answers: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = header(id, 0, rd, rcode, 1, answers.len() as u16);
    out.extend_from_slice(question);
    for (rtype, rdata) in answers {
        out.extend_from_slice(&0xC00Cu16.to_be_bytes()); // указатель на QNAME
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&CLASS_IN.to_be_bytes());
        out.extend_from_slice(&ANSWER_TTL.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(rdata);
    }
    out
}

/// Интернет-контрольная сумма (RFC 1071), до финального инвертирования.
fn sum16(mut acc: u32, data: &[u8]) -> u32 {
    let (pairs, rest) = data.as_chunks::<2>();
    for c in pairs {
        acc += u16::from_be_bytes(*c) as u32;
    }
    if let [last] = rest {
        acc += (*last as u32) << 8;
    }
    acc
}

fn fold(mut acc: u32) -> u16 {
    while acc >> 16 != 0 {
        acc = (acc & 0xffff) + (acc >> 16);
    }
    !(acc as u16)
}

/// Собрать IPv4+UDP-пакет с корректными контрольными суммами.
fn build_ipv4_udp(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total = 20 + udp_len;
    let mut p = Vec::with_capacity(total);
    p.push(0x45);
    p.push(0);
    p.extend_from_slice(&(total as u16).to_be_bytes());
    p.extend_from_slice(&0u16.to_be_bytes()); // identification
    p.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
    p.push(64); // TTL
    p.push(17); // UDP
    p.extend_from_slice(&[0, 0]); // checksum
    p.extend_from_slice(&src.octets());
    p.extend_from_slice(&dst.octets());
    let ipsum = fold(sum16(0, &p[..20]));
    p[10..12].copy_from_slice(&ipsum.to_be_bytes());

    p.extend_from_slice(&sport.to_be_bytes());
    p.extend_from_slice(&dport.to_be_bytes());
    p.extend_from_slice(&(udp_len as u16).to_be_bytes());
    p.extend_from_slice(&[0, 0]);
    p.extend_from_slice(payload);

    let mut acc = sum16(0, &src.octets());
    acc = sum16(acc, &dst.octets());
    acc += 17;
    acc += udp_len as u32;
    acc = sum16(acc, &p[20..]);
    let mut usum = fold(acc);
    if usum == 0 {
        usum = 0xffff; // 0 в UDP означает «нет суммы»
    }
    p[26..28].copy_from_slice(&usum.to_be_bytes());
    p
}

// ---------------------------------------------------------------------------
// Нормализация меток
// ---------------------------------------------------------------------------

fn translit(c: char) -> Option<&'static str> {
    Some(match c {
        'а' => "a",
        'б' => "b",
        'в' => "v",
        'г' => "g",
        'д' => "d",
        'е' => "e",
        'ё' => "e",
        'ж' => "zh",
        'з' => "z",
        'и' => "i",
        'й' => "y",
        'к' => "k",
        'л' => "l",
        'м' => "m",
        'н' => "n",
        'о' => "o",
        'п' => "p",
        'р' => "r",
        'с' => "s",
        'т' => "t",
        'у' => "u",
        'ф' => "f",
        'х' => "kh",
        'ц' => "ts",
        'ч' => "ch",
        'ш' => "sh",
        'щ' => "shch",
        'ъ' => "",
        'ы' => "y",
        'ь' => "",
        'э' => "e",
        'ю' => "yu",
        'я' => "ya",
        // украинские/белорусские
        'і' => "i",
        'ї' => "yi",
        'є' => "ye",
        'ґ' => "g",
        'ў' => "u",
        _ => return None,
    })
}

/// DNS-метка из отображаемого имени: нижний регистр, транслитерация
/// кириллицы, пробелы/подчёркивания/точки → `-`, прочее выкидывается,
/// повторные `-` схлопываются, `-` по краям обрезаются, максимум 63 символа.
/// Может вернуть пустую строку — вызывающий решает, чем её заменить.
pub fn normalize_label(display: &str) -> String {
    let mut out = String::with_capacity(display.len());
    let push_dash = |out: &mut String| {
        if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    };
    for ch in display.chars().flat_map(char::to_lowercase) {
        if ch.is_ascii_lowercase() || ch.is_ascii_digit() {
            out.push(ch);
        } else if matches!(ch, ' ' | '_' | '-' | '.') || ch.is_whitespace() {
            push_dash(&mut out);
        } else if let Some(t) = translit(ch) {
            out.push_str(t);
        }
    }
    out.truncate(63); // только ASCII — граница символа безопасна
    while out.ends_with('-') {
        out.pop();
    }
    out
}

// ---------------------------------------------------------------------------
// Команды настройки ОС
// ---------------------------------------------------------------------------

/// Windows: PowerShell-команда добавления NRPT-правила для `.vl`.
pub fn windows_nrpt_add() -> String {
    // сначала убираем свои старые правила — повторный вызов не плодит дубликаты
    format!(
        "{}; Add-DnsClientNrptRule -Namespace \".{DNS_SUFFIX}\" -NameServers \"{DNS_ADDR}\" -Comment \"{NRPT_COMMENT}\"",
        windows_nrpt_remove()
    )
}

/// Метка наших NRPT-правил (чтобы не трогать пользовательские `.vl`).
const NRPT_COMMENT: &str = "VoidLink";

/// Windows: PowerShell-команда удаления наших NRPT-правил.
pub fn windows_nrpt_remove() -> String {
    format!(
        "Get-DnsClientNrptRule | Where-Object {{ $_.Namespace -eq '.{DNS_SUFFIX}' -and $_.Comment -eq '{NRPT_COMMENT}' }} | Remove-DnsClientNrptRule -Force"
    )
}

/// Linux (systemd-resolved): команды (argv) для интерфейса `ifname`.
pub fn linux_resolvectl_setup(ifname: &str) -> Vec<Vec<String>> {
    vec![
        vec!["resolvectl".into(), "dns".into(), ifname.into(), DNS_ADDR.to_string()],
        vec!["resolvectl".into(), "domain".into(), ifname.into(), format!("~{DNS_SUFFIX}")],
    ]
}

/// Linux: откат настроек resolvectl для интерфейса.
pub fn linux_resolvectl_revert(ifname: &str) -> Vec<String> {
    vec!["resolvectl".into(), "revert".into(), ifname.into()]
}

/// macOS: путь файла резолвера для домена `.vl`.
pub const MACOS_RESOLVER_PATH: &str = "/etc/resolver/vl";

/// macOS: содержимое `/etc/resolver/vl`.
pub fn macos_resolver_content() -> String {
    format!("# VoidLink: имена пиров\nnameserver {DNS_ADDR}\nport {DNS_PORT}\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const CLIENT: Ipv4Addr = Ipv4Addr::new(100, 66, 0, 2);

    fn qname(name: &str) -> Vec<u8> {
        let mut v = Vec::new();
        for l in name.split('.').filter(|l| !l.is_empty()) {
            v.push(l.len() as u8);
            v.extend_from_slice(l.as_bytes());
        }
        v.push(0);
        v
    }

    fn query(id: u16, name: &str, qtype: u16, qclass: u16) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(&id.to_be_bytes());
        v.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        v.extend_from_slice(&1u16.to_be_bytes());
        v.extend_from_slice(&[0; 6]);
        v.extend_from_slice(&qname(name));
        v.extend_from_slice(&qtype.to_be_bytes());
        v.extend_from_slice(&qclass.to_be_bytes());
        v
    }

    fn wrap(dns: &[u8]) -> Vec<u8> {
        build_ipv4_udp(CLIENT, DNS_ADDR, 40000, DNS_PORT, dns)
    }

    fn resolver(member: &str, group: Option<&str>) -> Option<Resolved> {
        let v6 = [0xfd, 0x66, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        match (member, group) {
            ("alpha", None) => Some((Some(u32::from(Ipv4Addr::new(100, 66, 0, 2))), Some(v6))),
            ("alpha", Some("work")) => Some((Some(u32::from(Ipv4Addr::new(100, 66, 1, 2))), None)),
            ("bravo", None) => Some((Some(u32::from(Ipv4Addr::new(100, 66, 0, 3))), None)),
            ("six", None) => Some((None, Some(v6))),
            _ => None,
        }
    }

    struct Parsed {
        dns: Vec<u8>,
    }

    /// Разобрать ответ, проверив IP- и UDP-суммы и адресацию.
    fn parse_resp(p: &[u8]) -> Parsed {
        assert_eq!(p[0], 0x45);
        assert_eq!(be16(p, 2) as usize, p.len());
        assert_eq!(fold(sum16(0, &p[..20])), 0, "IP checksum");
        assert_eq!(p[9], 17);
        assert_eq!(&p[12..16], &DNS_ADDR.octets());
        assert_eq!(&p[16..20], &CLIENT.octets());
        assert_eq!(be16(p, 20), 53);
        assert_eq!(be16(p, 22), 40000);
        assert_eq!(be16(p, 24) as usize, p.len() - 20);
        let mut acc = sum16(0, &p[12..20]);
        acc += 17 + (p.len() - 20) as u32;
        acc = sum16(acc, &p[20..]);
        assert_eq!(fold(acc), 0, "UDP checksum");
        Parsed { dns: p[28..].to_vec() }
    }

    impl Parsed {
        fn id(&self) -> u16 {
            be16(&self.dns, 0)
        }
        fn flags(&self) -> u16 {
            be16(&self.dns, 2)
        }
        fn rcode(&self) -> u8 {
            (self.flags() & 0x0f) as u8
        }
        fn qd(&self) -> u16 {
            be16(&self.dns, 4)
        }
        fn an(&self) -> u16 {
            be16(&self.dns, 6)
        }
        /// Ответные записи (type, ttl, rdata).
        fn answers(&self) -> Vec<(u16, u32, Vec<u8>)> {
            let d = &self.dns;
            let mut off = 12;
            for _ in 0..self.qd() {
                let (_, end) = parse_qname(d, off).unwrap();
                off = end + 4;
            }
            let mut out = Vec::new();
            for _ in 0..self.an() {
                assert_eq!(be16(d, off), 0xC00C);
                let t = be16(d, off + 2);
                assert_eq!(be16(d, off + 4), CLASS_IN);
                let ttl = u32::from_be_bytes(d[off + 6..off + 10].try_into().unwrap());
                let rl = be16(d, off + 10) as usize;
                out.push((t, ttl, d[off + 12..off + 12 + rl].to_vec()));
                off += 12 + rl;
            }
            assert_eq!(off, d.len());
            out
        }
    }

    fn ask(name: &str, qtype: u16) -> Parsed {
        let pkt = wrap(&query(0x1234, name, qtype, CLASS_IN));
        parse_resp(&handle_packet(&pkt, resolver).expect("ответ"))
    }

    #[test]
    fn a_record_member() {
        let r = ask("alpha.vl", TYPE_A);
        assert_eq!(r.id(), 0x1234);
        assert_eq!(r.flags() & 0x8000, 0x8000, "QR");
        assert_eq!(r.flags() & 0x0400, 0x0400, "AA");
        assert_eq!(r.flags() & 0x0100, 0x0100, "RD эхом");
        assert_eq!(r.rcode(), RCODE_NOERROR);
        assert_eq!(r.qd(), 1);
        assert_eq!(r.answers(), vec![(TYPE_A, 30, vec![100, 66, 0, 2])]);
    }

    #[test]
    fn a_record_member_group_case_insensitive() {
        let r = ask("ALPHA.Work.VL", TYPE_A);
        assert_eq!(r.rcode(), RCODE_NOERROR);
        assert_eq!(r.answers(), vec![(TYPE_A, 30, vec![100, 66, 1, 2])]);
        // вопрос эхом в исходном регистре
        assert_eq!(&r.dns[12..12 + qname("ALPHA.Work.VL").len()], &qname("ALPHA.Work.VL")[..]);
    }

    #[test]
    fn aaaa_and_any() {
        let r = ask("alpha.vl", TYPE_AAAA);
        let a = r.answers();
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].0, TYPE_AAAA);
        assert_eq!(a[0].2.len(), 16);

        let r = ask("alpha.vl", TYPE_ANY);
        let types: Vec<u16> = r.answers().iter().map(|a| a.0).collect();
        assert_eq!(types, vec![TYPE_A, TYPE_AAAA]);

        let r = ask("six.vl", TYPE_A);
        assert_eq!(r.rcode(), RCODE_NOERROR);
        assert!(r.answers().is_empty());
    }

    #[test]
    fn missing_aaaa_is_noerror_empty() {
        let r = ask("bravo.vl", TYPE_AAAA);
        assert_eq!(r.rcode(), RCODE_NOERROR);
        assert_eq!(r.an(), 0);
        assert!(r.answers().is_empty());
    }

    #[test]
    fn apex_and_two_label_misses_nodata() {
        for name in ["vl", "VL", "nobody.vl", "work.vl"] {
            let r = ask(name, TYPE_A);
            assert_eq!(r.rcode(), RCODE_NOERROR, "{name}");
            assert_eq!(r.qd(), 1);
            assert_eq!(r.an(), 0);
        }
    }

    #[test]
    fn unknown_names_nxdomain() {
        for name in ["alpha.other.vl", "alpha.com", "a.b.c.vl", "alpha.vl.example"] {
            let r = ask(name, TYPE_A);
            assert_eq!(r.rcode(), RCODE_NXDOMAIN, "{name}");
            assert_eq!(r.qd(), 1);
            assert_eq!(r.an(), 0);
        }
    }

    #[test]
    fn other_qtype_for_existing_name_noerror() {
        let r = ask("alpha.vl", 16); // TXT
        assert_eq!(r.rcode(), RCODE_NOERROR);
        assert_eq!(r.an(), 0);
    }

    #[test]
    fn non_in_class_refused() {
        let pkt = wrap(&query(7, "alpha.vl", TYPE_A, 3));
        let r = parse_resp(&handle_packet(&pkt, resolver).unwrap());
        assert_eq!(r.rcode(), RCODE_REFUSED);
    }

    #[test]
    fn garbage_formerr() {
        // заголовок есть, вопрос оборван
        let mut q = query(0xBEEF, "alpha.vl", TYPE_A, CLASS_IN);
        q.truncate(q.len() - 3);
        let r = parse_resp(&handle_packet(&wrap(&q), resolver).unwrap());
        assert_eq!(r.id(), 0xBEEF);
        assert_eq!(r.rcode(), RCODE_FORMERR);
        assert_eq!(r.qd(), 0);
        assert_eq!(r.dns.len(), 12);

        // qdcount = 2
        let mut q = query(1, "alpha.vl", TYPE_A, CLASS_IN);
        q[5] = 2;
        let r = parse_resp(&handle_packet(&wrap(&q), resolver).unwrap());
        assert_eq!(r.rcode(), RCODE_FORMERR);

        // указатель сжатия в QNAME
        let mut q = query(1, "alpha.vl", TYPE_A, CLASS_IN);
        q[12] = 0xC0;
        let r = parse_resp(&handle_packet(&wrap(&q), resolver).unwrap());
        assert_eq!(r.rcode(), RCODE_FORMERR);

        // метка уходит за конец
        let mut q = query(1, "alpha.vl", TYPE_A, CLASS_IN);
        q[12] = 60;
        let r = parse_resp(&handle_packet(&wrap(&q), resolver).unwrap());
        assert_eq!(r.rcode(), RCODE_FORMERR);
    }

    #[test]
    fn notimp_for_other_opcode() {
        let mut q = query(5, "alpha.vl", TYPE_A, CLASS_IN);
        q[2] |= 2 << 3; // opcode = 2 (STATUS)
        let r = parse_resp(&handle_packet(&wrap(&q), resolver).unwrap());
        assert_eq!(r.rcode(), RCODE_NOTIMP);
        assert_eq!((r.flags() >> 11) & 0x0f, 2);
    }

    #[test]
    fn ignored_packets() {
        let good = query(1, "alpha.vl", TYPE_A, CLASS_IN);
        // ответ (QR=1)
        let mut resp = good.clone();
        resp[2] |= 0x80;
        assert!(handle_packet(&wrap(&resp), resolver).is_none());
        // слишком короткий DNS
        assert!(handle_packet(&wrap(&good[..11]), resolver).is_none());
        // другой адрес
        let p = build_ipv4_udp(CLIENT, Ipv4Addr::new(8, 8, 8, 8), 40000, 53, &good);
        assert!(handle_packet(&p, resolver).is_none());
        // другой порт
        let p = build_ipv4_udp(CLIENT, DNS_ADDR, 40000, 5353, &good);
        assert!(handle_packet(&p, resolver).is_none());
        // не UDP
        let mut p = wrap(&good);
        p[9] = 6;
        assert!(handle_packet(&p, resolver).is_none());
        // фрагмент
        let mut p = wrap(&good);
        p[6] = 0x20;
        assert!(handle_packet(&p, resolver).is_none());
        // IPv6 / мусор / обрезанный пакет
        assert!(handle_packet(&[0x60; 40], resolver).is_none());
        assert!(handle_packet(&[], resolver).is_none());
        let p = wrap(&good);
        assert!(handle_packet(&p[..p.len() - 1], resolver).is_none());
    }

    #[test]
    fn ip_options_and_trailing_padding() {
        // IHL=6 (4 байта опций) и лишние байты за total length
        let dns = query(9, "bravo.vl", TYPE_A, CLASS_IN);
        let base = wrap(&dns);
        let mut p = Vec::new();
        p.push(0x46);
        p.push(0);
        p.extend_from_slice(&((base.len() + 4) as u16).to_be_bytes());
        p.extend_from_slice(&base[4..20]);
        p.extend_from_slice(&[1, 1, 1, 0]); // NOP-опции
        p.extend_from_slice(&base[20..]);
        p.extend_from_slice(&[0xAA; 6]);
        let r = parse_resp(&handle_packet(&p, resolver).unwrap());
        assert_eq!(r.id(), 9);
        assert_eq!(r.answers(), vec![(TYPE_A, 30, vec![100, 66, 0, 3])]);
    }

    #[test]
    fn checksum_known_vector() {
        // классический пример из Википедии
        let hdr = [
            0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8,
            0x00, 0x01, 0xc0, 0xa8, 0x00, 0xc7,
        ];
        assert_eq!(fold(sum16(0, &hdr)), 0xb861);
        // нечётная длина
        assert_eq!(fold(sum16(0, &[0x01])), !0x0100);
    }

    #[test]
    fn normalize() {
        assert_eq!(normalize_label("Alpha"), "alpha");
        assert_eq!(normalize_label("Максим Беляков"), "maksim-belyakov");
        assert_eq!(normalize_label("Щука_Ёжик"), "shchuka-ezhik");
        assert_eq!(normalize_label("  my  cool__pc  "), "my-cool-pc");
        assert_eq!(normalize_label("Объём"), "obem");
        assert_eq!(normalize_label("dev.box-01"), "dev-box-01");
        assert_eq!(normalize_label("!!@#$"), "");
        assert_eq!(normalize_label("日本 pc 🚀"), "pc");
        assert_eq!(normalize_label("Ґанок Їжак"), "ganok-yizhak");
        let long = "a".repeat(62) + " b";
        let n = normalize_label(&long);
        assert_eq!(n.len(), 62, "хвостовой дефис после обрезки убран");
        assert!(normalize_label(&"я".repeat(100)).len() <= 63);
    }

    #[test]
    fn os_commands() {
        let add = windows_nrpt_add();
        assert!(add.starts_with(&windows_nrpt_remove()), "{add}");
        assert!(add.ends_with(
            "; Add-DnsClientNrptRule -Namespace \".vl\" -NameServers \"100.66.0.53\" -Comment \"VoidLink\""
        ));
        assert!(windows_nrpt_remove().contains("Remove-DnsClientNrptRule"));
        assert!(windows_nrpt_remove().contains("'.vl'"));
        assert!(windows_nrpt_remove().contains("$_.Comment -eq 'VoidLink'"));
        let l = linux_resolvectl_setup("voidlink0");
        assert_eq!(l[0], ["resolvectl", "dns", "voidlink0", "100.66.0.53"]);
        assert_eq!(l[1], ["resolvectl", "domain", "voidlink0", "~vl"]);
        assert_eq!(linux_resolvectl_revert("voidlink0"), ["resolvectl", "revert", "voidlink0"]);
        assert!(macos_resolver_content().contains("nameserver 100.66.0.53\n"));
        assert_eq!(MACOS_RESOLVER_PATH, "/etc/resolver/vl");
    }
}
