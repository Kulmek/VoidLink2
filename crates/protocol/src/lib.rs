//! Протокол туннеля v2.
//!
//! Два класса UDP-фреймов с общим заголовком:
//! ```text
//! magic "TNL2" (4) | typ (1) | body_len (2, LE) | body
//! ```
//!
//! **Управляющие фреймы** (клиент ↔ сервер): body = nonce(12) ||
//! ChaCha20-Poly1305(payload, aad = заголовок). Ключ канала выводится из
//! static-static X25519(identity клиента, identity сервера).
//!
//! **Фреймы группы** (клиент ↔ клиент, в т.ч. через релей): открытая часть
//! заголовка содержит group_id / src_ip / dst_ip — сервер-релей читает только
//! её и пересылает фрейм целиком, не расшифровывая payload (end-to-end).
//! Payload шифруется ключом группы.

use anyhow::{ensure, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::Rng;
use x25519_dalek::{PublicKey, StaticSecret};

pub const MAGIC: [u8; 4] = *b"TNL2";
pub const HDR_LEN: usize = 4 + 1 + 2;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;
pub const PUBKEY_LEN: usize = 32;

pub const PROTOCOL_VERSION: u8 = 2;

/// Типы управляющих фреймов.
pub mod ctrl {
    pub const HELLO: u8 = 0x01;
    pub const CREATE_GROUP: u8 = 0x02;
    pub const LIST_GROUPS: u8 = 0x03;
    pub const JOIN_GROUP: u8 = 0x04;
    pub const LEAVE_GROUP: u8 = 0x05;
    pub const INVITE: u8 = 0x06;
    pub const KICK: u8 = 0x07;
    pub const BAN: u8 = 0x08;
    pub const RENAME_GROUP: u8 = 0x09;
    pub const DELETE_GROUP: u8 = 0x0A;
    pub const STATUS: u8 = 0x0B;
    pub const CTRL_PING: u8 = 0x0C;
    pub const FRIEND_GROUPS: u8 = 0x0D;
    /// Клиент → сервер: отклонить приглашение. Payload — gid (`enc_gid`).
    /// Идемпотентно: нет приглашения — нет ошибки. Старые серверы тип не
    /// знают и молча игнорируют (приглашение остаётся висеть).
    pub const DECLINE_INVITE: u8 = 0x0E;
    /// Клиент → сервер: окно неотвеченных приглашений с gid ≥ payload
    /// (`enc_gid`), ответ — `INVITE_LIST`. Без побочных эффектов: так
    /// дочитывается неполный список. Старые серверы тип игнорируют.
    pub const LIST_INVITES: u8 = 0x0F;

    pub const WELCOME: u8 = 0x81;
    pub const GROUP_STATE: u8 = 0x82;
    pub const GROUP_LIST: u8 = 0x83;
    pub const GROUP_UPDATE: u8 = 0x84;
    pub const INVITE_RCVD: u8 = 0x85;
    pub const ERROR: u8 = 0x86;
    /// Сервер → владельцу группы: приглашённый отклонил приглашение.
    /// Payload — `enc_invite_declined`. Старые клиенты тип игнорируют.
    pub const INVITE_DECLINED: u8 = 0x87;
    /// Сервер → клиенту: окно неотвеченных приглашений одним фреймом
    /// (`enc_invite_list`, не больше 16 за раз). Сразу после HELLO, в ответ
    /// на DECLINE_INVITE / LIST_INVITES, после JOIN, потратившего
    /// приглашение или отклонённого (группы нет, бан, нет приглашения), и
    /// после BAN/KICK, снявшего приглашение. Чего нет в покрытом окне
    /// (`InviteList::covers`), на сервере уже недействительно — клиент
    /// снимает такие окна; неполное окно дочитывается LIST_INVITES.
    /// Старые клиенты тип игнорируют (и не получают повторов на каждый HELLO).
    pub const INVITE_LIST: u8 = 0x88;
    pub const CTRL_PONG: u8 = 0x8C;
    pub const FRIEND_GROUPS_RESP: u8 = 0x8D;
    /// Сервер → клиент, **открытым текстом**, пустое тело: «сессии с этого
    /// адреса нет» (сервер перезапущен или сессия истекла). Клиент сразу
    /// шлёт HELLO, не дожидаясь таймаута. Старые клиенты фрейм игнорируют.
    pub const RESET: u8 = 0x8E;
}

/// Типы фреймов внутри группы.
pub mod grp {
    /// IP-пакет: payload = сырой IPv4.
    pub const DATA: u8 = 0x21;
    /// RTT-зонд: payload = 8-байтовая метка времени отправителя.
    pub const PING: u8 = 0x22;
    /// Ответ: payload = та же метка.
    pub const PONG: u8 = 0x23;
    /// Пробивание NAT: без payload. Ответ на PUNCH — KEEPALIVE, **не** PUNCH:
    /// иначе два клиента бесконечно отражают PUNCH друг другу.
    pub const PUNCH: u8 = 0x24;
    /// Поддержание NAT-маппинга и liveness: без payload. На него не отвечают.
    pub const KEEPALIVE: u8 = 0x25;
}

pub type SymKey = [u8; 32];

// ---------- identity ----------

/// Постоянная личность: ed25519 (подписи) + x25519 (канальный ключ).
#[derive(Clone)]
pub struct Identity {
    pub ed_seed: [u8; 32],
    pub x_seed: [u8; 32],
}

impl Identity {
    pub fn generate() -> Self {
        let mut ed_seed = [0u8; 32];
        let mut x_seed = [0u8; 32];
        rand::rng().fill_bytes(&mut ed_seed);
        rand::rng().fill_bytes(&mut x_seed);
        Self { ed_seed, x_seed }
    }

    pub fn ed(&self) -> SigningKey {
        SigningKey::from_bytes(&self.ed_seed)
    }

    /// Публичный ключ ed25519 (identity для сервера/друзей).
    pub fn ed_pub(&self) -> [u8; 32] {
        self.ed().verifying_key().to_bytes()
    }

    /// Публичный ключ x25519 (для вывода канального ключа).
    pub fn x_pub(&self) -> [u8; 32] {
        PublicKey::from(&StaticSecret::from(self.x_seed)).to_bytes()
    }

    /// Общий ключ канала с пировым identity (static-static DH + KDF).
    pub fn ctrl_key_with(&self, peer_x_pub: &[u8; 32]) -> SymKey {
        let shared = StaticSecret::from(self.x_seed)
            .diffie_hellman(&PublicKey::from(*peer_x_pub))
            .to_bytes();
        derive_key(b"tunnel/v2/ctrl", &shared)
    }

    /// Подписывает данные identity-ключом.
    pub fn sign(&self, msg: &[u8]) -> [u8; 64] {
        self.ed().sign(msg).to_bytes()
    }

    pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> Result<()> {
        let vk = VerifyingKey::from_bytes(pubkey)?;
        vk.verify(msg, &ed25519_dalek::Signature::from_bytes(sig))
            .map_err(|_| anyhow::anyhow!("bad signature"))
    }

    /// Friend code: base32 (Crockford, без I/L/O/U) публичного ключа.
    pub fn friend_code(&self) -> String {
        friend_code_of(&self.ed_pub())
    }

    /// Разбор friend code → ed25519 pubkey.
    pub fn parse_friend_code(code: &str) -> Result<[u8; 32]> {
        parse_friend_code(code)
    }
}

pub fn derive_key(tag: &[u8], material: &[u8]) -> SymKey {
    let mut h = blake3::Hasher::new();
    h.update(tag);
    h.update(material);
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

const B32: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn friend_code_of(pubkey: &[u8; 32]) -> String {
    let mut bits: u32 = 0;
    let mut nbits = 0;
    let mut emitted = 0usize;
    let mut out = String::from("TUN-");
    for b in pubkey.iter() {
        bits = (bits << 8) | *b as u32;
        nbits += 8;
        while nbits >= 5 {
            nbits -= 5;
            out.push(B32[((bits >> nbits) & 31) as usize] as char);
            emitted += 1;
            if emitted.is_multiple_of(8) && emitted < 52 {
                out.push('-');
            }
        }
    }
    // 256 бит = 51 группа по 5 бит + 1 бит остатка → паддинг-символ до 52.
    if nbits > 0 {
        out.push(B32[((bits << (5 - nbits)) & 31) as usize] as char);
    }
    out
}

/// Длина friend code без префикса и разделителей (256 бит / 5 бит, вверх).
pub const FRIEND_CODE_CHARS: usize = 52;

/// Нормализация символа friend code: Crockford-алиасы (O→0, I/L→1) и
/// кириллические двойники латиницы (набор или копирование в русской
/// раскладке). Проверка алфавита — дальше.
fn normalize_code_char(c: char) -> char {
    match c {
        'А' | 'а' => 'A',
        'В' | 'в' => 'B',
        'Е' | 'е' => 'E',
        'К' | 'к' => 'K',
        'М' | 'м' => 'M',
        'Н' | 'н' => 'H',
        'О' | 'о' => '0',
        'Р' | 'р' => 'P',
        'С' | 'с' => 'C',
        'Т' | 'т' => 'T',
        'Х' | 'х' => 'X',
        _ => match c.to_ascii_uppercase() {
            'O' => '0',
            'I' | 'L' => '1',
            other => other,
        },
    }
}

/// Разбор friend code. Терпим к тому, что приходит из буфера обмена и
/// мессенджеров: регистр, пробелы, переводы строк, дефисы и любые другие
/// разделители (в т.ч. рамка TUI `│`), отсутствие префикса `TUN-`.
pub fn parse_friend_code(code: &str) -> Result<[u8; 32]> {
    let cleaned: String = code
        .chars()
        .map(normalize_code_char)
        .filter(|c| c.is_ascii_alphanumeric())
        .collect();
    // В алфавите Crockford нет «U», поэтому «TUN» в начале — всегда префикс.
    let body = cleaned.strip_prefix("TUN").unwrap_or(&cleaned);
    ensure!(
        body.len() == FRIEND_CODE_CHARS,
        "friend code: нужно {FRIEND_CODE_CHARS} символов после TUN-, получено {} — код скопирован не целиком?",
        body.len()
    );
    let mut acc: u64 = 0;
    let mut nbits = 0;
    let mut out = [0u8; 32];
    let mut oi = 0;
    for c in body.chars() {
        let v = B32
            .iter()
            .position(|b| *b as char == c)
            .ok_or_else(|| anyhow::anyhow!("неверный символ {c:?} в friend code"))? as u64;
        acc = (acc << 5) | v;
        nbits += 5;
        if nbits >= 8 && oi < 32 {
            nbits -= 8;
            out[oi] = (acc >> nbits) as u8;
            oi += 1;
        }
    }
    ensure!(oi == 32, "friend code неверной длины");
    Ok(out)
}

pub fn hex_of(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn hex_to_bytes(s: &str) -> Result<Vec<u8>> {
    let s = s.trim().to_lowercase();
    ensure!(s.len().is_multiple_of(2), "odd hex length");
    Ok((0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16))
        .collect::<std::result::Result<Vec<u8>, _>>()?)
}

// ---------- фреймы ----------

/// Собирает датаграмму с незашифрованным body (используется только для HELLO).
pub fn plain_frame(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(HDR_LEN + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(typ);
    out.extend_from_slice(&(body.len() as u16).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Разбирает общий заголовок. Возвращает (typ, body).
pub fn split_frame(datagram: &[u8]) -> Result<(u8, &[u8])> {    ensure!(datagram.len() >= HDR_LEN, "frame too short");
    ensure!(datagram[..4] == MAGIC, "bad magic");
    let typ = datagram[4];
    let len = u16::from_le_bytes([datagram[5], datagram[6]]) as usize;
    let body = &datagram[HDR_LEN..];
    ensure!(body.len() == len, "length mismatch");
    Ok((typ, body))
}

fn frame_header(typ: u8, body_len: usize) -> [u8; HDR_LEN] {
    let mut hdr = [0u8; HDR_LEN];
    hdr[..4].copy_from_slice(&MAGIC);
    hdr[4] = typ;
    let l = (body_len + NONCE_LEN + TAG_LEN) as u16;
    hdr[5] = l.to_le_bytes()[0];
    hdr[6] = l.to_le_bytes()[1];
    hdr
}

fn cipher(key: &SymKey) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(key.into())
}

// ---------- управляющие фреймы ----------

pub fn seal_ctrl(key: &SymKey, typ: u8, payload: &[u8]) -> Vec<u8> {
    let hdr = frame_header(typ, payload.len());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher(key)
        .encrypt(&Nonce::from(nonce), Payload { msg: payload, aad: &hdr })
        .expect("ctrl encrypt");
    let mut out = Vec::with_capacity(HDR_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

pub fn open_ctrl(key: &SymKey, typ: u8, body: &[u8]) -> Result<Vec<u8>> {
    ensure!(body.len() >= NONCE_LEN + TAG_LEN, "ctrl body too short");
    let (nonce, ct) = body.split_at(NONCE_LEN);
    cipher(key)
        .decrypt(&Nonce::try_from(nonce).map_err(|_| anyhow::anyhow!("bad nonce len"))?, Payload { msg: ct, aad: &frame_header(typ, ct.len() - TAG_LEN) })
        .map_err(|_| anyhow::anyhow!("ctrl decrypt failed"))
}

// ---------- фреймы группы ----------

/// Открытая часть заголовка группы: gid(4) | src_ip(4) | dst_ip(4).
pub const GRP_HDR_LEN: usize = 12;

pub fn parse_group_header(datagram: &[u8]) -> Result<(u32, u32, u32)> {
    let (_typ, body) = split_frame(datagram)?;
    ensure!(body.len() >= GRP_HDR_LEN, "group header too short");
    let gid = u32::from_be_bytes(body[..4].try_into().unwrap());
    let src = u32::from_be_bytes(body[4..8].try_into().unwrap());
    let dst = u32::from_be_bytes(body[8..12].try_into().unwrap());
    Ok((gid, src, dst))
}

pub fn seal_group(key: &SymKey, typ: u8, gid: u32, src: u32, dst: u32, payload: &[u8]) -> Vec<u8> {
    let mut aad = frame_header(typ, GRP_HDR_LEN + payload.len()).to_vec();
    aad.extend_from_slice(&gid.to_be_bytes());
    aad.extend_from_slice(&src.to_be_bytes());
    aad.extend_from_slice(&dst.to_be_bytes());
    let mut nonce = [0u8; NONCE_LEN];
    rand::rng().fill_bytes(&mut nonce);
    let ct = cipher(key)
        .encrypt(&Nonce::from(nonce), Payload { msg: payload, aad: &aad })
        .expect("group encrypt");
    let mut out = aad; // открытая часть: frame header + group header
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    out
}

/// Разбирает и расшифровывает фрейм группы. Возвращает (typ, gid, src, dst, payload).
pub fn open_group(key: &SymKey, datagram: &[u8]) -> Result<(u8, u32, u32, u32, Vec<u8>)> {
    let (typ, body) = split_frame(datagram)?;
    ensure!(body.len() >= GRP_HDR_LEN + NONCE_LEN + TAG_LEN, "group body too short");
    let (ghdr, rest) = body.split_at(GRP_HDR_LEN);
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let mut aad = frame_header(typ, ct.len() - TAG_LEN + GRP_HDR_LEN).to_vec();
    aad.extend_from_slice(ghdr);
    let pt = cipher(key)
        .decrypt(&Nonce::try_from(nonce).map_err(|_| anyhow::anyhow!("bad nonce len"))?, Payload { msg: ct, aad: &aad })
        .map_err(|_| anyhow::anyhow!("group decrypt failed"))?;
    let gid = u32::from_be_bytes(ghdr[..4].try_into().unwrap());
    let src = u32::from_be_bytes(ghdr[4..8].try_into().unwrap());
    let dst = u32::from_be_bytes(ghdr[8..12].try_into().unwrap());
    Ok((typ, gid, src, dst, pt))
}

// ---------- кодирование payload'ов (общие хелперы) ----------

/// Строка с префиксом длины (1 байт). Длиннее 255 байт — обрезается по
/// границе символа (раньше был assert, и длинное имя/статус кириллицей
/// — 2 байта на букву — роняло поток движка).
pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    let s = truncate_bytes(s, 255);
    buf.push(s.len() as u8);
    buf.extend_from_slice(s.as_bytes());
}

/// Префикс строки не длиннее `max` байт, не разрезая UTF-8 символ.
pub fn truncate_bytes(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

pub fn put_pub(buf: &mut Vec<u8>, p: &[u8; 32]) {
    buf.extend_from_slice(p);
}

pub fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_be_bytes());
}

pub fn put_bool(buf: &mut Vec<u8>, v: bool) {
    buf.push(v as u8);
}

pub struct Reader<'a> {
    pub b: &'a [u8],
    pub p: usize,
}

impl<'a> Reader<'a> {
    pub fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    pub fn u8(&mut self) -> Result<u8> {
        ensure!(self.p < self.b.len(), "truncated u8");
        let v = self.b[self.p];
        self.p += 1;
        Ok(v)
    }
    pub fn u32(&mut self) -> Result<u32> {
        ensure!(self.p + 4 <= self.b.len(), "truncated u32");
        let v = u32::from_be_bytes(self.b[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        Ok(v)
    }
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        ensure!(self.p + n <= self.b.len(), "truncated bytes");
        let r = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(r)
    }
    pub fn pub_key(&mut self) -> Result<[u8; 32]> {
        self.bytes(32)?.try_into().map_err(|_| anyhow::anyhow!("bad pubkey"))
    }
    pub fn str(&mut self) -> Result<String> {
        let n = self.u8()? as usize;
        Ok(String::from_utf8_lossy(self.bytes(n)?).into_owned())
    }
    pub fn boolean(&mut self) -> Result<bool> {
        Ok(self.u8()? != 0)
    }
    pub fn tail(&mut self) -> &'a [u8] {
        let r = &self.b[self.p.min(self.b.len())..];
        self.p = self.b.len();
        r
    }
}

/// IP-адреса — в network byte order (big-endian), как внутри IPv4-пакета.
pub fn ipv4_dst(packet: &[u8]) -> Result<u32> {
    ensure!(packet.len() >= 20, "packet too short");
    ensure!(packet[0] >> 4 == 4, "not ipv4");
    Ok(u32::from_be_bytes(packet[16..20].try_into().unwrap()))
}

pub fn ipv4_src(packet: &[u8]) -> Result<u32> {
    ensure!(packet.len() >= 20, "packet too short");
    ensure!(packet[0] >> 4 == 4, "not ipv4");
    Ok(u32::from_be_bytes(packet[12..16].try_into().unwrap()))
}

/// Группа по адресу 100.66.<gid>.<host>: октет №2 (индекс 2).
pub fn group_of_ip(ip: u32) -> u32 {
    (ip >> 8) & 0xFF
}

pub fn ip_str(ip: u32) -> String {
    std::net::Ipv4Addr::from(ip).to_string()
}

pub mod payloads;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_и_подписи() {
        let a = Identity::generate();
        let b = Identity::generate();
        // Friend code туда-обратно.
        let code = a.friend_code();
        assert_eq!(Identity::parse_friend_code(&code).unwrap(), a.ed_pub());
        // Подпись проверяется, чужая не проходит.
        let msg = b"hello";
        let sig = a.sign(msg);
        Identity::verify(&a.ed_pub(), msg, &sig).unwrap();
        assert!(Identity::verify(&b.ed_pub(), msg, &sig).is_err());
        // Симметричный общий ключ: обе стороны выводят одно и то же.
        assert_eq!(a.ctrl_key_with(&b.x_pub()), b.ctrl_key_with(&a.x_pub()));
    }

    #[test]
    fn friend_code_терпим_к_копированию() {
        let a = Identity::generate();
        let pk = a.ed_pub();
        let code = a.friend_code();
        assert_eq!(code.len(), 4 + FRIEND_CODE_CHARS + 6, "TUN- + 52 символа + 6 дефисов");
        // Перевод строки и пробелы из буфера обмена, нижний регистр.
        assert_eq!(parse_friend_code(&format!("  {code}\r\n")).unwrap(), pk);
        assert_eq!(parse_friend_code(&code.to_lowercase()).unwrap(), pk);
        // Без префикса и без дефисов.
        let bare: String = code[4..].chars().filter(|c| *c != '-').collect();
        assert_eq!(parse_friend_code(&bare).unwrap(), pk);
        // Рамка TUI и перенос посередине.
        let (l, r) = code.split_at(30);
        assert_eq!(parse_friend_code(&format!("│{l}\n{r}│")).unwrap(), pk);
        // Кириллические двойники латиницы в теле кода.
        let cyr: String = code
            .chars()
            .enumerate()
            .map(|(i, c)| match c {
                'A' if i > 3 => 'А',
                'B' if i > 3 => 'В',
                'E' if i > 3 => 'Е',
                'K' if i > 3 => 'К',
                'M' if i > 3 => 'М',
                'H' if i > 3 => 'Н',
                'P' if i > 3 => 'Р',
                'C' if i > 3 => 'С',
                'T' if i > 3 => 'Т',
                'X' if i > 3 => 'Х',
                other => other,
            })
            .collect();
        assert_eq!(parse_friend_code(&cyr).unwrap(), pk);
        // Обрезанный код — понятная ошибка с длиной.
        let err = parse_friend_code(&code[..40]).unwrap_err().to_string();
        assert!(err.contains("получено"), "{err}");
    }

    #[test]
    fn длинная_строка_обрезается_а_не_паникует() {
        let long = "ж".repeat(200); // 400 байт
        let mut buf = Vec::new();
        put_str(&mut buf, &long);
        assert_eq!(buf[0] as usize, buf.len() - 1);
        let mut r = Reader::new(&buf);
        assert_eq!(r.str().unwrap(), "ж".repeat(127));
    }

    #[test]
    fn шифрование_ctrl_и_group_туда_обратно() {
        let key = [42u8; 32];
        // Ctrl: шифруется/расшифровывается, чужой AAD/ключ не открывает.
        let frame = seal_ctrl(&key, ctrl::STATUS, b"payload");
        let (typ, body) = split_frame(&frame).unwrap();
        let p = open_ctrl(&key, typ, body).unwrap();
        assert_eq!(typ, ctrl::STATUS);
        assert_eq!(p, b"payload");
        let other = seal_ctrl(&[7u8; 32], ctrl::STATUS, b"x");
        let (typ2, body2) = split_frame(&other).unwrap();
        assert!(open_ctrl(&key, typ2, body2).is_err());
        // Tamper: битый ciphertext → ошибка.
        let mut tampered = frame.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        let (_, tb) = split_frame(&tampered).unwrap();
        assert!(open_ctrl(&key, ctrl::STATUS, tb).is_err());

        // Group: заголовок открытый, payload шифруется, tamper ловится.
        let g = seal_group(&key, 5, 7, 0x0A00_0002, 0x0A00_0003, b"data");
        let (gid, src, dst) = parse_group_header(&g).unwrap();
        assert_eq!((gid, src, dst), (7, 0x0A00_0002, 0x0A00_0003));
        let (t, g2, s2, d2, p) = open_group(&key, &g).unwrap();
        assert_eq!((t, g2, s2, d2), (5, 7, 0x0A00_0002, 0x0A00_0003));
        assert_eq!(p, b"data");
        let mut tg = g.clone();
        let last = tg.len() - 1;
        tg[last] ^= 1;
        assert!(open_group(&key, &tg).is_err());
    }
}
