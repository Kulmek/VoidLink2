//! Общий протокол туннеля: фреймы, шифрование, кодирование сообщений.
//!
//! Формат UDP-датаграммы (фрейма):
//! ```text
//! magic "TNL1" (4) | typ (1) | payload_len (2, LE) | payload
//! payload = nonce (12) || ChaCha20-Poly1305(payload, aad = header)
//! ```
//! Ключ шифрования выводится из ключа комнаты (blake3), поэтому сервер/клиенты
//! должны знать один и тот же ключ.

use anyhow::{ensure, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;

pub const MAGIC: [u8; 4] = *b"TNL1";
pub const HDR_LEN: usize = 4 + 1 + 2;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

/// Типы сообщений.
pub mod msg {
    /// Клиент -> сервер: вход в комнату (payload: room, name).
    pub const REG: u8 = 0x01;
    /// Сервер -> клиент: выдан виртуальный IP (payload: ip).
    pub const WELCOME: u8 = 0x81;
    /// Сервер -> клиент: состав комнаты (payload: [ip, endpoint, name]...).
    pub const ROSTER: u8 = 0x84;
    /// Пир -> пир (или через сервер-релей): IP-пакет (payload: dst_ip, packet).
    pub const DATA: u8 = 0x11;
    /// Пир -> пир: пробивание NAT (payload: sender_ip).
    pub const PUNCH: u8 = 0x10;
    /// Кто угодно -> кто угодно: keepalive (payload: sender_ip).
    pub const KEEPALIVE: u8 = 0x12;
}

pub type SymKey = [u8; 32];

/// Выводит симметричный ключ из ключа комнаты.
pub fn derive_key(room_key: &str) -> SymKey {
    let mut h = blake3::Hasher::new();
    h.update(b"tunnel/v1/room:");
    h.update(room_key.as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(h.finalize().as_bytes());
    out
}

fn cipher(key: &SymKey) -> ChaCha20Poly1305 {
    ChaCha20Poly1305::new(Key::from_slice(key))
}

/// Шифрует payload в полный фрейм (готовый UDP-датаграмма).
pub fn seal(key: &SymKey, typ: u8, payload: &[u8]) -> Vec<u8> {
    let hdr = header(typ, payload.len());
    let mut nonce_bytes = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce_bytes);
    let ct = cipher(key)
        .encrypt(
            Nonce::from_slice(&nonce_bytes),
            Payload { msg: payload, aad: &hdr },
        )
        .expect("chacha20poly1305 encrypt");
    let mut out = Vec::with_capacity(HDR_LEN + NONCE_LEN + ct.len());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&ct);
    out
}

/// Разбирает и расшифровывает фрейм. Возвращает (typ, payload).
pub fn open(key: &SymKey, datagram: &[u8]) -> Result<(u8, Vec<u8>)> {
    ensure!(datagram.len() >= HDR_LEN + NONCE_LEN + TAG_LEN, "frame too short");
    ensure!(&datagram[..4] == &MAGIC, "bad magic");
    let typ = datagram[4];
    let len = u16::from_le_bytes([datagram[5], datagram[6]]) as usize;
    let rest = &datagram[HDR_LEN..];
    ensure!(rest.len() == len, "length mismatch");
    let (nonce, ct) = rest.split_at(NONCE_LEN);
    let pt = cipher(key)
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &datagram[..HDR_LEN] })
        .map_err(|_| anyhow::anyhow!("decrypt failed"))?;
    Ok((typ, pt))
}

fn header(typ: u8, payload_len: usize) -> [u8; HDR_LEN] {
    let mut hdr = [0u8; HDR_LEN];
    hdr[..4].copy_from_slice(&MAGIC);
    hdr[4] = typ;
    let l = (payload_len + NONCE_LEN + TAG_LEN) as u16;
    hdr[5] = l.to_le_bytes()[0];
    hdr[6] = l.to_le_bytes()[1];
    hdr
}

// ---------- кодирование payload'ов ----------

fn put_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    assert!(b.len() < 256, "string too long");
    buf.push(b.len() as u8);
    buf.extend_from_slice(b);
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }
    fn u8(&mut self) -> Result<u8> {
        ensure!(self.p < self.b.len(), "truncated u8");
        let v = self.b[self.p];
        self.p += 1;
        Ok(v)
    }
    fn u32(&mut self) -> Result<u32> {
        ensure!(self.p + 4 <= self.b.len(), "truncated u32");
        let v = u32::from_be_bytes(self.b[self.p..self.p + 4].try_into().unwrap());
        self.p += 4;
        Ok(v)
    }
    fn str(&mut self) -> Result<String> {
        let n = self.u8()? as usize;
        ensure!(self.p + n <= self.b.len(), "truncated string");
        let s = String::from_utf8_lossy(&self.b[self.p..self.p + n]).into_owned();
        self.p += n;
        Ok(s)
    }
}

fn put_ip(buf: &mut Vec<u8>, ip: u32) {
    // IP-адреса везде в network byte order (как внутри IPv4-пакета).
    buf.extend_from_slice(&ip.to_be_bytes());
}

/// REG: room + name.
pub fn enc_reg(room: &str, name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_str(&mut v, room);
    put_str(&mut v, name);
    v
}

pub fn dec_reg(p: &[u8]) -> Result<(String, String)> {
    let mut r = Reader::new(p);
    let room = r.str()?;
    let name = r.str()?;
    Ok((room, name))
}

/// WELCOME: выданный виртуальный IP.
pub fn enc_welcome(ip: u32) -> Vec<u8> {
    let mut v = Vec::new();
    put_ip(&mut v, ip);
    v
}

pub fn dec_welcome(p: &[u8]) -> Result<u32> {
    Reader::new(p).u32()
}

/// Запись ростера: виртуальный IP + публичный endpoint + имя.
#[derive(Debug, Clone)]
pub struct RosterEntry {
    pub ip: u32,
    pub endpoint: String,
    pub name: String,
}

pub fn enc_roster(entries: &[RosterEntry]) -> Vec<u8> {
    let mut v = Vec::new();
    for e in entries {
        put_ip(&mut v, e.ip);
        put_str(&mut v, &e.endpoint);
        put_str(&mut v, &e.name);
    }
    v
}

pub fn dec_roster(p: &[u8]) -> Result<Vec<RosterEntry>> {
    let mut r = Reader::new(p);
    let mut out = Vec::new();
    while r.p < p.len() {
        let ip = r.u32()?;
        let endpoint = r.str()?;
        let name = r.str()?;
        out.push(RosterEntry { ip, endpoint, name });
    }
    Ok(out)
}

/// DATA: адресат + сырой IP-пакет.
pub fn enc_data(dst_ip: u32, packet: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(4 + packet.len());
    put_ip(&mut v, dst_ip);
    v.extend_from_slice(packet);
    v
}

pub fn dec_data(p: &[u8]) -> Result<(u32, &[u8])> {
    ensure!(p.len() >= 4, "data payload too short");
    let dst = u32::from_be_bytes(p[..4].try_into().unwrap());
    Ok((dst, &p[4..]))
}

/// PUNCH / KEEPALIVE: IP отправителя.
pub fn enc_sender_ip(ip: u32) -> Vec<u8> {
    let mut v = Vec::new();
    put_ip(&mut v, ip);
    v
}

pub fn dec_sender_ip(p: &[u8]) -> Result<u32> {
    Reader::new(p).u32()
}

/// Извлекает dst IP из сырого IPv4-пакета (байты 16..20).
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
