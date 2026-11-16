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
    ChaCha20Poly1305, Key, Nonce,
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
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

    pub const WELCOME: u8 = 0x81;
    pub const GROUP_STATE: u8 = 0x82;
    pub const GROUP_LIST: u8 = 0x83;
    pub const GROUP_UPDATE: u8 = 0x84;
    pub const INVITE_RCVD: u8 = 0x85;
    pub const ERROR: u8 = 0x86;
    pub const CTRL_PONG: u8 = 0x8C;
    pub const FRIEND_GROUPS_RESP: u8 = 0x8D;
}

/// Типы фреймов внутри группы.
pub mod grp {
    /// IP-пакет: payload = сырой IPv4.
    pub const DATA: u8 = 0x21;
    /// RTT-зонд: payload = 8-байтовая метка времени отправителя.
    pub const PING: u8 = 0x22;
    /// Ответ: payload = та же метка.
    pub const PONG: u8 = 0x23;
    /// Пробивание NAT: без payload.
    pub const PUNCH: u8 = 0x24;
    /// Поддержание NAT-маппинга и liveness: без payload.
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
        rand::thread_rng().fill_bytes(&mut ed_seed);
        rand::thread_rng().fill_bytes(&mut x_seed);
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

pub fn parse_friend_code(code: &str) -> Result<[u8; 32]> {
    let cleaned: String = code
        .to_ascii_uppercase()
        .chars()
        .filter(|c| *c != '-' && *c != ' ')
        .collect();
    let body = cleaned
        .strip_prefix("TUN")
        .ok_or_else(|| anyhow::anyhow!("friend code должен начинаться с TUN"))?;
    ensure!(body.len() == 52, "friend code неверной длины");
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
        if nbits >= 8 {
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
    ChaCha20Poly1305::new(Key::from_slice(key))
}

// ---------- управляющие фреймы ----------

pub fn seal_ctrl(key: &SymKey, typ: u8, payload: &[u8]) -> Vec<u8> {
    let hdr = frame_header(typ, payload.len());
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher(key)
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: payload, aad: &hdr })
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
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &frame_header(typ, ct.len() - TAG_LEN) })
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
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher(key)
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: payload, aad: &aad })
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
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &aad })
        .map_err(|_| anyhow::anyhow!("group decrypt failed"))?;
    let gid = u32::from_be_bytes(ghdr[..4].try_into().unwrap());
    let src = u32::from_be_bytes(ghdr[4..8].try_into().unwrap());
    let dst = u32::from_be_bytes(ghdr[8..12].try_into().unwrap());
    Ok((typ, gid, src, dst, pt))
}

// ---------- кодирование payload'ов (общие хелперы) ----------

pub fn put_str(buf: &mut Vec<u8>, s: &str) {
    let b = s.as_bytes();
    assert!(b.len() < 256, "string too long");
    buf.push(b.len() as u8);
    buf.extend_from_slice(b);
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
