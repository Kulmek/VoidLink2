//! Кодеки payload'ов управляющих сообщений (клиент ↔ сервер).

use crate::{put_bool, put_pub, put_str, put_u32, Reader};
use anyhow::{ensure, Context, Result};

/// Информация об участнике группы (в GROUP_STATE / GROUP_UPDATE).
#[derive(Debug, Clone)]
pub struct MemberInfo {
    pub pubkey: [u8; 32],
    pub name: String,
    pub ip: u32,
    pub online: bool,
    pub status: String,
    /// Публичный UDP-endpoint (только для онлайн-пиров; для punch).
    pub endpoint: Option<String>,
}

fn put_member(buf: &mut Vec<u8>, m: &MemberInfo) {
    put_pub(buf, &m.pubkey);
    put_str(buf, &m.name);
    put_u32(buf, m.ip);
    put_bool(buf, m.online);
    put_str(buf, &m.status);
    match &m.endpoint {
        Some(e) => put_str(buf, e),
        None => put_str(buf, ""),
    }
}

fn read_member(r: &mut Reader) -> Result<MemberInfo> {
    Ok(MemberInfo {
        pubkey: r.pub_key()?,
        name: r.str()?,
        ip: r.u32()?,
        online: r.boolean()?,
        status: r.str()?,
        endpoint: {
            let s = r.str()?;
            if s.is_empty() { None } else { Some(s) }
        },
    })
}

// ---------- клиент -> сервер ----------

/// Байты, которые подписывает клиент (защита HELLO от подмены).
pub fn hello_sign_bytes(ed: &[u8; 32], x: &[u8; 32], name: &str, version: u8) -> Vec<u8> {
    let mut v = Vec::new();
    put_pub(&mut v, ed);
    put_pub(&mut v, x);
    put_str(&mut v, name);
    v.push(version);
    v
}

/// HELLO: ed25519 pubkey + x25519 pubkey + имя + подпись ed25519.
pub fn enc_hello(ed_pub: &[u8; 32], x_pub: &[u8; 32], name: &str, version: u8, sig: &[u8; 64]) -> Vec<u8> {
    let mut v = hello_sign_bytes(ed_pub, x_pub, name, version);
    v.extend_from_slice(sig);
    v
}

pub fn dec_hello(p: &[u8]) -> Result<([u8; 32], [u8; 32], String, u8)> {
    let mut r = Reader::new(p);
    let ed = r.pub_key()?;
    let x = r.pub_key()?;
    let name = r.str()?;
    let version = r.u8()?;
    let sig: [u8; 64] = r
        .bytes(64)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("bad signature length"))?;
    let msg = hello_sign_bytes(&ed, &x, &name, version);
    crate::Identity::verify(&ed, &msg, &sig).context("HELLO signature check")?;
    Ok((ed, x, name, version))
}

/// CREATE_GROUP: имя + приватность.
pub fn enc_create_group(name: &str, private: bool) -> Vec<u8> {
    let mut v = Vec::new();
    put_str(&mut v, name);
    put_bool(&mut v, private);
    v
}

pub fn dec_create_group(p: &[u8]) -> Result<(String, bool)> {
    let mut r = Reader::new(p);
    let name = r.str()?;
    let private = r.boolean()?;
    Ok((name, private))
}

/// JOIN / LEAVE / DELETE / LIST: только gid (для DELETE префиксной правки нет).
pub fn enc_gid(gid: u32) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, gid);
    v
}

pub fn dec_gid(p: &[u8]) -> Result<u32> {
    Reader::new(p).u32()
}

/// INVITE / KICK / BAN: gid + pubkey цели.
pub fn enc_gid_target(gid: u32, target: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, gid);
    put_pub(&mut v, target);
    v
}

pub fn dec_gid_target(p: &[u8]) -> Result<(u32, [u8; 32])> {
    let mut r = Reader::new(p);
    let gid = r.u32()?;
    let target = r.pub_key()?;
    Ok((gid, target))
}

/// RENAME: gid + имя.
pub fn enc_rename(gid: u32, name: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, gid);
    put_str(&mut v, name);
    v
}

pub fn dec_rename(p: &[u8]) -> Result<(u32, String)> {
    let mut r = Reader::new(p);
    let gid = r.u32()?;
    let name = r.str()?;
    Ok((gid, name))
}

/// STATUS: статус-текст.
pub fn enc_status(text: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_str(&mut v, text);
    v
}

pub fn dec_status(p: &[u8]) -> Result<String> {
    Reader::new(p).str()
}

/// FRIEND_GROUPS: pubkey друга.
pub fn enc_pubkey(pubkey: &[u8; 32]) -> Vec<u8> {
    let mut v = Vec::new();
    put_pub(&mut v, pubkey);
    v
}

pub fn dec_pubkey(p: &[u8]) -> Result<[u8; 32]> {
    Reader::new(p).pub_key()
}

// ---------- сервер -> клиент ----------

/// WELCOME (открытый текст): x_pub сервера + подпись ed25519 сервера.
/// Клиент проверяет подпись по pinned ed25519-ключу и выводит канальный ключ.
pub fn enc_welcome(x_pub: &[u8; 32], sig: &[u8; 64]) -> Vec<u8> {
    let mut v = Vec::with_capacity(96);
    v.extend_from_slice(x_pub);
    v.extend_from_slice(sig);
    v
}

pub fn dec_welcome(p: &[u8]) -> Result<([u8; 32], [u8; 64])> {
    ensure!(p.len() == 96, "bad welcome payload");
    Ok((
        p[..32].try_into().unwrap(),
        p[32..].try_into().unwrap(),
    ))
}

/// GROUP_STATE: полное состояние одной группы.
pub struct GroupState {
    pub gid: u32,
    pub name: String,
    pub owner: [u8; 32],
    pub private: bool,
    pub key: [u8; 32],
    pub deleted: bool,
    pub my_ip: u32,
    pub members: Vec<MemberInfo>,
}

pub fn enc_group_state(g: &GroupState) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, g.gid);
    put_str(&mut v, &g.name);
    put_pub(&mut v, &g.owner);
    put_bool(&mut v, g.private);
    v.extend_from_slice(&g.key);
    put_bool(&mut v, g.deleted);
    put_u32(&mut v, g.my_ip);
    put_u32(&mut v, g.members.len() as u32);
    for m in &g.members {
        put_member(&mut v, m);
    }
    v
}

pub fn dec_group_state(p: &[u8]) -> Result<GroupState> {
    let mut r = Reader::new(p);
    let gid = r.u32()?;
    let name = r.str()?;
    let owner = r.pub_key()?;
    let private = r.boolean()?;
    let key = r.bytes(32)?.try_into().unwrap();
    let deleted = r.boolean()?;
    let my_ip = r.u32()?;
    let n = r.u32()? as usize;
    let mut members = Vec::with_capacity(n.min(256));
    for _ in 0..n {
        members.push(read_member(&mut r)?);
    }
    Ok(GroupState { gid, name, owner, private, key, deleted, my_ip, members })
}

/// GROUP_LIST: сводка по группам (свои + публичные).
#[derive(Debug, Clone)]
pub struct GroupSummary {
    pub gid: u32,
    pub name: String,
    pub private: bool,
    pub mine: bool,
    pub online: u32,
    pub total: u32,
}

pub fn enc_group_list(items: &[GroupSummary]) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, items.len() as u32);
    for g in items {
        put_u32(&mut v, g.gid);
        put_str(&mut v, &g.name);
        put_bool(&mut v, g.private);
        put_bool(&mut v, g.mine);
        put_u32(&mut v, g.online);
        put_u32(&mut v, g.total);
    }
    v
}

pub fn dec_group_list(p: &[u8]) -> Result<Vec<GroupSummary>> {
    let mut r = Reader::new(p);
    let n = r.u32()? as usize;
    let mut out = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        out.push(GroupSummary {
            gid: r.u32()?,
            name: r.str()?,
            private: r.boolean()?,
            mine: r.boolean()?,
            online: r.u32()?,
            total: r.u32()?,
        });
    }
    Ok(out)
}

/// INVITE_RCVD: приглашение в группу.
#[derive(Debug, Clone)]
pub struct InviteInfo {
    pub gid: u32,
    pub group_name: String,
    pub from_pubkey: [u8; 32],
    pub from_name: String,
}

pub fn enc_invite(i: &InviteInfo) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, i.gid);
    put_str(&mut v, &i.group_name);
    put_pub(&mut v, &i.from_pubkey);
    put_str(&mut v, &i.from_name);
    v
}

pub fn dec_invite(p: &[u8]) -> Result<InviteInfo> {
    let mut r = Reader::new(p);
    Ok(InviteInfo {
        gid: r.u32()?,
        group_name: r.str()?,
        from_pubkey: r.pub_key()?,
        from_name: r.str()?,
    })
}

/// ERROR: текст ошибки.
pub fn enc_error(text: &str) -> Vec<u8> {
    let mut v = Vec::new();
    put_str(&mut v, text);
    v
}

pub fn dec_error(p: &[u8]) -> Result<String> {
    Reader::new(p).str()
}

/// FRIEND_GROUPS_RESP: группы друга (публичные + общие).
#[derive(Debug, Clone)]
pub struct FriendGroup {
    pub gid: u32,
    pub name: String,
    pub private: bool,
    pub shared: bool, // оба в группе
}

pub fn enc_friend_groups(items: &[FriendGroup]) -> Vec<u8> {
    let mut v = Vec::new();
    put_u32(&mut v, items.len() as u32);
    for g in items {
        put_u32(&mut v, g.gid);
        put_str(&mut v, &g.name);
        put_bool(&mut v, g.private);
        put_bool(&mut v, g.shared);
    }
    v
}

pub fn dec_friend_groups(p: &[u8]) -> Result<Vec<FriendGroup>> {
    let mut r = Reader::new(p);
    let n = r.u32()? as usize;
    let mut out = Vec::with_capacity(n.min(1024));
    for _ in 0..n {
        out.push(FriendGroup {
            gid: r.u32()?,
            name: r.str()?,
            private: r.boolean()?,
            shared: r.boolean()?,
        });
    }
    Ok(out)
}

/// RTT-зонд: 8-байтовая метка времени.
pub fn enc_ping(nonce: u64) -> Vec<u8> {
    nonce.to_be_bytes().to_vec()
}

pub fn dec_ping(p: &[u8]) -> Result<u64> {
    ensure!(p.len() == 8, "bad ping payload");
    Ok(u64::from_be_bytes(p.try_into().unwrap()))
}
