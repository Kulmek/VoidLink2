//! Локальное хранилище клиента: identity, друзья, серверы, настройки.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tunnel_protocol as proto;

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct Config {
    #[serde(default)]
    pub identity: Option<StoredIdentity>,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub servers: Vec<StoredServer>,
    #[serde(default)]
    pub friends: Vec<StoredFriend>,
    /// Группы, к которым подключаемся автоматически при старте `run`.
    #[serde(default)]
    pub autojoin: Vec<u32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StoredIdentity {
    pub ed_seed: String, // hex
    pub x_seed: String,  // hex
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredServer {
    pub addr: String,
    /// hex ed25519 pubkey сервера (пиннинг identity).
    pub pubkey: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct StoredFriend {
    pub pubkey: String, // hex
    pub alias: String,
}

pub struct Store {
    path: PathBuf,
}

/// Каталог по умолчанию: %APPDATA%\tunnel (Windows), иначе ./tunnel-client-data.
pub fn default_dir() -> PathBuf {
    if let Ok(appdata) = std::env::var("APPDATA") {
        return Path::new(&appdata).join("tunnel");
    }
    if let Ok(home) = std::env::var("HOME") {
        return Path::new(&home).join(".tunnel-client");
    }
    PathBuf::from("tunnel-client-data")
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(dir);
        Self { path: dir.join("client.json") }
    }

    pub fn load(&self) -> Result<Config> {
        match std::fs::read(&self.path) {
            Ok(raw) => Ok(serde_json::from_slice(&raw).context("client.json parse")?),
            Err(_) => Ok(Config::default()),
        }
    }

    pub fn save(&self, cfg: &Config) -> Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(cfg)?)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

/// Инициализация identity: загрузка из конфига или генерация новой.
pub fn ensure_identity(cfg: &mut Config) -> proto::Identity {
    if let Some(si) = &cfg.identity {
        if let (Ok(ed), Ok(x)) = (proto::hex_to_bytes(&si.ed_seed), proto::hex_to_bytes(&si.x_seed)) {
            if ed.len() == 32 && x.len() == 32 {
                let mut edb = [0u8; 32];
                let mut xb = [0u8; 32];
                edb.copy_from_slice(&ed);
                xb.copy_from_slice(&x);
                return proto::Identity { ed_seed: edb, x_seed: xb };
            }
        }
    }
    let id = proto::Identity::generate();
    cfg.identity = Some(StoredIdentity {
        ed_seed: proto::hex_of(&id.ed_seed),
        x_seed: proto::hex_of(&id.x_seed),
    });
    id
}

/// Токен пира → pubkey: friend code, hex или alias из списка друзей.
pub fn resolve_peer(cfg: &Config, token: &str) -> Result<[u8; 32]> {
    if let Ok(pk) = proto::Identity::parse_friend_code(token) {
        return Ok(pk);
    }
    let t = token.trim().to_lowercase();
    if let Ok(v) = proto::hex_to_bytes(&t) {
        if v.len() == 32 {
            return Ok(v.try_into().unwrap());
        }
    }
    if let Some(f) = cfg.friends.iter().find(|f| f.alias.to_lowercase() == t) {
        let v = proto::hex_to_bytes(&f.pubkey)?;
        anyhow::ensure!(v.len() == 32, "bad stored pubkey");
        return Ok(v.try_into().unwrap());
    }
    anyhow::bail!("не найден peer по токену {token:?} (ни friend code, ни hex, ни alias)")
}
