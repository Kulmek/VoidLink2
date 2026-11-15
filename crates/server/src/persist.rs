//! Персистентность сервера: server.json (identity, группы, leases, бан-листы).

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Serialize, Deserialize, Default)]
pub struct Persisted {
    pub ed_seed: [u8; 32],
    pub x_seed: [u8; 32],
    pub next_gid: u32,
    pub groups: Vec<PGroup>,
}

#[derive(Serialize, Deserialize)]
pub struct PGroup {
    pub id: u32,
    pub name: String,
    pub owner: String, // hex pubkey
    #[serde(default)]
    pub private: bool,
    pub key: [u8; 32],
    /// (hex pubkey, ip)
    pub members: Vec<(String, u32)>,
    #[serde(default)]
    pub banned: Vec<String>,
    #[serde(default)]
    pub invites: Vec<String>,
}

pub struct Store {
    path: PathBuf,
}

impl Store {
    pub fn new(dir: &Path) -> Self {
        let _ = std::fs::create_dir_all(dir);
        Self { path: dir.join("server.json") }
    }

    pub fn load(&self) -> Option<Persisted> {
        let raw = std::fs::read(&self.path).ok()?;
        match serde_json::from_slice(&raw) {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("[server] не удалось прочитать {}: {e}", self.path.display());
                None
            }
        }
    }

    /// Атомарная запись: tmp + rename.
    pub fn save(&self, data: &Persisted) -> std::io::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(data)?;
        std::fs::write(&tmp, json)?;
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}
