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

    /// `Ok(None)` — файла нет (первый запуск). Битый файл — ошибка: раньше
    /// сервер молча создавал новую identity и затирал файл, после чего все
    /// клиенты (они пиннят ключ сервера) переставали подключаться.
    pub fn load(&self) -> anyhow::Result<Option<Persisted>> {
        let raw = match std::fs::read(&self.path) {
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => anyhow::bail!("не прочитать {}: {e}", self.path.display()),
        };
        serde_json::from_slice(&raw).map(Some).map_err(|e| {
            anyhow::anyhow!(
                "{} повреждён ({e}); почини или убери файл (новая identity сервера = новый код для всех клиентов)",
                self.path.display()
            )
        })
    }

    /// Атомарная запись: tmp + rename.
    pub fn save(&self, data: &Persisted) -> std::io::Result<()> {
        let tmp = self.path.with_extension("json.tmp");
        let json = serde_json::to_vec_pretty(data)?;
        {
            use std::io::Write;
            let mut f = std::fs::File::create(&tmp)?;
            f.write_all(&json)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}
