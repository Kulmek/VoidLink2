//! Профили и перенос identity между машинами.
//!
//! Профиль — отдельный каталог данных клиента: `default_dir()/profiles/<имя>`
//! (`tunnel-client --profile <имя>`). Имя: `[A-Za-z0-9_-]{1,32}`.
//!
//! Экспорт identity — JSON-файл:
//! - открытый: `{version, friend_code, ed_seed, x_seed}` (seed'ы в hex);
//! - зашифрованный парольной фразой: `{version, friend_code, kdf, nonce, ciphertext}`,
//!   где `ciphertext = ChaCha20-Poly1305(ed_seed || x_seed, aad = friend_code)`,
//!   ключ выводится намеренно медленной KDF (итерированный keyed-hash blake3
//!   со случайной 16-байтной солью), параметры KDF лежат в файле.
//!
//! Импорт проверяет, что friend code совпадает с seed'ами, и не затирает
//! существующую identity без `force`. Здесь только чистые функции над путями
//! и байтами — CLI-обвязку делает интеграция.

#![allow(dead_code)] // подключается при интеграции

use anyhow::{Context, Result, anyhow, bail, ensure};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::Rng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use tunnel_protocol as proto;

use crate::store::{Config, StoredIdentity};

/// Версия формата файла экспорта.
pub const EXPORT_VERSION: u32 = 1;
/// Идентификатор KDF в файле.
pub const KDF_ALG: &str = "blake3-iter";
/// Итераций KDF при экспорте (2^18).
pub const KDF_ITERATIONS: u32 = 1 << 18;
/// Минимум итераций, принимаемый при импорте (защита от «облегчённых» файлов).
pub const KDF_MIN_ITERATIONS: u32 = 1 << 18;
/// Максимум итераций при импорте (чтобы файл не подвесил клиент).
pub const KDF_MAX_ITERATIONS: u32 = 1 << 26;
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const KDF_CONTEXT: &str = "VoidLink identity export v1 passphrase key";

// ---------------------------------------------------------------- профили

/// Проверка имени профиля: `[A-Za-z0-9_-]{1,32}`.
pub fn validate_profile_name(name: &str) -> Result<()> {
    ensure!(!name.is_empty(), "имя профиля пустое");
    ensure!(name.len() <= 32, "имя профиля длиннее 32 символов");
    ensure!(
        name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
        "имя профиля может содержать только латиницу, цифры, '_' и '-'"
    );
    Ok(())
}

/// Каталог профиля внутри базового каталога: `<base>/profiles/<name>`.
pub fn profile_dir_in(base: &Path, name: &str) -> Result<PathBuf> {
    validate_profile_name(name)?;
    Ok(base.join("profiles").join(name))
}

/// Каталог данных для `--profile`: без профиля — `default_dir()`,
/// иначе `default_dir()/profiles/<name>`.
pub fn resolve_dir(profile: Option<&str>) -> Result<PathBuf> {
    let base = crate::store::default_dir();
    match profile {
        None => Ok(base),
        Some(name) => profile_dir_in(&base, name),
    }
}

/// Список профилей (каталоги с корректными именами), по алфавиту.
/// Нет каталога `profiles` — пустой список.
pub fn list_profiles(base: &Path) -> Result<Vec<String>> {
    let dir = base.join("profiles");
    let rd = match std::fs::read_dir(&dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("чтение {}", dir.display())),
    };
    let mut out = Vec::new();
    for ent in rd {
        let ent = ent?;
        if !ent.file_type()?.is_dir() {
            continue;
        }
        if let Some(name) = ent.file_name().to_str()
            && validate_profile_name(name).is_ok()
        {
            out.push(name.to_string());
        }
    }
    out.sort();
    Ok(out)
}

// ---------------------------------------------------------------- формат файла

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KdfParams {
    pub alg: String,
    /// hex, 16 байт.
    pub salt: String,
    pub iterations: u32,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct ExportFile {
    version: u32,
    friend_code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ed_seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    x_seed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    kdf: Option<KdfParams>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ciphertext: Option<String>,
}

/// Ключ из парольной фразы: derive_key(контекст, соль || фраза), затем
/// `iterations` раз k = keyed_hash(k, соль || номер итерации).
pub fn derive_key(passphrase: &str, salt: &[u8], iterations: u32) -> [u8; 32] {
    let mut seed = Vec::with_capacity(salt.len() + passphrase.len());
    seed.extend_from_slice(salt);
    seed.extend_from_slice(passphrase.as_bytes());
    let mut k = blake3::derive_key(KDF_CONTEXT, &seed);
    let mut buf = [0u8; SALT_LEN + 4];
    buf[..SALT_LEN.min(salt.len())].copy_from_slice(&salt[..SALT_LEN.min(salt.len())]);
    for i in 0..iterations {
        buf[SALT_LEN..].copy_from_slice(&i.to_le_bytes());
        k = *blake3::keyed_hash(&k, &buf).as_bytes();
    }
    k
}

fn hex32(s: &str, what: &str) -> Result<[u8; 32]> {
    let v = proto::hex_to_bytes(s.trim()).with_context(|| format!("{what}: не hex"))?;
    v.try_into().map_err(|_| anyhow!("{what}: ожидалось 32 байта"))
}

fn identity_from_seeds(ed: [u8; 32], x: [u8; 32], friend_code: &str) -> Result<proto::Identity> {
    let id = proto::Identity { ed_seed: ed, x_seed: x };
    let claimed = proto::Identity::parse_friend_code(friend_code)
        .map_err(|e| anyhow!("некорректный friend code в файле: {e}"))?;
    ensure!(
        claimed == id.ed_pub(),
        "friend code в файле не соответствует ключам (файл повреждён или подменён)"
    );
    Ok(id)
}

/// Сериализует identity в JSON экспорта. С `passphrase` seed'ы шифруются.
pub fn export_identity(id: &proto::Identity, passphrase: Option<&str>) -> Result<Vec<u8>> {
    export_with_iterations(id, passphrase, KDF_ITERATIONS)
}

fn export_with_iterations(id: &proto::Identity, passphrase: Option<&str>, iterations: u32) -> Result<Vec<u8>> {
    let friend_code = id.friend_code();
    let file = match passphrase {
        None => ExportFile {
            version: EXPORT_VERSION,
            friend_code,
            ed_seed: Some(proto::hex_of(&id.ed_seed)),
            x_seed: Some(proto::hex_of(&id.x_seed)),
            kdf: None,
            nonce: None,
            ciphertext: None,
        },
        Some(pass) => {
            ensure!(!pass.is_empty(), "парольная фраза пустая");
            let mut salt = [0u8; SALT_LEN];
            let mut nonce = [0u8; NONCE_LEN];
            rand::rng().fill_bytes(&mut salt);
            rand::rng().fill_bytes(&mut nonce);
            let key = derive_key(pass, &salt, iterations);
            let mut plain = [0u8; 64];
            plain[..32].copy_from_slice(&id.ed_seed);
            plain[32..].copy_from_slice(&id.x_seed);
            let ct = ChaCha20Poly1305::new((&key).into())
                .encrypt(&Nonce::from(nonce), Payload { msg: &plain, aad: friend_code.as_bytes() })
                .map_err(|_| anyhow!("ошибка шифрования"))?;
            ExportFile {
                version: EXPORT_VERSION,
                friend_code,
                ed_seed: None,
                x_seed: None,
                kdf: Some(KdfParams { alg: KDF_ALG.into(), salt: proto::hex_of(&salt), iterations }),
                nonce: Some(proto::hex_of(&nonce)),
                ciphertext: Some(proto::hex_of(&ct)),
            }
        }
    };
    Ok(serde_json::to_vec_pretty(&file)?)
}

/// Зашифрован ли файл экспорта (нужна ли парольная фраза).
pub fn is_encrypted(data: &[u8]) -> Result<bool> {
    let f: ExportFile = serde_json::from_slice(data).context("файл экспорта: некорректный JSON")?;
    Ok(f.kdf.is_some() || f.ciphertext.is_some())
}

/// Разбирает и проверяет файл экспорта.
pub fn import_identity(data: &[u8], passphrase: Option<&str>) -> Result<proto::Identity> {
    import_with_min_iterations(data, passphrase, KDF_MIN_ITERATIONS)
}

fn import_with_min_iterations(data: &[u8], passphrase: Option<&str>, min_iter: u32) -> Result<proto::Identity> {
    let f: ExportFile = serde_json::from_slice(data).context("файл экспорта: некорректный JSON")?;
    ensure!(
        f.version == EXPORT_VERSION,
        "неподдерживаемая версия файла экспорта: {} (ожидалась {EXPORT_VERSION})",
        f.version
    );
    let encrypted = f.kdf.is_some() || f.nonce.is_some() || f.ciphertext.is_some();
    if !encrypted {
        let (Some(ed), Some(x)) = (&f.ed_seed, &f.x_seed) else {
            bail!("в файле экспорта нет ключей");
        };
        return identity_from_seeds(hex32(ed, "ed_seed")?, hex32(x, "x_seed")?, &f.friend_code);
    }
    ensure!(f.ed_seed.is_none() && f.x_seed.is_none(), "файл экспорта: открытые и зашифрованные ключи одновременно");
    let (Some(kdf), Some(nonce), Some(ct)) = (&f.kdf, &f.nonce, &f.ciphertext) else {
        bail!("файл экспорта: неполные поля шифрования");
    };
    let Some(pass) = passphrase else {
        bail!("файл зашифрован — укажите парольную фразу (--passphrase)");
    };
    ensure!(kdf.alg == KDF_ALG, "неподдерживаемая KDF: {}", kdf.alg);
    ensure!(
        (min_iter..=KDF_MAX_ITERATIONS).contains(&kdf.iterations),
        "недопустимое число итераций KDF: {}",
        kdf.iterations
    );
    let salt = proto::hex_to_bytes(&kdf.salt).context("соль KDF: не hex")?;
    ensure!(salt.len() == SALT_LEN, "соль KDF: ожидалось {SALT_LEN} байт");
    let nonce = proto::hex_to_bytes(nonce).context("nonce: не hex")?;
    let nonce = Nonce::try_from(nonce.as_slice()).map_err(|_| anyhow!("nonce: ожидалось {NONCE_LEN} байт"))?;
    let ct = proto::hex_to_bytes(ct).context("ciphertext: не hex")?;
    let key = derive_key(pass, &salt, kdf.iterations);
    let plain = ChaCha20Poly1305::new((&key).into())
        .decrypt(&nonce, Payload { msg: &ct, aad: f.friend_code.as_bytes() })
        .map_err(|_| anyhow!("неверная парольная фраза или файл повреждён"))?;
    ensure!(plain.len() == 64, "файл экспорта: неверная длина ключей");
    let ed: [u8; 32] = plain[..32].try_into().unwrap();
    let x: [u8; 32] = plain[32..].try_into().unwrap();
    identity_from_seeds(ed, x, &f.friend_code)
}

// ---------------------------------------------------------------- файлы и конфиг

/// Записывает экспорт identity в файл (через временный файл + rename).
pub fn export_to_file(path: &Path, id: &proto::Identity, passphrase: Option<&str>) -> Result<()> {
    let data = export_identity(id, passphrase)?;
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, &data).with_context(|| format!("запись {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("запись {}", path.display()))?;
    Ok(())
}

/// Читает и проверяет файл экспорта.
pub fn import_from_file(path: &Path, passphrase: Option<&str>) -> Result<proto::Identity> {
    let data = std::fs::read(path).with_context(|| format!("чтение {}", path.display()))?;
    import_identity(&data, passphrase)
}

/// Кладёт identity в конфиг. Если там уже другая identity — ошибка без `force`.
/// Та же самая identity — no-op. Возвращает true, если конфиг изменён.
pub fn apply_identity(cfg: &mut Config, id: &proto::Identity, force: bool) -> Result<bool> {
    let new = StoredIdentity { ed_seed: proto::hex_of(&id.ed_seed), x_seed: proto::hex_of(&id.x_seed) };
    if let Some(cur) = &cfg.identity {
        if cur.ed_seed.eq_ignore_ascii_case(&new.ed_seed) && cur.x_seed.eq_ignore_ascii_case(&new.x_seed) {
            return Ok(false);
        }
        ensure!(
            force,
            "в профиле уже есть другая identity — она будет потеряна; повторите с --force, если уверены"
        );
    }
    cfg.identity = Some(new);
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    // В тестах KDF облегчена, кроме одного теста с боевыми параметрами.
    const T_ITER: u32 = 64;

    fn imp(data: &[u8], pass: Option<&str>) -> Result<proto::Identity> {
        import_with_min_iterations(data, pass, 1)
    }

    fn same(a: &proto::Identity, b: &proto::Identity) -> bool {
        a.ed_seed == b.ed_seed && a.x_seed == b.x_seed
    }

    #[test]
    fn имя_профиля() {
        for ok in ["a", "work", "Home_2", "x-y", &"z".repeat(32)] {
            assert!(validate_profile_name(ok).is_ok(), "{ok}");
        }
        for bad in ["", &"z".repeat(33), "a b", "../x", "a/b", "a\\b", ".", "..", "имя", "a.b"] {
            assert!(validate_profile_name(bad).is_err(), "{bad}");
        }
        let base = Path::new("/base");
        assert_eq!(profile_dir_in(base, "work").unwrap(), base.join("profiles").join("work"));
        assert!(profile_dir_in(base, "..").is_err());
    }

    #[test]
    fn список_профилей() {
        let base = std::env::temp_dir().join(format!("vl-profiles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        assert!(list_profiles(&base).unwrap().is_empty());
        for n in ["work", "alpha", "bad name"] {
            std::fs::create_dir_all(base.join("profiles").join(n)).unwrap();
        }
        std::fs::write(base.join("profiles").join("file"), b"x").unwrap();
        assert_eq!(list_profiles(&base).unwrap(), vec!["alpha", "work"]);
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn открытый_экспорт_туда_обратно() {
        let id = proto::Identity::generate();
        let data = export_identity(&id, None).unwrap();
        assert!(!is_encrypted(&data).unwrap());
        let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(v["friend_code"], id.friend_code());
        assert_eq!(v["version"], EXPORT_VERSION);
        assert!(same(&import_identity(&data, None).unwrap(), &id));
        // Лишняя фраза для открытого файла не мешает.
        assert!(same(&import_identity(&data, Some("x")).unwrap(), &id));
    }

    #[test]
    fn зашифрованный_экспорт_туда_обратно() {
        let id = proto::Identity::generate();
        let data = export_with_iterations(&id, Some("пароль 123"), T_ITER).unwrap();
        assert!(is_encrypted(&data).unwrap());
        let text = String::from_utf8(data.clone()).unwrap();
        assert!(!text.contains(&proto::hex_of(&id.ed_seed)));
        assert!(!text.contains(&proto::hex_of(&id.x_seed)));
        assert!(same(&imp(&data, Some("пароль 123")).unwrap(), &id));
        let err = imp(&data, None).err().expect("ожидалась ошибка").to_string();
        assert!(err.contains("парольную фразу"), "{err}");
    }

    #[test]
    fn боевые_параметры_kdf() {
        let id = proto::Identity::generate();
        let data = export_identity(&id, Some("secret")).unwrap();
        let v: serde_json::Value = serde_json::from_slice(&data).unwrap();
        assert_eq!(v["kdf"]["iterations"], KDF_ITERATIONS);
        assert_eq!(v["kdf"]["alg"], KDF_ALG);
        assert_eq!(v["kdf"]["salt"].as_str().unwrap().len(), SALT_LEN * 2);
        assert!(same(&import_identity(&data, Some("secret")).unwrap(), &id));
        // Файл с заниженными итерациями боевой импорт не принимает.
        let weak = export_with_iterations(&id, Some("secret"), T_ITER).unwrap();
        assert!(import_identity(&weak, Some("secret")).err().expect("ожидалась ошибка").to_string().contains("итераций"));
    }

    #[test]
    fn неверная_фраза() {
        let id = proto::Identity::generate();
        let data = export_with_iterations(&id, Some("right"), T_ITER).unwrap();
        let err = imp(&data, Some("wrong")).err().expect("ожидалась ошибка").to_string();
        assert!(err.contains("неверная парольная фраза"), "{err}");
    }

    #[test]
    fn подмена_файла() {
        let id = proto::Identity::generate();
        let data = export_with_iterations(&id, Some("p"), T_ITER).unwrap();
        let mut v: serde_json::Value = serde_json::from_slice(&data).unwrap();

        // Испорченный шифртекст.
        let mut t = v.clone();
        let mut ct = t["ciphertext"].as_str().unwrap().to_string();
        let flip = if ct.starts_with('0') { "1" } else { "0" };
        ct.replace_range(0..1, flip);
        t["ciphertext"] = ct.into();
        assert!(imp(&serde_json::to_vec(&t).unwrap(), Some("p")).is_err());

        // Изменённая соль → другой ключ.
        let mut t = v.clone();
        t["kdf"]["salt"] = proto::hex_of(&[7u8; SALT_LEN]).into();
        assert!(imp(&serde_json::to_vec(&t).unwrap(), Some("p")).is_err());

        // Чужой friend code (aad) → AEAD не сходится.
        let other = proto::Identity::generate();
        v["friend_code"] = other.friend_code().into();
        assert!(imp(&serde_json::to_vec(&v).unwrap(), Some("p")).is_err());

        // Мусор и чужая версия.
        assert!(imp(b"not json", None).is_err());
        let mut plain: serde_json::Value = serde_json::from_slice(&export_identity(&id, None).unwrap()).unwrap();
        plain["version"] = 99.into();
        assert!(imp(&serde_json::to_vec(&plain).unwrap(), None).err().expect("ожидалась ошибка").to_string().contains("версия"));
    }

    #[test]
    fn friend_code_не_совпадает() {
        let id = proto::Identity::generate();
        let other = proto::Identity::generate();
        let mut v: serde_json::Value = serde_json::from_slice(&export_identity(&id, None).unwrap()).unwrap();
        v["friend_code"] = other.friend_code().into();
        let err = imp(&serde_json::to_vec(&v).unwrap(), None).err().expect("ожидалась ошибка").to_string();
        assert!(err.contains("не соответствует"), "{err}");
        // Подменённый seed при исходном коде — тоже ошибка.
        let mut v: serde_json::Value = serde_json::from_slice(&export_identity(&id, None).unwrap()).unwrap();
        v["ed_seed"] = proto::hex_of(&other.ed_seed).into();
        assert!(imp(&serde_json::to_vec(&v).unwrap(), None).is_err());
    }

    #[test]
    fn файл_и_перезапись_identity() {
        let id = proto::Identity::generate();
        let path = std::env::temp_dir().join(format!("vl-export-{}.json", std::process::id()));
        export_to_file(&path, &id, None).unwrap();
        let got = import_from_file(&path, None).unwrap();
        assert!(same(&got, &id));
        let _ = std::fs::remove_file(&path);

        let mut cfg = Config::default();
        assert!(apply_identity(&mut cfg, &got, false).unwrap());
        assert!(!apply_identity(&mut cfg, &got, false).unwrap());
        let other = proto::Identity::generate();
        assert!(apply_identity(&mut cfg, &other, false).expect_err("ожидалась ошибка").to_string().contains("--force"));
        assert!(same(&crate::store::ensure_identity(&mut cfg), &id));
        assert!(apply_identity(&mut cfg, &other, true).unwrap());
        assert!(same(&crate::store::ensure_identity(&mut cfg), &other));
    }
}
