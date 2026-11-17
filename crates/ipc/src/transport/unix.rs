//! Unix: `UnixListener` / `UnixStream`, файл сокета с правами `0600`.
//!
//! Каталог сокета (каталог данных) должен быть `0700`: между `bind` и `chmod`
//! файл короткое время имеет права по umask.

use std::fs;
use std::io::{self, Read, Write};
use std::net::Shutdown;
use std::os::unix::fs::{FileTypeExt, MetadataExt, PermissionsExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Слушающий сокет демона. При drop удаляет свой файл сокета.
pub struct Listener {
    inner: UnixListener,
    path: PathBuf,
    /// (dev, ino) нашего файла — чтобы не удалить чужой сокет, созданный позже.
    id: (u64, u64),
}

impl Listener {
    /// Создаёт сокет по пути `name` с правами `0600`. Если файл уже есть —
    /// `AddrInUse`: устаревший сокет убирает [`cleanup_stale`] (под замком демона).
    pub fn bind(name: impl AsRef<Path>) -> io::Result<Listener> {
        let path = name.as_ref().to_path_buf();
        let inner = UnixListener::bind(&path)?;
        let setup = (|| {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
            let md = fs::symlink_metadata(&path)?;
            Ok::<_, io::Error>((md.dev(), md.ino()))
        })();
        match setup {
            Ok(id) => Ok(Listener { inner, path, id }),
            Err(e) => {
                let _ = fs::remove_file(&path);
                Err(e)
            }
        }
    }

    /// Ждёт следующего клиента.
    pub fn accept(&self) -> io::Result<Conn> {
        let (s, _) = self.inner.accept()?;
        Ok(Conn { inner: s })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        if let Ok(md) = fs::symlink_metadata(&self.path)
            && (md.dev(), md.ino()) == self.id
        {
            let _ = fs::remove_file(&self.path);
        }
    }
}

/// Удаляет устаревший файл сокета, к которому никто не слушает.
/// `Ok(true)` — удалён, `Ok(false)` — файла нет, `AddrInUse` — демон жив,
/// `InvalidInput` — по пути лежит не сокет (не трогаем).
/// Вызывать только под замком демона (`daemon.lock`), иначе гонка с живым стартом.
pub fn cleanup_stale(path: impl AsRef<Path>) -> io::Result<bool> {
    let path = path.as_ref();
    let md = match fs::symlink_metadata(path) {
        Ok(md) => md,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(false),
        Err(e) => return Err(e),
    };
    if !md.file_type().is_socket() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("{} — не сокет", path.display()),
        ));
    }
    match UnixStream::connect(path) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AddrInUse,
            "сокет занят работающим демоном",
        )),
        Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
            fs::remove_file(path)?;
            Ok(true)
        }
        Err(e) => Err(e),
    }
}

/// Подключается к сокету демона.
pub fn connect(name: impl AsRef<Path>) -> io::Result<Conn> {
    Ok(Conn {
        inner: UnixStream::connect(name)?,
    })
}

/// Соединение с пиром. `try_clone()` даёт вторую половину для другого потока.
pub struct Conn {
    inner: UnixStream,
}

impl Conn {
    pub fn try_clone(&self) -> io::Result<Conn> {
        Ok(Conn {
            inner: self.inner.try_clone()?,
        })
    }

    pub fn set_read_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.inner.set_read_timeout(t)
    }

    pub fn set_write_timeout(&self, t: Option<Duration>) -> io::Result<()> {
        self.inner.set_write_timeout(t)
    }

    /// Закрывает соединение в обе стороны (будит заблокированное чтение в клоне).
    pub fn shutdown(&self) -> io::Result<()> {
        self.inner.shutdown(Shutdown::Both)
    }
}

impl Read for Conn {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl Write for Conn {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}
