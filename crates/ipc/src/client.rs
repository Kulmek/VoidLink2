//! Блокирующий клиент IPC для фронтендов (TUI, трей, CLI).
//!
//! `IpcClient::connect` — подключение, `Hello` и ожидание `Welcome` (или
//! `Reject`) с таймаутом. Чтение идёт в отдельном потоке: сообщения демона
//! кладутся в ограниченную очередь, поэтому таймауты работают одинаково на
//! Unix-сокете и named pipe (у пайпа нет `set_read_timeout`). Если фронтенд
//! не читает, очередь заполняется, поток чтения встаёт, и демон видит
//! медленного подписчика (пропуски, потом снимок) — сам демон не ждёт.
//!
//! `request` ждёт `Ack` своего `id`; всё остальное, что пришло за это время
//! (события, снимки), не теряется — его отдаст следующий `recv`.

use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::codec::{CodecError, read_msg, write_msg};
use crate::proto::{AckResult, ClientKind, ClientMsg, DaemonMsg};
use crate::transport::{self, Conn};

/// Сколько сообщений демона буферизует поток чтения.
pub const CLIENT_QUEUE: usize = 1024;

#[derive(Debug)]
pub enum ClientError {
    /// Не удалось подключиться (демона нет, нет прав, пайп не от SYSTEM…).
    Connect(io::Error),
    /// Демон отказал в `Hello` (версия протокола и т.п.).
    Rejected(String),
    /// Ответ не пришёл вовремя.
    Timeout,
    /// Демон завершается (`Shutdown`).
    Shutdown(String),
    /// Соединение закрыто или испорчено.
    Closed(Option<CodecError>),
    /// Демон прислал не то, что ожидалось.
    Protocol(String),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Connect(e) => write!(f, "демон недоступен: {e}"),
            ClientError::Rejected(r) => write!(f, "демон отказал: {r}"),
            ClientError::Timeout => write!(f, "демон не ответил вовремя"),
            ClientError::Shutdown(r) => write!(f, "демон завершается: {r}"),
            ClientError::Closed(None) => write!(f, "соединение с демоном закрыто"),
            ClientError::Closed(Some(e)) => write!(f, "соединение с демоном потеряно: {e}"),
            ClientError::Protocol(m) => write!(f, "ошибка протокола IPC: {m}"),
        }
    }
}

impl std::error::Error for ClientError {}

/// Подключение к демону.
pub struct IpcClient {
    wr: Conn,
    rx: Receiver<Result<DaemonMsg, CodecError>>,
    /// Сообщения, прочитанные во время ожидания `Ack`.
    pending: VecDeque<DaemonMsg>,
    /// Ошибка чтения уже получена — дальше только она.
    dead: bool,
    next_id: u64,
    me: Value,
    daemon_ver: String,
    reader: Option<JoinHandle<()>>,
}

impl IpcClient {
    /// Подключиться к `name` (путь сокета / имя пайпа), отправить `Hello`
    /// и дождаться `Welcome` не дольше `timeout`.
    #[cfg(unix)]
    pub fn connect(
        name: impl AsRef<std::path::Path>,
        kind: ClientKind,
        ver: &str,
        timeout: Duration,
    ) -> Result<IpcClient, ClientError> {
        let conn = transport::connect(name).map_err(ClientError::Connect)?;
        Self::handshake(conn, kind, ver, timeout)
    }

    /// Подключиться к `name` (путь сокета / имя пайпа), отправить `Hello`
    /// и дождаться `Welcome` не дольше `timeout`.
    #[cfg(windows)]
    pub fn connect(
        name: impl AsRef<std::ffi::OsStr>,
        kind: ClientKind,
        ver: &str,
        timeout: Duration,
    ) -> Result<IpcClient, ClientError> {
        let conn = transport::connect(name).map_err(ClientError::Connect)?;
        Self::handshake(conn, kind, ver, timeout)
    }

    /// `Hello` → `Welcome` поверх уже открытого соединения.
    pub fn handshake(conn: Conn, kind: ClientKind, ver: &str, timeout: Duration) -> Result<IpcClient, ClientError> {
        let mut rd = conn.try_clone().map_err(ClientError::Connect)?;
        let (tx, rx) = mpsc::sync_channel(CLIENT_QUEUE);
        let reader = std::thread::Builder::new()
            .name("ipc-client-read".into())
            .spawn(move || {
                loop {
                    let m = read_msg::<_, DaemonMsg>(&mut rd);
                    let end = m.is_err();
                    if tx.send(m).is_err() || end {
                        break;
                    }
                }
            })
            .map_err(ClientError::Connect)?;
        let mut c = IpcClient {
            wr: conn,
            rx,
            pending: VecDeque::new(),
            dead: false,
            next_id: 1,
            me: Value::Null,
            daemon_ver: String::new(),
            reader: Some(reader),
        };
        c.write(&ClientMsg::hello(kind, ver))?;
        match c.recv_raw(Some(timeout))? {
            DaemonMsg::Welcome { me, daemon_ver, .. } => {
                c.me = me;
                c.daemon_ver = daemon_ver;
                Ok(c)
            }
            DaemonMsg::Reject { reason } => Err(ClientError::Rejected(reason)),
            DaemonMsg::Shutdown { reason } => Err(ClientError::Shutdown(reason)),
            m => Err(ClientError::Protocol(format!("ждали Welcome, пришло {m:?}"))),
        }
    }

    /// `me` из `Welcome` (pubkey, friend code).
    pub fn me(&self) -> &Value {
        &self.me
    }

    pub fn daemon_ver(&self) -> &str {
        &self.daemon_ver
    }

    fn write(&mut self, m: &ClientMsg) -> Result<(), ClientError> {
        write_msg(&mut self.wr, m).map_err(|e| ClientError::Closed(Some(e)))
    }

    /// Подписаться на события и снимки. Первыми придут история событий и
    /// текущий снимок.
    pub fn subscribe(&mut self, snapshots_ms: u32) -> Result<(), ClientError> {
        self.write(&ClientMsg::Subscribe { snapshots_ms })
    }

    /// Отправить команду, не дожидаясь `Ack`; возвращает её `id`.
    pub fn send_req(&mut self, cmd: Value) -> Result<u64, ClientError> {
        let id = self.next_id;
        self.next_id += 1;
        self.write(&ClientMsg::Req { id, cmd })?;
        Ok(id)
    }

    /// Команда и ожидание её `Ack` не дольше `timeout`. Прочие сообщения,
    /// пришедшие за это время, остаются в очереди для [`IpcClient::recv`].
    pub fn request(&mut self, cmd: Value, timeout: Duration) -> Result<AckResult, ClientError> {
        let id = self.send_req(cmd)?;
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(ClientError::Timeout);
            }
            match self.recv_raw(Some(left))? {
                DaemonMsg::Ack { id: got, result } if got == id => return Ok(result),
                DaemonMsg::Shutdown { reason } => return Err(ClientError::Shutdown(reason)),
                m => self.pending.push_back(m),
            }
        }
    }

    /// Следующее сообщение демона; `None` в `timeout` — ждать сколько угодно.
    /// `Shutdown` отдаётся как сообщение (фронтенд сам решает, что показать).
    pub fn recv(&mut self, timeout: Option<Duration>) -> Result<DaemonMsg, ClientError> {
        if let Some(m) = self.pending.pop_front() {
            return Ok(m);
        }
        self.recv_raw(timeout)
    }

    /// Сообщение без ожидания (`Ok(None)` — пока ничего нет).
    pub fn try_recv(&mut self) -> Result<Option<DaemonMsg>, ClientError> {
        if let Some(m) = self.pending.pop_front() {
            return Ok(Some(m));
        }
        if self.dead {
            return Err(ClientError::Closed(None));
        }
        match self.rx.try_recv() {
            Ok(Ok(m)) => Ok(Some(m)),
            Ok(Err(e)) => {
                self.dead = true;
                Err(closed(e))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => {
                self.dead = true;
                Err(ClientError::Closed(None))
            }
        }
    }

    fn recv_raw(&mut self, timeout: Option<Duration>) -> Result<DaemonMsg, ClientError> {
        if self.dead {
            return Err(ClientError::Closed(None));
        }
        let r = match timeout {
            Some(t) => match self.rx.recv_timeout(t) {
                Ok(r) => r,
                Err(RecvTimeoutError::Timeout) => return Err(ClientError::Timeout),
                Err(RecvTimeoutError::Disconnected) => {
                    self.dead = true;
                    return Err(ClientError::Closed(None));
                }
            },
            None => match self.rx.recv() {
                Ok(r) => r,
                Err(_) => {
                    self.dead = true;
                    return Err(ClientError::Closed(None));
                }
            },
        };
        r.map_err(|e| {
            self.dead = true;
            closed(e)
        })
    }

    /// Вежливое закрытие: `Bye` и разрыв.
    pub fn bye(mut self) {
        let _ = self.write(&ClientMsg::Bye);
        // Остальное сделает Drop.
    }
}

fn closed(e: CodecError) -> ClientError {
    match e {
        CodecError::Closed => ClientError::Closed(None),
        e => ClientError::Closed(Some(e)),
    }
}

impl Drop for IpcClient {
    fn drop(&mut self) {
        // Поток чтения увидит EOF (или ошибку отправки в уже закрытую
        // очередь, когда `rx` уйдёт вслед за этим) и выйдет сам — не ждём.
        let _ = self.wr.shutdown();
        drop(self.reader.take());
    }
}
