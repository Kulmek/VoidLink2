//! TCP-фолбэк транспорт для сетей, где режут UDP.
//!
//! По TCP ходят те же самые датаграммы «TNL2», что и по UDP, только каждая
//! обёрнута в рамку: `u16 LE длина` + `кадр`. Нулевая длина или длина больше
//! `max_frame` — нарушение протокола, соединение закрывается.
//!
//! Устройство:
//! - поток accept принимает соединения и проверяет лимиты (всего / на IP);
//! - на каждое соединение — поток-читатель (разбирает рамки и отдаёт кадры
//!   обработчику `handler(addr, frame)`) и поток-писатель с ограниченной
//!   очередью: `send` не блокируется, при переполнении кадр отбрасывается
//!   (как потерянная UDP-датаграмма);
//! - соединение без входящих данных дольше `idle_timeout` закрывается;
//! - при закрытии соединение убирается из реестра, писатель завершается.
//!
//! Адрес клиента (`SocketAddr` TCP-соединения) играет роль UDP-адреса: сервер
//! отвечает через `TcpSender::send(addr, ..)`, если `is_tcp(addr)`.

#![allow(dead_code)] // подключается при интеграции

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

/// Обработчик входящего кадра: адрес TCP-соединения и сам кадр (без рамки).
pub type FrameHandler = Arc<dyn Fn(SocketAddr, &[u8]) + Send + Sync>;

/// Максимальный размер кадра по умолчанию (UDP-датаграммы туннеля заметно меньше).
pub const DEFAULT_MAX_FRAME: usize = 4096;

/// Таймаут записи: «зависший» клиент не держит писателя вечно.
const WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Лимиты TCP-транспорта.
#[derive(Clone, Debug)]
pub struct TcpLimits {
    /// Максимум одновременных соединений.
    pub max_conns: usize,
    /// Максимум одновременных соединений с одного IP.
    pub max_per_ip: usize,
    /// Соединение без входящих данных столько времени закрывается.
    pub idle_timeout: Duration,
    /// Максимальная длина кадра (не больше u16::MAX).
    pub max_frame: usize,
    /// Длина очереди исходящих кадров на соединение.
    pub queue_len: usize,
}

impl Default for TcpLimits {
    fn default() -> Self {
        TcpLimits {
            max_conns: 1024,
            max_per_ip: 8,
            // Клиент пингует раз в 5 с — как SESSION_TIMEOUT у UDP-сессий.
            idle_timeout: Duration::from_secs(30),
            max_frame: DEFAULT_MAX_FRAME,
            queue_len: 256,
        }
    }
}

struct Conn {
    id: u64,
    tx: SyncSender<Vec<u8>>,
    /// Клон сокета — чтобы закрыть соединение снаружи (shutdown будит читателя).
    stream: TcpStream,
}

#[derive(Default)]
struct Registry {
    conns: Mutex<HashMap<SocketAddr, Conn>>,
    next_id: AtomicU64,
}

/// Отправитель кадров по TCP-соединениям; дёшево клонируется.
#[derive(Clone)]
pub struct TcpSender {
    reg: Arc<Registry>,
    max_frame: usize,
}

impl TcpSender {
    /// Поставить кадр в очередь соединения `addr`. Не блокируется:
    /// `false` — соединения нет, кадр некорректного размера или очередь полна.
    pub fn send(&self, addr: SocketAddr, frame: &[u8]) -> bool {
        if frame.is_empty() || frame.len() > self.max_frame {
            return false;
        }
        let conns = self.reg.conns.lock().unwrap();
        let Some(c) = conns.get(&addr) else {
            return false;
        };
        match c.tx.try_send(frame.to_vec()) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) | Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Это адрес живого TCP-соединения?
    pub fn is_tcp(&self, addr: SocketAddr) -> bool {
        self.reg.conns.lock().unwrap().contains_key(&addr)
    }

    /// Закрыть соединение (например, при kick/ban).
    pub fn close(&self, addr: SocketAddr) {
        if let Some(c) = self.reg.conns.lock().unwrap().remove(&addr) {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
    }

    /// Число живых соединений.
    pub fn conn_count(&self) -> usize {
        self.reg.conns.lock().unwrap().len()
    }

    fn close_all(&self) {
        let drained: Vec<Conn> = self.reg.conns.lock().unwrap().drain().map(|(_, c)| c).collect();
        for c in drained {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
    }
}

/// Запущенный TCP-транспорт. При `stop()` / drop закрывает слушатель и все соединения.
pub struct TcpTransport {
    local_addr: SocketAddr,
    sender: TcpSender,
    stop: Arc<AtomicBool>,
    accept: Option<JoinHandle<()>>,
}

impl TcpTransport {
    /// Слушать `listen`, отдавать входящие кадры в `handler`.
    pub fn start(listen: SocketAddr, handler: FrameHandler, limits: TcpLimits) -> io::Result<Self> {
        let listener = TcpListener::bind(listen)?;
        let local_addr = listener.local_addr()?;
        let mut limits = limits;
        limits.max_frame = limits.max_frame.clamp(1, u16::MAX as usize);
        limits.queue_len = limits.queue_len.max(1);
        let sender = TcpSender {
            reg: Arc::new(Registry::default()),
            max_frame: limits.max_frame,
        };
        let stop = Arc::new(AtomicBool::new(false));
        let accept = {
            let sender = sender.clone();
            let stop = stop.clone();
            thread::Builder::new()
                .name("tcp-accept".into())
                .spawn(move || accept_loop(listener, sender, handler, limits, stop))?
        };
        Ok(TcpTransport {
            local_addr,
            sender,
            stop,
            accept: Some(accept),
        })
    }

    /// Фактический адрес слушателя (полезно при порте 0).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Отправитель для ответов клиентам.
    pub fn sender(&self) -> TcpSender {
        self.sender.clone()
    }

    /// Остановить приём и закрыть все соединения.
    pub fn stop(&mut self) {
        if self.stop.swap(true, Ordering::SeqCst) {
            return;
        }
        // Будим блокирующий accept подключением к самим себе.
        let mut wake = self.local_addr;
        if wake.ip().is_unspecified() {
            wake.set_ip(match wake.ip() {
                IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
            });
        }
        let _ = TcpStream::connect_timeout(&wake, Duration::from_secs(1));
        if let Some(h) = self.accept.take() {
            let _ = h.join();
        }
        self.sender.close_all();
    }
}

impl Drop for TcpTransport {
    fn drop(&mut self) {
        self.stop();
    }
}

fn accept_loop(
    listener: TcpListener,
    sender: TcpSender,
    handler: FrameHandler,
    limits: TcpLimits,
    stop: Arc<AtomicBool>,
) {
    for stream in listener.incoming() {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        let Ok(stream) = stream else {
            // Например, EMFILE: не крутим цикл вхолостую.
            thread::sleep(Duration::from_millis(10));
            continue;
        };
        let Ok(peer) = stream.peer_addr() else { continue };
        if let Err(e) = admit(stream, peer, &sender, &handler, &limits) {
            let _ = e; // превышение лимитов и ошибки сокета — молча
        }
    }
}

/// Проверить лимиты, зарегистрировать соединение и запустить его потоки.
fn admit(
    stream: TcpStream,
    peer: SocketAddr,
    sender: &TcpSender,
    handler: &FrameHandler,
    limits: &TcpLimits,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_read_timeout(Some(limits.idle_timeout))?;
    stream.set_write_timeout(Some(WRITE_TIMEOUT))?;
    let reader_stream = stream.try_clone()?;
    let writer_stream = stream.try_clone()?;
    let (tx, rx) = mpsc::sync_channel::<Vec<u8>>(limits.queue_len);
    let reg = &sender.reg;
    let id = reg.next_id.fetch_add(1, Ordering::Relaxed);
    {
        let mut conns = reg.conns.lock().unwrap();
        let per_ip = conns.keys().filter(|a| a.ip() == peer.ip()).count();
        if conns.len() >= limits.max_conns || per_ip >= limits.max_per_ip {
            let _ = stream.shutdown(Shutdown::Both);
            return Err(io::Error::other("лимит соединений"));
        }
        conns.insert(peer, Conn { id, tx, stream });
    }

    thread::Builder::new()
        .name("tcp-writer".into())
        .spawn(move || writer_loop(writer_stream, rx))?;

    let reg = sender.reg.clone();
    let handler = handler.clone();
    let max_frame = limits.max_frame;
    thread::Builder::new().name("tcp-reader".into()).spawn(move || {
        reader_loop(reader_stream, peer, max_frame, &handler);
        // Закрытие: убираем из реестра только «своё» соединение (адрес мог
        // уже переиспользоваться новым) и закрываем сокет — писатель выйдет,
        // когда отправитель очереди будет сброшен вместе с записью реестра.
        let mut conns = reg.conns.lock().unwrap();
        if conns.get(&peer).is_some_and(|c| c.id == id)
            && let Some(c) = conns.remove(&peer)
        {
            let _ = c.stream.shutdown(Shutdown::Both);
        }
    })?;
    Ok(())
}

/// Читать рамки до ошибки, таймаута простоя или нарушения формата.
fn reader_loop(mut s: TcpStream, peer: SocketAddr, max_frame: usize, handler: &FrameHandler) {
    let mut buf = vec![0u8; max_frame];
    loop {
        let mut hdr = [0u8; 2];
        if s.read_exact(&mut hdr).is_err() {
            break; // EOF, таймаут простоя или ошибка
        }
        let len = u16::from_le_bytes(hdr) as usize;
        if len == 0 || len > max_frame {
            break; // нарушение протокола
        }
        if s.read_exact(&mut buf[..len]).is_err() {
            break;
        }
        handler(peer, &buf[..len]);
    }
    let _ = s.shutdown(Shutdown::Both);
}

fn writer_loop(mut s: TcpStream, rx: Receiver<Vec<u8>>) {
    let mut out = Vec::with_capacity(2 + DEFAULT_MAX_FRAME);
    while let Ok(frame) = rx.recv() {
        out.clear();
        out.extend_from_slice(&(frame.len() as u16).to_le_bytes());
        out.extend_from_slice(&frame);
        if s.write_all(&out).is_err() {
            let _ = s.shutdown(Shutdown::Both);
            break;
        }
    }
}

/// Обернуть кадр в рамку (для клиентов и тестов).
pub fn encode_frame(frame: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(2 + frame.len());
    out.extend_from_slice(&(frame.len() as u16).to_le_bytes());
    out.extend_from_slice(frame);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// Обработчик, складывающий кадры в канал.
    fn collector() -> (FrameHandler, Receiver<(SocketAddr, Vec<u8>)>) {
        let (tx, rx) = mpsc::channel();
        let tx = Mutex::new(tx);
        let h: FrameHandler = Arc::new(move |a, f: &[u8]| {
            let _ = tx.lock().unwrap().send((a, f.to_vec()));
        });
        (h, rx)
    }

    fn read_frame(s: &mut TcpStream) -> io::Result<Vec<u8>> {
        let mut hdr = [0u8; 2];
        s.read_exact(&mut hdr)?;
        let mut body = vec![0u8; u16::from_le_bytes(hdr) as usize];
        s.read_exact(&mut body)?;
        Ok(body)
    }

    /// Сервер закрыл соединение: чтение вернёт EOF или ошибку.
    fn is_closed(s: &mut TcpStream) -> bool {
        s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        let mut b = [0u8; 1];
        matches!(s.read(&mut b), Ok(0) | Err(_))
    }

    fn wait_until(mut f: impl FnMut() -> bool) -> bool {
        let t = Instant::now();
        while t.elapsed() < Duration::from_secs(3) {
            if f() {
                return true;
            }
            thread::sleep(Duration::from_millis(10));
        }
        false
    }

    #[test]
    fn frames_both_ways() {
        let (h, rx) = collector();
        let t = TcpTransport::start(loopback(), h, TcpLimits::default()).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        c.write_all(&encode_frame(b"TNL2 hello")).unwrap();
        // Две рамки одним write — разбор не должен зависеть от границ TCP.
        let mut two = encode_frame(b"one");
        two.extend(encode_frame(b"two"));
        c.write_all(&two).unwrap();

        let (addr, f) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(addr, c.local_addr().unwrap());
        assert_eq!(f, b"TNL2 hello");
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap().1, b"one");
        assert_eq!(rx.recv_timeout(Duration::from_secs(3)).unwrap().1, b"two");

        let s = t.sender();
        assert!(s.is_tcp(addr));
        assert!(s.send(addr, b"reply"));
        assert!(!s.send(addr, b""), "пустой кадр не отправляется");
        assert!(!s.send("127.0.0.1:1".parse().unwrap(), b"x"));
        c.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        assert_eq!(read_frame(&mut c).unwrap(), b"reply");

        drop(c);
        assert!(wait_until(|| !s.is_tcp(addr)), "закрытое соединение убрано из реестра");
    }

    #[test]
    fn zero_length_closes() {
        let (h, _rx) = collector();
        let t = TcpTransport::start(loopback(), h, TcpLimits::default()).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        c.write_all(&[0, 0]).unwrap();
        assert!(is_closed(&mut c));
        assert!(wait_until(|| t.sender().conn_count() == 0));
    }

    #[test]
    fn oversize_closes() {
        let (h, rx) = collector();
        let limits = TcpLimits {
            max_frame: 100,
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        c.write_all(&101u16.to_le_bytes()).unwrap();
        assert!(is_closed(&mut c));
        assert!(rx.try_recv().is_err());
        assert!(!t.sender().send(c.local_addr().unwrap(), &[1u8; 101]));
    }

    #[test]
    fn limits_enforced() {
        let (h, _rx) = collector();
        let limits = TcpLimits {
            max_conns: 3,
            max_per_ip: 2,
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let s = t.sender();
        let _a = TcpStream::connect(t.local_addr()).unwrap();
        let _b = TcpStream::connect(t.local_addr()).unwrap();
        assert!(wait_until(|| s.conn_count() == 2));
        // Третье с того же IP — сверх max_per_ip.
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        assert!(is_closed(&mut c));
        assert_eq!(s.conn_count(), 2);
    }

    #[test]
    fn max_conns_enforced() {
        let (h, _rx) = collector();
        let limits = TcpLimits {
            max_conns: 2,
            max_per_ip: 10,
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let s = t.sender();
        let _a = TcpStream::connect(t.local_addr()).unwrap();
        let _b = TcpStream::connect(t.local_addr()).unwrap();
        assert!(wait_until(|| s.conn_count() == 2));
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        assert!(is_closed(&mut c));
        assert_eq!(s.conn_count(), 2);
        // Освободили слот — новое соединение проходит.
        drop(_a);
        assert!(wait_until(|| s.conn_count() == 1));
        let _d = TcpStream::connect(t.local_addr()).unwrap();
        assert!(wait_until(|| s.conn_count() == 2));
    }

    #[test]
    fn idle_timeout_closes() {
        let (h, rx) = collector();
        let limits = TcpLimits {
            idle_timeout: Duration::from_millis(300),
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        // Активность продлевает жизнь соединения.
        for _ in 0..3 {
            thread::sleep(Duration::from_millis(150));
            c.write_all(&encode_frame(b"ping")).unwrap();
        }
        for _ in 0..3 {
            rx.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        assert_eq!(t.sender().conn_count(), 1);
        let started = Instant::now();
        assert!(is_closed(&mut c));
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(wait_until(|| t.sender().conn_count() == 0));
    }

    #[test]
    fn queue_overflow_drops() {
        let (h, rx) = collector();
        let limits = TcpLimits {
            queue_len: 4,
            ..TcpLimits::default()
        };
        let t = TcpTransport::start(loopback(), h, limits).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        c.write_all(&encode_frame(b"hi")).unwrap();
        let (addr, _) = rx.recv_timeout(Duration::from_secs(3)).unwrap();
        // Клиент не читает: буферы сокета заполнятся, затем очередь — и send
        // начнёт возвращать false, не блокируясь.
        let s = t.sender();
        let big = vec![7u8; DEFAULT_MAX_FRAME];
        let started = Instant::now();
        let mut dropped = false;
        for _ in 0..100_000 {
            if !s.send(addr, &big) {
                dropped = true;
                break;
            }
        }
        assert!(dropped, "переполнение очереди должно отбрасывать кадры");
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn stop_closes_everything() {
        let (h, _rx) = collector();
        let mut t = TcpTransport::start(loopback(), h, TcpLimits::default()).unwrap();
        let mut c = TcpStream::connect(t.local_addr()).unwrap();
        let s = t.sender();
        assert!(wait_until(|| s.conn_count() == 1));
        t.stop();
        assert!(is_closed(&mut c));
        assert_eq!(s.conn_count(), 0);
        assert!(TcpStream::connect_timeout(&t.local_addr(), Duration::from_millis(300)).is_err());
    }
}
