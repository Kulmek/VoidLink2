//! Хаб событий демона (PLAN.md 7.3).
//!
//! Хаб владеет бэкендом (движком) и раздаёт его события подписчикам
//! (фронтендам). Правила:
//! - каждое событие получает монотонный `seq` (с 1, без повторов);
//! - очередь на подписчика ограничена; переполнение — событие этому
//!   подписчику не доставляется (он видит дырку в `seq` и ждёт снимок),
//!   остальные подписчики и движок не ждут медленного;
//! - снимок рассылается раз в [`SNAPSHOT_EVERY`] и сразу после изменений
//!   (`Backend::changed`); подписчику, у которого был пропуск, снимок
//!   досылается на ближайшем такте, пока не влезет в очередь;
//! - кольцо последних [`RING_CAP`] событий — новый подписчик сразу получает
//!   историю лога и текущий снимок вне очереди (в [`Subscription`]).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::Value;

/// Сколько последних событий хранит кольцо для новых подписчиков.
pub const RING_CAP: usize = 500;
/// Период рассылки снимков без изменений.
pub const SNAPSHOT_EVERY: Duration = Duration::from_secs(1);
/// Очередь подписчика по умолчанию.
pub const DEFAULT_QUEUE: usize = 256;
/// Такт цикла хаба в [`Hub::run`].
pub const TICK: Duration = Duration::from_millis(50);

/// То, что демон знает о движке. Интеграция реализует его для
/// `tunnel-engine` (JSON — сериализованные `Snapshot`/`Event`/`Cmd`/`Me`).
pub trait Backend: Send + Sync {
    /// Текущий снимок состояния.
    fn snapshot(&self) -> Value;
    /// Накопившиеся события, без блокировки.
    fn poll_events(&self) -> Vec<Value>;
    /// Команда движку; `Err` — команда отклонена (уйдёт клиенту в `Ack`).
    fn send(&self, cmd: Value) -> Result<(), String>;
    /// Мой pubkey / friend code (для `Welcome`).
    fn me(&self) -> Value;
    /// Состояние изменилось с прошлого вызова (флаг сбрасывается).
    fn changed(&self) -> bool;
}

/// Сообщение подписчику. `seq` снимка — номер последнего события, которое
/// в нём уже учтено.
#[derive(Debug, Clone)]
pub enum HubMsg {
    Event { seq: u64, ev: Arc<Value> },
    Snapshot { seq: u64, snap: Arc<Value> },
}

impl HubMsg {
    pub fn seq(&self) -> u64 {
        match self {
            HubMsg::Event { seq, .. } | HubMsg::Snapshot { seq, .. } => *seq,
        }
    }
}

/// Подписка: история и снимок на момент подписки + очередь живых сообщений.
/// Drop подписки (и её `rx`) — отписка: хаб уберёт её на следующей рассылке.
pub struct Subscription {
    pub id: u64,
    /// Последние события из кольца (по возрастанию `seq`).
    pub history: Vec<(u64, Arc<Value>)>,
    /// Снимок на момент подписки.
    pub snapshot: (u64, Arc<Value>),
    pub rx: Receiver<HubMsg>,
}

struct Sub {
    id: u64,
    tx: SyncSender<HubMsg>,
    /// Был пропуск — дослать снимок как можно скорее.
    need_snapshot: bool,
    /// Всего потерянных сообщений (для лога/диагностики).
    dropped: u64,
}

struct Inner {
    seq: u64,
    ring: VecDeque<(u64, Arc<Value>)>,
    subs: Vec<Sub>,
    next_id: u64,
    last_snap: Option<Instant>,
    snap: Option<Arc<Value>>,
}

pub struct Hub<B: Backend> {
    backend: B,
    inner: Mutex<Inner>,
}

impl<B: Backend> Hub<B> {
    pub fn new(backend: B) -> Self {
        Self {
            backend,
            inner: Mutex::new(Inner {
                seq: 0,
                ring: VecDeque::with_capacity(RING_CAP),
                subs: Vec::new(),
                next_id: 1,
                last_snap: None,
                snap: None,
            }),
        }
    }

    pub fn backend(&self) -> &B {
        &self.backend
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Команда фронтенда — прямо в бэкенд.
    pub fn send(&self, cmd: Value) -> Result<(), String> {
        self.backend.send(cmd)
    }

    pub fn me(&self) -> Value {
        self.backend.me()
    }

    /// Номер последнего выданного события.
    pub fn seq(&self) -> u64 {
        self.lock().seq
    }

    pub fn subscribers(&self) -> usize {
        self.lock().subs.len()
    }

    /// Новый подписчик с очередью `queue` сообщений (минимум 1).
    pub fn subscribe(&self, queue: usize) -> Subscription {
        let (tx, rx) = mpsc::sync_channel(queue.max(1));
        let mut g = self.lock();
        let snap = match &g.snap {
            Some(s) => s.clone(),
            None => {
                let s = Arc::new(self.backend.snapshot());
                g.snap = Some(s.clone());
                s
            }
        };
        let id = g.next_id;
        g.next_id += 1;
        g.subs.push(Sub { id, tx, need_snapshot: false, dropped: 0 });
        Subscription {
            id,
            history: g.ring.iter().cloned().collect(),
            snapshot: (g.seq, snap),
            rx,
        }
    }

    /// Потерянные сообщения подписчика (`None` — нет такого).
    pub fn dropped(&self, id: u64) -> Option<u64> {
        self.lock().subs.iter().find(|s| s.id == id).map(|s| s.dropped)
    }

    /// Один такт: забрать события, разослать, при необходимости — снимок.
    pub fn pump(&self) {
        self.pump_at(Instant::now());
    }

    /// [`Hub::pump`] с явным «сейчас» (для тестов). Никогда не блокируется
    /// на подписчиках: только `try_send`.
    pub fn pump_at(&self, now: Instant) {
        let events = self.backend.poll_events();
        let changed = self.backend.changed();
        let mut g = self.lock();
        let g = &mut *g;
        for ev in events {
            g.seq += 1;
            let ev = Arc::new(ev);
            if g.ring.len() == RING_CAP {
                g.ring.pop_front();
            }
            g.ring.push_back((g.seq, ev.clone()));
            let seq = g.seq;
            g.subs.retain_mut(|s| deliver(s, HubMsg::Event { seq, ev: ev.clone() }));
        }
        let due = g.last_snap.is_none_or(|t| now.saturating_duration_since(t) >= SNAPSHOT_EVERY);
        if changed || due || g.snap.is_none() {
            g.snap = Some(Arc::new(self.backend.snapshot()));
            g.last_snap = Some(now);
            for s in &mut g.subs {
                s.need_snapshot = true;
            }
        }
        let Some(snap) = g.snap.clone() else { return };
        let seq = g.seq;
        g.subs.retain_mut(|s| {
            if !s.need_snapshot {
                return true;
            }
            match s.tx.try_send(HubMsg::Snapshot { seq, snap: snap.clone() }) {
                Ok(()) => {
                    s.need_snapshot = false;
                    true
                }
                Err(TrySendError::Full(_)) => true, // досылаем на следующем такте
                Err(TrySendError::Disconnected(_)) => false,
            }
        });
    }

    /// Цикл хаба до `stop`: такт раз в [`TICK`].
    pub fn run(&self, stop: &AtomicBool) {
        while !stop.load(Ordering::Relaxed) {
            self.pump();
            std::thread::sleep(TICK);
        }
    }
}

/// Доставить сообщение; `false` — подписчик ушёл.
fn deliver(s: &mut Sub, msg: HubMsg) -> bool {
    match s.tx.try_send(msg) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            s.dropped += 1;
            s.need_snapshot = true;
            true
        }
        Err(TrySendError::Disconnected(_)) => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::atomic::AtomicU64;

    #[derive(Default)]
    struct Fake {
        events: Mutex<Vec<Value>>,
        changed: AtomicBool,
        snaps: AtomicU64,
        sent: Mutex<Vec<Value>>,
    }

    impl Fake {
        fn push(&self, n: usize) {
            let mut e = self.events.lock().unwrap();
            for i in 0..n {
                e.push(json!({ "n": i }));
            }
        }
    }

    impl Backend for Fake {
        fn snapshot(&self) -> Value {
            json!({ "snap": self.snaps.fetch_add(1, Ordering::Relaxed) })
        }
        fn poll_events(&self) -> Vec<Value> {
            std::mem::take(&mut *self.events.lock().unwrap())
        }
        fn send(&self, cmd: Value) -> Result<(), String> {
            if cmd.is_null() {
                return Err("пустая команда".into());
            }
            self.sent.lock().unwrap().push(cmd);
            Ok(())
        }
        fn me(&self) -> Value {
            json!({ "code": "ME" })
        }
        fn changed(&self) -> bool {
            self.changed.swap(false, Ordering::Relaxed)
        }
    }

    fn drain(rx: &Receiver<HubMsg>) -> Vec<HubMsg> {
        rx.try_iter().collect()
    }

    fn event_seqs(msgs: &[HubMsg]) -> Vec<u64> {
        msgs.iter()
            .filter_map(|m| match m {
                HubMsg::Event { seq, .. } => Some(*seq),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn slow_subscriber_does_not_block_others() {
        let hub = Arc::new(Hub::new(Fake::default()));
        let slow = hub.subscribe(2); // никогда не читает
        let fast = hub.subscribe(DEFAULT_QUEUE);
        let reader = std::thread::spawn(move || {
            let mut got = Vec::new();
            while got.len() < 1000 {
                match fast.rx.recv_timeout(Duration::from_secs(5)) {
                    Ok(HubMsg::Event { seq, .. }) => got.push(seq),
                    Ok(_) => {}
                    Err(_) => break,
                }
            }
            got
        });
        let t0 = Instant::now();
        for _ in 0..100 {
            hub.backend().push(10);
            hub.pump();
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(t0.elapsed() < Duration::from_secs(5), "хаб ждал медленного");
        let got = reader.join().unwrap();
        assert_eq!(got, (1..=1000).collect::<Vec<_>>());
        assert!(hub.dropped(slow.id).unwrap() > 0);
        drop(slow);
    }

    #[test]
    fn overflow_makes_seq_gap_then_snapshot() {
        let hub = Hub::new(Fake::default());
        let now = Instant::now();
        hub.pump_at(now); // первый снимок
        let sub = hub.subscribe(3);
        hub.backend().push(10);
        hub.pump_at(now + Duration::from_millis(10));
        let first = drain(&sub.rx);
        assert_eq!(event_seqs(&first), vec![1, 2, 3]);
        assert_eq!(hub.dropped(sub.id), Some(7));
        // Очередь свободна: досылается снимок с seq последнего события.
        hub.backend().push(2);
        hub.pump_at(now + Duration::from_millis(20));
        let next = drain(&sub.rx);
        assert_eq!(event_seqs(&next), vec![11, 12]); // дырка 4..=10
        match next.last().unwrap() {
            HubMsg::Snapshot { seq, .. } => assert_eq!(*seq, 12),
            m => panic!("ждали снимок, пришло {m:?}"),
        }
    }

    #[test]
    fn ring_replays_last_500() {
        let hub = Hub::new(Fake::default());
        hub.backend().push(RING_CAP + 120);
        hub.pump();
        let sub = hub.subscribe(8);
        assert_eq!(sub.history.len(), RING_CAP);
        assert_eq!(sub.history.first().unwrap().0, 121);
        assert_eq!(sub.history.last().unwrap().0, (RING_CAP + 120) as u64);
        assert!(sub.history.windows(2).all(|w| w[1].0 == w[0].0 + 1));
        assert_eq!(sub.history.last().unwrap().1["n"], json!(RING_CAP + 119));
        assert_eq!(sub.snapshot.0, (RING_CAP + 120) as u64);
        // Новое событие продолжает нумерацию.
        hub.backend().push(1);
        hub.pump();
        assert_eq!(event_seqs(&drain(&sub.rx)), vec![(RING_CAP + 121) as u64]);
    }

    #[test]
    fn snapshots_periodic_and_on_change() {
        let hub = Hub::new(Fake::default());
        let now = Instant::now();
        hub.pump_at(now);
        let sub = hub.subscribe(16);
        let snaps = |msgs: Vec<HubMsg>| msgs.iter().filter(|m| matches!(m, HubMsg::Snapshot { .. })).count();
        hub.pump_at(now + Duration::from_millis(100));
        assert_eq!(snaps(drain(&sub.rx)), 0);
        hub.backend().changed.store(true, Ordering::Relaxed);
        hub.pump_at(now + Duration::from_millis(200));
        assert_eq!(snaps(drain(&sub.rx)), 1);
        hub.pump_at(now + Duration::from_millis(900));
        assert_eq!(snaps(drain(&sub.rx)), 0);
        hub.pump_at(now + Duration::from_millis(1250));
        assert_eq!(snaps(drain(&sub.rx)), 1);
    }

    #[test]
    fn dropped_subscription_is_removed_and_send_passes_through() {
        let hub = Hub::new(Fake::default());
        let a = hub.subscribe(4);
        let _b = hub.subscribe(4);
        assert_eq!(hub.subscribers(), 2);
        drop(a);
        hub.backend().push(1);
        hub.pump();
        assert_eq!(hub.subscribers(), 1);
        assert!(hub.send(json!({ "cmd": "x" })).is_ok());
        assert!(hub.send(Value::Null).is_err());
        assert_eq!(hub.me()["code"], "ME");
    }
}
