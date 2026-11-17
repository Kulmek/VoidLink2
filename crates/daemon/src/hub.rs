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
//! - пока подписчик ждёт снимок, события ему не шлются (считаются
//!   потерянными): снимок с `seq` этого такта их покрывает, а место в очереди
//!   остаётся под сам снимок — иначе ровный поток событий его вытесняет;
//! - снимок бэкенда строится вне мьютекса хаба (IPC-потоки не ждут движок);
//!   [`Hub::pump`] вызывается из одного потока (цикл [`Hub::run`]);
//! - кольцо последних [`RING_CAP`] событий — новый подписчик сразу получает
//!   историю лога и текущий снимок вне очереди (в [`Subscription`]).

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::log::{Level, LogFn};

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
    /// Кэш снимка и `seq` последнего события, учтённого в нём (не `seq`
    /// хаба на момент рассылки: между тактами они могут разойтись).
    snap: Option<(u64, Arc<Value>)>,
}

pub struct Hub<B: Backend> {
    backend: B,
    inner: Mutex<Inner>,
    log: Option<LogFn>,
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
            log: None,
        }
    }

    /// Хаб с логом (первое переполнение подписчика пишется в лог).
    pub fn with_log(backend: B, log: LogFn) -> Self {
        let mut h = Self::new(backend);
        h.log = Some(log);
        h
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
        // Снимок бэкенда — вне мьютекса хаба. `seq` берём до снимка: события
        // с номером ≤ seq уже забраны из бэкенда, значит, в снимке учтены.
        let pre = {
            let g = self.lock();
            g.snap.is_none().then_some(g.seq)
        };
        let fresh = pre.map(|seq| (seq, Arc::new(self.backend.snapshot())));
        let mut g = self.lock();
        let snap = match (&g.snap, fresh) {
            (Some(s), _) => s.clone(),
            (None, Some(s)) => {
                g.snap = Some(s.clone());
                s
            }
            (None, None) => unreachable!("снимок был в кэше, а кэш не очищается"),
        };
        let id = g.next_id;
        g.next_id += 1;
        g.subs.push(Sub {
            id,
            tx,
            need_snapshot: false,
            dropped: 0,
        });
        Subscription {
            id,
            history: g.ring.iter().cloned().collect(),
            snapshot: snap,
            rx,
        }
    }

    /// Потерянные сообщения подписчика (`None` — нет такого).
    pub fn dropped(&self, id: u64) -> Option<u64> {
        self.lock()
            .subs
            .iter()
            .find(|s| s.id == id)
            .map(|s| s.dropped)
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
        let mut overflowed = Vec::new();
        let (need, snap_seq) = {
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
                g.subs.retain_mut(|s| {
                    deliver(
                        s,
                        HubMsg::Event {
                            seq,
                            ev: ev.clone(),
                        },
                        &mut overflowed,
                    )
                });
            }
            let due = g
                .last_snap
                .is_none_or(|t| now.saturating_duration_since(t) >= SNAPSHOT_EVERY);
            // Подписчику с пропуском нужен снимок, покрывающий дырку: кэш,
            // не учитывающий последние события, не годится.
            let stale = g.snap.as_ref().is_some_and(|(q, _)| *q < g.seq)
                && g.subs.iter().any(|s| s.need_snapshot);
            (changed || due || stale || g.snap.is_none(), g.seq)
        };
        if let Some(log) = &self.log {
            for id in overflowed {
                log(
                    Level::Warn,
                    &format!("подписчик {id}: очередь переполнена, события теряются до снимка"),
                );
            }
        }
        // Снимок строится без мьютекса хаба; он не старше событий этого такта
        // (взят после poll_events), поэтому его seq = последний выданный.
        let fresh = need.then(|| Arc::new(self.backend.snapshot()));
        let mut g = self.lock();
        let g = &mut *g;
        if let Some(s) = fresh {
            g.snap = Some((snap_seq, s));
            g.last_snap = Some(now);
            for s in &mut g.subs {
                s.need_snapshot = true;
            }
        }
        let Some((seq, snap)) = g.snap.clone() else {
            return;
        };
        g.subs.retain_mut(|s| {
            if !s.need_snapshot {
                return true;
            }
            match s.tx.try_send(HubMsg::Snapshot {
                seq,
                snap: snap.clone(),
            }) {
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

/// Доставить событие; `false` — подписчик ушёл. Подписчику, ждущему снимок,
/// событие не шлётся (его покроет снимок конца такта). Первое переполнение
/// подписчика — его id в `overflowed` (для лога).
fn deliver(s: &mut Sub, msg: HubMsg, overflowed: &mut Vec<u64>) -> bool {
    if s.need_snapshot {
        s.dropped += 1;
        return true;
    }
    match s.tx.try_send(msg) {
        Ok(()) => true,
        Err(TrySendError::Full(_)) => {
            if s.dropped == 0 {
                overflowed.push(s.id);
            }
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
        // Очередь свободна: события, пока ждём снимок, не шлются; снимок
        // с seq последнего события покрывает дырку 4..=12.
        hub.backend().push(2);
        hub.pump_at(now + Duration::from_millis(20));
        let next = drain(&sub.rx);
        assert!(event_seqs(&next).is_empty());
        match next.as_slice() {
            [HubMsg::Snapshot { seq, .. }] => assert_eq!(*seq, 12),
            m => panic!("ждали один снимок, пришло {m:?}"),
        }
        assert_eq!(hub.dropped(sub.id), Some(9));
        // После снимка события идут как обычно.
        hub.backend().push(1);
        hub.pump_at(now + Duration::from_millis(30));
        assert_eq!(event_seqs(&drain(&sub.rx)), vec![13]);
    }

    #[test]
    fn snapshot_not_starved_by_steady_stream() {
        let logged = Arc::new(Mutex::new(Vec::<String>::new()));
        let l = logged.clone();
        let log: LogFn = Arc::new(move |_, m| l.lock().unwrap().push(m.to_string()));
        let hub = Hub::with_log(Fake::default(), log);
        let now = Instant::now();
        hub.pump_at(now);
        let sub = hub.subscribe(3);
        hub.backend().push(10); // переполнение
        hub.pump_at(now + Duration::from_millis(10));
        let mut got_snap = None;
        for tick in 1..=3u64 {
            // Клиент читает 3 сообщения за такт, движок шлёт 3 события за такт.
            let read: Vec<HubMsg> = sub.rx.try_iter().take(3).collect();
            if let Some(m) = read.iter().find(|m| matches!(m, HubMsg::Snapshot { .. })) {
                got_snap = Some((tick, m.seq()));
                break;
            }
            hub.backend().push(3);
            hub.pump_at(now + Duration::from_millis(10 + 10 * tick));
        }
        let (tick, seq) = got_snap.expect("снимок не дошёл за 3 такта");
        assert!(tick <= 2, "снимок пришёл только на такте {tick}");
        assert_eq!(seq, hub.seq());
        assert_eq!(
            logged.lock().unwrap().len(),
            1,
            "переполнение логируется один раз"
        );
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
        let snaps = |msgs: Vec<HubMsg>| {
            msgs.iter()
                .filter(|m| matches!(m, HubMsg::Snapshot { .. }))
                .count()
        };
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
