//! `FakeBackend` — бэкенд без движка и сети для тестов IPC и для
//! `tunnel-daemon console --fake` (разработка фронтендов без туннеля).
//!
//! Держит в памяти список групп и принимает команды в JSON-форме `Cmd`
//! движка: `"RefreshList"`, `{"Join": gid}`, `{"Leave": gid}`,
//! `{"Create": {"name": …, "private": …}}`, `{"SetName": …}`. Успех —
//! событие в форме `Event` движка (`GroupJoined`, `GroupLeft`, `Notice`…)
//! и флаг «изменилось» (хаб сразу разошлёт снимок); неверный gid —
//! `Err` (уйдёт клиенту в `Ack`). Клоны делят одно состояние: тест держит
//! клон и подкидывает события через [`FakeBackend::push_event`].

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use serde_json::{Value, json};

use crate::hub::Backend;

#[derive(Debug, Clone)]
struct Group {
    gid: u32,
    name: String,
    private: bool,
    joined: bool,
}

struct State {
    groups: Vec<Group>,
    events: Vec<Value>,
    next_gid: u32,
    name: String,
    /// Все принятые команды (для тестов).
    sent: Vec<Value>,
}

struct Shared {
    st: Mutex<State>,
    changed: AtomicBool,
}

#[derive(Clone)]
pub struct FakeBackend(Arc<Shared>);

impl Default for FakeBackend {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeBackend {
    /// Три публичные группы (1..=3), ни в одной не состоим; первое событие —
    /// `Connected`.
    pub fn new() -> Self {
        let groups = (1..=3)
            .map(|gid| Group { gid, name: format!("группа-{gid}"), private: false, joined: false })
            .collect();
        let st = State {
            groups,
            events: vec![json!({ "Connected": "127.0.0.1:7000" })],
            next_gid: 4,
            name: "fake".into(),
            sent: Vec::new(),
        };
        FakeBackend(Arc::new(Shared { st: Mutex::new(st), changed: AtomicBool::new(true) }))
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.0.st.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Подкинуть событие (уйдёт подписчикам на следующем такте хаба).
    pub fn push_event(&self, ev: Value) {
        self.lock().events.push(ev);
    }

    /// Пометить состояние изменившимся (снимок на ближайшем такте).
    pub fn touch(&self) {
        self.0.changed.store(true, Ordering::Relaxed);
    }

    /// Принятые команды по порядку.
    pub fn sent(&self) -> Vec<Value> {
        self.lock().sent.clone()
    }

    /// gid групп, в которых состоим.
    pub fn joined(&self) -> Vec<u32> {
        self.lock().groups.iter().filter(|g| g.joined).map(|g| g.gid).collect()
    }

    fn my_ip(gid: u32) -> u32 {
        // 10.<gid>.0.2 — только чтобы поле было правдоподобным.
        (10 << 24) | ((gid & 0xff) << 16) | 2
    }

    fn apply(st: &mut State, cmd: &Value) -> Result<Vec<Value>, String> {
        let gid_of = |v: &Value| v.as_u64().and_then(|g| u32::try_from(g).ok()).ok_or("ожидался gid (u32)".to_string());
        let (name, arg) = match cmd {
            Value::String(s) => (s.as_str(), &Value::Null),
            Value::Object(m) if m.len() == 1 => {
                let (k, v) = m.iter().next().expect("ровно один ключ");
                (k.as_str(), v)
            }
            _ => return Err(format!("неверная команда: {cmd}")),
        };
        match name {
            "RefreshList" => Ok(vec![json!({ "Notice": "список групп обновлён" })]),
            "Join" => {
                let gid = gid_of(arg)?;
                let g = st.groups.iter_mut().find(|g| g.gid == gid).ok_or(format!("нет группы {gid}"))?;
                if g.joined {
                    return Ok(vec![json!({ "Error": format!("уже в группе {gid}") })]);
                }
                g.joined = true;
                Ok(vec![json!({ "GroupJoined": { "gid": gid, "name": g.name, "my_ip": Self::my_ip(gid) } })])
            }
            "Leave" => {
                let gid = gid_of(arg)?;
                let g = st.groups.iter_mut().find(|g| g.gid == gid).ok_or(format!("нет группы {gid}"))?;
                if !g.joined {
                    return Err(format!("не в группе {gid}"));
                }
                g.joined = false;
                Ok(vec![json!({ "GroupLeft": { "gid": gid, "name": g.name } })])
            }
            "Create" => {
                let name = arg.get("name").and_then(Value::as_str).ok_or("Create: нужно name")?;
                let private = arg.get("private").and_then(Value::as_bool).unwrap_or(false);
                let gid = st.next_gid;
                st.next_gid += 1;
                st.groups.push(Group { gid, name: name.to_string(), private, joined: true });
                Ok(vec![json!({ "GroupJoined": { "gid": gid, "name": name, "my_ip": Self::my_ip(gid) } })])
            }
            "SetName" => {
                let n = arg.as_str().ok_or("SetName: нужна строка")?;
                st.name = n.to_string();
                Ok(vec![json!({ "Notice": format!("имя: {n}") })])
            }
            "Quit" => Err("демон не завершается по команде фронтенда".into()),
            other => Err(format!("fake: команда {other} не поддерживается")),
        }
    }
}

impl Backend for FakeBackend {
    fn snapshot(&self) -> Value {
        let st = self.lock();
        let groups: Vec<Value> = st
            .groups
            .iter()
            .filter(|g| g.joined)
            .map(|g| {
                let owner = [0u8; 32];
                json!({
                    "gid": g.gid, "name": g.name, "private": g.private, "my_ip": Self::my_ip(g.gid),
                    "owner": owner, "joined_s_ago": 0, "members": []
                })
            })
            .collect();
        let list: Vec<Value> = st
            .groups
            .iter()
            .map(|g| json!({ "gid": g.gid, "name": g.name, "private": g.private, "mine": false, "online": u32::from(g.joined), "total": u32::from(g.joined) }))
            .collect();
        // Форма `tunnel_client::snapshot::Snapshot` (её разбирают IpcEngine и
        // CLI); `name` сверху — для старых проверок ipc_e2e.
        let srv_key = "00".repeat(32);
        json!({
            "groups": groups,
            "meta": {
                "connected": true, "server": "127.0.0.1:7000", "server_label": "fake", "group_list": list,
                "rx_hist": [], "tx_hist": [], "uptime_s": 0
            },
            "stats": { "rx_bytes": 0, "tx_bytes": 0, "rx_pkts": 0, "tx_pkts": 0 },
            "cfg": {
                "name": st.name, "status": "", "autojoin": [], "friends": [],
                "servers": [{ "addr": "127.0.0.1:7000", "pubkey": srv_key, "label": "fake" }]
            },
            "pending_invites": [],
            "name": st.name,
        })
    }

    fn poll_events(&self) -> Vec<Value> {
        std::mem::take(&mut self.lock().events)
    }

    fn send(&self, cmd: Value) -> Result<(), String> {
        let mut st = self.lock();
        let evs = Self::apply(&mut st, &cmd)?;
        st.sent.push(cmd);
        st.events.extend(evs);
        drop(st);
        self.touch();
        Ok(())
    }

    fn me(&self) -> Value {
        json!({ "my_pub": "00".repeat(32), "my_code": "FAKE-0000" })
    }

    fn changed(&self) -> bool {
        self.0.changed.swap(false, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn join_leave_create() {
        let b = FakeBackend::new();
        assert_eq!(b.poll_events().len(), 1); // Connected
        assert!(b.send(json!({ "Join": 2 })).is_ok());
        assert_eq!(b.joined(), vec![2]);
        let ev = b.poll_events();
        assert_eq!(ev[0]["GroupJoined"]["gid"], 2);
        assert!(b.send(json!({ "Join": 99 })).is_err());
        assert!(b.send(json!({ "Leave": 1 })).is_err());
        assert!(b.send(json!({ "Create": { "name": "x", "private": true } })).is_ok());
        assert_eq!(b.joined(), vec![2, 4]);
        assert!(b.send(json!("RefreshList")).is_ok());
        assert!(b.send(json!(42)).is_err());
        assert!(b.send(json!("Quit")).is_err());
        assert_eq!(b.snapshot()["groups"].as_array().unwrap().len(), 2);
        assert!(b.changed());
        assert!(!b.changed());
    }
}
