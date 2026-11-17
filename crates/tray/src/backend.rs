//! Источник данных трея: [`crate::remote::IpcTrayBackend`] — IPC-клиент
//! демона (7.3/7.5), `StubBackend` — состояние в памяти (`--demo`, тесты).
#![cfg_attr(not(windows), allow(dead_code))] // вне Windows трей не собирается в бинарь

use std::sync::Mutex;

use crate::model::{Action, Conn, TrayGroup, TrayInvite, TrayState};

pub trait TrayBackend {
    /// Текущий снимок; вызывается по таймеру (раз в ~500 мс), не должен блокировать надолго.
    /// IPC-реализация обязана заполнять `TrayState::kicked` из событий демона
    /// (Kicked / GroupDeleted) и `TrayState::errors`, накопленные с прошлого
    /// вызова, и отдавать каждое один раз: трей не угадывает исключение по
    /// разнице снимков.
    fn state(&self) -> TrayState;
    /// Действие демона (группы, приглашения, остановка). Локальные действия
    /// (`Action::is_local`) трей выполняет сам и сюда не передаёт.
    fn act(&self, a: Action);
}

/// Заглушка: держит состояние в памяти и применяет действия к нему.
pub struct StubBackend {
    st: Mutex<TrayState>,
}

impl StubBackend {
    pub fn new(st: TrayState) -> Self {
        Self { st: Mutex::new(st) }
    }

    /// Демонстрационное состояние для ручной проверки трея без демона.
    pub fn demo() -> Self {
        Self::new(TrayState {
            conn: Conn::Connected,
            my_ips: vec!["10.1.0.2".into()],
            server_label: Some("демо-сервер".into()),
            my_code: Some("DEMO-CODE-0000".into()),
            groups: vec![
                TrayGroup {
                    gid: 1,
                    name: "дом".into(),
                    joined: true,
                },
                TrayGroup {
                    gid: 2,
                    name: "работа".into(),
                    joined: false,
                },
            ],
            invites: vec![TrayInvite {
                gid: 3,
                group_name: "игры".into(),
                from: "друг".into(),
            }],
            kicked: Vec::new(),
            errors: Vec::new(),
            tui_open: false,
        })
    }
}

impl TrayBackend for StubBackend {
    fn state(&self) -> TrayState {
        self.st.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn act(&self, a: Action) {
        let mut s = self.st.lock().unwrap_or_else(|e| e.into_inner());
        match a {
            Action::ToggleGroup { gid, join } => {
                if let Some(g) = s.groups.iter_mut().find(|g| g.gid == gid) {
                    g.joined = join;
                }
            }
            Action::AcceptInvite(gid) => {
                if let Some(pos) = s.invites.iter().position(|i| i.gid == gid) {
                    let inv = s.invites.remove(pos);
                    s.groups.push(TrayGroup {
                        gid,
                        name: inv.group_name,
                        joined: true,
                    });
                }
            }
            Action::DeclineInvite(gid) => s.invites.retain(|i| i.gid != gid),
            Action::StopTunnel => s.conn = Conn::DaemonDown,
            Action::OpenTui | Action::CopyIp | Action::CopyCode | Action::Exit => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stub_applies_actions() {
        let b = StubBackend::demo();
        b.act(Action::ToggleGroup { gid: 2, join: true });
        assert!(b.state().groups.iter().all(|g| g.joined));
        b.act(Action::AcceptInvite(3));
        let s = b.state();
        assert!(s.invites.is_empty());
        assert!(
            s.groups
                .iter()
                .any(|g| g.gid == 3 && g.joined && g.name == "игры")
        );
        let b = StubBackend::demo();
        b.act(Action::DeclineInvite(3));
        assert!(b.state().invites.is_empty());
        assert_eq!(b.state().groups.len(), 2);
        b.act(Action::StopTunnel);
        assert_eq!(b.state().conn, Conn::DaemonDown);
    }
}
