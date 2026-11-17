//! Сообщения IPC (PLAN.md, 7.2).

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Мажорная версия IPC-протокола. Несовпадение — `Reject` на `Hello` и закрытие.
pub const PROTO_VERSION: u32 = 1;

/// Тип фронтенда.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClientKind {
    Tui,
    Tray,
    Cli,
}

/// Фронтенд → демон.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum ClientMsg {
    /// Первое сообщение соединения.
    Hello {
        proto: u32,
        kind: ClientKind,
        /// Версия фронтенда (для логов и текста ошибки).
        ver: String,
    },
    /// Команда движку (`Cmd` в JSON); ответ — `Ack` с тем же `id`.
    Req { id: u64, cmd: Value },
    /// Подписка на события и снимки; `snapshots_ms` — желаемый период снимков.
    Subscribe { snapshots_ms: u32 },
    /// Вежливое закрытие.
    Bye,
}

/// Итог приёма команды демоном (не результат её выполнения — тот приходит событием).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckResult {
    Ok,
    Err(String),
}

/// Демон → фронтенд.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "t", rename_all = "snake_case")]
pub enum DaemonMsg {
    /// Ответ на подходящий `Hello`; `me` — `my_pub`, `my_code` и т.п.
    Welcome {
        proto: u32,
        daemon_ver: String,
        me: Value,
    },
    /// Отказ на `Hello` (несовпадение версии и т.п.), после него — закрытие.
    Reject { reason: String },
    /// Команда `id` принята / отклонена демоном.
    Ack { id: u64, result: AckResult },
    /// Событие движка; дырка в `seq` — пропуск, ждать снимок.
    Event { seq: u64, ev: Value },
    /// Полный снимок состояния.
    Snapshot { seq: u64, snap: Value },
    /// Демон завершается.
    Shutdown { reason: String },
}

impl ClientMsg {
    /// `Hello` текущей версии протокола.
    pub fn hello(kind: ClientKind, ver: impl Into<String>) -> Self {
        ClientMsg::Hello {
            proto: PROTO_VERSION,
            kind,
            ver: ver.into(),
        }
    }
}

/// Проверка версии из `Hello` на стороне демона: `Err` — готовый `Reject`.
pub fn check_hello(proto: u32) -> Result<(), DaemonMsg> {
    if proto == PROTO_VERSION {
        Ok(())
    } else {
        Err(DaemonMsg::Reject {
            reason: format!(
                "несовместимая версия IPC: клиент {proto}, демон {PROTO_VERSION} — обновите tunnel-client / демон"
            ),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_roundtrip() {
        let msgs = vec![
            ClientMsg::hello(ClientKind::Tray, "0.1.0"),
            ClientMsg::Req {
                id: 7,
                cmd: serde_json::json!({"Join": {"gid": 3}}),
            },
            ClientMsg::Subscribe { snapshots_ms: 1000 },
            ClientMsg::Bye,
        ];
        for m in msgs {
            let s = serde_json::to_string(&m).unwrap();
            assert_eq!(serde_json::from_str::<ClientMsg>(&s).unwrap(), m);
        }
        let ds = vec![
            DaemonMsg::Welcome {
                proto: PROTO_VERSION,
                daemon_ver: "0.1.0".into(),
                me: serde_json::json!({"my_code": "ABCD"}),
            },
            DaemonMsg::Ack {
                id: 7,
                result: AckResult::Err("нет сервера".into()),
            },
            DaemonMsg::Ack {
                id: 8,
                result: AckResult::Ok,
            },
            DaemonMsg::Event {
                seq: 1,
                ev: serde_json::json!("Connected"),
            },
            DaemonMsg::Snapshot {
                seq: 2,
                snap: serde_json::json!({}),
            },
            DaemonMsg::Shutdown {
                reason: "стоп".into(),
            },
        ];
        for d in ds {
            let s = serde_json::to_string(&d).unwrap();
            assert_eq!(serde_json::from_str::<DaemonMsg>(&s).unwrap(), d);
        }
    }

    #[test]
    fn hello_version_check() {
        assert!(check_hello(PROTO_VERSION).is_ok());
        assert!(matches!(check_hello(99), Err(DaemonMsg::Reject { .. })));
    }
}
