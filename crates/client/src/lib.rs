//! Клиент туннеля (протокол v3) как библиотека: движок, хранилище, TUI и
//! вспомогательные модули. CLI (`main.rs`) и другие крейты (daemon, tray)
//! используют их через `tunnel_client::…`.

pub mod dns;
pub mod engine;
#[cfg(test)]
mod engine_e2e;
pub mod invites;
pub mod ipv6;
pub mod profile;
pub mod snapshot;
pub mod store;
pub mod tcp_link;
// Wintun (на не-Windows — заглушка крейта wintun): движок пока ходит
// через этот модуль на всех ОС.
pub mod tun;
#[cfg(target_os = "linux")]
pub mod tun_linux;
#[cfg(target_os = "macos")]
pub mod tun_macos;
pub mod tui;
