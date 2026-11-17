//! tunnel-client как библиотека: движок, конфиг, TUI и вспомогательные
//! модули. Бинарь `tunnel-client` (main.rs) и демон (`tunnel-daemon`,
//! PLAN.md 7.3) пользуются одним и тем же кодом.

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
pub mod tui;
pub mod tun;
#[cfg(target_os = "linux")]
pub mod tun_linux;
#[cfg(target_os = "macos")]
pub mod tun_macos;
