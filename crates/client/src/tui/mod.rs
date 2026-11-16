//! TUI-режим клиента (ratatui + crossterm).
//!
//! Движок ничего не знает про UI: TUI читает состояние (`Engine::groups`,
//! `Engine::meta`, `Engine::stats`), шлёт команды (`Engine::cmds`) и слушает
//! события (`Engine::events`).

pub mod app;
pub mod identicon;
pub mod setup;
pub mod theme;
pub mod ui;

use std::io::Stdout;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyEventKind};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::prelude::*;

use crate::engine::{self, Engine};
use crate::store::{Config, Store};

use app::App;

/// Запускает TUI: поднимает движок и рисует интерфейс до выхода.
pub fn run(
    cfg: Arc<Config>,
    server: std::net::SocketAddr,
    server_pub: [u8; 32],
    identity: tunnel_protocol::Identity,
    adapter_name: &str,
    dll: Option<String>,
    store: Arc<Store>,
) -> Result<()> {
    let shared = Arc::new(Mutex::new((*cfg).clone()));
    let save_store = store.clone();
    let save = move |c: &Config| {
        let _ = save_store.save(c);
    };
    let eng = engine::start(
        shared,
        server,
        server_pub,
        identity,
        adapter_name,
        dll,
        Arc::new(save),
    )?;

    let mut term = setup_terminal()?;
    let cfg_snapshot = eng.cfg.lock().unwrap().clone();
    let mut app = App::new(eng.my_pub, &eng.my_code, &cfg_snapshot);
    let res = event_loop(&mut term, &mut app, &eng);
    restore_terminal(&mut term)?;
    // Останавливаем движок (потоки туннеля).
    let _ = eng.cmds.send(engine::Cmd::Quit);
    res
}

pub(crate) fn setup_terminal() -> Result<Terminal<CrosstermBackend<Stdout>>> {
    enable_raw_mode()?;
    let mut out = std::io::stdout();
    execute!(out, EnterAlternateScreen)?;
    Ok(Terminal::new(CrosstermBackend::new(out))?)
}

pub(crate) fn restore_terminal(term: &mut Terminal<CrosstermBackend<Stdout>>) -> Result<()> {
    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(())
}

fn event_loop(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut App,
    eng: &Engine,
) -> Result<()> {
    let tick = Duration::from_millis(120);
    loop {
        app.sync(eng);
        term.draw(|f| ui::draw(f, app))?;
        if app.quit {
            return Ok(());
        }
        if event::poll(tick)? {
            match event::read()? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    app.handle_key(key, eng);
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
}
