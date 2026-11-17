//! Экран первичной настройки (first-run) TUI.
//!
//! Показывается при запуске `tui`/`ui`, если конфиг ещё не заполнен:
//! нет имени профиля или ни одного сервера. Работает **до** запуска движка:
//! это отдельный терминальный цикл, который заполняет конфиг, имя адаптера
//! и путь к `wintun.dll`; сохранение выполняет вызывающий (`main`).
//!
//! Клавиши: `↑↓`/`Tab` — поле, ввод — редактирование, `Enter` — применить,
//! `Esc` — отмена.

use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};
use ratatui::prelude::*;
use ratatui::widgets::{Block, BorderType, Borders, Clear, Paragraph};
use tunnel_protocol as proto;

use super::theme::{Theme, ThemeKind};
use super::{restore_terminal, setup_terminal};
use crate::store::{Config, StoredServer};

/// Поля формы.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Field {
    Name,
    ServerAddr,
    ServerCode,
    Adapter,
    Dll,
}

const FIELDS: [Field; 5] = [
    Field::Name,
    Field::ServerAddr,
    Field::ServerCode,
    Field::Adapter,
    Field::Dll,
];

impl Field {
    fn label(self) -> &'static str {
        match self {
            Field::Name => "имя",
            Field::ServerAddr => "адрес сервера",
            Field::ServerCode => "код сервера",
            Field::Adapter => "адаптер",
            Field::Dll => "wintun.dll",
        }
    }

    fn hint(self) -> &'static str {
        match self {
            Field::Name => "как вас видят другие · обязателен",
            Field::ServerAddr => "ip:port · пусто — оставить существующие серверы",
            Field::ServerCode => "friend code сервера (TUN-…) · печатает tunnel-server",
            Field::Adapter => "имя Wintun-адаптера (для нескольких клиентов — разное)",
            Field::Dll => "путь к dll · пусто — рядом с exe или из PATH",
        }
    }
}

/// Состояние формы.
struct Form {
    sel: usize,
    name: String,
    addr: String,
    code: String,
    adapter: String,
    dll: String,
}

impl Form {
    fn value(&self, f: Field) -> &str {
        match f {
            Field::Name => &self.name,
            Field::ServerAddr => &self.addr,
            Field::ServerCode => &self.code,
            Field::Adapter => &self.adapter,
            Field::Dll => &self.dll,
        }
    }

    fn set(&mut self, f: Field, c: char) {
        let v = match f {
            Field::Name => &mut self.name,
            Field::ServerAddr => &mut self.addr,
            Field::ServerCode => &mut self.code,
            Field::Adapter => &mut self.adapter,
            Field::Dll => &mut self.dll,
        };
        // Поля однострочные: ограничим длину, чтобы не сломать разметку.
        if v.chars().count() < 80 {
            v.push(c);
        }
    }

    fn del(&mut self, f: Field) {
        match f {
            Field::Name => {
                self.name.pop();
            }
            Field::ServerAddr => {
                self.addr.pop();
            }
            Field::ServerCode => {
                self.code.pop();
            }
            Field::Adapter => {
                self.adapter.pop();
            }
            Field::Dll => {
                self.dll.pop();
            }
        }
    }

    fn selected(&self) -> Field {
        FIELDS[self.sel]
    }

    /// Ошибки валидации; пустой список — форма корректна.
    fn validate(&self, has_servers: bool) -> Vec<String> {
        let mut errs = Vec::new();
        if self.name.trim().is_empty() {
            errs.push("имя профиля не задано".into());
        }
        let addr = self.addr.trim();
        let code = self.code.trim();
        if addr.is_empty() && code.is_empty() {
            if !has_servers {
                errs.push("нет серверов: укажи адрес (ip:port) и код (TUN-…)".into());
            }
        } else if addr.is_empty() {
            errs.push("адрес сервера не задан".into());
        } else if code.is_empty() {
            errs.push("код сервера не задан".into());
        } else {
            if addr.parse::<std::net::SocketAddr>().is_err() {
                errs.push(format!("адрес {addr:?} — не ip:port"));
            }
            if proto::Identity::parse_friend_code(code).is_err() {
                errs.push(format!("код {code:?} — не friend code вида TUN-…"));
            }
        }
        if self.adapter.trim().is_empty() {
            errs.push("имя адаптера не задано".into());
        }
        errs
    }

    /// Переносит значения формы в конфиг/флаги. Вызывать после validate().
    fn apply(&self, cfg: &mut Config, adapter: &mut String, dll: &mut Option<String>) {
        cfg.name = self.name.trim().to_string();
        let addr = self.addr.trim();
        if !addr.is_empty() {
            let pk = proto::hex_of(
                &proto::Identity::parse_friend_code(self.code.trim()).expect("код проверен validate"),
            );
            if let Some(existing) = cfg.servers.iter_mut().find(|s| s.addr == addr) {
                // Сервер уже есть — обновляем закреплённый ключ.
                existing.pubkey = pk;
            } else {
                cfg.servers.insert(
                    0,
                    StoredServer { addr: addr.to_string(), pubkey: pk, label: String::new() },
                );
            }
        }
        *adapter = self.adapter.trim().to_string();
        let dll_path = self.dll.trim();
        *dll = if dll_path.is_empty() { None } else { Some(dll_path.to_string()) };
    }
}

enum Action {
    Continue,
    Apply,
    Cancel,
}

/// Показывает экран настройки. Возвращает `true` — продолжать запуск
/// (конфиг/флаги обновлены), `false` — пользователь отменил.
pub fn run(cfg: &mut Config, adapter: &mut String, dll: &mut Option<String>) -> Result<bool> {
    let kind = ThemeKind::from_key(&cfg.theme).unwrap_or(ThemeKind::Dark);
    let th = Theme::of(kind);
    let mut form = Form {
        sel: 0,
        name: cfg.name.clone(),
        addr: cfg.servers.first().map(|s| s.addr.clone()).unwrap_or_default(),
        code: String::new(),
        adapter: adapter.clone(),
        dll: dll.clone().unwrap_or_default(),
    };

    let mut term = setup_terminal(false)?;
    let my_code = crate::store::ensure_identity(cfg).friend_code();
    let res = loop_(&mut term, &mut form, cfg, adapter, dll, &th, &my_code);
    restore_terminal(&mut term)?;
    res
}

fn loop_(
    term: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
    form: &mut Form,
    cfg: &mut Config,
    adapter: &mut String,
    dll: &mut Option<String>,
    th: &Theme,
    my_code: &str,
) -> Result<bool> {
    loop {
        let errs = form.validate(!cfg.servers.is_empty());
        term.draw(|f| draw(f, form, &errs, th, my_code))?;
        if event::poll(Duration::from_millis(120))?
            && let Event::Key(key) = event::read()? {
                if key.kind != KeyEventKind::Press {
                    continue;
                }
                match handle_key(key, form, !cfg.servers.is_empty()) {
                    Action::Cancel => return Ok(false),
                    Action::Apply => {
                        if errs.is_empty() {
                            form.apply(cfg, adapter, dll);
                            return Ok(true);
                        }
                    }
                    Action::Continue => {}
                }
            }
    }
}

fn handle_key(key: ratatui::crossterm::event::KeyEvent, form: &mut Form, has_servers: bool) -> Action {
    // Ctrl-C — выход без сохранения.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Cancel;
    }
    match key.code {
        KeyCode::Esc => Action::Cancel,
        KeyCode::Enter => {
            if form.validate(has_servers).is_empty() {
                Action::Apply
            } else {
                Action::Continue
            }
        }
        KeyCode::Up => {
            form.sel = (form.sel + FIELDS.len() - 1) % FIELDS.len();
            Action::Continue
        }
        KeyCode::Down | KeyCode::Tab => {
            form.sel = (form.sel + 1) % FIELDS.len();
            Action::Continue
        }
        KeyCode::BackTab => {
            form.sel = (form.sel + FIELDS.len() - 1) % FIELDS.len();
            Action::Continue
        }
        KeyCode::Backspace => {
            form.del(form.selected());
            Action::Continue
        }
        KeyCode::Char(c) if !c.is_control() => {
            form.set(form.selected(), c);
            Action::Continue
        }
        _ => Action::Continue,
    }
}

fn draw(f: &mut Frame, form: &Form, errs: &[String], th: &Theme, my_code: &str) {
    // Фон — цветом темы, как и в основном экране.
    f.render_widget(Block::default().style(th.frame()), f.area());
    let area = centered(f.area(), 72, 15 + errs.len() as u16);
    f.render_widget(Clear, area);

    let lines: Vec<Line> = FIELDS
        .iter()
        .enumerate()
        .flat_map(|(i, &field)| {
            let sel = i == form.sel;
            let value = form.value(field);
            let value = if sel {
                format!("{value}▌")
            } else if value.is_empty() {
                "·".to_string()
            } else {
                value.to_string()
            };
            let mut rows = vec![Line::from(vec![
                Span::styled(format!("{:<15}", field.label()), th.dim),
                Span::styled(
                    value,
                    if sel { th.focused_border } else { th.base },
                ),
            ])];
            if sel {
                rows.push(Line::from(Span::styled(format!("  {}", field.hint()), th.dim)));
            }
            rows
        })
        .collect();

    let mut err_lines: Vec<Line> = errs
        .iter()
        .map(|e| Line::from(Span::styled(format!("✗ {e}"), th.error)))
        .collect();
    err_lines.push(Line::from(Span::styled(
        "Enter — применить · Esc — отмена",
        th.dim,
    )));

    let text: Vec<Line> = lines
        .into_iter()
        .chain(std::iter::once(Line::from("")))
        .chain(err_lines)
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(th.focused_border)
        .style(th.surface())
        .title(Span::styled(" ◆ Первичная настройка Tunnel ", th.title))
        .title_bottom(Line::from(Span::styled(
            format!(" твой friend code: {my_code} "),
            th.dim,
        )));
    f.render_widget(Paragraph::new(text).block(block), area);
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form(name: &str, addr: &str, code: &str) -> Form {
        Form {
            sel: 0,
            name: name.into(),
            addr: addr.into(),
            code: code.into(),
            adapter: "TunnelVPN".into(),
            dll: String::new(),
        }
    }

    fn render(form: &Form, errs: &[String], w: u16, h: u16) -> String {
        let mut term = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        let th = Theme::of(ThemeKind::Dark);
        term.draw(|f| draw(f, form, errs, &th, "TUN-TEST-CODE")).unwrap();
        let buf = term.backend().buffer().clone();
        let mut out = String::new();
        for y in 0..h {
            for x in 0..w {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn экран_настройки_рисуется() {
        let f = form("", "", "");
        let text = render(&f, &f.validate(false), 100, 30);
        assert!(text.contains("Первичная настройка"), "нет заголовка:\n{text}");
        assert!(text.contains("имя"), "нет поля имени");
        assert!(text.contains("код сервера"), "нет поля кода");
        assert!(text.contains("TUN-TEST-CODE"), "нет friend code");
        assert!(text.contains("✗"), "не показаны ошибки");
    }

    #[test]
    fn валидная_форма_без_ошибок_и_не_паникует_в_узком_экране() {
        let id = proto::Identity::generate();
        let f = form("alpha", "10.0.0.1:5555", &id.friend_code());
        let errs = f.validate(false);
        assert!(errs.is_empty());
        let _ = render(&f, &errs, 40, 8);
    }

    #[test]
    fn пустая_форма_без_серверов_даёт_ошибки() {
        let f = form("", "", "");
        let errs = f.validate(false);
        assert!(errs.len() >= 2, "должны быть имя и сервер: {errs:?}");
        assert!(f.validate(true).iter().all(|e| !e.contains("сервер")));
    }

    #[test]
    fn корректная_форма_проходит() {
        let id = proto::Identity::generate();
        let code = id.friend_code();
        let f = form("alpha", "127.0.0.1:5555", &code);
        assert!(f.validate(true).is_empty());
        assert!(f.validate(false).is_empty());
    }

    #[test]
    fn битые_адрес_и_код_замечаются() {
        let f = form("alpha", "нет-адреса", "TUN-мусор");
        let errs = f.validate(true);
        assert!(errs.iter().any(|e| e.contains("ip:port")));
        assert!(errs.iter().any(|e| e.contains("friend code")));
    }

    #[test]
    fn применение_пишет_в_конфиг() {
        let mut cfg = Config::default();
        let mut adapter = String::new();
        let mut dll: Option<String> = None;
        let id = proto::Identity::generate();
        let f = form("alpha", "10.0.0.1:5555", &id.friend_code());
        assert!(f.validate(false).is_empty());
        f.apply(&mut cfg, &mut adapter, &mut dll);
        assert_eq!(cfg.name, "alpha");
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].addr, "10.0.0.1:5555");
        // Ключ сервера закреплён из friend code.
        assert_eq!(
            cfg.servers[0].pubkey,
            proto::hex_of(&proto::Identity::parse_friend_code(&id.friend_code()).unwrap())
        );
        assert_eq!(adapter, "TunnelVPN");
        assert_eq!(dll, None);
    }

    #[test]
    fn повторный_адрес_обновляет_ключ_а_не_дублирует() {
        let mut cfg = Config::default();
        let id = proto::Identity::generate();
        cfg.servers.push(StoredServer {
            addr: "10.0.0.1:5555".into(),
            pubkey: "00".repeat(32),
            label: String::new(),
        });
        let mut adapter = "TunnelVPN".to_string();
        let mut dll: Option<String> = None;
        let f = form("alpha", "10.0.0.1:5555", &id.friend_code());
        f.apply(&mut cfg, &mut adapter, &mut dll);
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].pubkey, proto::hex_of(&id.ed_pub()));
    }
}
