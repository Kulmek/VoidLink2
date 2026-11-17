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

    /// Подсказка поля. `own_adapter` — адаптер и dll в этом режиме задаёт
    /// сам клиент (embedded); иначе их задаёт демон (служба).
    fn hint(self, own_adapter: bool) -> &'static str {
        match self {
            Field::Name => "как вас видят другие · обязателен",
            Field::ServerAddr => "ip:port · пусто — оставить существующие серверы",
            Field::ServerCode => "friend code сервера (TUN-…) · печатает tunnel-server",
            Field::Adapter => {
                if own_adapter {
                    "имя Wintun-адаптера (для нескольких клиентов — разное)"
                } else {
                    "задаёт демон (служба) — здесь не нужно"
                }
            }
            Field::Dll => {
                if own_adapter {
                    "путь к dll · пусто — рядом с exe или из PATH"
                } else {
                    "задаёт демон (служба) — здесь не нужно"
                }
            }
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
    /// Адаптер и dll обязательны (свой движок) — в тонком режиме их задаёт
    /// демон, и пустые поля не мешают.
    own_adapter: bool,
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
    ///
    /// `known` — серверы, уже записанные в конфиг. Для них friend code не
    /// нужен (ключ уже закреплён) — иначе первичную настройку нельзя было бы
    /// завершить, если сервер в конфиге есть, а имени ещё нет. Новый сервер
    /// без кода добавить нельзя: без него не закрепить ключ.
    fn validate(&self, known: &[StoredServer]) -> Vec<String> {
        let mut errs = Vec::new();
        if self.name.trim().is_empty() {
            errs.push("имя профиля не задано".into());
        }
        let addr = self.addr.trim();
        let code = self.code.trim();
        let known_addr = known.iter().any(|s| s.addr == addr);
        if addr.is_empty() && code.is_empty() {
            if known.is_empty() {
                errs.push("нет серверов: укажи адрес (ip:port) и код (TUN-…)".into());
            }
        } else if addr.is_empty() {
            errs.push("адрес сервера не задан".into());
        } else if code.is_empty() {
            if !known_addr {
                errs.push("код сервера не задан".into());
            }
        } else {
            if addr.parse::<std::net::SocketAddr>().is_err() {
                errs.push(format!("адрес {addr:?} — не ip:port"));
            }
            if proto::Identity::parse_friend_code(code).is_err() {
                errs.push(format!("код {code:?} — не friend code вида TUN-…"));
            }
        }
        if self.own_adapter && self.adapter.trim().is_empty() {
            errs.push("имя адаптера не задано".into());
        }
        errs
    }

    /// Переносит значения формы в конфиг/флаги. Вызывать после validate().
    fn apply(&self, cfg: &mut Config, adapter: &mut String, dll: &mut Option<String>) {
        cfg.name = self.name.trim().to_string();
        let addr = self.addr.trim();
        if !addr.is_empty() {
            // Код пуст — сервер уже в конфиге, ключ закреплён: не трогаем его.
            let pk = if self.code.trim().is_empty() {
                None
            } else {
                Some(proto::hex_of(
                    &proto::Identity::parse_friend_code(self.code.trim())
                        .expect("код проверен validate"),
                ))
            };
            if let Some(existing) = cfg.servers.iter_mut().find(|s| s.addr == addr) {
                // Сервер уже есть — обновляем закреплённый ключ (если код введён).
                if let Some(pk) = pk {
                    existing.pubkey = pk;
                }
            } else {
                let pk = pk.expect("для нового сервера код обязателен (validate)");
                cfg.servers.insert(
                    0,
                    StoredServer {
                        addr: addr.to_string(),
                        pubkey: pk,
                        label: String::new(),
                    },
                );
            }
        }
        *adapter = self.adapter.trim().to_string();
        let dll_path = self.dll.trim();
        *dll = if dll_path.is_empty() {
            None
        } else {
            Some(dll_path.to_string())
        };
    }
}

enum Action {
    Continue,
    Apply,
    Cancel,
}

/// Показывает экран настройки. Возвращает `true` — продолжать запуск
/// (конфиг/флаги обновлены), `false` — пользователь отменил.
///
/// `own_adapter` — адаптер и dll задаёт сам клиент (embedded): поля
/// обязательны. В тонком режиме их задаёт демон (служба) — поля не
/// обязательны и не применяются.
///
/// `my_code` — наш friend code (identity уже создана вызывающим).
pub fn run(
    cfg: &mut Config,
    adapter: &mut String,
    dll: &mut Option<String>,
    own_adapter: bool,
    my_code: &str,
) -> Result<bool> {
    let kind = ThemeKind::from_key(&cfg.theme).unwrap_or(ThemeKind::Dark);
    let th = Theme::of(kind);
    let mut form = Form {
        sel: 0,
        name: cfg.name.clone(),
        addr: cfg
            .servers
            .first()
            .map(|s| s.addr.clone())
            .unwrap_or_default(),
        code: String::new(),
        adapter: adapter.clone(),
        dll: dll.clone().unwrap_or_default(),
        own_adapter,
    };

    let mut term = setup_terminal(false)?;
    let res = loop_(&mut term, &mut form, cfg, adapter, dll, &th, my_code);
    // Ошибка восстановления консоли не должна отменять применённую
    // настройку: иначе введённое имя и сервер теряются (вызывающий не
    // дойдёт до сохранения конфига).
    if let Err(e) = restore_terminal(&mut term, false) {
        eprintln!("предупреждение: консоль не восстановлена: {e}");
    }
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
        let errs = form.validate(&cfg.servers);
        term.draw(|f| draw(f, form, &errs, th, my_code))?;
        if event::poll(Duration::from_millis(120))?
            && let Event::Key(key) = event::read()?
        {
            if key.kind != KeyEventKind::Press {
                continue;
            }
            match handle_key(key, form, &cfg.servers) {
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

fn handle_key(
    key: ratatui::crossterm::event::KeyEvent,
    form: &mut Form,
    known: &[StoredServer],
) -> Action {
    // Ctrl-C — выход без сохранения.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Action::Cancel;
    }
    match key.code {
        KeyCode::Esc => Action::Cancel,
        KeyCode::Enter => {
            if form.validate(known).is_empty() {
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
                Span::styled(value, if sel { th.focused_border } else { th.base }),
            ])];
            if sel {
                rows.push(Line::from(Span::styled(
                    format!("  {}", field.hint(form.own_adapter)),
                    th.dim,
                )));
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

    /// Форма с адаптером (embedded: свой движок).
    fn form(name: &str, addr: &str, code: &str) -> Form {
        Form {
            sel: 0,
            name: name.into(),
            addr: addr.into(),
            code: code.into(),
            adapter: "TunnelVPN".into(),
            dll: String::new(),
            own_adapter: true,
        }
    }

    /// Форма тонкого режима: адаптер и dll задаёт демон.
    fn form_remote(name: &str, addr: &str, code: &str) -> Form {
        Form {
            adapter: String::new(),
            own_adapter: false,
            ..form(name, addr, code)
        }
    }

    /// Сервер, уже записанный в конфиг.
    fn stored(addr: &str) -> StoredServer {
        StoredServer {
            addr: addr.into(),
            pubkey: "00".repeat(32),
            label: String::new(),
        }
    }

    /// Клавиша как её видит crossterm.
    fn key(code: KeyCode) -> ratatui::crossterm::event::KeyEvent {
        ratatui::crossterm::event::KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// Печатает текст в выделенное поле (как живой пользователь).
    fn type_text(form: &mut Form, text: &str, known: &[StoredServer]) {
        for c in text.chars() {
            handle_key(key(KeyCode::Char(c)), form, known);
        }
    }

    /// Ввод формы «как живой пользователь»: имя, адрес, код, Enter.
    fn fill_and_press_enter(
        form: &mut Form,
        name: &str,
        addr: &str,
        code: &str,
        known: &[StoredServer],
    ) -> Action {
        type_text(form, name, known);
        handle_key(key(KeyCode::Tab), form, known);
        type_text(form, addr, known);
        handle_key(key(KeyCode::Tab), form, known);
        type_text(form, code, known);
        handle_key(key(KeyCode::Enter), form, known)
    }

    /// Первый запуск: пустой конфиг — форма заполняется и применяется.
    #[test]
    fn первый_запуск_форма_заполняется_и_применяется() {
        let id = proto::Identity::generate();
        let code = id.friend_code();
        let mut f = form("", "", "");
        let act = fill_and_press_enter(&mut f, "alpha", "10.0.0.1:5555", &code, &[]);
        assert!(matches!(act, Action::Apply), "Enter не применил форму");
        let mut cfg = Config::default();
        let mut adapter = String::new();
        let mut dll: Option<String> = None;
        f.apply(&mut cfg, &mut adapter, &mut dll);
        assert_eq!(cfg.name, "alpha");
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].addr, "10.0.0.1:5555");
        assert_eq!(adapter, "TunnelVPN");
    }

    /// Сервер в конфиге уже есть, не хватает только имени: код сервера не
    /// нужен (ключ уже закреплён) — иначе настройку не завершить.
    #[test]
    fn сервер_уже_есть_имя_задаётся_без_кода() {
        let known = vec![stored("10.0.0.1:5555")];
        let mut f = form("", "10.0.0.1:5555", "");
        type_text(&mut f, "alpha", &known);
        let act = handle_key(key(KeyCode::Enter), &mut f, &known);
        assert!(
            matches!(act, Action::Apply),
            "форма не принята без кода уже настроенного сервера"
        );
        let mut cfg = Config {
            servers: known.clone(),
            ..Config::default()
        };
        let mut adapter = String::new();
        let mut dll: Option<String> = None;
        f.apply(&mut cfg, &mut adapter, &mut dll);
        assert_eq!(cfg.name, "alpha");
        // Ключ настроенного сервера не тронут.
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].pubkey, "00".repeat(32));
    }

    /// Новый сервер без кода — по-прежнему нельзя: ключ не закрепить.
    #[test]
    fn новый_сервер_без_кода_не_проходит() {
        let f = form("alpha", "10.0.0.9:5555", "");
        let errs = f.validate(&[stored("10.0.0.1:5555")]);
        assert!(
            errs.iter().any(|e| e.contains("код сервера")),
            "ожидалась ошибка про код сервера: {errs:?}"
        );
    }

    /// Тонкий режим (демон): адаптер и dll задаёт демон — пустые поля не
    /// мешают завершить настройку.
    #[test]
    fn тонкий_режим_не_требует_адаптер() {
        let id = proto::Identity::generate();
        let mut f = form_remote("", "", "");
        let act = fill_and_press_enter(&mut f, "alpha", "10.0.0.1:5555", &id.friend_code(), &[]);
        assert!(matches!(act, Action::Apply), "Enter не применил форму");
        assert!(f.validate(&[]).is_empty());
    }

    /// Свой движок: адаптер обязателен (иначе TUN не поднять).
    #[test]
    fn свой_движок_требует_адаптер() {
        let mut f = form("alpha", "10.0.0.1:5555", "");
        f.adapter = String::new();
        let errs = f.validate(&[]);
        assert!(
            errs.iter().any(|e| e.contains("адаптер")),
            "ожидалась ошибка про адаптер: {errs:?}"
        );
    }

    /// Первый запуск: введённые имя и сервер должны оказаться в client.json
    /// (иначе приходится вводить их заново командами CLI).
    #[test]
    fn первый_запуск_пишет_имя_и_сервер_в_client_json() {
        let dir = std::env::temp_dir().join(format!("vl-first-run-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let store = crate::store::Store::new(&dir);
        let mut cfg = store.load().unwrap();
        crate::store::ensure_identity(&mut cfg);

        let id = proto::Identity::generate();
        let mut f = form("", "", "");
        let act = fill_and_press_enter(&mut f, "alpha", "10.0.0.1:5555", &id.friend_code(), &[]);
        assert!(matches!(act, Action::Apply));

        // Так сохраняет вызывающий (main): форма → конфиг → client.json.
        let mut adapter = String::new();
        let mut dll: Option<String> = None;
        f.apply(&mut cfg, &mut adapter, &mut dll);
        store.save(&cfg).unwrap();

        let saved = store.load().unwrap();
        assert_eq!(saved.name, "alpha");
        assert_eq!(saved.servers.len(), 1);
        assert_eq!(saved.servers[0].addr, "10.0.0.1:5555");
        assert_eq!(
            saved.servers[0].pubkey,
            proto::hex_of(&proto::Identity::parse_friend_code(&id.friend_code()).unwrap())
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn render(form: &Form, errs: &[String], w: u16, h: u16) -> String {
        let mut term = Terminal::new(ratatui::backend::TestBackend::new(w, h)).unwrap();
        let th = Theme::of(ThemeKind::Dark);
        term.draw(|f| draw(f, form, errs, &th, "TUN-TEST-CODE"))
            .unwrap();
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
        let text = render(&f, &f.validate(&[]), 100, 30);
        assert!(
            text.contains("Первичная настройка"),
            "нет заголовка:\n{text}"
        );
        assert!(text.contains("имя"), "нет поля имени");
        assert!(text.contains("код сервера"), "нет поля кода");
        assert!(text.contains("TUN-TEST-CODE"), "нет friend code");
        assert!(text.contains("✗"), "не показаны ошибки");
    }

    #[test]
    fn валидная_форма_без_ошибок_и_не_паникует_в_узком_экране() {
        let id = proto::Identity::generate();
        let f = form("alpha", "10.0.0.1:5555", &id.friend_code());
        let errs = f.validate(&[]);
        assert!(errs.is_empty());
        let _ = render(&f, &errs, 40, 8);
    }

    #[test]
    fn пустая_форма_без_серверов_даёт_ошибки() {
        let f = form("", "", "");
        let errs = f.validate(&[]);
        assert!(errs.len() >= 2, "должны быть имя и сервер: {errs:?}");
        // Сервер в конфиге есть — сервер спрашивать не нужно.
        assert!(
            f.validate(&[stored("10.0.0.1:5555")])
                .iter()
                .all(|e| !e.contains("сервер"))
        );
    }

    #[test]
    fn корректная_форма_проходит() {
        let id = proto::Identity::generate();
        let code = id.friend_code();
        let f = form("alpha", "127.0.0.1:5555", &code);
        assert!(f.validate(&[stored("10.0.0.1:5555")]).is_empty());
        assert!(f.validate(&[]).is_empty());
    }

    #[test]
    fn битые_адрес_и_код_замечаются() {
        let f = form("alpha", "нет-адреса", "TUN-мусор");
        let errs = f.validate(&[stored("10.0.0.1:5555")]);
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
        assert!(f.validate(&[]).is_empty());
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
        cfg.servers.push(stored("10.0.0.1:5555"));
        let mut adapter = "TunnelVPN".to_string();
        let mut dll: Option<String> = None;
        let f = form("alpha", "10.0.0.1:5555", &id.friend_code());
        f.apply(&mut cfg, &mut adapter, &mut dll);
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].pubkey, proto::hex_of(&id.ed_pub()));
    }
}
