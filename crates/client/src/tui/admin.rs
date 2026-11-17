//! Попап «Управление группой» для владельца: баны, приглашения, передача
//! владения.
//!
//! Модуль самодостаточный: состояние — простые данные (`AdminView`),
//! отрисовка — `draw`, ввод — чистые `handle_key` / `handle_mouse`, которые
//! возвращают `AdminAction`. Что делать с действием (слать UNBAN / KICK /
//! TRANSFER серверу, запрашивать GET_GROUP), решает вызывающий код.

// подключается при интеграции
#![allow(dead_code)]

use std::cell::{Cell, RefCell};
use std::net::Ipv4Addr;

use ratatui::Frame;
use ratatui::crossterm::event::{
    KeyCode, KeyEvent, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
};
use ratatui::layout::{Constraint, Layout, Position, Rect};
use ratatui::style::Modifier;
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell as TCell, Clear, Paragraph, Row, Scrollbar,
    ScrollbarOrientation, ScrollbarState, Table, TableState, Tabs, Wrap,
};

use crate::tui::theme::{Btn, Theme};

// ---------------------------------------------------------------- данные

/// Вкладка попапа.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum AdminTab {
    #[default]
    Bans,
    Invites,
    Transfer,
}

impl AdminTab {
    pub const ALL: [AdminTab; 3] = [AdminTab::Bans, AdminTab::Invites, AdminTab::Transfer];

    fn index(self) -> usize {
        match self {
            AdminTab::Bans => 0,
            AdminTab::Invites => 1,
            AdminTab::Transfer => 2,
        }
    }

    fn next(self) -> Self {
        Self::ALL[(self.index() + 1) % 3]
    }

    fn prev(self) -> Self {
        Self::ALL[(self.index() + 2) % 3]
    }
}

/// Забаненный участник.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BanEntry {
    pub pk: [u8; 32],
    pub name: String,
}

/// Висящее приглашение.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteEntry {
    pub pk: [u8; 32],
    pub name: String,
    /// Сколько секунд осталось до истечения (0 — уже истекло).
    pub expires_in_secs: u64,
}

/// Участник группы — кандидат на передачу владения.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberEntry {
    pub pk: [u8; 32],
    pub name: String,
    pub ip: Ipv4Addr,
}

/// Шаг подтверждения передачи владения.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TransferConfirm {
    pub pk: [u8; 32],
    pub name: String,
}

/// Что попросил сделать пользователь.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdminAction {
    Unban(u32, [u8; 32]),
    RevokeInvite(u32, [u8; 32]),
    Transfer(u32, [u8; 32]),
    Refresh(u32),
    Close,
}

/// Где что нарисовано в последнем кадре (заполняется в `draw`).
#[derive(Default, Debug)]
pub struct AdminHits {
    /// Рамка всего попапа.
    pub popup: Cell<Rect>,
    /// Заголовки вкладок.
    pub tabs: RefCell<Vec<(Rect, AdminTab)>>,
    /// Область строк таблицы (без шапки) и смещение прокрутки.
    pub rows: Cell<(Rect, usize)>,
    /// Кнопки: клик = нажатие клавиши.
    pub buttons: RefCell<Vec<(Rect, KeyEvent)>>,
    /// Рамка окна подтверждения (если открыто).
    pub confirm: Cell<Rect>,
}

/// Состояние попапа.
#[derive(Debug, Default)]
pub struct AdminView {
    pub gid: u32,
    pub group_name: String,
    pub bans: Vec<BanEntry>,
    pub invites: Vec<InviteEntry>,
    pub members: Vec<MemberEntry>,
    pub tab: AdminTab,
    pub selected: usize,
    pub confirm: Option<TransferConfirm>,
    pub hits: AdminHits,
}

impl AdminView {
    pub fn new(gid: u32, group_name: impl Into<String>) -> Self {
        AdminView {
            gid,
            group_name: group_name.into(),
            ..Default::default()
        }
    }

    /// Обновляет списки (после ответа сервера) и поправляет выбор.
    pub fn set_data(
        &mut self,
        bans: Vec<BanEntry>,
        invites: Vec<InviteEntry>,
        members: Vec<MemberEntry>,
    ) {
        self.bans = bans;
        self.invites = invites;
        self.members = members;
        if let Some(c) = &self.confirm
            && !self.members.iter().any(|m| m.pk == c.pk)
        {
            self.confirm = None;
        }
        self.clamp();
    }

    /// Список текущей вкладки пуст.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Длина списка текущей вкладки.
    pub fn len(&self) -> usize {
        match self.tab {
            AdminTab::Bans => self.bans.len(),
            AdminTab::Invites => self.invites.len(),
            AdminTab::Transfer => self.members.len(),
        }
    }

    fn clamp(&mut self) {
        let len = self.len();
        if self.selected >= len {
            self.selected = len.saturating_sub(1);
        }
    }

    fn set_tab(&mut self, tab: AdminTab) {
        if self.tab != tab {
            self.tab = tab;
            self.selected = 0;
        }
    }

    fn select_by(&mut self, delta: i64) {
        let len = self.len();
        if len == 0 {
            self.selected = 0;
            return;
        }
        let cur = self.selected.min(len - 1) as i64;
        self.selected = (cur + delta).clamp(0, len as i64 - 1) as usize;
    }

    /// Ключ и имя выбранной строки текущей вкладки.
    fn current(&self) -> Option<([u8; 32], String)> {
        let i = self.selected;
        match self.tab {
            AdminTab::Bans => self.bans.get(i).map(|e| (e.pk, e.name.clone())),
            AdminTab::Invites => self.invites.get(i).map(|e| (e.pk, e.name.clone())),
            AdminTab::Transfer => self.members.get(i).map(|e| (e.pk, e.name.clone())),
        }
    }

    /// Основное действие вкладки над выбранной строкой.
    fn activate(&mut self) -> Option<AdminAction> {
        let (pk, name) = self.current()?;
        match self.tab {
            AdminTab::Bans => Some(AdminAction::Unban(self.gid, pk)),
            AdminTab::Invites => Some(AdminAction::RevokeInvite(self.gid, pk)),
            AdminTab::Transfer => {
                self.confirm = Some(TransferConfirm { pk, name });
                None
            }
        }
    }
}

// ---------------------------------------------------------------- ввод

/// Обработка клавиши. Возвращает действие, если оно есть.
pub fn handle_key(v: &mut AdminView, k: KeyEvent) -> Option<AdminAction> {
    if v.confirm.is_some() {
        return match k.code {
            // Только явное «да»: Enter открывает это окно, поэтому двойное
            // нажатие или автоповтор не должны передать владение. Буквы —
            // по физическим клавишам: Y в русской раскладке даёт «н».
            KeyCode::Char('y' | 'Y' | 'н' | 'Н') => {
                let c = v.confirm.take()?;
                Some(AdminAction::Transfer(v.gid, c.pk))
            }
            KeyCode::Esc | KeyCode::Char('n' | 'N' | 'т' | 'Т') => {
                v.confirm = None;
                None
            }
            _ => None,
        };
    }
    match k.code {
        KeyCode::Esc | KeyCode::Char('q') => Some(AdminAction::Close),
        KeyCode::Char('c') if k.modifiers.contains(KeyModifiers::CONTROL) => {
            Some(AdminAction::Close)
        }
        KeyCode::Tab | KeyCode::Right => {
            v.set_tab(v.tab.next());
            None
        }
        KeyCode::BackTab | KeyCode::Left => {
            v.set_tab(v.tab.prev());
            None
        }
        KeyCode::Char(c @ '1'..='3') => {
            v.set_tab(AdminTab::ALL[(c as u8 - b'1') as usize]);
            None
        }
        KeyCode::Up | KeyCode::Char('k') => {
            v.select_by(-1);
            None
        }
        KeyCode::Down | KeyCode::Char('j') => {
            v.select_by(1);
            None
        }
        KeyCode::PageUp => {
            v.select_by(-10);
            None
        }
        KeyCode::PageDown => {
            v.select_by(10);
            None
        }
        KeyCode::Home => {
            v.selected = 0;
            None
        }
        KeyCode::End => {
            v.selected = v.len().saturating_sub(1);
            None
        }
        KeyCode::Char('r') | KeyCode::F(5) => Some(AdminAction::Refresh(v.gid)),
        KeyCode::Enter | KeyCode::Delete => v.activate(),
        _ => None,
    }
}

fn inside(r: Rect, x: u16, y: u16) -> bool {
    r.contains(Position::new(x, y))
}

/// Обработка мыши по геометрии последнего кадра.
pub fn handle_mouse(v: &mut AdminView, m: MouseEvent) -> Option<AdminAction> {
    let (x, y) = (m.column, m.row);
    match m.kind {
        MouseEventKind::Down(MouseButton::Left) => {
            let btn = v
                .hits
                .buttons
                .borrow()
                .iter()
                .find(|(r, _)| inside(*r, x, y))
                .map(|(_, k)| *k);
            if let Some(k) = btn {
                return handle_key(v, k);
            }
            if v.confirm.is_some() {
                // Клик мимо окна подтверждения — отмена, не закрытие.
                if !inside(v.hits.confirm.get(), x, y) {
                    v.confirm = None;
                }
                return None;
            }
            if !inside(v.hits.popup.get(), x, y) {
                return Some(AdminAction::Close);
            }
            let tab = v
                .hits
                .tabs
                .borrow()
                .iter()
                .find(|(r, _)| inside(*r, x, y))
                .map(|(_, t)| *t);
            if let Some(t) = tab {
                v.set_tab(t);
                return None;
            }
            let (rows, off) = v.hits.rows.get();
            if inside(rows, x, y) {
                let i = off + (y - rows.y) as usize;
                if i < v.len() {
                    v.selected = i;
                }
            }
            None
        }
        MouseEventKind::ScrollUp if v.confirm.is_none() => {
            v.select_by(-1);
            None
        }
        MouseEventKind::ScrollDown if v.confirm.is_none() => {
            v.select_by(1);
            None
        }
        _ => None,
    }
}

// ---------------------------------------------------------------- форматирование

/// Сколько осталось до истечения приглашения: «ещё 6 д», «ещё 3 ч».
pub fn human_expiry(secs: u64) -> String {
    match secs {
        0 => "истекло".to_string(),
        1..60 => "ещё <1 мин".to_string(),
        60..3600 => format!("ещё {} мин", secs / 60),
        3600..86400 => format!("ещё {} ч", secs / 3600),
        _ => format!("ещё {} д", secs / 86400),
    }
}

/// Короткий отпечаток ключа: первые 4 байта в hex.
fn short_pk(pk: &[u8; 32]) -> String {
    pk[..4].iter().map(|b| format!("{b:02x}")).collect::<String>() + "…"
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect {
        x: area.x + (area.width.saturating_sub(w)) / 2,
        y: area.y + (area.height.saturating_sub(h)) / 2,
        width: w,
        height: h,
    }
}

/// Строка кнопок-«чипов» (как в `ui.rs`): рисует и запоминает, куда кликать.
fn draw_buttons(
    f: &mut Frame,
    th: &Theme,
    hits: &RefCell<Vec<(Rect, KeyEvent)>>,
    row: Rect,
    items: &[(&str, Btn, KeyEvent)],
) {
    if row.width == 0 || row.height == 0 {
        return;
    }
    let mut hits = hits.borrow_mut();
    let mut spans = Vec::new();
    let mut x = row.x;
    for (label, kind, k) in items {
        let chip = Span::styled(format!(" {label} "), th.button(*kind));
        let w = chip.width() as u16;
        if x + w > row.right() {
            break;
        }
        hits.push((Rect::new(x, row.y, w, 1), *k));
        spans.push(chip);
        spans.push(Span::raw("  "));
        x += w + 2;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), Rect { height: 1, ..row });
}

// ---------------------------------------------------------------- отрисовка

/// Рисует попап поверх `area` (обычно весь кадр).
pub fn draw(f: &mut Frame, th: &Theme, v: &AdminView, area: Rect) {
    v.hits.tabs.borrow_mut().clear();
    v.hits.buttons.borrow_mut().clear();
    v.hits.rows.set((Rect::default(), 0));
    v.hits.confirm.set(Rect::default());

    // Рамка + вкладки + разделитель + шапка таблицы + строки + кнопки.
    let want_h = (v.len().max(3) as u16 + 7).min(22);
    let rect = centered(area, 76, want_h);
    v.hits.popup.set(rect);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(th.accent)
        .style(th.surface())
        .title(Line::from(Span::styled(
            format!(" Управление группой «{}» ", v.group_name),
            th.title,
        )))
        .title_bottom(Line::from(Span::styled(
            " Tab — вкладка · ↑↓ — выбор · r — обновить · Esc — закрыть ",
            th.dim,
        )));
    let inner = block.inner(rect);
    f.render_widget(block, rect);
    if inner.width == 0 || inner.height < 3 {
        return;
    }

    let [tabs_row, sep_row, table_area, buttons_row] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(inner);

    draw_tabs(f, th, v, tabs_row);
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(
            "─".repeat(sep_row.width as usize),
            th.unfocused_border,
        ))),
        sep_row,
    );
    draw_table(f, th, v, table_area);
    draw_actions(f, th, v, buttons_row);

    if let Some(c) = &v.confirm {
        draw_confirm(f, th, v, c, area);
    }
}

fn tab_title(v: &AdminView, t: AdminTab) -> String {
    match t {
        AdminTab::Bans => format!("Баны ({})", v.bans.len()),
        AdminTab::Invites => format!("Приглашения ({})", v.invites.len()),
        AdminTab::Transfer => "Передача владения".to_string(),
    }
}

fn draw_tabs(f: &mut Frame, th: &Theme, v: &AdminView, row: Rect) {
    let titles: Vec<String> = AdminTab::ALL.iter().map(|t| tab_title(v, *t)).collect();
    // Геометрия повторяет раскладку Tabs: « заголовок » + «│» между ними.
    {
        let mut hits = v.hits.tabs.borrow_mut();
        let mut x = row.x;
        for (i, t) in titles.iter().enumerate() {
            let w = Line::from(t.as_str()).width() as u16 + 2;
            if x >= row.right() {
                break;
            }
            let w = w.min(row.right() - x);
            hits.push((Rect::new(x, row.y, w, 1), AdminTab::ALL[i]));
            x += w + 1;
        }
    }
    let tabs = Tabs::new(titles)
        .select(v.tab.index())
        .style(th.tab_inactive())
        .highlight_style(th.tab_active())
        .divider(Span::styled("│", th.unfocused_border))
        .padding(" ", " ");
    f.render_widget(tabs, row);
}

fn draw_table(f: &mut Frame, th: &Theme, v: &AdminView, area: Rect) {
    let len = v.len();
    if len == 0 {
        let msg = match v.tab {
            AdminTab::Bans => "Банов нет.",
            AdminTab::Invites => "Висящих приглашений нет.",
            AdminTab::Transfer => "В группе нет других участников — передавать некому.",
        };
        let p = Paragraph::new(Line::from(Span::styled(msg, th.dim))).wrap(Wrap { trim: true });
        f.render_widget(p, area);
        return;
    }

    let header_style = th.dim.add_modifier(Modifier::BOLD);
    let (header, widths, rows): (Row, Vec<Constraint>, Vec<Row>) = match v.tab {
        AdminTab::Bans => (
            Row::new(["Имя", "Ключ"]),
            vec![Constraint::Fill(1), Constraint::Length(10)],
            v.bans
                .iter()
                .map(|e| {
                    Row::new([
                        TCell::from(Span::styled(e.name.clone(), th.base)),
                        TCell::from(Span::styled(short_pk(&e.pk), th.dim)),
                    ])
                })
                .collect(),
        ),
        AdminTab::Invites => (
            Row::new(["Имя", "Ключ", "Истекает"]),
            vec![Constraint::Fill(1), Constraint::Length(10), Constraint::Length(11)],
            v.invites
                .iter()
                .map(|e| {
                    let exp_style = match e.expires_in_secs {
                        0 => th.error,
                        1..3600 => th.warn,
                        _ => th.base,
                    };
                    Row::new([
                        TCell::from(Span::styled(e.name.clone(), th.base)),
                        TCell::from(Span::styled(short_pk(&e.pk), th.dim)),
                        TCell::from(Span::styled(human_expiry(e.expires_in_secs), exp_style)),
                    ])
                })
                .collect(),
        ),
        AdminTab::Transfer => (
            Row::new(["Имя", "IP", "Ключ"]),
            vec![Constraint::Fill(1), Constraint::Length(15), Constraint::Length(10)],
            v.members
                .iter()
                .map(|e| {
                    Row::new([
                        TCell::from(Span::styled(e.name.clone(), th.base)),
                        TCell::from(Span::styled(e.ip.to_string(), th.accent)),
                        TCell::from(Span::styled(short_pk(&e.pk), th.dim)),
                    ])
                })
                .collect(),
        ),
    };

    // Справа место под полосу прокрутки.
    let visible = area.height.saturating_sub(1) as usize;
    let need_scroll = len > visible;
    let table_area = if need_scroll {
        Rect { width: area.width.saturating_sub(1), ..area }
    } else {
        area
    };

    let table = Table::new(rows, widths)
        .header(header.style(header_style))
        .column_spacing(1)
        .row_highlight_style(th.selected)
        .highlight_symbol("▌ ");
    let mut state = TableState::default();
    state.select(Some(v.selected.min(len - 1)));
    f.render_stateful_widget(table, table_area, &mut state);

    let rows_rect = Rect {
        y: area.y + 1,
        height: area.height.saturating_sub(1),
        ..table_area
    };
    v.hits.rows.set((rows_rect, state.offset()));

    if need_scroll {
        let mut sb = ScrollbarState::new(len.saturating_sub(visible))
            .position(state.offset())
            .viewport_content_length(visible);
        f.render_stateful_widget(
            Scrollbar::new(ScrollbarOrientation::VerticalRight)
                .track_style(th.scroll_track())
                .thumb_style(th.scroll_thumb()),
            area,
            &mut sb,
        );
    }
}

fn draw_actions(f: &mut Frame, th: &Theme, v: &AdminView, row: Rect) {
    let empty = v.is_empty();
    let enter = key(KeyCode::Enter);
    let main = match v.tab {
        AdminTab::Bans => ("Разбанить (Enter)", Btn::Primary),
        AdminTab::Invites => ("Отозвать приглашение (Enter)", Btn::Danger),
        AdminTab::Transfer => ("Передать владение (Enter)", Btn::Danger),
    };
    let refresh = ("Обновить (r)", Btn::Normal, key(KeyCode::Char('r')));
    let close = ("Закрыть (Esc)", Btn::Normal, key(KeyCode::Esc));
    // При пустом списке главная кнопка — нейтральная: делать нечего.
    let items = [(main.0, if empty { Btn::Normal } else { main.1 }, enter), refresh, close];
    if v.confirm.is_none() {
        draw_buttons(f, th, &v.hits.buttons, row, &items);
    } else {
        // Под подтверждением кнопки видны, но не кликаются.
        draw_buttons(f, th, &RefCell::new(Vec::new()), row, &items);
    }
}

fn draw_confirm(f: &mut Frame, th: &Theme, v: &AdminView, c: &TransferConfirm, area: Rect) {
    let rect = centered(area, 60, 8);
    v.hits.confirm.set(rect);
    f.render_widget(Clear, rect);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(th.error)
        .style(th.surface())
        .title(Line::from(Span::styled(" Передать владение? ", th.error)));
    let lines = vec![
        Line::from(vec![
            Span::styled("Новый владелец: ", th.base),
            Span::styled(c.name.clone(), th.title),
            Span::styled(format!(" ({})", short_pk(&c.pk)), th.dim),
        ]),
        Line::from(Span::styled(
            "Вы станете обычным участником. Отменить нельзя.",
            th.warn,
        )),
    ];
    let inner = block.inner(rect);
    f.render_widget(Paragraph::new(lines).wrap(Wrap { trim: true }).block(block), rect);
    if inner.height >= 2 {
        let row = Rect { y: inner.bottom() - 1, height: 1, ..inner };
        draw_buttons(
            f,
            th,
            &v.hits.buttons,
            row,
            &[
                ("Да, передать (y)", Btn::Danger, key(KeyCode::Char('y'))),
                ("Отмена (n/Esc)", Btn::Normal, key(KeyCode::Esc)),
            ],
        );
    }
}

// ---------------------------------------------------------------- тесты

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::ThemeKind;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::buffer::Buffer;

    fn pk(n: u8) -> [u8; 32] {
        [n; 32]
    }

    fn demo() -> AdminView {
        let mut v = AdminView::new(7, "Дача");
        v.set_data(
            vec![
                BanEntry { pk: pk(1), name: "troll".into() },
                BanEntry { pk: pk(2), name: "спамер".into() },
            ],
            vec![
                InviteEntry { pk: pk(3), name: "вася".into(), expires_in_secs: 6 * 86400 + 100 },
                InviteEntry { pk: pk(4), name: "петя".into(), expires_in_secs: 3 * 3600 + 5 },
            ],
            vec![
                MemberEntry { pk: pk(5), name: "маша".into(), ip: Ipv4Addr::new(10, 66, 0, 5) },
                MemberEntry { pk: pk(6), name: "коля".into(), ip: Ipv4Addr::new(10, 66, 0, 6) },
            ],
        );
        v
    }

    fn render(v: &AdminView, kind: ThemeKind, w: u16, h: u16) -> Buffer {
        let th = Theme::of(kind);
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, &th, v, f.area())).unwrap();
        term.backend().buffer().clone()
    }

    fn text(buf: &Buffer) -> String {
        let a = buf.area;
        let mut out = String::new();
        for y in 0..a.height {
            for x in 0..a.width {
                out.push_str(buf[(x, y)].symbol());
            }
            out.push('\n');
        }
        out
    }

    /// Координаты первого вхождения `needle` в экран.
    fn find(buf: &Buffer, needle: &str) -> (u16, u16) {
        let a = buf.area;
        let first: char = needle.chars().next().unwrap();
        let n = needle.chars().count();
        for y in 0..a.height {
            for x in 0..a.width {
                if !buf[(x, y)].symbol().starts_with(first) {
                    continue;
                }
                let s: String = (0..n as u16)
                    .filter(|i| x + i < a.width)
                    .map(|i| buf[(x + i, y)].symbol().to_string())
                    .collect();
                if s == needle {
                    return (x, y);
                }
            }
        }
        panic!("не нашли {needle:?} на экране:\n{}", text(buf));
    }

    fn click(x: u16, y: u16) -> MouseEvent {
        MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: x,
            row: y,
            modifiers: KeyModifiers::NONE,
        }
    }

    fn k(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn срок_истечения_по_человечески() {
        assert_eq!(human_expiry(0), "истекло");
        assert_eq!(human_expiry(30), "ещё <1 мин");
        assert_eq!(human_expiry(5 * 60), "ещё 5 мин");
        assert_eq!(human_expiry(3 * 3600 + 59), "ещё 3 ч");
        assert_eq!(human_expiry(6 * 86400 + 3600), "ещё 6 д");
    }

    #[test]
    fn снимок_одинаков_во_всех_темах_и_стили_из_палитры() {
        let mut snaps = Vec::new();
        for kind in ThemeKind::ALL {
            let th = Theme::of(kind);
            let mut v = demo();
            for tab in AdminTab::ALL {
                v.set_tab(tab);
                let buf = render(&v, kind, 80, 20);
                let s = text(&buf);
                assert!(s.contains("Управление группой «Дача»"), "{s}");
                assert!(s.contains("Баны (2)") && s.contains("Приглашения (2)"), "{s}");
                // Скруглённая рамка цвета акцента.
                let (x0, y0) = find(&buf, "╭");
                assert_eq!(buf[(x0, y0)].fg, th.accent.fg.unwrap());
                // Внутренность попапа — фон панели темы, а не «дыра».
                assert_eq!(buf[(x0 + 1, y0 + 1)].bg, th.c.surface, "{kind:?}");
                // Активная вкладка и обычные кнопки — из палитры.
                let active = th.tab_active();
                let (x, y) = find(&buf, &tab_title(&v, tab));
                assert_eq!(buf[(x, y)].bg, active.bg.unwrap(), "{kind:?} {tab:?}");
                let (x, y) = find(&buf, " Обновить");
                assert_eq!(buf[(x, y)].bg, th.c.button_bg);
                match tab {
                    AdminTab::Bans => {
                        assert!(s.contains("troll") && s.contains("01010101…"), "{s}");
                        let (x, y) = find(&buf, " Разбанить");
                        assert_eq!(buf[(x, y)].bg, th.c.accent, "Btn::Primary");
                    }
                    AdminTab::Invites => {
                        assert!(s.contains("ещё 6 д") && s.contains("ещё 3 ч"), "{s}");
                        let (x, y) = find(&buf, " Отозвать приглашение");
                        assert_eq!(buf[(x, y)].bg, th.c.danger, "Btn::Danger");
                    }
                    AdminTab::Transfer => {
                        assert!(s.contains("маша") && s.contains("10.66.0.5"), "{s}");
                        let (x, y) = find(&buf, " Передать владение (Enter)");
                        assert_eq!(buf[(x, y)].bg, th.c.danger, "Btn::Danger");
                    }
                }
                snaps.push((tab, s));
            }
        }
        // Текст не зависит от темы — только цвета.
        for (tab, s) in &snaps {
            let first = &snaps.iter().find(|(t, _)| t == tab).unwrap().1;
            assert_eq!(s, first);
        }
    }

    #[test]
    fn узкие_и_низкие_экраны_не_паникуют() {
        for kind in ThemeKind::ALL {
            let mut v = demo();
            for tab in AdminTab::ALL {
                v.set_tab(tab);
                for (w, h) in [(80, 24), (40, 12), (30, 10), (20, 6), (10, 4), (3, 3), (1, 1), (0, 0)] {
                    let _ = render(&v, kind, w, h);
                }
                v.confirm = Some(TransferConfirm { pk: pk(5), name: "маша".into() });
                for (w, h) in [(40, 12), (20, 6), (5, 3)] {
                    let _ = render(&v, kind, w, h);
                }
                v.confirm = None;
            }
        }
        // На 40 колонках видны рамка и первая кнопка.
        let v = demo();
        let s = text(&render(&v, ThemeKind::Dark, 40, 12));
        assert!(s.contains("Разбанить") && s.contains("troll"), "{s}");
    }

    #[test]
    fn длинный_список_прокручивается_с_полосой() {
        let mut v = AdminView::new(1, "g");
        let bans = (0..40u8).map(|i| BanEntry { pk: pk(i), name: format!("user{i}") }).collect();
        v.set_data(bans, vec![], vec![]);
        handle_key(&mut v, k(KeyCode::End));
        assert_eq!(v.selected, 39);
        let buf = render(&v, ThemeKind::Dark, 80, 30);
        let s = text(&buf);
        assert!(s.contains("user39") && !s.contains("user0 "), "{s}");
        assert!(s.contains('█') || s.contains('▐') || s.contains('║'), "нет полосы: {s}");
        let (_, off) = v.hits.rows.get();
        assert!(off > 0);
    }

    #[test]
    fn пустые_вкладки() {
        let mut v = AdminView::new(1, "g");
        let s = text(&render(&v, ThemeKind::Light, 80, 20));
        assert!(s.contains("Банов нет"), "{s}");
        assert_eq!(handle_key(&mut v, k(KeyCode::Enter)), None);
        v.set_tab(AdminTab::Transfer);
        let s = text(&render(&v, ThemeKind::Light, 80, 20));
        assert!(s.contains("передавать некому"), "{s}");
        assert_eq!(handle_key(&mut v, k(KeyCode::Enter)), None);
        assert!(v.confirm.is_none());
    }

    #[test]
    fn клавиши_действия_по_вкладкам() {
        let mut v = demo();
        assert_eq!(handle_key(&mut v, k(KeyCode::Down)), None);
        assert_eq!(v.selected, 1);
        assert_eq!(handle_key(&mut v, k(KeyCode::Down)), None);
        assert_eq!(v.selected, 1, "упор в край");
        assert_eq!(handle_key(&mut v, k(KeyCode::Enter)), Some(AdminAction::Unban(7, pk(2))));

        assert_eq!(handle_key(&mut v, k(KeyCode::Tab)), None);
        assert_eq!(v.tab, AdminTab::Invites);
        assert_eq!(v.selected, 0, "смена вкладки сбрасывает выбор");
        assert_eq!(
            handle_key(&mut v, k(KeyCode::Delete)),
            Some(AdminAction::RevokeInvite(7, pk(3)))
        );

        assert_eq!(handle_key(&mut v, k(KeyCode::Char('3'))), None);
        assert_eq!(v.tab, AdminTab::Transfer);
        assert_eq!(handle_key(&mut v, k(KeyCode::Char('r'))), Some(AdminAction::Refresh(7)));
        assert_eq!(handle_key(&mut v, k(KeyCode::BackTab)), None);
        assert_eq!(v.tab, AdminTab::Invites);
        assert_eq!(handle_key(&mut v, k(KeyCode::Left)), None);
        assert_eq!(v.tab, AdminTab::Bans);
        assert_eq!(handle_key(&mut v, k(KeyCode::Esc)), Some(AdminAction::Close));
    }

    #[test]
    fn передача_владения_только_после_подтверждения() {
        let mut v = demo();
        handle_key(&mut v, k(KeyCode::Char('3')));
        handle_key(&mut v, k(KeyCode::Down));
        assert_eq!(handle_key(&mut v, k(KeyCode::Enter)), None);
        assert_eq!(v.confirm.as_ref().unwrap().pk, pk(6));
        // Esc в подтверждении — отмена, а не закрытие попапа.
        assert_eq!(handle_key(&mut v, k(KeyCode::Esc)), None);
        assert!(v.confirm.is_none());
        // Пока открыто подтверждение, прочие клавиши ничего не делают.
        handle_key(&mut v, k(KeyCode::Enter));
        assert_eq!(handle_key(&mut v, k(KeyCode::Tab)), None);
        assert_eq!(v.tab, AdminTab::Transfer);
        assert_eq!(handle_key(&mut v, k(KeyCode::Char('y'))), Some(AdminAction::Transfer(7, pk(6))));
        assert!(v.confirm.is_none());
    }

    #[test]
    fn двойной_enter_не_передаёт_владение() {
        let mut v = demo();
        handle_key(&mut v, k(KeyCode::Char('3')));
        assert_eq!(handle_key(&mut v, k(KeyCode::Enter)), None);
        assert!(v.confirm.is_some());
        // Второй Enter (автоповтор) — ничего, окно остаётся.
        assert_eq!(handle_key(&mut v, k(KeyCode::Enter)), None);
        assert_eq!(handle_key(&mut v, k(KeyCode::Enter)), None);
        assert!(v.confirm.is_some());
    }

    #[test]
    fn подтверждение_по_физическим_клавишам() {
        let mut v = demo();
        v.set_tab(AdminTab::Transfer);
        // Русская раскладка: физическая N — «т», отмена.
        handle_key(&mut v, k(KeyCode::Enter));
        assert_eq!(handle_key(&mut v, k(KeyCode::Char('т'))), None);
        assert!(v.confirm.is_none());
        // «д» (физическая L) — не подтверждение.
        handle_key(&mut v, k(KeyCode::Enter));
        assert_eq!(handle_key(&mut v, k(KeyCode::Char('д'))), None);
        assert!(v.confirm.is_some());
        // Физическая Y — «н», подтверждение.
        assert_eq!(handle_key(&mut v, k(KeyCode::Char('н'))), Some(AdminAction::Transfer(7, pk(5))));
    }

    #[test]
    fn окно_подтверждения_в_цветах_темы() {
        for kind in ThemeKind::ALL {
            let th = Theme::of(kind);
            let mut v = demo();
            v.set_tab(AdminTab::Transfer);
            handle_key(&mut v, k(KeyCode::Enter));
            let buf = render(&v, kind, 80, 20);
            let (x, y) = find(&buf, "Новый владелец");
            assert_eq!(buf[(x, y)].bg, th.c.surface, "{kind:?}");
            let (x, y) = find(&buf, " Да, передать");
            assert_eq!(buf[(x, y)].bg, th.c.danger, "{kind:?}");
        }
    }

    #[test]
    fn подтверждение_сбрасывается_если_участник_ушёл() {
        let mut v = demo();
        v.set_tab(AdminTab::Transfer);
        handle_key(&mut v, k(KeyCode::Enter));
        assert!(v.confirm.is_some());
        let members = vec![MemberEntry { pk: pk(6), name: "коля".into(), ip: Ipv4Addr::new(10, 66, 0, 6) }];
        v.set_data(v.bans.clone(), v.invites.clone(), members);
        assert!(v.confirm.is_none());
        assert_eq!(v.selected, 0);
    }

    #[test]
    fn мышь_вкладки_строки_кнопки() {
        let mut v = demo();
        let buf = render(&v, ThemeKind::Dark, 80, 20);
        // Клик по вкладке «Приглашения».
        let (x, y) = find(&buf, "Приглашения");
        assert_eq!(handle_mouse(&mut v, click(x + 2, y)), None);
        assert_eq!(v.tab, AdminTab::Invites);

        let buf = render(&v, ThemeKind::Dark, 80, 20);
        let (x, y) = find(&buf, "петя");
        assert_eq!(handle_mouse(&mut v, click(x, y)), None);
        assert_eq!(v.selected, 1);
        let (x, y) = find(&buf, "Отозвать");
        assert_eq!(handle_mouse(&mut v, click(x, y)), Some(AdminAction::RevokeInvite(7, pk(4))));

        // Колесо — выбор с упором в края.
        let wheel = |kind| MouseEvent { kind, column: 0, row: 0, modifiers: KeyModifiers::NONE };
        handle_mouse(&mut v, wheel(MouseEventKind::ScrollUp));
        handle_mouse(&mut v, wheel(MouseEventKind::ScrollUp));
        assert_eq!(v.selected, 0);

        // Кнопка «Обновить» и клик мимо попапа.
        let (x, y) = find(&buf, "Обновить");
        assert_eq!(handle_mouse(&mut v, click(x, y)), Some(AdminAction::Refresh(7)));
        assert_eq!(handle_mouse(&mut v, click(0, 0)), Some(AdminAction::Close));
    }

    #[test]
    fn мышь_подтверждение_передачи() {
        let mut v = demo();
        v.set_tab(AdminTab::Transfer);
        let buf = render(&v, ThemeKind::Contrast, 80, 20);
        let (x, y) = find(&buf, "Передать владение (Enter)");
        assert_eq!(handle_mouse(&mut v, click(x, y)), None);
        assert!(v.confirm.is_some());

        let buf = render(&v, ThemeKind::Contrast, 80, 20);
        let s = text(&buf);
        assert!(s.contains("Передать владение?") && s.contains("маша"), "{s}");
        // Клик мимо окна подтверждения — только отмена.
        assert_eq!(handle_mouse(&mut v, click(0, 0)), None);
        assert!(v.confirm.is_none());

        handle_key(&mut v, k(KeyCode::Enter));
        let buf = render(&v, ThemeKind::Contrast, 80, 20);
        let (x, y) = find(&buf, "Да, передать");
        assert_eq!(handle_mouse(&mut v, click(x, y)), Some(AdminAction::Transfer(7, pk(5))));
    }
}
