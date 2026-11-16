//! Отрисовка TUI: шапка, списки, таблица участников, лог, статус-бар, попапы.

use std::cell::RefCell;

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, List, ListItem, ListState, Paragraph, Row, Sparkline, Table,
    TableState, Wrap,
};
use ratatui::Frame;

use tunnel_protocol as proto;

use crate::tui::app::{
    App, ConfirmPopup, Focus, FriendCardPopup, InputPopup, ListPickPopup, MsgKind, PeerPickPopup,
    Popup, SettingsPopup, SETTING_ROWS, TOOLBAR,
};
use crate::tui::identicon::Identicon;
use crate::tui::theme::Theme;

pub fn draw(f: &mut Frame, app: &App) {
    let area = f.area();
    let th = Theme::of(app.theme_kind);

    // Геометрия для мыши собирается заново каждый кадр.
    app.hits.toolbar.borrow_mut().clear();
    app.hits.popup_buttons.borrow_mut().clear();
    app.hits.popup.set(Rect::default());
    app.hits.popup_off.set(0);

    let chunks = Layout::vertical([
        Constraint::Length(3),
        Constraint::Length(1),
        Constraint::Min(8),
        Constraint::Length(8),
        Constraint::Length(1),
    ])
    .split(area);

    draw_header(f, app, &th, chunks[0]);
    draw_toolbar(f, app, &th, chunks[1]);
    draw_body(f, app, &th, chunks[2]);
    draw_log(f, app, &th, chunks[3]);
    draw_status(f, app, &th, chunks[4]);

    if let Some(popup) = app.stack.last() {
        draw_popup(f, app, &th, popup, area);
    }
    draw_toasts(f, app, &th, area);
}

// ---------------------------------------------------------------- шапка

fn draw_header(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let conn_style = if app.connected { th.ok } else { th.error };
    let conn_text = if app.connected {
        "подключено"
    } else {
        "реконнект"
    };
    let server = if app.server_addr.is_empty() {
        "—".to_string()
    } else {
        app.server_addr.clone()
    };

    let mut spans = vec![Span::styled(
        format!(" {} ", app.my_name),
        th.title.add_modifier(Modifier::BOLD),
    )];
    if !app.my_status.is_empty() {
        spans.push(Span::styled(format!("· {} ", app.my_status), th.dim));
    }
    if !app.server_label.is_empty() {
        spans.push(Span::styled(format!("· {} ", app.server_label), th.dim));
    }
    spans.push(Span::styled("· сервер ", th.dim));
    spans.push(Span::styled(server, th.accent));
    spans.push(Span::styled(" · ", th.dim));
    spans.push(Span::styled(conn_text.to_string(), conn_style));
    if !app.status_msg.is_empty() {
        spans.push(Span::styled(format!(" · {}", app.status_msg), th.warn));
    }

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.focused_border)
        .title(Span::styled(
            " Tunnel ",
            th.title.add_modifier(Modifier::BOLD),
        ));
    let p = Paragraph::new(Line::from(spans)).block(block);
    f.render_widget(p, area);
}

// ---------------------------------------------------------------- панель действий

/// Кнопки-клавиши под шапкой: клик по ним = нажатие клавиши.
fn draw_toolbar(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let items: Vec<(&str, Style, KeyEvent)> = TOOLBAR
        .iter()
        .map(|(label, code, mods)| (*label, th.dim, KeyEvent::new(*code, *mods)))
        .collect();
    let row = Rect {
        x: area.x + 1,
        width: area.width.saturating_sub(1),
        ..area
    };
    draw_buttons(f, &app.hits.toolbar, row, &items, 1);
}

/// Строка кнопок-«чипов»: рисует их и запоминает в `hits`, куда кликать.
/// Кнопки, которые не влезли по ширине, не рисуются.
fn draw_buttons(
    f: &mut Frame,
    hits: &RefCell<Vec<(Rect, KeyEvent)>>,
    row: Rect,
    items: &[(&str, Style, KeyEvent)],
    gap: u16,
) {
    if row.width == 0 || row.height == 0 {
        return;
    }
    let mut hits = hits.borrow_mut();
    let mut spans = Vec::new();
    let mut x = row.x;
    for (label, style, key) in items {
        let chip = Span::styled(format!(" {label} "), style.add_modifier(Modifier::REVERSED));
        let w = chip.width() as u16;
        if x + w > row.right() {
            break;
        }
        hits.push((Rect::new(x, row.y, w, 1), *key));
        spans.push(chip);
        spans.push(Span::raw(" ".repeat(gap as usize)));
        x += w + gap;
    }
    f.render_widget(Paragraph::new(Line::from(spans)), Rect { height: 1, ..row });
}

/// Строка внутри рамки попапа (`n` — номер строки от верхней границы).
fn inner_row(rect: Rect, n: u16) -> Rect {
    let y = rect.y + 1 + n;
    if rect.width < 3 || y + 1 >= rect.bottom() {
        return Rect::default();
    }
    Rect::new(rect.x + 1, y, rect.width - 2, 1)
}

fn key(code: KeyCode) -> KeyEvent {
    KeyEvent::new(code, KeyModifiers::NONE)
}

// ---------------------------------------------------------------- тело

fn draw_body(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let cols = Layout::horizontal([Constraint::Percentage(32), Constraint::Min(40)]).split(area);
    let left = Layout::vertical([Constraint::Percentage(55), Constraint::Percentage(45)]).split(cols[0]);

    draw_groups(f, app, th, left[0]);
    draw_friends(f, app, th, left[1]);
    draw_peers(f, app, th, cols[1]);
}

fn block_with_focus(
    th: &Theme,
    title: String,
    focused: bool,
    bottom: Option<String>,
) -> Block<'static> {
    let mut b = Block::default().borders(Borders::ALL).title(title);
    b = b.border_style(if focused {
        th.focused_border
    } else {
        th.unfocused_border
    });
    if let Some(bottom) = bottom {
        b = b.title_bottom(Line::from(Span::styled(bottom, th.dim)).right_aligned());
    }
    b
}

fn draw_groups(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let list = app.visible_groups();
    let title = if app.filter.is_empty() {
        format!(" Группы ({}) ", list.len())
    } else {
        format!(" Группы /{} ({}) ", app.filter, list.len())
    };
    let block = block_with_focus(th, title, app.focus == Focus::Groups, None);

    let items: Vec<ListItem> = list
        .iter()
        .map(|g| {
            let (mark, mark_style) = if g.mine {
                ("●", th.ok)
            } else {
                ("○", th.dim)
            };
            let mut spans = vec![Span::styled(format!("{mark} "), mark_style)];
            spans.push(Span::styled(
                g.name.clone(),
                if g.mine { th.base } else { th.dim },
            ));
            if g.private {
                spans.push(Span::styled(" [priv]", th.warn));
            }
            if g.mine {
                spans.push(Span::styled(
                    format!("  {}/{}", g.online, g.total),
                    th.dim,
                ));
            } else if g.private {
                spans.push(Span::styled("  (по приглашению)", th.dim));
            } else {
                spans.push(Span::styled("  (публичная)", th.dim));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    if let Some(sel) = app
        .sel_group
        .and_then(|g| list.iter().position(|x| x.gid == g))
    {
        state.select(Some(sel));
    }
    let list = List::new(items)
        .block(block)
        .highlight_style(th.selected)
        .highlight_symbol("▌ ");
    f.render_stateful_widget(list, area, &mut state);
    app.hits.groups.set((area, state.offset()));
}

fn draw_friends(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let list = app.visible_friends();
    let title = if app.filter.is_empty() {
        format!(" Друзья ({}) ", list.len())
    } else {
        format!(" Друзья /{} ({}) ", app.filter, list.len())
    };
    let block = block_with_focus(th, title, app.focus == Focus::Friends, None);

    let items: Vec<ListItem> = list
        .iter()
        .map(|fr| {
            let (mark, style) = if fr.online {
                ("●", th.ok)
            } else {
                ("○", th.dim)
            };
            let mut spans = vec![Span::styled(format!("{mark} "), style)];
            spans.push(Span::styled(fr.alias.clone(), th.base));
            if fr.shared_groups > 0 {
                spans.push(Span::styled(
                    format!("  {} общих", fr.shared_groups),
                    th.dim,
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();

    let mut state = ListState::default();
    if let Some(sel) = app
        .sel_friend
        .and_then(|f| list.iter().position(|x| x.pubkey == f))
    {
        state.select(Some(sel));
    }
    let list = List::new(items)
        .block(block)
        .highlight_style(th.selected)
        .highlight_symbol("▌ ");
    f.render_stateful_widget(list, area, &mut state);
    app.hits.friends.set((area, state.offset()));
}

fn draw_peers(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let g = app.selected_group();
    let title = match g {
        Some(g) => {
            let kind = if g.private { "приватная" } else { "публичная" };
            let mine = g
                .my_ip
                .map(|ip| format!(" · мой IP {}", proto::ip_str(ip)))
                .unwrap_or_default();
            format!(" Группа {} «{}» ({}){mine} ", g.gid, g.name, kind)
        }
        None => " Группа ".to_string(),
    };
    let bottom = Some(format!(
        "сортировка: {} · s — сменить",
        app.sort.label()
    ));
    let block = block_with_focus(th, title, app.focus == Focus::Peers, bottom);

    let header = Row::new(vec![
        Cell::from("имя"),
        Cell::from("IP"),
        Cell::from("связь"),
        Cell::from("RTT"),
        Cell::from("статус"),
    ])
    .style(th.dim.add_modifier(Modifier::BOLD));

    let mut rows: Vec<Row> = Vec::new();

    // Строка «я».
    if let Some(g) = g {
        rows.push(Row::new(vec![
            Cell::from(format!("{} (я)", app.my_name)),
            Cell::from(g.my_ip.map(proto::ip_str).unwrap_or_default()),
            Cell::from("—"),
            Cell::from("—"),
            Cell::from(app.my_status.clone()),
        ]));
    }

    let peers = app.visible_peers();
    for p in peers.iter() {
        let link = if !p.online {
            ("офлайн", th.offline)
        } else if p.direct {
            ("direct", th.direct)
        } else {
            ("relay", th.relay)
        };
        let rtt = match p.rtt_ms {
            Some(v) => format!("{v} мс"),
            None => "—".to_string(),
        };
        let rtt_style = match p.rtt_ms {
            Some(v) if v < 50 => th.ok,
            Some(_) => th.relay,
            None => th.dim,
        };
        rows.push(
            Row::new(vec![
                Cell::from(p.name.clone()),
                Cell::from(proto::ip_str(p.ip)),
                Cell::from(Span::styled(link.0, link.1)),
                Cell::from(Span::styled(rtt, rtt_style)),
                Cell::from(p.status.clone()),
            ])
            .style(if p.online { th.base } else { th.offline }),
        );
    }

    if rows.len() <= 1 {
        rows.push(Row::new(vec![
            Cell::from("(пока никого нет)"),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
        ]));
    }

    let widths = [
        Constraint::Min(12),
        Constraint::Length(13),
        Constraint::Length(8),
        Constraint::Length(8),
        Constraint::Min(8),
    ];
    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(th.selected)
        .highlight_symbol("▌ ");

    let mut state = TableState::default();
    // Индексы в таблице: 0 — строка «я», дальше — участники.
    if let Some(sel) = app
        .sel_peer
        .and_then(|p| peers.iter().position(|x| x.pubkey == p))
    {
        state.select(Some(sel + 1));
    }
    f.render_stateful_widget(table, area, &mut state);
    app.hits.peers.set((area, state.offset()));
}

// ---------------------------------------------------------------- лог

fn draw_log(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let block = block_with_focus(
        th,
        " Лог ".to_string(),
        app.focus == Focus::Log,
        Some("PgUp/PgDn или колесо — прокрутка".to_string()),
    );
    let inner_height = area.height.saturating_sub(2) as usize;
    let total = app.log.len();
    let end = total.saturating_sub(app.log_scroll);
    let start = end.saturating_sub(inner_height);

    let lines: Vec<Line> = app.log[start..end]
        .iter()
        .map(|l| {
            let style = match l.kind {
                MsgKind::Info => th.dim,
                MsgKind::Ok => th.ok,
                MsgKind::Warn => th.warn,
                MsgKind::Error => th.error,
            };
            Line::from(vec![
                Span::styled(format!("{} ", hhmmss(l.at)), th.dim),
                Span::styled(l.text.clone(), style),
            ])
        })
        .collect();

    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
    app.hits.log.set(area);
}

// ---------------------------------------------------------------- статус

fn draw_status(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let cols = Layout::horizontal([Constraint::Min(30), Constraint::Length(26)]).split(area);

    let my_ip = app
        .selected_group()
        .and_then(|g| g.my_ip)
        .map(proto::ip_str)
        .unwrap_or_else(|| "—".into());
    let (direct, relay) = app
        .peers
        .iter()
        .fold((0usize, 0usize), |(d, r), p| {
            if !p.online {
                (d, r)
            } else if p.direct {
                (d + 1, r)
            } else {
                (d, r + 1)
            }
        });

    let rx_rate = app.rx_hist.last().copied().unwrap_or(0);
    let tx_rate = app.tx_hist.last().copied().unwrap_or(0);

    let mut spans = vec![
        Span::styled(" IP ", th.dim),
        Span::styled(my_ip, th.accent),
        Span::styled(format!("  direct {direct} / relay {relay}"), th.dim),
        Span::styled(
            format!("  группы {}", app.groups.iter().filter(|g| g.mine).count()),
            th.dim,
        ),
        Span::styled(format!("  фокус: {}", app.focus.label()), th.dim),
        Span::styled(
            format!(
                "  ↓{}/с ↑{}/с  пакеты {}/{}",
                kb(rx_rate),
                kb(tx_rate),
                app.rx_pkts,
                app.tx_pkts
            ),
            th.dim,
        ),
    ];
    if app.filtering {
        spans.push(Span::styled(format!("  /{}", app.filter), th.warn));
    }
    let p = Paragraph::new(Line::from(spans));
    f.render_widget(p, cols[0]);

    // Спарклайн трафика (последние секунды).
    let data = app.rx_hist.clone();
    let spark = Sparkline::default()
        .data(&data)
        .max(data.iter().copied().max().unwrap_or(1).max(1024))
        .style(th.direct);
    f.render_widget(spark, cols[1]);
}

// ---------------------------------------------------------------- тосты

fn draw_toasts(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    if app.toasts.is_empty() {
        return;
    }
    let n = app.toasts.len() as u16;
    let w = 52.min(area.width.saturating_sub(4));
    let h = (n + 2).min(area.height.saturating_sub(2));
    let x = area.x + area.width.saturating_sub(w + 1);
    let y = area.y + area.height.saturating_sub(h + 2);
    let rect = Rect {
        x,
        y,
        width: w,
        height: h,
    };
    f.render_widget(Clear, rect);
    let block = Block::default().borders(Borders::ALL).border_style(th.accent);
    let lines: Vec<Line> = app
        .toasts
        .iter()
        .map(|t| {
            let style = match t.kind {
                MsgKind::Info => th.base,
                MsgKind::Ok => th.ok,
                MsgKind::Warn => th.warn,
                MsgKind::Error => th.error,
            };
            Line::from(Span::styled(t.text.clone(), style))
        })
        .collect();
    let p = Paragraph::new(lines).block(block).wrap(Wrap { trim: true });
    f.render_widget(p, rect);
}

// ---------------------------------------------------------------- попапы

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

fn draw_popup(f: &mut Frame, app: &App, th: &Theme, popup: &Popup, area: Rect) {
    match popup {
        Popup::Help => {
            let lines = help_lines(th);
            let rect = centered(area, 72, lines.len() as u16 + 2);
            app.hits.popup.set(rect);
            f.render_widget(Clear, rect);
            let block = Block::default()
                .borders(Borders::ALL)
                .border_style(th.accent)
                .title(" Справка (F1) ")
                .title_bottom(Line::from(Span::styled(
                    " Esc или клик мимо окна — закрыть ",
                    th.dim,
                )));
            let p = Paragraph::new(lines).block(block);
            f.render_widget(p, rect);
        }
        Popup::Input(inp) => {
            let rect = centered(area, 70, 7);
            app.hits.popup.set(rect);
            f.render_widget(Clear, rect);
            draw_input(f, app, th, inp, rect);
        }
        Popup::Confirm(c) => {
            let rect = centered(area, 60, 7);
            app.hits.popup.set(rect);
            f.render_widget(Clear, rect);
            draw_confirm(f, app, th, c, rect);
        }
        Popup::PeerPick(p) => {
            let h = (p.items.len() as u16 + 4).min(20).max(8);
            let rect = centered(area, 60, h);
            app.hits.popup.set(rect);
            f.render_widget(Clear, rect);
            app.hits.popup_off.set(draw_peer_pick(f, th, p, rect));
        }
        Popup::FriendCard(c) => {
            // 5 строк identicon + 6 служебных + группы + кнопки + рамка.
            let h = (c.groups.len().max(1) as u16 + 14).min(26);
            let rect = centered(area, 56, h);
            app.hits.popup.set(rect);
            f.render_widget(Clear, rect);
            draw_friend_card(f, app, th, c, rect);
        }
        Popup::ListPick(p) => {
            let h = (p.items.len() as u16 + 4).min(20).max(8);
            let rect = centered(area, 56, h);
            app.hits.popup.set(rect);
            f.render_widget(Clear, rect);
            app.hits.popup_off.set(draw_list_pick(f, th, p, rect));
        }
        Popup::Settings(s) => {
            let rect = centered(area, 60, 12);
            app.hits.popup.set(rect);
            f.render_widget(Clear, rect);
            app.hits.popup_off.set(draw_settings(f, app, th, s, rect));
        }
        Popup::Profile => {
            // 5 строк identicon + 9 строк данных + кнопки + рамка.
            let rect = centered(area, 60, 17);
            app.hits.popup.set(rect);
            f.render_widget(Clear, rect);
            draw_profile(f, app, th, rect);
        }
    }
}

fn draw_input(f: &mut Frame, app: &App, th: &Theme, inp: &InputPopup, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.accent)
        .title(format!(" {} ", inp.title))
        .title_bottom(Line::from(Span::styled(inp.hint.clone(), th.dim)));
    let mut value = inp.value.clone();
    if matches!(inp.action, crate::tui::app::InputAction::Command) {
        value = format!(":{value}");
    }
    let text = Line::from(vec![
        Span::styled(value, th.base),
        Span::styled("▏", th.accent.add_modifier(Modifier::SLOW_BLINK)),
    ]);
    let mut lines = vec![text];
    if matches!(inp.action, crate::tui::app::InputAction::CreateGroup) {
        lines.push(Line::from(Span::styled(
            format!(
                "приватная группа: {}",
                if inp.private { "да (Tab или клик — переключить)" } else { "нет (Tab или клик — переключить)" }
            ),
            th.dim,
        )));
    }
    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
    draw_buttons(
        f,
        &app.hits.popup_buttons,
        inner_row(area, 3),
        &[
            ("OK (Enter)", th.ok, key(KeyCode::Enter)),
            ("Отмена (Esc)", th.dim, key(KeyCode::Esc)),
        ],
        2,
    );
}

fn draw_confirm(f: &mut Frame, app: &App, th: &Theme, c: &ConfirmPopup, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.warn)
        .title(format!(" {} ", c.title));
    let p = Paragraph::new(Line::from(c.message.clone())).block(block);
    f.render_widget(p, area);
    draw_buttons(
        f,
        &app.hits.popup_buttons,
        inner_row(area, 2),
        &[
            ("Да (y)", th.warn, key(KeyCode::Char('y'))),
            ("Отмена (Esc)", th.dim, key(KeyCode::Esc)),
        ],
        2,
    );
}

/// Возвращает смещение прокрутки списка (для мыши).
fn draw_peer_pick(f: &mut Frame, th: &Theme, p: &PeerPickPopup, area: Rect) -> usize {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.accent)
        .title(format!(" {} ", p.title))
        .title_bottom(Line::from(Span::styled(
            "клик — выбор, ещё клик/Enter — применить · Esc — отмена",
            th.dim,
        )));
    let items: Vec<ListItem> = p
        .items
        .iter()
        .map(|i| {
            let (mark, style) = if i.online {
                ("●", th.ok)
            } else {
                ("○", th.dim)
            };
            ListItem::new(Line::from(vec![
                Span::styled(format!("{mark} "), style),
                Span::styled(i.label.clone(), th.base),
                Span::styled(format!("  {}", i.sub), th.dim),
            ]))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(p.sel));
    let list = List::new(items)
        .block(block)
        .highlight_style(th.selected)
        .highlight_symbol("▌ ");
    f.render_stateful_widget(list, area, &mut state);
    state.offset()
}

fn draw_friend_card(f: &mut Frame, app: &App, th: &Theme, c: &FriendCardPopup, area: Rect) {
    let id = Identicon::from_pubkey(&c.pubkey);
    let mut lines: Vec<Line> = Vec::new();
    for r in 0..5 {
        let spans: Vec<Span> = id
            .row_line(r)
            .into_iter()
            .map(|(s, fg, bg)| Span::styled(s, Style::default().fg(fg).bg(bg)))
            .collect();
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("имя: ", th.dim),
        Span::styled(c.alias.clone(), th.base),
    ]));
    lines.push(Line::from(vec![
        Span::styled("pubkey: ", th.dim),
        Span::styled(proto::hex_of(&c.pubkey), th.dim),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled("группы друга:", th.title)));
    if c.loading {
        lines.push(Line::from(Span::styled("загрузка…", th.dim)));
    } else if c.groups.is_empty() {
        lines.push(Line::from(Span::styled(
            "(нет видимых групп)",
            th.dim,
        )));
    } else {
        for g in c.groups.iter() {
            lines.push(Line::from(vec![
                Span::styled(format!("{} ", g.gid), th.accent),
                Span::styled(g.name.clone(), th.base),
                Span::styled(
                    format!(
                        " {}",
                        if g.private { "[приватная]" } else { "[публичная]" }
                    ),
                    th.dim,
                ),
                Span::styled(if g.shared { "  (общая)" } else { "" }, th.ok),
            ]));
        }
    }
    lines.push(Line::from(""));
    let buttons_at = lines.len() as u16;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.accent)
        .title(format!(" Друг: {} ", c.alias));
    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
    draw_buttons(
        f,
        &app.hits.popup_buttons,
        inner_row(area, buttons_at),
        &[
            ("Копировать pubkey (c)", th.accent, key(KeyCode::Char('c'))),
            ("Закрыть (Esc)", th.dim, key(KeyCode::Esc)),
        ],
        2,
    );
}

fn draw_list_pick(f: &mut Frame, th: &Theme, p: &ListPickPopup, area: Rect) -> usize {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.accent)
        .title(format!(" {} ", p.title))
        .title_bottom(Line::from(Span::styled(
            "Enter или клик — выбрать · Esc — закрыть",
            th.dim,
        )));
    let items: Vec<ListItem> = p
        .items
        .iter()
        .map(|i| {
            let mark = if i.checked { "[x]" } else { "[ ]" };
            let mut spans = vec![
                Span::styled(format!("{mark} "), th.ok),
                Span::styled(i.label.clone(), th.base),
            ];
            if !i.value.is_empty() {
                spans.push(Span::styled(format!("  {}", i.value), th.dim));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let mut state = ListState::default();
    state.select(Some(p.sel));
    let list = List::new(items)
        .block(block)
        .highlight_style(th.selected)
        .highlight_symbol("▌ ");
    f.render_stateful_widget(list, area, &mut state);
    state.offset()
}

fn draw_settings(f: &mut Frame, app: &App, th: &Theme, s: &SettingsPopup, area: Rect) -> usize {
    let rows: Vec<(String, String)> = vec![
        (
            "имя".to_string(),
            if app.my_name.is_empty() {
                "(не задано)".into()
            } else {
                app.my_name.clone()
            },
        ),
        (
            "статус".to_string(),
            if app.my_status.is_empty() {
                "(не задан)".into()
            } else {
                app.my_status.clone()
            },
        ),
        (
            "сервер".to_string(),
            app.servers
                .first()
                .map(|s| s.addr.clone())
                .unwrap_or_else(|| "(нет)".into()),
        ),
        (
            "автовход".to_string(),
            if app.autojoin.is_empty() {
                "(нет)".into()
            } else {
                app.autojoin
                    .iter()
                    .map(|g| g.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        ),
        ("тема".to_string(), app.theme_kind.label().to_string()),
    ];

    let items: Vec<ListItem> = SETTING_ROWS
        .iter()
        .zip(rows.iter())
        .map(|(_, (label, value))| {
            ListItem::new(Line::from(vec![
                Span::styled(format!("{label:<12}"), th.dim),
                Span::styled(value.clone(), th.base),
            ]))
        })
        .collect();

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.accent)
        .title(" Настройки ")
        .title_bottom(Line::from(Span::styled(
            "Enter или клик — изменить · Esc — закрыть",
            th.dim,
        )));
    let mut state = ListState::default();
    state.select(Some(s.sel));
    let list = List::new(items)
        .block(block)
        .highlight_style(th.selected)
        .highlight_symbol("▌ ");
    f.render_stateful_widget(list, area, &mut state);
    state.offset()
}

fn draw_profile(f: &mut Frame, app: &App, th: &Theme, area: Rect) {
    let id = Identicon::from_pubkey(&app.my_pub);
    let mut lines: Vec<Line> = Vec::new();
    for r in 0..5 {
        let spans: Vec<Span> = id
            .row_line(r)
            .into_iter()
            .map(|(s, fg, bg)| Span::styled(s, Style::default().fg(fg).bg(bg)))
            .collect();
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![
        Span::styled("имя:     ", th.dim),
        Span::styled(app.my_name.clone(), th.base),
    ]));
    lines.push(Line::from(vec![
        Span::styled("статус:  ", th.dim),
        Span::styled(app.my_status.clone(), th.dim),
    ]));
    lines.push(Line::from(vec![
        Span::styled("friend code: ", th.dim),
        Span::styled(app.my_code.clone(), th.accent),
    ]));
    lines.push(Line::from(vec![
        Span::styled("группы:  ", th.dim),
        Span::styled(
            format!("{}", app.groups.iter().filter(|g| g.mine).count()),
            th.base,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled("друзья:  ", th.dim),
        Span::styled(app.friends.len().to_string(), th.base),
    ]));
    lines.push(Line::from(vec![
        Span::styled("в сети:  ", th.dim),
        Span::styled(uptime(app.started), th.base),
    ]));
    lines.push(Line::from(vec![
        Span::styled("трафик:  ", th.dim),
        Span::styled(
            format!(
                "↓ {} ↑ {} (пакетов {}/{})",
                kb(app.rx_bytes),
                kb(app.tx_bytes),
                app.rx_pkts,
                app.tx_pkts
            ),
            th.base,
        ),
    ]));
    lines.push(Line::from(""));
    let buttons_at = lines.len() as u16;

    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(th.accent)
        .title(" Профиль ");
    let p = Paragraph::new(lines).block(block);
    f.render_widget(p, area);
    draw_buttons(
        f,
        &app.hits.popup_buttons,
        inner_row(area, buttons_at),
        &[
            ("Копировать friend code (c)", th.accent, key(KeyCode::Char('c'))),
            ("Закрыть (Esc)", th.dim, key(KeyCode::Esc)),
        ],
        2,
    );
}

// ---------------------------------------------------------------- справка

fn help_lines(th: &Theme) -> Vec<Line<'static>> {
    let kv = |k: &str, v: &str| {
        Line::from(vec![
            Span::styled(format!("{k:<14}"), th.accent),
            Span::styled(v.to_string(), th.base),
        ])
    };
    vec![
        Line::from(Span::styled(
            "Навигация",
            th.title.add_modifier(Modifier::BOLD),
        )),
        kv("Tab / Shift-Tab", "смена фокуса (группы → друзья → участники → лог)"),
        kv("↑ ↓", "перемещение по списку"),
        kv("Enter", "войти в группу / карточка друга"),
        kv("/", "поиск по спискам (Esc — сбросить, Enter — принять)"),
        kv("s", "сменить сортировку (имя / онлайн / RTT)"),
        kv("r", "обновить список групп"),
        Line::from(""),
        Line::from(Span::styled(
            "Группы",
            th.title.add_modifier(Modifier::BOLD),
        )),
        kv("F2", "создать группу (Tab — приватная)"),
        kv("F6", "переименовать группу"),
        kv("F8", "удалить группу (только владелец)"),
        kv("j", "войти в публичную группу"),
        kv("x", "покинуть группу"),
        kv("i", "пригласить друга в группу"),
        kv("k / b", "исключить / забанить участника"),
        Line::from(""),
        Line::from(Span::styled(
            "Друзья и профиль",
            th.title.add_modifier(Modifier::BOLD),
        )),
        kv("a", "добавить друга по friend code"),
        kv("d", "удалить друга (с подтверждением)"),
        kv("c", "скопировать IP / pubkey / friend code"),
        kv("p", "карточка профиля"),
        kv("F3", "настройки (имя, сервер, автовход, тема)"),
        Line::from(""),
        Line::from(Span::styled(
            "Прочее",
            th.title.add_modifier(Modifier::BOLD),
        )),
        kv(":", "командная строка (:help — список)"),
        kv("PgUp / PgDn", "прокрутка лога"),
        kv("Ctrl-C", "выход (или :quit)"),
        Line::from(""),
        Line::from(Span::styled(
            "Мышь",
            th.title.add_modifier(Modifier::BOLD),
        )),
        kv("клик", "фокус и выбор строки; второй клик — как Enter"),
        kv("колесо", "прокрутка списка или лога под курсором"),
        kv("кнопки", "панель под шапкой и кнопки в окнах = клавиши"),
        kv("мимо окна", "закрыть окно (как Esc)"),
        kv("Shift+мышь", "выделить текст средствами терминала"),
    ]
}

// ---------------------------------------------------------------- время

/// Байты → человекочитаемый вид.
fn kb(v: u64) -> String {
    if v >= 1024 * 1024 {
        format!("{:.1} МБ", v as f64 / (1024.0 * 1024.0))
    } else if v >= 1024 {
        format!("{:.1} КБ", v as f64 / 1024.0)
    } else {
        format!("{v} Б")
    }
}

/// Время в формате ч:м:с (аптайм).
fn uptime(t: std::time::Instant) -> String {
    let secs = t.elapsed().as_secs();
    format!("{:02}:{:02}:{:02}", secs / 3600, (secs / 60) % 60, secs % 60)
}

fn hhmmss(t: std::time::Instant) -> String {
    let secs = t.elapsed().as_secs();
    format!("{:02}:{:02}:{:02}", (secs / 3600) % 24, (secs / 60) % 60, secs % 60)
}

/// Простейший горизонтальный спарклайн-подобный индикатор (для тестов).
#[allow(dead_code)]
fn bar(value: u64, max: u64, width: usize) -> String {
    if max == 0 {
        return " ".repeat(width);
    }
    let filled = ((value as f64 / max as f64) * width as f64) as usize;
    let mut s = String::new();
    for i in 0..width {
        s.push(if i < filled { '█' } else { '·' });
    }
    s
}

/// Пустое пространство для выравнивания.
#[allow(dead_code)]
fn pad(s: &str, width: usize) -> String {
    let len = s.chars().count();
    if len >= width {
        s.to_string()
    } else {
        format!("{s}{}", " ".repeat(width - len))
    }
}

/// Стиль по умолчанию для пустых ячеек.
#[allow(dead_code)]
fn empty_style() -> Style {
    Style::default().fg(Color::DarkGray)
}

/// Выравнивание по центру (утилита).
#[allow(dead_code)]
fn center() -> Alignment {
    Alignment::Center
}

// ---------------------------------------------------------------- тесты

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::Config;
    use crate::tui::app::{App, FriendView, GroupView, PeerView};
    use ratatui::backend::TestBackend;
    use ratatui::Terminal;

    fn demo_app() -> App {
        let mut app = App::new([9; 32], "TUN-TEST-CODE-TEST-CODE", &Config::default());
        app.my_name = "alpha".into();
        app.my_status = "в сети".into();
        app.connected = true;
        app.server_addr = "127.0.0.1:5599".into();
        app.groups = vec![
            GroupView {
                gid: 1,
                name: "gamers".into(),
                private: false,
                mine: true,
                online: 2,
                total: 2,
                my_ip: Some(0x6442_0102),
                owner_is_me: true,
                peers: vec![PeerView {
                    pubkey: [2; 32],
                    name: "bravo".into(),
                    ip: 0x6442_0103,
                    online: true,
                    direct: true,
                    rtt_ms: Some(7),
                    status: "ok".into(),
                }],
            },
            GroupView {
                gid: 2,
                name: "secret".into(),
                private: true,
                mine: false,
                online: 1,
                total: 1,
                my_ip: None,
                owner_is_me: false,
                peers: vec![],
            },
        ];
        app.peers = vec![PeerView {
            pubkey: [2; 32],
            name: "bravo".into(),
            ip: 0x6442_0103,
            online: true,
            direct: true,
            rtt_ms: Some(7),
            status: "ok".into(),
        }];
        app.friends = vec![FriendView {
            alias: "bravo".into(),
            pubkey: [2; 32],
            online: true,
            shared_groups: 1,
        }];
        app.sel_group = Some(1);
        app
    }

    fn render(app: &App, w: u16, h: u16) -> String {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
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
    fn основной_экран_содержит_ключевое() {
        let text = render(&demo_app(), 140, 40);
        assert!(text.contains("Группы"), "нет блока групп:\n{text}");
        assert!(text.contains("gamers"), "нет группы gamers");
        assert!(text.contains("Друзья"), "нет блока друзей");
        assert!(text.contains("bravo"), "нет друга bravo");
        assert!(text.contains("direct"), "нет метки direct");
        assert!(text.contains("7 мс"), "нет RTT");
        assert!(text.contains("100.66.1.2"), "нет своего IP");
        assert!(text.contains("подключено"), "нет статуса соединения");
    }

    #[test]
    fn попапы_отрисовываются() {
        let mut app = demo_app();
        app.stack.push(Popup::Help);
        let text = render(&app, 140, 40);
        assert!(text.contains("Справка"), "нет оверлея справки");
        assert!(text.contains("Создать группу") || text.contains("создать группу"));

        let mut app = demo_app();
        app.stack.push(Popup::Profile);
        let text = render(&app, 140, 40);
        assert!(text.contains("Профиль"));
        assert!(text.contains("TUN-TEST-CODE"));

        let mut app = demo_app();
        app.stack.push(Popup::Settings(crate::tui::app::SettingsPopup { sel: 0 }));
        let text = render(&app, 140, 40);
        assert!(text.contains("Настройки"));
    }

    #[test]
    fn узкий_экран_не_паникует() {
        for (w, h) in [(40u16, 12u16), (80, 24), (200, 60)] {
            let _ = render(&demo_app(), w, h);
        }
    }

    /// Служебный тест: печатает отрисованный экран (запуск с --nocapture).
    #[test]
    fn печать_экрана() {
        let text = render(&demo_app(), 140, 36);
        println!("{text}");
    }

    // ---------- мышь ----------

    use crate::tui::app::{ConfirmAction, Hit};
    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    /// Рисует кадр (это заполняет `app.hits`) и возвращает экран построчно,
    /// по одному символу на клетку.
    fn frame(app: &App, w: u16, h: u16) -> Vec<Vec<char>> {
        let mut term = Terminal::new(TestBackend::new(w, h)).unwrap();
        term.draw(|f| draw(f, app)).unwrap();
        let buf = term.backend().buffer().clone();
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().chars().next().unwrap_or(' '))
                    .collect()
            })
            .collect()
    }

    /// Координаты первого вхождения `text` правее `min_x`.
    fn find(screen: &[Vec<char>], text: &str, min_x: usize) -> (u16, u16) {
        let pat: Vec<char> = text.chars().collect();
        for (y, row) in screen.iter().enumerate() {
            for x in min_x..row.len().saturating_sub(pat.len() - 1) {
                if row[x..x + pat.len()] == pat[..] {
                    return (x as u16, y as u16);
                }
            }
        }
        panic!("на экране нет «{text}»");
    }

    fn k(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn мышь_попадание_в_панели_и_кнопки() {
        let app = demo_app();
        let s = frame(&app, 140, 40);

        let (x, y) = find(&s, "secret", 0);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Groups, 1));
        let (x, y) = find(&s, "● gamers", 0);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Groups, 0));

        // «bravo» есть и в друзьях (слева), и в таблице участников (справа).
        let (x, y) = find(&s, "● bravo", 0);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Friends, 0));
        let (x, y) = find(&s, "bravo", 40);
        assert_eq!(app.hit(x, y), Hit::Item(Focus::Peers, 0));
        // Строка «я» и заголовок таблицы — мимо участников.
        let (x, y) = find(&s, "alpha (я)", 40);
        assert_eq!(app.hit(x, y), Hit::Panel(Focus::Peers));

        let (x, y) = find(&s, "F3 настройки", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::F(3))));
        let (x, y) = find(&s, "^C выход", 0);
        assert_eq!(
            app.hit(x + 1, y),
            Hit::Key(KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL))
        );

        let (x, y) = find(&s, "Лог", 0);
        assert_eq!(app.hit(x, y + 1), Hit::Panel(Focus::Log));
        // Шапка — не кликабельна.
        assert_eq!(app.hit(1, 1), Hit::Nothing);
    }

    #[test]
    fn мышь_клик_выбирает_второй_применяет() {
        let mut app = demo_app();
        let _ = frame(&app, 140, 40);
        // Фокус на группах, выбрана группа 1: клик по группе 2 только выбирает.
        assert!(!app.select_item(Focus::Groups, 1));
        assert_eq!(app.sel_group, Some(2));
        // Повторный клик по той же строке — «Enter».
        assert!(app.select_item(Focus::Groups, 1));
        // Клик в другой панели сначала переводит фокус.
        assert!(!app.select_item(Focus::Friends, 0));
        assert_eq!(app.focus, Focus::Friends);
        assert!(app.select_item(Focus::Friends, 0));
    }

    #[test]
    fn мышь_колесо_без_хода_по_кругу() {
        let mut app = demo_app();
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "● gamers", 0);
        app.wheel(x, y, -1);
        assert_eq!(app.sel_group, Some(1), "вверх с первой строки — стоим");
        app.wheel(x, y, 1);
        assert_eq!(app.sel_group, Some(2));
        app.wheel(x, y, 1);
        assert_eq!(app.sel_group, Some(2), "вниз с последней — стоим");
    }

    #[test]
    fn мышь_попапы() {
        let mut app = demo_app();
        app.stack.push(Popup::Confirm(ConfirmPopup {
            title: "Удалить группу".into(),
            message: "Точно?".into(),
            action: ConfirmAction::DeleteGroup(1),
        }));
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "Да (y)", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Char('y'))));
        let (x, y) = find(&s, "Отмена (Esc)", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Esc)));
        let (x, y) = find(&s, "Точно?", 0);
        assert_eq!(app.hit(x, y), Hit::PopupInside);
        assert_eq!(app.hit(0, 0), Hit::PopupOutside);

        let mut app = demo_app();
        app.stack.push(Popup::Settings(SettingsPopup { sel: 0 }));
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "тема", 0);
        assert_eq!(app.hit(x, y), Hit::PopupItem(4));
        // Клик по строке настроек применяется сразу.
        assert!(app.click_popup_item(4));
        match app.stack.last() {
            Some(Popup::Settings(s)) => assert_eq!(s.sel, 4),
            _ => panic!("нет попапа настроек"),
        }

        let mut app = demo_app();
        app.stack.push(Popup::Profile);
        let s = frame(&app, 140, 40);
        let (x, y) = find(&s, "Копировать friend code", 0);
        assert_eq!(app.hit(x, y), Hit::Key(k(KeyCode::Char('c'))));
    }
}
