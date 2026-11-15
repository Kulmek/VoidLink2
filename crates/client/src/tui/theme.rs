//! Цветовые темы TUI.

use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThemeKind {
    Dark,
    Light,
    Contrast,
}

impl ThemeKind {
    pub fn next(self) -> Self {
        match self {
            ThemeKind::Dark => ThemeKind::Light,
            ThemeKind::Light => ThemeKind::Contrast,
            ThemeKind::Contrast => ThemeKind::Dark,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            ThemeKind::Dark => "тёмная",
            ThemeKind::Light => "светлая",
            ThemeKind::Contrast => "контрастная",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "light" => Some(ThemeKind::Light),
            "contrast" => Some(ThemeKind::Contrast),
            "dark" => Some(ThemeKind::Dark),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ThemeKind::Dark => "dark",
            ThemeKind::Light => "light",
            ThemeKind::Contrast => "contrast",
        }
    }
}

/// Набор стилей для отрисовки.
#[derive(Clone, Copy)]
pub struct Theme {
    pub base: Style,
    pub dim: Style,
    pub title: Style,
    pub accent: Style,
    pub direct: Style,
    pub relay: Style,
    pub offline: Style,
    pub error: Style,
    pub warn: Style,
    pub ok: Style,
    pub selected: Style,
    pub focused_border: Style,
    pub unfocused_border: Style,
}

impl Theme {
    pub fn of(kind: ThemeKind) -> Self {
        match kind {
            ThemeKind::Dark => Theme {
                base: Style::default().fg(Color::Gray),
                dim: Style::default().fg(Color::DarkGray),
                title: Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                accent: Style::default().fg(Color::Cyan),
                direct: Style::default().fg(Color::Green),
                relay: Style::default().fg(Color::Yellow),
                offline: Style::default().fg(Color::DarkGray),
                error: Style::default().fg(Color::Red),
                warn: Style::default().fg(Color::Yellow),
                ok: Style::default().fg(Color::Green),
                selected: Style::default().bg(Color::Rgb(38, 48, 60)).add_modifier(Modifier::BOLD),
                focused_border: Style::default().fg(Color::Cyan),
                unfocused_border: Style::default().fg(Color::DarkGray),
            },
            ThemeKind::Light => Theme {
                base: Style::default().fg(Color::Black),
                dim: Style::default().fg(Color::DarkGray),
                title: Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
                accent: Style::default().fg(Color::Blue),
                direct: Style::default().fg(Color::Green),
                relay: Style::default().fg(Color::Rgb(160, 100, 0)),
                offline: Style::default().fg(Color::Gray),
                error: Style::default().fg(Color::Red),
                warn: Style::default().fg(Color::Rgb(160, 100, 0)),
                ok: Style::default().fg(Color::Green),
                selected: Style::default().bg(Color::Rgb(200, 210, 225)).add_modifier(Modifier::BOLD),
                focused_border: Style::default().fg(Color::Blue),
                unfocused_border: Style::default().fg(Color::Gray),
            },
            ThemeKind::Contrast => Theme {
                base: Style::default().fg(Color::White),
                dim: Style::default().fg(Color::Gray),
                title: Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                accent: Style::default().fg(Color::Cyan),
                direct: Style::default().fg(Color::LightGreen).add_modifier(Modifier::BOLD),
                relay: Style::default().fg(Color::LightYellow),
                offline: Style::default().fg(Color::Gray),
                error: Style::default().fg(Color::LightRed).add_modifier(Modifier::BOLD),
                warn: Style::default().fg(Color::LightYellow),
                ok: Style::default().fg(Color::LightGreen),
                selected: Style::default().bg(Color::Blue).fg(Color::White).add_modifier(Modifier::BOLD),
                focused_border: Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
                unfocused_border: Style::default().fg(Color::Gray),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn тема_переключается_по_кругу() {
        assert_eq!(ThemeKind::Dark.next(), ThemeKind::Light);
        assert_eq!(ThemeKind::Light.next(), ThemeKind::Contrast);
        assert_eq!(ThemeKind::Contrast.next(), ThemeKind::Dark);
    }

    #[test]
    fn тема_читается_из_строки() {
        assert_eq!(ThemeKind::from_str("light"), Some(ThemeKind::Light));
        assert_eq!(ThemeKind::from_str("contrast"), Some(ThemeKind::Contrast));
        assert_eq!(ThemeKind::from_str("dark"), Some(ThemeKind::Dark));
        assert_eq!(ThemeKind::from_str("нет"), None);
        assert_eq!(ThemeKind::Light.as_str(), "light");
    }
}
