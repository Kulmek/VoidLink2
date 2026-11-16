//! Цветовые темы TUI.
//!
//! Каждая тема — явная RGB-палитра ([`Palette`]): терминал может быть
//! настроен как угодно, поэтому фон кадра красится самой темой и светлая тема
//! не зависит от фона терминала. Из палитры собираются готовые стили
//! ([`Theme`]) для виджетов: панели, таблицы, кнопки, вкладки, шкалы, графики.

use ratatui::style::{Color, Modifier, Style};

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ThemeKind {
    Dark,
    Light,
    Contrast,
    Amber,
    Fjord,
}

impl ThemeKind {
    /// Все темы в порядке переключения.
    pub const ALL: [ThemeKind; 5] = [
        ThemeKind::Dark,
        ThemeKind::Light,
        ThemeKind::Contrast,
        ThemeKind::Amber,
        ThemeKind::Fjord,
    ];

    /// Следующая тема по кругу (порядок — [`ThemeKind::ALL`]).
    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|k| *k == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }

    pub fn label(self) -> &'static str {
        match self {
            ThemeKind::Dark => "тёмная",
            ThemeKind::Light => "светлая",
            ThemeKind::Contrast => "контрастная",
            ThemeKind::Amber => "янтарная",
            ThemeKind::Fjord => "фьорд",
        }
    }

    /// Ключ темы в client.json. Неизвестный ключ → `None` (вызывающий
    /// подставляет тёмную тему).
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "light" => Some(ThemeKind::Light),
            "contrast" => Some(ThemeKind::Contrast),
            "dark" => Some(ThemeKind::Dark),
            "amber" => Some(ThemeKind::Amber),
            "fjord" => Some(ThemeKind::Fjord),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ThemeKind::Dark => "dark",
            ThemeKind::Light => "light",
            ThemeKind::Contrast => "contrast",
            ThemeKind::Amber => "amber",
            ThemeKind::Fjord => "fjord",
        }
    }
}

/// Роли цветов темы.
#[derive(Clone, Copy, Debug)]
pub struct Palette {
    /// Фон кадра.
    pub bg: Color,
    /// Фон панелей и окон.
    pub surface: Color,
    /// Фон шапки, заголовка таблицы, поля ввода.
    pub header_bg: Color,
    pub border: Color,
    pub border_focused: Color,
    pub text: Color,
    pub text_muted: Color,
    pub accent: Color,
    pub accent_alt: Color,
    pub success: Color,
    pub warn: Color,
    pub danger: Color,
    /// Текст поверх заливки акцентным/семантическим цветом (кнопки, «пилюли»).
    pub on_fill: Color,
    /// Выбранная строка в панели с фокусом.
    pub sel_bg: Color,
    pub sel_fg: Color,
    /// Выбранная строка в панели без фокуса.
    pub sel_inactive_bg: Color,
    pub gauge_fill: Color,
    pub gauge_empty: Color,
    pub scroll_thumb: Color,
    pub scroll_track: Color,
    /// Обычная кнопка; основная — `accent`, опасная — `danger` (текст `on_fill`).
    pub button_bg: Color,
    pub button_fg: Color,
    pub tab_active_bg: Color,
    pub tab_active_fg: Color,
    pub tab_inactive: Color,
    /// Графики трафика: приём / передача.
    pub chart_rx: Color,
    pub chart_tx: Color,
}

const fn rgb(hex: u32) -> Color {
    Color::Rgb((hex >> 16) as u8, (hex >> 8) as u8, hex as u8)
}

impl Palette {
    pub const fn of(kind: ThemeKind) -> Self {
        match kind {
            // Глубокий сине-серый, один акцент — небесно-голубой.
            ThemeKind::Dark => Palette {
                bg: rgb(0x11161E),
                surface: rgb(0x161C26),
                header_bg: rgb(0x1C2430),
                border: rgb(0x344052),
                border_focused: rgb(0x5DB3F2),
                text: rgb(0xD8DEE8),
                text_muted: rgb(0x8D99AB),
                accent: rgb(0x5DB3F2),
                accent_alt: rgb(0xB79CFF),
                success: rgb(0x5CCB8A),
                warn: rgb(0xE6B65C),
                danger: rgb(0xF07583),
                on_fill: rgb(0x0D1219),
                sel_bg: rgb(0x284566),
                sel_fg: rgb(0xF2F6FB),
                sel_inactive_bg: rgb(0x222C3A),
                gauge_fill: rgb(0x5DB3F2),
                gauge_empty: rgb(0x2A3442),
                scroll_thumb: rgb(0x7D8DA3),
                scroll_track: rgb(0x344052),
                button_bg: rgb(0x273141),
                button_fg: rgb(0xD8DEE8),
                tab_active_bg: rgb(0x5DB3F2),
                tab_active_fg: rgb(0x0D1219),
                tab_inactive: rgb(0x8D99AB),
                chart_rx: rgb(0x5DB3F2),
                chart_tx: rgb(0xB79CFF),
            },
            // Светлая: тёмный текст на почти белом, насыщенные тёмные
            // семантические цвета (никакого жёлтого и серого на белом).
            ThemeKind::Light => Palette {
                bg: rgb(0xEEF1F5),
                surface: rgb(0xFBFCFD),
                header_bg: rgb(0xE2E7EE),
                border: rgb(0xA3AEBD),
                border_focused: rgb(0x1F66B8),
                text: rgb(0x18202B),
                text_muted: rgb(0x56606E),
                accent: rgb(0x1F66B8),
                accent_alt: rgb(0x7039B5),
                success: rgb(0x1D7A43),
                warn: rgb(0x8F5200),
                danger: rgb(0xBF2E3D),
                on_fill: rgb(0xFFFFFF),
                sel_bg: rgb(0xCFE0F5),
                sel_fg: rgb(0x0E1724),
                sel_inactive_bg: rgb(0xE3E8EF),
                gauge_fill: rgb(0x1F66B8),
                gauge_empty: rgb(0xD9DFE7),
                scroll_thumb: rgb(0x56606E),
                scroll_track: rgb(0xA3AEBD),
                button_bg: rgb(0xDDE3EA),
                button_fg: rgb(0x18202B),
                tab_active_bg: rgb(0x1F66B8),
                tab_active_fg: rgb(0xFFFFFF),
                tab_inactive: rgb(0x56606E),
                chart_rx: rgb(0x1F66B8),
                chart_tx: rgb(0x7039B5),
            },
            // Высокий контраст: чёрный фон, белый текст, яркие циан и жёлтый;
            // всё текстовое — не ниже 7:1.
            ThemeKind::Contrast => Palette {
                bg: rgb(0x000000),
                surface: rgb(0x000000),
                header_bg: rgb(0x141414),
                border: rgb(0xC8C8C8),
                border_focused: rgb(0x00E1FF),
                text: rgb(0xFFFFFF),
                text_muted: rgb(0xD2D2D2),
                accent: rgb(0x00E1FF),
                accent_alt: rgb(0xFFD000),
                success: rgb(0x45F37F),
                warn: rgb(0xFFD000),
                danger: rgb(0xFF7A7A),
                on_fill: rgb(0x000000),
                sel_bg: rgb(0xFFD000),
                sel_fg: rgb(0x000000),
                sel_inactive_bg: rgb(0x3A3A3A),
                gauge_fill: rgb(0x00E1FF),
                gauge_empty: rgb(0x333333),
                scroll_thumb: rgb(0xFFFFFF),
                scroll_track: rgb(0x8A8A8A),
                button_bg: rgb(0x2A2A2A),
                button_fg: rgb(0xFFFFFF),
                tab_active_bg: rgb(0xFFD000),
                tab_active_fg: rgb(0x000000),
                tab_inactive: rgb(0xD2D2D2),
                chart_rx: rgb(0x00E1FF),
                chart_tx: rgb(0xFFD000),
            },
            // Тёплая «янтарная»: тёмно-коричневый фон, медовый акцент.
            ThemeKind::Amber => Palette {
                bg: rgb(0x17120D),
                surface: rgb(0x1D1711),
                header_bg: rgb(0x261E16),
                border: rgb(0x4B3D2D),
                border_focused: rgb(0xF2A93B),
                text: rgb(0xEEDFCA),
                text_muted: rgb(0xA9967E),
                accent: rgb(0xF2A93B),
                accent_alt: rgb(0xE8826A),
                success: rgb(0xA3C86E),
                warn: rgb(0xF4C452),
                danger: rgb(0xEE6B5D),
                on_fill: rgb(0x17120D),
                sel_bg: rgb(0x553A1E),
                sel_fg: rgb(0xFFF4E3),
                sel_inactive_bg: rgb(0x2E241A),
                gauge_fill: rgb(0xF2A93B),
                gauge_empty: rgb(0x33291E),
                scroll_thumb: rgb(0x9A8368),
                scroll_track: rgb(0x4B3D2D),
                button_bg: rgb(0x30261C),
                button_fg: rgb(0xEEDFCA),
                tab_active_bg: rgb(0xF2A93B),
                tab_active_fg: rgb(0x17120D),
                tab_inactive: rgb(0xA9967E),
                chart_rx: rgb(0xF2A93B),
                chart_tx: rgb(0xE8826A),
            },
            // Холодная «фьорд»: серо-синий сумрак, ледяной циан.
            ThemeKind::Fjord => Palette {
                bg: rgb(0x1F2530),
                surface: rgb(0x252C38),
                header_bg: rgb(0x2C3441),
                border: rgb(0x46515F),
                border_focused: rgb(0x86C3D6),
                text: rgb(0xDDE4EC),
                text_muted: rgb(0x9DA8B7),
                accent: rgb(0x86C3D6),
                accent_alt: rgb(0xA9B9EA),
                success: rgb(0xA5CF8C),
                warn: rgb(0xE8C67C),
                danger: rgb(0xE08A93),
                on_fill: rgb(0x1F2530),
                sel_bg: rgb(0x3A4C62),
                sel_fg: rgb(0xF3F6FA),
                sel_inactive_bg: rgb(0x303947),
                gauge_fill: rgb(0x86C3D6),
                gauge_empty: rgb(0x363F4D),
                scroll_thumb: rgb(0x8592A3),
                scroll_track: rgb(0x46515F),
                button_bg: rgb(0x343D4B),
                button_fg: rgb(0xDDE4EC),
                tab_active_bg: rgb(0x86C3D6),
                tab_active_fg: rgb(0x1F2530),
                tab_inactive: rgb(0x9DA8B7),
                chart_rx: rgb(0x86C3D6),
                chart_tx: rgb(0xA9B9EA),
            },
        }
    }
}

/// Вид кнопки.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Btn {
    Normal,
    /// Действие по умолчанию (Enter).
    Primary,
    /// Необратимое/отказ.
    Danger,
}

/// Набор стилей для отрисовки. Текстовые стили задают только цвет текста —
/// фон берётся у панели, на которой они нарисованы.
#[derive(Clone, Copy)]
pub struct Theme {
    pub c: Palette,
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
        let c = Palette::of(kind);
        let fg = |col: Color| Style::default().fg(col);
        let contrast = kind == ThemeKind::Contrast;
        let strong = |s: Style| if contrast { s.add_modifier(Modifier::BOLD) } else { s };
        Theme {
            c,
            base: fg(c.text),
            dim: fg(c.text_muted),
            title: fg(c.accent).add_modifier(Modifier::BOLD),
            accent: fg(c.accent),
            direct: strong(fg(c.success)),
            relay: fg(c.warn),
            offline: fg(c.text_muted),
            error: strong(fg(c.danger)),
            warn: fg(c.warn),
            ok: fg(c.success),
            selected: Style::default()
                .bg(c.sel_bg)
                .fg(c.sel_fg)
                .add_modifier(Modifier::BOLD),
            focused_border: strong(fg(c.border_focused)),
            unfocused_border: fg(c.border),
        }
    }

    /// Фон кадра (с цветом текста по умолчанию).
    pub fn frame(&self) -> Style {
        Style::default().bg(self.c.bg).fg(self.c.text)
    }

    /// Фон панели или окна.
    pub fn surface(&self) -> Style {
        Style::default().bg(self.c.surface).fg(self.c.text)
    }

    /// Шапка, заголовок таблицы, поле ввода.
    pub fn header(&self) -> Style {
        Style::default().bg(self.c.header_bg).fg(self.c.text)
    }

    /// Выбранная строка в панели без фокуса: видно, но не кричит.
    pub fn selected_inactive(&self) -> Style {
        Style::default().bg(self.c.sel_inactive_bg).fg(self.c.text)
    }

    /// Выбранная строка: яркая в панели с фокусом, приглушённая без него.
    pub fn selection(&self, focused: bool) -> Style {
        if focused {
            self.selected
        } else {
            self.selected_inactive()
        }
    }

    /// «Пилюля»: заливка цветом `bg`, контрастный текст.
    pub fn pill(&self, bg: Color) -> Style {
        Style::default()
            .bg(bg)
            .fg(self.c.on_fill)
            .add_modifier(Modifier::BOLD)
    }

    /// Нейтральная «пилюля» (счётчики, подписи).
    pub fn chip(&self) -> Style {
        Style::default().bg(self.c.button_bg).fg(self.c.button_fg)
    }

    pub fn button(&self, kind: Btn) -> Style {
        match kind {
            Btn::Normal => self.chip(),
            Btn::Primary => self.pill(self.c.accent),
            Btn::Danger => self.pill(self.c.danger),
        }
    }

    pub fn tab_active(&self) -> Style {
        Style::default()
            .bg(self.c.tab_active_bg)
            .fg(self.c.tab_active_fg)
            .add_modifier(Modifier::BOLD)
    }

    pub fn tab_inactive(&self) -> Style {
        Style::default().fg(self.c.tab_inactive)
    }

    pub fn gauge_filled(&self) -> Style {
        Style::default().fg(self.c.gauge_fill)
    }

    pub fn gauge_unfilled(&self) -> Style {
        Style::default().fg(self.c.gauge_empty)
    }

    pub fn scroll_thumb(&self) -> Style {
        Style::default().fg(self.c.scroll_thumb)
    }

    pub fn scroll_track(&self) -> Style {
        Style::default().fg(self.c.scroll_track)
    }

    pub fn chart_rx(&self) -> Style {
        Style::default().fg(self.c.chart_rx)
    }

    pub fn chart_tx(&self) -> Style {
        Style::default().fg(self.c.chart_tx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn тема_переключается_по_кругу() {
        assert_eq!(ThemeKind::Dark.next(), ThemeKind::Light);
        assert_eq!(ThemeKind::Light.next(), ThemeKind::Contrast);
        assert_eq!(ThemeKind::Contrast.next(), ThemeKind::Amber);
        assert_eq!(ThemeKind::Amber.next(), ThemeKind::Fjord);
        assert_eq!(ThemeKind::Fjord.next(), ThemeKind::Dark);
        // next() обходит все темы ровно по разу.
        let mut seen = Vec::new();
        let mut k = ThemeKind::Dark;
        for _ in 0..ThemeKind::ALL.len() {
            assert!(!seen.contains(&k), "тема {k:?} повторилась");
            seen.push(k);
            k = k.next();
        }
        assert_eq!(k, ThemeKind::Dark);
        assert_eq!(seen.len(), ThemeKind::ALL.len());
    }

    #[test]
    fn тема_читается_из_строки() {
        assert_eq!(ThemeKind::from_str("light"), Some(ThemeKind::Light));
        assert_eq!(ThemeKind::from_str("contrast"), Some(ThemeKind::Contrast));
        assert_eq!(ThemeKind::from_str("dark"), Some(ThemeKind::Dark));
        assert_eq!(ThemeKind::from_str("нет"), None);
        assert_eq!(ThemeKind::Light.as_str(), "light");
        for k in ThemeKind::ALL {
            assert_eq!(ThemeKind::from_str(k.as_str()), Some(k), "{k:?}");
            assert!(!k.label().is_empty());
        }
    }

    fn lum(c: Color) -> f64 {
        let Color::Rgb(r, g, b) = c else {
            panic!("цвет темы не RGB: {c:?}");
        };
        let ch = |v: u8| {
            let v = v as f64 / 255.0;
            if v <= 0.03928 {
                v / 12.92
            } else {
                ((v + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * ch(r) + 0.7152 * ch(g) + 0.0722 * ch(b)
    }

    fn ratio(a: Color, b: Color) -> f64 {
        let (x, y) = (lum(a), lum(b));
        let (hi, lo) = if x > y { (x, y) } else { (y, x) };
        (hi + 0.05) / (lo + 0.05)
    }

    #[test]
    fn контраст_текста_достаточный() {
        for k in ThemeKind::ALL {
            let c = Palette::of(k);
            let min = if k == ThemeKind::Contrast { 7.0 } else { 4.5 };
            let pairs = [
                ("текст/фон", c.text, c.bg),
                ("текст/панель", c.text, c.surface),
                ("текст/шапка", c.text, c.header_bg),
                ("приглушённый/панель", c.text_muted, c.surface),
                ("приглушённый/фон", c.text_muted, c.bg),
                ("выбор", c.sel_fg, c.sel_bg),
                ("выбор без фокуса", c.text, c.sel_inactive_bg),
                ("акцент/панель", c.accent, c.surface),
                ("успех/панель", c.success, c.surface),
                ("внимание/панель", c.warn, c.surface),
                ("ошибка/панель", c.danger, c.surface),
                ("кнопка", c.button_fg, c.button_bg),
                ("основная кнопка", c.on_fill, c.accent),
                ("опасная кнопка", c.on_fill, c.danger),
                ("пилюля успеха", c.on_fill, c.success),
                ("вкладка", c.tab_active_fg, c.tab_active_bg),
                ("вкладка неактивная", c.tab_inactive, c.bg),
            ];
            for (what, fg, bg) in pairs {
                let r = ratio(fg, bg);
                assert!(r >= min, "{k:?}: {what} = {r:.2} < {min}");
            }
            // Рамка с фокусом заметна на панели.
            assert!(ratio(c.border_focused, c.surface) >= 3.0, "{k:?}: рамка");
        }
    }
}
