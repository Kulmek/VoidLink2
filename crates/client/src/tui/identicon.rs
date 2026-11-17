//! Identicon-аватар: постоянный «пиксельный» узор из pubkey.

use ratatui::style::Color;

/// Сетка 5×5, симметричная по вертикали.
pub struct Identicon {
    pub cells: [[bool; 5]; 5],
    pub fg: Color,
    pub bg: Color,
}

impl Identicon {
    /// Строит узор из 32 байт pubkey: цвет — из первых байт,
    /// узор — из остальных (по 3 бита на ячейку, зеркалим).
    pub fn from_pubkey(pubkey: &[u8; 32]) -> Self {
        let h = pubkey;
        let fg = match (h[0], h[1]) {
            (0, _) => Color::Red,
            (1, _) => Color::Green,
            (2, _) => Color::Yellow,
            (3, _) => Color::Blue,
            (4, _) => Color::Magenta,
            (5, _) => Color::Cyan,
            (6, _) => Color::LightRed,
            _ => Color::LightGreen,
        };
        let bg = Color::Rgb(30, 34, 40);

        // 15 ячеек (левый столбец из 5 + 2 средних) = 45 бит.
        let mut bits = [0u8; 15];
        for (i, b) in bits.iter_mut().enumerate() {
            *b = h[2 + i] & 0b111;
        }
        let mut cells = [[false; 5]; 5];
        for (row, line) in cells.iter_mut().enumerate() {
            for col in 0..3 {
                let bit_index = row * 3 + col;
                let on = (bits[bit_index] >> (col % 3)) & 1 == 1;
                line[col] = on;
                line[4 - col] = on;
            }
        }
        Self { cells, fg, bg }
    }

    /// Горизонтальная линия из 5 «пикселей» (по 2 символа на ячейку).
    pub fn row_line(&self, row: usize) -> Vec<(String, Color, Color)> {
        (0..5)
            .map(|col| {
                if self.cells[row][col] {
                    ("██".to_string(), self.fg, self.bg)
                } else {
                    ("  ".to_string(), self.bg, self.bg)
                }
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn узор_детерминирован() {
        let pk = [42u8; 32];
        let a = Identicon::from_pubkey(&pk);
        let b = Identicon::from_pubkey(&pk);
        assert_eq!(a.cells, b.cells);
        assert_eq!(a.fg, b.fg);
    }

    #[test]
    fn узор_симметричен_по_вертикали() {
        let id = Identicon::from_pubkey(&[7u8; 32]);
        for line in &id.cells {
            let mut mirrored = *line;
            mirrored.reverse();
            assert_eq!(*line, mirrored);
        }
    }

    #[test]
    fn разные_ключи_дают_разные_узоры() {
        let a = Identicon::from_pubkey(&[1u8; 32]);
        let b = Identicon::from_pubkey(&[2u8; 32]);
        assert_ne!(a.cells, b.cells);
    }
}
