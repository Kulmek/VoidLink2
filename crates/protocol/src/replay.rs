//! Окно повторов (как в WireGuard / IPsec): 1024 бита над наибольшим
//! принятым счётчиком.

/// Ширина окна: принимаются счётчики не ниже `max - (REPLAY_WINDOW - 1)`.
pub const REPLAY_WINDOW: u64 = 1024;

const WORDS: usize = (REPLAY_WINDOW / 64) as usize;

/// Окно повторов одного потока счётчиков (ctrl-сессия или (gid, epoch, src)).
///
/// Порядок использования: [`check`](Self::check) — по желанию до
/// расшифровки (дёшево отсечь мусор), [`commit`](Self::commit) — **только
/// после** успешной расшифровки. Иначе подделка с огромным счётчиком сдвинула
/// бы окно и заставила отвергать честные фреймы.
#[derive(Debug, Clone, Default)]
pub struct ReplayWindow {
    /// Наибольший принятый счётчик; `None` — ещё ничего не принято.
    top: Option<u64>,
    /// Бит `c % 1024` — счётчик `c` из окна уже принят (кольцевой буфер).
    bits: [u64; WORDS],
}

impl ReplayWindow {
    pub fn new() -> Self {
        Self::default()
    }

    /// Наибольший принятый счётчик.
    pub fn max(&self) -> Option<u64> {
        self.top
    }

    fn bit(c: u64) -> (usize, u64) {
        let i = (c % REPLAY_WINDOW) as usize;
        (i / 64, 1u64 << (i % 64))
    }

    /// Был бы `c` принят (новый и не слишком старый). Окно не меняет.
    pub fn check(&self, c: u64) -> bool {
        let Some(top) = self.top else { return true };
        if c > top {
            return true;
        }
        if top - c >= REPLAY_WINDOW {
            return false;
        }
        let (w, m) = Self::bit(c);
        self.bits[w] & m == 0
    }

    /// Отмечает `c` принятым и сдвигает окно. Вызывать только после успешной
    /// расшифровки фрейма. Возвращает `false` (окно не меняется), если `c` —
    /// повтор или слишком старый: такой фрейм отбрасывается.
    pub fn commit(&mut self, c: u64) -> bool {
        if !self.check(c) {
            return false;
        }
        match self.top {
            Some(top) if c <= top => {}
            Some(top) if c - top < REPLAY_WINDOW => {
                // Освобождаем позиции счётчиков (top, c]: они ещё не приняты,
                // а в кольце на их местах лежат биты на 1024 старше.
                let mut i = top + 1;
                loop {
                    let (w, m) = Self::bit(i);
                    self.bits[w] &= !m;
                    if i == c {
                        break;
                    }
                    i += 1;
                }
                self.top = Some(c);
            }
            _ => {
                // Первый счётчик или прыжок дальше окна: всё старое вне окна.
                self.bits = [0; WORDS];
                self.top = Some(c);
            }
        }
        let (w, m) = Self::bit(c);
        self.bits[w] |= m;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn по_порядку_и_повторы() {
        let mut w = ReplayWindow::new();
        assert_eq!(w.max(), None);
        for c in 0..5000 {
            assert!(w.check(c));
            assert!(w.commit(c), "{c}");
            assert!(!w.check(c) && !w.commit(c), "повтор {c}");
        }
        assert_eq!(w.max(), Some(4999));
        // Всё окно занято — любой старый повтор отвергается.
        for c in 3976..5000 {
            assert!(!w.check(c));
        }
    }

    #[test]
    fn счётчик_ноль_первый_и_повтор() {
        let mut w = ReplayWindow::new();
        assert!(w.commit(0));
        assert!(!w.commit(0));
        assert!(w.commit(1));
        assert!(!w.commit(0));
    }

    #[test]
    fn первым_может_прийти_любой_счётчик() {
        let mut w = ReplayWindow::new();
        assert!(w.commit(500));
        // Пропущенные до него — в окне и ещё не видены.
        for c in 0..500 {
            assert!(w.check(c), "{c}");
        }
        assert!(w.commit(3));
        assert!(!w.commit(3));
        assert!(!w.commit(500));
    }

    #[test]
    fn перестановка_внутри_окна() {
        let mut w = ReplayWindow::new();
        let order = [10u64, 3, 7, 0, 11, 1, 2, 9, 4, 8, 5, 6];
        for c in order {
            assert!(w.commit(c), "{c}");
        }
        for c in 0..=11 {
            assert!(!w.check(c), "{c}");
        }
        assert!(w.commit(12));
    }

    #[test]
    fn граница_окна_ровно_1023_назад() {
        let mut w = ReplayWindow::new();
        assert!(w.commit(2000));
        assert!(w.check(2000 - 1023), "max-1023 — ещё в окне");
        assert!(!w.check(2000 - 1024), "max-1024 — слишком старый");
        assert!(w.commit(2000 - 1023));
        assert!(!w.commit(2000 - 1024));
        assert!(!w.commit(0));
    }

    #[test]
    fn слишком_старый_после_сдвига() {
        let mut w = ReplayWindow::new();
        assert!(w.commit(5));
        assert!(w.commit(5 + 1024));
        // 5 уже за окном; позиция в кольце та же, что у 1029, но 5 — старый.
        assert!(!w.check(5));
        // 6..1028 не видены и в окне (top - c < 1024 только для c ≥ 6).
        assert!(w.check(6) && w.check(1028));
        assert!(w.commit(6));
    }

    #[test]
    fn сдвиг_очищает_биты_старого_круга() {
        let mut w = ReplayWindow::new();
        // Принимаем 0..1024 (полное окно), затем сдвиг на 512.
        for c in 0..1024 {
            assert!(w.commit(c));
        }
        assert!(w.commit(1535));
        // 1024..1535 — новые, хотя их позиции в кольце были заняты 0..511.
        for c in 1024..1535 {
            assert!(w.check(c), "{c}");
        }
        // 512..1023 видены и ещё в окне.
        for c in 512..1024 {
            assert!(!w.check(c), "{c}");
        }
        // 0..511 — за окном.
        assert!(!w.check(511) && !w.check(0));
    }

    #[test]
    fn огромный_прыжок() {
        let mut w = ReplayWindow::new();
        for c in 0..100 {
            assert!(w.commit(c));
        }
        assert!(w.commit(1 << 40));
        assert!(!w.check(99));
        assert!(w.check((1 << 40) - 1));
        assert!(w.check((1 << 40) - 1023));
        assert!(!w.check((1 << 40) - 1024));
        assert!(!w.commit(1 << 40));
    }

    #[test]
    fn граница_u64() {
        let mut w = ReplayWindow::new();
        assert!(w.commit(u64::MAX - 1));
        assert!(w.commit(u64::MAX));
        assert!(!w.commit(u64::MAX));
        assert!(!w.commit(u64::MAX - 1));
        assert!(w.commit(u64::MAX - 1023));
        assert!(!w.check(u64::MAX - 1024));
        assert!(!w.check(0));
        let mut w = ReplayWindow::new();
        assert!(w.commit(0));
        assert!(w.commit(u64::MAX), "прыжок через всё пространство");
        assert!(!w.check(0));
        assert!(w.check(u64::MAX - 5));
    }

    #[test]
    fn check_не_меняет_окно() {
        let mut w = ReplayWindow::new();
        assert!(w.check(1 << 50));
        // Подделка с огромным счётчиком не прошла расшифровку — commit не
        // вызван, честные счётчики принимаются.
        assert!(w.commit(0));
        assert!(w.check(1 << 50));
        assert!(w.commit(1));
        assert_eq!(w.max(), Some(1));
    }

    #[test]
    fn сверка_с_эталоном_на_случайных_последовательностях() {
        use rand::{RngExt, SeedableRng, rngs::StdRng};
        use std::collections::HashSet;
        let mut rng = StdRng::seed_from_u64(0x5eed);
        for _ in 0..50 {
            let mut w = ReplayWindow::new();
            let mut seen = HashSet::new();
            let mut top: Option<u64> = None;
            let mut base = 0u64;
            for _ in 0..3000 {
                // В основном около вершины, иногда далеко назад или вперёд.
                let c = match rng.random_range(0..20) {
                    0 => base.saturating_add(rng.random_range(0..5000)),
                    1 => base.saturating_sub(rng.random_range(0..3000)),
                    _ => base
                        .saturating_add(rng.random_range(0..40))
                        .saturating_sub(20),
                };
                base = base.max(c);
                let expect = match top {
                    None => true,
                    Some(t) => c > t || (t - c < REPLAY_WINDOW && !seen.contains(&c)),
                };
                assert_eq!(w.check(c), expect, "c={c} top={top:?}");
                assert_eq!(w.commit(c), expect);
                if expect {
                    seen.insert(c);
                    top = Some(top.map_or(c, |t| t.max(c)));
                }
            }
        }
    }
}
