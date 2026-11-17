//! FRAG (раздел 3): длинные сообщения сервера режутся на куски, каждый —
//! отдельный шифрованный ctrl-фрейм `ctrl::FRAG`.
//!
//! ```text
//! msg_id u32 | inner_typ u8 | idx u16 | count u16 | chunk
//! ```

use std::time::{Duration, Instant};

use anyhow::{Result, bail, ensure};

use crate::{Reader, ctrl};

/// Payload длиннее — режется; куски по столько же байт.
pub const FRAG_THRESHOLD: usize = 1100;
/// Наибольшее число кусков одного сообщения.
pub const FRAG_MAX_COUNT: usize = 256;
/// Наибольший payload, который можно передать через FRAG.
pub const FRAG_MAX_PAYLOAD: usize = FRAG_THRESHOLD * FRAG_MAX_COUNT;
/// Сколько сборок держится одновременно.
pub const FRAG_MAX_PENDING: usize = 8;
/// Сборка, не завершённая за столько от первого куска, выбрасывается.
pub const FRAG_TIMEOUT: Duration = Duration::from_secs(5);
/// Заголовок куска.
pub const FRAG_HDR_LEN: usize = 4 + 1 + 2 + 2;

/// Режет payload на куски FRAG. `None` — резать не нужно (≤ порога), шлётся
/// как есть. Ошибка — payload не влезает в `FRAG_MAX_COUNT` кусков или
/// `inner_typ` сам FRAG.
pub fn split_frag(msg_id: u32, inner_typ: u8, payload: &[u8]) -> Result<Option<Vec<Vec<u8>>>> {
    ensure!(inner_typ != ctrl::FRAG, "FRAG внутри FRAG");
    if payload.len() <= FRAG_THRESHOLD {
        return Ok(None);
    }
    ensure!(
        payload.len() <= FRAG_MAX_PAYLOAD,
        "сообщение {} байт не влезает в FRAG ({FRAG_MAX_PAYLOAD})",
        payload.len()
    );
    let count = payload.len().div_ceil(FRAG_THRESHOLD) as u16;
    Ok(Some(
        payload
            .chunks(FRAG_THRESHOLD)
            .enumerate()
            .map(|(idx, chunk)| {
                let mut v = Vec::with_capacity(FRAG_HDR_LEN + chunk.len());
                v.extend_from_slice(&msg_id.to_be_bytes());
                v.push(inner_typ);
                v.extend_from_slice(&(idx as u16).to_be_bytes());
                v.extend_from_slice(&count.to_be_bytes());
                v.extend_from_slice(chunk);
                v
            })
            .collect(),
    ))
}

/// Сообщение сервера → список (typ, payload) для `seal_ctrl` по порядку.
/// Короткое — одно `(typ, payload)`; длинное — куски `(ctrl::FRAG, …)` с
/// `msg_id = *next_msg_id` (затем счётчик растёт, с обёрткой: сборки живут
/// 5 с, совпадение через 2^32 сообщений не страшно).
pub fn prepare(next_msg_id: &mut u32, typ: u8, payload: &[u8]) -> Result<Vec<(u8, Vec<u8>)>> {
    match split_frag(*next_msg_id, typ, payload)? {
        None => Ok(vec![(typ, payload.to_vec())]),
        Some(chunks) => {
            *next_msg_id = next_msg_id.wrapping_add(1);
            Ok(chunks.into_iter().map(|c| (ctrl::FRAG, c)).collect())
        }
    }
}

/// Разобранный кусок.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FragChunk<'a> {
    pub msg_id: u32,
    pub inner_typ: u8,
    pub idx: u16,
    pub count: u16,
    pub chunk: &'a [u8],
}

/// Разбор и проверка куска: `1 ≤ count ≤ FRAG_MAX_COUNT`, `idx < count`,
/// все куски кроме последнего — ровно `FRAG_THRESHOLD` байт, последний —
/// 1..=`FRAG_THRESHOLD`, `inner_typ ≠ FRAG`.
pub fn dec_frag(p: &[u8]) -> Result<FragChunk<'_>> {
    let mut r = Reader::new(p);
    let msg_id = r.u32()?;
    let inner_typ = r.u8()?;
    let idx = r.u16()?;
    let count = r.u16()?;
    let chunk = r.tail();
    ensure!(inner_typ != ctrl::FRAG, "FRAG внутри FRAG");
    ensure!(
        count >= 1 && count as usize <= FRAG_MAX_COUNT,
        "FRAG: count {count}"
    );
    ensure!(idx < count, "FRAG: idx {idx} ≥ count {count}");
    if idx + 1 < count {
        ensure!(
            chunk.len() == FRAG_THRESHOLD,
            "FRAG: кусок {idx} длиной {}",
            chunk.len()
        );
    } else {
        ensure!(
            (1..=FRAG_THRESHOLD).contains(&chunk.len()),
            "FRAG: последний кусок длиной {}",
            chunk.len()
        );
    }
    Ok(FragChunk {
        msg_id,
        inner_typ,
        idx,
        count,
        chunk,
    })
}

struct Pending {
    msg_id: u32,
    inner_typ: u8,
    count: u16,
    /// Куски на своих местах (каждый ≤ FRAG_THRESHOLD — память ограничена).
    chunks: Vec<Option<Vec<u8>>>,
    have: u16,
    started: Instant,
}

/// Сборщик FRAG на стороне клиента (один на сессию). Память ограничена:
/// ≤ `FRAG_MAX_PENDING` сборок × `FRAG_MAX_PAYLOAD`.
#[derive(Default)]
pub struct Reassembler {
    pending: Vec<Pending>,
}

impl Reassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Сколько сборок сейчас в работе.
    pub fn pending(&self) -> usize {
        self.pending.len()
    }

    /// Выбрасывает сборки старше `FRAG_TIMEOUT`.
    pub fn expire(&mut self, now: Instant) {
        self.pending
            .retain(|p| now.saturating_duration_since(p.started) < FRAG_TIMEOUT);
    }

    /// Принимает payload ctrl-фрейма FRAG. `Some((inner_typ, payload))` —
    /// сообщение собрано. Повтор куска и любой порядок допустимы. Кусок,
    /// противоречащий начатой сборке (другие count / inner_typ) или неверный
    /// сам по себе (длина, idx, count), — ошибка, и сборка того же `msg_id`
    /// выбрасывается. Девятая сборка вытесняет самую старую.
    pub fn push(&mut self, frag_payload: &[u8], now: Instant) -> Result<Option<(u8, Vec<u8>)>> {
        let c = match dec_frag(frag_payload) {
            Ok(c) => c,
            Err(e) => {
                // msg_id читается и у битого куска: сборка, в которую он
                // целил, уже недостоверна (раздел 3).
                if let Some(id) = frag_payload.get(..4) {
                    let id = u32::from_be_bytes(id.try_into().unwrap());
                    self.pending.retain(|p| p.msg_id != id);
                }
                return Err(e);
            }
        };
        self.expire(now);
        let pos = match self.pending.iter().position(|p| p.msg_id == c.msg_id) {
            Some(i) => {
                let p = &self.pending[i];
                if p.count != c.count || p.inner_typ != c.inner_typ {
                    self.pending.swap_remove(i);
                    bail!(
                        "FRAG {}: count/inner_typ не совпадают с началом сборки",
                        c.msg_id
                    );
                }
                i
            }
            None => {
                if c.count == 1 {
                    return Ok(Some((c.inner_typ, c.chunk.to_vec())));
                }
                if self.pending.len() >= FRAG_MAX_PENDING
                    && let Some(oldest) =
                        (0..self.pending.len()).min_by_key(|&i| self.pending[i].started)
                {
                    self.pending.swap_remove(oldest);
                }
                self.pending.push(Pending {
                    msg_id: c.msg_id,
                    inner_typ: c.inner_typ,
                    count: c.count,
                    chunks: vec![None; c.count as usize],
                    have: 0,
                    started: now,
                });
                self.pending.len() - 1
            }
        };
        let p = &mut self.pending[pos];
        let slot = &mut p.chunks[c.idx as usize];
        if slot.is_none() {
            *slot = Some(c.chunk.to_vec());
            p.have += 1;
        }
        if p.have < p.count {
            return Ok(None);
        }
        let p = self.pending.swap_remove(pos);
        let total = p.chunks.iter().flatten().map(Vec::len).sum();
        let mut out = Vec::with_capacity(total);
        for ch in p.chunks.into_iter().flatten() {
            out.extend_from_slice(&ch);
        }
        Ok(Some((p.inner_typ, out)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(n: usize) -> Vec<u8> {
        (0..n).map(|i| (i * 7 + i / 251) as u8).collect()
    }

    #[test]
    fn короткое_не_режется() {
        assert_eq!(
            split_frag(1, ctrl::GROUP_STATE, &msg(FRAG_THRESHOLD)).unwrap(),
            None
        );
        let mut id = 5;
        let out = prepare(&mut id, ctrl::GROUP_STATE, &msg(10)).unwrap();
        assert_eq!(out, vec![(ctrl::GROUP_STATE, msg(10))]);
        assert_eq!(id, 5, "msg_id тратится только на длинные");
        assert_eq!(
            prepare(&mut id, ctrl::ERROR, &[]).unwrap(),
            vec![(ctrl::ERROR, vec![])]
        );
    }

    #[test]
    fn нарезка_и_сборка() {
        for n in [
            FRAG_THRESHOLD + 1,
            2 * FRAG_THRESHOLD,
            2 * FRAG_THRESHOLD + 1,
            50_000,
            FRAG_MAX_PAYLOAD,
        ] {
            let m = msg(n);
            let mut id = u32::MAX;
            let parts = prepare(&mut id, ctrl::GROUP_STATE, &m).unwrap();
            assert_eq!(id, 0, "обёртка msg_id");
            assert_eq!(parts.len(), n.div_ceil(FRAG_THRESHOLD));
            assert!(
                parts
                    .iter()
                    .all(|(t, p)| *t == ctrl::FRAG && p.len() <= FRAG_HDR_LEN + FRAG_THRESHOLD)
            );
            let mut r = Reassembler::new();
            let now = Instant::now();
            let mut got = None;
            for (i, (_, p)) in parts.iter().enumerate() {
                let res = r.push(p, now).unwrap();
                if i + 1 < parts.len() {
                    assert!(res.is_none());
                } else {
                    got = res;
                }
            }
            assert_eq!(got, Some((ctrl::GROUP_STATE, m)));
            assert_eq!(r.pending(), 0);
        }
    }

    #[test]
    fn слишком_длинное_и_frag_в_frag() {
        assert!(split_frag(0, ctrl::GROUP_STATE, &msg(FRAG_MAX_PAYLOAD + 1)).is_err());
        assert!(split_frag(0, ctrl::FRAG, &msg(10)).is_err());
    }

    #[test]
    fn вразнобой_и_с_повторами() {
        let m = msg(5 * FRAG_THRESHOLD + 17);
        let parts = split_frag(9, ctrl::GROUP_LIST, &m).unwrap().unwrap();
        let order = [3usize, 0, 3, 5, 1, 1, 4, 0];
        let mut r = Reassembler::new();
        let now = Instant::now();
        for i in order {
            assert!(r.push(&parts[i], now).unwrap().is_none(), "кусок {i}");
        }
        assert_eq!(r.push(&parts[2], now).unwrap(), Some((ctrl::GROUP_LIST, m)));
        // Поздний повтор после сборки открывает новую сборку, которая истечёт.
        assert!(r.push(&parts[0], now).unwrap().is_none());
        assert_eq!(r.pending(), 1);
        r.expire(now + FRAG_TIMEOUT);
        assert_eq!(r.pending(), 0);
    }

    #[test]
    fn таймаут_по_явному_времени() {
        let parts = split_frag(1, ctrl::GROUP_STATE, &msg(3000))
            .unwrap()
            .unwrap();
        let t0 = Instant::now();
        let mut r = Reassembler::new();
        assert!(r.push(&parts[0], t0).unwrap().is_none());
        assert!(
            r.push(&parts[1], t0 + Duration::from_millis(4999))
                .unwrap()
                .is_none()
        );
        // Сборка истекла (5 с от первого куска): последний кусок начинает новую.
        assert!(r.push(&parts[2], t0 + FRAG_TIMEOUT).unwrap().is_none());
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn не_больше_8_сборок() {
        let t0 = Instant::now();
        let mut r = Reassembler::new();
        let msgs: Vec<_> = (0..10u32)
            .map(|id| {
                split_frag(id, ctrl::GROUP_STATE, &msg(2500))
                    .unwrap()
                    .unwrap()
            })
            .collect();
        for (i, parts) in msgs.iter().enumerate() {
            r.push(&parts[0], t0 + Duration::from_millis(i as u64))
                .unwrap();
            assert!(r.pending() <= FRAG_MAX_PENDING);
        }
        assert_eq!(r.pending(), FRAG_MAX_PENDING);
        // Две самые старые (0 и 1) вытеснены: их дочитка не собирает сообщение.
        assert!(r.push(&msgs[0][1], t0).unwrap().is_none());
        // Свежие собираются.
        assert!(r.push(&msgs[9][1], t0).unwrap().is_none());
        assert!(r.push(&msgs[9][2], t0).unwrap().is_some());
    }

    #[test]
    fn противоречивые_куски_отвергаются() {
        let a = split_frag(4, ctrl::GROUP_STATE, &msg(3000))
            .unwrap()
            .unwrap();
        let b = split_frag(4, ctrl::GROUP_LIST, &msg(3000))
            .unwrap()
            .unwrap();
        let c = split_frag(4, ctrl::GROUP_STATE, &msg(5000))
            .unwrap()
            .unwrap();
        let now = Instant::now();
        let mut r = Reassembler::new();
        r.push(&a[0], now).unwrap();
        assert!(r.push(&b[1], now).is_err(), "другой inner_typ");
        assert_eq!(r.pending(), 0, "сборка выброшена");
        r.push(&a[0], now).unwrap();
        assert!(r.push(&c[1], now).is_err(), "другой count");
        assert_eq!(r.pending(), 0, "сборка выброшена");
    }

    #[test]
    fn кусок_неверной_длины_выбрасывает_сборку() {
        let parts = split_frag(4, ctrl::GROUP_STATE, &msg(3000))
            .unwrap()
            .unwrap();
        let now = Instant::now();
        let mut r = Reassembler::new();
        r.push(&parts[0], now).unwrap();
        r.push(&parts[2], now).unwrap();
        // Тот же msg_id, idx 1 из 3, но 1099 байт вместо 1100.
        let mut bad = parts[1].clone();
        bad.pop();
        assert!(r.push(&bad, now).is_err());
        assert_eq!(r.pending(), 0, "сборка msg_id 4 должна быть выброшена");
        // Дочитка верным куском начинает сборку заново, а не завершает старую.
        assert!(r.push(&parts[1], now).unwrap().is_none());
        // Чужие сборки битый кусок не трогает.
        let other = split_frag(5, ctrl::GROUP_STATE, &msg(3000))
            .unwrap()
            .unwrap();
        r.push(&other[0], now).unwrap();
        assert!(r.push(&bad, now).is_err());
        assert_eq!(r.pending(), 1);
    }

    #[test]
    fn любой_битый_кусок_выбрасывает_начатую_сборку() {
        // Сборка msg_id 7 из 3 кусков; каждый вариант битого куска того же
        // msg_id должен выбросить её целиком (раздел 3), а итог не собраться.
        let m = msg(2 * FRAG_THRESHOLD + 300);
        let parts = split_frag(7, ctrl::GROUP_STATE, &m).unwrap().unwrap();
        let hdr = |idx: u16, count: u16, inner: u8| {
            let mut v = 7u32.to_be_bytes().to_vec();
            v.push(inner);
            v.extend_from_slice(&idx.to_be_bytes());
            v.extend_from_slice(&count.to_be_bytes());
            v
        };
        let with_len = |idx: u16, len: usize| {
            let mut v = hdr(idx, 3, ctrl::GROUP_STATE);
            v.extend(std::iter::repeat_n(1u8, len));
            v
        };
        let bad: Vec<(&str, Vec<u8>)> = vec![
            (
                "не последний длиннее порога",
                with_len(1, FRAG_THRESHOLD + 1),
            ),
            ("не последний короче порога", with_len(1, 300)),
            ("последний длиннее порога", with_len(2, FRAG_THRESHOLD + 1)),
            ("последний пустой", with_len(2, 0)),
            ("idx ≥ count", {
                let mut v = hdr(3, 3, ctrl::GROUP_STATE);
                v.extend(std::iter::repeat_n(1u8, 10));
                v
            }),
            ("FRAG в FRAG", {
                let mut v = hdr(2, 3, ctrl::FRAG);
                v.extend(std::iter::repeat_n(1u8, 10));
                v
            }),
        ];
        let now = Instant::now();
        for (what, b) in bad {
            let mut r = Reassembler::new();
            assert!(r.push(&parts[0], now).unwrap().is_none());
            assert!(r.push(&parts[1], now).unwrap().is_none());
            assert!(r.push(&b, now).is_err(), "{what}: должен быть отвергнут");
            assert_eq!(r.pending(), 0, "{what}: сборка не выброшена");
            // Верный последний кусок не завершает выброшенную сборку.
            assert!(
                r.push(&parts[2], now).unwrap().is_none(),
                "{what}: собралось из остатков"
            );
            assert_eq!(r.pending(), 1);
        }
        // Контроль: без битого куска сообщение собирается целиком.
        let mut r = Reassembler::new();
        for p in &parts[..2] {
            assert!(r.push(p, now).unwrap().is_none());
        }
        assert_eq!(
            r.push(&parts[2], now).unwrap(),
            Some((ctrl::GROUP_STATE, m))
        );
    }

    #[test]
    fn неверные_куски() {
        let mk = |idx: u16, count: u16, len: usize, inner: u8| {
            let mut v = 1u32.to_be_bytes().to_vec();
            v.push(inner);
            v.extend_from_slice(&idx.to_be_bytes());
            v.extend_from_slice(&count.to_be_bytes());
            v.extend(std::iter::repeat_n(0u8, len));
            v
        };
        let now = Instant::now();
        let mut r = Reassembler::new();
        assert!(r.push(&mk(0, 0, 10, 0x82), now).is_err(), "count 0");
        assert!(
            r.push(&mk(0, FRAG_MAX_COUNT as u16 + 1, 1100, 0x82), now)
                .is_err(),
            "count > max"
        );
        assert!(r.push(&mk(3, 3, 10, 0x82), now).is_err(), "idx ≥ count");
        assert!(
            r.push(&mk(0, 3, 1099, 0x82), now).is_err(),
            "короткий не последний"
        );
        assert!(r.push(&mk(0, 3, 1101, 0x82), now).is_err(), "длинный кусок");
        assert!(r.push(&mk(2, 3, 0, 0x82), now).is_err(), "пустой последний");
        assert!(
            r.push(&mk(0, 2, 1100, ctrl::FRAG), now).is_err(),
            "FRAG в FRAG"
        );
        assert!(r.push(&[0; FRAG_HDR_LEN - 1], now).is_err(), "обрезан");
        assert_eq!(r.pending(), 0);
        // count = 1 — сразу готово.
        assert_eq!(
            r.push(&mk(0, 1, 5, 0x82), now).unwrap(),
            Some((0x82, vec![0; 5]))
        );
    }
}
