//! Неотвеченные приглашения на стороне движка (PLAN 7.1).
//!
//! Чистая модель без потоков и часов: время передаётся параметром `now`,
//! поэтому `LocalEngine` и демон (7.3) ведут один и тот же список, а тесты
//! не ждут реальных секунд. Правила перенесены из `tui::App` один в один:
//!
//! * [`INVITE_SYNC_GRACE`] — сверка со списком сервера не снимает
//!   приглашение, пришедшее меньше 2 с назад (список мог быть собран раньше);
//! * [`INVITE_DECLINE_MEMORY`] — отклонённое 5 с не возвращается
//!   запоздавшим списком, собранным сервером до нашего DECLINE;
//! * повтор приглашения обновляет данные, но не дублирует запись и не
//!   сбрасывает момент получения;
//! * `Join` приглашение не тратит — оно держится до `GroupJoined` (JOIN
//!   может не пройти), а `DeclineInvite` убирает сразу.
//!
//! Из протокола v3: `expires_in` (секунд) — истёкшие снимает [`PendingInvites::tick`],
//! повторное приглашение продлевает срок.
//!
//! Что фильтрует вызывающий: приглашения в группы, где мы уже состоим или
//! которые в автовходе, — их в модель не кладут (как `skip` в `App`).
//! Очередь окон и «Позже» — состояние фронтенда, здесь их нет.

#![allow(dead_code)] // подключается при интеграции

use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant};
use tunnel_protocol::payloads;

/// См. `tui::app::INVITE_SYNC_GRACE` — значение должно совпадать.
pub const INVITE_SYNC_GRACE: Duration = Duration::from_secs(2);
/// См. `tui::app::INVITE_DECLINE_MEMORY` — значение должно совпадать.
pub const INVITE_DECLINE_MEMORY: Duration = Duration::from_secs(5);

/// Входящее приглашение (INVITE_RCVD или элемент INVITE_LIST).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncomingInvite {
    pub gid: u32,
    pub group_name: String,
    pub from_pubkey: [u8; 32],
    pub from_name: String,
    /// Через сколько секунд истекает (протокол v3); `None` — бессрочно.
    pub expires_in: Option<u32>,
}

impl From<payloads::InviteInfo> for IncomingInvite {
    fn from(i: payloads::InviteInfo) -> Self {
        Self {
            gid: i.gid,
            group_name: i.group_name,
            from_pubkey: i.from_pubkey,
            from_name: i.from_name,
            expires_in: Some(i.expires_in),
        }
    }
}

/// Приглашение в снимке (сериализуемое: длительности вместо `Instant`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invite {
    pub gid: u32,
    pub group_name: String,
    pub from_pubkey: [u8; 32],
    pub from_name: String,
    /// Сколько миллисекунд назад пришло (первая доставка).
    pub received_ms_ago: u64,
    /// Сколько секунд осталось до истечения (с округлением вверх).
    pub expires_in_s: Option<u64>,
}

/// Результат [`PendingInvites::on_invite`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InviteOutcome {
    /// Новое — фронтенду показать окно / тост.
    New,
    /// Уже было — данные обновлены, второго окна не нужно.
    Updated,
    /// Недавно отклонено — запоздавший список, игнор.
    Declined,
}

#[derive(Debug, Clone)]
struct Entry {
    gid: u32,
    group_name: String,
    from_pubkey: [u8; 32],
    from_name: String,
    received_at: Instant,
    expires_at: Option<Instant>,
}

impl Entry {
    fn view(&self, now: Instant) -> Invite {
        Invite {
            gid: self.gid,
            group_name: self.group_name.clone(),
            from_pubkey: self.from_pubkey,
            from_name: self.from_name.clone(),
            received_ms_ago: now.saturating_duration_since(self.received_at).as_millis() as u64,
            expires_in_s: self.expires_at.map(|t| {
                let left = t.saturating_duration_since(now);
                left.as_secs() + u64::from(left.subsec_nanos() > 0)
            }),
        }
    }

    fn expired(&self, now: Instant) -> bool {
        self.expires_at.is_some_and(|t| now >= t)
    }
}

/// Неотвеченные приглашения + память недавних отказов.
#[derive(Debug, Clone, Default)]
pub struct PendingInvites {
    /// В порядке получения.
    items: Vec<Entry>,
    /// Только что отклонённые (gid, когда).
    declined: Vec<(u32, Instant)>,
}

impl PendingInvites {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn contains(&self, gid: u32) -> bool {
        self.items.iter().any(|e| e.gid == gid)
    }

    /// Отклонено меньше [`INVITE_DECLINE_MEMORY`] назад.
    pub fn recently_declined(&self, gid: u32, now: Instant) -> bool {
        self.declined
            .iter()
            .any(|(g, t)| *g == gid && now.saturating_duration_since(*t) < INVITE_DECLINE_MEMORY)
    }

    /// Пришло приглашение (сервер повторяет неотвеченные после каждого HELLO).
    pub fn on_invite(&mut self, inv: IncomingInvite, now: Instant) -> InviteOutcome {
        if self.recently_declined(inv.gid, now) {
            return InviteOutcome::Declined;
        }
        let expires_at = inv
            .expires_in
            .map(|s| now + Duration::from_secs(u64::from(s)));
        if let Some(e) = self.items.iter_mut().find(|e| e.gid == inv.gid) {
            e.group_name = inv.group_name;
            e.from_name = inv.from_name;
            e.from_pubkey = inv.from_pubkey;
            // Повторный INVITE продлевает срок (сервер присылает актуальный).
            if expires_at.is_some() {
                e.expires_at = expires_at;
            }
            return InviteOutcome::Updated;
        }
        self.items.push(Entry {
            gid: inv.gid,
            group_name: inv.group_name,
            from_pubkey: inv.from_pubkey,
            from_name: inv.from_name,
            received_at: now,
            expires_at,
        });
        InviteOutcome::New
    }

    fn remove(&mut self, gid: u32, now: Instant) -> Option<Invite> {
        let pos = self.items.iter().position(|e| e.gid == gid)?;
        Some(self.items.remove(pos).view(now))
    }

    /// Вошли в группу (по приглашению или иначе) — приглашение не нужно.
    pub fn on_group_joined(&mut self, gid: u32, now: Instant) -> Option<Invite> {
        self.remove(gid, now)
    }

    /// Группа удалена.
    pub fn on_group_deleted(&mut self, gid: u32, now: Instant) -> Option<Invite> {
        self.remove(gid, now)
    }

    /// Сервер отозвал приглашение (`InviteRevoked`). `Some` — оно было
    /// (фронтенду — тост «отменено»).
    pub fn on_revoked(&mut self, gid: u32, now: Instant) -> Option<Invite> {
        self.remove(gid, now)
    }

    /// Отказ отправлен (`Cmd::DeclineInvite`): убрать сразу, не дожидаясь
    /// списка от сервера, и запомнить на [`INVITE_DECLINE_MEMORY`].
    pub fn on_decline(&mut self, gid: u32, now: Instant) -> Option<Invite> {
        self.declined
            .retain(|(g, t)| *g != gid && now.saturating_duration_since(*t) < INVITE_DECLINE_MEMORY);
        self.declined.push((gid, now));
        self.remove(gid, now)
    }

    /// Окно списка неотвеченных приглашений (gid ≥ `from`): всё, чего в нём
    /// нет, снять. Окно достоверно от `from`; неполное — только до последнего
    /// gid в нём. Пришедшие за [`INVITE_SYNC_GRACE`] до сверки не трогаются.
    /// Возвращает снятые (gid, имя группы) по возрастанию gid.
    pub fn on_synced(
        &mut self,
        gids: &[u32],
        from: u32,
        complete: bool,
        now: Instant,
    ) -> Vec<(u32, String)> {
        let upto = if complete {
            u32::MAX
        } else {
            gids.iter().copied().max().unwrap_or(0)
        };
        let mut stale = Vec::new();
        self.items.retain(|e| {
            let gone = (from..=upto).contains(&e.gid)
                && !gids.contains(&e.gid)
                && now.saturating_duration_since(e.received_at) >= INVITE_SYNC_GRACE;
            if gone {
                stale.push((e.gid, e.group_name.clone()));
            }
            !gone
        });
        stale.sort_by_key(|(g, _)| *g);
        stale
    }

    /// Раз в тик: снять истёкшие (их же сервер удаляет в housekeeping) и
    /// забыть старые отказы. Возвращает истёкшие.
    pub fn tick(&mut self, now: Instant) -> Vec<Invite> {
        self.declined
            .retain(|(_, t)| now.saturating_duration_since(*t) < INVITE_DECLINE_MEMORY);
        let mut expired = Vec::new();
        self.items.retain(|e| {
            if e.expired(now) {
                expired.push(e.view(now));
                false
            } else {
                true
            }
        });
        expired.sort_by_key(|i| i.gid);
        expired
    }

    /// Текущий список (для снимка), по возрастанию gid.
    pub fn list(&self, now: Instant) -> Vec<Invite> {
        let mut v: Vec<Invite> = self.items.iter().map(|e| e.view(now)).collect();
        v.sort_by_key(|i| i.gid);
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inc(gid: u32) -> IncomingInvite {
        IncomingInvite {
            gid,
            group_name: format!("g{gid}"),
            from_name: "bravo-srv".into(),
            from_pubkey: [2; 32],
            expires_in: None,
        }
    }

    /// Начало отсчёта и «давно пришедшее» время: сверка такие не щадит.
    fn t0() -> Instant {
        Instant::now()
    }

    fn old(p: &mut PendingInvites, t: Instant, gids: &[u32]) -> Instant {
        for &g in gids {
            assert_eq!(p.on_invite(inc(g), t), InviteOutcome::New);
        }
        t + INVITE_SYNC_GRACE * 2
    }

    fn gids(p: &PendingInvites, now: Instant) -> Vec<u32> {
        p.list(now).iter().map(|i| i.gid).collect()
    }

    fn named(v: &[(u32, &str)]) -> Vec<(u32, String)> {
        v.iter().map(|(g, n)| (*g, n.to_string())).collect()
    }

    #[test]
    fn приглашение_добавляется_повтор_обновляет_без_дубликата() {
        let t = t0();
        let mut p = PendingInvites::new();
        assert_eq!(p.on_invite(inc(2), t), InviteOutcome::New);
        assert_eq!(p.on_invite(inc(1), t), InviteOutcome::New);
        assert_eq!(p.on_invite(inc(1), t), InviteOutcome::Updated);
        let mut renamed = inc(2);
        renamed.group_name = "новое имя".into();
        renamed.from_name = "charlie".into();
        renamed.from_pubkey = [3; 32];
        let later = t + Duration::from_secs(1);
        assert_eq!(p.on_invite(renamed, later), InviteOutcome::Updated);
        let l = p.list(later);
        assert_eq!(l.iter().map(|i| i.gid).collect::<Vec<_>>(), vec![1, 2], "по gid");
        assert_eq!(l[1].group_name, "новое имя");
        assert_eq!(l[1].from_name, "charlie");
        assert_eq!(l[1].from_pubkey, [3; 32]);
        // Момент получения — первая доставка (повтор его не сбрасывает).
        assert_eq!(l[1].received_ms_ago, 1000);
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn join_не_тратит_приглашение_до_group_joined() {
        let t = t0();
        let mut p = PendingInvites::new();
        p.on_invite(inc(5), t);
        // Cmd::Join ничего не меняет — модель о нём не знает.
        assert!(p.contains(5));
        assert_eq!(p.on_group_joined(5, t).map(|i| i.gid), Some(5));
        assert!(!p.contains(5) && p.is_empty());
        assert!(p.on_group_joined(5, t).is_none());
    }

    #[test]
    fn удаление_группы_и_отзыв_снимают_приглашение() {
        let t = t0();
        let mut p = PendingInvites::new();
        p.on_invite(inc(1), t);
        p.on_invite(inc(2), t);
        assert_eq!(p.on_group_deleted(1, t).map(|i| i.group_name), Some("g1".into()));
        assert_eq!(p.on_revoked(2, t).map(|i| i.gid), Some(2));
        // Отзыв неизвестного — None (фронтенд не тостит).
        assert!(p.on_revoked(2, t).is_none());
        assert!(p.is_empty());
    }

    #[test]
    fn отказ_снимает_сразу() {
        let t = t0();
        let mut p = PendingInvites::new();
        p.on_invite(inc(3), t);
        p.on_invite(inc(4), t);
        assert_eq!(p.on_decline(3, t).map(|i| i.gid), Some(3));
        assert_eq!(gids(&p, t), vec![4]);
        // `:decline` по gid без приглашения — тоже запоминается.
        assert!(p.on_decline(9, t).is_none());
        assert!(p.recently_declined(9, t));
    }

    #[test]
    fn полный_список_с_сервера_снимает_устаревшие_приглашения() {
        let mut p = PendingInvites::new();
        let now = old(&mut p, t0(), &[1, 2, 3]);
        // Пока были офлайн, группу 1 удалили, а 2 отозвали.
        let gone = p.on_synced(&[3], 0, true, now);
        assert_eq!(gone, named(&[(1, "g1"), (2, "g2")]));
        assert_eq!(gids(&p, now), vec![3]);
        assert!(p.on_synced(&[3], 0, true, now).is_empty());
    }

    #[test]
    fn неполный_список_снимает_устаревшие_только_до_последнего_gid() {
        let mut p = PendingInvites::new();
        let now = old(&mut p, t0(), &[1, 2, 3, 20, 30]);
        // Сервер обрезал список после gid 3: 2 отозвано, про 20 и 30 —
        // ничего не известно.
        let gone = p.on_synced(&[1, 3], 0, false, now);
        assert_eq!(gone, named(&[(2, "g2")]));
        assert_eq!(gids(&p, now), vec![1, 3, 20, 30]);
        // Пустой неполный список ничего не снимает.
        assert!(p.on_synced(&[], 0, false, now).is_empty());
        // Полный — снимает и хвост.
        let gone = p.on_synced(&[1, 3, 30], 0, true, now);
        assert_eq!(gone, named(&[(20, "g20")]));
    }

    #[test]
    fn окно_списка_снимает_устаревшие_только_в_своих_границах() {
        let mut p = PendingInvites::new();
        let now = old(&mut p, t0(), &[1, 2, 17, 18, 25, 40]);
        let gone = p.on_synced(&[17, 25], 17, false, now);
        assert_eq!(gone, named(&[(18, "g18")]));
        assert_eq!(gids(&p, now), vec![1, 2, 17, 25, 40]);
        let gone = p.on_synced(&[17, 25], 17, true, now);
        assert_eq!(gone, named(&[(40, "g40")]));
        assert_eq!(gids(&p, now), vec![1, 2, 17, 25]);
    }

    #[test]
    fn запоздавший_список_не_возвращает_отклонённое_приглашение() {
        let t = t0();
        let mut p = PendingInvites::new();
        let now = old(&mut p, t, &[1, 2]);
        p.on_decline(1, now);
        p.on_decline(2, now);
        assert!(!p.contains(2));
        // Ответ на отказ от 1 пришёл поздно — собран до отказа от 2: [2].
        let soon = now + Duration::from_millis(100);
        assert_eq!(p.on_invite(inc(2), soon), InviteOutcome::Declined);
        assert!(!p.contains(2));
        assert!(p.on_synced(&[2], 0, true, soon).is_empty());
        // Повторный отказ продлевает память, не дублируя её.
        p.on_decline(2, soon);
        assert_eq!(p.declined.iter().filter(|(g, _)| *g == 2).count(), 1);
        // Чуть раньше срока — ещё помним.
        let edge = soon + INVITE_DECLINE_MEMORY - Duration::from_millis(1);
        assert_eq!(p.on_invite(inc(2), edge), InviteOutcome::Declined);
        // Спустя INVITE_DECLINE_MEMORY повторное приглашение снова видно.
        let after = soon + INVITE_DECLINE_MEMORY;
        assert!(!p.recently_declined(2, after));
        assert_eq!(p.on_invite(inc(2), after), InviteOutcome::New);
        assert!(p.contains(2));
        // Отказ от 1 (раньше) тоже забыт.
        assert_eq!(p.on_invite(inc(1), after), InviteOutcome::New);
    }

    #[test]
    fn список_после_отклонённого_входа_снимает_принятое_приглашение() {
        let mut p = PendingInvites::new();
        let now = old(&mut p, t0(), &[7]);
        // JOIN отклонён (приглашение отозвано) — список без 7.
        let gone = p.on_synced(&[], 0, true, now);
        assert_eq!(gone, named(&[(7, "g7")]));
        assert!(p.is_empty());
    }

    #[test]
    fn сверка_не_снимает_только_что_пришедшее_приглашение() {
        let t = t0();
        let mut p = PendingInvites::new();
        p.on_invite(inc(1), t);
        let fresh_at = t + INVITE_SYNC_GRACE * 2;
        p.on_invite(inc(2), fresh_at);
        // Список собран сервером до приглашения 2 и пришёл после него.
        let now = fresh_at + INVITE_SYNC_GRACE - Duration::from_millis(1);
        let gone = p.on_synced(&[], 0, true, now);
        assert_eq!(gone, named(&[(1, "g1")]));
        assert!(p.contains(2), "свежее приглашение не снято устаревшим списком");
        // Ровно через INVITE_SYNC_GRACE — уже снимается (как `>=` в App).
        let gone = p.on_synced(&[], 0, true, fresh_at + INVITE_SYNC_GRACE);
        assert_eq!(gone, named(&[(2, "g2")]));
    }

    #[test]
    fn истёкшие_снимаются_на_тике_повтор_продлевает() {
        let t = t0();
        let mut p = PendingInvites::new();
        let mut a = inc(1);
        a.expires_in = Some(10);
        p.on_invite(a.clone(), t);
        p.on_invite(inc(2), t); // бессрочное
        let l = p.list(t + Duration::from_millis(500));
        assert_eq!(l[0].expires_in_s, Some(10), "округление вверх");
        assert_eq!(l[1].expires_in_s, None);
        assert!(p.tick(t + Duration::from_secs(9)).is_empty());
        // Повтор продлевает срок.
        p.on_invite(a, t + Duration::from_secs(9));
        assert!(p.tick(t + Duration::from_secs(15)).is_empty());
        // Повтор без срока (v2-сервер) срок не снимает.
        assert_eq!(p.on_invite(inc(1), t + Duration::from_secs(15)), InviteOutcome::Updated);
        let gone = p.tick(t + Duration::from_secs(19));
        assert_eq!(gone.iter().map(|i| i.gid).collect::<Vec<_>>(), vec![1]);
        assert_eq!(gone[0].expires_in_s, Some(0));
        assert_eq!(gids(&p, t + Duration::from_secs(19)), vec![2]);
    }

    #[test]
    fn тик_забывает_старые_отказы() {
        let t = t0();
        let mut p = PendingInvites::new();
        p.on_decline(1, t);
        p.tick(t + Duration::from_secs(1));
        assert_eq!(p.declined.len(), 1);
        p.tick(t + INVITE_DECLINE_MEMORY);
        assert!(p.declined.is_empty());
    }

    #[test]
    fn из_invite_info_без_срока() {
        let i = payloads::InviteInfo {
            gid: 4,
            group_name: "g".into(),
            from_pubkey: [1; 32],
            from_name: "a".into(),
            expires_in: 90,
        };
        let inc: IncomingInvite = i.into();
        assert_eq!((inc.gid, inc.expires_in), (4, Some(90)));
    }

    #[test]
    fn константы_совпадают_с_tui() {
        assert_eq!(INVITE_SYNC_GRACE, crate::tui::app::INVITE_SYNC_GRACE);
        assert_eq!(INVITE_DECLINE_MEMORY, crate::tui::app::INVITE_DECLINE_MEMORY);
    }
}
