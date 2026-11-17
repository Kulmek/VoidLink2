//! Клиент туннеля (протокол v3): CLI-диспетчер.
//!
//! Глобальные флаги: `--dir <путь>` (каталог конфига), `--debug`,
//! `--server <N|addr|label>` (по умолчанию — последний использованный).
//! Для `run` дополнительно: `--adapter <имя>`, `--dll <путь>`.
//!
//! Подкоманды:
//!   id                          — friend code и ключи identity
//!   set-name <имя>              — имя профиля (видят другие)
//!   set-status <текст>          — статус-текст
//!   add-server <addr> <code> [label] — добавить сервер (addr ip:port, code — friend code сервера)
//!   servers                     — список серверов
//!   del-server <N|addr|label>   — удалить сервер
//!   groups                      — список групп на сервере
//!   create <имя> [--private]    — создать группу (владелец = мы)
//!   join <gid>                  — войти в группу
//!   leave <gid>                 — выйти
//!   invites                     — неотвеченные приглашения
//!   decline <gid>               — отклонить приглашение
//!   invite <gid> <peer>         — пригласить (владелец)
//!   kick <gid> <peer>           — исключить (владелец)
//!   ban <gid> <peer>            — забанить (владелец)
//!   unban <gid> <peer>          — снять бан (владелец)
//!   bans <gid>                  — баны и неотвеченные приглашения (владелец)
//!   transfer <gid> <peer>       — передать группу участнику (владелец)
//!   rename <gid> <имя>          — переименовать (владелец)
//!   delete <gid>                — удалить группу (владелец)
//!   friend-groups <peer>        — группы друга
//!   add-friend <code> [alias]   — добавить друга локально
//!   del-friend <alias>          — удалить друга
//!   friends                     — список друзей
//!   invisible on|off            — невидимка (другие видят нас офлайн)
//!   run                         — поднять туннель (autojoin-группы)
//!   tui                         — поднять туннель с графическим интерфейсом
//!
//! Если в конфиге нет имени или серверов, `tui` сначала показывает
//! экран первичной настройки (tui::setup): имя, сервер, адаптер, dll.

mod dns;
mod engine;
#[cfg(test)]
mod engine_e2e;
mod ipv6;
mod invites;
mod snapshot;
mod profile;
mod store;
mod tcp_link;
#[cfg(windows)]
mod tun;
#[cfg(target_os = "linux")]
mod tun_linux;
#[cfg(target_os = "macos")]
mod tun_macos;
mod tui;

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use tunnel_protocol as proto;
use proto::ctrl;
use proto::payloads;

use store::{Config, StoredFriend, StoredServer};

fn main() -> Result<()> {
    let mut dir = store::default_dir();
    let mut adapter = engine::DEFAULT_ADAPTER.to_string();
    let mut adapter_set = false;
    let mut dll: Option<String> = None;
    let mut server_sel: Option<String> = None;
    let mut debug = false;
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    // Глобальные флаги (до подкоманды).
    let mut i = 0;
    while i < args.len() {
        let a = args[i].as_str();
        if a == "--dir" {
            dir = args.get(i + 1).context("--dir требует значение")?.into();
            args.drain(i..=i + 1);
        } else if a == "--adapter" {
            adapter = args.get(i + 1).context("--adapter требует значение")?.clone();
            adapter_set = true;
            args.drain(i..=i + 1);
        } else if a == "--dll" {
            if !cfg!(windows) {
                bail!("--dll нужен только на Windows (wintun.dll)");
            }
            dll = Some(args.get(i + 1).context("--dll требует значение")?.clone());
            args.drain(i..=i + 1);
        } else if a == "--server" {
            server_sel = Some(args.get(i + 1).context("--server требует значение")?.clone());
            args.drain(i..=i + 1);
        } else if a == "--debug" {
            debug = true;
            args.remove(i);
        } else {
            i += 1;
        }
    }
    engine::set_debug(debug);

    let store = store::Store::new(&dir);
    let mut cfg: Config = store.load().context("чтение конфига")?;
    // Адаптер и dll из конфига (экран «Серверы» в TUI), если не заданы флагами.
    if !adapter_set && !cfg.adapter.is_empty() {
        adapter = cfg.adapter.clone();
    }
    if dll.is_none() && !cfg.dll.is_empty() {
        dll = Some(cfg.dll.clone());
    }

    let save = |c: &Config| -> Result<()> { store.save(c).context("запись конфига") };

    // Identity: создаётся один раз и сразу сохраняется, чтобы все команды
    // (и `run`) использовали одну и ту же личность.
    if cfg.identity.is_none() {
        let id = store::ensure_identity(&mut cfg);
        save(&cfg)?;
        println!("создана новая identity: {}", id.friend_code());
    }

    let cmd = args.first().cloned().unwrap_or_else(|| "tui".into());
    let rest: Vec<String> = args[1.min(args.len())..].to_vec();
    let rest: &[String] = &rest;

    let identity = store::ensure_identity(&mut cfg);

    match cmd.as_str() {
        "help" | "-h" | "--help" => usage(),
        "id" => {
            let id = store::ensure_identity(&mut cfg);
            save(&cfg)?;
            println!("friend code: {}", id.friend_code());
            println!("ed25519 pub: {}", proto::hex_of(&id.ed_pub()));
            println!("x25519 pub:  {}", proto::hex_of(&id.x_pub()));
            println!("name:        {}", if cfg.name.is_empty() { "(не задано)" } else { &cfg.name });
            println!("status:      {}", if cfg.status.is_empty() { "(не задано)" } else { &cfg.status });
        }
        "set-name" => {
            let name = rest.join(" ");
            bail_if_empty(&name, "usage: set-name <имя>");
            cfg.name = name;
            save(&cfg)?;
            println!("имя установлено: {}", cfg.name);
        }
        "set-status" => {
            let text = rest.join(" ");
            cfg.status = text;
            save(&cfg)?;
            println!("статус установлен: {:?}", cfg.status);
        }
        "add-server" => {
            let addr = rest.get(0).context("usage: add-server <addr> <code> [label]")?;
            let code = rest.get(1).context("usage: add-server <addr> <code> [label]")?;
            addr.parse::<SocketAddr>().context("addr должен быть ip:port")?;
            let pub_hex = proto::hex_of(&proto::Identity::parse_friend_code(code)?);
            let label = rest.get(2).cloned().unwrap_or_default();
            if cfg.servers.iter().any(|s| s.addr == *addr) {
                bail!("сервер {addr} уже добавлен");
            }
            cfg.servers.push(StoredServer { addr: addr.clone(), pubkey: pub_hex, label });
            save(&cfg)?;
            println!("сервер {addr} добавлен (pubkey закреплён)");
        }
        "servers" => {
            if cfg.servers.is_empty() {
                println!("(нет серверов; добавь: add-server <addr> <code> [label])");
            }
            for (n, s) in cfg.servers.iter().enumerate() {
                println!("{}: {} {} [{}]", n, s.addr, if s.label.is_empty() { "-" } else { &s.label }, s.pubkey);
            }
        }
        "del-server" => {
            let tok = rest.first().context("usage: del-server <N|addr|label>")?;
            // Раньше числовой токен сравнивался сам с собой и
            // `del-server 1` удалял все серверы.
            let idx = find_server(&cfg, tok).with_context(|| format!("сервер {tok:?} не найден"))?;
            cfg.servers.remove(idx);
            save(&cfg)?;
            println!("удалено");
        }
        "groups" => with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
            let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
            conn.send_ctrl(ctrl::LIST_GROUPS, &[]);
            let p = conn.wait_for(ctrl::GROUP_LIST, std::time::Duration::from_secs(10))?;
            let items = payloads::dec_group_list(&p)?;
            if items.is_empty() {
                println!("(групп нет; создай: create <имя>)");
            }
            for g in items {
                println!(
                    "{:>4}  {:<20} {} online {}/{} {}",
                    g.gid,
                    g.name,
                    if g.private { "[private]" } else { "[public] " },
                    g.online,
                    g.total,
                    if g.mine { "(состою)" } else { "" }
                );
            }
            Ok(())
        })?,
        "create" => {
            let private = rest.iter().any(|a| a == "--private");
            let name: String = rest.iter().filter(|a| *a != "--private").cloned().collect::<Vec<_>>().join(" ");
            bail_if_empty(&name, "usage: create <имя> [--private]");
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                // После HELLO3 сервер шлёт GROUP_STATE каждой нашей группы:
                // созданная — та, которой нет среди своих в списке.
                conn.send_ctrl(ctrl::LIST_GROUPS, &[]);
                let p = conn.wait_for(ctrl::GROUP_LIST, std::time::Duration::from_secs(10))?;
                let known: std::collections::HashSet<u32> =
                    payloads::dec_group_list(&p)?.iter().filter(|g| g.mine).map(|g| g.gid).collect();
                conn.send_ctrl(ctrl::CREATE_GROUP, &payloads::enc_create_group(&name, private));
                let st = loop {
                    let p = conn.wait_for(ctrl::GROUP_STATE, std::time::Duration::from_secs(10))?;
                    let st = payloads::dec_group_state(&p)?;
                    if !st.deleted && !known.contains(&st.gid) {
                        break st;
                    }
                };
                println!("группа {} \"{}\" создана, мой IP {}", st.gid, st.name, proto::ip_str(st.my_ip));
                if autojoin_add(&store, server, st.gid)? {
                    println!("добавлена в autojoin");
                }
                Ok(())
            })?;
        }
        "join" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
                // Своё состояние — по gid (GROUP_STATE шлётся и на GET_GROUP).
                let st = loop {
                    let p = conn.wait_for(ctrl::GROUP_STATE, std::time::Duration::from_secs(10))?;
                    let st = payloads::dec_group_state(&p)?;
                    if st.gid == gid {
                        break st;
                    }
                };
                if st.deleted {
                    bail!("группа {gid} удалена");
                }
                println!("вошёл в {} \"{}\", мой IP {}", st.gid, st.name, proto::ip_str(st.my_ip));
                if autojoin_add(&store, server, gid)? {
                    println!("добавлена в autojoin");
                }
                Ok(())
            })?;
        }
        "invites" => with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
            // Сервер шлёт первое окно (до 16) неотвеченных приглашений сразу
            // после HELLO3 (потерянное запрашивается LIST_INVITES с 0),
            // остальные дочитываются окнами LIST_INVITES.
            let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
            let Some(mut list) = conn.invite_list()? else {
                bail!("список приглашений не получен (потеря пакетов) — повторите");
            };
            let mut items = Vec::new();
            let complete = loop {
                let next = list.next_from();
                items.append(&mut list.items);
                match next {
                    Some(from) => match conn.invite_page(from)? {
                        Some(page) => list = page,
                        None => break false,
                    },
                    None => break list.complete,
                }
            };
            for inv in &items {
                let from = cfg2
                    .friends
                    .iter()
                    .find(|f| f.pubkey == proto::hex_of(&inv.from_pubkey))
                    .map(|f| f.alias.clone())
                    .unwrap_or_else(|| inv.from_name.clone());
                println!(
                    "{:>4}  {:<20} от {from} (истекает через {})",
                    inv.gid,
                    inv.group_name,
                    engine::fmt_secs(inv.expires_in)
                );
            }
            if items.is_empty() {
                println!("(приглашений нет)");
            } else {
                if !complete {
                    println!("… показаны не все (остальные не получены — потеря пакетов), повторите");
                }
                println!("принять: join <gid> · отклонить: decline <gid>");
            }
            Ok(())
        })?,
        "decline" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                // Без списка не проверить, есть ли приглашение («отклонено»
                // было бы неправдой: DECLINE идемпотентен).
                let Some(mut list) = conn.invite_list()? else {
                    bail!("список приглашений не получен (потеря пакетов) — отказ не отправлен");
                };
                // Окно после HELLO — первые 16 по gid; gid дальше него —
                // окно с самого gid (иначе отказ от несуществующего
                // приглашения «прошёл» бы: DECLINE идемпотентен).
                if !list.covers(gid) {
                    list = conn.invite_page(gid)?.context(
                        "список приглашений не получен (потеря пакетов) — отказ не отправлен",
                    )?;
                }
                if !list.items.iter().any(|i| i.gid == gid) {
                    bail!("нет приглашения в группу {gid}");
                }
                // Сервер отвечает на DECLINE_INVITE свежим окном, покрывающим
                // gid, — это и подтверждение: gid в нём нет. DECLINE
                // идемпотентен, при потере (или запоздавшем старом списке) —
                // повтор.
                for _ in 0..3 {
                    conn.send_ctrl(ctrl::DECLINE_INVITE, &payloads::enc_gid(gid));
                    match conn.wait_for(ctrl::INVITE_LIST, std::time::Duration::from_secs(3)) {
                        Ok(p) => {
                            let l = payloads::dec_invite_list(&p)?;
                            if l.covers(gid) && !l.items.iter().any(|i| i.gid == gid) {
                                println!("приглашение в {gid} отклонено");
                                return Ok(());
                            }
                        }
                        Err(e) if e.to_string().starts_with("сервер:") => return Err(e),
                        Err(_) => {}
                    }
                }
                bail!("сервер не подтвердил отказ — повторите")
            })?;
        }
        "leave" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
                conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3)).ok(); // ждём ERROR
                autojoin_remove(&store, server, gid)?;
                println!("вышел из {gid} (autojoin снят)");
                Ok(())
            })?;
        }
        "invite" | "kick" | "ban" | "unban" | "transfer" => {
            let gid = parse_gid(rest.first())?;
            let peer = rest.get(1).context(format!("usage: {cmd} <gid> <peer (code|hex|alias)>"))?;
            let target = store::resolve_peer(&cfg, peer)?;
            let typ = match cmd.as_str() {
                "invite" => ctrl::INVITE,
                "kick" => ctrl::KICK,
                "ban" => ctrl::BAN,
                "unban" => ctrl::UNBAN,
                _ => ctrl::TRANSFER_OWNER,
            };
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(typ, &payloads::enc_gid_target(gid, &target));
                let r = conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3));
                if let Err(e) = r {
                    if e.to_string().contains("сервер:") {
                        bail!("{e}");
                    }
                }
                println!("{}: ок", cmd);
                Ok(())
            })?;
        }
        "rename" => {
            let gid = parse_gid(rest.first())?;
            let name = rest[1.min(rest.len())..].join(" ");
            bail_if_empty(&name, "usage: rename <gid> <имя>");
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::RENAME_GROUP, &payloads::enc_rename(gid, &name));
                let r = conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3));
                if let Err(e) = r {
                    if e.to_string().contains("сервер:") {
                        bail!("{e}");
                    }
                }
                println!("переименовано");
                Ok(())
            })?;
        }
        "delete" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::DELETE_GROUP, &payloads::enc_gid(gid));
                let r = conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3));
                if let Err(e) = r {
                    if e.to_string().contains("сервер:") {
                        bail!("{e}");
                    }
                }
                autojoin_remove(&store, server, gid)?;
                println!("группа {gid} удалена");
                Ok(())
            })?;
        }
        "friend-groups" => {
            let peer = rest.first().context("usage: friend-groups <peer>")?;
            let target = store::resolve_peer(&cfg, peer)?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::FRIEND_GROUPS, &payloads::enc_pubkey(&target));
                // Ответ — о ком спрошено (target в ответе).
                let items = loop {
                    let p = conn.wait_for(ctrl::FRIEND_GROUPS_RESP, std::time::Duration::from_secs(10))?;
                    let f = payloads::dec_friend_groups(&p)?;
                    if f.target == target {
                        break f.groups;
                    }
                };
                if items.is_empty() {
                    println!("(у друга нет видимых групп)");
                }
                for g in items {
                    println!("{:>4}  {:<20} {} {}", g.gid, g.name, if g.private { "[private]" } else { "[public] " }, if g.shared { "(общая)" } else { "" });
                }
                Ok(())
            })?;
        }
        "bans" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = connect(&store, cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::GROUP_ADMIN, &payloads::enc_gid(gid));
                let info = loop {
                    let p = conn.wait_for(ctrl::ADMIN_INFO, std::time::Duration::from_secs(10))?;
                    let a = payloads::dec_admin_info(&p)?;
                    if a.gid == gid {
                        break a;
                    }
                };
                let who = |pk: &[u8; 32], name: &str| {
                    let alias = cfg2.friends.iter().find(|f| f.pubkey == proto::hex_of(pk)).map(|f| f.alias.clone());
                    let shown = alias.unwrap_or_else(|| if name.is_empty() { "(без имени)".into() } else { name.to_string() });
                    format!("{shown:<20} {}", proto::friend_code_of(pk))
                };
                println!("баны группы {gid}:");
                if info.bans.is_empty() {
                    println!("  (нет)");
                }
                for b in &info.bans {
                    println!("  {}", who(&b.pubkey, &b.name));
                }
                println!("неотвеченные приглашения:");
                if info.invites.is_empty() {
                    println!("  (нет)");
                }
                for i in &info.invites {
                    println!("  {}  истекает через {}", who(&i.pubkey, &i.name), engine::fmt_secs(i.expires_in));
                }
                println!("снять бан: unban {gid} <peer> · отозвать приглашение: kick {gid} <peer>");
                Ok(())
            })?;
        }
        "invisible" => {
            let on = match rest.first().map(|s| s.as_str()) {
                Some("on") => true,
                Some("off") => false,
                _ => bail!("usage: invisible on|off"),
            };
            cfg.invisible = on;
            save(&cfg)?;
            // Флаг уходит в HELLO3: на сервере он живёт, пока жива сессия.
            println!(
                "невидимка {}: применится при следующем подключении (tui/run)",
                if on { "включена" } else { "выключена" }
            );
        }
        "add-friend" => {
            let code = rest.first().context("usage: add-friend <code> [alias]")?;
            let pk = proto::Identity::parse_friend_code(code)?;
            let alias = rest.get(1).cloned().unwrap_or_else(|| code.clone());
            if cfg.friends.iter().any(|f| f.pubkey == proto::hex_of(&pk)) {
                bail!("друг уже добавлен");
            }
            cfg.friends.push(StoredFriend { pubkey: proto::hex_of(&pk), alias: alias.clone() });
            save(&cfg)?;
            println!("друг добавлен: {} ({})", alias.clone(), proto::hex_of(&pk));
        }
        "del-friend" => {
            let alias = rest.first().context("usage: del-friend <alias>")?;
            let before = cfg.friends.len();
            cfg.friends.retain(|f| &f.alias != alias);
            if cfg.friends.len() == before {
                bail!("друг {alias:?} не найден");
            }
            save(&cfg)?;
            println!("удалён");
        }
        "friends" => {
            if cfg.friends.is_empty() {
                println!("(нет друзей; добавь: add-friend <code> [alias])");
            }
            for f in &cfg.friends {
                println!("{:<16} {}", f.alias, f.pubkey);
            }
        }
        "run" | "tui" | "ui" => {
            let tui_mode = cmd != "run";
            // Первичная настройка: если конфиг не заполнен (нет имени или
            // серверов) и флаги не заданы — спрашиваем прямо в TUI, до старта
            // движка. Консольному `run` достаточно CLI-подсказки.
            if tui_mode && (cfg.name.is_empty() || cfg.servers.is_empty()) {
                if !tui::setup::run(&mut cfg, &mut adapter, &mut dll)? {
                    bail!("настройка не завершена; запусти ещё раз или задай параметры командами CLI");
                }
                save(&cfg)?;
            }
            if cfg.name.is_empty() {
                bail!("задай имя: set-name <имя> (или запусти `tunnel-client tui` — настройка там)");
            }
            let (server, pub_key) = pick_server(&cfg, server_sel.as_deref())?;
            save(&cfg)?;
            let cfg = Arc::new(cfg);
            let store = Arc::new(store::Store::new(&dir));
            if !tui_mode {
                // Автовход, ротация ключа сервера, невидимка — в client.json.
                let save_store = store.clone();
                let save = Arc::new(move |c: &Config| {
                    let _ = save_store.save(c);
                });
                engine::run(cfg, server, pub_key, identity.clone(), &adapter, dll, save)?;
            } else {
                tui::run(
                    cfg,
                    server,
                    pub_key,
                    identity.clone(),
                    &adapter,
                    dll,
                    store,
                )?;
            }
        }
        other => {
            eprintln!("неизвестная команда: {other:?}");
            usage();
            std::process::exit(2);
        }
    }
    Ok(())
}

/// Подсказка по флагам `run` для текущей ОС.
fn run_flags_help() -> &'static str {
    if cfg!(windows) {
        "--adapter <имя wintun-адаптера> --dll <путь к wintun.dll>; нужен запуск от администратора"
    } else if cfg!(target_os = "linux") {
        "--adapter <имя интерфейса, по умолчанию voidlink0>; нужен root или CAP_NET_ADMIN"
    } else {
        "адаптер — utunN, выбирается автоматически; нужен запуск через sudo"
    }
}

fn usage() {
    println!(
        r#"tunnel-client (протокол v3) — Hamachi-подобный VPN
global: --dir <path> --debug --server <N|addr|label> (по умолчанию — последний использованный)
  id                          friend code и identity
  set-name <имя>              имя профиля
  set-status <текст>          статус
  add-server <addr> <code> [label]
  servers | del-server <N|addr|label>
  groups                      список групп
  create <имя> [--private]    создать группу
  join <gid> | leave <gid> | delete <gid>
  invites | decline <gid>     приглашения: список / отклонить
  invite <gid> <peer> | kick <gid> <peer> | ban <gid> <peer>
  unban <gid> <peer>          снять бан
  bans <gid>                  баны и неотвеченные приглашения (владелец)
  transfer <gid> <peer>       передать группу участнику
  rename <gid> <имя>
  friend-groups <peer>
  add-friend <code> [alias] | del-friend <alias> | friends
  invisible on|off            невидимка: другие видят вас офлайн
  run                         поднять туннель (global: --adapter --dll --server <N>, см. ниже)
  tui                         то же, но с графическим интерфейсом (ratatui)
peer = friend code (TUN-…) | hex | alias

Если при запуске tui имя или сервер не заданы — сначала открывается
экран первичной настройки (Enter — применить, Esc — отмена)."#
    );
    println!("run/tui: {}", run_flags_help());
}

fn bail_if_empty(s: &str, msg: &str) {
    if s.trim().is_empty() {
        eprintln!("{msg}");
        std::process::exit(2);
    }
}

fn parse_gid(v: Option<&String>) -> Result<u32> {
    let v = v.context("нужен gid")?;
    v.parse::<u32>().context("gid должен быть числом")
}

/// Индекс сервера по токену: номер из `servers` (с 0), адрес или метка.
fn find_server(cfg: &Config, tok: &str) -> Option<usize> {
    if let Some(i) = cfg.servers.iter().position(|s| s.addr == tok || (!s.label.is_empty() && s.label == tok)) {
        return Some(i);
    }
    tok.parse::<usize>().ok().filter(|n| *n < cfg.servers.len())
}

/// Выбор сервера: --server <N|addr|label>, иначе последний использованный
/// (`active_server`, его же автовход), иначе первый в списке.
fn pick_server(cfg: &Config, sel: Option<&str>) -> Result<(SocketAddr, [u8; 32])> {
    let active = cfg
        .servers
        .iter()
        .find(|s| s.addr.parse::<SocketAddr>().is_ok_and(|a| a.to_string() == cfg.active_server));
    let entry = match sel {
        // Раньше `--server N` всегда выбирал первый сервер.
        Some(tok) => &cfg.servers[find_server(cfg, tok).with_context(|| format!("сервер {tok:?} не найден"))?],
        None => active
            .or(cfg.servers.first())
            .context("нет серверов; добавь: add-server <addr> <code>")?,
    };
    let addr: SocketAddr = entry.addr.parse().context("bad server addr")?;
    let pkv = proto::hex_to_bytes(&entry.pubkey).context("bad server pubkey")?;
    anyhow::ensure!(pkv.len() == 32, "bad server pubkey");
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pkv);
    Ok((addr, pk))
}

/// Правка client.json по свежей копии с диска: CLI-команда не затирает
/// то, что успела записать раньше (ротация ключа сервера, автовход).
fn persist<T>(store: &store::Store, f: impl FnOnce(&mut Config) -> T) -> Result<T> {
    let mut c = store.load().context("чтение конфига")?;
    let r = f(&mut c);
    store.save(&c).context("запись конфига")?;
    Ok(r)
}

/// Одноразовое соединение с сервером. Ключ, перезакреплённый по цепочке
/// ротации (WELCOME), сразу сохраняется.
fn connect(
    store: &store::Store,
    cfg: &Config,
    server: SocketAddr,
    pub_key: &[u8; 32],
    identity: &proto::Identity,
) -> Result<engine::CtrlConn> {
    let conn = engine::CtrlConn::connect(cfg, server, pub_key, identity)?;
    if let Some(new_ed) = conn.rotated {
        persist(store, |c| c.repin_server(server, &new_ed))?;
        eprintln!(
            "ключ сервера {server} сменён по цепочке ротации; закреплён новый: {}",
            proto::friend_code_of(&new_ed)
        );
    }
    Ok(conn)
}

/// Автовход в `gid` сервера `server`. `true` — добавлен.
fn autojoin_add(store: &store::Store, server: SocketAddr, gid: u32) -> Result<bool> {
    persist(store, |c| {
        c.activate_server(server);
        let add = !c.autojoin.contains(&gid);
        if add {
            c.autojoin.push(gid);
        }
        add
    })
}

fn autojoin_remove(store: &store::Store, server: SocketAddr, gid: u32) -> Result<()> {
    persist(store, |c| {
        c.activate_server(server);
        c.autojoin.retain(|g| *g != gid);
    })
}

/// Выполняет замыкание с выбранным сервером.
fn with_server<T>(
    cfg: &Config,
    sel: Option<&str>,
    f: impl FnOnce(SocketAddr, [u8; 32], &Config) -> Result<T>,
) -> Result<T> {
    let (server, pub_key) = pick_server(cfg, sel)?;
    f(server, pub_key, cfg)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn srv(addr: &str, label: &str) -> StoredServer {
        StoredServer { addr: addr.into(), pubkey: String::new(), label: label.into() }
    }

    #[test]
    fn сервер_по_номеру_адресу_метке() {
        let cfg = Config {
            servers: vec![srv("1.1.1.1:5555", "home"), srv("2.2.2.2:5555", ""), srv("3.3.3.3:5555", "work")],
            ..Config::default()
        };
        assert_eq!(find_server(&cfg, "1"), Some(1), "номер — индекс, а не «всегда первый»");
        assert_eq!(find_server(&cfg, "2"), Some(2));
        assert_eq!(find_server(&cfg, "3"), None);
        assert_eq!(find_server(&cfg, "3.3.3.3:5555"), Some(2));
        assert_eq!(find_server(&cfg, "home"), Some(0));
        assert_eq!(find_server(&cfg, ""), None, "пустая метка не совпадает с сервером без метки");
    }
}
