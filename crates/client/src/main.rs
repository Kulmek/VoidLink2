//! Клиент туннеля v2: CLI-диспетчер.
//!
//! Глобальные флаги: `--dir <путь>` (каталог конфига), `--debug`.
//! Для `run` дополнительно: `--adapter <имя>`, `--dll <путь>`, `--server <N|addr|label>`.
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
//!   invite <gid> <peer>         — пригласить (владелец)
//!   kick <gid> <peer>           — исключить (владелец)
//!   ban <gid> <peer>            — забанить (владелец)
//!   rename <gid> <имя>          — переименовать (владелец)
//!   delete <gid>                — удалить группу (владелец)
//!   friend-groups <peer>        — группы друга
//!   add-friend <code> [alias]   — добавить друга локально
//!   del-friend <alias>          — удалить друга
//!   friends                     — список друзей
//!   run                         — поднять туннель (autojoin-группы)
//!   tui                         — поднять туннель с графическим интерфейсом

mod engine;
mod store;
mod tun;
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
    let mut adapter = "TunnelVPN".to_string();
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
            args.drain(i..=i + 1);
        } else if a == "--dll" {
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

    let save = |c: &Config| -> Result<()> { store.save(c).context("запись конфига") };

    // Identity: создаётся один раз и сразу сохраняется, чтобы все команды
    // (и `run`) использовали одну и ту же личность.
    if cfg.identity.is_none() {
        let id = store::ensure_identity(&mut cfg);
        save(&cfg)?;
        println!("создана новая identity: {}", id.friend_code());
    }

    let cmd = args.first().cloned().unwrap_or_else(|| "help".into());
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
            let before = cfg.servers.len();
            cfg.servers.retain(|s| s.addr != *tok && s.label != *tok && tok.parse::<usize>().map(|n| n.to_string() != *tok).unwrap_or(true));
            if cfg.servers.len() == before {
                bail!("сервер {tok:?} не найден");
            }
            save(&cfg)?;
            println!("удалено");
        }
        "groups" => with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
            let conn = engine::CtrlConn::connect(cfg2, server, &pub_key, &identity)?;
            conn.send_ctrl(ctrl::LIST_GROUPS, &payloads::enc_gid(0));
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
                let conn = engine::CtrlConn::connect(cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::CREATE_GROUP, &payloads::enc_create_group(&name, private));
                let p = conn.wait_for(ctrl::GROUP_STATE, std::time::Duration::from_secs(10))?;
                let st = payloads::dec_group_state(&p)?;
                println!("группа {} \"{}\" создана, мой IP {}", st.gid, st.name, proto::ip_str(st.my_ip));
                if !cfg2.autojoin.contains(&st.gid) {
                    let mut c = Config::clone(cfg2);
                    c.autojoin.push(st.gid);
                    save(&c)?;
                    println!("добавлена в autojoin");
                }
                Ok(())
            })?;
        }
        "join" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = engine::CtrlConn::connect(cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::JOIN_GROUP, &payloads::enc_gid(gid));
                let p = conn.wait_for(ctrl::GROUP_STATE, std::time::Duration::from_secs(10))?;
                let st = payloads::dec_group_state(&p)?;
                println!("вошёл в {} \"{}\", мой IP {}", st.gid, st.name, proto::ip_str(st.my_ip));
                if !cfg2.autojoin.contains(&gid) {
                    let mut c = Config::clone(cfg2);
                    c.autojoin.push(gid);
                    save(&c)?;
                    println!("добавлена в autojoin");
                }
                Ok(())
            })?;
        }
        "leave" => {
            let gid = parse_gid(rest.first())?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = engine::CtrlConn::connect(cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::LEAVE_GROUP, &payloads::enc_gid(gid));
                conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3)).ok(); // ждём ERROR
                let mut c = Config::clone(cfg2);
                c.autojoin.retain(|g| *g != gid);
                save(&c)?;
                println!("вышел из {gid} (autojoin снят)");
                Ok(())
            })?;
        }
        "invite" | "kick" | "ban" => {
            let gid = parse_gid(rest.first())?;
            let peer = rest.get(1).context(format!("usage: {cmd} <gid> <peer (code|hex|alias)>"))?;
            let target = store::resolve_peer(&cfg, peer)?;
            let typ = match cmd.as_str() {
                "invite" => ctrl::INVITE,
                "kick" => ctrl::KICK,
                _ => ctrl::BAN,
            };
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = engine::CtrlConn::connect(cfg2, server, &pub_key, &identity)?;
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
                let conn = engine::CtrlConn::connect(cfg2, server, &pub_key, &identity)?;
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
                let conn = engine::CtrlConn::connect(cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::DELETE_GROUP, &payloads::enc_gid(gid));
                let r = conn.wait_for(ctrl::CTRL_PING, std::time::Duration::from_secs(3));
                if let Err(e) = r {
                    if e.to_string().contains("сервер:") {
                        bail!("{e}");
                    }
                }
                let mut c = Config::clone(cfg2);
                c.autojoin.retain(|g| *g != gid);
                save(&c)?;
                println!("группа {gid} удалена");
                Ok(())
            })?;
        }
        "friend-groups" => {
            let peer = rest.first().context("usage: friend-groups <peer>")?;
            let target = store::resolve_peer(&cfg, peer)?;
            with_server(&cfg, server_sel.as_deref(), |server, pub_key, cfg2| {
                let conn = engine::CtrlConn::connect(cfg2, server, &pub_key, &identity)?;
                conn.send_ctrl(ctrl::FRIEND_GROUPS, &payloads::enc_pubkey(&target));
                let p = conn.wait_for(ctrl::FRIEND_GROUPS_RESP, std::time::Duration::from_secs(10))?;
                let items = payloads::dec_friend_groups(&p)?;
                if items.is_empty() {
                    println!("(у друга нет видимых групп)");
                }
                for g in items {
                    println!("{:>4}  {:<20} {} {}", g.gid, g.name, if g.private { "[private]" } else { "[public] " }, if g.shared { "(общая)" } else { "" });
                }
                Ok(())
            })?;
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
            let (server, pub_key) = pick_server(&cfg, server_sel.as_deref())?;
            if cfg.name.is_empty() {
                bail!("задай имя: set-name <имя>");
            }
            save(&cfg)?;
            let cfg = Arc::new(cfg);
            if cmd == "run" {
                engine::run(cfg, server, pub_key, identity.clone(), &adapter, dll)?;
            } else {
                let store = Arc::new(store::Store::new(&dir));
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

fn usage() {
    println!(
        r#"tunnel-client v2 — Hamachi-подобный VPN
global: --dir <path> --debug
  id                          friend code и identity
  set-name <имя>              имя профиля
  set-status <текст>          статус
  add-server <addr> <code> [label]
  servers | del-server <N|addr|label>
  groups                      список групп
  create <имя> [--private]    создать группу
  join <gid> | leave <gid> | delete <gid>
  invite <gid> <peer> | kick <gid> <peer> | ban <gid> <peer>
  rename <gid> <имя>
  friend-groups <peer>
  add-friend <code> [alias] | del-friend <alias> | friends
  run                         поднять туннель (global: --adapter --dll --server <N>)
  tui                         то же, но с графическим интерфейсом (ratatui)
peer = friend code (TUN-…) | hex | alias"#
    );
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

/// Выбор сервера: --server <N|addr|label> или первый в списке.
fn pick_server(cfg: &Config, sel: Option<&str>) -> Result<(SocketAddr, [u8; 32])> {
    let entry = match sel {
        Some(tok) => {
            let n = tok.parse::<usize>().ok();
            cfg.servers
                .iter()
                .find(|s| &s.addr == tok || &s.label == tok || n.is_some() && n.unwrap().to_string() == *tok)
                .with_context(|| format!("сервер {tok:?} не найден"))?
        }
        None => cfg.servers.first().context("нет серверов; добавь: add-server <addr> <code>")?,
    };
    let addr: SocketAddr = entry.addr.parse().context("bad server addr")?;
    let pkv = proto::hex_to_bytes(&entry.pubkey).context("bad server pubkey")?;
    anyhow::ensure!(pkv.len() == 32, "bad server pubkey");
    let mut pk = [0u8; 32];
    pk.copy_from_slice(&pkv);
    Ok((addr, pk))
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
