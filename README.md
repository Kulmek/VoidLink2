# VoidLink

**Виртуальная локальная сеть для своих: соберите группу из друзей и играйте так, будто все сидят в одной LAN.**

[![CI](https://github.com/adamantida/VoidLink2/actions/workflows/ci.yml/badge.svg)](https://github.com/adamantida/VoidLink2/actions/workflows/ci.yml)
![Rust](https://img.shields.io/badge/Rust-edition%202024-b7410e?logo=rust)
![Platforms](https://img.shields.io/badge/платформы-Windows%20%7C%20Linux%20%7C%20macOS-555)

VoidLink работает по схеме Hamachi и ZeroTier: участники объединяются в группы,
каждый получает постоянный IP вида `100.66.<gid>.x`, и внутри группы проходят
`ping`, игровой трафик и любые TCP/UDP-сервисы. Сервер свой, ключи свои.

**Содержание:** [Что это](#что-это) · [Возможности](#возможности) · [Интерфейс](#интерфейс) · [Быстрый старт](#быстрый-старт) · [Команды](#команды) · [Структура](#структура-проекта) · [Документация](#документация) · [Статус](#статус-и-дорожная-карта) · [Участие](#участие-в-разработке)

## Что это

Сервер VoidLink — точка встречи: хранит группы, выдаёт IP, принимает приглашения
и помогает клиентам найти друг друга. Пока прямого канала нет, трафик идёт через
сервер как через релей. Когда клиенты пробили NAT (UDP hole punching), пакеты
идут напрямую, peer-to-peer.

```mermaid
flowchart LR
    A["Клиент A<br/>100.66.3.2"] -->|"управление и релей, ChaCha20"| S["tunnel-server<br/>рандеву и релей"]
    B["Клиент B<br/>100.66.3.3"] -->|"управление и релей, ChaCha20"| S
    A <-.->|"прямой UDP после hole punching"| B
```

Полезная нагрузка группы шифруется ключом группы, который создаёт и раздаёт
сервер, поэтому оператор сервера считается доверенным (см. [SECURITY](docs/SECURITY.md)).
Посторонние в сети видят только открытый заголовок `gid | src_ip | dst_ip`.
Список друзей хранится у клиента, а не на сервере. IP закреплён за ключом
участника и возвращается с ним после офлайна.

## Возможности

### Сеть

- Публичные и приватные группы, адреса `100.66.<gid>.0/24` (gid от 1 до 254).
- Прямой канал через UDP hole punching, релей сервера работает сразу как запасной путь.
- Автовход в выбранные группы при запуске, поиск LAN-адресов, переподключение
  за секунды после перезапуска сервера.
- Приглашения не теряются, даже если адресат был офлайн. Режим невидимки.
- Резервный TCP-путь до сервера на случай блокировки UDP (`set-transport auto|udp|tcp`).
- Встроенный DNS: имена пиров `<участник>.vl` и `<участник>.<группа>.vl`
  (`100.66.0.53`); IPv6-оверлей `fd66:766c:696e::/48`.

### Безопасность

- Identity на ed25519 (подписи) и x25519 (ключи канала). Friend code выглядит как `TUN-XXXX…`.
- Шифрование ChaCha20-Poly1305: ключ группы для трафика, сеансовые ключи для управления.
  HELLO подписан, клиент закрепляет ключ сервера (pinning).
- Cookie и CHALLENGE на рукопожатие, окно повторов для шифрованных фреймов.
- Лимиты скорости на сессию, IP, группу и сервер. Ротация ключа: `tunnel-server rotate-key`.
- Перенос identity между машинами: `export-identity` / `import-identity`.

Подробнее: [SECURITY](docs/SECURITY.md).

### Интерфейс

- **CLI** `tunnel-client` для скриптов и быстрых действий.
- **TUI** на ratatui: группы, друзья, участники, лог, приглашения, мышь, поиск,
  командная строка `:`, пять тем (тёмная, светлая, контрастная, янтарная, фьорд).
- **Демон / служба Windows** `tunnel-daemon`: туннель поднимается до входа пользователя.
  TUI, CLI и трей подключаются к демону по IPC (именованный канал / Unix-сокет)
  без прав администратора; без демона `tui` поднимает свой движок (`--embedded`),
  см. [DAEMON](docs/DAEMON.md).
- **Трей** `tunnel-tray`: состояние соединения и уведомления.

### Платформы

| Компонент | Windows | Linux | macOS |
|---|:---:|:---:|:---:|
| Сервер `tunnel-server` | отладка | да | отладка |
| Клиент: CLI и TUI | да | да | да |
| Туннель (TUN-адаптер) | да (Wintun) | да (`/dev/net/tun`) | да (`utun`) |
| Служба и трей | да | — | — |

## Интерфейс

TUI работает в терминале. Слева группы и друзья, справа участники выбранной
группы, внизу лог и график трафика:

```text
┌ VoidLink ── сервер 203.0.113.10:5555 ── подключено ────────────────────────┐
├ Группы ──────────────┬ Участники «mynet» · 100.66.3.x ─────────────────────┤
│ ▸ mynet     [pub]  4 │ IP           связь    RTT   имя                     │
│   home      [prv]  2 │ 100.66.3.2   direct   12ms  alpha                   │
│ Друзья               │ 100.66.3.3   relay    48ms  bravo                   │
│ ● bravo              │ 100.66.3.4   —        —     charlie   (офлайн)      │
├ Лог ──────────────────────────────────────────────── Трафик ↓ 1.2 МБ/с ──┤
│ 12:05 alpha: прямой канал установлен                                       │
└ : команда · / поиск · Tab фокус · F1 справка ───────────────────────────────┘
```

Клавиши, мышь и темы: [TUI](docs/TUI.md).

## Быстрый старт

### Сервер на Linux

Нужен VPS с белым IP и открытым портом `5555` (UDP; TCP на том же порту — для
фолбэка).

```bash
cargo build --release -p tunnel-server
sudo infrastructure/linux/install-server.sh target/release/tunnel-server --listen 0.0.0.0:5555
sudo ufw allow 5555/udp && sudo ufw allow 5555/tcp
```

Установщик создаёт службу `tunnel-server` и печатает **Server code** (`TUN-…`):
клиенты вписывают его при добавлении сервера. Подробнее: [SERVER](docs/SERVER.md).

### Клиент на Windows

1. Распакуйте архив и в PowerShell от администратора выполните:

   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install.ps1
   ```

2. Добавьте сервер (команды — из `%ProgramFiles%\Tunnel`):

   ```powershell
   .\tunnel-client.exe add-server 203.0.113.10:5555 TUN-XXXX… mysrv
   ```

3. Задайте имя и откройте интерфейс (пока TUI поднимает туннель сам, нужна
   консоль администратора):

   ```powershell
   .\tunnel-client.exe set-name alpha
   .\tunnel-client.exe tui
   ```

В TUI создайте группу (`F2`) или войдите в существующую (`j`). Подробнее: [INSTALL](docs/INSTALL.md).

### Клиент на Linux и macOS

Либо держит туннель демон (`tunnel-daemon console`, тогда `tui` — тонкий клиент). Нужен root (или `CAP_NET_ADMIN` на Linux); адаптер — `voidlink0` (Linux) или `utunN` (macOS).
Подробнее: [INSTALL](docs/INSTALL.md).

```bash
cargo build --release -p tunnel-client
./target/release/tunnel-client add-server 203.0.113.10:5555 TUN-XXXX… mysrv
./target/release/tunnel-client create mynet --private
sudo ./target/release/tunnel-client --dir "$HOME/.tunnel-client" tui
```

Когда оба участника в группе, проверка связи: `ping 100.66.<gid>.3`.

## Команды

### Клиент `tunnel-client`

| Команда | Действие |
|---|---|
| `id` | friend code и ключи identity |
| `set-name <имя>` / `set-status <текст>` | имя и статус |
| `add-server <addr> <code> [label]` / `servers` / `del-server <N\|addr\|label>` | серверы клиента |
| `groups` | группы на сервере |
| `create <имя> [--private]` | создать группу (владелец — вы) |
| `join <gid>` / `leave <gid>` / `delete <gid>` | войти, выйти, удалить |
| `invite` / `kick` / `ban` / `unban <gid> <peer>` | приглашения и модерация (владелец) |
| `invites` / `decline <gid>` | неотвеченные приглашения и отказ |
| `add-friend <code> [alias]` / `del-friend <alias>` / `friends` | друзья (хранятся локально) |
| `run` | поднять туннель, лог в консоль |
| `tui` (`ui`) | интерфейс |

`peer` — friend code (`TUN-…`), hex-ключ или alias. Остальные команды
(`bans`, `transfer`, `rename`, `alias`, `set-transport`, `set-mtu`, `dns`,
`invisible`, `export-identity` и др.): `tunnel-client help` и [CLIENT](docs/CLIENT.md).
Глобальные флаги: `--dir`, `--profile`, `--debug`, `--server`, для `run`/`tui`
ещё `--adapter` и `--dll` (только Windows).

### Служба и сервер

- `tunnel-daemon console|service|install|uninstall [--purge]`: консоль, режим SCM, установка и удаление службы. См. [DAEMON](docs/DAEMON.md).
- `tunnel-server [адрес=0.0.0.0:5555] [--data <dir>] [--workers N] [-q] [--tcp|--no-tcp] [--metrics <addr>]`, а также лимиты (`--relay-rate`, `--join-rate`, `--max-owned-groups` и др.). Подкоманда `rotate-key`. См. [SERVER](docs/SERVER.md).

## Структура проекта

Cargo-workspace на Rust 2024:

| Каталог | Назначение |
|---|---|
| `crates/protocol` | протокол v3: фреймы, рукопожатие, identity, шифрование, фрагментация |
| `crates/server` | `tunnel-server`: рандеву, группы, IP, приглашения, релей, метрики, персистентность |
| `crates/client` | `tunnel-client`: движок, CLI, TUI, TUN (Wintun, Linux, macOS), DNS, IPv6, TCP-путь |
| `crates/ipc` | протокол и транспорт между службой и интерфейсами |
| `crates/daemon` | `tunnel-daemon`: служба, владеющая туннелем |
| `crates/winsvc` | установка и запуск службы Windows (SCM) |
| `crates/tray` | `tunnel-tray`: значок в трее Windows |

Прочее: `docs/` (документация), `infrastructure/` (systemd, NAT-стенд, скрипты
Windows), `vendor/wintun/` (подписанный `wintun.dll`, который сборка кладёт рядом с exe).

## Документация

Карта и порядок чтения по ролям: [docs/README](docs/README.md).

| Документ | О чём |
|---|---|
| [INSTALL](docs/INSTALL.md) | установка клиента на Windows, Linux и macOS |
| [SERVER](docs/SERVER.md) | сборка, systemd, флаги, ротация ключа |
| [CLIENT](docs/CLIENT.md) | клиент: команды, группы, друзья |
| [TUI](docs/TUI.md) | интерфейс: клавиши, мышь, темы |
| [CONFIG](docs/CONFIG.md) | `client.json`, `server.json` и их поля |
| [TROUBLESHOOTING](docs/TROUBLESHOOTING.md) | типичные проблемы и решения |
| [FAQ](docs/FAQ.md) | частые вопросы |
| [GLOSSARY](docs/GLOSSARY.md) | термины: identity, friend code, gid, lease |
| [ARCHITECTURE](docs/ARCHITECTURE.md) | компоненты, потоки данных, состояние |
| [PROTOCOL](docs/PROTOCOL.md) | спецификация протокола v3 |
| [SECURITY](docs/SECURITY.md) | модель угроз, криптография, ключи |
| [NETWORKING](docs/NETWORKING.md) | NAT, hole punching, релей, TCP-путь, DNS, IPv6 |
| [DAEMON](docs/DAEMON.md) | служба, трей, жизненный цикл туннеля |
| [IPC](docs/IPC.md) | протокол между службой и интерфейсами |
| [DEVELOPMENT](docs/DEVELOPMENT.md) | окружение, сборка, проверки перед коммитом |
| [TESTING](docs/TESTING.md) | тесты, e2e-сценарии, NAT-лаборатория |
| [PLAN](docs/PLAN.md) | план развития по этапам |
| [CHANGELOG](docs/CHANGELOG.md) | история изменений |

## Статус и дорожная карта

- **Готово:** протокол v3, группы и lease IP, движок клиента (Windows, Linux, macOS),
  TUI с мышью, темами, экранами серверов и управления группой, многопоточный сервер
  с лимитами, метриками и TCP-фолбэком, ротация ключа сервера, DNS и IPv6,
  служба Windows и трей.
- **TUI и CLI поверх демона** (`tui --remote` / `--embedded`): реализованы. Служба
  Windows (`service`) и `console` запускают настоящий движок; без сервера демон ждёт
  первой настройки (`AddServer`), см. [DAEMON](docs/DAEMON.md).

Подробно по этапам: [PLAN](docs/PLAN.md).

## Участие в разработке

Перед pull request проверьте:

```bash
cargo fmt --all -- --check
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
```

Правила работы с ветками и советы по отладке: [DEVELOPMENT](docs/DEVELOPMENT.md).
Найдя уязвимость, не открывайте публичный issue, а напишите мейнтейнеру напрямую.
