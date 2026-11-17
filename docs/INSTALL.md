# Установка клиента VoidLink

Нужен работающий сервер и его **Server code** (`TUN-…`) — см.
[SERVER.md](SERVER.md).

## Windows: служба + трей (рекомендуется)

Состав (zip-артефакт CI или `cargo build --release`):
`tunnel-daemon.exe`, `tunnel-client.exe`, `tunnel-tray.exe`, `wintun.dll`,
`install.ps1`, `uninstall.ps1`.

1. Распакуйте архив в любую папку.
2. PowerShell в этой папке:

   ```
   powershell -ExecutionPolicy Bypass -File .\install.ps1
   ```

   Скрипт сам запросит права администратора (UAC) и:
   - скопирует файлы в `%ProgramFiles%\Tunnel` (туда пишет только
     администратор; `wintun.dll` служба грузит только оттуда);
   - выполнит `tunnel-daemon install`: служба `TunnelDaemon` (LocalSystem,
     автозапуск, перезапуск при сбое), конфиг `%ProgramData%\tunnel\client.json`
     с закрытыми правами, импорт `%APPDATA%\tunnel\client.json` текущего
     пользователя (identity, друзья и friend code сохраняются), автозапуск
     трея при входе;
   - запустит службу и трей.

   Флаг `-NoTray` — не запускать трей сразу.

Туннель теперь живёт в службе: поднимается до входа пользователя, не падает
при закрытии окон. Трей показывает состояние и уведомления, TUI и CLI
работают **без прав администратора** и подключаются к службе по
`\\.\pipe\tunnel-daemon`.

### Первый запуск

```
cd "$env:ProgramFiles\Tunnel"
.\tunnel-client.exe add-server <ip:порт> <TUN-код-сервера> [label]
.\tunnel-client.exe set-name alpha
.\tunnel-client.exe tui
```

В TUI — создать (`:create <имя>`) или войти в группу, добавить друзей
(`add-friend <TUN-…>`), отметить группы для автовхода. Свой friend code —
`tunnel-client id`. Проверка: `ping 100.66.<gid>.<n>`.

### Обновление

Запустите `install.ps1` новой версии поверх: служба останавливается, exe
заменяются, служба стартует снова. Фронтенды переподключаются сами.

### Удаление

```
powershell -ExecutionPolicy Bypass -File "$env:ProgramFiles\Tunnel\uninstall.ps1"
```

(install.ps1 кладёт его рядом с exe; можно и из архива). Удаляются служба, адаптер Wintun, трей и
`%ProgramFiles%\Tunnel`. Конфиг в `%ProgramData%\tunnel` остаётся — при
повторной установке friend code тот же. `-Purge` удаляет и его (identity
теряется безвозвратно).

### Без службы (переносной режим)

`tunnel-client.exe run` или `tunnel-client.exe tui` из консоли
**администратора** — движок внутри процесса, `wintun.dll` рядом с exe,
конфиг `%APPDATA%\tunnel\client.json`. Закрыли окно — туннель упал. Не
запускайте одновременно со службой: одна identity — одна сессия на сервере.

## Linux / macOS

Клиент собирается и на Unix (`cargo build --release -p tunnel-client`);
туннель Wintun — только Windows, на Linux/macOS используется для
управления и разработки:

```
tunnel-client add-server <ip:порт> <TUN-код> [label]
tunnel-client id                 # friend code
tunnel-client groups             # группы на сервере
tunnel-client create mynet --private
tunnel-client invite <gid> <peer>
tunnel-client tui
```

Конфиг — `~/.tunnel-client/client.json` (другой каталог: `--dir <путь>`).
Демон для Unix (`tunnel-daemon console`, Unix-сокет) — для разработки и
тестов, см. PLAN.md, этап 7.

## Частые проблемы

- **«нет сервера»** — не выполнен `add-server`.
- **Server code не совпадает** — сервер переустановлен без `server.json`
  (новая identity). Восстановите файл на сервере или заново `add-server`.
- **Служба не стартует** — `%ProgramData%\tunnel\logs\daemon.log`,
  `sc query TunnelDaemon`; нет `wintun.dll` рядом с `tunnel-daemon.exe`.
- **Нет связи через NAT** — трафик идёт через релей сервера, это нормально;
  проверьте, что UDP-порт сервера открыт.
