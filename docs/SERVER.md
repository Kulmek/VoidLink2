# Сервер VoidLink (`tunnel-server`)

Сервер — точка встречи и релей: хранит группы, lease IP, инвайты, раздаёт
endpoint-ы для hole punching и пересылает трафик, пока прямого канала нет.
Работает на Linux (собирается и на macOS/Windows — для отладки). Наружу нужен
один UDP-порт (по умолчанию 5555).

## Сборка под Linux

На самом сервере (или любой Linux-машине той же архитектуры):

```
cargo build --release -p tunnel-server
# → target/release/tunnel-server
```

С macOS/Windows — кросс-сборка статического бинарника (не зависит от glibc
на VPS):

```
rustup target add x86_64-unknown-linux-musl
cargo install cargo-zigbuild        # или cross
cargo zigbuild --release -p tunnel-server --target x86_64-unknown-linux-musl
# → target/x86_64-unknown-linux-musl/release/tunnel-server
```

## Установка (systemd)

```
sudo infrastructure/linux/install-server.sh [путь/к/tunnel-server] [--listen 0.0.0.0:5555]
```

Скрипт:

- создаёт системного пользователя `tunnel` (без shell и home);
- кладёт бинарник в `/opt/tunnel/tunnel-server`, юнит —
  `/etc/systemd/system/tunnel-server.service`;
- создаёт `/etc/default/tunnel-server` (адрес `TUNNEL_LISTEN` и доп. флаги
  `TUNNEL_ARGS`), если его ещё нет;
- включает и запускает службу, печатает **Server code** (`TUN-…`) — его
  вписывают клиенты (`add-server <ip:порт> <TUN-код>`);
- повторный запуск — обновление: стоп → замена бинарника → старт,
  `server.json` не трогается.

Состояние — `/var/lib/tunnel/server.json` (`StateDirectory=tunnel`, права
0700). Юнит ужесточён: `NoNewPrivileges`, `ProtectSystem=strict`,
`ProtectHome`, `PrivateTmp`, `PrivateDevices`, пустой набор capabilities,
фильтр системных вызовов. Писать сервер может только в `/var/lib/tunnel`.

Файрвол: открыть только UDP-порт сервера, например `ufw allow 5555/udp`.

Полезное:

```
systemctl status tunnel-server
journalctl -u tunnel-server -f             # события и сводка раз в 5 минут
sudoedit /etc/default/tunnel-server && sudo systemctl restart tunnel-server
```

## Флаги

```
tunnel-server [адрес=0.0.0.0:5555] [флаги]
tunnel-server rotate-key [--data <dir>]
```

| флаг | по умолчанию | смысл |
|---|---|---|
| `--data <dir>` | `tunnel-data` | каталог состояния (`server.json`); в юните — `/var/lib/tunnel` |
| `--workers N` | 0 = по ядрам, до 8 | потоков-воркеров на UDP-сокете |
| `-q`, `--quiet` | — | не печатать события (сводка остаётся) |
| `--relay-rate R` / `--relay-burst B` | 4000 / 8000 | релей: фреймов/с на сессию и запас |
| `--ctrl-rate R` / `--ctrl-burst B` | 50 / 100 | управляющие фреймы на сессию |
| `--hello-rate R` / `--hello-burst B` | 5 / 20 | открытые пакеты (HELLO, HELLO3, RESET, UNSUPPORTED, CHALLENGE) в секунду на IP |
| `--session-timeout <сек>` | 30 | сессия без пакетов столько — офлайн |
| `--max-owned-groups N` | 16 | групп во владении одной identity |
| `--invite-ttl-days N` | 7 | срок жизни приглашения |
| `--metrics <адрес>` ⏳ | выключено | HTTP-эндпоинт метрик (сессии, группы, релей, отброшенные пакеты); слушать лучше на `127.0.0.1` |

Лимиты — раздел 9 [PROTOCOL.md](PROTOCOL.md). Флаги, помеченные ⏳, появятся
вместе с протоколом v3; актуальный список — `tunnel-server --help`.

Флаги в службе задаются через `TUNNEL_ARGS` в `/etc/default/tunnel-server`:

```
TUNNEL_LISTEN=0.0.0.0:5555
TUNNEL_ARGS=--workers 4 -q --max-owned-groups 32
```

## Ротация ключа сервера

Раздел 8 [PROTOCOL.md](PROTOCOL.md). Сервер должен быть остановлен:

```
sudo systemctl stop tunnel-server
sudo -u tunnel /opt/tunnel/tunnel-server rotate-key --data /var/lib/tunnel
sudo systemctl start tunnel-server
```

Старый ключ подписывает новый, звено дописывается в `server.json`
(`rotations`). Клиенты, закрепившие любой из последних 8 ключей цепочки,
перезакрепляются сами; новым клиентам раздаётся напечатанный новый код.
Перед ротацией сделайте резервную копию (ниже).

## Корректная остановка

`systemctl stop` шлёт `SIGTERM` (`KillSignal=SIGTERM`). Сервер перестаёт
принимать пакеты, дописывает `server.json` атомарно (tmp + rename) и
выходит; на это отведено `TimeoutStopSec=15s`, после чего systemd добивает
процесс `SIGKILL`. Даже при аварийном завершении `server.json` не бывает
наполовину записанным: в худшем случае теряются последние секунды изменений.
Клиенты после рестарта сервера получают `RESET` и переподключаются за секунды.

`Restart=on-failure`: упавший сервер поднимается через 2 с. Если
`server.json` повреждён, сервер **не стартует** (а не создаёт новую identity,
из-за которой все клиенты потеряли бы сервер) — восстановите файл из копии.

## Резервная копия `server.json`

В `server.json` — identity сервера (приватный ключ; от него зависит Server
code), группы, lease IP, бан-листы, инвайты, цепочка ротаций. Потеря файла =
новый Server code и пустой сервер: всем клиентам придётся перенастраиваться.

Копия «на горячую» безопасна (файл заменяется атомарно, читается целиком):

```
sudo install -m 0600 /var/lib/tunnel/server.json ~/server.json.$(date +%F)
```

Периодически, например cron/systemd-timer раз в сутки:

```
0 4 * * * root install -m 0600 /var/lib/tunnel/server.json /root/backup/server.json.$(date +\%F)
```

Восстановление:

```
sudo systemctl stop tunnel-server
sudo install -o tunnel -g tunnel -m 0600 server.json.YYYY-MM-DD /var/lib/tunnel/server.json
sudo systemctl start tunnel-server
```

Перенос на другой VPS — то же самое: новый сервер с этим `server.json`
сохраняет Server code; клиентам достаточно сменить адрес
(`del-server` + `add-server` с прежним кодом).
