#!/usr/bin/env bash
# Установка/обновление tunnel-server на Linux (systemd).
#
#   sudo ./install-server.sh [путь/к/tunnel-server] [--listen 0.0.0.0:5555] [--no-start]
#
# По умолчанию бинарник ищется в target/release/tunnel-server (и в
# target/<triple>/release/) относительно корня репозитория, затем рядом со скриптом.
# Повторный запуск = обновление: служба останавливается, бинарник заменяется,
# server.json в /var/lib/tunnel не трогается.
set -euo pipefail

PREFIX=/opt/tunnel
UNIT_DST=/etc/systemd/system/tunnel-server.service
DEFAULTS=/etc/default/tunnel-server
SVC_USER=tunnel
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"

bin=""
listen=""
start=1
while [[ $# -gt 0 ]]; do
    case "$1" in
        --listen) listen="${2:?--listen: нужен адрес}"; shift 2 ;;
        --no-start) start=0; shift ;;
        -h|--help) sed -n '2,9p' "$0"; exit 0 ;;
        *) bin="$1"; shift ;;
    esac
done

if [[ $EUID -ne 0 ]]; then
    echo "нужны права root: sudo $0" >&2
    exit 1
fi
if ! command -v systemctl >/dev/null; then
    echo "systemd не найден" >&2
    exit 1
fi

if [[ -z "$bin" ]]; then
    for c in "$repo/target/release/tunnel-server" \
             "$repo/target/x86_64-unknown-linux-gnu/release/tunnel-server" \
             "$repo/target/x86_64-unknown-linux-musl/release/tunnel-server" \
             "$here/tunnel-server"; do
        if [[ -x "$c" ]]; then bin="$c"; break; fi
    done
fi
if [[ -z "$bin" || ! -f "$bin" ]]; then
    echo "не найден бинарник tunnel-server; соберите: cargo build --release -p tunnel-server" >&2
    exit 1
fi

# Выделенный системный пользователь без shell и home
if ! id -u "$SVC_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /var/lib/tunnel \
        --shell /usr/sbin/nologin --user-group "$SVC_USER"
    echo "создан пользователь $SVC_USER"
fi

was_active=0
if systemctl is-active --quiet tunnel-server; then
    was_active=1
    echo "останавливаю tunnel-server для обновления…"
    systemctl stop tunnel-server
fi

install -d -m 0755 "$PREFIX"
install -m 0755 "$bin" "$PREFIX/tunnel-server"
if [[ -f "$repo/docs/SERVER.md" ]]; then
    install -m 0644 "$repo/docs/SERVER.md" "$PREFIX/SERVER.md"
fi
install -m 0644 "$here/tunnel-server.service" "$UNIT_DST"

if [[ ! -f "$DEFAULTS" ]]; then
    cat > "$DEFAULTS" <<CFG
# Параметры tunnel-server (читаются systemd-юнитом)
TUNNEL_LISTEN=${listen:-0.0.0.0:5555}
# Доп. флаги, например: --workers 4 -q --max-owned-groups 32
TUNNEL_ARGS=
CFG
    chmod 0644 "$DEFAULTS"
elif [[ -n "$listen" ]]; then
    sed -i "s|^TUNNEL_LISTEN=.*|TUNNEL_LISTEN=$listen|" "$DEFAULTS"
fi

systemctl daemon-reload
systemctl enable tunnel-server >/dev/null

if [[ $start -eq 1 || $was_active -eq 1 ]]; then
    systemctl restart tunnel-server
    sleep 1
    if systemctl is-active --quiet tunnel-server; then
        echo "tunnel-server запущен. Server code:"
        journalctl -u tunnel-server -n 50 --no-pager -o cat | grep -m1 -o 'TUN-[A-Za-z0-9-]*' \
            || echo "  (см. journalctl -u tunnel-server)"
    else
        echo "служба не стартовала:" >&2
        journalctl -u tunnel-server -n 30 --no-pager >&2
        exit 1
    fi
fi

port="$(sed -n 's/^TUNNEL_LISTEN=.*:\([0-9]*\)$/\1/p' "$DEFAULTS")"
echo "откройте UDP-порт ${port:-5555} в файрволе (например: ufw allow ${port:-5555}/udp)"
