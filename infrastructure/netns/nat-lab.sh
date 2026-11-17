#!/usr/bin/env bash
# nat-lab.sh — лаборатория NAT на сетевых пространствах имён Linux (ip netns +
# veth + nftables) для проверки пробития NAT, релея и фолбэков VoidLink.
#
# Запуск: Linux, root (или CAP_NET_ADMIN), iproute2, nftables, ping, ss.
# Подходит для CI-раннера (ubuntu) или одноразовой ВМ. См. docs/TESTING.md.
#
#   sudo ./nat-lab.sh run <сценарий>     поднять сеть, сервер, клиентов, проверить, снести
#   sudo ./nat-lab.sh up <сценарий>      только сеть
#   sudo ./nat-lab.sh start              сервер + два клиента (сеть уже поднята)
#   sudo ./nat-lab.sh check              ping по оверлею + direct/relay по счётчику сервера
#   sudo ./nat-lab.sh exec <ns> <cmd…>   команда внутри пространства (srv|wan|nat1|nat2|c1|c2)
#   sudo ./nat-lab.sh down               убить процессы, удалить пространства
#   ./nat-lab.sh list                    список сценариев
#
# Сценарии (EXPECT — ожидаемый путь трафика c1↔c2):
#   cone          c1, c2 за разными port-restricted cone NAT (порт сохраняется)  → direct
#   symmetric     оба за symmetric NAT (случайный порт на каждое назначение)     → relay
#   mixed         c1 за cone, c2 за symmetric                                     → relay
#   samenat       c1, c2 за одним NAT, hairpin выключен (только LAN-кандидаты)   → direct
#   hairpin       c1, c2 за одним NAT, hairpin включён                            → direct
#   udpblock      у c1 UDP наружу заблокирован                                    → tcp (фолбэк)
#
# Топология (адреса фиксированы):
#
#   vl-srv 203.0.113.10 ──┐
#                         ├── br0 (vl-wan, «интернет» 203.0.113.0/24)
#   vl-nat1 203.0.113.21 ─┤                 vl-nat2 203.0.113.22
#     lan 10.1.0.1/24     │                   lan 10.2.0.1/24
#     ├─ vl-c1 10.1.0.11  └───────────────────  └─ vl-c2 10.2.0.12
#     └─ vl-c2 10.1.0.12   (samenat/hairpin: c2 в LAN nat1, nat2 не создаётся)
#
# Замечание о «full cone»: conntrack Linux фильтрует входящее по полному
# кортежу (адрес+порт удалённой стороны), поэтому «cone» здесь —
# port-restricted cone с сохранением порта (endpoint-independent mapping).
# Для пробития NAT этого достаточно и это самый частый домашний NAT.
#
# Переменные окружения:
#   SERVER_BIN   путь к tunnel-server        (по умолчанию: target/release/tunnel-server)
#   CLIENT_BIN   путь к tunnel-client        (по умолчанию: target/release/tunnel-client)
#   CLIENT_RUN   подкоманда движка клиента   (по умолчанию: run)
#   ADAPTER      имя TUN-интерфейса клиента  (по умолчанию: vl0)
#   WORK         каталог данных и логов      (по умолчанию: /tmp/vl-nat-lab)
#   PINGS        число ping в check          (по умолчанию: 20)
#   SETTLE       секунд на пробитие до check (по умолчанию: 8)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
SERVER_BIN="${SERVER_BIN:-$REPO/target/release/tunnel-server}"
CLIENT_BIN="${CLIENT_BIN:-$REPO/target/release/tunnel-client}"
CLIENT_RUN="${CLIENT_RUN:-run}"
ADAPTER="${ADAPTER:-vl0}"
WORK="${WORK:-/tmp/vl-nat-lab}"
PINGS="${PINGS:-20}"
SETTLE="${SETTLE:-8}"

SRV_IP=203.0.113.10
SRV_PORT=5555
NAT1_WAN=203.0.113.21
NAT2_WAN=203.0.113.22
ALL_NS=(vl-c1 vl-c2 vl-nat1 vl-nat2 vl-srv vl-wan)

log() { printf '\033[1;34m[nat-lab]\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31m[nat-lab] ОШИБКА:\033[0m %s\n' "$*" >&2; exit 1; }
nsx() { local ns="$1"; shift; ip netns exec "$ns" "$@"; }

need_root() {
    [[ $(id -u) -eq 0 ]] || die "нужен root (ip netns / nft)"
    local t
    for t in ip nft ping ss; do
        command -v "$t" >/dev/null || die "не найдено: $t"
    done
}

scenario_expect() {
    case "$1" in
        cone | samenat | hairpin) echo direct ;;
        symmetric | mixed) echo relay ;;
        udpblock) echo tcp ;;
        *) die "неизвестный сценарий: $1 (см. ./nat-lab.sh list)" ;;
    esac
}

# --- сеть -------------------------------------------------------------------

mk_ns() {
    ip netns add "$1"
    nsx "$1" ip link set lo up
}

# veth: $1 ns_a, $2 if_a, $3 ns_b, $4 if_b
mk_veth() {
    ip link add "$2" netns "$1" type veth peer name "$4" netns "$3"
    nsx "$1" ip link set "$2" up
    nsx "$3" ip link set "$4" up
}

# nftables NAT-роутера: $1 ns, $2 LAN-подсеть, $3 WAN-адрес, $4 режим (cone|symmetric)
nat_rules() {
    local ns="$1" lan="$2" wan="$3" mode="$4" masq="masquerade"
    [[ $mode == symmetric ]] && masq="masquerade fully-random"
    nsx "$ns" nft -f - <<EOF
table ip vlnat {
    chain pre {
        type nat hook prerouting priority dstnat; policy accept;
    }
    chain post {
        type nat hook postrouting priority srcnat; policy accept;
        oifname "wan" ip saddr $lan $masq
        # hairpin: развёрнутый обратно в LAN пакет уходит с WAN-адреса роутера
        oifname "lan" ip saddr $lan ip daddr $lan ct status dnat snat ip to $wan
    }
    chain fwd {
        type filter hook forward priority filter; policy drop;
        ct state established,related accept
        iifname "lan" accept
    }
}
EOF
}

# NAT-роутер: $1 номер (1|2), $2 режим
mk_nat() {
    local n="$1" mode="$2" ns="vl-nat$1" wan
    wan=$([[ $n == 1 ]] && echo "$NAT1_WAN" || echo "$NAT2_WAN")
    mk_ns "$ns"
    nsx "$ns" sysctl -qw net.ipv4.ip_forward=1
    mk_veth vl-wan "wan-nat$n" "$ns" wan
    nsx vl-wan ip link set "wan-nat$n" master br0
    nsx "$ns" ip addr add "$wan/24" dev wan
    nsx "$ns" ip link add lan type bridge
    nsx "$ns" ip addr add "10.$n.0.1/24" dev lan
    nsx "$ns" ip link set lan up
    nat_rules "$ns" "10.$n.0.0/24" "$wan" "$mode"
    echo "$mode" >"$WORK/nat$n.mode"
}

# клиент: $1 имя (c1|c2), $2 номер NAT, $3 адрес в LAN
mk_client() {
    local c="$1" n="$2" addr="$3" ns="vl-$1"
    mk_ns "$ns"
    mk_veth "vl-nat$n" "lan-$c" "$ns" eth0
    nsx "vl-nat$n" ip link set "lan-$c" master lan
    nsx "$ns" ip addr add "$addr/24" dev eth0
    nsx "$ns" ip route add default via "10.$n.0.1"
    echo "$n" >"$WORK/$c.nat"
}

cmd_up() {
    local sc="${1:-}"
    [[ -n $sc ]] || die "usage: up <сценарий>"
    scenario_expect "$sc" >/dev/null
    need_root
    cmd_down quiet
    mkdir -p "$WORK"
    echo "$sc" >"$WORK/scenario"

    mk_ns vl-wan
    nsx vl-wan ip link add br0 type bridge
    nsx vl-wan ip link set br0 up

    mk_ns vl-srv
    mk_veth vl-wan wan-srv vl-srv eth0
    nsx vl-wan ip link set wan-srv master br0
    nsx vl-srv ip addr add "$SRV_IP/24" dev eth0
    # счётчик датаграмм на порт сервера: по приросту видно, шёл ли ping через релей
    nsx vl-srv nft -f - <<EOF
table inet vlmon {
    counter relay_in {}
    chain in {
        type filter hook input priority filter; policy accept;
        udp dport $SRV_PORT ip saddr != $SRV_IP counter name relay_in
    }
}
EOF

    case "$sc" in
        cone)
            mk_nat 1 cone
            mk_nat 2 cone
            mk_client c1 1 10.1.0.11
            mk_client c2 2 10.2.0.12
            ;;
        symmetric)
            mk_nat 1 symmetric
            mk_nat 2 symmetric
            mk_client c1 1 10.1.0.11
            mk_client c2 2 10.2.0.12
            ;;
        mixed)
            mk_nat 1 cone
            mk_nat 2 symmetric
            mk_client c1 1 10.1.0.11
            mk_client c2 2 10.2.0.12
            ;;
        samenat | hairpin)
            mk_nat 1 cone
            mk_client c1 1 10.1.0.11
            mk_client c2 1 10.1.0.12
            ;;
        udpblock)
            mk_nat 1 cone
            mk_nat 2 cone
            mk_client c1 1 10.1.0.11
            mk_client c2 2 10.2.0.12
            ;;
    esac
    nsx vl-c1 ping -c1 -W2 "$SRV_IP" >/dev/null || die "c1 не видит сервер (ICMP)"
    nsx vl-c2 ping -c1 -W2 "$SRV_IP" >/dev/null || die "c2 не видит сервер (ICMP)"
    log "сеть поднята: сценарий $sc, ожидается $(scenario_expect "$sc")"
}

# --- процессы ----------------------------------------------------------------

bg() { # $1 ns, $2 лог, $3… команда; pid → $WORK/<ns>.pid
    local ns="$1" out="$2"
    shift 2
    ip netns exec "$ns" "$@" >"$out" 2>&1 &
    echo $! >"$WORK/$ns.pid"
}

client() { # $1 имя, $2… аргументы tunnel-client
    local c="$1"
    shift
    nsx "vl-$c" "$CLIENT_BIN" --dir "$WORK/$c" "$@"
}

overlay_ip() { # из вывода create/join: «… мой IP 10.x.y.z»
    grep -oE 'мой IP [0-9.]+' "$1" | awk '{print $3}' | tail -n1
}

udp_port() { # UDP-порт движка клиента в его пространстве
    nsx "vl-$1" ss -Huanp 2>/dev/null | grep -F "$(basename "$CLIENT_BIN")" |
        awk '{print $4}' | grep -oE '[0-9]+$' | head -n1
}

cmd_start() {
    need_root
    [[ -f $WORK/scenario ]] || die "сначала: up <сценарий>"
    [[ -x $SERVER_BIN ]] || die "нет $SERVER_BIN (cargo build --release -p tunnel-server или SERVER_BIN=…)"
    [[ -x $CLIENT_BIN ]] || die "нет $CLIENT_BIN (CLIENT_BIN=…)"
    local sc code gid _
    sc=$(cat "$WORK/scenario")

    log "старт tunnel-server в vl-srv"
    bg vl-srv "$WORK/server.log" "$SERVER_BIN" "0.0.0.0:$SRV_PORT" --data "$WORK/srv"
    for _ in $(seq 1 50); do
        code=$(grep -oE 'TUN-[A-Za-z0-9-]+' "$WORK/server.log" | head -n1 || true)
        [[ -n $code ]] && break
        sleep 0.1
    done
    [[ -n ${code:-} ]] || die "сервер не напечатал Server code (см. $WORK/server.log)"
    log "server code: $code"

    for c in c1 c2; do
        client "$c" set-name "lab-$c" >/dev/null
        client "$c" add-server "$SRV_IP:$SRV_PORT" "$code" lab >/dev/null
    done
    client c1 create "nat-lab-$sc" | tee "$WORK/c1.group" >&2
    gid=$(grep -oE 'группа [0-9]+' "$WORK/c1.group" | awk '{print $2}')
    [[ -n $gid ]] || die "не удалось создать группу"
    client c2 join "$gid" | tee "$WORK/c2.group" >&2
    echo "$gid" >"$WORK/gid"

    if [[ $sc == udpblock ]]; then
        # группа уже настроена по UDP; дальше UDP c1 наружу режется целиком,
        # включая уже установленные потоки (правило встаёт первым в цепочке)
        nsx vl-nat1 nft insert rule ip vlnat fwd iifname lan oifname wan ip saddr 10.1.0.11 meta l4proto udp drop
        log "UDP от c1 наружу заблокирован"
    fi

    for c in c1 c2; do
        log "старт движка $c"
        # shellcheck disable=SC2086 # CLIENT_RUN может содержать несколько слов
        bg "vl-$c" "$WORK/$c.log" "$CLIENT_BIN" --dir "$WORK/$c" --adapter "$ADAPTER" --debug $CLIENT_RUN
    done
    sleep 2

    if [[ $sc == hairpin ]]; then
        local p1 p2
        p1=$(udp_port c1)
        p2=$(udp_port c2)
        [[ -n $p1 && -n $p2 ]] || die "не найден UDP-порт клиентов для hairpin (ss)"
        # статическое отражение публичных портов (cone сохраняет порт) обратно в LAN
        nsx vl-nat1 nft add rule ip vlnat pre iifname lan ip daddr "$NAT1_WAN" udp dport "$p1" dnat ip to "10.1.0.11:$p1"
        nsx vl-nat1 nft add rule ip vlnat pre iifname lan ip daddr "$NAT1_WAN" udp dport "$p2" dnat ip to "10.1.0.12:$p2"
        log "hairpin включён: $NAT1_WAN:$p1 → c1, $NAT1_WAN:$p2 → c2"
    fi
}

cmd_check() {
    need_root
    local sc expect ip2 before after delta path rc=0
    sc=$(cat "$WORK/scenario")
    expect=$(scenario_expect "$sc")
    ip2=$(overlay_ip "$WORK/c2.group")
    [[ -n $ip2 ]] || die "нет оверлейного IP c2"
    log "ждём пробития ${SETTLE}s…"
    sleep "$SETTLE"

    if ! nsx vl-c1 ip link show "$ADAPTER" >/dev/null 2>&1; then
        log "в vl-c1 нет интерфейса $ADAPTER — TUN на этой ОС не поднят; хвост логов:"
        tail -n 20 "$WORK/c1.log" "$WORK/c2.log" >&2 || true
        return 2
    fi

    before=$(counter_val)
    if nsx vl-c1 ping -c "$PINGS" -i 0.2 -W 2 "$ip2" >"$WORK/ping.log" 2>&1; then
        log "ping c1 → c2 ($ip2): ок"
    else
        log "ping c1 → c2 ($ip2): потери/нет ответа"
        rc=1
    fi
    tail -n 2 "$WORK/ping.log" >&2
    after=$(counter_val)
    delta=$((after - before))
    # через релей каждая пара echo/reply даёт ≥2 датаграммы на сервер; фон (keepalive) мал
    if ((delta >= PINGS)); then path=relay; else path=direct; fi
    [[ $expect == tcp ]] && path="tcp?(udp-счётчик $delta)"
    log "датаграмм на сервер за ping: $delta → путь: $path, ожидалось: $expect"
    if [[ $expect != tcp && $path != "$expect" ]]; then rc=1; fi
    if ((rc == 0)); then
        log "СЦЕНАРИЙ $sc: PASS"
    else
        log "СЦЕНАРИЙ $sc: FAIL (логи: $WORK)"
    fi
    return "$rc"
}

counter_val() {
    nsx vl-srv nft list counter inet vlmon relay_in | grep -oE 'packets [0-9]+' | awk '{print $2}'
}

cmd_down() {
    local ns pid
    for ns in "${ALL_NS[@]}"; do
        if [[ -f $WORK/$ns.pid ]]; then
            pid=$(cat "$WORK/$ns.pid")
            # SIGTERM: заодно проверяется корректная остановка сервера/движка
            kill -TERM "$pid" 2>/dev/null || true
            rm -f "$WORK/$ns.pid"
        fi
    done
    for ns in "${ALL_NS[@]}"; do
        if ip netns pids "$ns" >/dev/null 2>&1; then
            ip netns pids "$ns" 2>/dev/null | xargs -r kill -KILL 2>/dev/null || true
            ip netns del "$ns" 2>/dev/null || true
        fi
    done
    [[ ${1:-} == quiet ]] || log "лаборатория снесена (логи остались в $WORK)"
}

cmd_run() {
    local sc="${1:-}" rc=0
    cmd_up "$sc"
    trap 'cmd_down' EXIT
    cmd_start
    cmd_check || rc=$?
    return "$rc"
}

cmd_exec() {
    local ns="${1:-}"
    shift || true
    [[ -n $ns ]] || die "usage: exec <srv|wan|nat1|nat2|c1|c2> <cmd…>"
    nsx "vl-$ns" "$@"
}

case "${1:-help}" in
    up) cmd_up "${2:-}" ;;
    start) cmd_start ;;
    check) cmd_check ;;
    down) need_root && cmd_down ;;
    run) cmd_run "${2:-}" ;;
    exec)
        shift
        cmd_exec "$@"
        ;;
    list) printf '%s\n' cone symmetric mixed samenat hairpin udpblock ;;
    *) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
