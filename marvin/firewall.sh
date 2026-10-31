#!/bin/bash
#
# firewall.sh
#
# Host firewall (ufw) for marvin, built so it CAN'T take scoring down by surprise.
# It only CLOSES what is clearly not needed - it does not guess what is scored:
#   - SSH stays open to everyone: 22/tcp always, plus any other port sshd listens on.
#   - Every database port stays open to everyone (even while the DB is down, so it works
#     again after a restart). LIMIT_DB="yes" in marvin.conf + SCORING_IPS = team + scorer only.
#   - EVERY other port that is listening right now stays open too, so a scored service you
#     didn't know about keeps working. Only listeners running from a temp folder / a deleted
#     or quarantined file (backdoors) are left closed.
#   - Ports that are NOT listening now are closed: a backdoor started later can't be reached.
#   - Ping and outbound traffic are allowed (DNS, AD, updates).
#
# Safety net: 'apply' schedules an automatic ROLLBACK in 5 minutes. Type "yes" when the
# scoreboard is still green to keep the rules. If you don't - or your SSH session dies -
# the old firewall comes back by itself.
#
# Usage:
#   sudo ./firewall.sh                  show the plan: what stays open, what gets blocked
#   sudo ./firewall.sh discover [MIN]   watch who connects for MIN minutes (default 6) to find the scorer's IP
#   sudo ./firewall.sh apply            put the rules on (with the rollback timer)
#   sudo ./firewall.sh confirm          keep the rules (stops the rollback timer)
#   sudo ./firewall.sh rollback         put the old firewall back right now
#   sudo ./firewall.sh status           rules, timer, recent blocked connections
#   sudo ./firewall.sh block IP         drop everything to/from an attacker IP (and cut its connections)
#   sudo ./firewall.sh unblock IP
#   ROLLBACK_SECS=600 ./firewall.sh apply    longer safety window
#
# Lab testing only: FW_TEST_NETNS=name runs everything inside that network namespace.
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

require_root

# lab only: run inside a network namespace so a test can't touch the real network
NS_PROP=()
if [[ -n "$FW_TEST_NETNS" ]]
then
    [[ -z "$MARVIN_IN_NETNS" ]] && exec ip netns exec "$FW_TEST_NETNS" env MARVIN_IN_NETNS=1 "$0" "$@"
    NS_PROP=(-p "NetworkNamespacePath=/run/netns/$FW_TEST_NETNS")
fi

setup_dirs
load_conf
SCRIPT_NAME=firewall
FW_DIR="$DATA_DIR/firewall"
BLOCKLIST="$FW_DIR/blocklist.txt"
CLIENTS="$FW_DIR/clients.txt"
ROLLBACK_SECS="${ROLLBACK_SECS:-300}"
TIMER=marvin-fw-rollback
touch "$BLOCKLIST"

have ufw || { flag "ufw is not installed (apt-get install ufw)"; exit 1; }

valid_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ || "$1" =~ ^[0-9a-fA-F:]+(/[0-9]{1,3})?$ ]]; }

# every database port on this box (listening or not - a stopped DB must work again after a restart)
db_ports() {
    local e p
    for e in $(detect_engines)
    do
        for p in $(engine_ports "$e")
        do
            echo "$p $e"
        done
    done | sort -u
}

# a listener whose program runs from a temp folder / a deleted or quarantined file = backdoor
backdoor_listener() {
    local exe
    exe=$(readlink "/proc/$1/exe" 2>/dev/null)
    [[ "$exe" == /tmp/* || "$exe" == /dev/shm/* || "$exe" == /var/tmp/* || "$exe" == *"(deleted)" || "$exe" == "$EVIDENCE"/* ]]
}

# the plan, one rule per line: PORT/PROTO<TAB>FROM<TAB>WHY
build_plan() {
    local p e ip x proto port addr name pid
    {
        printf "22/tcp\tany\tSSH (scored - always open)\n"
        listeners | awk '$4 ~ /^sshd/ {print $2 "/" $1}' | sort -u | while read -r x
        do
            printf "%s\tany\tSSH (sshd listens here)\n" "$x"
        done
        db_ports | while read -r p e
        do
            if [[ "$LIMIT_DB" == "yes" && -n "$SCORING_IPS" ]]
            then
                printf "%s/tcp\t%s\t%s from the team network (LIMIT_DB=yes)\n" "$p" "$TEAM_NET" "$e"
                for ip in $SCORING_IPS
                do
                    printf "%s/tcp\t%s\t%s from the scoring engine (LIMIT_DB=yes)\n" "$p" "$ip" "$e"
                done
            else
                printf "%s/tcp\tany\t%s database\n" "$p" "$e"
            fi
        done
        for x in $EXTRA_PORTS
        do
            [[ "$x" == */* ]] || x="$x/tcp"
            printf "%s\tany\textra port from marvin.conf\n" "$x"
        done
        # everything else listening on the network right now stays reachable (maybe scored)
        listeners | while read -r proto port addr name pid
        do
            is_local_addr "$addr" && continue
            backdoor_listener "$pid" && continue
            printf "%s/%s\tany\tlistening now (%s)\n" "$port" "$proto" "$name"
        done
    } | awk -F'\t' '!seen[$1 FS $2]++' > "$MARVIN_TMP/plan"
}

port_allowed() {   # port_allowed PORT PROTO
    awk -F'\t' -v p="$1/$2" '$1 == p {f = 1} END {exit !f}' "$MARVIN_TMP/plan"
}

show_plan() {
    local proto port addr name pid
    build_plan
    section "FIREWALL PLAN"
    explain "Inbound: the ports below stay open; ports nothing listens on are closed, and so are"
    explain "listeners running from temp folders (backdoors). Ping + outbound traffic stay allowed."
    printf "\n  ${bold}%-12s %-20s %s${reset}\n" PORT FROM WHY
    awk -F'\t' '{printf "  %-12s %-20s %s\n", $1, $2, $3}' "$MARVIN_TMP/plan"
    printf "\n  ${bold}Everything listening right now:${reset}\n"
    listeners | while read -r proto port addr name pid
    do
        is_local_addr "$addr" && continue
        if port_allowed "$port" "$proto"
        then
            printf "  ${info}open   ${reset} %-12s %-16s on %s\n" "$port/$proto" "$name" "$addr"
        else
            printf "  ${error}BLOCKED${reset} %-12s %-16s on %s  (runs from a temp folder - backdoor)\n" "$port/$proto" "$name" "$addr"
        fi
    done | sort -u
    explain "A service that is DOWN right now isn't listening, so its port would be closed - add the"
    explain "scored ports to EXTRA_PORTS in $CONF to be safe (database ports are always kept open)."
    [[ "$LIMIT_DB" == "yes" && -n "$SCORING_IPS" ]] \
        && caution "LIMIT_DB=yes: the DB port only answers the team network + $SCORING_IPS - a wrong scorer IP = failed DB checks"
    [[ -s "$BLOCKLIST" ]] && printf "  blocked attacker IPs: %s\n" "$(paste -sd' ' "$BLOCKLIST")"
    if have docker && docker ps -q 2>/dev/null | grep -q .
    then
        caution "Docker is running: ports published by containers SKIP ufw (Docker's own iptables rules)."
    fi
    printf "\n  ufw right now: %s\n" "$(ufw status | head -n 1)"
}

discover() {
    local mins="${1:-6}" ports filter
    section "WHO CONNECTS TO MARVIN? (${mins} minutes)"
    explain "The scorer checks every 2-4 minutes, so watch at least 6 minutes. IPs outside the team"
    explain "network ($TEAM_NET) that show up again and again on 22 / the DB port are the scoring engine."
    ports=$(listeners | awk '$1 == "tcp"' | while read -r _ p a _ _; do is_local_addr "$a" || echo "$p"; done | sort -un | paste -sd' ' -)
    printf "  watching ports: %s\n\n" "$ports"
    : > "$MARVIN_TMP/syn"
    if have tcpdump
    then
        filter="tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn and ($(printf 'dst port %s or ' $ports | sed 's/ or $//'))"
        timeout "$((mins * 60))" tcpdump -l -nn -q -i any "$filter" 2>/dev/null \
            | awk '{for (i = 1; i <= NF; i++) if ($i == ">") {src = $(i-1); dst = $(i+1); sub(/\.[0-9]+$/, "", src); sub(/:$/, "", dst); n = split(dst, d, "."); print substr($1, 1, 8), src, d[n]; fflush()}}' \
            | tee -a "$MARVIN_TMP/syn" | awk '{print "  " $0}'
    else
        explain "(tcpdump not installed - sampling connections every second instead)"
        end=$(( $(date +%s) + mins * 60 ))
        while (( $(date +%s) < end ))
        do
            ss -Htn state established state syn-recv 2>/dev/null | awk -v ps=" $ports " -v t="$(date +%H:%M:%S)" '{n = split($3, l, ":"); p = l[n]
                peer = $4; sub(/:[0-9]+$/, "", peer); gsub(/[\[\]]/, "", peer); sub(/^::ffff:/, "", peer)
                if (index(ps, " " p " ")) print t, peer, p}' >> "$MARVIN_TMP/syn"
            sleep 1
        done
    fi
    sort -u "$MARVIN_TMP/syn" -o "$MARVIN_TMP/syn.u"
    awk '{k = $2 " " $3; n[k]++; if (!(k in first)) first[k] = $1; last[k] = $1}
         END {for (k in n) print k, n[k], first[k], last[k]}' "$MARVIN_TMP/syn.u" | sort > "$CLIENTS"
    printf "\n  ${bold}%-18s %-6s %-6s %-9s %-9s %s${reset}\n" IP PORT TIMES FIRST LAST WHERE
    while read -r ip port n f l
    do
        is_local_addr "$ip" && continue
        if ip_in_team_net "$ip"
        then
            printf "  %-18s %-6s %-6s %-9s %-9s team box\n" "$ip" "$port" "$n" "$f" "$l"
        else
            printf "  ${warn}%-18s %-6s %-6s %-9s %-9s OUTSIDE (scorer? red team?)${reset}\n" "$ip" "$port" "$n" "$f" "$l"
        fi
    done < "$CLIENTS"
    explain "Saved in $CLIENTS. The scorer comes back every few minutes on SSH AND the DB port;"
    explain "red team usually scans many ports once. Ask Black Team (0-point ticket) if unsure."
    if [[ "$MODE" == "interactive" ]]
    then
        ask_text "Scoring engine IP(s) to save in marvin.conf (space separated, Enter = skip): "
        if [[ -n "$REPLY" ]]
        then
            sed -i "s#^SCORING_IPS=.*#SCORING_IPS=\"$REPLY\"#" "$CONF" && did "SCORING_IPS set to '$REPLY' in $CONF"
        fi
    fi
}

write_rollback() {   # write_rollback BACKUP_TGZ WAS_ENABLED
    cat > "$FW_DIR/rollback.sh" <<EOF
#!/bin/bash
# written by marvin firewall.sh $(date -Is): put the firewall back the way it was
tar xzf "$1" -C /
if [[ "$2" == "yes" ]]
then
    ufw --force disable >/dev/null
    ufw --force enable >/dev/null
else
    ufw --force disable >/dev/null
fi
printf "%s firewall ROLLED BACK to %s\n" "\$(date -Is)" "$1" >> "$ACTIONS"
EOF
    chmod 700 "$FW_DIR/rollback.sh"
}

stop_timer() {
    systemctl stop "$TIMER.timer" "$TIMER.service" >/dev/null 2>&1
    systemctl reset-failed "$TIMER.timer" "$TIMER.service" >/dev/null 2>&1
}

apply() {
    local stamp backup was port from why ans ip pid
    show_plan
    if [[ "$MODE" != "interactive" ]]
    then
        caution "The firewall is only put on interactively (you must watch the scoreboard while the timer runs)."
        todo "Put the firewall on: ./firewall.sh apply (after checking the plan + scoring page)"
        return
    fi
    printf "\n"
    explain "Keep THIS SSH session open. Rules go on now; in $ROLLBACK_SECS seconds they come OFF again"
    explain "unless you type yes. Watch the scoring page: SSH + DB checks must stay green."
    confirm_risky "Put these rules on now?" || return

    stamp=$(date +%Y%m%d-%H%M%S)
    backup="$FW_DIR/ufw-before-$stamp.tgz"
    tar czf "$backup" -C / etc/ufw 2>/dev/null
    ufw status | grep -q 'Status: active' && was=yes || was=no
    ufw status verbose > "$FW_DIR/ufw-before-$stamp.txt" 2>&1
    write_rollback "$backup" "$was"
    stop_timer
    systemd-run --quiet --unit="$TIMER" --on-active="${ROLLBACK_SECS}s" "${NS_PROP[@]}" /bin/bash "$FW_DIR/rollback.sh" \
        || { flag "could not schedule the rollback timer - NOT applying"; return; }
    log_action "FIREWALL rollback scheduled in ${ROLLBACK_SECS}s ($backup)"

    # reset wipes anything red team put in ufw (user rules AND before.rules), keeping copies
    ufw --force reset >/dev/null
    ufw default deny incoming >/dev/null
    ufw default allow outgoing >/dev/null
    ufw logging low >/dev/null
    while IFS=$'\t' read -r port from why
    do
        if [[ "$from" == "any" ]]
        then
            ufw allow "$port" comment "marvin: $why" >/dev/null
        else
            ufw allow from "$from" to any port "${port%/*}" proto "${port#*/}" comment "marvin: $why" >/dev/null
        fi
        printf "  allow %-10s from %-18s (%s)\n" "$port" "$from" "$why"
    done < "$MARVIN_TMP/plan"
    while read -r ip
    do
        [[ -n "$ip" ]] && ufw insert 1 deny from "$ip" >/dev/null && printf "  deny  everything from %s (blocklist)\n" "$ip"
    done < "$BLOCKLIST"
    if ufw --force enable >/dev/null
    then
        did "FIREWALL applied (deny inbound except the plan), rollback in ${ROLLBACK_SECS}s" "./firewall.sh rollback"
    else
        flag "ufw enable failed - rolling back"; rollback_now; return
    fi
    ufw status numbered | sed 's/^/    /'

    printf "\n${bold}Watch the scoring page now. Blocked connections are shown below as they happen.${reset}\n"
    printf "${bold}Type yes + Enter to KEEP the rules (anything else, or waiting %ss, rolls back).${reset}\n\n" "$ROLLBACK_SECS"
    # the live view runs in its own subshell so ALL of it (journalctl, grep, awk) can be stopped after
    (
        journalctl -kf -n 0 2>/dev/null | grep --line-buffered 'UFW BLOCK' \
            | awk '{s = d = p = ""; for (i = 1; i <= NF; i++) {if ($i ~ /^SRC=/) s = substr($i, 5); else if ($i ~ /^DPT=/) d = substr($i, 5); else if ($i ~ /^PROTO=/) p = substr($i, 7)}
                    print "  " $3 "  BLOCKED " tolower(p) " from " s " to port " d; fflush()}'
    ) &
    pid=$!
    read -r -t "$ROLLBACK_SECS" -u 3 ans
    pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null
    if [[ "$ans" == "yes" ]]
    then
        stop_timer
        did "FIREWALL confirmed - rules kept"
        [[ -x "$SCRIPT_DIR/watch.sh" ]] && "$SCRIPT_DIR/watch.sh" --rebaseline fw >/dev/null 2>&1
    else
        caution "not confirmed - putting the old firewall back now"
        rollback_now
    fi
}

rollback_now() {
    stop_timer
    if [[ -x "$FW_DIR/rollback.sh" ]]
    then
        bash "$FW_DIR/rollback.sh"
        did "FIREWALL rolled back"
        ufw status | head -n 1 | sed 's/^/  /'
    else
        flag "no rollback file yet ($FW_DIR/rollback.sh) - to turn ufw off:  ufw disable"
    fi
}

status() {
    section "FIREWALL STATUS"
    ufw status verbose | sed 's/^/  /'
    printf "\n  rollback timer: %s\n" "$(systemctl is-active "$TIMER.timer" 2>/dev/null | sed 's/^active$/RUNNING - type ./firewall.sh confirm to keep the rules/')"
    printf "  blocked attacker IPs: %s\n" "$(paste -sd' ' "$BLOCKLIST")"
    step "Blocked in the last 15 minutes (top 10)"
    journalctl -k --since "-15min" --no-pager 2>/dev/null | grep 'UFW BLOCK' \
        | awk '{s = d = ""; for (i = 1; i <= NF; i++) {if ($i ~ /^SRC=/) s = substr($i, 5); else if ($i ~ /^DPT=/) d = substr($i, 5)} print s " -> port " d}' \
        | sort | uniq -c | sort -rn | head -n 10 | sed 's/^/  /'
}

block() {
    local ip="$1" gw
    valid_ip "$ip" || { flag "'$ip' is not an IP address"; exit 1; }
    gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
    if in_list "$ip" "$SCORING_IPS" || [[ "$ip" == "$gw" ]] || my_ips | grep -qxF "$ip"
    then
        flag "$ip is the scoring engine, the router or marvin itself - NOT blocking it"
        exit 1
    fi
    if ip_in_team_net "$ip"
    then
        caution "$ip is INSIDE the team network - a team box (maybe one red team owns). Blocking it can break that app."
        MODE=interactive
        confirm_risky "Block team box $ip anyway?" || exit 0
    fi
    grep -qxF "$ip" "$BLOCKLIST" || echo "$ip" >> "$BLOCKLIST"
    ufw insert 1 deny from "$ip" >/dev/null 2>&1
    ufw insert 1 deny out to "$ip" >/dev/null 2>&1
    did "BLOCKED $ip in and out" "./firewall.sh unblock $ip"
    ufw status | grep -q 'Status: active' || caution "ufw is not active, so the block only works once you apply the firewall"
    if ss -K dst "$ip" >/dev/null 2>&1
    then
        ok "cut marvin's open connections with $ip"
    else
        ss -Htnp dst "$ip" 2>/dev/null | sed 's/^/      still connected: /'
        explain "Kill those with: ./respond.sh proc <PID>"
    fi
}

unblock() {
    local ip="$1"
    sed -i "\#^${ip}\$#d" "$BLOCKLIST"
    ufw delete deny from "$ip" >/dev/null 2>&1
    ufw delete deny out to "$ip" >/dev/null 2>&1
    did "UNBLOCKED $ip"
}

case "$1" in
    ""|plan) show_plan ;;
    discover) discover "$2" ;;
    apply) apply ;;
    confirm) stop_timer; did "FIREWALL confirmed - rollback timer stopped" ;;
    rollback) rollback_now ;;
    status) status ;;
    block) block "$2" ;;
    unblock) unblock "$2" ;;
    --auto) MODE=auto; show_plan ;;
    --audit) MODE=audit; show_plan ;;
    -h|--help) usage_from_header ;;
    *) printf "${error}Unknown option: %s${reset}\n\n" "$1"; usage_from_header; exit 1 ;;
esac
exit 0
