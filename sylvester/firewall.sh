#!/bin/bash
#
# firewall.sh
#
# Host firewall (firewalld) for sylvester, built so it CAN'T take scoring down by surprise.
# It only CLOSES what is clearly not needed - it does not guess what is scored:
#   - SSH stays open: the ssh service + 22/tcp always, plus any other port sshd listens on.
#   - The streaming app's ports stay open (even while it is down, so it works after a restart).
#   - EVERY other port that is listening right now stays open too, so a scored service you
#     didn't know about keeps working. Only listeners running from a temp folder / a deleted
#     or quarantined file (backdoors) are left closed. Add more with EXTRA_PORTS in sylvester.conf.
#   - Ports nothing listens on are closed, so a backdoor started later can't be reached.
#   - Ping and outbound traffic are allowed.
#
# Safety net: 'apply' schedules an automatic ROLLBACK in 5 minutes. Type "yes" when the
# scoreboard is still green to keep it. If you don't - or your SSH session dies - the old
# firewall comes back by itself.
#
# Usage:
#   sudo ./firewall.sh                  the plan: what stays open, what gets closed
#   sudo ./firewall.sh discover [MIN]   watch who connects for MIN minutes (default 6) - find the scorer
#   sudo ./firewall.sh apply            put it on (with the rollback timer)
#   sudo ./firewall.sh confirm          keep it (stops the timer)
#   sudo ./firewall.sh rollback         old firewall back right now
#   sudo ./firewall.sh status           zone, rules, timer
#   sudo ./firewall.sh block IP         drop everything from an attacker IP (and cut its connections)
#   sudo ./firewall.sh unblock IP
#
# Sylvester (video streamer, Rocky Linux) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

require_root
setup_dirs
load_conf
SCRIPT_NAME=firewall
FW_DIR="$DATA_DIR/firewall"
BLOCKLIST="$FW_DIR/blocklist.txt"
ROLLBACK_SECS="${ROLLBACK_SECS:-300}"
TIMER=sylvester-fw-rollback
touch "$BLOCKLIST"
APPS="${APPS:-$(detect_apps | paste -sd' ' -)}"

have firewall-cmd || { flag "firewalld is not installed (dnf install firewalld)"; exit 1; }
running() { [[ "$(firewall-cmd --state 2>/dev/null)" == "running" ]]; }
zone() { firewall-cmd --get-default-zone 2>/dev/null || echo public; }
valid_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; }

# a listener whose program runs from a temp folder / a deleted or quarantined file = backdoor
backdoor_listener() {
    local exe
    exe=$(readlink "/proc/$1/exe" 2>/dev/null)
    [[ "$exe" == /tmp/* || "$exe" == /dev/shm/* || "$exe" == /var/tmp/* || "$exe" == *"(deleted)" || "$exe" == "$EVIDENCE"/* ]]
}

build_plan() {
    local a p x proto port addr name pid
    {
        printf "22/tcp\tSSH (scored - always open)\n"
        listeners | awk '$4 ~ /^sshd/ {print $2 "/" $1}' | sort -u | while read -r x
        do
            printf "%s\tSSH (sshd listens here)\n" "$x"
        done
        for a in $APPS
        do
            for p in $(app_ports "$a") $(printf '%s/tcp ' $(app_field "$a" 4))
            do
                printf "%s\t%s\n" "$p" "$a"
            done
        done
        for x in $EXTRA_PORTS
        do
            [[ "$x" == */* ]] || x="$x/tcp"
            printf "%s\textra port from sylvester.conf\n" "$x"
        done
        # everything else listening on the network right now stays reachable (maybe scored)
        listeners | while read -r proto port addr name pid
        do
            is_local_addr "$addr" && continue
            backdoor_listener "$pid" && continue
            printf "%s/%s\tlistening now (%s)\n" "$port" "$proto" "$name"
        done
    } | awk -F'\t' '!seen[$1]++' > "$SYL_TMP/plan"
}

show_plan() {
    local proto port addr name pid
    build_plan
    section "FIREWALL PLAN (firewalld zone: $(zone))"
    explain "Inbound: these ports stay open; ports nothing listens on are closed, and so are listeners"
    explain "running from temp folders (backdoors). Ping + outbound traffic stay allowed."
    awk -F'\t' '{printf "  open  %-12s %s\n", $1, $2}' "$SYL_TMP/plan"
    printf "\n  ${bold}Listening right now:${reset}\n"
    listeners | while read -r proto port addr name pid
    do
        is_local_addr "$addr" && continue
        if grep -q "^$port/$proto"$'\t' "$SYL_TMP/plan"
        then
            printf "  ${info}open   ${reset} %-12s %-16s\n" "$port/$proto" "$name"
        else
            printf "  ${error}CLOSED ${reset} %-12s %-16s (runs from a temp folder - backdoor)\n" "$port/$proto" "$name"
        fi
    done | sort -u
    explain "A scored service that is DOWN right now isn't listening, so its port would be closed -"
    explain "add the scored ports to EXTRA_PORTS in $CONF to be safe."
    if running
    then
        printf "\n  firewalld now: zone %s  services: %s  ports: %s\n" "$(zone)" \
            "$(firewall-cmd --zone="$(zone)" --list-services)" "$(firewall-cmd --zone="$(zone)" --list-ports)"
        firewall-cmd --zone="$(zone)" --list-rich-rules | sed 's/^/  rich rule: /'
    else
        caution "firewalld is NOT running (red team may have stopped it)"
    fi
}

discover() {
    local mins="${1:-6}" ports
    section "WHO CONNECTS TO SYLVESTER? (${mins} minutes)"
    explain "The scorer checks every 2-4 minutes - outside IPs that keep coming back on 22 / the app port."
    ports=$(listeners | awk '$1 == "tcp"' | while read -r _ p a _ _; do is_local_addr "$a" || echo "$p"; done | sort -un | paste -sd' ' -)
    : > "$SYL_TMP/syn"
    end=$(( $(date +%s) + mins * 60 ))
    while (( $(date +%s) < end ))
    do
        ss -Htn state established state syn-recv 2>/dev/null | awk -v ps=" $ports " -v t="$(date +%H:%M:%S)" '{n = split($3, l, ":"); p = l[n]
            peer = $4; sub(/:[0-9]+$/, "", peer); gsub(/[\[\]]/, "", peer); sub(/^::ffff:/, "", peer)
            if (index(ps, " " p " ")) print t, peer, p}' >> "$SYL_TMP/syn"
        sleep 1
    done
    sort -u "$SYL_TMP/syn" | awk '{k = $2 " " $3; n[k]++; if (!(k in f)) f[k] = $1; l[k] = $1} END {for (k in n) print k, n[k], f[k], l[k]}' \
        | sort > "$FW_DIR/clients.txt"
    printf "  %-18s %-6s %-6s %-9s %s\n" IP PORT SEEN FIRST LAST
    while read -r ip port n f l
    do
        is_local_addr "$ip" && continue
        printf "  %-18s %-6s %-6s %-9s %s %s\n" "$ip" "$port" "$n" "$f" "$l" "$(ip_in_team_net "$ip" && echo team || echo OUTSIDE)"
    done < "$FW_DIR/clients.txt"
    if [[ "$MODE" == "interactive" ]]
    then
        ask_text "Scoring engine IP(s) to save in sylvester.conf (Enter = skip): "
        [[ -n "$REPLY" ]] && sed -i "s#^SCORING_IPS=.*#SCORING_IPS=\"$REPLY\"#" "$CONF" && did "SCORING_IPS set to '$REPLY'"
    fi
}

stop_timer() {
    systemctl stop "$TIMER.timer" "$TIMER.service" >/dev/null 2>&1
    systemctl reset-failed "$TIMER.timer" "$TIMER.service" >/dev/null 2>&1
}

apply() {
    local z backup was s p why ans
    show_plan
    if [[ "$MODE" != "interactive" ]]
    then
        todo "Put the firewall on: ./firewall.sh apply (after checking the plan + scoring page)"
        return
    fi
    explain "Keep THIS SSH session open. It comes OFF again in $ROLLBACK_SECS s unless you type yes."
    confirm_risky "Put this firewall on now?" || return
    backup="$FW_DIR/firewalld-before-$(date +%Y%m%d-%H%M%S).tgz"
    tar czf "$backup" -C / etc/firewalld 2>/dev/null
    running && was=yes || was=no
    cat > "$FW_DIR/rollback.sh" <<EOF
#!/bin/bash
# written by sylvester firewall.sh $(date -Is): put the firewall back the way it was
tar xzf "$backup" -C /
if [[ "$was" == "yes" ]]; then systemctl restart firewalld; else systemctl stop firewalld; fi
printf "%s firewall ROLLED BACK to %s\n" "\$(date -Is)" "$backup" >> "$ACTIONS"
EOF
    chmod 700 "$FW_DIR/rollback.sh"
    stop_timer
    systemd-run --quiet --unit="$TIMER" --on-active="${ROLLBACK_SECS}s" /bin/bash "$FW_DIR/rollback.sh" \
        || { flag "could not schedule the rollback timer - NOT applying"; return; }
    running || { systemctl unmask firewalld >/dev/null 2>&1; systemctl enable --now firewalld >/dev/null 2>&1; }
    running || { flag "firewalld would not start"; stop_timer; return; }
    z=$(zone)
    for s in $(firewall-cmd --permanent --zone="$z" --list-services)
    do
        [[ "$s" == "ssh" ]] || { firewall-cmd --permanent --zone="$z" --remove-service="$s" >/dev/null; printf "  closed service %s\n" "$s"; }
    done
    for p in $(firewall-cmd --permanent --zone="$z" --list-ports)
    do
        grep -q "^$p"$'\t' "$SYL_TMP/plan" || { firewall-cmd --permanent --zone="$z" --remove-port="$p" >/dev/null; printf "  closed port %s\n" "$p"; }
    done
    firewall-cmd --permanent --zone="$z" --add-service=ssh >/dev/null
    while IFS=$'\t' read -r p why
    do
        firewall-cmd --permanent --zone="$z" --add-port="$p" >/dev/null && printf "  open  %-10s (%s)\n" "$p" "$why"
    done < "$SYL_TMP/plan"
    firewall-cmd --permanent --zone="$z" --set-target=default >/dev/null
    while read -r ip
    do
        [[ -n "$ip" ]] && firewall-cmd --permanent --zone="$z" --add-rich-rule="rule family=ipv4 source address=$ip drop" >/dev/null
    done < "$BLOCKLIST"
    firewall-cmd --reload >/dev/null && did "FIREWALL applied in zone $z, rollback in ${ROLLBACK_SECS}s" "./firewall.sh rollback"
    firewall-cmd --zone="$z" --list-all | sed 's/^/    /'
    printf "\n${bold}Watch the scoring page. Type yes + Enter to KEEP it (anything else / waiting = rollback).${reset}\n"
    read -r -t "$ROLLBACK_SECS" -u 3 ans
    if [[ "$ans" == "yes" ]]
    then
        stop_timer; did "FIREWALL confirmed - kept"
    else
        caution "not confirmed - putting the old firewall back now"; rollback_now
    fi
}

rollback_now() {
    stop_timer
    [[ -x "$FW_DIR/rollback.sh" ]] && bash "$FW_DIR/rollback.sh" && did "FIREWALL rolled back" || flag "no rollback file yet"
}

status() {
    section "FIREWALL STATUS"
    firewall-cmd --state 2>&1 | sed 's/^/  firewalld: /'
    running && firewall-cmd --zone="$(zone)" --list-all | sed 's/^/  /'
    printf "  rollback timer: %s\n" "$(systemctl is-active "$TIMER.timer" 2>/dev/null)"
    printf "  blocked IPs: %s\n" "$(paste -sd' ' "$BLOCKLIST")"
}

block() {
    local ip="$1" gw
    valid_ip "$ip" || { flag "'$ip' is not an IPv4 address"; exit 1; }
    gw=$(ip route show default 2>/dev/null | awk '{print $3; exit}')
    if in_list "$ip" "$SCORING_IPS" || [[ "$ip" == "$gw" ]] || my_ips | grep -qxF "$ip"
    then
        flag "$ip is the scoring engine, the router or sylvester itself - NOT blocking it"; exit 1
    fi
    if ip_in_team_net "$ip"
    then
        MODE=interactive
        caution "$ip is a TEAM box (maybe red team owns it). Blocking it can break that app."
        confirm_risky "Block $ip anyway?" || exit 0
    fi
    grep -qxF "$ip" "$BLOCKLIST" || echo "$ip" >> "$BLOCKLIST"
    if running
    then
        firewall-cmd --zone="$(zone)" --add-rich-rule="rule family=ipv4 source address=$ip drop" >/dev/null
        firewall-cmd --permanent --zone="$(zone)" --add-rich-rule="rule family=ipv4 source address=$ip drop" >/dev/null
        did "BLOCKED $ip" "./firewall.sh unblock $ip"
    else
        caution "firewalld isn't running - $ip is on the blocklist and gets blocked when you apply"
    fi
    ss -K dst "$ip" >/dev/null 2>&1 && ok "cut open connections with $ip"
}

unblock() {
    sed -i "\#^$1\$#d" "$BLOCKLIST"
    firewall-cmd --zone="$(zone)" --remove-rich-rule="rule family=ipv4 source address=$1 drop" >/dev/null 2>&1
    firewall-cmd --permanent --zone="$(zone)" --remove-rich-rule="rule family=ipv4 source address=$1 drop" >/dev/null 2>&1
    did "UNBLOCKED $1"
}

case "$1" in
    ""|plan|--auto|--audit) show_plan ;;
    discover) discover "$2" ;;
    apply) apply ;;
    confirm) stop_timer; did "FIREWALL confirmed - rollback timer stopped" ;;
    rollback) rollback_now ;;
    status) status ;;
    block) block "$2" ;;
    unblock) unblock "$2" ;;
    -h|--help) usage_from_header ;;
    *) printf "${error}Unknown option: %s${reset}\n\n" "$1"; usage_from_header; exit 1 ;;
esac
exit 0
