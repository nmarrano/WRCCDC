#!/bin/bash
#
# respond.sh
#
# Incident response helpers for when the monitor shows red team on sylvester.
# Each one SAVES EVIDENCE FIRST (into /root/sylvester-data/evidence/), then asks,
# then acts, and writes what it did to logs/actions.log so the incident report
# (the 'report' command) has a timeline with times.
# Protected accounts (sylvester.conf) are refused unless you add --force.
#
# Usage:
#   sudo ./respond.sh proc PID              who started it, what it talks to - then kill it
#   sudo ./respond.sh user NAME             lock a Linux account + kill its programs
#   sudo ./respond.sh ip IP                 block an attacker IP and cut its connections
#   sudo ./respond.sh file PATH             quarantine a file (moved to evidence, never deleted)
#   sudo ./respond.sh unit NAME             stop + disable + mask a systemd service/timer
#   sudo ./respond.sh note "TEXT"           add your own line to the timeline
#   sudo ./respond.sh report [SINCE]        incident report draft (SINCE like 10:30 or 2026-11-07T10:30)
#
# Sylvester (video streamer, Rocky Linux) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

require_root
setup_dirs
load_conf
SCRIPT_NAME=respond
MODE=interactive
FORCE=""
ARGS=()
for a in "$@"
do
    [[ "$a" == "--force" ]] && FORCE=1 || ARGS+=("$a")
done
set -- "${ARGS[@]}"

do_proc() {
    local pid="$1" exe unit
    [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]] || { flag "no process $pid"; exit 1; }
    exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
    unit=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
    section "PROCESS $pid"
    ps -o user,pid,ppid,lstart,etime,args -p "$pid" | sed 's/^/  /'
    printf "\n  program: %s\n  folder:  %s\n  systemd unit: %s\n" "$exe" "$(readlink "/proc/$pid/cwd" 2>/dev/null)" "${unit:-none}"
    printf "\n  started by:\n"; proc_tree_up "$(ps -o ppid= -p "$pid" | tr -d ' ')" | head -n 6 | sed 's/^/    /'
    printf "\n  children:\n"; ps --ppid "$pid" -o pid=,args= 2>/dev/null | sed 's/^/    /'
    printf "\n  network:\n"; ss -tunap 2>/dev/null | grep "pid=$pid," | awk '{print "    " $1, $2, $5, "->", $6}'
    case "$unit" in
        sshd.service|ssh.service) flag "this is the SSH server itself - killing it can take the SSH check down!" ;;
    esac
    if confirm_risky "Save evidence and kill $pid (and its children)?"
    then
        kill_proc "$pid" "respond.sh by hand"
        printf "  evidence: %s\n" "$EV"
        if [[ -n "$exe" && -f "$exe" && ( "$exe" == /tmp/* || "$exe" == /dev/shm/* || "$exe" == /var/tmp/* || "$exe" == /home/* ) ]]
        then
            confirm_risky "Quarantine its program file $exe too?" && quarantine "$exe" "program of killed process $pid"
        fi
    fi
}

do_user() {
    local u="$1" h
    getent passwd "$u" >/dev/null || { flag "no user $u"; exit 1; }
    if is_protected_linux "$u" && [[ -z "$FORCE" ]]
    then
        flag "'$u' is protected (root, you, or PROTECTED_LINUX_USERS). If the scorer uses it, locking it"
        flag "turns the SSH check red. Change its password instead (passwd $u + PCR). Override: --force"
        exit 1
    fi
    new_evidence "user-$u"
    h=$(getent passwd "$u" | cut -d: -f6)
    {
        printf "== when: %s\n" "$(date -Is)"
        getent passwd "$u"; id "$u"; passwd -S "$u" 2>/dev/null
        printf "\n== processes\n"; ps -u "$u" -o pid,lstart,args 2>/dev/null
        printf "\n== logins\n"; last -n 20 "$u" 2>/dev/null
        printf "\n== home %s\n" "$h"; ls -la "$h" 2>/dev/null
    } > "$EV/info.txt" 2>&1
    cp -a "$h/.ssh" "$EV/ssh" 2>/dev/null
    cp -a "/var/spool/cron/crontabs/$u" "$EV/crontab" 2>/dev/null
    cp -a "$h/.bash_history" "$EV/bash_history" 2>/dev/null
    section "LINUX ACCOUNT $u"
    head -n 20 "$EV/info.txt" | sed 's/^/  /'
    printf "  evidence: %s\n" "$EV"
    if confirm_risky "Lock '$u' and kill all its programs?"
    then
        lock_user "$u" "respond.sh by hand"
        for g in sudo admin wheel lxd docker disk
        do
            id -nG "$u" | grep -qw "$g" && gpasswd -d "$u" "$g" >/dev/null && did "REMOVED $u from group $g" "gpasswd -a $u $g"
        done
        [[ -s "$h/.ssh/authorized_keys" ]] && quarantine "$h/.ssh/authorized_keys" "keys of locked user $u"
    fi
}

do_ip() {
    "$SCRIPT_DIR/firewall.sh" block "$1"
}

do_file() {
    [[ -e "$1" ]] || { flag "no such file $1"; exit 1; }
    ls -la "$1" | sed 's/^/  /'
    file -b "$1" 2>/dev/null | sed 's/^/  /'
    [[ -f "$1" ]] && head -c 400 "$1" | tr -c '[:print:]\n' '.' | head -n 8 | sed 's/^/  | /'
    is_owned "$1" && flag "a PACKAGE installed this file - moving it can break that program"
    confirm_risky "Quarantine $1?" && quarantine "$1" "respond.sh by hand"
}

do_unit() {
    local u="$1" frag
    [[ "$u" == *.* ]] || u="$u.service"
    if in_list "${u%.service}" "$(app_units | paste -sd' ' -)"
    then
        flag "$u is the streaming app (scored) - not touching it"; exit 1
    fi
    case "$u" in
        sshd.service|ssh.service) flag "$u is a scored service - not touching it"; exit 1 ;;
    esac
    frag=$(systemctl show -p FragmentPath --value "$u" 2>/dev/null)
    new_evidence "unit-$u"
    systemctl cat "$u" > "$EV/unit.txt" 2>&1
    systemctl status "$u" --no-pager > "$EV/status.txt" 2>&1
    section "SYSTEMD UNIT $u"
    sed 's/^/  /' "$EV/unit.txt" | head -n 25
    confirm_risky "Stop, disable and mask $u?" || return
    systemctl disable --now "$u" >/dev/null 2>&1
    [[ -n "$frag" && -f "$frag" ]] && ! is_owned "$frag" && quarantine "$frag" "unit stopped by respond.sh"
    systemctl mask "$u" >/dev/null 2>&1
    systemctl daemon-reload
    did "STOPPED, DISABLED and MASKED $u (evidence $EV)" "systemctl unmask $u"
}

do_note() {
    log_action "NOTE $*"
    ok "added to the timeline: $*"
}

do_report() {
    local since="$1" out
    [[ "$since" =~ ^[0-9]{1,2}:[0-9]{2}$ ]] && since="$(date +%Y-%m-%d)T$since"
    out="$DATA_DIR/reports/incident-$(date +%Y%m%d-%H%M%S).txt"
    {
        cat <<EOF
Title: [sylvester 192.168.220.69] <short description>

Time detected:
Detected by:      <name> via <alerts.log / process monitor / auth log / DB log>
Affected system:  sylvester, 192.168.220.69 (outside: 10.100.1XX.69), Rocky Linux, $(detect_apps | paste -sd' ' -)

What happened:
  - Attacker IP:
  - Account used:
  - How they got in:
  - What they did (commands / queries / files):
  - Data accessed? (which tables - customer PII / card numbers?):

Actions taken (from sylvester's timeline):
EOF
        awk -v s="$since" 's == "" || $1 >= s' "$ACTIONS" | sed -E 's/^([0-9-]+)T([0-9:]+)[^ ]* [^ ]+ /  \2  /'
        printf "\nAlerts seen (from alerts.log):\n"
        awk -v s="$since" 's == "" || $1 >= s' "$ALERTS" | grep -vE 'REBASELINE|SESSION' | tail -n 40 | sed -E 's/^([0-9-]+)T([0-9:]+)[^ ]* /  \2  /'
        printf "\nEvidence saved on sylvester:\n"
        ls -1d "$EVIDENCE"/*/ 2>/dev/null | tail -n 15 | sed 's/^/  /'
        cat <<'EOF'

Current status:   contained / service up / monitoring

Prevention going forward:
EOF
    } > "$out"
    cat "$out"
    printf "\n${info}saved to %s - fill in the <...> parts, then paste it into a ticket at teams.wccomps.org${reset}\n" "$out"
}

case "$1" in
    proc) do_proc "$2" ;;
    user) do_user "$2" ;;
    ip) do_ip "$2" ;;
    file) do_file "$2" ;;
    unit) do_unit "$2" ;;
    note) shift; do_note "$*" ;;
    report) do_report "$2" ;;
    -h|--help) usage_from_header ;;
    *) usage_from_header; exit 1 ;;
esac
exit 0
