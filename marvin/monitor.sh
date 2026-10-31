#!/bin/bash
#
# monitor.sh
#
# Builds the tmux session "marvin": everything you need to watch, one window each.
#   0 alerts  watch.sh (health, drift from the baseline, red flags) + the alerts log
#   1 procs   every NEW process the moment it starts (red = suspicious) + process tree
#   2 net     listening ports + live connections (team / OUTSIDE) + firewall blocks
#   3 auth    SSH logins, failed logins, sudo, su, user/password changes - live
#   4 db      live database connections (every engine) + database logs
#   5 users   Linux login users + every database account (NEW ones in red)
#   6 shell   a shell in the scripts folder, with a cheat sheet
#
# tmux keys: Ctrl-b then 0-6 = go to a window, Ctrl-b then an arrow = other pane,
# Ctrl-b d = detach (everything keeps running; come back with: tmux attach -t marvin).
# The mouse works too (click a window name or pane, scroll with the wheel).
#
# Usage:
#   sudo ./monitor.sh             build the session (or re-use it) and attach
#   sudo ./monitor.sh kill        close the session
#   sudo ./monitor.sh --no-tmux   no tmux: run watch.sh in the background, print how to follow it
#   sudo ./monitor.sh view NAME   one view by itself: watch alerts newprocs tree net fw auth db dblog users help
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/db.sh"

require_root
setup_dirs
load_conf
SCRIPT_NAME=monitor
MODE=auto
SESSION=marvin
ENGINES="${DB_ENGINES:-$(detect_engines | paste -sd' ' -)}"

clear_screen() { [[ -t 1 ]] && printf '\e[H\e[2J'; }

# ---------------- views (each runs forever inside a tmux pane) ----------------

view_alerts() {
    printf "${bold}alerts.log (newest at the bottom)${reset}\n"
    tail -n 30 -F "$ALERTS" 2>/dev/null | sed -u -E \
        -e "s/.*(HEALTH|PROC CRIT|DB [a-z]+ login|NET outbound|DISK|LOGIN|USERS).*/${error}&${reset}/" \
        -e "s/.*(DRIFT|PROC SUSP|AUTH|PRIV|FWBLOCK).*/${warn}&${reset}/" \
        -e "s/.*(RECOVERED|REBASELINE).*/${info}&${reset}/"
}

# a light "pspy": polls /proc every second using only bash builtins, so it doesn't see itself
view_newprocs() {
    declare -A seen uname
    local p pid ppid uid k v pcomm comm cmd mark n u
    local -a args
    while IFS=: read -r n _ u _
    do
        [[ -z "${uname[$u]}" ]] && uname[$u]=$n     # first name wins: a red team UID 0 account doesn't rename root
    done < /etc/passwd
    for p in /proc/[0-9]*
    do
        seen[${p#/proc/}]=1
    done
    printf "${bold}New processes the moment they start (cron jobs, reverse shells, red team commands).${reset}\n"
    printf "${bold}RED = suspicious. Investigate:  ./respond.sh proc PID${reset}\n\n"
    while true
    do
        for p in /proc/[0-9]*
        do
            pid=${p#/proc/}
            [[ -n "${seen[$pid]}" ]] && continue
            seen[$pid]=1
            mapfile -d '' -t args < "$p/cmdline" 2>/dev/null || continue
            cmd="${args[*]}"
            [[ -z "$cmd" ]] && continue
            ppid=""; uid=""
            while read -r k v _
            do
                case "$k" in PPid:) ppid=$v ;; Uid:) uid=$v ;; esac
            done < "$p/status" 2>/dev/null
            [[ "$ppid" == "$BASHPID" || "$ppid" == "$$" ]] && continue
            pcomm=""; read -r pcomm < "/proc/$ppid/comm" 2>/dev/null
            comm=""; read -r comm < "$p/comm" 2>/dev/null
            mark=""
            if [[ "$cmd" =~ $CRIT_CMD || "$cmd" =~ ^/(tmp|dev/shm|var/tmp)/ || ( "$pcomm" =~ $DB_DAEMONS && "$comm" =~ $SHELLS ) ]]
            then
                mark="$error$bold"
            elif [[ "$cmd" =~ $SUSP_CMD ]]
            then
                mark="$warn"
            fi
            printf "%s%(%H:%M:%S)T %6s %-10s <- %-12s %s%s\n" "$mark" -1 "$pid" "${uname[$uid]:-$uid}" "${pcomm:0:12}" "${cmd:0:170}" "$reset"
        done
        sleep 1
    done
}

view_tree() {
    while true
    do
        clear_screen
        printf "${bold}process tree  %s  (kernel threads hidden, refresh 10s)${reset}\n" "$(date +%H:%M:%S)"
        ps -eo pid,user,etime,args --forest 2>/dev/null | awk 'NR == 1 || $4 !~ /^\[/' | cut -c1-"${COLUMNS:-200}"
        sleep 10
    done
}

view_net() {
    local l peer proc p name lports
    while true
    do
        clear_screen
        printf "${bold}LISTENING on the network  %s${reset}\n" "$(date +%H:%M:%S)"
        listeners | while read -r proto port addr name pid
        do
            is_local_addr "$addr" || printf "  %-4s %-6s %-16s %-16s pid %s\n" "$proto" "$port" "$addr" "$name" "$pid"
        done
        printf "\n${bold}CONNECTIONS (who is talking to marvin right now)${reset}\n"
        lports=" $(listeners | awk '{print $2}' | sort -u | paste -sd' ' -) "
        ss -Htnp state established 2>/dev/null | awk '{print $3, $4, $5}' | while read -r l peer proc
        do
            p=${peer%:*}; p=${p#[}; p=${p%]}; p=${p#::ffff:}
            is_local_addr "$p" && continue
            name=$(grep -o '"[^"]*"' <<< "$proc" | head -n 1 | tr -d '"')
            if [[ "$lports" == *" ${l##*:} "* ]]
            then
                where="IN  -> port ${l##*:}"
            else
                where="OUT -> $peer"
            fi
            if ip_in_team_net "$p" || in_list "$p" "$SCORING_IPS"
            then
                printf "  %-15s %-24s %-16s %s\n" "$p" "$where" "${name:-?}" "team/scorer"
            else
                printf "  ${warn}%-15s %-24s %-16s %s${reset}\n" "$p" "$where" "${name:-?}" "OUTSIDE"
            fi
        done
        sleep 3
    done
}

view_fw() {
    printf "${bold}firewall blocks, live (ufw status: %s)${reset}\n" "$(ufw status 2>/dev/null | head -n 1 | awk '{print $2}')"
    (journalctl -kf -n 20 -o short 2>/dev/null || tail -n 20 -F /var/log/ufw.log) | grep --line-buffered 'UFW BLOCK' \
        | awk '{s = d = p = ""; for (i = 1; i <= NF; i++) {if ($i ~ /^SRC=/) s = substr($i, 5); else if ($i ~ /^DPT=/) d = substr($i, 5); else if ($i ~ /^PROTO=/) p = substr($i, 7)}
                printf "  %s  BLOCKED %-4s from %-16s to port %s\n", $3, tolower(p), s, d; fflush()}'
}

view_auth() {
    printf "${bold}logins / sudo / user changes, live (red = failed or new user, green = login)${reset}\n"
    journalctl -f -n 30 -o short SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session SYSLOG_IDENTIFIER=sudo SYSLOG_IDENTIFIER=su \
        SYSLOG_IDENTIFIER=useradd SYSLOG_IDENTIFIER=userdel SYSLOG_IDENTIFIER=usermod SYSLOG_IDENTIFIER=passwd \
        SYSLOG_IDENTIFIER=chpasswd SYSLOG_IDENTIFIER=gpasswd SYSLOG_IDENTIFIER=groupadd SYSLOG_IDENTIFIER=chage 2>/dev/null \
        | grep --line-buffered -vE 'session closed|Received disconnect|Disconnected from|Connection closed|pam_unix\(sudo:session\): session opened' \
        | sed -u -E "s/.*(Failed|Invalid user|authentication failure|new user|new group|delete user|changed password|password changed|add '.*' to group).*/${error}&${reset}/; s/.*Accepted.*/${info}&${reset}/"
}

view_db() {
    local e
    declare -A ok
    while true
    do
        clear_screen
        printf "${bold}live database connections  %s  (refresh 5s)${reset}\n" "$(date +%H:%M:%S)"
        for e in $ENGINES
        do
            [[ "${ok[$e]}" == 1 ]] || { db_connect "$e" >/dev/null 2>&1 && ok[$e]=1; }
            printf "\n${bold}== %s ==${reset}\n" "$e"
            if [[ "${ok[$e]}" == 1 ]]
            then
                db_sessions "$e" 2>&1 | head -n 25
            else
                printf "  ${error}can't log in - is it running?${reset}\n"
            fi
        done
        sleep 5
    done
}

view_dblog() {
    local f files=()
    printf "${bold}database logs, live${reset}\n"
    for f in /var/log/mysql/error.log /var/log/mysql/general.log /var/log/postgresql/postgresql-*-main.log /var/log/redis/redis-server.log
    do
        [[ -f "$f" ]] && files+=("$f")
    done
    [[ ${#files[@]} -gt 0 ]] && tail -n 5 -F "${files[@]}" 2>/dev/null &
    # mongod logs every connection as JSON - only show the interesting ones
    [[ -f /var/log/mongodb/mongod.log ]] && tail -n 0 -F /var/log/mongodb/mongod.log 2>/dev/null \
        | grep --line-buffered -E 'uthenticat|"c":"ACCESS"|createUser|dropUser|grantRoles|Connection accepted' \
        | sed -u -E 's/.*"t":\{"\$date":"[^T]*T([0-9:]+)[^"]*"\}.*"msg":"([^"]*)".*"(remote|client)":"([^"]*)".*/mongod \1 \2 \4/' &
    wait
}

view_users() {
    local u
    while true
    do
        clear_screen
        printf "${bold}accounts  %s  (refresh 30s; ${error}NEW${reset}${bold} = not in the baseline)${reset}\n\n" "$(date +%H:%M:%S)"
        printf "${bold}Linux accounts that can log in${reset}\n"
        for u in $(login_users)
        do
            if grep -q "^user $u"$'\t' "$BASELINE/users" 2>/dev/null || [[ ! -f "$BASELINE/users" ]]
            then
                printf "  %-16s uid=%-6s %-8s %s\n" "$u" "$(id -u "$u")" "$(passwd -S "$u" 2>/dev/null | awk '{print ($2 == "L" ? "LOCKED" : "")}')" "$(id -nG "$u" | tr ' ' ',')"
            else
                printf "  ${error}NEW %-12s uid=%-6s %s${reset}\n" "$u" "$(id -u "$u")" "$(id -nG "$u" | tr ' ' ',')"
            fi
        done
        for e in $ENGINES
        do
            printf "\n${bold}%s accounts${reset}\n" "$e"
            db_connect "$e" >/dev/null 2>&1 || { printf "  ${error}can't log in${reset}\n"; continue; }
            db_snapshot "$e" | while IFS=$'\t' read -r k v
            do
                if [[ ! -f "$BASELINE/dbusers" ]] || grep -qF "$k"$'\t' "$BASELINE/dbusers"
                then
                    printf "  %-36s %s\n" "${k#* }" "${v:0:110}"
                else
                    printf "  ${error}NEW %-32s %s${reset}\n" "${k#* }" "${v:0:110}"
                fi
            done
        done
        sleep 30
    done
}

view_help() {
    cat <<EOF
${bold}marvin cheat sheet${reset}   (scripts are in $SCRIPT_DIR)

${bold}tmux${reset}   Ctrl-b 0..6 = windows (alerts procs net auth db users shell)
       Ctrl-b arrow = switch pane    Ctrl-b d = detach (tmux attach -t marvin to come back)
       Ctrl-b [ = scroll mode (q to leave)   mouse: click / scroll

${bold}something bad is happening${reset}
  ./respond.sh proc PID            save evidence, kill a process
  ./respond.sh user NAME           lock a Linux account (refuses protected ones)
  ./respond.sh dbuser ENGINE NAME  lock a database account (mysql postgres redis mongodb)
  ./respond.sh ip IP               block an attacker IP and cut its connections
  ./respond.sh file PATH           quarantine a file (moved, not deleted)
  ./respond.sh unit NAME           stop + disable + mask a systemd service
  ./respond.sh report              incident report draft for the ticket

${bold}checking${reset}
  ./watch.sh --once                one full check now
  ./watch.sh --rebaseline          after YOU changed something on purpose
  ./linux-lockdown.sh --audit      re-scan the Linux side (changes nothing)
  ./<engine>-lockdown.sh --audit   re-scan a database (mysql postgres redis mongodb)
  ./firewall.sh status             firewall rules + recent blocks
  ./backup.sh                      fresh backup     ./backup.sh list
  cat $TODO_FILE   (things that need a human)

${bold}scoring${reset}: scoring.wccomps.org (PCR = password change request)   tickets: teams.wccomps.org
EOF
}

view_watch() { "$SCRIPT_DIR/watch.sh"; }

# ---------------- the tmux session ----------------

build() {
    local W
    tmux new-session -d -s "$SESSION" -n alerts -c "$SCRIPT_DIR" -x 220 -y 55
    tmux set-option -t "$SESSION" mouse on >/dev/null
    tmux set-option -t "$SESSION" history-limit 50000 >/dev/null
    tmux set-option -t "$SESSION" allow-rename off >/dev/null
    tmux set-option -t "$SESSION" status-left "#[bold] MARVIN #[default]" >/dev/null
    tmux set-option -t "$SESSION" status-right "#[fg=yellow]$(hostname) %H:%M " >/dev/null

    W="$SESSION:alerts"
    tmux send-keys -t "$W" "./watch.sh" C-m
    tmux split-window -v -l 30% -t "$W" -c "$SCRIPT_DIR"
    tmux send-keys -t "$W.1" "./monitor.sh view alerts" C-m

    tmux new-window -t "$SESSION" -n procs -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:procs" "./monitor.sh view newprocs" C-m
    tmux split-window -v -l 45% -t "$SESSION:procs" -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:procs.1" "./monitor.sh view tree" C-m

    tmux new-window -t "$SESSION" -n net -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:net" "./monitor.sh view net" C-m
    tmux split-window -v -l 35% -t "$SESSION:net" -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:net.1" "./monitor.sh view fw" C-m

    tmux new-window -t "$SESSION" -n auth -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:auth" "./monitor.sh view auth" C-m

    tmux new-window -t "$SESSION" -n db -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:db" "./monitor.sh view db" C-m
    tmux split-window -v -l 40% -t "$SESSION:db" -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:db.1" "./monitor.sh view dblog" C-m

    tmux new-window -t "$SESSION" -n users -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:users" "./monitor.sh view users" C-m

    tmux new-window -t "$SESSION" -n shell -c "$SCRIPT_DIR"
    tmux send-keys -t "$SESSION:shell" "./monitor.sh view help" C-m

    tmux select-window -t "$SESSION:alerts"
    log_action "MONITOR tmux session '$SESSION' started"
}

no_tmux() {
    nohup "$SCRIPT_DIR/watch.sh" > "$LOG_DIR/watch-screen.log" 2>&1 &
    did "WATCH started in the background (pid $!) - no tmux"
    printf "  follow the alerts:      tail -f %s\n" "$ALERTS"
    printf "  the watcher's screen:   tail -f %s\n" "$LOG_DIR/watch-screen.log"
    printf "  new processes live:     ./monitor.sh view newprocs\n"
    printf "  stop it:                pkill -f watch.sh\n"
}

case "$1" in
    view)
        case "$2" in
            watch|alerts|newprocs|tree|net|fw|auth|db|dblog|users|help) "view_$2" ;;
            *) printf "views: watch alerts newprocs tree net fw auth db dblog users help\n"; exit 1 ;;
        esac ;;
    kill) tmux kill-session -t "$SESSION" 2>/dev/null && did "MONITOR tmux session closed" ;;
    --no-tmux) no_tmux ;;
    -h|--help) usage_from_header ;;
    "")
        if ! have tmux
        then
            caution "tmux is not installed."
            if [[ -t 0 ]] && read -r -p "  Install it now with apt-get (needs the package mirror)? [y/N]: " a && [[ "$a" == [yY]* ]]
            then
                apt-get install -y tmux >/dev/null 2>&1 || DEBIAN_FRONTEND=noninteractive apt-get install -y tmux
            fi
        fi
        if ! have tmux
        then
            no_tmux
            exit 0
        fi
        if tmux has-session -t "$SESSION" 2>/dev/null
        then
            if [[ -t 0 ]] && read -r -p "  The '$SESSION' session already exists. Rebuild it? [y/N]: " a && [[ "$a" == [yY]* ]]
            then
                tmux kill-session -t "$SESSION"
                build
            fi
        else
            build
        fi
        if [[ -t 0 && -t 1 ]]
        then
            [[ -n "$TMUX" ]] && tmux switch-client -t "$SESSION" || tmux attach-session -t "$SESSION"
        else
            printf "  monitor running in tmux session '%s'. Attach with:  sudo tmux attach -t %s\n" "$SESSION" "$SESSION"
        fi ;;
    *) printf "${error}Unknown option: %s${reset}\n\n" "$1"; usage_from_header; exit 1 ;;
esac
exit 0
