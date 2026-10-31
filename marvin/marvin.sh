#!/bin/bash
#
# marvin.sh
#
# Marvin - "the database box". One command for the first minutes of the competition,
# in the spirit of sovereignty.sh:
#   1. init       which users must never be touched (the scorer's), which databases run here
#   2. backup     /etc + a dump of every database, BEFORE anything changes
#   3. learn      watch database logins for a couple of minutes, so the accounts the apps
#                 and the scorer use are known (and protected)
#   4. lockdown   Linux, then every database engine found (MySQL/MariaDB, PostgreSQL,
#                 Redis, MongoDB)
#   5. firewall   show the plan (applying it is always your call: ./firewall.sh apply)
#   6. baseline   snapshot the clean box for the watcher
#   7. monitor    the tmux session with every live view
#
# Never deletes a user, never touches protected accounts, never changes a password the
# apps/scorer use on its own. Everything risky goes on /root/marvin-data/TODO.txt.
#
# Usage:
#   sudo ./marvin.sh init         write /root/marvin-data/marvin.conf (asks a few questions)
#   sudo ./marvin.sh              everything, asking before each change (Enter = the safe answer)
#   sudo ./marvin.sh --auto       everything, safe fixes automatically, risky ones -> TODO.txt
#   sudo ./marvin.sh --audit      report only, change nothing
#   sudo ./marvin.sh todo         what still needs a human
#   options:  --no-tmux   don't start the monitor     --learn N   minutes of login learning (default 2)
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/db.sh"

ACTION=run; TMUX_AT_END=yes; LEARN_MIN=2
while [[ $# -gt 0 ]]
do
    case "$1" in
        init) ACTION=init ;;
        todo) ACTION=todo ;;
        --auto) MODE=auto ;;
        --audit|--dry-run) MODE=audit ;;
        --no-tmux) TMUX_AT_END=no ;;
        --learn) LEARN_MIN="$2"; shift ;;
        -h|--help) usage_from_header; exit 0 ;;
        *) printf "${error}Unknown option: %s${reset}\n\n" "$1"; usage_from_header; exit 1 ;;
    esac
    shift
done

require_root
setup_dirs
load_conf
SCRIPT_NAME=marvin
FLAG="--$MODE"; [[ "$MODE" == "interactive" ]] && FLAG=""

init() {
    local engines e users team ip
    section "MARVIN SETUP  ($CONF)"
    engines=$(detect_engines | paste -sd' ' -)
    printf "  databases found here: ${bold}%s${reset}\n" "${engines:-NONE}"
    for e in $engines
    do
        printf "      %-9s port(s) %s\n" "$e" "$(engine_ports "$e")"
    done
    docker_db_warning
    ip=$(my_ips | grep -v '^127\.' | head -n 1)
    team="${TEAM_NET}"
    [[ -n "$ip" ]] && team="$(cut -d. -f1-3 <<< "$ip").0/24"
    printf "  this box: %s   team network: %s\n\n" "${ip:-?}" "$team"
    printf "  ${bold}Linux accounts that can log in:${reset} %s\n" "$(login_users | paste -sd' ' -)"
    explain "PROTECTED users are never locked or changed by the scripts. Put in: the account(s) the"
    explain "SCORER uses (scoring page: SSH check), your own, your teammates'."
    if [[ "$MODE" == "interactive" ]]
    then
        ask_text "Protected Linux users [${PROTECTED_LINUX_USERS:-$ME}]: "; users="${REPLY:-${PROTECTED_LINUX_USERS:-$ME}}"
        explain "Database accounts the scorer + apps use (scoring page DB check, app config files)."
        explain "Accounts seen logging in are protected automatically, so it's fine to leave this empty."
        ask_text "Protected database users [${PROTECTED_DB_USERS}]: "; PROTECTED_DB_USERS="${REPLY:-$PROTECTED_DB_USERS}"
        ask_text "Team network [$team]: "; team="${REPLY:-$team}"
        explain "Scoring engine IP(s): leave empty if you don't know yet (./firewall.sh discover finds them)."
        ask_text "Scoring engine IP(s) [${SCORING_IPS}]: "; SCORING_IPS="${REPLY:-$SCORING_IPS}"
        explain "Ports besides SSH + the database that the scoring page checks on marvin (e.g. 8080/tcp)."
        ask_text "Extra scored ports [${EXTRA_PORTS}]: "; EXTRA_PORTS="${REPLY:-$EXTRA_PORTS}"
    else
        users="${PROTECTED_LINUX_USERS:-$ME}"
    fi
    [[ -f "$CONF" ]] && cp -a "$CONF" "$CONF.$(date +%H%M%S).bak"
    cat > "$CONF" <<EOF
# marvin.conf - every marvin script reads this.  Edit any time:  nano $CONF
# Written by marvin.sh init $(date -Is)

# Linux accounts that are NEVER locked or changed: the scorer's SSH user, you, teammates.
PROTECTED_LINUX_USERS="$users"

# Database accounts that are NEVER locked or dropped: the scorer's DB login, the apps' logins.
# (Accounts seen logging in - $SEEN_DIR - are protected automatically too.)
PROTECTED_DB_USERS="$PROTECTED_DB_USERS"

# Database engines on this box: mysql postgres redis mongodb
DB_ENGINES="$engines"

# The team network (the other boxes). Database logins from outside it are flagged.
TEAM_NET="$team"

# Scoring engine IP(s). Empty = the database port stays open to everyone in the firewall.
# Find them with: ./firewall.sh discover
SCORING_IPS="$SCORING_IPS"

# Extra ports the scoring page checks on marvin, besides 22 and the database (e.g. "8080/tcp 161/udp")
EXTRA_PORTS="$EXTRA_PORTS"
EOF
    chmod 600 "$CONF"
    did "CONFIG written: $CONF"
    sed 's/^/      /' "$CONF" | grep -v '^      #' | grep .
}

learn() {
    local e end n
    [[ "$LEARN_MIN" =~ ^[0-9]+$ && "$LEARN_MIN" -gt 0 ]] || return
    section "LEARNING WHO LOGS IN TO THE DATABASES (${LEARN_MIN} min)"
    explain "Apps and the scorer log in to the databases every few minutes. Every account seen now"
    explain "is PROTECTED from the lockdown, so we don't lock out the scorer or an app by mistake."
    for e in $DB_ENGINES
    do
        db_connect "$e" >/dev/null 2>&1 && printf "  watching %s\n" "$e" || caution "can't log in to $e yet (its lockdown script will ask)"
    done
    # PostgreSQL only remembers logins when log_connections is on - turn it on first
    [[ " $DB_ENGINES " == *" postgres "* && "$MODE" != "audit" ]] && "$SCRIPT_DIR/postgres-lockdown.sh" --auto logging >/dev/null 2>&1
    end=$(( $(date +%s) + LEARN_MIN * 60 ))
    while (( $(date +%s) < end ))
    do
        for e in $DB_ENGINES
        do
            db_seen_update "$e" >/dev/null 2>&1
        done
        printf "\r  %3ss left   accounts seen so far: %s   " "$(( end - $(date +%s) ))" \
            "$(cat "$SEEN_DIR"/*.txt 2>/dev/null | awk '{print $1}' | sort -u | paste -sd' ' -)"
        sleep 3
    done
    printf "\n"
    for e in $DB_ENGINES
    do
        [[ -s "$SEEN_DIR/$e.txt" ]] && awk -v e="$e" '{printf "      %-9s %-20s from %s\n", e, $1, $2}' "$SEEN_DIR/$e.txt"
    done
}

show_todo() {
    section "NEEDS A HUMAN  ($TODO_FILE)"
    if [[ -s "$TODO_FILE" ]]
    then
        sed 's/^/  /' "$TODO_FILE"
        explain "Each item: decide, then run that script's step interactively, e.g.  ./mysql-lockdown.sh accounts"
    else
        ok "nothing left"
    fi
}

if [[ "$ACTION" == "init" ]]; then init; exit 0; fi
if [[ "$ACTION" == "todo" ]]; then show_todo; exit 0; fi

# Give the user one more chance before running (like sovereignty.sh)
banner "marvin.sh  -  lock down the database box"
printf "\n  You are ${info}%s${reset} (sudo from: %s)\n" "$(whoami)" "${ME:-root}"
printf "  Scripts folder: ${info}%s${reset}\n" "$SCRIPT_DIR"
printf "  Data + evidence: ${info}%s${reset}\n" "$DATA_DIR"
if [[ "$MODE" != "auto" ]]
then
    read -r -u 3 -p "  Continue? [y/n]: " a
    [[ "$a" == [nN]* ]] && { printf "Script ended.\n"; exit 0; }
fi
START=$(date -Is)
log_action "START marvin.sh mode=$MODE"

# 1. config
if [[ ! -f "$CONF" ]]
then
    init
    load_conf
fi
DB_ENGINES="${DB_ENGINES:-$(detect_engines | paste -sd' ' -)}"
[[ -z "$PROTECTED_LINUX_USERS" ]] && caution "PROTECTED_LINUX_USERS is empty - fill it in: ./marvin.sh init"

# 2. backup (before anything changes)
[[ "$MODE" != "audit" ]] && "$SCRIPT_DIR/backup.sh"

# 3. learn which DB accounts are in use
[[ -n "$DB_ENGINES" ]] && learn

# 4. lockdown: Linux first (passwords, backdoors), then each database
"$SCRIPT_DIR/linux-lockdown.sh" $FLAG
for e in $DB_ENGINES
do
    if [[ -x "$SCRIPT_DIR/$e-lockdown.sh" ]]
    then
        "$SCRIPT_DIR/$e-lockdown.sh" $FLAG
    else
        caution "no lockdown script for '$e'"
    fi
done

# 5. firewall: always a human decision (the scoreboard has to be watched while it goes on)
"$SCRIPT_DIR/firewall.sh" plan
if [[ "$MODE" == "interactive" ]]
then
    confirm_risky "Put the firewall on now (5 minute automatic rollback)?" && "$SCRIPT_DIR/firewall.sh" apply
else
    todo "Put the firewall on: ./firewall.sh apply (check the plan + scoring page first)"
fi

# 6. baseline of the cleaned box + a fresh "known good" backup
if [[ "$MODE" != "audit" ]]
then
    "$SCRIPT_DIR/watch.sh" --rebaseline
    "$SCRIPT_DIR/backup.sh" >/dev/null 2>&1 && ok "fresh 'known good' backup made"
fi
log_action "END marvin.sh"

# summary
section "SUMMARY"
printf "  changes made this run:   %s   (all of them: %s)\n" "$(awk -v s="$START" '$1 >= s' "$ACTIONS" | grep -vcE ' (START|END) ')" "$ACTIONS"
printf "  problems flagged:        %s   (%s)\n" "$(awk -v s="$START" '$1 >= s' "$FINDINGS" | wc -l)" "$FINDINGS"
printf "  evidence + quarantine:   %s\n" "$EVIDENCE"
show_todo
explain "Next: tell the team what changed (DB accounts, passwords), file PCRs for scored accounts,"
explain "work through the TODO list, then keep the monitor open."

# 7. monitor
if [[ "$TMUX_AT_END" == "yes" && "$MODE" != "audit" ]]
then
    [[ "$MODE" == "interactive" ]] && pause_enter
    "$SCRIPT_DIR/monitor.sh"
fi
exit 0
