#!/bin/bash
#
# sylvester.sh
#
# Sylvester - "the video streaming box" (Rocky Linux). One command for the first minutes:
#   1. init       which users must never be touched (the scorer's), which app runs here
#   2. backup     /etc + the app's config and database, BEFORE anything changes
#   3. lockdown   Linux (incl. SELinux), then the streaming app
#   4. firewall   show the plan (applying it is always your call: ./firewall.sh apply)
#   5. baseline   snapshot the clean box for the watcher
#   6. monitor    the tmux session "sylvester" with every live view
# Never deletes a user, never touches protected accounts. Risky things -> /root/sylvester-data/TODO.txt
#
# Usage:
#   sudo ./sylvester.sh init       write /root/sylvester-data/sylvester.conf
#   sudo ./sylvester.sh            everything, asking before each change (Enter = the safe answer)
#   sudo ./sylvester.sh --auto     safe fixes automatically, risky ones -> TODO.txt
#   sudo ./sylvester.sh --audit    report only, change nothing
#   sudo ./sylvester.sh todo       what still needs a human
#   option: --no-tmux
#
# Sylvester (video streamer, Rocky Linux) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

ACTION=run; TMUX_AT_END=yes
for a in "$@"
do
    case "$a" in
        init) ACTION=init ;;
        todo) ACTION=todo ;;
        --auto) MODE=auto ;;
        --audit|--dry-run) MODE=audit ;;
        --no-tmux) TMUX_AT_END=no ;;
        -h|--help) usage_from_header; exit 0 ;;
        *) printf "${error}Unknown option: %s${reset}\n\n" "$a"; usage_from_header; exit 1 ;;
    esac
done
require_root
setup_dirs
load_conf
SCRIPT_NAME=sylvester
FLAG="--$MODE"; [[ "$MODE" == "interactive" ]] && FLAG=""

init() {
    local apps a ip team users url port
    section "SYLVESTER SETUP  ($CONF)"
    apps=$(detect_apps | paste -sd' ' -)
    printf "  streaming/web apps found: ${bold}%s${reset}\n" "${apps:-NONE - check the scoring page + ss -tulpn}"
    for a in $apps; do printf "      %-9s ports %s\n" "$a" "$(app_ports "$a")"; done
    ip=$(my_ips | grep -v '^127\.' | head -n 1)
    team="$TEAM_NET"; [[ -n "$ip" ]] && team="$(cut -d. -f1-3 <<< "$ip").0/24"
    port=$(for a in $apps; do app_ports "$a"; done | grep -oE '^[0-9]+' | head -n 1)
    url="${STREAM_URL:-http://127.0.0.1:${port:-80}/}"
    printf "  Linux accounts that can log in: %s\n" "$(login_users | paste -sd' ' -)"
    explain "PROTECTED users are never locked: the scorer's SSH user (scoring page), you, teammates."
    users="${PROTECTED_LINUX_USERS:-$ME}"
    if [[ "$MODE" == "interactive" ]]
    then
        ask_text "Protected Linux users [$users]: "; users="${REPLY:-$users}"
        ask_text "Team network [$team]: "; team="${REPLY:-$team}"
        ask_text "URL the scorer checks (health check) [$url]: "; url="${REPLY:-$url}"
        ask_text "Scoring engine IP(s) [${SCORING_IPS}] (unknown? leave empty, ./firewall.sh discover): "; SCORING_IPS="${REPLY:-$SCORING_IPS}"
        ask_text "Extra scored ports besides 22 + the app (e.g. 1935/tcp) [${EXTRA_PORTS}]: "; EXTRA_PORTS="${REPLY:-$EXTRA_PORTS}"
    fi
    [[ -f "$CONF" ]] && cp -a "$CONF" "$CONF.$(date +%H%M%S).bak"
    cat > "$CONF" <<EOF
# sylvester.conf - every sylvester script reads this.  Edit any time:  nano $CONF
# Written by sylvester.sh init $(date -Is)

# Linux accounts that are NEVER locked or changed: the scorer's SSH user, you, teammates.
PROTECTED_LINUX_USERS="$users"

# The streaming / web app(s) on this box (jellyfin emby plex owncast mediamtx icecast nginx httpd)
APPS="$apps"

# What the scorer probably opens - watch.sh checks it every minute
STREAM_URL="$url"

# The team network (the other boxes)
TEAM_NET="$team"

# Scoring engine IP(s) - find them with ./firewall.sh discover
SCORING_IPS="$SCORING_IPS"

# Extra ports the scoring page checks on sylvester, besides 22 and the app's own
EXTRA_PORTS="$EXTRA_PORTS"
EOF
    chmod 600 "$CONF"
    did "CONFIG written: $CONF"
    grep -vE '^#|^$' "$CONF" | sed 's/^/      /'
}

if [[ "$ACTION" == "init" ]]; then init; exit 0; fi
if [[ "$ACTION" == "todo" ]]; then section "NEEDS A HUMAN"; sed 's/^/  /' "$TODO_FILE" 2>/dev/null; exit 0; fi

banner "sylvester.sh  -  lock down the video streaming box"
printf "\n  You are ${info}%s${reset} (sudo from: %s)\n  Scripts: ${info}%s${reset}\n  Data + evidence: ${info}%s${reset}\n" \
    "$(whoami)" "${ME:-root}" "$SCRIPT_DIR" "$DATA_DIR"
if [[ "$MODE" != "auto" ]]
then
    read -r -u 3 -p "  Continue? [y/n]: " a
    [[ "$a" == [nN]* ]] && { printf "Script ended.\n"; exit 0; }
fi
START=$(date -Is)
log_action "START sylvester.sh mode=$MODE"
[[ -f "$CONF" ]] || { init; load_conf; }
[[ -z "$PROTECTED_LINUX_USERS" ]] && caution "PROTECTED_LINUX_USERS is empty - fill it in: ./sylvester.sh init"

[[ "$MODE" != "audit" ]] && "$SCRIPT_DIR/backup.sh"
"$SCRIPT_DIR/linux-lockdown.sh" $FLAG
"$SCRIPT_DIR/stream-lockdown.sh" $FLAG
"$SCRIPT_DIR/firewall.sh" plan
if [[ "$MODE" == "interactive" ]]
then
    confirm_risky "Put the firewall on now (5 minute automatic rollback)?" && "$SCRIPT_DIR/firewall.sh" apply
else
    todo "Put the firewall on: ./firewall.sh apply (check the plan + scoring page first)"
fi
if [[ "$MODE" != "audit" ]]
then
    "$SCRIPT_DIR/watch.sh" --rebaseline
    "$SCRIPT_DIR/backup.sh" >/dev/null 2>&1 && ok "fresh 'known good' backup made"
fi
log_action "END sylvester.sh"

section "SUMMARY"
printf "  changes made this run:   %s   (%s)\n" "$(awk -v s="$START" '$1 >= s' "$ACTIONS" | grep -vcE ' (START|END) ')" "$ACTIONS"
printf "  problems flagged:        %s   (%s)\n" "$(awk -v s="$START" '$1 >= s' "$FINDINGS" | wc -l)" "$FINDINGS"
section "NEEDS A HUMAN  ($TODO_FILE)"
sed 's/^/  /' "$TODO_FILE" 2>/dev/null
if [[ "$TMUX_AT_END" == "yes" && "$MODE" != "audit" ]]
then
    [[ "$MODE" == "interactive" ]] && pause_enter
    "$SCRIPT_DIR/monitor.sh"
fi
exit 0
