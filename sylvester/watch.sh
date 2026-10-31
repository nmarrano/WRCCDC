#!/bin/bash
#
# watch.sh
#
# The alarm system. Every pass (default every 60 s) it:
#   - checks the streaming app is up and answering on the network (and STREAM_URL)
#   - compares the box with a baseline snapshot taken when it was clean:
#       security files (passwd, sudoers, ssh, pam, cron, systemd, profile...), users,
#       listening ports, SUID files, unknown systemd units, firewall, SELinux
#   - flags suspicious processes (reverse shells, temp-folder programs, DB-started shells)
#   - flags outbound connections leaving the team network
#   - prints new SSH logins, failed logins, sudo use, user changes, firewall blocks
# New problems are appended (with time) to /root/sylvester-data/logs/alerts.log.
#
# Usage:
#   sudo ./watch.sh                   loop forever (Ctrl-C stops it)
#   sudo ./watch.sh --once            one pass
#   sudo ./watch.sh --rebaseline      "the box as it is NOW is good" - run after YOU change things
#   sudo ./watch.sh --rebaseline fw   re-snapshot one part: files users listen suid units fw
#   INTERVAL=30 sudo ./watch.sh       check more often
#
# Sylvester (video streamer, Rocky Linux) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

require_root
setup_dirs
load_conf
SCRIPT_NAME=watch
MODE=auto                   # never stop to ask anything
STATE="$DATA_DIR/watch-state"
INTERVAL="${INTERVAL:-60}"
PARTS="files users listen suid units fw"
mkdir -p "$STATE/now"
APPS="${APPS:-$(detect_apps | paste -sd' ' -)}"

CRIT_PATHS=(
    /etc/passwd /etc/shadow /etc/group /etc/gshadow /etc/sudoers /etc/sudoers.d
    /etc/ssh /etc/pam.d /etc/security /etc/ld.so.preload /etc/ld.so.conf /etc/ld.so.conf.d /etc/rc.local
    /etc/crontab /etc/cron.d /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /var/spool/cron
    /etc/systemd/system /usr/local/lib/systemd /etc/update-motd.d /etc/apt/apt.conf.d /etc/udev/rules.d
    /etc/profile /etc/profile.d /etc/bash.bashrc /etc/environment /etc/hosts /etc/resolv.conf
    /etc/jellyfin /etc/nginx /etc/httpd /etc/firewalld /etc/selinux/config /usr/local/etc/mediamtx.yml /etc/mediamtx
    /root/.ssh /root/.bashrc /root/.profile /home/*/.ssh /home/*/.bashrc /home/*/.profile
)

# ---- snapshots: sorted "key<TAB>value" lines ----

snap_files() {
    find "${CRIT_PATHS[@]}" -xdev -type f -print0 2>/dev/null | xargs -0 -r sha256sum 2>/dev/null \
        | awk '{h = $1; sub(/^[0-9a-f]+  /, ""); print $0 "\t" substr(h, 1, 16)}' | sort
}
snap_users() {
    { awk -F: '{print "user " $1 "\tuid=" $3 " shell=" $7}' /etc/passwd
      awk -F: '$4 != "" {print "group " $1 "\tmembers=" $4}' /etc/group; } | sort
}
snap_listen() { listeners | awk '!/^udp/ || $2 != "323"' | awk '{print $1 " " $3 ":" $2 "\t" $4}' | sort -u; }
snap_suid()   { find / "${PRUNE[@]}" -type f \( -perm -4000 -o -perm -2000 \) -printf '%p\t%m %U\n' 2>/dev/null | sort; }
snap_units() {
    find /etc/systemd/system /usr/local/lib/systemd /usr/lib/systemd/system /run/systemd/transient -type f \
         \( -name '*.service' -o -name '*.timer' \) 2>/dev/null | not_owned | grep -vE '/sylvester-|/snap[.-]' \
        | while read -r f; do printf '%s\t%s\n' "$f" "$(sha256sum < "$f" | cut -c1-16)"; done | sort
}
snap_fw() {
    printf "firewalld\t%s %s\n" "$(firewall-cmd --state 2>&1)" "$(firewall-cmd --list-all 2>/dev/null | sha256sum | cut -c1-12)"
    printf "selinux\t%s\n" "$(getenforce 2>/dev/null)"
}

compare() {   # compare PART: baseline vs now
    awk -F'\t' 'NR == FNR {old[$1] = $2; next}
        {seen[$1] = 1
         if (!($1 in old)) print "NEW      " $1 (length($2) < 70 ? "  (" $2 ")" : "")
         else if (old[$1] != $2) {
             if (length(old[$1]) < 50 && length($2) < 50) print "CHANGED  " $1 "  (" old[$1] " -> " $2 ")"
             else print "CHANGED  " $1}}
        END {for (k in old) if (!(k in seen)) print "GONE     " k}' "$BASELINE/$1" "$STATE/now/$1" | sort
}

rebaseline() {
    local part
    for part in ${1:-$PARTS}
    do
        "snap_$part" > "$BASELINE/$part"
    done
    date -Is > "$BASELINE/taken"
    printf "%s REBASELINE %s\n" "$(date -Is)" "${1:-all}" >> "$ALERTS"
    printf "${info}Baseline saved (%s) in %s${reset}\n" "${1:-all parts}" "$BASELINE"
}

# ---- the streaming app ----

health() {
    local a u p ip code
    HEALTH_SUMMARY=""
    ip=$(my_ips | grep -v '^127\.' | head -n 1)
    for a in $APPS
    do
        u=$(app_field "$a" 2)
        if ! systemctl is-active --quiet "$u"
        then
            HEALTH_SUMMARY+="$a=DOWN "
            printf "HEALTH %s (%s) is %s - systemctl status %s; journalctl -u %s -n 30\n" "$a" "$u" "$(systemctl is-active "$u")" "$u" "$u"
            continue
        fi
        HEALTH_SUMMARY+="$a=up "
        for p in $(app_ports "$a" | grep -oE '[0-9]+/tcp' | cut -d/ -f1)
        do
            timeout 3 bash -c "exec 3<>/dev/tcp/${ip:-127.0.0.1}/$p" 2>/dev/null \
                || printf "HEALTH %s port %s does not answer on %s\n" "$a" "$p" "$ip"
        done
    done
    if [[ -n "$STREAM_URL" ]]
    then
        code=$(curl -sk -m 8 -o /dev/null -w '%{http_code}' "$STREAM_URL")
        HEALTH_SUMMARY+="web=$code "
        [[ "$code" =~ ^(2|3|401) ]] || printf "HEALTH %s answered HTTP %s\n" "$STREAM_URL" "$code"
    fi
    timeout 3 bash -c "exec 3<>/dev/tcp/127.0.0.1/22" 2>/dev/null || printf "HEALTH ssh (port 22) is not answering\n"
}

procs() {
    scan_procs | awk -F'\t' '{printf "PROC %s pid=%s user=%s %s: %s\n", $1, $2, $3, $4, substr($5, 1, 100)}'
}

outbound() {
    local l peer proc p lports name
    lports=" $(listeners | awk '{print $2}' | sort -u | paste -sd' ' -) "
    ss -Htnp state established 2>/dev/null | awk '{print $3, $4, $5}' | while read -r l peer proc
    do
        p=${peer%:*}; p=${p#[}; p=${p%]}; p=${p#::ffff:}
        is_local_addr "$p" && continue
        [[ "$lports" == *" ${l##*:} "* ]] && continue          # someone connected TO us
        ip_in_team_net "$p" && continue
        name=$(grep -o '"[^"]*"' <<< "$proc" | head -n 1 | tr -d '"')
        printf "NET outbound %s -> %s (leaves the team network)\n" "${name:-?}" "$peer"
    done
}

disk() {
    df -P / /var 2>/dev/null | awk 'NR > 1 {u = $5; sub(/%/, "", u); if (u + 0 >= 90) print "DISK " $6 " is " $5 " full - a full disk crashes databases"}' | sort -u
}

sessions() { who 2>/dev/null | awk '{printf "SESSION %s on %s from %s\n", $1, $2, $NF}'; }

events() {   # journal events since the last pass (always new, so logged directly)
    local since now
    now=$(date +%s)
    since=$(cat "$STATE/last" 2>/dev/null || echo $(( now - INTERVAL )))
    echo "$now" > "$STATE/last"
    # "Oct 31 10:40:00 sylvester sshd[123]: Accepted ..." -> "10:40:00 Accepted ..."
    local tidy='s/^[A-Za-z]{3} +[0-9]+ ([0-9:]+) [^ ]+ [^ :]+: /\1 /'
    {
        journalctl -q --no-pager -o short --since "@$since" SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session 2>/dev/null \
            | grep -E 'Accepted ' | sed -E "$tidy" | sed 's/^/LOGIN /'
        journalctl -q --no-pager -o short --since "@$since" SYSLOG_IDENTIFIER=sshd SYSLOG_IDENTIFIER=sshd-session 2>/dev/null \
            | grep -E 'Failed |Invalid user' | grep -oE 'from [0-9a-fA-F.:]+' | sort | uniq -c \
            | awk '{printf "AUTH %s failed SSH logins %s %s\n", $1, $2, $3}'
        journalctl -q --no-pager -o short --since "@$since" SYSLOG_IDENTIFIER=sudo SYSLOG_IDENTIFIER=su 2>/dev/null \
            | grep -E 'COMMAND=|session opened|authentication failure' | sed -E "$tidy" | sed 's/^/PRIV /'
        journalctl -q --no-pager -o short --since "@$since" SYSLOG_IDENTIFIER=useradd SYSLOG_IDENTIFIER=userdel \
            SYSLOG_IDENTIFIER=usermod SYSLOG_IDENTIFIER=groupadd SYSLOG_IDENTIFIER=gpasswd SYSLOG_IDENTIFIER=passwd \
            SYSLOG_IDENTIFIER=chpasswd SYSLOG_IDENTIFIER=chage 2>/dev/null | sed -E "$tidy" | sed 's/^/USERS /'
        journalctl -k -q --no-pager -o short --since "@$since" 2>/dev/null | grep 'UFW BLOCK' \
            | awk '{s = d = ""; for (i = 1; i <= NF; i++) {if ($i ~ /^SRC=/) s = substr($i, 5); else if ($i ~ /^DPT=/) d = substr($i, 5)}
                    print s " -> port " d}' | sort | uniq -c | sort -rn | head -n 5 | awk '{c = $1; $1 = ""; print "FWBLOCK " c "x" $0}'
    } | cut -c1-200
}

show() {   # show FILE COLOR: lines not in the previous pass get a red NEW tag
    local line
    head -n 25 "$1" | while IFS= read -r line
    do
        if grep -qxF -- "$line" "$STATE/new" 2>/dev/null
        then
            printf "${error}NEW  %s${reset}\n" "$line"
        else
            printf "%s     %s${reset}\n" "$2" "$line"
        fi
    done
    (( $(wc -l < "$1") > 25 )) && printf "     ... %s more lines in %s\n" "$(( $(wc -l < "$1") - 25 ))" "$1"
}

pass() {
    local part ts
    ts=$(date -Is)
    : > "$STATE/current"
    health >> "$STATE/current"
    for part in $PARTS
    do
        "snap_$part" > "$STATE/now/$part"
        [[ -f "$BASELINE/$part" ]] && compare "$part" | sed "s/^/DRIFT $part: /" >> "$STATE/current"
    done
    procs >> "$STATE/current"
    outbound >> "$STATE/current"
    disk >> "$STATE/current"
    sessions >> "$STATE/current"
    events > "$STATE/events"

    sort -u "$STATE/current" -o "$STATE/current"
    touch "$STATE/prev"
    comm -13 "$STATE/prev" "$STATE/current" | grep -v '^SESSION' > "$STATE/new"
    comm -23 "$STATE/prev" "$STATE/current" | grep '^HEALTH' | sed 's/^/RECOVERED /' > "$STATE/recovered"
    cat "$STATE/new" "$STATE/recovered" "$STATE/events" | sed "s/^/$ts /" >> "$ALERTS"

    [[ "$ONCE" == "true" || ! -t 1 ]] || printf '\e[H\e[2J'
    printf "${bold}${info}=== sylvester watch %s   every %ss   baseline from %s ===${reset}\n" "$(date +%H:%M:%S)" "$INTERVAL" "$(cut -c1-19 "$BASELINE/taken" 2>/dev/null || echo never)"
    if grep -q '^HEALTH' "$STATE/current"
    then
        printf "${error}${bold}SERVICE PROBLEM: %s${reset}\n" "$HEALTH_SUMMARY"
        grep '^HEALTH' "$STATE/current" > "$STATE/show"; show "$STATE/show" "$error"
    else
        printf "${info}SERVICES OK: %s ssh=up${reset}\n" "$HEALTH_SUMMARY"
    fi
    [[ -s "$STATE/recovered" ]] && printf "${info}%s${reset}\n" "$(cat "$STATE/recovered")"

    printf "\n${bold}-- red flags: processes / outbound / disk --${reset}\n"
    grep -E '^(PROC|NET|DISK)' "$STATE/current" > "$STATE/show"; show "$STATE/show" "$error"
    printf "\n${bold}-- changed since the baseline (if YOU did it: ./watch.sh --rebaseline) --${reset}\n"
    grep '^DRIFT' "$STATE/current" > "$STATE/show"; show "$STATE/show" "$warn"
    printf "\n${bold}-- logins / sudo / user changes / firewall blocks since the last pass --${reset}\n"
    [[ -s "$STATE/events" ]] && cat "$STATE/events"
    printf "\n${bold}-- logged in now --${reset}\n"
    grep '^SESSION' "$STATE/current" > "$STATE/show"; show "$STATE/show" ""
    printf "\n${note}alerts log: %s   respond: ./respond.sh proc|user|dbuser|ip|file|unit${reset}\n" "$ALERTS"
    mv "$STATE/current" "$STATE/prev"
}

ONCE="false"
case "$1" in
    --rebaseline) rebaseline "$2"; exit 0 ;;
    --once) ONCE="true" ;;
    -h|--help) usage_from_header; exit 0 ;;
    "") ;;
    *) printf "${error}Unknown option: %s (try --help)${reset}\n" "$1"; exit 1 ;;
esac

if [[ ! -f "$BASELINE/taken" ]]
then
    printf "${warn}No baseline yet - taking one now (this assumes the box is clean right now).${reset}\n"
    rebaseline
fi
if [[ "$ONCE" == "true" ]]
then
    pass
    exit 0
fi
trap 'printf "\n${info}watch stopped.${reset}\n"; exit 0' INT TERM
while true
do
    pass
    sleep "$INTERVAL"
done
