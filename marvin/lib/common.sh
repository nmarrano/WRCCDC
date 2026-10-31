#!/bin/bash
#
# lib/common.sh
#
# Shared settings and helpers for every marvin script. It is not run by itself;
# each script loads it with:   . "$SCRIPT_DIR/lib/common.sh"
# Nothing in this file changes the system on its own.
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

export LC_ALL=C
export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

# Use colors, but only if connected to a terminal
if [[ -t 1 ]]
then
    info=$'\e[32m'; warn=$'\e[33m'; error=$'\e[31m'; note=$'\e[36m'; bold=$'\e[1m'; reset=$'\e[0m'
else
    info=""; warn=""; error=""; note=""; bold=""; reset=""
fi

# ps complains about the terminal size when there is no terminal
[[ -t 1 ]] || export COLUMNS="${COLUMNS:-200}"

# Prompts read from fd 3 (the real keyboard), so they still work inside "while read" loops
exec 3<&0

DATA_DIR="${DATA_DIR:-/root/marvin-data}"
CONF="$DATA_DIR/marvin.conf"
SECRETS="$DATA_DIR/secrets.conf"
EVIDENCE="$DATA_DIR/evidence"
BACKUPS="$DATA_DIR/backups"
BASELINE="$DATA_DIR/baseline"
SEEN_DIR="$DATA_DIR/seen"
LOG_DIR="$DATA_DIR/logs"
ACTIONS="$LOG_DIR/actions.log"
ALERTS="$LOG_DIR/alerts.log"
FINDINGS="$LOG_DIR/findings.log"
TODO_FILE="$DATA_DIR/TODO.txt"

# interactive (ask), auto (do the safe fixes, list the rest), audit (change nothing)
MODE="${MODE:-interactive}"
SCRIPT_NAME="$(basename "$0" .sh)"

# who is running this (never lock yourself out)
ME="${SUDO_USER:-$(logname 2>/dev/null)}"
[[ "$ME" == "root" ]] && ME=""

MARVIN_TMP="$(mktemp -d /tmp/.marvin.XXXXXX)"
trap 'rm -rf "$MARVIN_TMP"' EXIT

# Programs that are databases. A shell started BY one of these = someone abused the database.
DB_DAEMONS='^(mysqld|mariadbd|postgres|postmaster|mongod|mongos|redis-server|redis-sentinel)$'
# Shells / interpreters / network tools
SHELLS='^(sh|bash|dash|zsh|ksh|csh|tcsh|fish|busybox|python[0-9.]*|perl|ruby|php[0-9.]*|lua[0-9.]*|node|nc|ncat|netcat|nc\.openbsd|nc\.traditional|socat|curl|wget|telnet)$'
# Almost certainly an attack: reverse shells, download-and-run, known attack/tunnel tools
CRIT_CMD='/dev/(tcp|udp)/|(^|[ /])(nc|ncat|netcat|nc\.traditional)( .*)? -[a-z]*[ec]( |$)|(^|[ /])socat .*(exec|system):|(^|[ /])(ba|da|z)?sh +-i( |$)|pty\.spawn|(curl|wget)[^|]*\| *(sudo +)?(ba|da|z)?sh|base64 +(-d|--decode)[^|]*\| *(ba|da|z)?sh|(^|[^a-z])(chisel|ligolo|frpc|xmrig|kinsing|gs-netcat|gsocket|pwncat|sliver|meterpreter|mettle|revsocks|rsockstun)([^a-z]|$)'
# Worth a look: network tools and one-liner interpreters
SUSP_CMD='(^|[ /])(nc|ncat|netcat|nc\.openbsd|nc\.traditional|socat|telnet)( |$)|(python[0-9.]*|perl|ruby|php[0-9.]*|lua[0-9.]*|node) +-(c|e|r)( |$)|mkfifo|xterm +-display'

have() { command -v "$1" >/dev/null 2>&1; }

usage_from_header() {   # print the comment block at the top of the calling script
    awk 'NR > 2 && /^#/ {sub(/^# ?/, ""); print; next} NR > 2 {exit}' "$0"
}

require_root() {
    if [[ "$(id -u)" != "0" ]]
    then
        printf "${error}ERROR: The script must be run with sudo privileges!  Try:  sudo %s${reset}\n" "$0"
        exit 1
    fi
}

setup_dirs() {
    mkdir -p "$EVIDENCE" "$BACKUPS" "$BASELINE" "$SEEN_DIR" "$LOG_DIR" "$DATA_DIR/firewall" "$DATA_DIR/reports"
    chmod 700 "$DATA_DIR"
    touch "$ACTIONS" "$ALERTS" "$FINDINGS" "$TODO_FILE"
}

load_conf() {
    PROTECTED_LINUX_USERS=""
    PROTECTED_DB_USERS=""
    DB_ENGINES=""
    TEAM_NET="192.168.220.0/24"
    SCORING_IPS=""
    EXTRA_PORTS=""
    LIMIT_DB="no"
    [[ -f "$CONF" ]] && . "$CONF"
    [[ -f "$SECRETS" ]] && . "$SECRETS"
}

# set_secret NAME VALUE   (secrets.conf is root-only, mode 600)
set_secret() {
    touch "$SECRETS" && chmod 600 "$SECRETS"
    sed -i "/^$1=/d" "$SECRETS"
    printf "%s=%q\n" "$1" "$2" >> "$SECRETS"
}

# ---- output ----

banner() {
    printf "\n${bold}${info}######################################################################${reset}\n"
    printf "${bold}${info}#  %-66s#${reset}\n" "$1"
    printf "${bold}${info}######################################################################${reset}\n"
    printf "  mode: ${bold}%s${reset}" "$MODE"
    case "$MODE" in
        interactive) printf "   (asks before every change)\n" ;;
        auto)        printf "   (does the SAFE fixes by itself, risky ones go on the TODO list)\n" ;;
        audit)       printf "   (look only - changes NOTHING)\n" ;;
    esac
}
section() { printf "\n${bold}${info}==================== %s ====================${reset}\n" "$*"; }
step()    { printf "\n${bold}--- %s ---${reset}\n" "$*"; }
explain() { printf "${note}    %s${reset}\n" "$*"; }
ok()      { printf "${info}  [ok]   %s${reset}\n" "$*"; }
caution() { printf "${warn}  [??]   %s${reset}\n" "$*"; }
flag() {
    printf "${error}  [!!]   %s${reset}\n" "$*"
    printf "%s %s %s\n" "$(date -Is)" "$SCRIPT_NAME" "$*" >> "$FINDINGS" 2>/dev/null
}
log_action() { printf "%s %s %s\n" "$(date -Is)" "$SCRIPT_NAME" "$*" >> "$ACTIONS" 2>/dev/null; }

did() {   # did "WHAT HAPPENED" ["UNDO COMMAND"]
    printf "${info}  [done] %s${reset}\n" "$1"
    [[ -n "$2" ]] && printf "         undo: %s\n" "$2"
    log_action "$1${2:+   (undo: $2)}"
}

todo_reset() {   # a full run of a script replaces that script's old TODO items
    [[ -f "$TODO_FILE" ]] && sed -i "/^- \[$SCRIPT_NAME\] /d" "$TODO_FILE"
}

todo() {   # something a human has to decide
    local line="- [$SCRIPT_NAME] $*"
    grep -qxF -- "$line" "$TODO_FILE" 2>/dev/null || printf "%s\n" "$line" >> "$TODO_FILE"
}

# ---- decisions ----

# confirm_safe "QUESTION": a fix that should not break scoring.
#   interactive: asks, Enter = YES.  auto: yes.  audit: no.
confirm_safe() {
    local a
    case "$MODE" in
        audit) printf "${note}  (audit: would ask \"%s\")${reset}\n" "$1"; return 1 ;;
        auto)  printf "${note}  auto-yes: %s${reset}\n" "$1"; return 0 ;;
    esac
    read -r -u 3 -p "  ${bold}$1 [Y/n]:${reset} " a
    [[ "$a" != [nN]* ]]
}

# confirm_risky "QUESTION": could break a scored service or lock someone out.
#   interactive: asks, Enter = NO.  auto/audit: no, and it goes on the TODO list.
confirm_risky() {
    local a
    if [[ "$MODE" != "interactive" ]]
    then
        printf "${warn}  skipped, needs a human: %s${reset}\n" "$1"
        todo "$1"
        return 1
    fi
    read -r -u 3 -p "  ${bold}$1 [y/N]:${reset} " a
    [[ "$a" == [yY]* ]]
}

ask_text() {   # ask_text "PROMPT" -> REPLY (empty in auto/audit)
    REPLY=""
    [[ "$MODE" == "interactive" ]] || return 1
    read -r -u 3 -p "  $1" REPLY
}

pause_enter() {
    [[ "$MODE" == "interactive" ]] && read -r -u 3 -p "  ${bold}Press Enter to continue...${reset}" _
}

# ---- users ----

in_list() { [[ " $2 " == *" $1 "* ]]; }   # in_list WORD "LIST OF WORDS"

is_protected_linux() {   # root and whoever runs the script are always protected
    [[ "$1" == "root" || ( -n "$ME" && "$1" == "$ME" ) ]] && return 0
    in_list "$1" "$PROTECTED_LINUX_USERS"
}

# DB accounts are protected if listed in marvin.conf OR seen logging in (apps, scorer)
is_protected_db() {   # is_protected_db ENGINE USER
    in_list "$2" "$PROTECTED_DB_USERS" && return 0
    [[ -f "$SEEN_DIR/$1.txt" ]] && awk -v u="$2" '$1 == u {f = 1} END {exit !f}' "$SEEN_DIR/$1.txt"
}

seen_from() {   # seen_from ENGINE USER -> "ip1 ip2"
    [[ -f "$SEEN_DIR/$1.txt" ]] && awk -v u="$2" '$1 == u {print $2}' "$SEEN_DIR/$1.txt" | sort -u | paste -sd' ' -
}

record_seen() {   # record_seen ENGINE USER FROM
    local f="$SEEN_DIR/$1.txt"
    [[ -z "$2" || "$2" == "NULL" ]] && return
    touch "$f"
    awk -v u="$2" -v h="${3:-?}" '$1 == u && $2 == h {f = 1} END {exit !f}' "$f" \
        || printf "%s\t%s\t%s\n" "$2" "${3:-?}" "$(date +%H:%M:%S)" >> "$f"
}

lock_user() {   # lock_user USER REASON: password + SSH keys stop working, its programs are killed
    local uid
    uid=$(id -u "$1" 2>/dev/null)
    usermod -L -e 1 "$1" 2>/dev/null
    # never pkill -u for a UID 0 account or a shared UID: that would kill root's (or someone else's) programs
    if [[ "$uid" != "0" ]] && (( $(awk -F: -v id="$uid" '$3 == id' /etc/passwd | wc -l) == 1 ))
    then
        pkill -KILL -u "$1" 2>/dev/null
        did "LOCKED Linux account $1 ($2) and killed its programs" "usermod -U -e '' $1"
    else
        did "LOCKED Linux account $1 ($2) - its UID is shared, so its programs were NOT killed" "usermod -U -e '' $1"
        explain "Find its sessions with 'who' and end them with: ./respond.sh proc <PID of its sshd/bash>"
    fi
}

login_users() {   # accounts with a real shell
    awk -F: '$7 !~ /(nologin|false|sync|shutdown|halt)$/ {print $1}' /etc/passwd
}

gen_password() {   # letters + digits only: no $ ' " \ to break config files
    tr -dc 'A-HJ-NP-Za-km-z2-9' < /dev/urandom | head -c "${1:-16}"
}

# ---- files ----

owned_cache() {
    if [[ ! -s "$MARVIN_TMP/owned" ]]
    then
        # Ubuntu merged /bin into /usr/bin: compare everything in the /usr form
        cat /var/lib/dpkg/info/*.list 2>/dev/null \
            | sed -E 's#^/(bin|sbin|lib|lib32|lib64|libx32)/#/usr/\1/#' | sort -u > "$MARVIN_TMP/owned"
    fi
}

is_owned() {   # is_owned PATH -> true if an installed package put this file there
    owned_cache
    grep -qxF -- "$(sed -E 's#^/(bin|sbin|lib|lib32|lib64|libx32)/#/usr/\1/#' <<< "$1")" "$MARVIN_TMP/owned"
}

not_owned() {   # stdin: paths -> stdout: the ones no package installed (a symlink counts as
    owned_cache     # owned when the file it points to is, like Ubuntu's alternatives and motd links)
    while IFS= read -r p
    do
        printf '%s\t%s\n' "$p" "$(readlink -f -- "$p" 2>/dev/null)"
    done | awk -F'\t' '
        function norm(p) { if (p ~ /^\/(bin|sbin|lib|lib32|lib64|libx32)\//) p = "/usr" p; return p }
        NR == FNR {own[$0] = 1; next}
        !(norm($1) in own) && ($2 == "" || !(norm($2) in own)) {print $1}' "$MARVIN_TMP/owned" -
}

# skip these trees when searching the whole disk (/mnt = other drives, $DATA_DIR = our evidence)
PRUNE=( \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /mnt -o -path /media -o -path /snap -o -path "$DATA_DIR" -o -path "/tmp/.marvin.*" \) -prune -o )

# a file that runs a shell / downloads / lives in a temp folder = attack
file_looks_bad() { grep -qE "$CRIT_CMD|$SUSP_CMD|/tmp/|/dev/shm/|/var/tmp/" "$1" 2>/dev/null; }

show_file() {   # show_file PATH WHAT
    printf "\n  ${warn}%s${reset}  (%s, last changed %s)\n" "$1" "$2" "$(date -r "$1" '+%b %d %H:%M' 2>/dev/null)"
    grep -vE '^\s*(#|$)' "$1" 2>/dev/null | head -n 12 | cut -c1-160 | sed 's/^/      | /'
}

# show a file, then quarantine it: auto-yes if it looks like an attack, otherwise a human decides
handle_file() {   # handle_file PATH WHAT
    show_file "$1" "$2"
    if file_looks_bad "$1"
    then
        flag "$1 looks like an attack (runs a shell / downloads / uses a temp folder)"
        confirm_safe "Quarantine $1?" && quarantine "$1" "$2"
    else
        confirm_risky "Quarantine $1 ($2)?" && quarantine "$1" "$2"
    fi
}

# loose_data_files: SQL dumps / exports / CSVs no package installed (copies of the data that
# red team only has to READ to score PII points). Data folders are skipped.
loose_data_files() {   # loose_data_files "EXTRA_DIRS_TO_SKIP_REGEX"
    find / "${PRUNE[@]}" -type f \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' -o -name '*.csv' \
         -o -name '*.bson' -o -name '*.rdb' -o -name '*.pgdump' -o -name '*.bak' \) -size +1k -print 2>/dev/null \
        | grep -vE "^(/var/lib/(mysql|postgresql|redis|mongodb)|/usr/share|/usr/lib)/${1:+|$1}" | not_owned
}

# files_written_by USER "SKIP_REGEX": files a database's Linux user created outside its own
# folders = output of INTO OUTFILE / COPY TO / SAVE (stolen data, webshells, SSH keys)
files_written_by() {
    find / "${PRUNE[@]}" -user "$1" -type f -print 2>/dev/null | grep -vE "$2"
}

new_evidence() {   # new_evidence LABEL -> sets EV to a fresh folder
    EV="$EVIDENCE/$(date +%Y%m%d-%H%M%S)-$1"
    mkdir -p "$EV"
}

# quarantine PATH REASON: record it, then MOVE it into evidence/ (never deleted)
quarantine() {
    local f="$1" dest
    [[ -e "$f" || -L "$f" ]] || return 1
    dest="$EVIDENCE/quarantine-$(date +%Y%m%d)"
    mkdir -p "$dest"
    chattr -ia "$f" 2>/dev/null
    {
        printf "original path: %s\nreason: %s\nwhen: %s\n" "$f" "$2" "$(date -Is)"
        stat "$f"
        [[ -f "$f" ]] && sha256sum "$f"
        printf -- "----\n"
    } >> "$dest/INFO.txt" 2>&1
    if mv "$f" "$dest/$(date +%H%M%S)$(printf '%s' "$f" | tr '/' '_')"
    then
        did "QUARANTINED $f ($2) -> $dest/" "mv $dest/<file> $f"
    else
        flag "could not move $f"
        return 1
    fi
}

backup_file() {   # backup_file PATH -> copy into evidence before editing it
    local dest="$EVIDENCE/before-edit-$(date +%Y%m%d)"
    mkdir -p "$dest"
    cp -a "$1" "$dest/$(date +%H%M%S)$(printf '%s' "$1" | tr '/' '_')" 2>/dev/null
}

# ---- processes ----

own_pids() {   # this script and every parent (our shell, our SSH session): never kill these
    local p=$$
    while [[ -n "$p" && "$p" != 0 && "$p" != 1 ]]
    do
        printf "%s " "$p"
        p=$(awk '/^PPid:/ {print $2}' "/proc/$p/status" 2>/dev/null)
    done
}

# scan_procs: one line per suspicious process
#   LEVEL<TAB>PID<TAB>USER<TAB>REASON<TAB>COMMAND      LEVEL = CRIT (attack) or SUSP (look at it)
scan_procs() {
    local p pid exe cmd comm ppid pcomm user level reason skip
    skip=" $(own_pids) "
    for p in /proc/[0-9]*
    do
        pid=${p#/proc/}
        [[ "$skip" == *" $pid "* ]] && continue
        cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null)
        [[ -z "$cmd" ]] && continue                       # kernel thread
        exe=$(readlink "$p/exe" 2>/dev/null)
        comm=$(cat "$p/comm" 2>/dev/null)
        ppid=$(awk '/^PPid:/ {print $2}' "$p/status" 2>/dev/null)
        pcomm=$(cat "/proc/$ppid/comm" 2>/dev/null)
        user=$(stat -c %U "$p" 2>/dev/null)
        level=""; reason=""
        if [[ "$pcomm" =~ $DB_DAEMONS && "$comm" =~ $SHELLS ]]
        then
            level=CRIT; reason="the database ($pcomm) started a shell/tool - classic DB-to-shell attack"
        elif [[ "$exe" == /tmp/* || "$exe" == /dev/shm/* || "$exe" == /var/tmp/* || "$exe" == /run/user/* || "$exe" == /run/shm/* ]]
        then
            level=CRIT; reason="runs from a temp folder ($exe)"
        elif [[ "$exe" == "$EVIDENCE"/* ]]
        then
            level=CRIT; reason="its program file was quarantined by marvin (it was a backdoor)"
        elif [[ "$exe" == /memfd:* ]]
        then
            level=CRIT; reason="runs from memory only (fileless malware)"
        elif [[ "$cmd" =~ $CRIT_CMD ]]
        then
            level=CRIT; reason="reverse-shell / attack-tool command line"
        elif [[ "$exe" == *" (deleted)" ]]
        then
            level=SUSP; reason="its program file was deleted after it started ($exe)"
        elif [[ "$cmd" =~ $SUSP_CMD ]]
        then
            level=SUSP; reason="network tool or one-liner interpreter"
        fi
        [[ -n "$level" ]] && printf "%s\t%s\t%s\t%s\t%s\n" "$level" "$pid" "${user:-?}" "$reason" "${cmd:0:200}"
    done
}

proc_tree_up() {   # parents of a PID (who started it)
    local p="$1"
    while [[ -n "$p" && "$p" != 0 ]]
    do
        ps -o pid=,user=,cmd= -p "$p" 2>/dev/null | cut -c1-150
        [[ "$p" == 1 ]] && break
        p=$(ps -o ppid= -p "$p" 2>/dev/null | tr -d ' ')
    done
}

proc_evidence() {   # proc_evidence PID -> saves everything about it in EV
    local pid="$1"
    new_evidence "proc-$pid"
    {
        printf "== when: %s\n" "$(date -Is)"
        ps -o user,pid,ppid,lstart,etime,cmd -p "$pid"
        printf "\n== executable: %s\n" "$(readlink "/proc/$pid/exe" 2>/dev/null)"
        printf "== command line: %s\n" "$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null)"
        printf "== working dir: %s\n" "$(readlink "/proc/$pid/cwd" 2>/dev/null)"
        printf "== systemd unit: %s\n" "$(ps -o unit= -p "$pid" 2>/dev/null)"
        printf "\n== parents (who started it)\n"; proc_tree_up "$pid"
        printf "\n== children\n"; ps --ppid "$pid" -o pid=,cmd= 2>/dev/null
        printf "\n== network\n"; ss -tunap 2>/dev/null | grep "pid=$pid,"
        printf "\n== open files\n"; ls -l "/proc/$pid/fd" 2>/dev/null | head -n 50
        printf "\n== environment\n"; tr '\0' '\n' < "/proc/$pid/environ" 2>/dev/null
    } > "$EV/info.txt" 2>&1
    # /proc/PID/exe can be copied even when the file was deleted from disk
    cp "/proc/$pid/exe" "$EV/executable.bin" 2>/dev/null && chmod 400 "$EV/executable.bin" \
        && sha256sum "$EV/executable.bin" >> "$EV/info.txt"
}

kill_proc() {   # kill_proc PID REASON: evidence first, then freeze + kill it and its children
    local pid="$1" unit kids
    [[ -d "/proc/$pid" ]] || return 1
    proc_evidence "$pid"
    unit=$(ps -o unit= -p "$pid" 2>/dev/null | tr -d ' ')
    kids=$(ps --ppid "$pid" -o pid= 2>/dev/null | tr '\n' ' ')
    kill -STOP "$pid" 2>/dev/null
    kill -9 "$pid" $kids 2>/dev/null
    did "KILLED pid $pid ${kids:++ children $kids}($2) evidence: $EV"
    case "$unit" in
        ""|session-*|user@*|init.scope|ssh.service) ;;
        *)
            caution "it was started by systemd unit '$unit' - it may come back."
            explain "Stop it for good:  ./respond.sh unit $unit" ;;
    esac
}

# ---- network ----

# listeners: "proto port addr process pid" per listening socket
listeners() {
    ss -Htulpn 2>/dev/null | awk '{
        proto = $1; local = $5; proc = $7
        port = local; sub(/.*:/, "", port)
        addr = local; sub(/:[^:]*$/, "", addr); sub(/%.*/, "", addr); gsub(/[\[\]]/, "", addr)
        name = "?"; pid = "?"
        if (match(proc, /"[^"]*"/)) name = substr(proc, RSTART + 1, RLENGTH - 2)
        if (match(proc, /pid=[0-9]+/)) pid = substr(proc, RSTART + 4, RLENGTH - 4)
        print proto, port, addr, name, pid
    }' | sort -u
}

is_local_addr() { [[ "$1" == 127.* || "$1" == "::1" || "$1" == "::ffff:127."* ]]; }

ip_in_team_net() {   # ip_in_team_net IP -> true if inside TEAM_NET (a /8, /16 or /24 is enough here)
    local ip="${1#::ffff:}" net="${TEAM_NET%/*}" bits="${TEAM_NET#*/}"
    case "$bits" in
        8)  [[ "${ip%%.*}" == "${net%%.*}" ]] ;;
        16) [[ "$(cut -d. -f1-2 <<< "$ip")" == "$(cut -d. -f1-2 <<< "$net")" ]] ;;
        *)  [[ "$(cut -d. -f1-3 <<< "$ip")" == "$(cut -d. -f1-3 <<< "$net")" ]] ;;
    esac
}

my_ips() { ip -4 -o addr show 2>/dev/null | awk '{sub(/\/.*/, "", $4); print $4}'; }

# ---- databases on this box ----

detect_engines() {   # prints the engines installed or listening here
    local l
    l=$(listeners)
    { have mysqld || have mariadbd || grep -qE ' (mysqld|mariadbd) ' <<< "$l"; } && echo mysql
    { ls /usr/lib/postgresql/*/bin/postgres >/dev/null 2>&1 || grep -qE ' (postgres|postmaster) ' <<< "$l"; } && echo postgres
    { have redis-server || grep -q ' redis-server ' <<< "$l"; } && echo redis
    { have mongod || grep -q ' mongod ' <<< "$l"; } && echo mongodb
}

engine_ports() {   # engine_ports ENGINE -> TCP ports that engine listens on (or its default)
    local re def p
    case "$1" in
        mysql)    re='mysqld|mariadbd'; def=3306 ;;
        postgres) re='postgres|postmaster'; def=5432 ;;
        redis)    re='redis-server'; def=6379 ;;
        mongodb)  re='mongod'; def=27017 ;;
    esac
    p=$(listeners | awk -v re="^($re)\$" '$1 == "tcp" && $4 ~ re {print $2}' | sort -un | paste -sd' ' -)
    echo "${p:-$def}"
}

docker_db_warning() {
    have docker || return
    if docker ps --format '{{.Image}} {{.Ports}}' 2>/dev/null | grep -qiE 'mysql|maria|postgres|redis|mongo'
    then
        flag "A database runs inside DOCKER here:"
        docker ps --format '    {{.Names}}  {{.Image}}  {{.Ports}}' 2>/dev/null
        explain "These scripts check databases installed on the box itself. For a container:"
        explain "  docker exec -it <name> bash   (then run the same SQL by hand), and note that"
        explain "  Docker-published ports SKIP ufw - filter them on the router or in DOCKER-USER."
    fi
}
