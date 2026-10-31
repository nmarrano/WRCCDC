#!/bin/bash
#
# stream-lockdown.sh
#
# Locks down the video streaming app on sylvester. It finds which app runs here
# (Jellyfin, Emby, Plex, Owncast, MediaMTX, Icecast, nginx-rtmp/HLS or Apache) and checks:
#   - setup left open (Jellyfin/Emby first-run wizard = the first visitor creates the admin)
#   - default / missing passwords (Owncast admin:abc123, MediaMTX "any" user, users with no password)
#   - unknown admin users and API keys, unknown plugins (plugins = code that runs in the app)
#   - the app running as root, files anyone can write, webshells in web folders,
#     files changed in the last 2 days, the app's SELinux label
# App settings are changed in the app's web admin page, so most fixes are printed as exact
# steps + TODO items. Files are moved to /root/sylvester-data/evidence/, never deleted.
#
# Usage:
#   sudo ./stream-lockdown.sh              every step, asks before each change
#   sudo ./stream-lockdown.sh --auto       safe fixes by itself, risky ones -> TODO.txt
#   sudo ./stream-lockdown.sh --audit      look only
#   sudo ./stream-lockdown.sh STEP...      only: info app files webshells connections
#
# Sylvester (video streamer, Rocky Linux) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

STEPS="info app files webshells connections"
RUN=""
for a in "$@"
do
    case "$a" in
        --auto) MODE=auto ;;
        --audit|--dry-run) MODE=audit ;;
        -h|--help) usage_from_header; exit 0 ;;
        *)
            if in_list "$a" "$STEPS"
            then
                RUN+="$a "
            else
                printf "${error}Unknown step or option: %s${reset}\n\n" "$a"; usage_from_header; exit 1
            fi ;;
    esac
done
RUN="${RUN:-$STEPS}"

require_root
setup_dirs
load_conf
APPS="${APPS:-$(detect_apps | paste -sd' ' -)}"
WEBSHELL_RE='(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|str_rot13)|base64_decode\s*\(\s*\$_|Runtime\.getRuntime\(\)\.exec|cmd\.exe|/bin/sh -i'

http_get() {   # http_get URL [user:pass] -> "CODE BODY..."
    curl -s -k -m 6 ${2:+-u "$2"} -w '\n%{http_code}' "$1" 2>/dev/null
}

step_info() {
    local a
    section "WHAT IS RUNNING"
    if [[ -z "$APPS" ]]
    then
        flag "no known streaming app found - look at the listening ports below and the scoring page"
    fi
    for a in $APPS
    do
        printf "  ${bold}%s${reset}  unit=%s (%s, %s)  ports=%s\n" "$a" "$(app_field "$a" 2)" \
            "$(systemctl is-active "$(app_field "$a" 2)" 2>/dev/null)" "$(systemctl is-enabled "$(app_field "$a" 2)" 2>/dev/null)" "$(app_ports "$a")"
        printf "      files: %s\n" "$(app_paths "$a" | paste -sd' ' -)"
    done
    printf "\n  listening on the network:\n"
    listeners | while read -r proto port addr name pid
    do
        is_local_addr "$addr" || printf "      %-4s %-6s %-16s %s\n" "$proto" "$port" "$name" "$(ps -o user= -p "$pid" 2>/dev/null)"
    done
    docker_app_warning
}

check_process() {   # the app should not run as root
    local a="$1" re user
    re=$(app_field "$a" 3)
    for pid in $(pgrep "$re")
    do
        user=$(ps -o user= -p "$pid" | tr -d ' ')
        if [[ "$user" == "root" && "$a" != "nginx" && "$a" != "httpd" ]]
        then
            flag "$a (pid $pid) runs as ROOT - a bug in it = root on the box"
            todo "$a runs as root - set User= in its systemd unit (systemctl edit $(app_field "$a" 2)) to its own user"
        fi
    done
    [[ "$a" =~ ^(nginx|httpd)$ ]] && ps -eo user=,comm= | awk -v a="$a" '$2 == a && $1 == "root"' | head -n 1 | grep -q . \
        && explain "($a's master process runs as root on purpose; the workers must not)"
    if have getenforce && [[ "$(getenforce)" != "Disabled" ]]
    then
        printf "      SELinux label: %s\n" "$(ps -eZ 2>/dev/null | awk -v re="$re" '$NF ~ re {print $1; exit}')"
        ps -eZ 2>/dev/null | awk -v re="$re" '$NF ~ re {print $1}' | grep -q unconfined_service_t \
            && caution "$a runs unconfined (SELinux does not protect it) - normal for apps installed from tarballs"
    fi
}

jellyfin_like() {   # jellyfin_like NAME PORT DATA_DB
    local a="$1" port="$2" db="$3" info
    info=$(http_get "http://127.0.0.1:$port/System/Info/Public")
    printf "      /System/Info/Public: %s\n" "$(head -n 1 <<< "$info" | cut -c1-160)"
    if grep -q '"StartupWizardCompleted":false' <<< "$info"
    then
        flag "$a's FIRST-RUN WIZARD IS OPEN: the first person to open http://<sylvester>:$port creates the ADMIN"
        explain "Do it yourself NOW in a browser: create the admin with a strong password (team sheet)."
        todo "Finish the $a setup wizard at http://192.168.220.69:$port (it lets anyone create the admin)"
    fi
    printf "      users shown on the login page: %s\n" "$(http_get "http://127.0.0.1:$port/Users/Public" | grep -oE '"Name":"[^"]*"' | cut -d'"' -f4 | paste -sd' ' -)"
    if [[ -f "$db" ]] && have sqlite3
    then
        printf "      users (from %s):\n" "$db"
        sqlite3 -readonly "$db" "SELECT Username, CASE WHEN Password IS NULL OR Password = '' THEN 'NO-PASSWORD' ELSE 'password' END,
            CASE WHEN EXISTS (SELECT 1 FROM Permissions p WHERE p.UserId = Users.Id AND p.Kind = 0 AND p.Value = 1) THEN 'ADMIN' ELSE '' END
            FROM Users" 2>/dev/null | sed 's/|/  /g; s/^/        /'
        sqlite3 -readonly "$db" "SELECT Username FROM Users WHERE Password IS NULL OR Password = ''" 2>/dev/null | while read -r u
        do
            flag "$a user '$u' has NO password"
            todo "Set a password for $a user '$u' (Dashboard -> Users -> $u -> Password)"
        done
        printf "      API keys (each one = full admin access, no password):\n"
        sqlite3 -readonly "$db" "SELECT Name, DateCreated FROM ApiKeys" 2>/dev/null | sed 's/|/  created /; s/^/        /'
        [[ -n "$(sqlite3 -readonly "$db" 'SELECT 1 FROM ApiKeys LIMIT 1' 2>/dev/null)" ]] \
            && todo "Review $a API keys (Dashboard -> API Keys) - revoke any the team didn't make"
        explain "Unknown ADMIN users: Dashboard -> Users -> untick 'Allow this user to manage the server' or disable them."
        todo "Check $a admin users in Dashboard -> Users; disable unknown ones (not the scorer's)"
    else
        explain "(sqlite3 not installed or $db missing - check users in the web Dashboard -> Users)"
    fi
}

step_app() {
    local a d f conf
    section "THE STREAMING APP"
    for a in $APPS
    do
        step "$a"
        check_process "$a"
        case "$a" in
            jellyfin) jellyfin_like jellyfin "$(app_ports jellyfin | grep -oE '^[0-9]+' | head -n 1 || echo 8096)" /var/lib/jellyfin/data/jellyfin.db
                      d=/var/lib/jellyfin/plugins ;;
            emby)     jellyfin_like emby 8096 /var/lib/emby/data/users.db; d=/var/lib/emby/plugins ;;
            plex)
                conf=$(find /var/lib/plexmediaserver -name Preferences.xml 2>/dev/null | head -n 1)
                if [[ -f "$conf" ]]
                then
                    printf "      %s\n" "$conf"
                    grep -q 'PlexOnlineToken=' "$conf" || flag "Plex is NOT claimed - anyone reaching :32400/web can claim it as THEIR server"
                    grep -oE 'allowedNetworks="[^"]*"' "$conf" | grep -qE '0\.0\.0\.0|/0"' \
                        && flag "Plex allowedNetworks lets the whole internet in WITHOUT a login: $(grep -oE 'allowedNetworks="[^"]*"' "$conf")"
                    grep -oE '(allowedNetworks|secureConnections|customConnections)="[^"]*"' "$conf" | sed 's/^/      /'
                    todo "Plex: Settings -> Network: clear 'List of IP addresses allowed without auth' unless the scorer needs it"
                fi
                d="/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/Plug-ins" ;;
            owncast)
                for p in $(app_ports owncast | grep -oE '[0-9]+')
                do
                    if [[ "$(http_get "http://127.0.0.1:$p/api/admin/status" admin:abc123 | tail -n 1)" == "200" ]]
                    then
                        flag "Owncast admin password is the DEFAULT (admin / abc123) on port $p"
                        explain "Change it: http://<sylvester>:$p/admin -> Configuration -> Server Setup -> Admin Password"
                        explain "(it is also the stream key in older Owncast - tell whoever pushes the stream)"
                        todo "Change the Owncast admin password (still abc123) at :$p/admin"
                    fi
                done ;;
            mediamtx)
                for f in $(app_paths mediamtx); do [[ -f "$f" ]] && conf="$f"; [[ -d "$f" && -f "$f/mediamtx.yml" ]] && conf="$f/mediamtx.yml"; done
                if [[ -f "$conf" ]]
                then
                    printf "      %s\n" "$conf"
                    grep -nE '^\s*(api|apiAddress|metrics|pprof|authMethod|- user|  pass|publishUser|publishPass|readUser):' "$conf" | sed 's/^/      /'
                    grep -qE '^\s*- user: any' "$conf" && grep -A4 -E '^\s*- user: any' "$conf" | grep -q 'action: publish' \
                        && flag "MediaMTX lets ANYONE publish (user: any + publish) - red team can replace the stream"
                    grep -qE '^api: (yes|true)' "$conf" && flag "MediaMTX control API is ON ($(grep -E '^apiAddress' "$conf")) - lock it to 127.0.0.1"
                    todo "MediaMTX: give 'publish' a user+password in $conf, apiAddress: 127.0.0.1:9997, then restart mediamtx"
                fi ;;
            nginx|httpd)
                conf=$( [[ "$a" == nginx ]] && echo /etc/nginx || echo /etc/httpd )
                grep -rnE 'allow +publish +all|autoindex +on|Options .*Indexes|server_tokens +on' "$conf" 2>/dev/null | sed 's/^/      /'
                grep -rqE 'allow +publish +all' "$conf" 2>/dev/null && flag "rtmp 'allow publish all': ANYONE can push a stream (replace ours)"
                grep -rqE 'autoindex +on|Options .*Indexes' "$conf" 2>/dev/null && caution "directory listing is on - shows every file in that folder"
                if have nginx && [[ "$a" == nginx ]]; then nginx -t 2>&1 | tail -n 1 | sed 's/^/      config test: /'; fi
                if have apachectl && [[ "$a" == httpd ]]; then apachectl -t 2>&1 | tail -n 1 | sed 's/^/      config test: /'; fi ;;
        esac
        if [[ -n "$d" && -d "$d" ]]
        then
            printf "      plugins in %s:\n" "$d"
            ls -1 "$d" 2>/dev/null | sed 's/^/        /'
            explain "Plugins run inside the app. One you didn't install = backdoor. Remove from Dashboard -> Plugins."
            todo "Check $a plugins in $d - remove any the team doesn't recognise"
        fi
        d=""
    done
}

step_files() {
    local a p f
    section "APP FILES"
    explain "Config files anyone can change, and files changed in the last 2 days (what did red team touch?)."
    for a in $APPS
    do
        for p in $(app_paths "$a")
        do
            find "$p" -xdev \( -type f -o -type d \) -perm -o+w ! -type l 2>/dev/null | head -n 20 | while read -r f
            do
                flag "anyone can write $f"
                confirm_safe "Remove write-for-everyone from $f?" && chmod o-w "$f" && did "PERMISSIONS o-w on $f" "chmod o+w $f"
            done
            printf "\n  changed in the last 2 days under %s (newest first):\n" "$p"
            find "$p" -xdev -type f -mtime -2 \
                 -not -name '*.log' -not -path '*/cache/*' -not -path '*/transcodes/*' -not -path '*/metadata/*' -not -name '*.ts' \
                 -printf '%TY-%Tm-%Td %TH:%TM  %u  %p\n' 2>/dev/null | sort -r | head -n 15 | sed 's/^/      /'
        done
    done
    step "App configs the scoring check might depend on - back them up first:  ./backup.sh"
}

step_webshells() {
    local roots f
    section "WEBSHELLS"
    explain "A webshell is a script dropped in a web folder that runs commands from a URL."
    roots="/var/www /usr/share/nginx /srv /opt $(for a in $APPS; do app_paths "$a"; done | paste -sd' ' -)"
    find $roots -xdev -type f \( -name '*.php*' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.jspx' -o -name '*.asp*' \
         -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' -o -name '*.sh' \) -size -2M 2>/dev/null | sort -u > "$SYL_TMP/scripts"
    printf "  %s script files in web/app folders\n" "$(wc -l < "$SYL_TMP/scripts")"
    : > "$SYL_TMP/shells"
    while read -r f
    do
        grep -lqE "$WEBSHELL_RE" "$f" 2>/dev/null && echo "$f" >> "$SYL_TMP/shells"
    done < "$SYL_TMP/scripts"
    [[ -s "$SYL_TMP/shells" ]] || ok "no webshell patterns found"
    while read -r f
    do
        printf "\n  ${warn}%s${reset}  (%s, changed %s)\n" "$f" "$(stat -c %U "$f")" "$(date -r "$f" '+%b %d %H:%M')"
        grep -nE "$WEBSHELL_RE" "$f" | head -n 3 | cut -c1-160 | sed 's/^/      | /'
        flag "webshell pattern in $f"
        if is_owned "$f"
        then
            confirm_risky "Quarantine $f (a PACKAGE installed it - may be a false alarm)?" && quarantine "$f" "webshell pattern"
        else
            confirm_safe "Quarantine $f?" && quarantine "$f" "webshell"
        fi
    done < "$SYL_TMP/shells"
}

step_connections() {
    local a p
    section "WHO IS WATCHING / CONNECTED"
    for a in $APPS
    do
        for p in $(app_ports "$a" | grep -oE '[0-9]+(/tcp)' | cut -d/ -f1)
        do
            printf "  %s port %s:\n" "$a" "$p"
            ss -Htn state established "( sport = :$p )" 2>/dev/null | awk '{print $4}' | sed 's/:[0-9]*$//; s/^\[//; s/\]$//; s/^::ffff://' \
                | sort | uniq -c | sort -rn | head -n 10 | sed 's/^/      /'
        done
    done
}

banner "stream-lockdown.sh  -  the streaming app on sylvester"
printf "  apps found: %s\n" "${APPS:-NONE}"
[[ "$RUN" == "$STEPS" ]] && todo_reset
log_action "START stream-lockdown mode=$MODE steps=$RUN apps=$APPS"
for s in $RUN
do
    "step_$s"
done
log_action "END stream-lockdown"
printf "\n${bold}${info}stream-lockdown finished.${reset}  changes: %s   TODO: %s\n" "$ACTIONS" "$TODO_FILE"
exit 0
