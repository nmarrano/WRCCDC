#!/bin/bash
#
# redis-lockdown.sh
#
# Locks down Redis on marvin. Redis attacks are fast: with no password, anyone who
# reaches port 6379 can read every key, wipe everything, make Redis write a file
# anywhere it can (an SSH key into /root/.ssh, a cron job), turn it into a replica
# of THEIR server, or load a module that runs commands.
#
# What it does: makes its own admin login (saved in secrets.conf), takes the
# dangerous commands (CONFIG, MODULE, DEBUG, REPLICAOF, ACL, FLUSHALL, SHUTDOWN,
# MONITOR) away from the default user the apps use, disables unknown ACL users,
# undoes red team's replica / file-location / module tricks, and saves it all.
#
# It NEVER changes the password the apps use (that breaks them) - the 'rotate'
# step does that, by hand, together with the app owners.
#
# Usage:
#   sudo ./redis-lockdown.sh               every step, asks before each change
#   sudo ./redis-lockdown.sh --auto        safe fixes by itself, risky ones -> TODO.txt
#   sudo ./redis-lockdown.sh --audit       look only, change nothing
#   sudo ./redis-lockdown.sh STEP...       only these steps:
#        info admin users commands tricks files connections
#   sudo ./redis-lockdown.sh rotate        set/change the password the apps use (coordinate first!)
#   sudo ./redis-lockdown.sh seen [MIN]    watch clients for MIN minutes (default 5)
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/db.sh"

STEPS="info admin users commands tricks files connections"
RUN=""; EXTRA=""
for a in "$@"
do
    case "$a" in
        --auto) MODE=auto ;;
        --audit|--dry-run) MODE=audit ;;
        -h|--help) usage_from_header; exit 0 ;;
        rotate|seen) RUN="$a" ;;
        [0-9]*) EXTRA="$a" ;;
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

# commands an app never needs, but an attacker loves
DENY_CMDS="config module debug replicaof slaveof shutdown acl flushall monitor failover"
REDIS_DIR_DEFAULT=/var/lib/redis

rconf() { rq CONFIG GET "$1" | sed -n 2p; }   # value of one CONFIG setting
ok_reply() { [[ "$1" == "OK" ]]; }

save_config() {   # make live changes survive a restart
    local out aclfile
    aclfile=$(rconf aclfile)
    if [[ -n "$aclfile" ]]
    then
        out=$(rq ACL SAVE)
        ok_reply "$out" && did "SAVED ACL users to $aclfile" || flag "ACL SAVE failed: $out"
    fi
    out=$(rq CONFIG REWRITE)
    if ok_reply "$out"
    then
        did "SAVED live settings into $(redis_conf_file) (CONFIG REWRITE)"
    else
        flag "CONFIG REWRITE failed: $out - the changes are live but are lost if Redis restarts"
        todo "Redis CONFIG REWRITE failed - re-apply the Redis lockdown after any Redis restart"
    fi
}

step_info() {
    local k
    section "WHAT IS RUNNING"
    printf "  logged in as: %s\n\n" "$REDIS_AS"
    rq INFO server | grep -E '^(redis_version|os|tcp_port|uptime_in_seconds|config_file|executable):' | tr -d '\r' | sed 's/^/      /'
    rq INFO replication | grep -E '^(role|master_host|master_port|connected_slaves):' | tr -d '\r' | sed 's/^/      /'
    for k in bind port protected-mode dir dbfilename aclfile enable-protected-configs enable-debug-command enable-module-command maxclients
    do
        printf "      %-26s %s\n" "$k" "$(rconf "$k")"
    done
    printf "      %-26s %s\n" "requirepass" "$( [[ -n "$(rconf requirepass)" ]] && echo '(set)' || echo '(EMPTY)')"
    case "$(rconf bind)" in
        *0.0.0.0*|"*"*|"* -::*") caution "Redis listens on every address - fine if apps on other boxes use it" ;;
        *127.0.0.1*) explain "Redis only listens locally: only programs ON marvin can use it." ;;
    esac
    for k in enable-protected-configs enable-debug-command enable-module-command
    do
        if [[ "$(rconf "$k")" =~ ^(yes|local)$ ]]
        then
            flag "$k = $(rconf "$k") - Redis 7 has this OFF by default; it lets CONFIG/DEBUG/MODULE do dangerous things"
            explain "It can only be changed in $(redis_conf_file) + a Redis restart."
            todo "Set $k no in $(redis_conf_file), then: systemctl restart redis-server"
        fi
    done
    docker_db_warning
}

step_admin() {
    local pw out
    section "MARVIN'S OWN ADMIN LOGIN"
    explain "To take dangerous commands away from the default user (the one apps use), this script"
    explain "first needs its OWN admin user. It is called '${REDIS_ADMIN_USER:-marvin}' and its password is saved"
    explain "in $SECRETS (root only). Nobody else needs it."
    if [[ -n "$REDIS_ADMIN_PASS" && "$REDIS_USER" == "${REDIS_ADMIN_USER:-marvin}" ]]
    then
        ok "already logged in as the marvin admin user"
        return
    fi
    [[ "$(rq ACL WHOAMI 2>&1)" == *"ERR"* ]] && { caution "this Redis has no ACLs (older than 6) - skipping"; return; }
    confirm_safe "Create the Redis admin user 'marvin'?" || return
    pw=$(gen_password 24)
    out=$(rq ACL SETUSER marvin on ">$pw" '~*' '&*' +@all)
    if ok_reply "$out"
    then
        set_secret REDIS_ADMIN_USER marvin
        set_secret REDIS_ADMIN_PASS "$pw"
        REDIS_ADMIN_USER=marvin; REDIS_ADMIN_PASS="$pw"; REDIS_USER=marvin; REDIS_PASS="$pw"
        [[ "$(rq PING)" == "PONG" ]] && did "CREATED Redis admin user 'marvin' (password in $SECRETS)" "ACL DELUSER marvin"
        save_config
    else
        flag "could not create the admin user: $out"
    fi
}

step_users() {
    local line name rules
    section "ACL USERS"
    explain "Apps almost always log in as 'default'. Extra users with +@all / allcommands are how"
    explain "red team keeps admin access after you set a password. Unknown ones are turned OFF"
    explain "(ACL SETUSER name off), not deleted."
    redis_seen_update
    rq ACL LIST > "$MARVIN_TMP/acl"
    sed 's/^/      /; s/#[0-9a-f]\{64\}/#<hash>/g' "$MARVIN_TMP/acl"
    printf "\n"
    explain "Seen connecting: $(awk '{print $1 "(" $2 ")"}' "$SEEN_DIR/redis.txt" 2>/dev/null | sort -u | paste -sd' ' -)"
    while read -r line
    do
        name=$(awk '{print $2}' <<< "$line")
        rules=${line#user $name }
        if [[ "$name" == "default" ]]
        then
            [[ " $rules " == *" on "* && " $rules " == *" nopass "* ]] \
                && flag "the default user needs NO password - anyone who reaches port $REDIS_PORT is in (fix: rotate step, with the app owners)" \
                && todo "Redis default user has no password: set one with './redis-lockdown.sh rotate' together with every app owner"
            continue
        fi
        [[ "$name" == "${REDIS_ADMIN_USER:-marvin}" ]] && continue
        [[ " $rules " == *" off "* ]] && continue
        if is_protected_db redis "$name"
        then
            caution "user '$name' is in use (seen from $(seen_from redis "$name")) - left alone"
            continue
        fi
        if [[ "$rules" =~ (\+@all|allcommands|\+@dangerous|\+@admin|\+config|\+module) ]]
        then
            flag "user '$name' has admin commands and nobody was seen using it"
            confirm_safe "Turn OFF Redis user '$name' (and kick its connections)?" && redis_off "$name"
        else
            caution "user '$name' wasn't seen connecting"
            confirm_risky "Turn OFF Redis user '$name'?" && redis_off "$name"
        fi
    done < "$MARVIN_TMP/acl"
}

redis_off() {
    local out
    out=$(rq ACL SETUSER "$1" off)
    if ok_reply "$out"
    then
        rq CLIENT KILL USER "$1" >/dev/null
        did "DISABLED Redis user '$1' and kicked its connections" "ACL SETUSER $1 on"
        save_config
    else
        flag "could not disable '$1': $out"
    fi
}

step_commands() {
    local c denied="" out
    section "TAKE DANGEROUS COMMANDS AWAY FROM THE APPS' USER"
    explain "The default user keeps every normal command (GET/SET/HSET/LPUSH/EXPIRE/INFO/CLIENT...),"
    explain "so apps keep working. It loses: ${DENY_CMDS// /, }."
    explain "Those are how red team writes files (CONFIG SET dir), loads code (MODULE), steals data"
    explain "(REPLICAOF, MONITOR), wipes everything (FLUSHALL) or creates users (ACL)."
    [[ "$REDIS_USER" == "${REDIS_ADMIN_USER:-marvin}" ]] || { caution "needs the marvin admin user first (admin step) - skipped"; return; }
    for c in $DENY_CMDS
    do
        [[ -n "$(rq COMMAND INFO "$c" | head -n 1)" ]] || continue      # not in this Redis version
        rq ACL GETUSER default | grep -qiE "(^|[ ])-$c([ ]|$)" || denied+="-$c "
    done
    if [[ -z "$denied" ]]
    then
        ok "the default user already can't use them"
        return
    fi
    confirm_safe "Remove those commands from the default user?" || return
    out=$(rq ACL SETUSER default $denied)
    if ok_reply "$out"
    then
        did "REMOVED commands from Redis default user: $denied" "ACL SETUSER default ${denied//-/+}"
        save_config
        explain "If an app now logs 'NOPERM this user has no permissions to run the ... command',"
        explain "give that ONE command back:  redis-cli --user marvin --askpass ACL SETUSER default +<command>"
    else
        flag "ACL SETUSER failed: $out"
    fi
}

step_tricks() {
    local role mhost d f mods m
    section "RED TEAM TRICKS: rogue replica, file locations, modules"

    step "Is Redis a replica of someone else's server?"
    role=$(rq INFO replication | awk -F: '/^role:/ {print $2}' | tr -d '\r')
    mhost=$(rq INFO replication | awk -F: '/^master_host:/ {print $2}' | tr -d '\r')
    if [[ "$role" == "slave" ]]
    then
        flag "Redis is a REPLICA of $mhost:$(rq INFO replication | awk -F: '/^master_port:/ {print $2}' | tr -d '\r')"
        explain "Red team points Redis at THEIR server: it copies their data over ours, and their 'master'"
        explain "can push a module that runs commands on marvin. A competition box has no replica setup."
        confirm_safe "Stop replicating (REPLICAOF NO ONE)?" \
            && ok_reply "$(rq REPLICAOF NO ONE)" && did "REPLICAOF NO ONE (was a replica of $mhost)" && save_config
    else
        ok "role = ${role:-?} (not a replica)"
    fi

    step "Where Redis saves its file"
    d=$(rconf dir); f=$(rconf dbfilename)
    printf "      dir = %s   dbfilename = %s\n" "$d" "$f"
    if [[ "$d" != "$REDIS_DIR_DEFAULT" || ! "$f" =~ ^(dump\.rdb|.*\.rdb)$ ]]
    then
        flag "Redis saves to $d/$f - red team sets this to /root/.ssh/authorized_keys or a cron folder"
        if confirm_safe "Put it back to $REDIS_DIR_DEFAULT/dump.rdb?"
        then
            if ok_reply "$(rq CONFIG SET dir "$REDIS_DIR_DEFAULT")" && ok_reply "$(rq CONFIG SET dbfilename dump.rdb)"
            then
                did "Redis dir/dbfilename reset to $REDIS_DIR_DEFAULT/dump.rdb (was $d/$f)"
                save_config
            else
                flag "CONFIG SET refused (protected config) - fix 'dir' and 'dbfilename' in $(redis_conf_file) and restart Redis"
                todo "Fix Redis dir/dbfilename in $(redis_conf_file) (now $d/$f) and restart redis-server"
            fi
        fi
        [[ -f "$d/$f" && "$d" != "$REDIS_DIR_DEFAULT" ]] && { confirm_safe "Quarantine $d/$f?" && quarantine "$d/$f" "file written by Redis SAVE"; }
    else
        ok "saves to $d/$f (normal)"
    fi

    step "Loaded modules"
    mods=$(rq MODULE LIST 2>&1)
    if [[ -z "$mods" || "$mods" == *"ERR"* || "$mods" == *"NOPERM"* ]]
    then
        ok "no modules loaded"
    else
        printf '%s\n' "$mods" | sed 's/^/      /'
        for m in $(printf '%s\n' "$mods" | awk 'prev == "name" {print} {prev = $0}')
        do
            flag "module '$m' is loaded - Ubuntu's Redis ships none; red team uses them to run commands"
            confirm_safe "Unload module '$m'?" && ok_reply "$(rq MODULE UNLOAD "$m")" && did "UNLOADED Redis module $m"
        done
    fi
    if grep -nE '^\s*loadmodule' "$(redis_conf_file)" 2>/dev/null
    then
        flag "redis.conf loads a module at every start (above)"
        todo "Remove the loadmodule line(s) from $(redis_conf_file)"
    fi
}

step_files() {
    local f
    section "FILES ON THE BOX"
    step "Files written BY Redis outside its folders"
    files_written_by redis '^(/var/lib/redis|/var/log/redis|/run/redis|/var/run/redis|/etc/redis)/' > "$MARVIN_TMP/rfiles"
    [[ -s "$MARVIN_TMP/rfiles" ]] || ok "none"
    while read -r f
    do
        flag "file owned by redis: $f"
        confirm_safe "Quarantine $f?" && quarantine "$f" "file written by Redis"
    done < "$MARVIN_TMP/rfiles"

    step "Redis dump files dropped where they get executed or read as keys"
    for f in $(grep -rlsa '^REDIS00' /root/.ssh /home/*/.ssh /var/lib/postgresql/.ssh /var/spool/cron /etc/cron.d /etc/cron.hourly /var/www /tmp 2>/dev/null)
    do
        flag "$f is a Redis dump (classic 'write an SSH key / cron job with Redis' attack)"
        confirm_safe "Quarantine $f?" && quarantine "$f" "Redis dump written as a key/cron file"
    done
    ok "checked .ssh, cron and web folders for Redis dumps"
    if [[ -f "$(redis_conf_file)" && "$(stat -c %a "$(redis_conf_file)")" =~ [1-7]$ ]]
    then
        flag "$(redis_conf_file) can be read by everyone and may hold passwords"
        confirm_safe "chmod o-rwx $(redis_conf_file)?" && chmod o-rwx "$(redis_conf_file)" && did "PERMISSIONS o-rwx on $(redis_conf_file)"
    fi
    for f in /root/.rediscli_history /home/*/.rediscli_history
    do
        [[ -s "$f" ]] && caution "$f exists ($(wc -l < "$f") lines) - may hold passwords (AUTH ...)"
    done
}

step_connections() {
    section "LIVE CONNECTIONS"
    redis_seen_update
    redis_sessions | sed 's/^/  /'
    explain "Users seen connecting so far (they are protected):"
    awk '{printf "      %-20s from %-18s first seen %s\n", $1, $2, $3}' "$SEEN_DIR/redis.txt" 2>/dev/null
}

step_seen() {
    local mins="${EXTRA:-5}" end before
    section "LEARNING WHICH USERS ARE USED (${mins} min)"
    end=$(( $(date +%s) + mins * 60 ))
    while (( $(date +%s) < end ))
    do
        before=$(cat "$SEEN_DIR/redis.txt" 2>/dev/null)
        redis_seen_update
        diff <(printf '%s\n' "$before") "$SEEN_DIR/redis.txt" 2>/dev/null | sed -n 's/^> /  NEW: /p'
        sleep 3
    done
    printf "\n"; awk '{printf "  %-20s from %-18s first seen %s\n", $1, $2, $3}' "$SEEN_DIR/redis.txt" 2>/dev/null
}

step_rotate() {
    local u newpw out
    section "SET / CHANGE A REDIS PASSWORD"
    explain "Apps log in as 'default' with the password in their config (REDIS_PASSWORD, redis.password,"
    explain "REDIS_URL=redis://:PASSWORD@marvin...). Tell the app owners FIRST - every app that uses"
    explain "Redis fails until its config has the new password. If the scorer checks Redis, file a PCR."
    [[ "$MODE" == "interactive" ]] || { caution "rotate only works interactively"; return; }
    rq ACL USERS | sed 's/^/      /'
    ask_text "User to change [default]: "; u="${REPLY:-default}"
    newpw=$(gen_password 20)
    ask_text "New password for '$u' (Enter = $newpw): "; newpw="${REPLY:-$newpw}"
    confirm_risky "Change the password of Redis user '$u' NOW (the app owners are ready)?" || return
    # resetpass + the new one: old passwords stop working
    out=$(rq ACL SETUSER "$u" on resetpass ">$newpw")
    if ok_reply "$out"
    then
        did "PASSWORD changed for Redis user '$u'"
        save_config
        printf "\n  ${bold}new password for Redis user '%s': ${info}%s${reset}\n" "$u" "$newpw"
        printf "  -> team sheet + every app config that uses Redis\n"
        todo "Make sure every app using Redis user '$u' has the new password (changed $(date +%H:%M))"
    else
        flag "password change failed: $out"
    fi
}

banner "redis-lockdown.sh  -  Redis on marvin"
if ! redis_connect
then
    flag "Can't talk to Redis on 127.0.0.1:${REDIS_PORT:-6379}. Running?  systemctl status redis-server"
    exit 1
fi
printf "  Redis %s on port %s, logged in as %s\n" "$(rq INFO server | awk -F: '/^redis_version:/ {print $2}' | tr -d '\r')" "$REDIS_PORT" "$REDIS_AS"
[[ "$RUN" == "$STEPS" ]] && todo_reset
log_action "START redis-lockdown mode=$MODE steps=$RUN"
for s in $RUN
do
    "step_$s"
done
log_action "END redis-lockdown"
printf "\n${bold}${info}redis-lockdown finished.${reset}  changes: %s   TODO: %s\n" "$ACTIONS" "$TODO_FILE"
exit 0
