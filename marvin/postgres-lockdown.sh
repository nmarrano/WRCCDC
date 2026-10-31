#!/bin/bash
#
# postgres-lockdown.sh
#
# Locks down PostgreSQL on marvin: pg_hba.conf (who may connect, from where, with
# or without a password), roles (superusers, roles that may run OS commands or
# read server files), and persistence hidden INSIDE the database (archive_command,
# preload libraries, C functions, functions that run COPY ... PROGRAM, event triggers).
#
# It NEVER drops a role and never locks:
#   - roles in PROTECTED_DB_USERS (marvin.conf): the scorer's and the apps' logins
#   - roles SEEN logging in (apps + scorer), kept in /root/marvin-data/seen/postgres.txt
#   - postgres itself (this script logs in as it, over the local socket)
# Unknown roles are disabled with NOLOGIN - the undo is printed.
# Passwords are only changed by the 'rotate' step, which you run by hand.
#
# Usage:
#   sudo ./postgres-lockdown.sh               every step, asks before each change
#   sudo ./postgres-lockdown.sh --auto        safe fixes by itself, risky ones -> TODO.txt
#   sudo ./postgres-lockdown.sh --audit       look only, change nothing
#   sudo ./postgres-lockdown.sh STEP...       only these steps:
#        info logging hba roles privileges persistence files connections
#   sudo ./postgres-lockdown.sh rotate        change one role's password (coordinate first!)
#   sudo ./postgres-lockdown.sh seen [MIN]    watch logins for MIN minutes (default 5)
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/db.sh"

STEPS="info logging hba roles privileges persistence files connections"
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

SUSPICIOUS_FN='COPY .*PROGRAM|pg_read_file|pg_read_binary_file|pg_ls_dir|lo_import|lo_export|dblink|ALTER +ROLE|CREATE +ROLE|CREATE +USER|GRANT +|pg_execute_server_program|/bin/|/tmp/'
BAD_CMD_RE='bash|sh -c|/bin/sh|curl|wget|nc |ncat|socat|python|perl|/tmp/|/dev/tcp|base64'

run_sql() {   # run_sql "SQL" "WHAT HAPPENED" "UNDO" [DB]
    local out
    if out=$(pgq_try "$1" "${4:-postgres}")
    then
        did "$2" "$3"
    else
        flag "FAILED: $1"
        printf "      %s\n" "$out"
        return 1
    fi
}

reload_pg() { pgq "SELECT pg_reload_conf()" >/dev/null && log_action "RELOADED postgres config"; }

hba_file() { pgq "SHOW hba_file"; }

hba_errors() { pgq "SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL"; }

# edit pg_hba.conf safely: backup, change, reload, and put the backup back if PG rejects it
hba_apply() {   # hba_apply NEW_FILE "WHAT"
    local f
    f=$(hba_file)
    cp "$f" "$MARVIN_TMP/hba.before"
    backup_file "$f"
    cat "$1" > "$f"
    reload_pg
    if [[ "$(hba_errors)" != "0" ]]
    then
        flag "PostgreSQL rejected the new pg_hba.conf - putting the old one back"
        pgq "SELECT line_number, error FROM pg_hba_file_rules WHERE error IS NOT NULL" | sed 's/^/      /'
        cat "$MARVIN_TMP/hba.before" > "$f"
        reload_pg
        return 1
    fi
    did "PG_HBA $2" "copy back the file saved in $EVIDENCE/before-edit-*/ then: SELECT pg_reload_conf();"
}

step_info() {
    section "WHAT IS RUNNING"
    have pg_lsclusters && pg_lsclusters | sed 's/^/      /'
    printf "\n"
    pgq "SELECT name, setting FROM pg_settings WHERE name IN ('server_version','port','listen_addresses','data_directory',
         'config_file','hba_file','password_encryption','ssl','log_connections','log_statement','archive_mode','archive_command',
         'shared_preload_libraries','session_preload_libraries','local_preload_libraries','max_connections') ORDER BY 1" \
        | awk -F'\t' '{printf "      %-26s %s\n", $1, $2}'
    step "Settings changed from the defaults (and the file that set them)"
    pgq "SELECT name, left(setting, 60), COALESCE(sourcefile, source) FROM pg_settings
         WHERE source NOT IN ('default', 'override', 'client', 'session') ORDER BY 1" \
        | awk -F'\t' '{printf "      %-28s %-40s %s\n", $1, $2, $3}'
    case "$(pgq 'SHOW listen_addresses')" in
        localhost|127.0.0.1|"")
            caution "listen_addresses is local only: other boxes (apps, scorer) can NOT reach PostgreSQL."
            explain "If an app on another box uses it: listen_addresses = '*' in postgresql.conf, then restart." ;;
    esac
    docker_db_warning
}

step_logging() {
    section "CONNECTION LOGGING"
    explain "With log_connections on, every login (user + IP) is written to the log. That is how this"
    explain "script learns which roles the apps + scorer use, and it is evidence for incident reports."
    if [[ "$(pgq 'SHOW log_connections')" == "on" ]]
    then
        ok "log_connections is on"
    elif confirm_safe "Turn on log_connections + log_disconnections (reload, no restart)?"
    then
        run_sql "ALTER SYSTEM SET log_connections = on" "SET log_connections = on" "ALTER SYSTEM RESET log_connections;"
        run_sql "ALTER SYSTEM SET log_disconnections = on" "SET log_disconnections = on" "ALTER SYSTEM RESET log_disconnections;"
        reload_pg
    fi
    printf "      log file: %s\n" "$(pg_log_file)"
}

print_hba() {
    printf "  ${bold}%-5s %-10s %-14s %-14s %-20s %-14s %s${reset}\n" LINE TYPE DATABASE USER ADDRESS METHOD ERROR
    pgq "SELECT line_number, type, array_to_string(database, ','), array_to_string(user_name, ','),
                COALESCE(address, '') || COALESCE('/' || netmask, ''), COALESCE(auth_method, ''), COALESCE(error, '')
         FROM pg_hba_file_rules ORDER BY line_number" \
        | awk -F'\t' '{printf "  %-5s %-10s %-14s %-14s %-20s %-14s %s\n", $1, $2, $3, $4, ($5 == "" ? "-" : $5), $6, $7}'
}

step_hba() {
    local f ln typ dbs users addr method r supers block n nopw
    section "pg_hba.conf - WHO MAY CONNECT"
    f=$(hba_file)
    explain "$f is read top to bottom and the FIRST matching line wins."
    explain "trust = NO password at all. peer = local Linux user must match (safe). scram-sha-256 = password."
    print_hba
    printf "\n"

    while IFS=$'\t' read -r ln typ dbs users addr method
    do
        case "$method" in
            trust)
                if [[ "$typ" == "local" ]]
                then
                    flag "line $ln: local '$users' logins need NO password (any Linux user can become a DB superuser)"
                else
                    flag "line $ln: $typ from ${addr:-anywhere} as '$users' needs NO PASSWORD - anyone who reaches port $(pgq 'SHOW port') gets in"
                fi ;;
            password) caution "line $ln: 'password' sends passwords in plain text - use scram-sha-256" ;;
        esac
        [[ "$typ" != "local" && "$dbs" == "all" && "$users" == "all" && "$addr" =~ ^(0\.0\.0\.0/0|::/0|0\.0\.0\.0/0\.0\.0\.0|)$ ]] \
            && caution "line $ln: every database, every user, from ANYWHERE ($method)"
        [[ "$addr" == "-" ]] && addr=""
    done < <(pgq "SELECT line_number, type, array_to_string(database, ','), array_to_string(user_name, ','),
                         COALESCE(address || COALESCE('/' || netmask, ''), '-'), auth_method
                  FROM pg_hba_file_rules WHERE error IS NULL ORDER BY line_number")
    n=$(hba_errors)
    [[ "$n" != "0" ]] && flag "$n line(s) in pg_hba.conf have errors (shown above) - PostgreSQL ignores the whole file on restart!"

    step "Superusers must use a password over the network"
    explain "A superuser can run OS commands (COPY ... TO PROGRAM). This adds lines at the TOP of"
    explain "pg_hba.conf so superusers that no app/scorer was seen using need a password from the"
    explain "network. postgres has no password by default, so it simply can't log in remotely."
    supers=""
    for r in $(pgq "SELECT rolname FROM pg_roles WHERE rolsuper AND rolcanlogin ORDER BY 1")
    do
        if is_protected_db postgres "$r" && [[ "$(seen_from postgres "$r")" != "local" ]]
        then
            caution "superuser '$r' is in use (seen from: $(seen_from postgres "$r")) - not restricted, see the roles step"
            continue
        fi
        grep -qE "^host\s+all\s+\"?$r\"?\s+0\.0\.0\.0/0\s+scram-sha-256" "$f" && continue
        supers+="$r "
    done
    if [[ -n "$supers" ]]
    then
        printf "      will add for: %s\n" "$supers"
        if confirm_safe "Require a password for these superusers over the network?"
        then
            block="# --- added by marvin postgres-lockdown.sh $(date -Is): superusers need a password over the network ---"
            for r in $supers
            do
                block+=$'\n'"host    all    \"$r\"    0.0.0.0/0    scram-sha-256"$'\n'"host    all    \"$r\"    ::/0         scram-sha-256"
            done
            n=$(grep -nE '^\s*[^#[:space:]]' "$f" | head -n 1 | cut -d: -f1)
            { head -n $(( ${n:-1} - 1 )) "$f"; printf '%s\n# --- end marvin ---\n' "$block"; tail -n +"${n:-1}" "$f"; } > "$MARVIN_TMP/hba.new"
            hba_apply "$MARVIN_TMP/hba.new" "superusers ($supers) now need a password over the network"
        fi
    else
        ok "no unprotected superusers left open over the network"
    fi

    step "Replace every 'trust' with a password check"
    if [[ -n "$(pgq "SELECT 1 FROM pg_hba_file_rules WHERE auth_method = 'trust' AND type <> 'local' LIMIT 1")" ]]
    then
        nopw=$(pgq "SELECT rolname FROM pg_authid WHERE rolcanlogin AND rolpassword IS NULL AND rolname <> 'postgres' ORDER BY 1" | paste -sd' ' -)
        explain "After this, network logins need the role's real password. An app whose config has a WRONG"
        explain "password (it never mattered with trust!) will start failing - warn the box owners first."
        [[ -n "$nopw" ]] && caution "these login roles have NO password and could no longer log in over the network: $nopw"
        if confirm_risky "Change every network 'trust' line to scram-sha-256?"
        then
            cp "$f" "$MARVIN_TMP/hba.new"
            for ln in $(pgq "SELECT line_number FROM pg_hba_file_rules WHERE auth_method = 'trust' AND type <> 'local'")
            do
                sed -i -E "${ln}s/(\s)trust(\s|$)/\1scram-sha-256\2/" "$MARVIN_TMP/hba.new"
            done
            hba_apply "$MARVIN_TMP/hba.new" "network 'trust' lines changed to scram-sha-256"
        fi
    else
        ok "no network logins without a password"
    fi
    if [[ -n "$(pgq "SELECT 1 FROM pg_hba_file_rules WHERE auth_method = 'trust' AND type = 'local' LIMIT 1")" ]]
    then
        explain "Local 'trust' lets ANY Linux user on marvin (www-data, a red team shell...) log in as postgres."
        if confirm_risky "Change local 'trust' lines to peer (Linux user must match the role)?"
        then
            cp "$f" "$MARVIN_TMP/hba.new"
            for ln in $(pgq "SELECT line_number FROM pg_hba_file_rules WHERE auth_method = 'trust' AND type = 'local'")
            do
                sed -i -E "${ln}s/(\s)trust(\s|$)/\1peer\2/" "$MARVIN_TMP/hba.new"
            done
            hba_apply "$MARVIN_TMP/hba.new" "local 'trust' lines changed to peer"
        fi
    fi
    printf "\n"; print_hba
}

print_roles() {
    local r su login cr cdb pw member status
    printf "  ${bold}%-18s %-6s %-6s %-11s %-9s %-7s %-12s %s${reset}\n" ROLE SUPER LOGIN CREATEROLE CREATEDB PASSWD STATUS "MEMBER OF"
    while IFS=$'\t' read -r r su login cr cdb pw member
    do
        if [[ "$r" == "postgres" ]]
        then
            status="system"
        elif is_protected_db postgres "$r"
        then
            status="PROTECTED"
        else
            status="unknown"
        fi
        printf "  %-18s %-6s %-6s %-11s %-9s %-7s %-12s %s\n" "$r" "$su" "$login" "$cr" "$cdb" "$pw" "$status" "${member:--}"
    done < "$MARVIN_TMP/roles"
    explain "PROTECTED = in PROTECTED_DB_USERS or seen logging in."
    explain "Seen so far: $(awk '{print $1 "(" $2 ")"}' "$SEEN_DIR/postgres.txt" 2>/dev/null | sort -u | paste -sd' ' -)"
}

step_roles() {
    local r su login cr cdb pw member g owns
    section "ROLES"
    explain "Superusers can do anything, including running OS commands. pg_execute_server_program /"
    explain "pg_read_server_files / pg_write_server_files let a normal role do that too - apps never"
    explain "need them. Roles are disabled with NOLOGIN, never dropped."
    pg_seen_update
    pg_users > "$MARVIN_TMP/roles"
    print_roles
    while IFS=$'\t' read -r r su login cr cdb pw member
    do
        [[ "$r" == "postgres" ]] && continue
        if [[ "$su" == "t" ]]
        then
            flag "'$r' is a SUPERUSER"
            if is_protected_db postgres "$r"
            then
                explain "It is in use. If the app really needs superuser it breaks without it - apps almost never do."
                confirm_risky "Remove SUPERUSER from (in use) '$r'?" \
                    && run_sql "ALTER ROLE $(pg_ident "$r") NOSUPERUSER" "NOSUPERUSER for '$r'" "ALTER ROLE \"$r\" SUPERUSER;"
            else
                confirm_safe "Remove SUPERUSER from '$r'?" \
                    && run_sql "ALTER ROLE $(pg_ident "$r") NOSUPERUSER" "NOSUPERUSER for '$r'" "ALTER ROLE \"$r\" SUPERUSER;"
            fi
        fi
        for g in pg_execute_server_program pg_read_server_files pg_write_server_files
        do
            [[ ",$member," == *",$g,"* ]] || continue
            flag "'$r' is a member of $g"
            confirm_safe "REVOKE $g from '$r'?" \
                && run_sql "REVOKE $g FROM $(pg_ident "$r")" "REVOKED $g from '$r'" "GRANT $g TO \"$r\";"
        done
        if [[ "$cr" == "t" && "$su" != "t" ]] && ! is_protected_db postgres "$r"
        then
            flag "'$r' has CREATEROLE (can make new roles)"
            confirm_safe "Remove CREATEROLE from '$r'?" \
                && run_sql "ALTER ROLE $(pg_ident "$r") NOCREATEROLE" "NOCREATEROLE for '$r'" "ALTER ROLE \"$r\" CREATEROLE;"
        fi
        [[ "$login" == "t" ]] || continue
        is_protected_db postgres "$r" && continue
        owns=$(pgq "SELECT string_agg(datname, ',') FROM pg_database WHERE datdba = (SELECT oid FROM pg_roles WHERE rolname = $(pg_str "$r"))")
        if [[ -n "$owns" ]]
        then
            caution "'$r' owns database(s) $owns but wasn't seen logging in - probably an app that hasn't connected yet"
            continue
        fi
        caution "'$r' can log in, isn't protected and wasn't seen logging in (password: $pw)"
        confirm_risky "Disable (NOLOGIN) the unknown role '$r'?" && nologin_role "$r"
    done < "$MARVIN_TMP/roles"
}

nologin_role() {
    run_sql "ALTER ROLE $(pg_ident "$1") NOLOGIN" "NOLOGIN for role '$1'" "ALTER ROLE \"$1\" LOGIN;" || return
    pgq "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = $(pg_str "$1")" >/dev/null \
        && log_action "TERMINATED sessions of '$1'"
}

step_privileges() {
    local db owner acl roles r
    section "WHO MAY CONNECT TO EACH DATABASE"
    explain "By default EVERY role may connect to EVERY database (PUBLIC has CONNECT). Then one stolen"
    explain "app password reaches the other apps' data too (if their tables allow it)."
    while IFS=$'\t' read -r db owner acl
    do
        printf "  %-16s owner=%-12s %s\n" "$db" "$owner" "${acl:-(default: everyone may connect)}"
        [[ "$db" == "postgres" ]] && continue
        if [[ -z "$acl" || "$acl" == *"=Tc/"* || "$acl" == *"=c/"* || "$acl" == *"=CTc/"* ]]
        then
            roles="$owner $(awk '{print $1}' "$SEEN_DIR/postgres.txt" 2>/dev/null | sort -u | paste -sd' ' -) $PROTECTED_DB_USERS"
            roles=$(printf '%s\n' $roles | sort -u | paste -sd' ' -)
            if confirm_risky "Only let '$roles' connect to database '$db'?"
            then
                for r in $roles
                do
                    pgq "SELECT 1 FROM pg_roles WHERE rolname = $(pg_str "$r")" | grep -q 1 \
                        && run_sql "GRANT CONNECT ON DATABASE $(pg_ident "$db") TO $(pg_ident "$r")" "GRANTED CONNECT on $db to $r"
                done
                run_sql "REVOKE CONNECT ON DATABASE $(pg_ident "$db") FROM PUBLIC" "REVOKED CONNECT on $db from PUBLIC" "GRANT CONNECT ON DATABASE \"$db\" TO PUBLIC;"
            fi
        fi
    done < <(pgq "SELECT datname, pg_get_userbyid(datdba), COALESCE(array_to_string(datacl, ' '), '') FROM pg_database
                  WHERE datallowconn AND NOT datistemplate ORDER BY 1")
}

step_persistence() {
    local v db sig lang probin src name ev fn lib
    section "PERSISTENCE INSIDE THE DATABASE"
    explain "Things that make PostgreSQL run commands by itself: archive_command (runs a shell command),"
    explain "preload libraries, C functions from odd paths, functions using COPY ... PROGRAM, event triggers."

    step "archive_command and other commands PostgreSQL runs"
    for v in archive_command restore_command archive_cleanup_command recovery_end_command ssl_passphrase_command
    do
        # SHOW says "(disabled)" while archive_mode is off - read what the config files really say
        val=$(pgq "SELECT setting FROM pg_file_settings WHERE name = $(pg_str "$v") ORDER BY seqno DESC LIMIT 1")
        [[ -z "$val" ]] && val=$(pgq "SELECT setting FROM pg_settings WHERE name = $(pg_str "$v")")
        [[ -z "$val" || "$val" == "(disabled)" ]] && continue
        printf "      %s = %s   (archive_mode = %s)\n" "$v" "$val" "$(pgq 'SHOW archive_mode')"
        if grep -qiE "$BAD_CMD_RE" <<< "$val"
        then
            flag "$v runs a shell/download command: $val"
            confirm_safe "Reset $v?" && reset_setting "$v" "$val"
        else
            caution "$v is set - fine if it's a real backup command, otherwise reset it"
            confirm_risky "Reset $v ($val)?" && reset_setting "$v" "$val"
        fi
    done
    ok "command settings checked"

    step "Preloaded libraries"
    for v in shared_preload_libraries session_preload_libraries local_preload_libraries
    do
        val=$(pgq "SHOW $v")
        [[ -z "$val" ]] && continue
        printf "      %s = %s\n" "$v" "$val"
        if [[ "$val" == */* || "$v" != "shared_preload_libraries" ]]
        then
            flag "$v loads '$val' into PostgreSQL ($([[ "$val" == */* ]] && echo 'from a file path!' || echo 'into every new session'))"
            confirm_safe "Reset $v?" && reset_setting "$v" "$val"
        else
            caution "shared_preload_libraries = $val (extensions like pg_stat_statements are normal)"
        fi
    done
    printf "\n  postgresql.auto.conf (written by ALTER SYSTEM - it overrides postgresql.conf):\n"
    sed 's/^/      | /' "$(pgq 'SHOW data_directory')/postgresql.auto.conf" 2>/dev/null

    for db in $(pg_databases)
    do
        step "Database '$db': functions, languages, event triggers"
        pgq "SELECT lanname FROM pg_language WHERE NOT lanpltrusted AND lanname NOT IN ('internal', 'c')" "$db" | while read -r lang
        do
            flag "untrusted language $lang is installed in $db (functions in it can run OS code)"
            todo "Check untrusted language $lang in database $db - DROP EXTENSION it if no app uses it"
        done
        pgq "SELECT p.oid::regprocedure, l.lanname, COALESCE(NULLIF(p.probin, ''), '-'),
                    regexp_replace(left(p.prosrc, 400), '\s+', ' ', 'g')
             FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang
             WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND n.nspname NOT LIKE 'pg_toast%'
               AND ( (p.probin IS NOT NULL AND p.probin NOT LIKE '\$libdir%')
                     OR p.prosrc ~* $(pg_str "$SUSPICIOUS_FN")
                     OR l.lanname IN ('plpython3u', 'plpythonu', 'plperlu', 'pltclu', 'plsh') )" "$db" > "$MARVIN_TMP/fns"
        while IFS=$'\t' read -r sig lang probin src
        do
            [[ "$probin" == "-" ]] && probin=""
            printf "\n  ${warn}%s.%s${reset}  language=%s %s\n      | %s\n" "$db" "$sig" "$lang" "${probin:+library=$probin}" "${src:0:200}"
            flag "function $db.$sig runs OS commands / reads files / loads an odd library"
            confirm_safe "DROP FUNCTION $sig in $db (definition saved first; CASCADE also drops triggers using it)?" \
                && drop_function "$db" "$sig"
        done < "$MARVIN_TMP/fns"
        while IFS=$'\t' read -r ev fn
        do
            printf "\n  ${warn}event trigger %s.%s${reset} -> %s\n" "$db" "$ev" "$fn"
            flag "event trigger $ev in $db runs $fn on every schema change"
            explain "Extensions sometimes use these; red team uses them to re-create backdoors."
            confirm_risky "DROP EVENT TRIGGER $ev in $db?" \
                && run_sql "DROP EVENT TRIGGER $(pg_ident "$ev")" "DROPPED event trigger $ev in $db" "" "$db"
        done < <(pgq "SELECT evtname, evtfoid::regproc FROM pg_event_trigger" "$db")
    done
}

reset_setting() {   # reset_setting NAME OLD_VALUE
    local conf
    run_sql "ALTER SYSTEM RESET $1" "RESET $1 (was: $2)" "ALTER SYSTEM SET $1 = '$2';"
    conf=$(pgq 'SHOW config_file')
    if grep -qE "^\s*$1\s*=" "$conf"
    then
        backup_file "$conf"
        sed -i -E "s/^(\s*$1\s*=.*)/#marvin# \1/" "$conf"
        did "COMMENTED OUT $1 in $conf"
    fi
    reload_pg
}

drop_function() {   # drop_function DB SIGNATURE
    new_evidence "pg-function-$1"
    pgq "SELECT pg_get_functiondef($(pg_str "$2")::regprocedure)" "$1" > "$EV/definition.sql" 2>&1
    run_sql "DROP FUNCTION $2 CASCADE" "DROPPED FUNCTION $2 in $1 (definition in $EV)" "psql $1 < $EV/definition.sql" "$1"
}

step_files() {
    local f data n
    section "FILES ON THE BOX"
    data=$(pgq 'SHOW data_directory')
    if [[ "$(stat -c %a "$data" 2>/dev/null)" != "700" ]]
    then
        flag "data folder $data is $(stat -c %a "$data") (should be 700)"
        confirm_safe "chmod 700 $data?" && chmod 700 "$data" && did "PERMISSIONS 700 on $data"
    else
        ok "data folder $data is private (700)"
    fi

    step "Files written BY postgres outside its folders (COPY TO / backdoor keys)"
    files_written_by postgres '^(/var/lib/postgresql|/var/log/postgresql|/run/postgresql|/etc/postgresql|/var/run/postgresql)/' > "$MARVIN_TMP/pgfiles"
    [[ -s "$MARVIN_TMP/pgfiles" ]] || ok "none"
    while read -r f
    do
        flag "file owned by postgres: $f ($(stat -c %s "$f") bytes)"
        head -c 300 "$f" | tr -c '[:print:]\n' '.' | head -n 4 | sed 's/^/      | /'
        confirm_safe "Quarantine $f?" && quarantine "$f" "file written by PostgreSQL"
    done < "$MARVIN_TMP/pgfiles"

    step "SSH keys and saved passwords of the postgres account"
    for f in /var/lib/postgresql/.ssh/authorized_keys /var/lib/postgresql/.ssh/authorized_keys2
    do
        [[ -f "$f" ]] || continue
        flag "$f lets someone SSH in as postgres (written with COPY ... TO)"
        confirm_safe "Quarantine $f?" && quarantine "$f" "postgres authorized_keys"
    done
    for f in /var/lib/postgresql/.psql_history /root/.psql_history /home/*/.psql_history
    do
        [[ -s "$f" ]] || continue
        n=$(grep -ciE 'password|create role|create user' "$f")
        caution "$f: $(wc -l < "$f") lines, $n with passwords/roles"
        if (( n > 0 )) && confirm_safe "Save a copy to evidence and empty $f?"
        then
            new_evidence "psql_history"; cp -a "$f" "$EV/"; : > "$f"
            did "EMPTIED $f (copy in $EV)"
        fi
    done
    for f in /var/lib/postgresql/.pgpass /root/.pgpass /home/*/.pgpass
    do
        [[ -f "$f" ]] || continue
        flag "$f stores database passwords (red team reads these)"
        confirm_risky "Quarantine $f?" && quarantine "$f" "stored PostgreSQL passwords"
    done

    step "Copies of the data lying around"
    loose_data_files > "$MARVIN_TMP/dumps"
    [[ -s "$MARVIN_TMP/dumps" ]] || ok "none"
    while read -r f
    do
        caution "data file: $f ($(du -h "$f" | cut -f1), owner $(stat -c %U "$f"))"
        confirm_risky "Quarantine $f (moved to $EVIDENCE, root-only)?" && quarantine "$f" "loose data dump"
    done < "$MARVIN_TMP/dumps"
}

step_connections() {
    section "LIVE CONNECTIONS"
    pg_seen_update
    pg_sessions
    explain "Roles seen logging in so far (they are protected):"
    awk '{printf "      %-20s from %-18s first seen %s\n", $1, $2, $3}' "$SEEN_DIR/postgres.txt" 2>/dev/null
}

step_seen() {
    local mins="${EXTRA:-5}" end before
    section "LEARNING WHICH ROLES ARE USED (${mins} min)"
    explain "Every role seen logging in is written to $SEEN_DIR/postgres.txt and is then PROTECTED."
    [[ "$(pgq 'SHOW log_connections')" == "on" ]] || explain "Tip: run the 'logging' step first so logins land in the log too."
    end=$(( $(date +%s) + mins * 60 ))
    while (( $(date +%s) < end ))
    do
        before=$(cat "$SEEN_DIR/postgres.txt" 2>/dev/null)
        pg_seen_update
        diff <(printf '%s\n' "$before") "$SEEN_DIR/postgres.txt" 2>/dev/null | sed -n 's/^> /  NEW: /p'
        sleep 3
    done
    printf "\n"; awk '{printf "  %-20s from %-18s first seen %s\n", $1, $2, $3}' "$SEEN_DIR/postgres.txt" 2>/dev/null
}

step_rotate() {
    local i=0 sel r su login cr cdb pw member newpw
    section "CHANGE A ROLE'S PASSWORD"
    explain "BEFORE you do this: tell the owner of the app box which role you are changing. They must"
    explain "put the new password in the app's config right after, or that app goes down. If the"
    explain "SCORER logs in as this role, also file a PCR in Quotient."
    [[ "$MODE" == "interactive" ]] || { caution "rotate only works interactively"; return; }
    pg_users | awk -F'\t' '$3 == "t"' > "$MARVIN_TMP/roles"
    while IFS=$'\t' read -r r su login cr cdb pw member
    do
        i=$((i + 1))
        printf "  %2d) %-20s password=%-6s seen from: %s\n" "$i" "$r" "$pw" "$(seen_from postgres "$r")"
    done < "$MARVIN_TMP/roles"
    ask_text "Number of the role to change (Enter = cancel): "; sel="$REPLY"
    [[ "$sel" =~ ^[0-9]+$ ]] || return
    r=$(sed -n "${sel}p" "$MARVIN_TMP/roles" | cut -f1)
    [[ -n "$r" ]] || return
    newpw=$(gen_password 16)
    ask_text "New password for '$r' (Enter = $newpw): "; newpw="${REPLY:-$newpw}"
    confirm_risky "Change the password of '$r' NOW (the app owner is ready)?" || return
    # through stdin, with statement logging off for this session, so it lands in no log
    if printf "SET log_statement = 'none';\nALTER ROLE %s WITH PASSWORD %s;\n" "$(pg_ident "$r")" "$(pg_str "$newpw")" \
        | (cd / && runuser -u postgres -- psql -X -q -p "$PG_PORT" -d postgres) 2>"$MARVIN_TMP/rot.err"
    then
        did "PASSWORD changed for PostgreSQL role '$r'"
        printf "\n  ${bold}new password for '%s': ${info}%s${reset}\n" "$r" "$newpw"
        printf "  -> put it in the team sheet, and in the app config on the box that uses '%s'\n" "$r"
        is_protected_db postgres "$r" && printf "  ${warn}-> it is in use: if the SCORER uses it, file a PCR in Quotient NOW${reset}\n"
        PGPASSWORD="$newpw" psql -X -h 127.0.0.1 -p "$PG_PORT" -U "$r" -d postgres -Atc 'SELECT 1' >/dev/null 2>&1 \
            && ok "test login over the network with the new password works"
        todo "Make sure the app using PostgreSQL role '$r' has the new password (changed $(date +%H:%M))"
    else
        flag "password change failed: $(cat "$MARVIN_TMP/rot.err")"
    fi
}

banner "postgres-lockdown.sh  -  PostgreSQL on marvin"
if ! pg_connect
then
    flag "Can't log in to PostgreSQL as postgres over the local socket. Is it running?  pg_lsclusters"
    explain "If red team changed the 'local ... postgres ... peer' line in pg_hba.conf, put it back at the"
    explain "top of the file:   local   all   postgres   peer     then: systemctl reload postgresql"
    exit 1
fi
printf "  PostgreSQL %s (cluster %s/%s, port %s)\n" "$(pgq 'SHOW server_version')" "$PG_VERSION" "$PG_CLUSTER" "$PG_PORT"
printf "  protected DB users: %s + everyone seen logging in\n" "${PROTECTED_DB_USERS:-<none listed>}"
[[ "$RUN" == "$STEPS" ]] && todo_reset
log_action "START postgres-lockdown mode=$MODE steps=$RUN"
for s in $RUN
do
    "step_$s"
done
log_action "END postgres-lockdown"
printf "\n${bold}${info}postgres-lockdown finished.${reset}  changes: %s   TODO: %s\n" "$ACTIONS" "$TODO_FILE"
exit 0
