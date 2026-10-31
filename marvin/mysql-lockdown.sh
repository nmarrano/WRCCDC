#!/bin/bash
#
# mysql-lockdown.sh
#
# Locks down MySQL or MariaDB on marvin: the login accounts, what each one is
# allowed to do, server settings that let SQL read/write files on the box, and
# persistence hidden INSIDE the database (UDFs, triggers, events, init_connect).
#
# It NEVER drops or locks:
#   - accounts in PROTECTED_DB_USERS (marvin.conf): the scorer's and the apps' logins
#   - accounts SEEN logging in (apps + scorer), kept in /root/marvin-data/seen/mysql.txt
#   - MySQL's own system accounts (root@localhost, debian-sys-maint, mysql.sys ...)
# Unknown accounts are LOCKED (ALTER USER ... ACCOUNT LOCK) - the undo is printed.
# Only anonymous ('') accounts are dropped: no app or scorer can log in with those.
# Passwords are only changed by the 'rotate' step, which you run by hand.
#
# Usage:
#   sudo ./mysql-lockdown.sh               every step, asks before each change
#   sudo ./mysql-lockdown.sh --auto        safe fixes by itself, risky ones -> TODO.txt
#   sudo ./mysql-lockdown.sh --audit       look only, change nothing
#   sudo ./mysql-lockdown.sh STEP...       only these steps:
#        info accounts privileges server persistence files connections
#   sudo ./mysql-lockdown.sh rotate        change one account's password (coordinate first!)
#   sudo ./mysql-lockdown.sh seen [MIN]    watch logins for MIN minutes (default 5) to learn
#                                          which accounts the apps + scorer use
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/db.sh"

STEPS="info accounts privileges server persistence files connections"
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

SUSPICIOUS_SQL='INTO +(OUT|DUMP)FILE|LOAD_FILE|sys_exec|sys_eval|CREATE +USER|GRANT |mysql\.user|SET +PASSWORD|ALTER +USER|DROP +(USER|DATABASE)'
DESTRUCTIVE_SQL='DROP +TABLE|TRUNCATE'

acct() { printf "%s@%s" "$(sql_str "$1")" "$(sql_str "$2")"; }   # 'user'@'host' for SQL

run_sql() {   # run_sql "SQL" "WHAT HAPPENED" "UNDO"  - runs it, reports success/failure
    local out
    if out=$(myq_try "$1")
    then
        did "$2" "$3"
    else
        flag "FAILED: $1"
        printf "      %s\n" "$out"
        return 1
    fi
}

# drop-in config file read after the distro's own (later files win)
mysql_dropin() {
    local d f
    if [[ "$(mysql_flavor)" == "mariadb" ]]
    then
        d=/etc/mysql/mariadb.conf.d; f=99-marvin.cnf
    else
        d=/etc/mysql/mysql.conf.d; f=zz-marvin.cnf
    fi
    [[ -d "$d" ]] || d=/etc/mysql/conf.d
    echo "$d/$f"
}

persist() {   # persist KEY VALUE - write it into our drop-in so it survives a restart
    local f
    f=$(mysql_dropin)
    [[ -f "$f" ]] || printf "# written by marvin mysql-lockdown.sh - later files win, so these beat the defaults\n[mysqld]\n" > "$f"
    sed -i "/^$1 *=/d" "$f"
    printf "%s = %s\n" "$1" "$2" >> "$f"
    chmod 644 "$f"
    log_action "PERSIST $1 = $2 in $f"
}

restart_mysql() {   # restart and make sure it comes back; on failure put the old config back
    local svc=mysql i
    [[ "$(mysql_flavor)" == "mariadb" ]] && svc=mariadb
    systemctl list-unit-files "$svc.service" >/dev/null 2>&1 || svc=mysql
    tar czf "$MARVIN_TMP/etc-mysql.tgz" -C / etc/mysql 2>/dev/null
    printf "  restarting %s (a few seconds of downtime)...\n" "$svc"
    systemctl restart "$svc"
    for i in $(seq 1 30)
    do
        mysql_health && { did "RESTARTED $svc - it is back up"; return 0; }
        sleep 1
    done
    flag "$svc did NOT come back up!  Last log lines:"
    journalctl -u "$svc" -n 15 --no-pager 2>/dev/null | sed 's/^/      /'
    return 1
}

step_info() {
    local cu
    section "WHAT IS RUNNING"
    printf "  logged in as: %s\n\n" "$MYSQL_AS"
    myq "SHOW VARIABLES WHERE Variable_name IN ('version','version_comment','port','bind_address','socket','datadir','plugin_dir',
         'skip_networking','performance_schema','secure_file_priv','local_infile','log_error','general_log','general_log_file',
         'init_connect','init_file','event_scheduler','max_connect_errors','max_connections','userstat')" \
        | awk -F'\t' '{printf "      %-20s %s\n", $1, $2}'

    step "Config files (active lines, passwords hidden)"
    grep -rnE --include='*.cnf' '^[^#;[:space:]]' /etc/mysql/ 2>/dev/null \
        | sed -E 's/^/      /; s/(password[[:space:]]*=[[:space:]]*).*/\1********/I'

    step "Can anyone log in WITHOUT a password? (skip-grant-tables)"
    cu=$(myq 'SELECT CURRENT_USER()')
    if [[ "$cu" == *skip-grants* ]] || grep -rqsE '^\s*skip[-_]grant[-_]tables' /etc/mysql/ \
       || tr '\0' ' ' < "/proc/$(pgrep -o -x 'mysqld|mariadbd')/cmdline" 2>/dev/null | grep -q 'skip-grant-tables'
    then
        flag "skip-grant-tables is ON: EVERY login works with ANY password, as ANY user!"
        grep -rnsE '^\s*skip[-_]grant[-_]tables' /etc/mysql/ | sed 's/^/      /'
        explain "Fix: comment it out of the config and restart MySQL. After the restart passwords are"
        explain "checked again - an app with a WRONG password in its config will start failing, so"
        explain "warn the box owners first."
        if confirm_risky "Comment out skip-grant-tables and restart MySQL?"
        then
            for f in $(grep -rlsE '^\s*skip[-_]grant[-_]tables' /etc/mysql/)
            do
                backup_file "$f"; sed -i -E 's/^(\s*skip[-_]grant[-_]tables.*)/#marvin# \1/' "$f"
            done
            restart_mysql
        fi
    else
        ok "passwords are checked (no skip-grant-tables)"
    fi

    case "$(myq 'SELECT @@bind_address')" in
        127.0.0.1|localhost|::1)
            caution "bind_address is local only: other boxes (apps, scorer) can NOT reach this database."
            explain "If an app on another box should use it, set bind-address = 0.0.0.0 and restart." ;;
    esac
    [[ "$(myq 'SELECT @@skip_networking')" == "1" ]] && caution "skip_networking is ON: only local socket logins work"
    docker_db_warning
}

print_accounts() {
    local u h plugin pw locked privs status
    printf "  ${bold}%-36s %-22s %-7s %-6s %-12s %s${reset}\n" ACCOUNT PLUGIN PASSWD LOCKED STATUS "GLOBAL PRIVILEGES (on every DB)"
    while IFS=$'\t' read -r u h plugin pw locked privs
    do
        if mysql_is_system "$u" "$h"
        then
            status="system"
        elif is_protected_db mysql "$u"
        then
            status="PROTECTED"
        else
            status="unknown"
        fi
        printf "  %-36s %-22s %-7s %-6s %-12s %s\n" "'$u'@'$h'" "$plugin" "$pw" "$locked" "$status" "${privs:--}"
    done < "$MARVIN_TMP/users"
    printf "\n"
    explain "PROTECTED = in PROTECTED_DB_USERS or seen logging in. system = MySQL's own accounts."
    explain "Seen so far: $(awk '{print $1 "(" $2 ")"}' "$SEEN_DIR/mysql.txt" 2>/dev/null | sort -u | paste -sd' ' -)"
}

step_accounts() {
    local u h plugin pw locked privs a
    section "ACCOUNTS"
    explain "Each MySQL account is 'user'@'host'. host '%' = from ANY IP. Red team adds accounts with"
    explain "admin powers, or uses accounts with no password. Locking is undone with ACCOUNT UNLOCK."
    explain "Accounts the apps/scorer use are found by watching logins - run './mysql-lockdown.sh seen'"
    explain "for a few minutes first if this is the first run, so they are protected."
    mysql_seen_update
    mysql_users > "$MARVIN_TMP/users"
    print_accounts

    while IFS=$'\t' read -r u h plugin pw locked privs
    do
        [[ "$u" == "<anonymous>" ]] && u=""
        a=$(acct "$u" "$h")
        if [[ -z "$u" ]]
        then
            flag "anonymous account ''@'$h' - anyone can log in with any name"
            confirm_safe "DROP the anonymous account ''@'$h'?" && run_sql "DROP USER $a" "DROPPED anonymous account ''@'$h'"
            continue
        fi
        if mysql_is_system "$u" "$h"
        then
            [[ "$pw" == "EMPTY" ]] && { flag "system account '$u'@'$h' has an EMPTY password"; todo "Set a password for MySQL '$u'@'$h' (rotate step)"; }
            continue
        fi
        [[ "$locked" == "Y" ]] && continue
        if [[ "$pw" == "EMPTY" ]]
        then
            flag "'$u'@'$h' has an EMPTY password"
            if is_protected_db mysql "$u"
            then
                caution "it is protected (an app/scorer uses it) - give it a password with the rotate step, together with the app owner"
                todo "MySQL '$u'@'$h' has an EMPTY password but is in use - rotate it with the app owner (+PCR if scored)"
            else
                confirm_safe "LOCK '$u'@'$h'?" && lock_account "$u" "$h" "empty password"
            fi
            continue
        fi
        is_protected_db mysql "$u" && continue
        if [[ "$u" == "root" && ! "$h" =~ ^(localhost|127\.0\.0\.1|::1)$ ]]
        then
            flag "root can log in from the network ('root'@'$h') and nobody was seen using it"
            confirm_risky "LOCK 'root'@'$h'? (only if the scorer does NOT log in as root)" && lock_account "$u" "$h" "remote root"
        elif [[ "$privs" =~ (SUPER|FILE|GRANT|CREATE-USER|SHUTDOWN|SELECT-ALL-DBS|WRITE-ALL-DBS) ]]
        then
            flag "'$u'@'$h' has admin powers ($privs) and nobody was seen using it"
            explain "Could be red team's account - or an app that just hasn't connected yet. Look in the app"
            explain "config files (wp-config.php, .env, LocalSettings.php...) for this user name first."
            confirm_risky "LOCK '$u'@'$h'?" && lock_account "$u" "$h" "unknown admin account"
        else
            caution "'$u'@'$h' is not protected and wasn't seen logging in (no admin powers)"
            explain "Probably an app that hasn't connected yet - or a spare red team login. Check the app configs."
            confirm_risky "LOCK the unknown account '$u'@'$h'?" && lock_account "$u" "$h" "unknown account"
        fi
    done < "$MARVIN_TMP/users"
}

lock_account() {   # lock_account USER HOST REASON  - lock, then kick its live connections
    local id
    run_sql "ALTER USER $(acct "$1" "$2") ACCOUNT LOCK" "LOCKED MySQL account '$1'@'$2' ($3)" \
        "ALTER USER '$1'@'$2' ACCOUNT UNLOCK;" || return
    for id in $(myq "SELECT ID FROM information_schema.PROCESSLIST WHERE USER = $(sql_str "$1")")
    do
        myq "KILL $id" && did "KILLED MySQL connection $id of '$1'"
    done
}

step_privileges() {
    local u h plugin pw locked privs a p revoke grants dbs db
    section "PRIVILEGES"
    explain "Privileges 'ON *.*' work on EVERY database - an app account like that can read every"
    explain "other app's customers. FILE lets SQL read files (/etc/passwd, configs) and write webshells."
    explain "SUPER/GRANT/CREATE USER/SHUTDOWN are admin powers apps never need."
    mysql_users > "$MARVIN_TMP/users"
    while IFS=$'\t' read -r u h plugin pw locked privs
    do
        [[ "$u" == "<anonymous>" ]] && continue
        mysql_is_system "$u" "$h" && continue
        a=$(acct "$u" "$h")
        grants=$(myq "SHOW GRANTS FOR $a")
        printf "\n  ${bold}'%s'@'%s'${reset}%s\n" "$u" "$h" "$(is_protected_db mysql "$u" && echo '  (PROTECTED)')"
        printf '%s\n' "$grants" | cut -c1-200 | sed 's/^/      /'

        if [[ "$privs" == *FILE* ]]
        then
            flag "'$u'@'$h' has FILE (read/write files on the box through SQL)"
            confirm_safe "REVOKE FILE from '$u'@'$h'?" && run_sql "REVOKE FILE ON *.* FROM $a" "REVOKED FILE from '$u'@'$h'" "GRANT FILE ON *.* TO '$u'@'$h';"
        fi
        revoke=""
        for p in SUPER PROCESS SHUTDOWN RELOAD CREATE-USER GRANT
        do
            [[ ",$privs," == *",$p,"* ]] || continue
            case "$p" in
                CREATE-USER) revoke+="CREATE USER, " ;;
                GRANT) ;;
                *) revoke+="$p, " ;;
            esac
        done
        revoke="${revoke%, }"
        if [[ -n "$revoke" || ",$privs," == *",GRANT,"* ]]
        then
            p="$revoke"
            [[ ",$privs," == *",GRANT,"* ]] && p="${p:+$p, }GRANT OPTION"
            flag "'$u'@'$h' has admin privileges: $p"
            if is_protected_db mysql "$u"
            then
                confirm_risky "REVOKE the admin privileges from (protected) '$u'@'$h'?" && p=yes || p=no
            else
                confirm_safe "REVOKE the admin privileges from '$u'@'$h'?" && p=yes || p=no
            fi
            if [[ "$p" == "yes" ]]
            then
                [[ -n "$revoke" ]] && run_sql "REVOKE $revoke ON *.* FROM $a" "REVOKED $revoke from '$u'@'$h'" "GRANT $revoke ON *.* TO '$u'@'$h';"
                [[ ",$privs," == *",GRANT,"* ]] && run_sql "REVOKE GRANT OPTION ON *.* FROM $a" "REVOKED GRANT OPTION from '$u'@'$h'"
            fi
        fi

        if [[ "$privs" =~ (SELECT-ALL-DBS|WRITE-ALL-DBS) ]]
        then
            flag "'$u'@'$h' can read/change EVERY database ($privs)"
            explain "Fix: give it ALL on ONLY its own database(s). The app keeps working as long as you name"
            explain "every database it uses (check the app config: DB_NAME / database name)."
            dbs=$(myq "SHOW DATABASES" | grep -vxE 'mysql|sys|performance_schema|information_schema' | paste -sd' ' -)
            printf "      databases on this server: %s\n" "$dbs"
            if confirm_risky "Limit '$u'@'$h' to only its own database(s)?"
            then
                ask_text "Which database(s) does '$u' use? (space separated): "
                [[ -z "$REPLY" ]] && { caution "nothing typed - skipped"; continue; }
                for db in $REPLY
                do
                    in_list "$db" "$dbs" || { flag "no database named '$db' - skipped"; continue 2; }
                done
                backup_grants "$u" "$h" "$grants"
                run_sql "REVOKE ALL PRIVILEGES ON *.* FROM $a" "REVOKED all global privileges from '$u'@'$h'" "see $EV" || continue
                myq "REVOKE GRANT OPTION ON *.* FROM $a" 2>/dev/null
                for db in $REPLY
                do
                    run_sql "GRANT ALL PRIVILEGES ON \`$db\`.* TO $a" "GRANTED ALL on $db.* to '$u'@'$h'"
                done
            fi
        fi
    done < "$MARVIN_TMP/users"
}

backup_grants() {
    new_evidence "mysql-grants-$1"
    printf '%s;\n' "$3" > "$EV/grants.sql"
    explain "old grants saved in $EV/grants.sql  (undo: mysql < $EV/grants.sql)"
}

step_server() {
    local v f
    section "SERVER SETTINGS"
    explain "Live changes use SET GLOBAL (no restart). They are also written to $(mysql_dropin)"
    explain "so they survive a restart."

    v=$(myq 'SELECT @@local_infile')
    if [[ "$v" == "1" ]]
    then
        flag "local_infile is ON (lets a client read files from the box into tables)"
        confirm_safe "Turn local_infile OFF?" && run_sql "SET GLOBAL local_infile = 0" "SET local_infile = 0" "SET GLOBAL local_infile = 1;" && persist local_infile 0
    else
        ok "local_infile is off"
    fi

    v=$(myq 'SELECT IFNULL(@@secure_file_priv, "NULL")')
    case "$v" in
        "")
            flag "secure_file_priv is EMPTY: SQL can read/write files ANYWHERE MySQL can (LOAD_FILE, INTO OUTFILE)"
            explain "Fix: secure_file_priv = /var/lib/mysql-files (needs a restart, a few seconds of downtime)."
            explain "Less urgent once FILE is revoked from every app account (privileges step)."
            if confirm_risky "Set secure_file_priv = /var/lib/mysql-files and restart MySQL?"
            then
                install -d -o mysql -g mysql -m 750 /var/lib/mysql-files
                persist secure_file_priv /var/lib/mysql-files
                restart_mysql || { sed -i '/^secure_file_priv/d' "$(mysql_dropin)"; restart_mysql; }
            fi ;;
        NULL) ok "secure_file_priv = NULL (file import/export disabled)" ;;
        *) ok "secure_file_priv = $v (file import/export limited to that folder)" ;;
    esac

    v=$(myq 'SELECT @@init_connect')
    if [[ -n "$v" ]]
    then
        flag "init_connect runs this SQL on EVERY login: $v"
        explain "Red team uses it to re-create accounts or copy data on each connection."
        if confirm_safe "Clear init_connect?"
        then
            run_sql "SET GLOBAL init_connect = ''" "CLEARED init_connect (was: $v)"
            for f in $(grep -rlsE '^\s*init[-_]connect' /etc/mysql/)
            do
                backup_file "$f"; sed -i -E 's/^(\s*init[-_]connect.*)/#marvin# \1/' "$f"
                did "COMMENTED OUT init_connect in $f"
            done
        fi
    else
        ok "init_connect is empty"
    fi

    v=$(myq "SHOW VARIABLES LIKE 'init_file'" | cut -f2)
    if [[ -n "$v" ]]
    then
        flag "init_file runs $v as ROOT every time MySQL starts:"
        head -n 10 "$v" 2>/dev/null | sed 's/^/      | /'
        for f in $(grep -rlsE '^\s*init[-_]file' /etc/mysql/)
        do
            confirm_safe "Comment out init_file in $f?" && { backup_file "$f"; sed -i -E 's/^(\s*init[-_]file.*)/#marvin# \1/' "$f"; did "COMMENTED OUT init_file in $f"; }
        done
    fi

    for v in general_log_file slow_query_log_file
    do
        f=$(myq "SELECT @@$v")
        if [[ -n "$f" && "$f" != /var/log/mysql/* && "$f" != "$(myq 'SELECT @@datadir')"* && "$f" != /var/lib/mysql/* ]]
        then
            flag "$v points to $f - red team aims the query log at a web folder to write a webshell"
            confirm_safe "Point $v back to /var/log/mysql/?" \
                && run_sql "SET GLOBAL $v = '/var/log/mysql/${v%_file}.log'" "SET $v = /var/log/mysql/${v%_file}.log (was $f)"
        fi
    done

    v=$(myq 'SELECT @@max_connect_errors')
    if (( ${v:-0} < 1000000 ))
    then
        caution "max_connect_errors = $v: after that many bad connections from one IP, MySQL BLOCKS that IP"
        explain "Red team scans can get the SCORER's IP blocked ('Host is blocked because of many connection errors')."
        confirm_safe "Raise max_connect_errors to 1000000?" && run_sql "SET GLOBAL max_connect_errors = 1000000" "SET max_connect_errors = 1000000" && persist max_connect_errors 1000000
    else
        ok "max_connect_errors = $v"
    fi

    if [[ "$(mysql_flavor)" == "mysql" ]]
    then
        v=$(myq 'SELECT @@log_error_verbosity')
        if (( ${v:-3} < 3 ))
        then
            explain "log_error_verbosity 3 writes failed logins ('Access denied') to the error log."
            confirm_safe "Log failed logins (log_error_verbosity = 3)?" && run_sql "SET GLOBAL log_error_verbosity = 3" "SET log_error_verbosity = 3" && persist loose-log_error_verbosity 3
        fi
    else
        v=$(myq 'SELECT @@userstat' 2>/dev/null)
        if [[ "$v" == "0" ]]
        then
            explain "MariaDB only remembers which accounts logged in when userstat is on (used to protect app/scorer accounts)."
            confirm_safe "Turn on userstat?" && run_sql "SET GLOBAL userstat = 1" "SET userstat = 1" && persist loose-userstat 1
        fi
    fi
    if [[ -f "$(mysql_dropin)" ]]
    then
        printf "\n  ${bold}%s:${reset}\n" "$(mysql_dropin)"
        sed 's/^/      | /' "$(mysql_dropin)"
        if [[ "$(mysql_flavor)" == "mysql" ]] && have mysqld && ! mysqld --validate-config >/dev/null 2>"$MARVIN_TMP/val"
        then
            flag "mysqld --validate-config does not like the config - MySQL would NOT start after a restart:"
            sed 's/^/      /' "$MARVIN_TMP/val"
            todo "Fix the MySQL config before any restart (mysqld --validate-config)"
        fi
    fi
}

step_persistence() {
    local name dl type kind schema obj body f
    section "PERSISTENCE INSIDE THE DATABASE"
    explain "UDFs = C code loaded into MySQL (sys_exec runs OS commands). Triggers/events/procedures"
    explain "= SQL that runs by itself. Apps use triggers too, so only clearly malicious ones are"
    explain "dropped automatically (they create users, grant, read/write files...)."

    step "User-defined functions (UDFs)"
    myq "SELECT name, dl, type FROM mysql.func" > "$MARVIN_TMP/udf"
    [[ -s "$MARVIN_TMP/udf" ]] || ok "no UDFs (normal)"
    while IFS=$'\t' read -r name dl type
    do
        flag "UDF $name from library $dl - normal MySQL has NONE"
        if confirm_safe "Remove UDF $name?"
        then
            myq "DROP FUNCTION IF EXISTS \`$name\`" 2>/dev/null
            [[ -n "$(myq "SELECT name FROM mysql.func WHERE name = $(sql_str "$name")")" ]] && myq "DELETE FROM mysql.func WHERE name = $(sql_str "$name")"
            did "REMOVED UDF $name ($dl)"
            f="$(myq 'SELECT @@plugin_dir')/$dl"
            [[ -f "$f" ]] && ! is_owned "$f" && quarantine "$f" "UDF library"
        fi
    done < "$MARVIN_TMP/udf"

    step "Plugin folder: libraries no package installed"
    for f in $(ls "$(myq 'SELECT @@plugin_dir')"/*.so 2>/dev/null | not_owned)
    do
        flag "library no package installed in the plugin folder: $f"
        if myq "SELECT PLUGIN_NAME FROM information_schema.PLUGINS WHERE PLUGIN_LIBRARY = $(sql_str "$(basename "$f")")" | grep -q .
        then
            caution "it is LOADED as a plugin - uninstall it first:  UNINSTALL PLUGIN <name>;"
            todo "MySQL plugin library $f is loaded - UNINSTALL PLUGIN it, then quarantine the file"
        else
            confirm_safe "Quarantine $f?" && quarantine "$f" "unknown MySQL plugin library"
        fi
    done

    step "Triggers, events, stored procedures and functions"
    myq "SELECT 'TRIGGER', TRIGGER_SCHEMA, TRIGGER_NAME, REPLACE(REPLACE(ACTION_STATEMENT, '\n', ' '), '\t', ' ')
           FROM information_schema.TRIGGERS WHERE TRIGGER_SCHEMA NOT IN ('mysql','sys','performance_schema','information_schema')
         UNION ALL
         SELECT 'EVENT', EVENT_SCHEMA, EVENT_NAME, REPLACE(REPLACE(EVENT_DEFINITION, '\n', ' '), '\t', ' ')
           FROM information_schema.EVENTS
         UNION ALL
         SELECT ROUTINE_TYPE, ROUTINE_SCHEMA, ROUTINE_NAME, REPLACE(REPLACE(IFNULL(ROUTINE_DEFINITION, ''), '\n', ' '), '\t', ' ')
           FROM information_schema.ROUTINES WHERE ROUTINE_SCHEMA NOT IN ('mysql','sys')" > "$MARVIN_TMP/code"
    [[ -s "$MARVIN_TMP/code" ]] || ok "none"
    printf "      event_scheduler = %s\n" "$(myq 'SELECT @@event_scheduler')"
    while IFS=$'\t' read -r kind schema obj body
    do
        printf "\n  ${bold}%s %s.%s${reset}\n      | %s\n" "$kind" "$schema" "$obj" "${body:0:200}"
        if grep -qiE "$SUSPICIOUS_SQL" <<< "$body"
        then
            flag "$kind $schema.$obj creates users / grants / touches files - persistence"
            confirm_safe "DROP $kind $schema.$obj (its code is saved first)?" && drop_code "$kind" "$schema" "$obj"
        elif grep -qiE "$DESTRUCTIVE_SQL" <<< "$body"
        then
            caution "$kind $schema.$obj deletes/changes data - fine if the app made it, bad if red team did"
            confirm_risky "DROP $kind $schema.$obj?" && drop_code "$kind" "$schema" "$obj"
        else
            explain "(looks like normal app code)"
        fi
    done < "$MARVIN_TMP/code"
}

drop_code() {   # drop_code KIND SCHEMA NAME
    new_evidence "mysql-$1-$2.$3"
    myq "SHOW CREATE $1 \`$2\`.\`$3\`" > "$EV/definition.sql" 2>&1
    run_sql "DROP $1 \`$2\`.\`$3\`" "DROPPED $1 $2.$3 (definition saved in $EV)" "mysql $2 < $EV/definition.sql (after cleaning up the SHOW CREATE output)"
}

step_files() {
    local f datadir n
    section "FILES ON THE BOX"
    datadir=$(myq 'SELECT @@datadir'); datadir=${datadir%/}

    if [[ -d "$datadir" ]] && [[ "$(stat -c %a "$datadir")" =~ [1-7]$ ]]
    then
        flag "the data folder $datadir can be read by everyone ($(stat -c %a "$datadir"))"
        confirm_safe "chmod o-rwx $datadir?" && chmod o-rwx "$datadir" && did "PERMISSIONS o-rwx on $datadir" "chmod $(stat -c %a "$datadir") $datadir"
    else
        ok "data folder $datadir is private"
    fi
    if [[ -f /etc/mysql/debian.cnf && "$(stat -c '%a %U' /etc/mysql/debian.cnf)" != "600 root" ]]
    then
        flag "/etc/mysql/debian.cnf (holds an admin password) is $(stat -c '%a %U' /etc/mysql/debian.cnf)"
        confirm_safe "Make it 600 root:root?" && chown root:root /etc/mysql/debian.cnf && chmod 600 /etc/mysql/debian.cnf && did "PERMISSIONS 600 root on debian.cnf"
    fi

    step "Files written BY MySQL outside its folders (INTO OUTFILE / webshells)"
    find / "${PRUNE[@]}" -user mysql -type f -print 2>/dev/null \
        | grep -vE "^($datadir|/var/lib/mysql|/var/lib/mysql-keyring|/var/log/mysql|/run/mysqld|/var/lib/mysql-files)/" > "$MARVIN_TMP/myfiles"
    [[ -s "$MARVIN_TMP/myfiles" ]] || ok "none"
    while read -r f
    do
        flag "file owned by mysql: $f ($(stat -c %s "$f") bytes)"
        head -c 300 "$f" | tr -c '[:print:]\n' '.' | head -n 4 | sed 's/^/      | /'
        confirm_safe "Quarantine $f?" && quarantine "$f" "file written by MySQL"
    done < "$MARVIN_TMP/myfiles"
    for f in /var/lib/mysql-files/*
    do
        [[ -f "$f" ]] || continue
        flag "export in /var/lib/mysql-files (someone dumped data with INTO OUTFILE): $f"
        confirm_safe "Quarantine $f?" && quarantine "$f" "INTO OUTFILE export"
    done

    step "Passwords lying around"
    for f in /root/.mysql_history /home/*/.mysql_history /var/lib/mysql/.mysql_history
    do
        [[ -s "$f" ]] || continue
        n=$(grep -ciE 'identified|password' "$f")
        caution "$f: $(wc -l < "$f") lines, $n with passwords in them"
        if (( n > 0 )) && confirm_safe "Save a copy to evidence and empty $f?"
        then
            new_evidence "mysql_history"; cp -a "$f" "$EV/"; : > "$f"
            did "EMPTIED $f (copy in $EV)"
        fi
    done
    for f in /root/.my.cnf /home/*/.my.cnf /etc/mysql/conf.d/*.cnf /etc/mysql/*.cnf
    do
        [[ -f "$f" ]] || continue
        grep -qiE '^\s*password\s*=' "$f" || continue
        [[ "$f" == /etc/mysql/debian.cnf ]] && continue
        flag "$f has a stored password (user: $(awk -F= '/^\s*user/ {gsub(/[ "]/, "", $2); print $2; exit}' "$f"))"
        explain "Red team reads these. Fine if YOU made it; otherwise quarantine it."
        confirm_risky "Quarantine $f?" && quarantine "$f" "stored MySQL password"
    done

    step "Copies of the data lying around (red team only needs to read them)"
    find / "${PRUNE[@]}" -type f \( -name '*.sql' -o -name '*.sql.gz' -o -name '*.dump' -o -name '*.csv' -o -name '*.ibd.bak' \) \
         -size +1k -print 2>/dev/null | grep -vE "^($datadir|/var/lib/mysql)/" | not_owned > "$MARVIN_TMP/dumps"
    [[ -s "$MARVIN_TMP/dumps" ]] || ok "none"
    while read -r f
    do
        caution "data file: $f ($(du -h "$f" | cut -f1), owner $(stat -c %U "$f"))"
        confirm_risky "Quarantine $f (moved to $EVIDENCE, root-only)?" && quarantine "$f" "loose data dump"
    done < "$MARVIN_TMP/dumps"
}

step_connections() {
    section "LIVE CONNECTIONS"
    mysql_seen_update
    mysql_sessions
    explain "Accounts seen logging in so far (they are protected):"
    awk '{printf "      %-20s from %-18s first seen %s\n", $1, $2, $3}' "$SEEN_DIR/mysql.txt" 2>/dev/null
}

step_seen() {
    local mins="${EXTRA:-5}" end before
    section "LEARNING WHICH ACCOUNTS ARE USED (${mins} min)"
    explain "The scorer checks every 2-4 minutes and apps connect when someone uses the site. Every"
    explain "account seen logging in is written to $SEEN_DIR/mysql.txt and is then PROTECTED."
    [[ "$(mysql_flavor)" == "mariadb" && "$(myq 'SELECT @@userstat')" == "0" ]] && myq 'SET GLOBAL userstat = 1' && did "SET userstat = 1 (MariaDB login tracking)"
    end=$(( $(date +%s) + mins * 60 ))
    while (( $(date +%s) < end ))
    do
        before=$(cat "$SEEN_DIR/mysql.txt" 2>/dev/null)
        mysql_seen_update
        diff <(printf '%s\n' "$before") "$SEEN_DIR/mysql.txt" 2>/dev/null | sed -n 's/^> /  NEW: /p'
        sleep 3
    done
    printf "\n"; awk '{printf "  %-20s from %-18s first seen %s\n", $1, $2, $3}' "$SEEN_DIR/mysql.txt" 2>/dev/null
}

step_rotate() {
    local i=0 sel u h plugin pw locked privs a newpw
    section "CHANGE AN ACCOUNT'S PASSWORD"
    explain "BEFORE you do this: tell the owner of the app box which account you are changing. They"
    explain "must put the new password in the app's config file right after (wp-config.php, .env...),"
    explain "or that app goes down. If the SCORER logs in as this account, also file a PCR in Quotient."
    [[ "$MODE" == "interactive" ]] || { caution "rotate only works interactively"; return; }
    mysql_users > "$MARVIN_TMP/users"
    while IFS=$'\t' read -r u h plugin pw locked privs
    do
        i=$((i + 1))
        printf "  %2d) %-34s %-8s seen from: %s\n" "$i" "'$u'@'$h'" "$pw" "$(seen_from mysql "$u")"
    done < "$MARVIN_TMP/users"
    ask_text "Number of the account to change (Enter = cancel): "; sel="$REPLY"
    [[ "$sel" =~ ^[0-9]+$ ]] || return
    IFS=$'\t' read -r u h plugin pw locked privs < <(sed -n "${sel}p" "$MARVIN_TMP/users")
    [[ -n "$u$h" ]] || return
    [[ "$plugin" == "auth_socket" || "$plugin" == "unix_socket" ]] && { caution "'$u'@'$h' logs in with the Linux account, not a password - nothing to change"; return; }
    newpw=$(gen_password 16)
    ask_text "New password for '$u'@'$h' (Enter = $newpw): "; newpw="${REPLY:-$newpw}"
    confirm_risky "Change the password of '$u'@'$h' NOW (the app owner is ready)?" || return
    a=$(acct "$u" "$h")
    # the password goes through stdin, never on a command line
    if printf "ALTER USER %s IDENTIFIED BY %s;\n" "$a" "$(sql_str "$newpw")" | mysql "${MYSQL_ARGS[@]}" 2>"$MARVIN_TMP/rot.err"
    then
        did "PASSWORD changed for MySQL '$u'@'$h'"
        printf "\n  ${bold}new password for '%s'@'%s': ${info}%s${reset}\n" "$u" "$h" "$newpw"
        printf "  -> put it in the team sheet, and in the app config on the box that uses '%s'\n" "$u"
        is_protected_db mysql "$u" && printf "  ${warn}-> it is in use: if the SCORER uses it, file a PCR in Quotient NOW${reset}\n"
        if [[ "$h" =~ ^(%|localhost|127\.0\.0\.1)$ ]] && MYSQL_PWD="$newpw" mysql --no-defaults -h 127.0.0.1 -u "$u" -NBe 'SELECT 1' >/dev/null 2>&1
        then
            ok "test login with the new password works"
        fi
        todo "Make sure the app using MySQL '$u' has the new password (changed $(date +%H:%M))"
    else
        flag "password change failed: $(cat "$MARVIN_TMP/rot.err")"
    fi
}

banner "mysql-lockdown.sh  -  MySQL / MariaDB on marvin"
if ! mysql_connect
then
    flag "Can't log in to MySQL/MariaDB. Is it running?  systemctl status mysql mariadb"
    explain "If root has a password, run this interactively and type it, or put it in $DATA_DIR/mysql-admin.cnf:"
    explain "  [client]\\n  user=root\\n  password=\"...\""
    exit 1
fi
printf "  %s %s, logged in as %s\n" "$(mysql_flavor)" "$(myq 'SELECT VERSION()')" "$MYSQL_AS"
printf "  protected DB users: %s + everyone seen logging in\n" "${PROTECTED_DB_USERS:-<none listed>}"
[[ "$RUN" == "$STEPS" ]] && todo_reset
log_action "START mysql-lockdown mode=$MODE steps=$RUN"
for s in $RUN
do
    "step_$s"
done
log_action "END mysql-lockdown"
printf "\n${bold}${info}mysql-lockdown finished.${reset}  changes: %s   TODO: %s\n" "$ACTIONS" "$TODO_FILE"
exit 0
