#!/bin/bash
#
# lib/db.sh
#
# How the marvin scripts log in to each database and read accounts, live
# connections and "who has logged in". Loaded after lib/common.sh.
# Nothing in this file changes a database.
#
#   db_connect ENGINE       log in (sets the variables the q-functions below use)
#   db_users ENGINE         one line per account
#   db_sessions ENGINE      live connections, as a table
#   db_seen_update ENGINE   remember every account seen logging in (apps + scorer)
#   db_health ENGINE        true if a test query works
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

sql_str() {   # SQL string literal: 'it''s'  (backslashes doubled for MySQL)
    local s="${1//\\/\\\\}"
    printf "'%s'" "${s//\'/\'\'}"
}
pg_str()   { printf "'%s'" "${1//\'/\'\'}"; }
pg_ident() { printf '"%s"' "${1//\"/\"\"}"; }
js_str() {
    local s="${1//\\/\\\\}"
    printf '"%s"' "${s//\"/\\\"}"
}

# ======================= MySQL / MariaDB =======================

mysql_socket() {
    local s
    s=$(ss -Hxlp 2>/dev/null | awk '/mysqld|mariadbd/ {print $5}' | grep -v mysqlx | head -n 1)
    echo "${s:-/run/mysqld/mysqld.sock}"
}

# --no-defaults / --defaults-file: never read a ~/.my.cnf that red team could have
# planted to send our admin login somewhere else
mysql_connect() {
    local u p f="$DATA_DIR/mysql-admin.cnf"
    have mysql || return 1
    MYSQL_ARGS=(--no-defaults --protocol=socket "--socket=$(mysql_socket)" -uroot)
    if mysql "${MYSQL_ARGS[@]}" -NBe 'SELECT 1' >/dev/null 2>&1
    then
        MYSQL_AS="root over the local socket"; return 0
    fi
    MYSQL_ARGS=(--defaults-file=/etc/mysql/debian.cnf)
    if [[ -r /etc/mysql/debian.cnf ]] && mysql "${MYSQL_ARGS[@]}" -NBe 'SELECT 1' >/dev/null 2>&1
    then
        MYSQL_AS="debian-sys-maint (/etc/mysql/debian.cnf)"; return 0
    fi
    MYSQL_ARGS=("--defaults-file=$f")
    if [[ -r "$f" ]] && mysql "${MYSQL_ARGS[@]}" -NBe 'SELECT 1' >/dev/null 2>&1
    then
        MYSQL_AS="the admin login saved in $f"; return 0
    fi
    MYSQL_ARGS=()
    [[ "$MODE" == "interactive" ]] || return 1
    printf "${warn}  Could not log in to MySQL as root automatically (root has a password).${reset}\n"
    read -r -u 3 -p "  MySQL admin user [root] (type 'skip' to skip): " u
    [[ "$u" == "skip" ]] && return 1
    read -r -s -u 3 -p "  password for ${u:-root}: " p; echo
    p=${p//\\/\\\\}
    printf '[client]\nuser="%s"\npassword="%s"\nsocket=%s\n' "${u:-root}" "${p//\"/\\\"}" "$(mysql_socket)" > "$f"
    chmod 600 "$f"
    MYSQL_ARGS=("--defaults-file=$f")
    if mysql "${MYSQL_ARGS[@]}" -NBe 'SELECT 1' >/dev/null 2>&1
    then
        MYSQL_AS="${u:-root} (saved in $f)"; return 0
    fi
    rm -f "$f"; MYSQL_ARGS=()
    return 1
}

myq()       { mysql "${MYSQL_ARGS[@]}" -NB -e "$1" 2>>"$MARVIN_TMP/sql.err"; }
myq_table() { mysql "${MYSQL_ARGS[@]}" -t -e "$1" 2>&1; }
myq_try()   { mysql "${MYSQL_ARGS[@]}" -NB -e "$1" 2>&1; }   # shows the error text

mysql_flavor() {
    [[ -n "$MYSQL_FLAVOR" ]] || { myq 'SELECT VERSION()' | grep -qi mariadb && MYSQL_FLAVOR=mariadb || MYSQL_FLAVOR=mysql; }
    echo "$MYSQL_FLAVOR"
}

# user<TAB>host<TAB>plugin<TAB>password(socket|EMPTY|set)<TAB>locked(Y/N)<TAB>global admin privileges
mysql_users() {
    local privs pw locked from
    privs="CONCAT_WS(',', IF(u.Select_priv='Y','SELECT-ALL-DBS',NULL), IF(u.Insert_priv='Y' OR u.Update_priv='Y' OR u.Delete_priv='Y' OR u.Drop_priv='Y','WRITE-ALL-DBS',NULL),
        IF(u.File_priv='Y','FILE',NULL), IF(u.Super_priv='Y','SUPER',NULL), IF(u.Grant_priv='Y','GRANT',NULL),
        IF(u.Create_user_priv='Y','CREATE-USER',NULL), IF(u.Process_priv='Y','PROCESS',NULL),
        IF(u.Shutdown_priv='Y','SHUTDOWN',NULL), IF(u.Reload_priv='Y','RELOAD',NULL))"
    pw="CASE WHEN u.plugin IN ('auth_socket','unix_socket') OR u.authentication_string IN ('invalid') THEN 'socket'
             WHEN u.authentication_string = '' OR u.authentication_string IS NULL THEN 'EMPTY' ELSE 'set' END"
    if [[ "$(mysql_flavor)" == "mariadb" ]]
    then
        locked="IF(JSON_VALUE(g.Priv, '\$.account_locked') IN ('true','1'), 'Y', 'N')"
        from="mysql.user u LEFT JOIN mysql.global_priv g ON g.User = u.User AND g.Host = u.Host"
    else
        locked="u.account_locked"
        from="mysql.user u"
    fi
    # an empty user name would vanish when bash splits on tabs, so it is printed as <anonymous>
    myq "SELECT IF(u.User = '', '<anonymous>', u.User), u.Host, u.plugin, $pw, $locked, $privs FROM $from ORDER BY u.User, u.Host"
}

MYSQL_SYSTEM_ACCOUNTS=" root@localhost debian-sys-maint@localhost mysql.sys@localhost mysql.session@localhost mysql.infoschema@localhost mariadb.sys@localhost mysql@localhost "
mysql_is_system() { [[ "$MYSQL_SYSTEM_ACCOUNTS" == *" $1@$2 "* ]]; }

mysql_sessions() {
    myq_table "SELECT ID, USER, HOST, DB, COMMAND, TIME, LEFT(IFNULL(INFO,''), 60) AS QUERY
               FROM information_schema.PROCESSLIST
               WHERE ID <> CONNECTION_ID() AND USER NOT IN ('system user','event_scheduler')
               ORDER BY TIME DESC LIMIT 40"
}

mysql_seen_update() {
    local u h
    while IFS=$'\t' read -r u h
    do
        # our own admin logins (and MySQL's internal threads) must not make 'root' look "in use"
        [[ "$u" =~ ^(root|debian-sys-maint|event_scheduler|system\ user)$ && "$h" =~ ^(localhost|127\.0\.0\.1|::1|\?|)$ ]] && continue
        record_seen mysql "$u" "$h"
    done < <(
        myq "SELECT USER, SUBSTRING_INDEX(HOST, ':', 1) FROM information_schema.PROCESSLIST
             WHERE USER NOT IN ('system user','event_scheduler','unauthenticated user') AND ID <> CONNECTION_ID()"
        # MySQL remembers every account that connected since it started
        [[ "$(myq 'SELECT @@performance_schema' 2>/dev/null)" == "1" ]] \
            && myq "SELECT USER, HOST FROM performance_schema.accounts WHERE USER IS NOT NULL AND TOTAL_CONNECTIONS > 0"
        # MariaDB does the same once userstat is on (mysql-lockdown.sh turns it on)
        [[ "$(mysql_flavor)" == "mariadb" ]] \
            && myq "SELECT USER, '?' FROM information_schema.USER_STATISTICS" 2>/dev/null
    )
}

mysql_health() { [[ "$(myq 'SELECT 1')" == "1" ]]; }

# ======================= PostgreSQL =======================

pg_connect() {
    have psql || return 1
    PG_PORT=""
    if have pg_lsclusters
    then
        PG_PORT=$(pg_lsclusters -h 2>/dev/null | awk '$4 == "online" {print $3; exit}')
        PG_VERSION=$(pg_lsclusters -h 2>/dev/null | awk '$4 == "online" {print $1; exit}')
        PG_CLUSTER=$(pg_lsclusters -h 2>/dev/null | awk '$4 == "online" {print $2; exit}')
    fi
    PG_PORT="${PG_PORT:-5432}"
    [[ "$(pgq 'SELECT 1')" == "1" ]]
}

# psql as the postgres Linux user ("peer" login, no password). -X = ignore .psqlrc
pgq() {
    (cd / && runuser -u postgres -- psql -X -qAt -F $'\t' -p "$PG_PORT" -d "${2:-postgres}" -c "$1") 2>>"$MARVIN_TMP/sql.err"
}
pgq_table() { (cd / && runuser -u postgres -- psql -X -q -p "$PG_PORT" -d "${2:-postgres}" -c "$1") 2>&1; }
pgq_try()   { (cd / && runuser -u postgres -- psql -X -qAt -F $'\t' -p "$PG_PORT" -d "${2:-postgres}" -c "$1") 2>&1; }

pg_databases() { pgq "SELECT datname FROM pg_database WHERE datallowconn AND NOT datistemplate ORDER BY 1"; }

# role<TAB>super<TAB>login<TAB>createrole<TAB>createdb<TAB>password(none|scram|md5)<TAB>member of
pg_users() {
    pgq "SELECT r.rolname, r.rolsuper, r.rolcanlogin, r.rolcreaterole, r.rolcreatedb,
                CASE WHEN a.rolpassword IS NULL THEN 'none' WHEN a.rolpassword LIKE 'SCRAM-SHA-256%' THEN 'scram'
                     WHEN a.rolpassword LIKE 'md5%' THEN 'md5' ELSE 'other' END,
                COALESCE((SELECT string_agg(g.rolname, ',') FROM pg_auth_members m JOIN pg_roles g ON g.oid = m.roleid
                          WHERE m.member = r.oid), '')
         FROM pg_roles r JOIN pg_authid a ON a.oid = r.oid
         WHERE r.rolname !~ '^pg_' ORDER BY 1"
}

pg_sessions() {
    pgq_table "SELECT pid, usename AS user, COALESCE(host(client_addr), 'local') AS client, datname AS db, state,
                      backend_start::timestamp(0) AS since, left(query, 50) AS query
               FROM pg_stat_activity WHERE pid <> pg_backend_pid() AND backend_type = 'client backend'
               ORDER BY backend_start"
}

pg_log_file() {
    have pg_lsclusters && pg_lsclusters -h 2>/dev/null | awk -v p="$PG_PORT" '$3 == p {print $7; exit}'
}

pg_seen_update() {
    local u h log
    while IFS=$'\t' read -r u h
    do
        # our own admin login (postgres over the local socket) must not count as "in use"
        [[ "$u" == "postgres" && "$h" =~ ^(local|\[local\]|127\.0\.0\.1|::1)$ ]] && continue
        record_seen postgres "$u" "$h"
    done < <(
        pgq "SELECT usename, COALESCE(host(client_addr), 'local') FROM pg_stat_activity
             WHERE backend_type = 'client backend' AND usename IS NOT NULL AND pid <> pg_backend_pid()"
        # with log_connections on, the log has "connection received: host=IP" then
        # "connection authorized: user=NAME" from the same [pid]
        log=$(pg_log_file)
        [[ -r "$log" ]] && tail -n 20000 "$log" | awk '
            match($0, /\[[0-9]+\]/) {pid = substr($0, RSTART, RLENGTH)}
            /connection received: host=/ {h = $0; sub(/.*host=/, "", h); sub(/ .*/, "", h); host[pid] = h}
            /connection authorized: user=/ {u = $0; sub(/.*user=/, "", u); sub(/ .*/, "", u)
                print u "\t" ((pid in host) ? host[pid] : "local")}' | sort -u
    )
}

pg_health() { [[ "$(pgq 'SELECT 1')" == "1" ]]; }

# ======================= Redis =======================

redis_conf_file() {
    local f
    f=$(rq INFO server 2>/dev/null | awk -F: '/^config_file:/ {sub(/\r$/, "", $2); print $2}')
    echo "${f:-/etc/redis/redis.conf}"
}

redis_connect() {
    local out pw
    have redis-cli || return 1
    REDIS_PORT=$(engine_ports redis | awk '{print $1}')
    REDIS_ARGS=(-h 127.0.0.1 -p "$REDIS_PORT")
    # our own admin user first (redis-lockdown.sh makes it), because the default user may be restricted
    if [[ -n "$REDIS_ADMIN_PASS" ]]
    then
        REDIS_USER="${REDIS_ADMIN_USER:-marvin}"; REDIS_PASS="$REDIS_ADMIN_PASS"
        [[ "$(rq PING)" == "PONG" ]] && { REDIS_AS="$REDIS_USER (saved in secrets.conf)"; return 0; }
    fi
    REDIS_USER=""; REDIS_PASS=""
    out=$(rq PING)
    if [[ "$out" == "PONG" ]]
    then
        REDIS_AS="the default user (NO password needed!)"; return 0
    fi
    pw=$(awk '$1 == "requirepass" {print $2}' /etc/redis/redis.conf 2>/dev/null | tail -n 1 | tr -d '"')
    if [[ -n "$pw" ]]
    then
        REDIS_PASS="$pw"
        [[ "$(rq PING)" == "PONG" ]] && { REDIS_AS="default user + requirepass from redis.conf"; return 0; }
    fi
    REDIS_PASS=""
    [[ "$MODE" == "interactive" ]] || return 1
    printf "${warn}  Redis wants a password.${reset}\n"
    read -r -u 3 -p "  Redis user [default] (type 'skip' to skip): " REDIS_USER
    [[ "$REDIS_USER" == "skip" ]] && { REDIS_USER=""; return 1; }
    [[ "$REDIS_USER" == "default" ]] && REDIS_USER=""
    read -r -s -u 3 -p "  password: " REDIS_PASS; echo
    [[ "$(rq PING)" == "PONG" ]] && { REDIS_AS="${REDIS_USER:-default} (typed in)"; return 0; }
    return 1
}

# the password goes in REDISCLI_AUTH (not on the command line). It must NOT be set at all when
# there is no password: an empty REDISCLI_AUTH makes redis-cli send AUTH "" and fail.
rq() {
    local auth=()
    [[ -n "$REDIS_PASS" ]] && auth=(env "REDISCLI_AUTH=$REDIS_PASS")
    if [[ -n "$REDIS_USER" ]]
    then
        "${auth[@]}" redis-cli "${REDIS_ARGS[@]}" --user "$REDIS_USER" --no-auth-warning "$@" 2>&1
    else
        "${auth[@]}" redis-cli "${REDIS_ARGS[@]}" --no-auth-warning "$@" 2>&1
    fi
}

redis_users()    { rq ACL LIST; }
redis_sessions() { rq CLIENT LIST | awk '{for (i = 1; i <= NF; i++) if ($i ~ /^(id|addr|user|age|idle|cmd|name)=/) printf "%s  ", $i; print ""}'; }
redis_seen_update() {
    local u h
    while read -r u h
    do
        record_seen redis "$u" "$h"
    done < <(rq CLIENT LIST | awk '{u = "default"; h = "?"
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^user=/) u = substr($i, 6)
            if ($i ~ /^addr=/) {h = substr($i, 6); sub(/:[0-9]+$/, "", h)}
        }
        if ($0 !~ /cmd=client\|list/) print u, h}')
}
redis_health() { [[ "$(rq PING)" == "PONG" ]]; }

# ======================= MongoDB =======================

mongo_connect() {
    local u p
    if have mongosh; then MONGO_SH=mongosh; elif have mongo; then MONGO_SH=mongo; else return 1; fi
    MONGO_PORT=$(engine_ports mongodb | awk '{print $1}')
    MONGO_USE_AUTH=""
    if [[ "$(mongo_js 'print(db.adminCommand({listDatabases: 1}).ok)' | tail -n 1)" == "1" ]]
    then
        MONGO_AS="no login (authorization is OFF - anyone can read everything!)"; return 0
    fi
    MONGO_USE_AUTH=1
    if [[ -n "$MONGO_ADMIN_USER" && "$(mongo_js 'print(db.adminCommand({listDatabases: 1}).ok)' | tail -n 1)" == "1" ]]
    then
        MONGO_AS="$MONGO_ADMIN_USER (saved in secrets.conf)"; return 0
    fi
    [[ "$MODE" == "interactive" ]] || return 1
    printf "${warn}  MongoDB wants a login (authorization is on). Use an admin user (look in the app configs).${reset}\n"
    read -r -u 3 -p "  MongoDB admin user (in the admin db) (type 'skip' to skip): " u
    [[ -z "$u" || "$u" == "skip" ]] && return 1
    read -r -s -u 3 -p "  password: " p; echo
    MONGO_ADMIN_USER="$u"; MONGO_ADMIN_PASS="$p"
    if [[ "$(mongo_js 'print(db.adminCommand({listDatabases: 1}).ok)' | tail -n 1)" == "1" ]]
    then
        set_secret MONGO_ADMIN_USER "$u"; set_secret MONGO_ADMIN_PASS "$p"
        MONGO_AS="$u (saved in secrets.conf)"; return 0
    fi
    return 1
}

# mongo_js 'JAVASCRIPT' - the password goes in a temp file, never on the command line
mongo_js() {
    local f="$MARVIN_TMP/m.js"
    {
        if [[ -n "$MONGO_USE_AUTH" && -n "$MONGO_ADMIN_USER" ]]
        then
            printf 'db.getSiblingDB("admin").auth(%s, %s);\n' "$(js_str "$MONGO_ADMIN_USER")" "$(js_str "$MONGO_ADMIN_PASS")"
        fi
        printf '%s\n' "$1"
    } > "$f"
    chmod 600 "$f"
    timeout 30 "$MONGO_SH" --quiet --norc "mongodb://127.0.0.1:$MONGO_PORT/admin" "$f" 2>&1
    rm -f "$f"
}

mongo_users() {
    mongo_js 'db.getSiblingDB("admin").system.users.find().forEach(function (u) {
        print(u.db + "\t" + u.user + "\t" + u.roles.map(function (r) { return r.role + "@" + r.db; }).join(","));
    });'
}

mongo_sessions() {
    mongo_js 'db.adminCommand({currentOp: 1, $all: true}).inprog.forEach(function (o) {
        if (!o.client) return;
        var who = (o.effectiveUsers || []).map(function (u) { return u.user + "@" + u.db; }).join(",") || "-";
        print([o.opid, who, o.client, o.appName || "", o.op || "", o.ns || "", o.secs_running || 0].join("  "));
    });'
}

mongo_log_file() {
    awk '/^ *path:/ {print $2; exit}' /etc/mongod.conf 2>/dev/null | tr -d '"' | grep . || echo /var/log/mongodb/mongod.log
}

mongo_seen_update() {
    local u h log
    while IFS=$'\t' read -r u h
    do
        record_seen mongodb "$u" "$h"
    done < <(
        # clients connected WITHOUT a login are recorded as "(no-login)": turning on authorization breaks them
        mongo_js 'var me = db.adminCommand({whatsmyuri: 1}).you;
        db.adminCommand({currentOp: 1, $all: true}).inprog.forEach(function (o) {
            if (!o.client || o.client === me || (o.desc || "").indexOf("conn") !== 0) return;
            var users = o.effectiveUsers || [];
            if (users.length === 0) print("(no-login)\t" + o.client.replace(/:[0-9]+$/, ""));
            users.forEach(function (u) { print(u.user + "\t" + o.client.replace(/:[0-9]+$/, "")); });
        });' | grep -P '^[^\t]+\t'
        log=$(mongo_log_file)
        if [[ -r "$log" ]]
        then
            tail -n 20000 "$log" > "$MARVIN_TMP/mlog"
            grep -E '"msg":"(Successfully authenticated|Authentication succeeded)"' "$MARVIN_TMP/mlog" \
                | sed -nE 's/.*"(client|remote)":"([^":]*)(:[0-9]+)?".*"user":"([^"]*)".*/\4\t\2/p' | sort -u > "$MARVIN_TMP/mauth"
            # IPs that connected but never logged in = login-less clients (localhost is skipped: that's us)
            grep '"msg":"Connection accepted"' "$MARVIN_TMP/mlog" | sed -nE 's/.*"remote":"([^":]*):[0-9]+".*/\1/p' | sort -u \
                | grep -vxE '127\.0\.0\.1|::1' | while read -r h
                do
                    cut -f2 "$MARVIN_TMP/mauth" | grep -qxF "$h" || printf '(no-login)\t%s\n' "$h"
                done
            cat "$MARVIN_TMP/mauth"
        fi
    )
}

mongo_health() { [[ "$(mongo_js 'print(db.adminCommand({ping: 1}).ok)' | tail -n 1)" == "1" ]]; }

# ======================= one line per account, every engine =======================

# db_snapshot ENGINE: "engine account<TAB>what it can do" (used for the baseline + the users view;
# password hashes are blanked so the line only changes when something real changes... or the password)
db_snapshot() {
    case "$1" in
        mysql)    mysql_users | awk -F'\t' '{print "mysql " $1 "@" $2 "\tlocked=" $5 " pw=" $4 " privs=" $6}' ;;
        postgres) pg_users | awk -F'\t' '{print "postgres " $1 "\tsuper=" $2 " login=" $3 " pw=" $6 " member=" $7}' ;;
        redis)    redis_users | awk '$1 == "user" {n = $2; $1 = $2 = ""; sub(/^ +/, ""); gsub(/#[0-9a-f]+/, "#pw"); print "redis " n "\t" $0}' ;;
        mongodb)  mongo_users | grep -P '\t' | awk -F'\t' '{print "mongodb " $1 "." $2 "\troles=" $3}' ;;
    esac
}

# ======================= dispatch =======================

db_connect()     { "$(db_prefix "$1")_connect"; }
db_users()       { "$(db_prefix "$1")_users"; }
db_sessions()    { "$(db_prefix "$1")_sessions"; }
db_seen_update() { "$(db_prefix "$1")_seen_update"; }
db_health()      { "$(db_prefix "$1")_health"; }
db_prefix() {
    case "$1" in
        mysql) echo mysql ;; postgres) echo pg ;; redis) echo redis ;; mongodb) echo mongo ;;
    esac
}
