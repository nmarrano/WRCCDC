#!/bin/bash
#
# backup.sh
#
# Backs up marvin BEFORE you change anything: /etc, plus a full dump of every
# database engine running here (MySQL/MariaDB, PostgreSQL, Redis, MongoDB).
# Everything goes to /root/marvin-data/backups/<time>/ (root only - the dumps
# hold customer data, and red team stealing a dump costs the same as stealing
# the database). A SHA256SUMS file shows later whether anyone touched them.
#
# Usage:
#   sudo ./backup.sh                 back up everything now
#   sudo ./backup.sh list            what backups exist
#   sudo ./backup.sh verify          check the checksums (did anyone change them?)
#   sudo ./backup.sh restore FILE    put ONE database dump back (asks first)
#   sudo ./backup.sh copy-out        how to copy the backups to your own computer
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/db.sh"

require_root
setup_dirs
load_conf
SCRIPT_NAME=backup

check_space() {
    local need=0 d avail
    for d in /etc /var/lib/mysql /var/lib/postgresql /var/lib/redis /var/lib/mongodb
    do
        [[ -d "$d" ]] && need=$(( need + $(du -sk "$d" 2>/dev/null | cut -f1) ))
    done
    avail=$(df --output=avail -k "$BACKUPS" | tail -n 1)
    printf "  data to back up: about %s MB, free space: %s MB\n" "$(( need / 1024 ))" "$(( avail / 1024 ))"
    if (( avail < need ))
    then
        flag "probably NOT enough disk space - a full disk can crash the databases!"
        confirm_risky "Back up anyway?" || exit 1
    fi
}

backup_now() {
    local dir out e
    banner "backup.sh  -  everything on marvin"
    check_space
    dir="$BACKUPS/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dir" && chmod 700 "$dir"

    step "/etc (every config file)"
    tar czf "$dir/etc.tgz" -C / etc 2>/dev/null && ok "etc.tgz" || flag "tar of /etc failed"

    for e in $(detect_engines)
    do
        case "$e" in
            mysql)
                step "MySQL / MariaDB"
                if mysql_connect
                then
                    # --single-transaction: a consistent copy without locking the apps out
                    mysqldump "${MYSQL_ARGS[@]}" --all-databases --single-transaction --routines --triggers --events \
                        --hex-blob 2>"$MARVIN_TMP/err" | gzip > "$dir/mysql-all.sql.gz"
                    if [[ "${PIPESTATUS[0]}" == "0" ]]
                    then
                        ok "mysql-all.sql.gz ($(du -h "$dir/mysql-all.sql.gz" | cut -f1)) - logged in as $MYSQL_AS"
                    else
                        flag "mysqldump failed: $(head -c 300 "$MARVIN_TMP/err")"
                    fi
                else
                    flag "could not log in to MySQL - NOT backed up"
                fi ;;
            postgres)
                step "PostgreSQL"
                if pg_connect
                then
                    (cd / && runuser -u postgres -- pg_dumpall -p "$PG_PORT") 2>"$MARVIN_TMP/err" | gzip > "$dir/pg-all.sql.gz"
                    if [[ "${PIPESTATUS[0]}" == "0" ]]
                    then
                        ok "pg-all.sql.gz ($(du -h "$dir/pg-all.sql.gz" | cut -f1))"
                    else
                        flag "pg_dumpall failed: $(head -c 300 "$MARVIN_TMP/err")"
                    fi
                else
                    flag "could not log in to PostgreSQL - NOT backed up"
                fi ;;
            redis)
                step "Redis"
                if redis_connect
                then
                    before=$(rq LASTSAVE)
                    out=$(rq BGSAVE)
                    for _ in $(seq 1 30)
                    do
                        [[ "$(rq LASTSAVE)" != "$before" ]] && break
                        sleep 1
                    done
                    f="$(rq CONFIG GET dir | sed -n 2p)/$(rq CONFIG GET dbfilename | sed -n 2p)"
                    [[ "$f" == "/" ]] && f=/var/lib/redis/dump.rdb
                    if [[ -f "$f" ]] && cp "$f" "$dir/redis-dump.rdb"
                    then
                        ok "redis-dump.rdb ($(du -h "$dir/redis-dump.rdb" | cut -f1))"
                    else
                        flag "Redis save/copy failed ($out, file $f)"
                    fi
                else
                    flag "could not log in to Redis - NOT backed up"
                fi ;;
            mongodb)
                step "MongoDB"
                if ! have mongodump
                then
                    flag "mongodump is not installed (mongodb-database-tools) - NOT backed up"
                    explain "Fallback: copy /var/lib/mongodb while mongod is stopped (downtime!)."
                elif mongo_connect
                then
                    # the password goes in a config file, not on the command line
                    printf 'uri: mongodb://127.0.0.1:%s/\n' "$MONGO_PORT" > "$MARVIN_TMP/md.yaml"
                    [[ -n "$MONGO_USE_AUTH" ]] && printf 'password: %s\n' "$MONGO_ADMIN_PASS" >> "$MARVIN_TMP/md.yaml"
                    chmod 600 "$MARVIN_TMP/md.yaml"
                    if mongodump --config="$MARVIN_TMP/md.yaml" ${MONGO_USE_AUTH:+--username="$MONGO_ADMIN_USER" --authenticationDatabase=admin} \
                        --archive="$dir/mongo-all.archive.gz" --gzip --quiet 2>"$MARVIN_TMP/err"
                    then
                        ok "mongo-all.archive.gz ($(du -h "$dir/mongo-all.archive.gz" | cut -f1))"
                    else
                        flag "mongodump failed: $(head -c 300 "$MARVIN_TMP/err")"
                    fi
                else
                    flag "could not log in to MongoDB - NOT backed up"
                fi ;;
        esac
    done

    (cd "$dir" && sha256sum -- * > SHA256SUMS)
    chmod 600 "$dir"/*
    did "BACKUP made in $dir ($(du -sh "$dir" | cut -f1))"
    printf "\n"
    ls -la "$dir" | sed 's/^/  /'
    explain "Copy it off the box too (red team can delete it):  ./backup.sh copy-out"
}

list_backups() {
    local d
    section "BACKUPS"
    for d in "$BACKUPS"/*/
    do
        [[ -d "$d" ]] || continue
        printf "  ${bold}%s${reset}  %s\n" "$(basename "$d")" "$(du -sh "$d" | cut -f1)"
        ls "$d" | grep -v SHA256SUMS | sed 's/^/      /'
    done
    printf "\n  free space: %s\n" "$(df -h --output=avail "$BACKUPS" | tail -n 1)"
}

verify_backups() {
    local d
    section "ARE THE BACKUPS UNTOUCHED?"
    for d in "$BACKUPS"/*/
    do
        [[ -f "$d/SHA256SUMS" ]] || continue
        if (cd "$d" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1)
        then
            ok "$(basename "$d")"
        else
            flag "$(basename "$d") was CHANGED since it was made:"
            (cd "$d" && sha256sum -c SHA256SUMS 2>&1 | grep -v ': OK$' | sed 's/^/      /')
        fi
    done
}

restore() {
    local f="$1"
    [[ -f "$f" ]] || { flag "no such file: $f   (see ./backup.sh list)"; exit 1; }
    MODE=interactive
    section "RESTORE $(basename "$f")"
    explain "This puts the data back the way it was WHEN THE BACKUP WAS MADE. Anything changed since"
    explain "(new orders, new posts) is lost, and accounts/passwords go back to that time too -"
    explain "re-run the lockdown afterwards. Make a fresh backup first if the current data matters."
    case "$f" in
        *mysql*.sql.gz)
            mysql_connect || { flag "can't log in to MySQL"; exit 1; }
            confirm_risky "Load $f into MySQL now?" || exit 0
            gunzip -c "$f" | mysql "${MYSQL_ARGS[@]}" && did "RESTORED MySQL from $f" || flag "restore failed" ;;
        *pg*.sql.gz)
            pg_connect || { flag "can't log in to PostgreSQL"; exit 1; }
            explain "Objects that already exist give 'already exists' errors - that is normal."
            confirm_risky "Load $f into PostgreSQL now?" || exit 0
            gunzip -c "$f" | (cd / && runuser -u postgres -- psql -X -q -p "$PG_PORT" -d postgres) 2>&1 | grep -v 'already exists' | tail -n 20
            did "RESTORED PostgreSQL from $f" ;;
        *redis*.rdb)
            confirm_risky "Stop Redis, put $f back as /var/lib/redis/dump.rdb and start it again?" || exit 0
            systemctl stop redis-server && cp "$f" /var/lib/redis/dump.rdb && chown redis:redis /var/lib/redis/dump.rdb \
                && systemctl start redis-server && did "RESTORED Redis from $f" ;;
        *mongo*.archive.gz)
            mongo_connect || { flag "can't log in to MongoDB"; exit 1; }
            explain "--drop: each collection in the backup REPLACES the current one."
            confirm_risky "Restore MongoDB from $f (with --drop)?" || exit 0
            printf 'uri: mongodb://127.0.0.1:%s/\n' "$MONGO_PORT" > "$MARVIN_TMP/md.yaml"
            [[ -n "$MONGO_USE_AUTH" ]] && printf 'password: %s\n' "$MONGO_ADMIN_PASS" >> "$MARVIN_TMP/md.yaml"
            mongorestore --config="$MARVIN_TMP/md.yaml" ${MONGO_USE_AUTH:+--username="$MONGO_ADMIN_USER" --authenticationDatabase=admin} \
                --archive="$f" --gzip --drop && did "RESTORED MongoDB from $f" ;;
        *etc.tgz)
            explain "Don't restore all of /etc at once. Pull out the one file you need, e.g.:"
            explain "  tar xzf $f -C /tmp etc/ssh/sshd_config && diff /tmp/etc/ssh/sshd_config /etc/ssh/sshd_config"
            explain "  cp /tmp/etc/ssh/sshd_config /etc/ssh/sshd_config" ;;
        *) flag "don't know how to restore $f" ;;
    esac
}

copy_out() {
    section "COPY THE BACKUPS TO YOUR OWN COMPUTER"
    explain "From YOUR computer (on the VPN), with your marvin login:"
    printf "\n    ssh %s@192.168.220.199 'sudo tar czf - -C %s .' > marvin-backups-\$(date +%%H%%M).tgz\n\n" "${ME:-USER}" "$BACKUPS"
    explain "Keep that file private - it holds the customer data."
}

case "$1" in
    ""|now) backup_now ;;
    list) list_backups ;;
    verify) verify_backups ;;
    restore) restore "$2" ;;
    copy-out) copy_out ;;
    -h|--help) usage_from_header ;;
    *) printf "${error}Unknown option: %s${reset}\n\n" "$1"; usage_from_header; exit 1 ;;
esac
exit 0
