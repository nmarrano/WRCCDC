#!/bin/bash
#
# mongodb-lockdown.sh
#
# Locks down MongoDB on marvin. MongoDB's classic hole is authorization being OFF:
# then anyone who reaches port 27017 reads, changes or deletes every database
# without a login. This script shows who connects (and whether they log in),
# checks the users and their roles, and can turn authorization on safely: it makes
# its own admin login first, edits /etc/mongod.conf, restarts mongod and puts the
# old config back if mongod doesn't come up.
#
# It NEVER drops a user. Users in PROTECTED_DB_USERS or SEEN logging in are never
# touched. Unknown admin users only lose their roles (saved first, undo printed).
# Turning authorization on and changing passwords are always a human decision.
#
# Usage:
#   sudo ./mongodb-lockdown.sh               every step, asks before each change
#   sudo ./mongodb-lockdown.sh --auto        safe fixes by itself, risky ones -> TODO.txt
#   sudo ./mongodb-lockdown.sh --audit       look only, change nothing
#   sudo ./mongodb-lockdown.sh STEP...       only these steps:
#        info users auth config files connections
#   sudo ./mongodb-lockdown.sh rotate        change one user's password (coordinate first!)
#   sudo ./mongodb-lockdown.sh seen [MIN]    watch logins for MIN minutes (default 5)
#
# Marvin (database server) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
. "$SCRIPT_DIR/lib/db.sh"

STEPS="info users auth config files connections"
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

MONGO_CONF=/etc/mongod.conf
ADMIN_ROLES='^(root|__system|userAdminAnyDatabase|dbAdminAnyDatabase|readWriteAnyDatabase|readAnyDatabase|clusterAdmin|clusterManager|hostManager|restore|backup)@|^(userAdmin|dbOwner|readWrite)@admin$'

mopt() { awk -F'\t' -v k="$1" '$1 == k {print $2}' "$MARVIN_TMP/opts"; }

load_opts() {
    mongo_js 'var p = db.adminCommand({getCmdLineOpts: 1}).parsed, s = p.security || {}, n = p.net || {};
        print("version\t" + db.version());
        print("config file\t" + (p.config || "-"));
        print("bindIp\t" + (n.bindIpAll ? "ALL (bindIpAll)" : (n.bindIp || "localhost (default)")));
        print("port\t" + (n.port || 27017));
        print("authorization\t" + (s.authorization || "disabled"));
        print("javascriptEnabled\t" + (s.javascriptEnabled === false ? "false" : "true"));
        print("dbPath\t" + ((p.storage || {}).dbPath || "-"));
        print("log\t" + ((p.systemLog || {}).path || "-"));' | grep -P '\t' > "$MARVIN_TMP/opts"
}

step_info() {
    section "WHAT IS RUNNING"
    printf "  logged in as: %s\n\n" "$MONGO_AS"
    awk -F'\t' '{printf "      %-20s %s\n", $1, $2}' "$MARVIN_TMP/opts"
    printf "\n  databases:\n"
    mongo_js 'db.adminCommand({listDatabases: 1}).databases.forEach(function (d) { print("      " + d.name + "  (" + Math.round(d.sizeOnDisk / 1024) + " KB)"); });'
    case "$(mopt bindIp)" in
        *0.0.0.0*|ALL*) caution "mongod listens on every address - fine if apps on other boxes use it" ;;
        *) explain "mongod only listens on $(mopt bindIp): apps on OTHER boxes can't reach it." ;;
    esac
    docker_db_warning
}

step_users() {
    local db user roles bad
    section "USERS AND ROLES"
    explain "Every MongoDB user is stored in admin.system.users. root / userAdminAnyDatabase /"
    explain "readWriteAnyDatabase etc. reach EVERY database. Apps should only have readWrite on their own."
    [[ "$(mopt authorization)" == "enabled" ]] \
        || caution "authorization is OFF, so right now users don't even matter - nobody needs to log in (auth step)"
    mongo_seen_update
    mongo_users > "$MARVIN_TMP/musers"
    printf "  ${bold}%-12s %-18s %-12s %s${reset}\n" DATABASE USER STATUS ROLES
    while IFS=$'\t' read -r db user roles
    do
        printf "  %-12s %-18s %-12s %s\n" "$db" "$user" "$(is_protected_db mongodb "$user" && echo PROTECTED || echo unknown)" "$roles"
    done < "$MARVIN_TMP/musers"
    [[ -s "$MARVIN_TMP/musers" ]] || caution "no users at all"
    explain "Seen so far: $(awk '{print $1 "(" $2 ")"}' "$SEEN_DIR/mongodb.txt" 2>/dev/null | sort -u | paste -sd' ' -)"

    while IFS=$'\t' read -r db user roles
    do
        [[ "$user" == "${MONGO_ADMIN_USER:-marvinAdmin}" ]] && continue
        bad=$(tr ',' '\n' <<< "$roles" | grep -E "$ADMIN_ROLES" | paste -sd, -)
        [[ -z "$bad" ]] && continue
        if is_protected_db mongodb "$user"
        then
            caution "'$user' ($db) has wide roles ($bad) but is in use - left alone"
            continue
        fi
        flag "'$user' ($db) has admin-level roles ($bad) and nobody was seen using it"
        explain "Could be red team's - or an app/scorer that hasn't logged in yet. Check the app configs"
        explain "(MONGO_URL / mongodb://USER:PASS@...) for this name first."
        confirm_risky "Take ALL roles away from '$user' ($db)? (saved first, undo printed)" && strip_roles "$db" "$user" "$roles"
    done < "$MARVIN_TMP/musers"
}

strip_roles() {   # strip_roles DB USER "role@db,role@db"
    local out
    new_evidence "mongo-user-$2"
    printf '%s\t%s\t%s\n' "$1" "$2" "$3" > "$EV/roles.txt"
    out=$(mongo_js "var d = db.getSiblingDB($(js_str "$1")), u = d.getUser($(js_str "$2"));
        d.revokeRolesFromUser($(js_str "$2"), u.roles); print('ok');")
    if [[ "$out" == *ok* ]]
    then
        did "REVOKED all roles from MongoDB user $2 ($1): $3" "db.getSiblingDB('$1').grantRolesToUser('$2', <roles in $EV/roles.txt>)"
        mongo_js "db.adminCommand({killAllSessionsByPattern: [{users: [{user: $(js_str "$2"), db: $(js_str "$1")}]}]})" >/dev/null
    else
        flag "could not revoke roles from $2: $out"
    fi
}

step_auth() {
    local nologin pw out i
    section "AUTHORIZATION (logins required?)"
    if [[ "$(mopt authorization)" == "enabled" ]]
    then
        ok "authorization is enabled - everyone has to log in"
        return
    fi
    flag "authorization is OFF: anyone who reaches port $(mopt port) can read, change and DELETE every database"
    explain "Turning it on: (1) make an admin login for marvin, (2) set 'security: authorization: enabled'"
    explain "in $MONGO_CONF, (3) restart mongod. After that every client must log in."
    explain "Apps that connect WITHOUT a username/password then FAIL - their owners must add a login"
    explain "(mongodb://USER:PASS@192.168.220.199/DB) to the app config first. The scorer too (PCR)."
    nologin=$(awk '$1 == "(no-login)" {print $2}' "$SEEN_DIR/mongodb.txt" 2>/dev/null | sort -u | paste -sd' ' -)
    if [[ -n "$nologin" ]]
    then
        flag "clients seen connecting WITHOUT a login (they break when auth goes on): $nologin"
    else
        explain "No login-less clients seen yet - run './mongodb-lockdown.sh seen 5' to be sure."
    fi
    confirm_risky "Turn MongoDB authorization ON now (restarts mongod; login-less apps will break)?" || return

    if [[ -z "$MONGO_ADMIN_USER" ]]
    then
        pw=$(gen_password 24)
        out=$(mongo_js "var a = db.getSiblingDB('admin');
            if (a.getUser('marvinAdmin')) { a.updateUser('marvinAdmin', {pwd: $(js_str "$pw"), roles: ['root']}); }
            else { a.createUser({user: 'marvinAdmin', pwd: $(js_str "$pw"), roles: ['root']}); }
            print('ok');")
        [[ "$out" == *ok* ]] || { flag "could not create the marvinAdmin user: $out"; return; }
        set_secret MONGO_ADMIN_USER marvinAdmin
        set_secret MONGO_ADMIN_PASS "$pw"
        MONGO_ADMIN_USER=marvinAdmin; MONGO_ADMIN_PASS="$pw"
        did "CREATED MongoDB admin user marvinAdmin (root role, password in $SECRETS)"
    fi

    backup_file "$MONGO_CONF"
    cp "$MONGO_CONF" "$MARVIN_TMP/mongod.conf.before"
    if grep -qE '^security:' "$MONGO_CONF"
    then
        if grep -qE '^\s+authorization:' "$MONGO_CONF"
        then
            sed -i -E 's/^(\s+)authorization:.*/\1authorization: enabled/' "$MONGO_CONF"
        else
            sed -i -E 's/^security:.*/security:\n  authorization: enabled/' "$MONGO_CONF"
        fi
    else
        printf '\nsecurity:\n  authorization: enabled\n' >> "$MONGO_CONF"
    fi
    systemctl restart mongod
    MONGO_USE_AUTH=1
    for i in $(seq 1 40)
    do
        mongo_health && break
        sleep 1
    done
    if mongo_health
    then
        did "AUTHORIZATION ENABLED in $MONGO_CONF, mongod restarted - logins now required" \
            "cp $EVIDENCE/before-edit-*/*mongod.conf $MONGO_CONF && systemctl restart mongod"
        todo "MongoDB auth is ON: every app/scorer needs a user+password in its connection string now"
        load_opts
    else
        flag "mongod did not come back with authorization on - putting the old config back"
        cp "$MARVIN_TMP/mongod.conf.before" "$MONGO_CONF"
        systemctl restart mongod
        MONGO_USE_AUTH=""
        journalctl -u mongod -n 10 --no-pager 2>/dev/null | sed 's/^/      /'
    fi
}

step_config() {
    local db n
    section "SETTINGS AND STORED CODE"
    if [[ "$(mopt javascriptEnabled)" == "true" ]]
    then
        caution "server-side JavaScript is on (\$where, mapReduce, \$function) - used in NoSQL injection"
        explain "Turning it off (security: javascriptEnabled: false + restart) breaks apps that use \$where."
        todo "Consider security.javascriptEnabled: false in $MONGO_CONF if no app uses \$where/mapReduce"
    fi
    if grep -qE '^\s*(enableLocalhostAuthBypass|authenticationMechanisms)' "$MONGO_CONF" 2>/dev/null
    then
        flag "$MONGO_CONF changes login behaviour:"
        grep -nE '^\s*(enableLocalhostAuthBypass|authenticationMechanisms)' "$MONGO_CONF" | sed 's/^/      /'
    fi
    step "Stored JavaScript (system.js) in each database"
    for db in $(mongo_js 'db.adminCommand({listDatabases: 1}).databases.forEach(function (d) { print(d.name); });')
    do
        n=$(mongo_js "print(db.getSiblingDB($(js_str "$db")).getCollection('system.js').countDocuments({}))" | tail -n 1)
        [[ "$n" =~ ^[0-9]+$ ]] && (( n > 0 )) || continue
        flag "database $db has $n stored JavaScript function(s):"
        mongo_js "db.getSiblingDB($(js_str "$db")).getCollection('system.js').find().forEach(function (f) { print('      ' + f._id + ': ' + String((f.value && f.value.code) || f.value).replace(/\\s+/g, ' ').slice(0, 150)); });"
        todo "Read the stored JavaScript in MongoDB database $db (system.js) - remove it if no app uses it"
    done
    ok "stored JavaScript checked"
}

step_files() {
    local f
    section "FILES ON THE BOX"
    step "Files written BY mongodb outside its folders"
    files_written_by mongodb '^(/var/lib/mongodb|/var/log/mongodb|/run/mongodb|/var/run/mongodb)/' > "$MARVIN_TMP/mfiles"
    [[ -s "$MARVIN_TMP/mfiles" ]] || ok "none"
    while read -r f
    do
        flag "file owned by mongodb: $f"
        confirm_safe "Quarantine $f?" && quarantine "$f" "file written by mongod"
    done < "$MARVIN_TMP/mfiles"
    if [[ -f "$MONGO_CONF" && "$(stat -c %a "$MONGO_CONF")" =~ [2367]$ ]]
    then
        flag "$MONGO_CONF can be changed by everyone"
        confirm_safe "chmod o-w $MONGO_CONF?" && chmod o-w "$MONGO_CONF" && did "PERMISSIONS o-w on $MONGO_CONF"
    fi
    step "Shell history (createUser / pwd: lines)"
    for f in /root/.mongosh/mongosh_repl_history /home/*/.mongosh/mongosh_repl_history /root/.dbshell /home/*/.dbshell
    do
        [[ -s "$f" ]] || continue
        if grep -qiE 'pwd|password|createUser|auth\(' "$f"
        then
            flag "$f has passwords in it"
            confirm_safe "Save a copy to evidence and empty $f?" && { new_evidence "mongo-history"; cp -a "$f" "$EV/"; : > "$f"; did "EMPTIED $f (copy in $EV)"; }
        fi
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
    mongo_seen_update
    printf "  opid  user  client  app  op  namespace  seconds\n"
    mongo_sessions | sed 's/^/  /'
    explain "Seen so far ((no-login) = connected without a username):"
    awk '{printf "      %-20s from %-18s first seen %s\n", $1, $2, $3}' "$SEEN_DIR/mongodb.txt" 2>/dev/null
}

step_seen() {
    local mins="${EXTRA:-5}" end before
    section "LEARNING WHO CONNECTS (${mins} min)"
    end=$(( $(date +%s) + mins * 60 ))
    while (( $(date +%s) < end ))
    do
        before=$(cat "$SEEN_DIR/mongodb.txt" 2>/dev/null)
        mongo_seen_update
        diff <(printf '%s\n' "$before") "$SEEN_DIR/mongodb.txt" 2>/dev/null | sed -n 's/^> /  NEW: /p'
        sleep 3
    done
    printf "\n"; awk '{printf "  %-20s from %-18s first seen %s\n", $1, $2, $3}' "$SEEN_DIR/mongodb.txt" 2>/dev/null
}

step_rotate() {
    local i=0 sel db user roles newpw out
    section "CHANGE A USER'S PASSWORD"
    explain "Tell the app owner FIRST: the app's connection string (mongodb://USER:PASS@...) must get the"
    explain "new password right after. If the scorer logs in as this user, file a PCR in Quotient."
    [[ "$MODE" == "interactive" ]] || { caution "rotate only works interactively"; return; }
    mongo_users > "$MARVIN_TMP/musers"
    while IFS=$'\t' read -r db user roles
    do
        i=$((i + 1))
        printf "  %2d) %-12s %-18s %s\n" "$i" "$db" "$user" "$roles"
    done < "$MARVIN_TMP/musers"
    ask_text "Number of the user to change (Enter = cancel): "; sel="$REPLY"
    [[ "$sel" =~ ^[0-9]+$ ]] || return
    IFS=$'\t' read -r db user roles < <(sed -n "${sel}p" "$MARVIN_TMP/musers")
    [[ -n "$user" ]] || return
    newpw=$(gen_password 16)
    ask_text "New password for '$user' (Enter = $newpw): "; newpw="${REPLY:-$newpw}"
    confirm_risky "Change the password of '$user' ($db) NOW (the app owner is ready)?" || return
    out=$(mongo_js "db.getSiblingDB($(js_str "$db")).changeUserPassword($(js_str "$user"), $(js_str "$newpw")); print('ok');")
    if [[ "$out" == *ok* ]]
    then
        did "PASSWORD changed for MongoDB user $user ($db)"
        printf "\n  ${bold}new password for '%s': ${info}%s${reset}\n" "$user" "$newpw"
        [[ "$user" == "$MONGO_ADMIN_USER" ]] && set_secret MONGO_ADMIN_PASS "$newpw"
        is_protected_db mongodb "$user" && printf "  ${warn}-> it is in use: if the SCORER uses it, file a PCR in Quotient NOW${reset}\n"
        todo "Make sure the app using MongoDB user '$user' has the new password (changed $(date +%H:%M))"
    else
        flag "password change failed: $out"
    fi
}

banner "mongodb-lockdown.sh  -  MongoDB on marvin"
if ! mongo_connect
then
    flag "Can't log in to MongoDB on 127.0.0.1:${MONGO_PORT:-27017}. Running?  systemctl status mongod"
    explain "With authorization on you need an admin login: run this interactively and type it."
    exit 1
fi
load_opts
printf "  MongoDB %s on port %s, logged in as %s\n" "$(mopt version)" "$(mopt port)" "$MONGO_AS"
[[ "$RUN" == "$STEPS" ]] && todo_reset
log_action "START mongodb-lockdown mode=$MODE steps=$RUN"
for s in $RUN
do
    "step_$s"
done
log_action "END mongodb-lockdown"
printf "\n${bold}${info}mongodb-lockdown finished.${reset}  changes: %s   TODO: %s\n" "$ACTIONS" "$TODO_FILE"
exit 0
