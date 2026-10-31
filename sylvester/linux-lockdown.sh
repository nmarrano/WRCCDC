#!/bin/bash
#
# linux-lockdown.sh
#
# Locks down the Linux side of sylvester (Rocky Linux 9): passwords, accounts, sudo, SSH
# keys, the SSH server, persistence (cron, systemd, login scripts, PAM, motd,
# apt hooks...), SUID files, running processes, listening ports and changed
# system programs. Every step says what it checks and why.
#
# It NEVER deletes a user. Suspicious accounts are LOCKED (the undo command is
# printed), and root, you, and PROTECTED_LINUX_USERS in sylvester.conf (the
# scorer's account, teammates) are never locked at all. Files are MOVED into
# /root/sylvester-data/evidence/, never deleted.
#
# Usage:
#   sudo ./linux-lockdown.sh                  every step, asks before each change
#   sudo ./linux-lockdown.sh --auto           does the SAFE fixes by itself, risky ones -> TODO.txt
#   sudo ./linux-lockdown.sh --audit          look only, change nothing
#   sudo ./linux-lockdown.sh STEP [STEP...]   only these steps:
#        passwords accounts sudo keys sshd selinux persistence suid processes network integrity
#
# Sylvester (video streamer, Rocky Linux) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"

STEPS="passwords accounts sudo keys sshd selinux persistence suid processes network integrity"
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

step_passwords() {
    local u pw p
    section "PASSWORDS"
    explain "Every team got the same image, so red team already knows every default password."
    explain "Change root and your own account FIRST, then the other real accounts."
    explain "If the SCORER logs in as an account (see the scoring page), change it here AND submit a"
    explain "Password Change Request in Quotient (scoring.wccomps.org) with the SAME new password."
    explain "Write every new password in the team password sheet - never in #general."
    if [[ "$MODE" != "interactive" ]]
    then
        caution "Passwords are only changed in interactive mode."
        todo "Change Linux passwords: root, your account, then every login account (scored ones need a PCR in Quotient)"
        return
    fi
    for u in $(login_users)
    do
        pw=$(gen_password 16)
        printf "\n  ${bold}%s${reset}   %s\n" "$u" "$(is_protected_linux "$u" && echo "(protected - if the scorer uses it, file a PCR!)")"
        if [[ "$u" == "root" || "$u" == "$ME" ]]
        then
            confirm_safe "Change the password for '$u'?" || continue
        else
            confirm_risky "Change the password for '$u'?" || continue
        fi
        printf "  suggested: ${info}%s${reset}\n" "$pw"
        read -r -s -u 3 -p "  type a new password, or press Enter to use the suggested one: " p; echo
        p="${p:-$pw}"
        if printf '%s:%s\n' "$u" "$p" | chpasswd
        then
            did "PASSWORD changed for Linux account $u"
            printf "  ${bold}%s's new password: ${info}%s${reset}   <- put it in the team sheet NOW\n" "$u" "$p"
            in_list "$u" "$PROTECTED_LINUX_USERS" && todo "PCR in Quotient for Linux user $u (password changed $(date +%H:%M))"
        else
            flag "chpasswd failed for $u"
        fi
    done
}

step_accounts() {
    local u uid groups shell home born g members m
    section "ACCOUNTS"
    explain "Red team adds accounts, gives an account UID 0 (= root), or adds it to admin groups."
    explain "Nothing is deleted. LOCKING stops the password AND SSH keys and kills its programs."
    explain "Undo a lock:  usermod -U -e '' USER"
    explain "Never locked: root, ${ME:-you}, and PROTECTED_LINUX_USERS = '${PROTECTED_LINUX_USERS:-<empty>}'"
    [[ -z "$PROTECTED_LINUX_USERS" ]] && caution "PROTECTED_LINUX_USERS is empty - put the scorer's SSH user in $CONF"

    step "Every account that can log in"
    printf "  ${bold}%-16s %-6s %-34s %-18s %s${reset}\n" USER UID GROUPS SHELL "HOME CREATED"
    for u in $(login_users)
    do
        uid=$(id -u "$u"); groups=$(id -nG "$u" 2>/dev/null | tr ' ' ','); shell=$(getent passwd "$u" | cut -d: -f7)
        home=$(getent passwd "$u" | cut -d: -f6)
        born=$(stat -c '%w' "$home" 2>/dev/null | cut -c1-16); [[ "$born" == "-" || -z "$born" ]] && born=$(stat -c '%y' "$home" 2>/dev/null | cut -c1-16)
        printf "  %-16s %-6s %-34s %-18s %s%s\n" "$u" "$uid" "${groups:0:34}" "$shell" "${born:-?}" \
            "$(is_protected_linux "$u" && echo '   <- protected')"
    done

    step "UID 0 accounts (a second root)"
    for u in $(awk -F: '$3 == 0 && $1 != "root" {print $1}' /etc/passwd)
    do
        flag "'$u' has UID 0 - it IS root under another name"
        if is_protected_linux "$u"
        then
            caution "'$u' is in PROTECTED_LINUX_USERS, so it is not locked. Are you sure that's right?"
            todo "Linux account $u has UID 0 but is protected - double-check"
        else
            confirm_safe "Lock '$u'?" && lock_user "$u" "UID 0 duplicate of root"
        fi
    done
    ok "UID 0 check done"

    step "Accounts with an EMPTY password (log in with no password at all)"
    for u in $(awk -F: '$2 == "" {print $1}' /etc/shadow)
    do
        flag "'$u' has an EMPTY password"
        if is_protected_linux "$u"
        then
            todo "Set a password for $u (it is empty) - and PCR it if the scorer uses it"
            confirm_risky "Set a random password for '$u' now?" && {
                m=$(gen_password 16); printf '%s:%s\n' "$u" "$m" | chpasswd && did "PASSWORD set for $u (was empty)"
                printf "  ${bold}%s's new password: ${info}%s${reset}\n" "$u" "$m"; }
        else
            confirm_safe "Lock '$u'?" && lock_user "$u" "empty password"
        fi
    done
    ok "empty password check done"

    step "Service accounts that were given a login shell"
    explain "Accounts below UID 1000 (apache, nginx, jellyfin, daemon...) never need to log in. Red team gives"
    explain "them /bin/bash so they can use them as a backdoor. (postgres normally has bash - skipped.)"
    while IFS=: read -r u _ uid _ _ _ shell
    do
        (( uid > 0 && uid < 1000 )) || continue
        [[ "$u" == "postgres" || "$shell" =~ (nologin|false|sync|shutdown|halt)$ ]] && continue
        flag "service account '$u' (UID $uid) has shell $shell"
        if is_protected_linux "$u"
        then
            caution "protected - left alone"
        elif confirm_safe "Set '$u' shell to /usr/sbin/nologin?"
        then
            usermod -s /usr/sbin/nologin "$u" && did "SHELL of $u set to nologin" "usermod -s $shell $u"
        fi
    done < /etc/passwd
    ok "service account check done"

    step "Normal accounts (UID 1000+) that are not protected"
    explain "These could be real teammates, the scorer, or red team. Lock only if you are SURE."
    for u in $(login_users)
    do
        uid=$(id -u "$u")
        (( uid >= 1000 )) || continue
        is_protected_linux "$u" && continue
        [[ "$(passwd -S "$u" 2>/dev/null | awk '{print $2}')" == "L" ]] && continue     # already locked
        printf "\n  ${warn}%s${reset}  uid=%s groups=%s\n" "$u" "$uid" "$(id -nG "$u" | tr ' ' ',')"
        printf "      last logins: %s\n" "$(last -n 3 "$u" 2>/dev/null | grep -v '^$\|wtmp' | awk '{print $3, $4, $5, $6, $7}' | paste -sd';' -)"
        printf "      running now: %s programs\n" "$(pgrep -u "$u" | wc -l)"
        confirm_risky "Lock '$u'? (only if nobody - scorer or teammate - uses it)" && lock_user "$u" "unknown account"
    done

    step "Admin-level groups"
    explain "wheel/sudo = full root. docker and disk = root in one command. Rocky's first admin is in wheel."
    for g in sudo admin wheel lxd docker disk shadow root
    do
        members=$(getent group "$g" | cut -d: -f4 | tr ',' ' ')
        [[ -z "$members" ]] && continue
        printf "  %-8s %s\n" "$g:" "$members"
        for m in $members
        do
            [[ "$m" == "root" || "$m" == "$ME" ]] && continue
            if is_protected_linux "$m"
            then
                [[ "$g" =~ ^(lxd|docker|disk|shadow)$ ]] && caution "protected '$m' is in '$g' (root-equivalent) - fine if that's the competition login"
                continue
            fi
            flag "'$m' (not protected) is in admin group '$g'"
            confirm_risky "Remove '$m' from group '$g'?" && gpasswd -d "$m" "$g" >/dev/null && did "REMOVED $m from group $g" "gpasswd -a $m $g"
        done
    done
}

step_sudo() {
    local f line std tmpf
    section "SUDO RULES"
    explain "Rocky's normal rules: root ALL and %wheel ALL, plus 'Defaults' lines and"
    explain "@includedir /etc/sudoers.d. Anything else, and every NOPASSWD, was added by someone."
    std='^(Defaults([:@!>][^ ]*)?[[:space:]]|root[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+ALL$|%admin[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+ALL$|%sudo[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+ALL$|%wheel[[:space:]]+ALL=\(ALL(:ALL)?\)[[:space:]]+ALL$|[@#]includedir[[:space:]]+/etc/sudoers\.d$)'
    have sudo || { caution "sudo is not installed"; return; }

    step "/etc/sudoers"
    grep -nvE '^\s*(#[^i]|#$|$)' /etc/sudoers | sed 's/^/      /'
    if grep -vE '^\s*(#|$)' /etc/sudoers | grep -qvE "$std"
    then
        grep -vE '^\s*(#|$)' /etc/sudoers | grep -vE "$std" | while IFS= read -r line
        do
            flag "non-standard rule in /etc/sudoers: $line"
        done
        explain "Commenting them out is checked with 'visudo -c' first (a broken sudoers = nobody has sudo)."
        if confirm_risky "Comment out the non-standard rules in /etc/sudoers?"
        then
            backup_file /etc/sudoers
            tmpf="$SYL_TMP/sudoers"
            awk -v std="$std" '/^[[:space:]]*(#|$)/ || $0 ~ std {print; next} {print "#sylvester# " $0}' /etc/sudoers > "$tmpf"
            if visudo -cf "$tmpf" >/dev/null
            then
                cat "$tmpf" > /etc/sudoers && did "SUDOERS non-standard rules commented out (#sylvester#)" "sed -i 's/^#sylvester# //' /etc/sudoers"
            else
                flag "the edited sudoers failed visudo -c - NOT changed"
            fi
        fi
    else
        ok "/etc/sudoers only has the standard rules"
    fi

    step "/etc/sudoers.d/"
    for f in /etc/sudoers.d/*
    do
        [[ -f "$f" ]] || continue
        is_owned "$f" && continue
        show_file "$f" "sudo rule file no package installed"
        grep -q NOPASSWD "$f" && flag "$f gives sudo WITHOUT a password"
        explain "Cloud images use files like 90-cloud-init-users for the first login - make sure you know"
        explain "the ROOT password before removing one, or you could lose sudo."
        confirm_risky "Quarantine $f?" && quarantine "$f" "sudoers.d entry"
    done
    if visudo -c >/dev/null 2>&1
    then
        ok "visudo -c: sudo config is valid"
    else
        flag "visudo -c reports an ERROR - fix it now:  EDITOR=nano visudo"
    fi
}

step_keys() {
    local f u home p extra
    section "SSH KEYS"
    explain "authorized_keys = log in with NO password. Red team plants their key so that changing"
    explain "passwords doesn't keep them out. The scorer logs in with a password, so moving these out"
    explain "is normally safe. If a teammate added THEIR OWN key on purpose, answer n for that file."
    {
        find / "${PRUNE[@]}" \( -name authorized_keys -o -name authorized_keys2 \) -type f -print 2>/dev/null
        # extra places sshd was told to look for keys (AuthorizedKeysFile)
        extra=$(sshd -T 2>/dev/null | awk '$1 == "authorizedkeysfile" {for (i = 2; i <= NF; i++) print $i}')
        for p in $extra
        do
            [[ "$p" == .ssh/authorized_keys || "$p" == .ssh/authorized_keys2 ]] && continue
            while IFS=: read -r u _ _ _ _ home _
            do
                f="${p//%h/$home}"; f="${f//%u/$u}"; f="${f//%%/%}"
                [[ "$f" == /* ]] || f="$home/$f"
                [[ -f "$f" ]] && echo "$f"
            done < /etc/passwd
        done
    } | sort -u > "$SYL_TMP/keys"
    if [[ ! -s "$SYL_TMP/keys" ]]
    then
        ok "no authorized_keys files anywhere"
    fi
    while read -r f
    do
        printf "\n  ${warn}%s${reset}  owner=%s  changed %s\n" "$f" "$(stat -c %U "$f")" "$(date -r "$f" '+%b %d %H:%M')"
        awk '!/^\s*(#|$)/ {o = ""; if ($1 !~ /^(ssh-|ecdsa-|sk-)/) {o = "[options: " $1 "] "; $1 = ""} print "      " o $1 " ..." substr($NF, 1, 40)}' "$f"
        flag "$(grep -cvE '^\s*(#|$)' "$f") key(s) in $f allow password-less login"
        confirm_safe "Quarantine $f?" && quarantine "$f" "ssh authorized_keys"
    done < "$SYL_TMP/keys"
}

step_sshd() {
    local f conf=/etc/ssh/sshd_config.d/00-sylvester.conf root_line
    PW_LINE=""
    section "SSH SERVER SETTINGS"
    have sshd || { caution "sshd is not installed - skipping"; return; }
    mkdir -p /run/sshd     # sshd -t needs this on some systems
    explain "This writes $conf. sshd uses the FIRST value it reads and that file is"
    explain "read first, so it beats anything red team put further down. It is checked with"
    explain "'sshd -t' before ssh is reloaded, and logged-in sessions stay open."
    explain "PasswordAuthentication is NOT turned off - the scorer logs in with a password."

    if ! grep -qE '^\s*Include\s+/etc/ssh/sshd_config\.d/\*\.conf' /etc/ssh/sshd_config
    then
        flag "/etc/ssh/sshd_config no longer includes sshd_config.d/ (Rocky has it near the top)"
        if confirm_safe "Put the Include line back at the top of sshd_config?"
        then
            backup_file /etc/ssh/sshd_config
            sed -i '1i Include /etc/ssh/sshd_config.d/*.conf' /etc/ssh/sshd_config
            did "SSHD restored the Include line in sshd_config"
        fi
    fi

    step "Drop-in files and Match blocks"
    for f in /etc/ssh/sshd_config.d/*.conf
    do
        [[ -f "$f" && "$f" != "$conf" ]] || continue
        show_file "$f" "$(is_owned "$f" && echo 'from a package' || echo 'NOT from a package')"
    done
    if grep -nE '^\s*Match\s' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*.conf 2>/dev/null
    then
        flag "Match blocks found (above): they give special rules to one user/IP - read them!"
        explain "e.g. 'Match User bob' + 'PermitRootLogin yes' or 'ForceCommand'. Edit the file and remove"
        explain "the block if you don't recognise it, then: sshd -t && systemctl reload ssh"
        todo "Read the sshd Match blocks: grep -n Match /etc/ssh/sshd_config /etc/ssh/sshd_config.d/*"
    fi
    [[ -s /etc/ssh/sshrc ]] && handle_file /etc/ssh/sshrc "runs on every SSH login"

    step "Current settings"
    sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|allowtcpforwarding|x11forwarding|maxauthtries|usepam) ' | sed 's/^/      /'
    if sshd -T 2>/dev/null | grep -qi '^passwordauthentication no'
    then
        flag "PasswordAuthentication is NO - if the scorer logs in with a password, the SSH check FAILS"
        if confirm_risky "Turn password logins back on?"
        then
            PW_LINE="PasswordAuthentication yes"
        fi
    fi

    step "New settings"
    root_line="# PermitRootLogin left as it was"
    explain "Blocking root over SSH is good - unless the scorer or a teammate logs in as root over SSH."
    explain "Root on the console (Proxmox) is NOT affected."
    if confirm_risky "Block root logins over SSH (PermitRootLogin no)?"
    then
        root_line="PermitRootLogin no"
    fi
    {
        printf "# written by sylvester linux-lockdown.sh %s\n" "$(date -Is)"
        printf "%s\n" "$root_line"
        [[ -n "$PW_LINE" ]] && printf "%s\n" "$PW_LINE"
        cat <<'EOF'
PermitEmptyPasswords no
MaxAuthTries 4
LoginGraceTime 30
X11Forwarding no
AllowAgentForwarding no
AllowTcpForwarding no
PermitTunnel no
GatewayPorts no
PermitUserEnvironment no
HostbasedAuthentication no
IgnoreRhosts yes
AuthorizedKeysFile .ssh/authorized_keys
AuthorizedKeysCommand none
EOF
    } > "$SYL_TMP/00-sylvester.conf"
    sed 's/^/      /' "$SYL_TMP/00-sylvester.conf"
    explain "AllowTcpForwarding no: red team can't tunnel through sylvester to reach other boxes."
    explain "AuthorizedKeysFile/Command: only the normal key file is used (no hidden key locations)."
    confirm_safe "Install these settings and reload ssh?" || return
    [[ -f "$conf" ]] && backup_file "$conf"
    install -m 600 "$SYL_TMP/00-sylvester.conf" "$conf"
    if sshd -t 2>"$SYL_TMP/sshd.err"
    then
        systemctl reload-or-restart ssh 2>/dev/null || systemctl reload-or-restart sshd 2>/dev/null
        did "SSHD hardened ($conf) and reloaded" "rm $conf && systemctl reload ssh"
        printf "${info}  Prove password logins still work from ANOTHER terminal before closing this one:\n"
        printf "      ssh SOME_USER@192.168.220.199${reset}\n"
        sshd -T 2>/dev/null | grep -Ei '^(permitrootlogin|passwordauthentication|authorizedkeysfile|allowtcpforwarding) ' | sed 's/^/      /'
    else
        flag "sshd -t rejected the new config - removed it, ssh NOT reloaded:"
        sed 's/^/      /' "$SYL_TMP/sshd.err"
        rm -f "$conf"
    fi
}

step_persistence() {
    local f u line n units t target lines bad_login
    section "PERSISTENCE (things that start by themselves)"
    explain "Once red team is in, they leave a way back: a cron job, a systemd service, a line in a"
    explain "login script, a PAM module... These checks look for files NO PACKAGE INSTALLED and for"
    explain "lines that run shells, download things or use temp folders."

    step "Preloaded libraries"
    if [[ -s /etc/ld.so.preload ]]
    then
        flag "/etc/ld.so.preload loads a library into EVERY program - almost always a rootkit:"
        sed 's/^/      | /' /etc/ld.so.preload
        confirm_safe "Quarantine /etc/ld.so.preload?" && quarantine /etc/ld.so.preload "ld.so.preload rootkit"
        explain "Programs started before this still have it loaded - log out/in, restart services later."
    else
        ok "no /etc/ld.so.preload"
    fi
    grep -l '^LD_PRELOAD' /etc/environment >/dev/null 2>&1 && flag "/etc/environment sets LD_PRELOAD: $(grep LD_PRELOAD /etc/environment)"
    for f in $(ls /etc/ld.so.conf.d/* 2>/dev/null | not_owned)
    do
        handle_file "$f" "extra library path"
    done

    step "Boot scripts"
    [[ -e /etc/rc.local ]] && { show_file /etc/rc.local "runs at boot - check it"; confirm_safe "Quarantine /etc/rc.local?" && quarantine /etc/rc.local "rc.local"; }
    for f in $(ls /etc/init.d/* 2>/dev/null | not_owned)
    do
        handle_file "$f" "init.d script no package installed"
    done

    step "Cron and at jobs"
    if grep -vE '^\s*(#|$|SHELL=|PATH=|MAILTO=|BASH_ENV=)' /etc/crontab 2>/dev/null | grep -qv 'run-parts'
    then
        grep -nvE '^\s*(#|$|SHELL=|PATH=|MAILTO=|BASH_ENV=)' /etc/crontab | grep -v 'run-parts' | while IFS= read -r line
        do
            flag "/etc/crontab line $line"
        done
        if confirm_safe "Comment out the non-standard /etc/crontab lines?"
        then
            backup_file /etc/crontab
            sed -i -E '/^\s*(#|$|SHELL=|PATH=|MAILTO=|BASH_ENV=)/b; /run-parts/b; s/^/#sylvester# /' /etc/crontab
            did "CRON non-standard /etc/crontab lines commented out (#sylvester#)" "sed -i 's/^#sylvester# //' /etc/crontab"
        fi
    else
        ok "/etc/crontab only has the standard run-parts lines"
    fi
    for f in $(ls -d /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/* 2>/dev/null | not_owned)
    do
        [[ -f "$f" && "$(basename "$f")" != ".placeholder" ]] && handle_file "$f" "cron job no package installed"
    done
    for f in /var/spool/cron/crontabs/* /var/spool/cron/*
    do
        [[ -f "$f" ]] || continue
        grep -qvE '^\s*(#|$)' "$f" || continue
        handle_file "$f" "personal crontab of $(basename "$f")"
    done
    for f in /var/spool/cron/atjobs/* /var/spool/at/[a-z]*
    do
        [[ -f "$f" && "$(basename "$f")" != ".SEQ" ]] || continue
        show_file "$f" "at job (runs once, later)"
        flag "an 'at' job is waiting to run: $f"
        confirm_safe "Quarantine $f?" && quarantine "$f" "at job"
    done

    step "systemd services / timers no package installed"
    explain "Includes units started with systemd-run (/run/systemd/transient)."
    explain "Skipped: snap units, sylvester's own units. Masked units (-> /dev/null) are fine."
    {
        find /etc/systemd/system /etc/systemd/user /usr/local/lib/systemd /usr/lib/systemd/system /usr/lib/systemd/user /run/systemd/transient \
             /root/.config/systemd /home/*/.config/systemd \( -type f -o -type l \) \
             \( -name '*.service' -o -name '*.timer' -o -name '*.socket' -o -name '*.path' -o -name '*.conf' \) 2>/dev/null \
            | while read -r f
            do
                if [[ -L "$f" ]]
                then
                    target=$(readlink -f "$f")
                    [[ "$target" == /dev/null || -z "$target" ]] && continue
                    echo "$target"
                else
                    echo "$f"
                fi
            done
    } | sort -u | not_owned | grep -vE '/snap[.-]|/sylvester-' > "$SYL_TMP/units"
    if [[ ! -s "$SYL_TMP/units" ]]
    then
        ok "every systemd unit file came from a package"
    fi
    while read -r f
    do
        u=$(basename "$f")
        printf "\n  ${warn}%s${reset}   enabled=%s active=%s\n" "$f" "$(systemctl is-enabled "$u" 2>/dev/null)" "$(systemctl is-active "$u" 2>/dev/null)"
        grep -E '^(Description|ExecStart|ExecStartPre|ExecStartPost|ExecStop|User|OnCalendar|OnBootSec|OnUnitActiveSec)=' "$f" | cut -c1-160 | sed 's/^/      | /'
        explain "Check the DB itself is not using it (mysql/postgresql/redis/mongod units come from packages)."
        if file_looks_bad "$f"
        then
            flag "$u runs a shell / download / temp-folder program"
            confirm_safe "Stop, disable and quarantine $u?" || continue
        else
            confirm_risky "Stop, disable and quarantine $u ($f)?" || continue
        fi
        if [[ "$f" != *.d/* ]]
        then
            systemctl disable --now "$u" >/dev/null 2>&1
            [[ "$f" == */user/* || "$f" == */.config/* ]] && systemctl --global disable "$u" >/dev/null 2>&1
        fi
        quarantine "$f" "systemd unit no package installed"
        systemctl daemon-reload
    done < "$SYL_TMP/units"

    step "Login scripts (run every time someone logs in)"
    bad_login='LD_PRELOAD|alias +(sudo|su|ps|ss|netstat|cat|passwd|ssh|mysql|psql|redis-cli|mongosh|ufw|who|last)=|/dev/(tcp|udp)/|(nc|ncat|socat)( .*)? -[a-z]*e |(curl|wget)[^|]*\| *(ba)?sh|base64 +(-d|--decode)|nohup .*&|python[0-9.]* -c'
    for f in /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/environment /etc/zsh/zshrc /etc/skel/.bashrc \
             /root/.bashrc /root/.profile /root/.bash_profile /root/.bash_login /root/.bash_logout \
             /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.bash_login /home/*/.bash_logout /home/*/.zshrc
    do
        [[ -f "$f" ]] || continue
        if is_owned "$f"
        then
            lines=$(grep -nE "$bad_login" "$f" | grep -vE '^[0-9]+:\s*#')
        else
            lines=$(grep -nE "$bad_login|PROMPT_COMMAND|trap .*DEBUG" "$f" | grep -vE '^[0-9]+:\s*#')
        fi
        [[ -z "$lines" ]] && continue
        flag "$f has suspicious lines:"
        printf '%s\n' "$lines" | cut -c1-160 | sed 's/^/      line /'
        if confirm_safe "Comment out those lines in $f (a copy is saved first)?"
        then
            backup_file "$f"
            chattr -ia "$f" 2>/dev/null
            for n in $(printf '%s\n' "$lines" | cut -d: -f1)
            do
                sed -i "${n}s/^/#sylvester# /" "$f"
            done
            did "LOGIN SCRIPT lines $(printf '%s' "$lines" | cut -d: -f1 | paste -sd, -) commented out in $f" "sed -i 's/^#sylvester# //' $f"
        fi
    done
    for f in $(ls /etc/profile.d/* 2>/dev/null | not_owned)
    do
        handle_file "$f" "login script no package installed"
    done
    for f in /root/.ssh/rc /home/*/.ssh/rc
    do
        [[ -f "$f" ]] && handle_file "$f" "runs on every SSH login of that user"
    done

    step "MOTD scripts (run as ROOT on every SSH login)"
    for f in $(ls /etc/update-motd.d/* 2>/dev/null | not_owned)
    do
        show_file "$f" "motd script no package installed"
        flag "$f runs as root every time anyone logs in over SSH"
        confirm_safe "Quarantine $f?" && quarantine "$f" "update-motd.d script"
    done

    step "apt hooks (run on every apt command)"
    for f in $(grep -lE 'Invoke|Pre-Install-Pkgs|Post-Invoke' /etc/apt/apt.conf.d/* 2>/dev/null | not_owned)
    do
        show_file "$f" "apt hook no package installed"
        confirm_safe "Quarantine $f?" && quarantine "$f" "apt hook"
    done

    step "udev rules that run programs"
    for f in $(grep -lE 'RUN\+?=' /etc/udev/rules.d/* 2>/dev/null | not_owned)
    do
        show_file "$f" "udev RUN rule"
        confirm_safe "Quarantine $f?" && quarantine "$f" "udev RUN rule"
    done

    step "PAM (the login system)"
    explain "A changed PAM config can accept ANY password, or log every password typed."
    if grep -nE '^\s*auth\s+(sufficient|\[success=done[^]]*\])\s+pam_permit\.so' /etc/pam.d/* 2>/dev/null
    then
        flag "pam_permit marked 'sufficient' (above) = any password works!"
        for f in $(grep -lE '^\s*auth\s+(sufficient|\[success=done[^]]*\])\s+pam_permit\.so' /etc/pam.d/*)
        do
            if confirm_safe "Comment out that pam_permit line in $f?"
            then
                backup_file "$f"
                sed -i -E 's/^(\s*auth\s+(sufficient|\[success=done[^]]*\])\s+pam_permit\.so.*)$/#sylvester# \1/' "$f"
                did "PAM pam_permit backdoor line commented out in $f" "sed -i 's/^#sylvester# //' $f"
            fi
        done
    fi
    if grep -nE '^\s*[^#].*pam_exec\.so' /etc/pam.d/* 2>/dev/null
    then
        flag "pam_exec (above) runs a program at login - stock Rocky never does this"
        explain "Commenting out a PAM line can lock everyone out if you pick the wrong one."
        explain "Keep this root shell open and test 'su - someuser' in a second terminal after."
        for f in $(grep -lE '^\s*[^#].*pam_exec\.so' /etc/pam.d/*)
        do
            if confirm_risky "Comment out the pam_exec lines in $f?"
            then
                backup_file "$f"
                sed -i -E '/^\s*[^#].*pam_exec\.so/ s/^/#sylvester# /' "$f"
                did "PAM pam_exec lines commented out in $f" "sed -i 's/^#sylvester# //' $f"
            fi
        done
    fi
    for f in $(find /usr/lib64/security /usr/lib/x86_64-linux-gnu/security /usr/lib/security /lib/security -name '*.so' 2>/dev/null | sort -u | not_owned)
    do
        if grep -q "$(basename "$f")" /etc/pam.d/* 2>/dev/null
        then
            flag "PAM module no package installed, IN USE: $f  ($(grep -l "$(basename "$f")" /etc/pam.d/* | paste -sd' ' -))"
            todo "Remove the PAM line using $f from /etc/pam.d, test logins, then quarantine the module"
        else
            flag "PAM module no package installed (not in use): $f"
            confirm_safe "Quarantine $f?" && quarantine "$f" "unknown PAM module"
        fi
    done
    ok "PAM check done"

    step "Programs hiding in temp folders"
    find /tmp /var/tmp /dev/shm -xdev -type f -not -path "$SYL_TMP/*" 2>/dev/null | while read -r f
    do
        if [[ -x "$f" ]] || [[ "$(head -c 4 "$f" 2>/dev/null | od -An -c | tr -d ' ')" == '177ELF' ]] || file_looks_bad "$f"
        then
            printf "  ${warn}%s${reset}  %s  %s\n" "$f" "$(stat -c '%U %s bytes' "$f")" "$(file -b "$f" 2>/dev/null | cut -c1-50)"
            flag "program/script in a temp folder: $f"
            confirm_safe "Quarantine $f?" && quarantine "$f" "program in temp folder"
        fi
    done
    find /tmp /var/tmp /dev/shm -mindepth 1 -maxdepth 1 -name '.*' -not -name '.X*-unix' -not -name '.ICE-unix' \
         -not -name '.font-unix' -not -name '.Test-unix' -not -name '.sylvester.*' 2>/dev/null | while read -r f
    do
        caution "hidden item in a temp folder: $f ($(stat -c '%U' "$f"))"
    done
}

step_suid() {
    local f gtfo caps
    section "SUID / SGID PROGRAMS AND CAPABILITIES"
    explain "A SUID program runs as its owner (root) no matter who starts it. Red team makes their own,"
    explain "or sets the bit on bash/find/python so any user can become root."
    gtfo='/(bash|sh|dash|zsh|ksh|find|python[0-9.]*|perl|ruby|php[0-9.]*|lua[0-9.]*|node|vi|vim|vim\.basic|nano|less|more|awk|gawk|mawk|cp|mv|tar|zip|env|tee|dd|base64|chmod|chown|socat|nc|ncat|busybox|rsync|sed|nmap|docker|gdb|strace|wget|curl|journalctl|systemctl|bpftrace|xxd|ed|ash)$'
    find / "${PRUNE[@]}" -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null | sort > "$SYL_TMP/suid"
    printf "  %s SUID/SGID files on the box\n" "$(wc -l < "$SYL_TMP/suid")"
    { not_owned < "$SYL_TMP/suid"; grep -E "$gtfo" "$SYL_TMP/suid"; } | sort -u | while read -r f
    do
        ls -l "$f" | sed 's/^/      /'
        flag "$f is SUID/SGID and $(is_owned "$f" && echo 'should NOT be (it can give a root shell)' || echo 'no package installed it')"
        if confirm_safe "Remove the SUID/SGID bit from $f?"
        then
            chattr -ia "$f" 2>/dev/null
            chmod u-s,g-s "$f" && did "SUID/SGID removed from $f" "chmod u+s $f"
        fi
    done
    ok "SUID check done"

    step "File capabilities"
    explain "cap_setuid on python/perl = root for anyone. stock Rocky gives almost nothing root-level caps."
    have getcap || { caution "getcap is not installed"; return; }
    getcap -r /usr /opt /home /root /tmp /var /srv /etc 2>/dev/null > "$SYL_TMP/caps"
    sed 's/^/      /' "$SYL_TMP/caps"
    grep -E 'cap_(setuid|setgid|dac_override|dac_read_search|sys_admin|sys_ptrace|sys_module|chown|fowner)' "$SYL_TMP/caps" \
        | awk '{print $1}' | while read -r f
    do
        # a package may ship root caps (snapd's snap-confine); an interpreter or tool never has them
        is_owned "$f" && ! [[ "$f" =~ $gtfo ]] && continue
        flag "$f has a root-level capability: $(getcap "$f")"
        confirm_safe "Remove its capabilities?" && setcap -r "$f" && did "CAPABILITIES removed from $f" "setcap '<old caps>' $f"
    done
    ok "capability check done"
}

step_processes() {
    local level pid user reason cmd n=0
    section "RUNNING PROCESSES"
    explain "Looks for: shells started BY the database (DB-to-shell attack), programs running from temp"
    explain "folders or from memory only, reverse shells, attack/tunnel tools, deleted program files."
    explain "Evidence (program copy, command line, connections) is saved BEFORE anything is killed."
    scan_procs > "$SYL_TMP/procs"
    if [[ ! -s "$SYL_TMP/procs" ]]
    then
        ok "nothing suspicious running"
        return
    fi
    while IFS=$'\t' read -r level pid user reason cmd
    do
        [[ -d "/proc/$pid" ]] || continue
        n=$((n + 1))
        printf "\n  ${error}%s${reset}  pid=%s user=%s\n      why: %s\n      cmd: %s\n" "$level" "$pid" "$user" "$reason" "$cmd"
        printf "      started by:\n"; proc_tree_up "$(ps -o ppid= -p "$pid" | tr -d ' ')" | head -n 4 | sed 's/^/        /'
        ss -tunap 2>/dev/null | grep "pid=$pid," | awk '{print "      net: " $1, $2, $5, "->", $6}'
        flag "$level process $pid ($user): $reason"
        if [[ "$level" == "CRIT" ]]
        then
            confirm_safe "Kill PID $pid (evidence is saved first)?" && kill_proc "$pid" "$reason"
        else
            confirm_risky "Kill PID $pid ($cmd)?" && kill_proc "$pid" "$reason"
        fi
    done < "$SYL_TMP/procs"
    explain "Killed something? Its parent may restart it - rerun 'persistence' and check cron/systemd."
}

step_network() {
    local proto port addr name pid exe expected l peer proc
    section "LISTENING PORTS AND CONNECTIONS"
    explain "Everything listening on the network. The scorer needs SSH (22) and the streaming app's port(s)."
    explain "Anything else is either a scored service you didn't know about (check the scoring page)"
    explain "or a backdoor. Programs no package installed are the red flags."
    expected=" 22 "
    for a in ${APPS:-$(detect_apps)}
    do
        for p in $(app_ports "$a")
        do
            expected+="${p%/*} "
        done
    done
    for p in $EXTRA_PORTS
    do
        expected+="${p%/*} "
    done
    printf "\n  ${bold}%-5s %-7s %-22s %-18s %-7s %s${reset}\n" PROTO PORT ADDRESS PROGRAM PID "PROGRAM FILE"
    listeners | while read -r proto port addr name pid
    do
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        printf "  %-5s %-7s %-22s %-18s %-7s %s\n" "$proto" "$port" "$addr" "$name" "$pid" "${exe:-?}"
    done
    printf "\n"
    listeners | while read -r proto port addr name pid
    do
        is_local_addr "$addr" && continue
        exe=$(readlink "/proc/$pid/exe" 2>/dev/null)
        if [[ "$exe" == /tmp/* || "$exe" == /dev/shm/* || "$exe" == /var/tmp/* || "$exe" == *"(deleted)" ]]
        then
            flag "$name (pid $pid) listens on $port/$proto from $exe - backdoor"
            confirm_safe "Kill PID $pid?" && kill_proc "$pid" "backdoor listener on port $port"
        elif [[ -n "$exe" && "$exe" != "?" ]] && ! is_owned "$exe"
        then
            flag "$name (pid $pid) listens on $port/$proto and NO package installed $exe"
            confirm_risky "Kill PID $pid ($name on port $port)?" && kill_proc "$pid" "unknown listener on port $port"
        elif [[ "$expected" != *" $port "* ]]
        then
            caution "port $port/$proto ($name) is not SSH or the streaming app - scored? if not, firewall.sh blocks it"
        fi
    done

    step "Outbound connections (sylvester calling out = reverse shells, data theft)"
    ss -Htnp state established 2>/dev/null | awk '{print $3, $4, $5}' | while read -r l peer proc
    do
        p=${peer%:*}; p=${p#[}; p=${p%]}; p=${p#::ffff:}
        is_local_addr "$p" && continue
        listeners | awk '{print $2}' | grep -qx "${l##*:}" && continue      # someone connected TO us
        name=$(grep -o '"[^"]*"' <<< "$proc" | head -n 1 | tr -d '"')
        if ip_in_team_net "$p"
        then
            printf "      %s -> %s (team box)\n" "${name:-?}" "$peer"
        else
            flag "outbound connection ${name:-?} -> $peer (outside the team network)"
        fi
    done

    step "Name resolution"
    printf "      resolv.conf nameservers: %s\n" "$(awk '/^nameserver/ {print $2}' /etc/resolv.conf | paste -sd' ' -)"
    grep -vE '^\s*(#|$)|localhost|ip6-|ff02::|fe00::' /etc/hosts | grep -v "$(hostname)" | while IFS= read -r l
    do
        caution "/etc/hosts entry: $l   (red team can redirect names here)"
    done
    printf "      default route: %s\n" "$(ip route show default 2>/dev/null | head -n 1)"
}

step_integrity() {
    local pkgs
    section "ARE THE SYSTEM PROGRAMS STILL THE ORIGINALS? (rpm -Va, ~1-2 minutes)"
    explain "Compares every installed file with what its package shipped. A changed sshd, sudo, su,"
    explain "passwd, ls, ps or ss means a trojan. Changed config files are listed so you can read them."
    rpm -Va > "$SYL_TMP/verify" 2>/dev/null
    # format: "S.5....T.  [c] /path"  - the 3rd character '5' = contents changed
    awk 'substr($1, 3, 1) == "5" && $2 != "c" {print $NF}' "$SYL_TMP/verify" \
        | grep -E '^/(usr/)?(bin|sbin|lib|lib64)/' > "$SYL_TMP/changed"
    awk 'substr($1, 3, 1) == "5" && $2 == "c" {print $NF}' "$SYL_TMP/verify" \
        | grep -E '^/etc/(pam\.d|security|ssh|sudoers|ld\.so|profile|bashrc|nsswitch\.conf|environment|crontab|nginx|httpd|jellyfin|selinux|firewalld)' > "$SYL_TMP/confs"
    if [[ -s "$SYL_TMP/changed" ]]
    then
        flag "program/library files that differ from their package (possible trojans):"
        sed 's/^/      /' "$SYL_TMP/changed"
        pkgs=$(xargs -r rpm -qf --qf '%{NAME}\n' < "$SYL_TMP/changed" 2>/dev/null | sort -u | paste -sd' ' -)
        printf "      packages: %s\n" "$pkgs"
        explain "Fix: reinstall those packages (needs the package mirror / internet):  dnf reinstall -y $pkgs"
        confirm_risky "Reinstall $pkgs now?" && dnf reinstall -y $pkgs && did "REINSTALLED $pkgs (files were modified)"
    else
        ok "no changed programs or libraries"
    fi
    if [[ -s "$SYL_TMP/confs" ]]
    then
        caution "security-related config files edited since install (read them - app configs are often edited on purpose):"
        sed 's/^/      /' "$SYL_TMP/confs"
    fi
}

step_selinux() {
    local mode cfg
    section "SELINUX"
    explain "On Rocky, SELinux stops a hacked web/stream app from touching the rest of the box."
    explain "Red team turns it off ('setenforce 0') because it blocks their tools."
    have getenforce || { caution "SELinux tools not installed"; return; }
    mode=$(getenforce 2>/dev/null)
    cfg=$(awk -F= '/^SELINUX=/ {print $2}' /etc/selinux/config 2>/dev/null)
    printf "      running: %s    at boot (/etc/selinux/config): %s\n" "$mode" "${cfg:-?}"
    case "$mode" in
        Enforcing) ok "SELinux is enforcing" ;;
        Permissive)
            flag "SELinux is PERMISSIVE - it only logs, it blocks nothing"
            explain "Turning it back on can break the streaming app if its files have wrong labels. Do it, then"
            explain "check the app right away; if it breaks: setenforce 0, then fix labels with restorecon -Rv <dir>."
            confirm_risky "Turn SELinux back on now (setenforce 1)?" && setenforce 1 && did "SELINUX set to Enforcing" "setenforce 0" ;;
        *) flag "SELinux is $mode (needs a reboot to turn on - leave it, but note it for the report)" ;;
    esac
    [[ "$cfg" != "enforcing" && "$mode" != "Disabled" ]] && todo "SELinux at boot is '$cfg' - set SELINUX=enforcing in /etc/selinux/config"
    if have ausearch
    then
        printf "\n  recent SELinux denials (what it blocked):\n"
        ausearch -m avc -ts recent 2>/dev/null | grep -oE 'comm="[^"]+".*(name|path)="[^"]+"' | sort | uniq -c | sort -rn | head -n 8 | sed 's/^/      /'
    fi
    if have semanage
    then
        printf "\n  booleans changed from default (red team flips these, e.g. httpd_execmem):\n"
        semanage boolean -l -C 2>/dev/null | tail -n +2 | sed 's/^/      /' | head -n 15
    fi
}

banner "linux-lockdown.sh  -  sylvester (Rocky Linux video streamer)"
printf "  you are: %s   protected Linux users: root %s %s\n" "${ME:-root}" "$ME" "$PROTECTED_LINUX_USERS"
printf "  evidence + logs: %s\n" "$DATA_DIR"
[[ "$RUN" == "$STEPS" ]] && todo_reset
log_action "START linux-lockdown mode=$MODE steps=$RUN"
for s in $RUN
do
    "step_$s"
done
log_action "END linux-lockdown"

printf "\n${bold}${info}linux-lockdown finished.${reset}\n"
printf "  what was changed:   %s\n" "$ACTIONS"
printf "  everything flagged: %s\n" "$FINDINGS"
[[ -s "$TODO_FILE" ]] && printf "  ${warn}needs a human:      %s  (%s items)${reset}\n" "$TODO_FILE" "$(wc -l < "$TODO_FILE")"
exit 0
