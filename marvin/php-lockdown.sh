#!/bin/bash
#
# php-lockdown.sh
#
# Protects any PHP on the box (phpMyAdmin/Adminer on a DB box, a PHP site, PHP-FPM behind
# nginx/Apache) against the PHP bugs red team is most likely to use:
#   - "php2shell" CVE-2026-109618 + CVE-2026-109619 (Oct 2026): unauthenticated RCE in
#     PHP-FPM / mod_php / php-cgi. Fixed in 8.5.12, 8.4.27, 8.3.36, 8.2.35 (or a distro backport).
#     Stopgap from the PHP project: session.upload_progress.enabled = 0 + restart the workers.
#   - CVE-2024-2961 "CNEXT": glibc iconv bug that turns a PHP file-read into RCE via php://filter.
#     Stopgap: disable the ISO-2022-CN-EXT charset (nobody uses it).
#   - webshells, PHP running in upload folders, phpMyAdmin/Adminer left reachable.
# It writes ONE drop-in ini file (easy undo), restarts PHP, checks the site still answers,
# and takes the change back by itself if the site breaks.
#
# Usage:
#   sudo ./php-lockdown.sh                  check + fix, asking first
#   sudo ./php-lockdown.sh --auto           safe fixes only, risky ones -> TODO.txt
#   sudo ./php-lockdown.sh --audit          check only
#   URL=http://127.0.0.1/ sudo ./php-lockdown.sh    page to test after changes (default http://127.0.0.1/)
#   sudo ./php-lockdown.sh undo             remove the hardening file + restart PHP
#
# WCComps 2026 INV2 - works on Ubuntu (marvin) and Rocky (sylvester)
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
T="${MARVIN_TMP:-$SYL_TMP}"

case "$1" in
    --auto) MODE=auto ;;
    --audit|--dry-run) MODE=audit ;;
    -h|--help) usage_from_header; exit 0 ;;
esac
require_root
setup_dirs
load_conf
SCRIPT_NAME=php-lockdown
URL="${URL:-${STREAM_URL:-http://127.0.0.1/}}"
INI_NAME=zz-wccomps-hardening.ini
FIXED="8.5.12 8.4.27 8.3.36 8.2.35"
CVES="CVE-2026-109618 CVE-2026-109619"

ver_ge() { [[ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n 1)" == "$2" ]]; }   # ver_ge A B: A >= B

# every "conf.d" folder PHP reads extra .ini files from (one per version/SAPI on Ubuntu, one on Rocky)
ini_dirs() {
    ls -d /etc/php/*/*/conf.d /etc/php.d /etc/opt/remi/php*/php.d 2>/dev/null
}

php_services() {
    systemctl list-units --type=service --no-legend 2>/dev/null | awk '{print $1}' \
        | grep -E '^(php[0-9.]*-fpm|php-fpm|apache2|httpd|nginx|lsws|frankenphp)\.service$'
}

http_code() { curl -sk -m 8 -o /dev/null -w '%{http_code}' "$URL" 2>/dev/null; }

restart_php() {
    local s
    for s in $(php_services)
    do
        [[ "$s" == nginx.service ]] && continue      # nginx has no PHP inside; FPM is restarted instead
        systemctl restart "$s" && printf "  restarted %s\n" "$s"
    done
}

step_versions() {
    local b v branch fixed patched
    section "PHP ON THIS BOX - IS IT PATCHED AGAINST php2shell?"
    if ! ls /usr/bin/php* /usr/sbin/php-fpm* /usr/sbin/php*-fpm* >/dev/null 2>&1 && [[ -z "$(ini_dirs)" ]]
    then
        ok "no PHP installed here - php2shell / CNEXT can't hit this box through PHP"
        NO_PHP=1
        return
    fi
    for b in $(ls /usr/bin/php[0-9.]* /usr/bin/php /usr/sbin/php-fpm* /usr/sbin/php*-fpm* 2>/dev/null | sort -u)
    do
        v=$("$b" -v 2>/dev/null | head -n 1 | awk '{print $2}')
        [[ -z "$v" ]] && continue
        branch=$(cut -d. -f1-2 <<< "$v")
        fixed=$(tr ' ' '\n' <<< "$FIXED" | grep "^$branch\." )
        patched=""
        [[ -n "$fixed" ]] && ver_ge "${v%%-*}" "$fixed" && patched="upstream $fixed+"
        # distros backport fixes without changing the PHP version - look in the package changelog
        if [[ -z "$patched" ]]
        then
            if zgrep -qsE "${CVES// /|}" /usr/share/doc/php${branch}*/changelog.Debian.gz /usr/share/doc/php*-common/changelog.Debian.gz 2>/dev/null \
               || rpm -q --changelog php-common php-cli 2>/dev/null | grep -qE "${CVES// /|}"
            then
                patched="distro backport (changelog mentions the CVEs)"
            fi
        fi
        if [[ -n "$patched" ]]
        then
            ok "$b = PHP $v - patched ($patched)"
        else
            flag "$b = PHP $v - NOT patched for php2shell ($CVES)"
            explain "Fix for real: update PHP (Ubuntu: apt-get install --only-upgrade 'php*'; Rocky: dnf update 'php*')"
            explain "and restart PHP-FPM / Apache. Until then the session.upload_progress stopgap below matters."
            todo "Update PHP ($v) for php2shell $CVES - fixed in $FIXED or a distro backport"
            UNPATCHED=1
        fi
    done
    printf "\n  PHP is served by: %s\n" "$(php_services | paste -sd' ' -)"
    for s in apache2ctl httpd
    do
        have "$s" && "$s" -M 2>/dev/null | grep -qi php && caution "Apache runs PHP inside itself (mod_php) - the PHP project calls this the highest php2shell risk"
    done
}

step_ini() {
    local d code_before code_after f risky_funcs=""
    section "PHP SETTINGS (one drop-in file: $INI_NAME)"
    [[ -n "$NO_PHP" ]] && { ok "no PHP - nothing to set"; return; }
    explain "Safe settings (don't break normal apps):"
    explain "  session.upload_progress.enabled = 0   php2shell stopgap (only upload progress bars stop)"
    explain "  allow_url_include = Off               no including code from a URL"
    explain "  expose_php = Off, display_errors = Off  don't hand red team versions / file paths"
    explain "  session.cookie_httponly = 1           JavaScript can't steal session cookies"
    cat > "$T/hardening.ini" <<'EOF'
; written by php-lockdown.sh (WCComps) - delete this file + restart PHP to undo
session.upload_progress.enabled = 0
allow_url_include = Off
expose_php = Off
display_errors = Off
log_errors = On
session.cookie_httponly = 1
EOF
    explain "Riskier (an app might need them - only with the app owner, test right after):"
    explain "  disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec"
    explain "    -> a webshell can't run commands. phpMyAdmin/WordPress core don't need them; some plugins do."
    if confirm_risky "Also disable PHP's shell functions (disable_functions)?"
    then
        printf 'disable_functions = exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec\n' >> "$T/hardening.ini"
        risky_funcs=1
    fi
    sed 's/^/      | /' "$T/hardening.ini"
    confirm_safe "Install this file in every PHP conf.d folder and restart PHP?" || return
    code_before=$(http_code)
    for d in $(ini_dirs)
    do
        install -m 644 "$T/hardening.ini" "$d/$INI_NAME" && printf "  wrote %s/%s\n" "$d" "$INI_NAME"
    done
    restart_php
    sleep 2
    code_after=$(http_code)
    printf "  %s answered HTTP %s before, HTTP %s after\n" "$URL" "${code_before:-000}" "${code_after:-000}"
    if [[ "$code_before" =~ ^[23] && ! "$code_after" =~ ^[234] ]]
    then
        flag "the site broke after the change - taking it back"
        undo
    else
        did "PHP HARDENED ($INI_NAME in $(ini_dirs | paste -sd' ' -))${risky_funcs:+ incl. disable_functions}" "./php-lockdown.sh undo"
        php -r 'echo "  check: session.upload_progress.enabled=", var_export((bool)ini_get("session.upload_progress.enabled"), true), "\n";' 2>/dev/null
        explain "PHP-FPM reads its own copy: confirm in the browser with a phpinfo() page only if you must (delete it after)."
    fi
}

undo() {
    local d
    for d in $(ini_dirs)
    do
        rm -f "$d/$INI_NAME"
    done
    restart_php
    did "PHP hardening file removed and PHP restarted"
}

step_iconv() {
    local f
    section "CNEXT (CVE-2024-2961): glibc iconv ISO-2022-CN-EXT"
    explain "This glibc bug turns any PHP 'read a file' bug (php://filter) into running commands."
    explain "Updated glibc fixes it; disabling the unused Chinese charset blocks it even if glibc is old."
    if ! iconv -l 2>/dev/null | grep -qi 'ISO-2022-CN-EXT'
    then
        ok "ISO-2022-CN-EXT is not available - blocked"
        return
    fi
    caution "ISO-2022-CN-EXT is enabled (glibc $(ldd --version 2>/dev/null | head -n 1 | awk '{print $NF}'))"
    f=$(ls /usr/lib/x86_64-linux-gnu/gconv/gconv-modules.d/gconv-modules-extra.conf /usr/lib64/gconv/gconv-modules.d/gconv-modules-extra.conf \
         /usr/lib/x86_64-linux-gnu/gconv/gconv-modules /usr/lib64/gconv/gconv-modules 2>/dev/null | xargs -r grep -l 'ISO-2022-CN-EXT' 2>/dev/null | head -n 1)
    [[ -z "$f" ]] && { caution "couldn't find the gconv-modules file - update glibc instead"; return; }
    if confirm_safe "Disable ISO-2022-CN-EXT in $f (then iconvconfig)?"
    then
        backup_file "$f"
        sed -i -E '/ISO-2022-CN-EXT/ s/^([^#])/#\1/' "$f"
        iconvconfig 2>/dev/null
        iconv -l 2>/dev/null | grep -qi 'ISO-2022-CN-EXT' && flag "still listed - restart PHP or update glibc" \
            || did "CNEXT blocked: ISO-2022-CN-EXT disabled in $f" "sed -i 's/^#\(.*ISO-2022-CN-EXT\)/\1/' $f && iconvconfig"
        restart_php
    fi
}

step_webapps() {
    local f roots
    section "PHP FILES RED TEAM USES"
    roots=$(ls -d /var/www /usr/share/nginx /usr/share/phpmyadmin /usr/share/phpMyAdmin /srv /opt 2>/dev/null | paste -sd' ' -)
    [[ -z "$roots" ]] && { ok "no web folders"; return; }
    step "phpMyAdmin / Adminer (a web login straight into the database)"
    find $roots /etc/phpmyadmin -maxdepth 4 \( -iname 'adminer*.php' -o -iname 'phpmyadmin' -o -name 'config.inc.php' \) 2>/dev/null | head -n 10 | while read -r f
    do
        flag "found $f - red team brute-forces / exploits these"
        todo "Restrict $f to the team network (or remove it if not scored) - check the scoring page first"
    done
    find $roots -maxdepth 5 -type d -iname setup -path '*phpmyadmin*' 2>/dev/null | while read -r f
    do
        flag "phpMyAdmin setup folder is present: $f (lets anyone write the config)"
        confirm_safe "Quarantine $f?" && quarantine "$f" "phpMyAdmin setup dir"
    done
    step "PHP files inside upload folders (normal sites never run code from uploads)"
    find $roots -xdev -type f -iname '*.php*' \( -path '*/uploads/*' -o -path '*/upload/*' -o -path '*/files/*' -o -path '*/images/*' -o -path '*/tmp/*' \) 2>/dev/null \
        | head -n 20 | while read -r f
    do
        flag "PHP in an upload folder: $f ($(stat -c '%U %y' "$f" | cut -c1-30))"
        confirm_safe "Quarantine $f?" && quarantine "$f" "PHP in upload folder"
    done
    step "Webshell patterns"
    find $roots -xdev -type f \( -iname '*.php*' -o -iname '*.phtml' \) -size -2M 2>/dev/null \
        | xargs -r grep -lE '(eval|assert|system|exec|shell_exec|passthru|popen|proc_open)\s*\(\s*(\$_(GET|POST|REQUEST|COOKIE|SERVER)|base64_decode|gzinflate|str_rot13)|base64_decode\s*\(\s*\$_' 2>/dev/null \
        | head -n 20 | while read -r f
    do
        flag "webshell pattern: $f"
        grep -nE 'eval|assert|system|exec|passthru' "$f" | head -n 2 | cut -c1-150 | sed 's/^/      | /'
        if is_owned "$f"
        then
            confirm_risky "Quarantine $f (from a package - may be a false alarm)?" && quarantine "$f" "webshell pattern"
        else
            confirm_safe "Quarantine $f?" && quarantine "$f" "webshell"
        fi
    done
    ok "web folders checked"
}

if [[ "$1" == "undo" ]]; then undo; exit 0; fi
banner "php-lockdown.sh  -  PHP bugs (php2shell, CNEXT, webshells)"
printf "  test page after changes: %s\n" "$URL"
log_action "START php-lockdown mode=$MODE"
step_versions
step_ini
step_iconv
step_webapps
log_action "END php-lockdown"
printf "\n${bold}${info}php-lockdown finished.${reset}  changes: %s   TODO: %s\n" "$ACTIONS" "$TODO_FILE"
exit 0
