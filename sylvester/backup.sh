#!/bin/bash
#
# backup.sh
#
# Backs up sylvester BEFORE you change anything: /etc and the streaming app's config +
# database (users, settings, plugins). Video files themselves are skipped (too big;
# red team rarely deletes them). Goes to /root/sylvester-data/backups/<time>/ (root only).
#
# Usage:
#   sudo ./backup.sh             back up now
#   sudo ./backup.sh list        what backups exist
#   sudo ./backup.sh verify      checksums: did anyone change them?
#   sudo ./backup.sh restore     how to put files back
#
# Sylvester (video streamer, Rocky Linux) - WCComps 2026 INV2
# Oct. 2026

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
. "$SCRIPT_DIR/lib/common.sh"
require_root
setup_dirs
load_conf
SCRIPT_NAME=backup
APPS="${APPS:-$(detect_apps | paste -sd' ' -)}"
MEDIA='--exclude=*.mp4 --exclude=*.mkv --exclude=*.avi --exclude=*.mov --exclude=*.ts --exclude=*.m4s --exclude=*.flv --exclude=*.webm --exclude=*/transcodes/* --exclude=*/cache/*'

backup_now() {
    local dir a paths
    banner "backup.sh  -  sylvester"
    dir="$BACKUPS/$(date +%Y%m%d-%H%M%S)"
    mkdir -p "$dir" && chmod 700 "$dir"
    tar czf "$dir/etc.tgz" -C / etc 2>/dev/null && ok "etc.tgz"
    for a in $APPS
    do
        paths=$(app_paths "$a" | grep -v '^/etc' | paste -sd' ' -)
        [[ -z "$paths" ]] && continue
        # shellcheck disable=SC2086
        tar czf "$dir/app-$a.tgz" $MEDIA $paths 2>/dev/null
        ok "app-$a.tgz ($(du -h "$dir/app-$a.tgz" | cut -f1)) - $paths (videos skipped)"
    done
    for a in /var/www /usr/share/nginx/html
    do
        [[ -d "$a" ]] && tar czf "$dir/web-$(basename "$a").tgz" $MEDIA "$a" 2>/dev/null && ok "web-$(basename "$a").tgz"
    done
    (cd "$dir" && sha256sum -- * > SHA256SUMS)
    chmod 600 "$dir"/*
    did "BACKUP made in $dir ($(du -sh "$dir" | cut -f1))"
    explain "Copy it off the box too:  ssh USER@192.168.220.69 'sudo tar czf - -C $BACKUPS .' > sylvester-backups.tgz"
}

case "$1" in
    ""|now) backup_now ;;
    list) for d in "$BACKUPS"/*/; do [[ -d "$d" ]] && printf "  %s  %s\n" "$(basename "$d")" "$(ls "$d" | grep -v SHA | paste -sd' ' -)"; done ;;
    verify) for d in "$BACKUPS"/*/; do (cd "$d" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1) && ok "$(basename "$d")" || flag "$(basename "$d") CHANGED"; done ;;
    restore)
        explain "Restore ONE thing, never all of /etc at once. Stop the app first (systemctl stop <app>):"
        explain "  tar xzf $BACKUPS/<time>/app-jellyfin.tgz -C /      (puts the app config/database back)"
        explain "  tar xzf $BACKUPS/<time>/etc.tgz -C /tmp etc/ssh/sshd_config   (then compare + copy one file)"
        explain "  restorecon -Rv <restored folder>     (fix SELinux labels!)   then: systemctl start <app>" ;;
    -h|--help) usage_from_header ;;
    *) usage_from_header; exit 1 ;;
esac
exit 0
