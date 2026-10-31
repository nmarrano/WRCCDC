# sylvester - video streaming box lockdown scripts (Rocky Linux)

Blue-team scripts for **sylvester** (`192.168.220.69`), the Rocky Linux video streamer, WCComps 2026
Invitational 2. Same design as the `marvin/` (database box) scripts, but for Rocky + a streaming app.
**These are separate from marvin**: own folder, own data folder `/root/sylvester-data/`, own config
`sylvester.conf`, own tmux session `sylvester`.

## Quick start (on sylvester, as root)
```bash
sudo -i
git clone https://github.com/nmarrano/WRCCDC.git && cd WRCCDC/sylvester && chmod +x *.sh
passwd                       # root first, then your own account
./sylvester.sh init          # protected users (scorer!), app, URL the scorer checks
./sylvester.sh               # backup -> Linux + SELinux -> streaming app -> firewall plan -> monitor
```

## Scripts

| Script | What it does |
|---|---|
| `sylvester.sh` | runs everything in order, then opens the tmux monitor |
| `linux-lockdown.sh` | passwords, accounts, sudo (wheel), SSH keys, sshd, **SELinux**, persistence (cron, systemd, ld.so.preload, PAM, login scripts, temp-folder programs), SUID/caps, processes, ports, `rpm -Va` |
| `stream-lockdown.sh` | finds Jellyfin / Emby / Plex / Owncast / MediaMTX / Icecast / nginx-rtmp / Apache; open setup wizard, default Owncast password, users with no password, admin users, API keys, plugins, app running as root, writable files, webshells, recently changed files |
| `php-lockdown.sh` | PHP (phpMyAdmin/Adminer, PHP sites): php2shell CVE-2026-109618/109619 check + stopgap, CNEXT CVE-2024-2961, webshells, PHP in uploads; auto-undo if the site breaks |
| `backup.sh` | /etc + app config/database (videos skipped) |
| `firewall.sh` | **firewalld** that only closes what is clearly unneeded: SSH, the app ports and every port listening now stay open; only temp-folder backdoor listeners + unused ports are closed. 5-min auto-rollback, `block IP` |
| `watch.sh` | alert loop: app service + ports + STREAM_URL, drift from baseline (files, users, ports, SUID, units, firewall, SELinux), bad processes, outbound |
| `monitor.sh` | tmux `sylvester`: alerts, new processes, net, logins, app status/logs, users, shell |
| `respond.sh` | `proc user ip file unit note report` - evidence first |

Modes: interactive (Enter = safe), `--auto` (safe fixes only, risky → TODO.txt), `--audit` (no changes).
Nothing is deleted (accounts locked, files moved to `/root/sylvester-data/evidence/`), protected users are
never touched, every change is in `logs/actions.log` with its undo.

## Day-of checklist
1. Scoring page: which checks hit sylvester (SSH? the web page on 8096/80? RTMP 1935?) and which usernames.
2. `./sylvester.sh init` → `./sylvester.sh` → `./sylvester.sh todo`.
3. App passwords/admins are changed in the app's **web admin page** (the script prints exactly where).
4. `./firewall.sh discover 6`, then `./firewall.sh apply` and type `yes` while the scoreboard stays green.
5. Keep `sudo tmux attach -t sylvester` open. Red line → `./respond.sh ...`.

## Tested
Ported from the lab-tested marvin scripts (same lockdown/monitor/respond core). The Rocky-specific parts
(rpm, firewalld, SELinux) and the app checks were syntax-checked; the app checks for Jellyfin/Plex/Owncast/
MediaMTX were written from their documented config formats and were **not** run against those apps - read
their output with care on the day.
