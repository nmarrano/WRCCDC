# marvin - database server lockdown scripts

Blue-team scripts for **marvin**, the Ubuntu 24.04 database box (WCComps 2026 Invitational 2).
Covers MySQL/MariaDB, PostgreSQL, Redis and MongoDB, plus the Linux side, a safe firewall,
monitoring in tmux and incident response. Modelled on `sovereignty.sh`, but every step explains itself.

**Competition steps: [RUNBOOK.md](RUNBOOK.md).** Context for an AI helper: [AI-CONTEXT.md](AI-CONTEXT.md).

## Get them onto the box
```bash
sudo -i
git clone https://github.com/nmarrano/WRCCDC.git && cd WRCCDC/marvin && chmod +x *.sh
./marvin.sh init      # protected users, databases, network
./marvin.sh           # everything (asks first)   |  --auto  |  --audit
```

## Scripts
| Script | What it does |
|---|---|
| `marvin.sh` | backup → learn DB logins → Linux + DB lockdowns → firewall plan → baseline → tmux monitor |
| `linux-lockdown.sh` | passwords, accounts (UID 0, empty pw, service shells, admin groups), sudo, SSH keys, sshd, persistence (cron, systemd, ld.so.preload, PAM, motd, apt hooks, login scripts, temp-folder programs), SUID/caps, processes, ports, `dpkg --verify` |
| `mysql-lockdown.sh` | accounts (anonymous, empty pw, remote root, unknown admins), FILE/SUPER/GRANT, `*.*` grants, local_infile, secure_file_priv, init_connect, query-log location, UDFs, plugin libs, malicious triggers/events/routines, INTO OUTFILE files, `rotate`, `seen` |
| `postgres-lockdown.sh` | pg_hba (trust, superusers over the network), superusers, pg_execute_server_program, archive_command, preload libs, COPY…PROGRAM functions, event triggers, log_connections, `rotate`, `seen` |
| `redis-lockdown.sh` | admin ACL user, dangerous commands removed from the apps' user, unknown ACL users off, rogue replica, dump dir/filename, modules, Redis dumps written as SSH keys / cron, `rotate` |
| `mongodb-lockdown.sh` | users + roles, authorization on (safe restart with rollback), login-less clients, stored JS, `rotate` |
| `backup.sh` | /etc + every database dump, checksums, `restore` |
| `firewall.sh` | ufw that only closes what is clearly unneeded: SSH (22 + any sshd port), DB ports and every port listening now stay open; only temp-folder backdoor listeners + unused ports are closed. `LIMIT_DB=yes` limits the DB port to team + scorer. 5-min auto-rollback, `block IP` |
| `watch.sh` | alert loop: DB health, drift from baseline (files, users, ports, SUID, units, **DB accounts**, firewall), processes, outside DB logins |
| `monitor.sh` | tmux session `marvin`: alerts, new processes, net, auth, DB sessions/logs, accounts, shell |
| `respond.sh` | `proc user dbuser ip file unit note report` - evidence first |

## Safety rules built in
- Modes: interactive (Enter = safe answer), `--auto` (only safe fixes; risky → `/root/marvin-data/TODO.txt`), `--audit` (no changes).
- Never deletes users or files: accounts are **locked**, files **moved** to `/root/marvin-data/evidence/`.
- Never touches `PROTECTED_*` users or DB accounts **seen logging in** (apps, scorer).
- Never changes app/scorer passwords on its own (`rotate` step, by hand, + PCR).
- Every change → `/root/marvin-data/logs/actions.log` with its undo command.

Tested on Ubuntu 24.04 with MySQL 8.0, PostgreSQL 16, Redis 7.0 and MongoDB 8.0 against a planted red-team setup.
MariaDB uses the same script (`mysql-lockdown.sh`) but was not lab-tested.
