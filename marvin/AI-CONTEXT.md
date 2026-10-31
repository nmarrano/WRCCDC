# Context for an AI helper (paste or upload this first)

I am a blue team student in a CCDC-style competition (WCComps Invitational 2, fictional company "Acme LLC").
I defend ONE box, **marvin**: Ubuntu 24.04 database server, 192.168.220.199 inside our network
(10.100.1XX.199 from outside through a 1:1 NAT, where the scoring engine is). Other team boxes in
192.168.220.0/24 run apps (blog, forums, e-commerce, tracker...) that probably use marvin's database.
A red team attacks us; a scoring engine checks services (likely SSH + the database) every 2-4 minutes,
with a penalty after 5 failed checks. Red team scores points for root/user access, stolen password
hashes, and especially stolen customer PII / credit card numbers (-200).

Please help me with **technical** questions only (commands, configs, troubleshooting, reading logs).
I will not ask you to write inject reports. Prefer short, exact commands for Ubuntu 24.04. Warn me
before anything that could take a scored service down or lock out the scoring engine.

## My scripts (github.com/nmarrano/WRCCDC, folder marvin/, run as root)
| Script | Does |
|---|---|
| `marvin.sh [init\|--auto\|--audit\|todo]` | Runs everything: backup, learn DB logins, lockdowns, firewall plan, baseline, tmux monitor |
| `linux-lockdown.sh [--auto] [step]` | passwords accounts sudo keys sshd persistence suid processes network integrity |
| `mysql-lockdown.sh`, `postgres-lockdown.sh`, `redis-lockdown.sh`, `mongodb-lockdown.sh` | Per-database lockdown; also `rotate` (password change) and `seen N` (learn which accounts log in) |
| `backup.sh [list\|verify\|restore FILE]` | /etc + dumps of every DB in /root/marvin-data/backups |
| `firewall.sh [plan\|discover\|apply\|rollback\|status\|block IP]` | ufw; SSH + DB ports stay open; 5-minute auto-rollback |
| `watch.sh [--once\|--rebaseline]` | Alert loop: DB health, drift from baseline, bad processes, outside DB logins |
| `monitor.sh` | tmux session "marvin" with live views |
| `respond.sh proc\|user\|dbuser\|ip\|file\|unit\|note\|report` | Incident response, evidence first |

Data: `/root/marvin-data/` - `marvin.conf` (protected users, TEAM_NET, SCORING_IPS), `logs/actions.log`
(every change + undo), `logs/alerts.log`, `logs/findings.log`, `TODO.txt` (risky items left for me),
`evidence/` (quarantined files, process dumps), `seen/<engine>.txt` (accounts seen logging in = protected),
`secrets.conf` (admin logins the scripts created: Redis user `marvin`, MongoDB `marvinAdmin`).

Design rules: nothing is deleted (accounts are locked, files moved to evidence/); protected and
"seen" accounts are never locked; app/scorer passwords are only changed by hand with `rotate`.

## Key facts about the databases on Ubuntu 24.04
- MySQL 8.0 / MariaDB 10.11: `sudo mysql` (root uses auth_socket). Config `/etc/mysql/mysql.conf.d/`
  (MariaDB `/etc/mysql/mariadb.conf.d/`), my changes in `zz-marvin.cnf` / `99-marvin.cnf`. Accounts are
  'user'@'host'. Lock: `ALTER USER 'u'@'h' ACCOUNT LOCK;`
- PostgreSQL 16: `sudo -u postgres psql`. `/etc/postgresql/16/main/pg_hba.conf` (first match wins),
  `postgresql.auto.conf` overrides. Disable: `ALTER ROLE x NOLOGIN;` Reload: `SELECT pg_reload_conf();`
- Redis 7.0: default user = the apps' login. The scripts removed CONFIG/MODULE/DEBUG/REPLICAOF/ACL/
  FLUSHALL/SHUTDOWN/MONITOR from it; admin is `redis-cli --user marvin --askpass`.
- MongoDB 8.0: `/etc/mongod.conf`, `security.authorization`. Admin `marvinAdmin` (password in secrets.conf).
- SSH: service `ssh` (socket-activated); my settings in `/etc/ssh/sshd_config.d/00-marvin.conf`.

## When I ask for help I will paste
the exact error / log lines, the output of the relevant script, and what changed last (`tail actions.log`).
