# Marvin Competition Runbook (no AI needed)

Box: **marvin**, Ubuntu database server, `192.168.220.199` (outside / scorer: `10.100.1XX.199`).
Everything the scripts change is logged in `/root/marvin-data/logs/actions.log`, with the undo command.

## 0. Before 9:00
- [ ] VPN up (NetBird, team SSO). Discord linked (`/link` in #general).
- [ ] Scoring page open: `https://scoring.wccomps.org` → note **which checks hit marvin** and **which usernames** they use.

## 1. Get in + get the scripts (minute 0-2)
```bash
ssh <user>@192.168.220.199
sudo -i
passwd                      # change root FIRST
passwd <your user>          # then yours -> team sheet
cd /root && git clone https://github.com/nmarrano/WRCCDC.git && cd WRCCDC/marvin
# no git?  curl -L https://github.com/nmarrano/WRCCDC/archive/refs/heads/main.tar.gz | tar xz && cd WRCCDC-main/marvin
chmod +x *.sh
```

## 2. Config (minute 2-4)
```bash
./marvin.sh init
```
- Protected Linux users = the scorer's SSH user + you + teammates. **These are never touched.**
- Protected DB users = the scorer's DB login (if the scoring page shows one). Apps are found automatically.
- Scoring IPs: leave empty for now.

## 3. Lock it down (minute 4-15)
```bash
./marvin.sh            # asks before each change. Enter = the SAFE answer.
# in a hurry:  ./marvin.sh --auto   (safe fixes only; risky ones -> TODO list)
```
What happens: backup → 2 min of watching DB logins (protects apps/scorer) → Linux lockdown → each database → firewall plan → baseline → **tmux monitor opens**.

Answer YES to: anything marked `[!!]` that is clearly red team (reverse shells, temp-folder programs, UID 0 accounts, unknown keys, UDFs, `archive_command` with curl, rogue replica).
Answer NO to: locking an account you don't recognise **unless** you checked the scoring page and the app configs.

## 4. Right after the lockdown
- [ ] `./marvin.sh todo` → work through the list.
- [ ] Post in teamXX-chat: DB engine, which DB users each box uses, what you changed.
- [ ] **Passwords used by apps**: coordinate with the box owner, then `./<engine>-lockdown.sh rotate`. Scored account → **PCR in Quotient** with the same password.
- [ ] Find the scorer's IP: `./firewall.sh discover 6` (type the outside IP it shows when asked).
- [ ] Firewall: `./firewall.sh apply` → watch the scoreboard → type `yes` within 5 min. If anything goes red, just wait - it rolls back by itself.

## 5. During the day (the tmux monitor)
| Keys | |
|---|---|
| `Ctrl-b 0`..`6` | windows: alerts, procs, net, auth, db, users, shell |
| `Ctrl-b` + arrow | switch pane |
| `Ctrl-b d` | detach (`sudo tmux attach -t marvin` to return) |
| `Ctrl-b [` | scroll (q to exit) |

Red line in **alerts** or **procs** → respond:
```bash
./respond.sh proc PID           # evidence + kill
./respond.sh user NAME          # lock Linux account (refuses protected ones)
./respond.sh dbuser mysql NAME  # lock DB account (mysql|postgres|redis|mongodb)
./respond.sh ip 1.2.3.4         # block + cut connections (refuses scorer/router)
./respond.sh unit NAME          # stop + mask a systemd backdoor
./respond.sh file /path         # quarantine
./linux-lockdown.sh persistence # re-hunt backdoors (or: --audit for everything)
./watch.sh --rebaseline         # after YOU changed something on purpose
./respond.sh report 10:30       # incident report draft -> ticket at teams.wccomps.org
```
Every ~hour: `./backup.sh` and `./linux-lockdown.sh --audit`.

## 6. Something is down
1. `systemctl status mysql postgresql redis-server mongod ssh`
2. `ss -tlnp` - is it listening on `0.0.0.0` (not just 127.0.0.1)?
3. `./firewall.sh status` - blocked? `./firewall.sh rollback` if you're unsure.
4. Was it a password change? Check `logs/actions.log` - put the old one back or fix the app config.
5. Data gone? `./backup.sh list` → `./backup.sh restore /root/marvin-data/backups/<time>/<file>`
6. Stuck 10 min → Scoring Service Check ticket (10 pts). Service Reset = 60 pts, last resort.

## Rules to remember
- Never delete accounts the scorer might use - lock or change password + PCR.
- Injects: PDF, `inject04_team13.pdf`, written by YOU (AI-detected = 0 points).
- #general and #memes are read by red team. Passwords go in the team sheet only.
