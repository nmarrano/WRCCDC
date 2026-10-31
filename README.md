# WRCCDC
Scripts to be used for WRCCDC. **One folder per box - don't mix them up:**

| Folder | Box | OS | Service | Data on the box | tmux |
|---|---|---|---|---|---|
| [marvin/](marvin/) | marvin `.199` | Ubuntu 24.04 | Database (MySQL/MariaDB, PostgreSQL, Redis, MongoDB) | `/root/marvin-data` | `marvin` |
| [sylvester/](sylvester/) | sylvester `.69` | Rocky Linux 9 | Video streamer (Jellyfin/Plex/Owncast/MediaMTX/nginx-rtmp...) | `/root/sylvester-data` | `sylvester` |

Start with `marvin/RUNBOOK.md` or `sylvester/README.md`.
