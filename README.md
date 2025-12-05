# LinResponse.sh - Linux Forensic Collection Script

[![NPM Version][bash-image]][npm-url]
[![NPM Version][Forensics-image]][npm-url]

<p align="center">
  <img width="660" height="400" src="https://github.com/4NV1L/Live-Response/blob/master/Script_Screenshot.png">
</p>



## Overview

`LinResponse.sh` is a comprehensive forensic evidence collection script for Linux endpoints. It automates the collection of critical system, user, and network information to support incident response, compromise assessment, and forensic investigations. The script is intended for use by security analysts, incident responders, and system administrators who need to quickly and consistently collect volatile and non-volatile data from Linux systems.

> **Note:** This script is for Linux endpoints only. MacOS and Windows forensic collection scripts are planned for future release.

---

## Example Usage

```sh
sudo bash LinResponse.sh --scan full
sudo bash LinResponse.sh --scan light
sudo bash LinResponse.sh --help
```

- `--scan full` : Runs the full forensic collection (default if no option is provided)
- `--scan light` : Runs a lightweight scan (user accounts, processes, network connections)
- `--help` : Displays usage information

---

## Command List (Organized by Function)

### System & User Enumeration
- `cat`, `awk`, `grep`, `w`, `last`, `faillog`, `getent`, `alias`, `uptime`, `env`, `whoami`, `id`
- User and group info: `/etc/passwd`, `/etc/group`, `/etc/shadow`, `/etc/login.defs`, `/etc/sudoers`
- SSH keys: `/root/.ssh/authorized_keys`, `/home/*/.ssh/authorized_keys`
- Shell history: `/root/.bash_history`, `/home/*/.bash_history`, `.zsh_history`, `.history`

### Process & Memory Inspection
- `ps`, `pstree`, `top`, `head`, `cat /proc/cmdline`, `cat /proc/*/maps`, `cat /proc/*/environ`
- Resource usage: `ps -eo ... --sort=-%mem`, `ps -eo ... --sort=-%cpu`

### Network Inspection
- `ss`, `netstat`, `lsof`, `arp`, `ifconfig`, `ip`, `iptables`, `route`, `hostname`, `cat /etc/hosts`, `cat /etc/resolv.conf`, `cat /etc/hosts.allow`, `cat /etc/hosts.deny`

### File System & Integrity
- `ls -ailhr` (on `/bin`, `/sbin`, `/etc/cron.d`, `/tmp`, `/home`, `/root`, `/usr/local`, `/opt`)
- `find` (for hidden files, SUID/SGID files, world-writable directories, recent file changes)
- `sha1sum` (hashing binaries, cron, tmp, and hidden files)
- `du`, `mount`, `df`, `lsblk`, `fdisk`, `lsusb`, `lspci`, `lsmod`, `modinfo`

### Log & Cron Collection
- `ls`, `cp`, `cat`, `find` (on `/var/log`, `/etc/cron*`, `/var/spool/cron/crontabs/*`)
- Log backup: `cp -R -v * /tmp/Forensics/Backuplogs`

### Security & Audit Checks
- `find` (private SSH keys, AWS keys, git credentials, SUID/SGID files, world-writable directories)
- `grep` (cryptominer indicators, suspicious process names)
- `rpm -Va`, `debsums -s` (package integrity)

### Docker Awareness
- `docker --version`, `docker ps -a`, `find` (for Dockerfile, docker-compose.yml)

---

## Detailed Functionality

- **Scan Selection:**
  - `--scan full` (default): Runs both the lightweight scan and the full forensic scan, collecting extensive system, user, process, network, file, and configuration data.
  - `--scan light`: Runs a subset of the full scan, focusing on user accounts, running processes, and network connections for quick triage.

- **Logging and Output:**
  - All collected data is stored in a timestamped directory under `Incident/`.
  - Each command's output is saved to a separate file for easy review.
  - A summary file is generated at the end, listing actions performed, failures, start/end time, and duration.
 
```sh
$ ls
MacMapping.txt              diskusage.txt            hidden-files.txt    last_users.txt         mount.txt                 process-tree.txt  sudoers_file.txt
awskeyfiles.txt             dmesg.txt                home.txt            listeningproc-TCP.txt  netrouting.txt            processes.txt     tmp.txt
bash_history_all_users.txt  docker-files.txt         hosts-file.txt      listeningproc-UDP.txt  netstat.txt               roothistory.txt   user-history-files.txt
binfiles.txt                etc.txt                  ifconfig.txt        listeningproc.txt      netstat_est.txt           sbinfiles.txt     useraccountstats.txt
cronjobs.txt                group_file.txt           iptables.txt        log.txt                passwd_file.txt           shadow_file.txt
current_users.txt           hidden-files-hashes.txt  kernel-modules.txt  mail.txt               private_ssh_keyfiles.txt  socketinfo.txt
```


- **User and Account Information:**
  - Enumerates normal and system user accounts, current and last logins, failed logins, and shell histories.
  - Collects SSH authorized keys for root and all users.

- **Process and Network Information:**
  - Captures running processes, process trees, top resource-consuming processes, open/listening ports, established connections, and network interface details.

- **File System and Configuration:**
  - Lists and hashes files in `/bin`, `/sbin`, `/etc/cron.d`, `/tmp`, `/home`, `/root`, `/usr/local`, `/opt`.
  - Collects information on hidden files and their hashes in key directories.
  - Gathers mount points, disk usage, kernel modules, and system configuration files.

- **Log and Cron Collection:**
  - Copies and lists available logs from `/var/log`.
  - Collects cron jobs and scheduled tasks from system and user crontabs.

- **Security and Audit Checks:**
  - Checks for world-writable directories, SUID/SGID files, recent file changes, and suspicious processes.
  - Looks for private SSH keys, AWS keys, and git credentials.
  - Performs basic cryptominer detection using known process and file indicators.

- **Docker Awareness:**
  - Detects Docker installation, running containers, and Docker-related files.

- **Summary and Error Reporting:**
  - At the end of execution, prints and saves a summary of actions performed, failures, and total runtime.

---

## Requirements & Notes

- **Root privileges** are required for full data collection.
- The script is intended for use on **Linux endpoints** only.
- Output is written to the `Incident/` directory in the current working directory.
- Some commands may not be available on all distributions; the script handles missing commands gracefully and logs failures.
- Forensic memory dump collection is not included by default, but can be added as a separate script.

---

## Roadmap

- MacOS and Windows forensic collection scripts are planned for future release.
- Suggestions and contributions are welcome!

---

## Disclaimer

Use this script at your own risk. It is intended for forensic and incident response purposes by trained professionals. Always test in a safe environment before deploying to production systems.

## References

- [RFC 3227: Guidelines for Evidence Collection and Archiving](https://tools.ietf.org/html/rfc3227)

---
*For suggestions, improvements, or issues, please open an issue or pull request.*

<!-- Markdown link & img dfn's -->
[bash-image]: https://img.shields.io/badge/Code-BASH-brightgreen&?style=for-the-badge&logo=appveyor
[Forensics-image]: https://img.shields.io/badge/Type-Forensics-brightgreen&?style=for-the-badge&logo=appveyor
[npm-url]: https://img.shields.io/badge/Type-Forensics-brightgreen&?style=for-the-badge&logo=appveyor

