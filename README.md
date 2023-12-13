# Live-Response (No Longer Supported)
> Linux Incident Response Bash script for live-response purposes.

[![NPM Version][bash-image]][npm-url]
[![NPM Version][Forensics-image]][npm-url]

<p align="center">
  <img width="660" height="400" src="https://github.com/4NV1L/Live-Response/blob/master/Script_Screenshot.png">
</p>

## Description

Through most intrusion events, or incidents you will want to initiate a live-response investigation. The goal of the script is mainly data collection and doing so while keeping the integrity of the evidence you collect. Live data collections should be conducted with minimal changes on the system, or if there are changes, they need to be logged. The level of changes to the target system will vary dependent on the organization needs.  With this bash script you will find evidence collecting commands and an audit trail for each command run on the system. You will have created folders in /tmp where you can access this data or compress it, to ship it off to a different machine. 

This is a continuous project, being tested, and changed as I have time. Please feel free to make recommendations as I will take them seriously. 

### Tested Operating systems

```sh
Ubuntu - Tested
```
### Usage 

This does not currently require installing additional packages, commands will be executed, if one does not exist it is skipped and logged in the audit file "log".

This does require root priviledges, and to be run within the /tmp directory. Make sure the script is there, or simple move the script to /tmp. Line 53, is the default path configuration, you can change this to a different path if needed, but I highly recommend running within /tmp for consistency in investigations.

```sh
chmod +x ./LinResponse.sh
./LinResponse.sh
```
* Once executed (Within /tmp as root) the script will initiate creating the following directory hierarchy: 
```sh
/tmp/Forensics$ ls -thrl
total 128K
drwxr-xr-x  3 root root 4.0K Apr  7 03:31 Incident
-rw-r--r--  1 root root 113K Apr  7 03:31 hashes.csv
drwxr-xr-x 17 root root 4.0K Apr  7 03:32 Backuplogs
-rw-r--r--  1 root root  204 Apr  7 03:32 potential-Cryptominers.txt
```
* /Backuplogs will contain your entire /var/log directory
* /Incident will contain your script collection 
```sh
$ ls
MacMapping.txt              diskusage.txt            hidden-files.txt    last_users.txt         mount.txt                 process-tree.txt  sudoers_file.txt
awskeyfiles.txt             dmesg.txt                home.txt            listeningproc-TCP.txt  netrouting.txt            processes.txt     tmp.txt
bash_history_all_users.txt  docker-files.txt         hosts-file.txt      listeningproc-UDP.txt  netstat.txt               roothistory.txt   user-history-files.txt
binfiles.txt                etc.txt                  ifconfig.txt        listeningproc.txt      netstat_est.txt           sbinfiles.txt     useraccountstats.txt
cronjobs.txt                group_file.txt           iptables.txt        log.txt                passwd_file.txt           shadow_file.txt
current_users.txt           hidden-files-hashes.txt  kernel-modules.txt  mail.txt               private_ssh_keyfiles.txt  socketinfo.txt
```
### Command List
List of commands enabled in the script (coming soon)


### Future work
* Stress testing other operating systems. 
* Create Downsized version of script, to remove redundant commands. 



### References 

* https://tools.ietf.org/html/rfc3227 Guidelines for Evidence Collection and Archiving
<!-- Markdown link & img dfn's -->
[bash-image]: https://img.shields.io/badge/Code-BASH-brightgreen&?style=for-the-badge&logo=appveyor
[Forensics-image]: https://img.shields.io/badge/Type-Forensics-brightgreen&?style=for-the-badge&logo=appveyor
[npm-url]: https://img.shields.io/badge/Type-Forensics-brightgreen&?style=for-the-badge&logo=appveyor
