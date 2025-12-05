#!/bin/bash
# Linux Forensic shell script
## 4NV1L
## This script needs to be stress tested

usage() {
printf "\e[1;34m #######################################################################\n \e[0m"
printf "\e[1;34m #######################################################################\n \e[0m" 
  printf "\e[1;34m\n"
  printf "███████╗  ██████╗  ██████╗  ███████╗ ███╗   ██╗ ███████╗ ██╗  ██████╗ ███████╗\n"
  printf "██╔════╝ ██╔═══██╗ ██╔══██╗ ██╔════╝ ████╗  ██║ ██╔════╝ ██║ ██╔════╝ ██╔════╝\n"
  printf "█████╗   ██║   ██║ ██████╔╝ █████╗   ██╔██╗ ██║ ███████╗ ██║ ██║      ███████╗\n"
  printf "██╔══╝   ██║   ██║ ██╔══██╗ ██╔══╝   ██║╚██╗██║ ╚════██║ ██║ ██║      ╚════██║\n"
  printf "██║      ╚██████╔╝ ██║  ██║ ███████╗ ██║ ╚████║ ███████║ ██║ ╚██████╗ ███████║\n"
  printf "╚═╝       ╚═════╝  ╚═╝  ╚═╝ ╚══════╝ ╚═╝  ╚═══╝ ╚══════╝ ╚═╝  ╚═════╝ ╚══════╝\n"
  printf "\e[0m\n"
printf "\e[1;34m #######################################################################\n \e[0m" 
printf "\e[1;34m ################ INCIDENT RESPONSE LINUX FORENSIC SCRIPT ##############\n \e[0m"
printf "\e[1;34m #######################################################################\n \e[0m"  
printf "\e[1;34m Usage: $0 --scan [full|light] (ex. ./script.sh --scan light | ./script.sh --scan full) \n \e[0m"
printf "\e[1;34m Default is full scan. \n \e[0m"
}

# Grabbing summary information and script tracking stats 
SCRIPT_START_TIME=$(date +%s)
SCRIPT_START_HUMAN=$(date)
SUMMARY_FILE="$saveto/summary.txt"
SUMMARY_ACTIONS=()
SUMMARY_FAILURES=()

# Helper to record actions
record_action() {
  SUMMARY_ACTIONS+=("$1")
}
# Helper to record failures
record_failure() {
  SUMMARY_FAILURES+=("$1")
}

# Scan args 
SCAN_TYPE="full"
while [[ $# -gt 0 ]]; do
  case $1 in
    --scan)
      SCAN_TYPE="$2"
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      shift
      ;;
  esac
done

usage



# functions to display progress bar for main sections 
prog() {
    local w=80 p=$1; shift
    # create a string of spaces, then change them to dots
    printf -v dots "%*s" "$(( $p*$w/100 ))" ""; dots=${dots// /.};
    # print those dots on a fixed-width space plus the percentage etc. 
    printf "\r\e[K|%-*s| %3d %% %s" "$w" "$dots" "$p" "$*"; 
}
# Function to display a horizontal bar for visual separation
bar() {
  # test loop
  for x in {1..100}; do
    prog "$x" $(printf '\e[00;36m [ Beginning Next Phase ]\e[00m\n') $(date)
    sleep .01  # do some work here
  done
  echo
}

# Checks script for the /tmp directory and root user you can comment this out if you don't want these checks. However, the script will be more effective if ran with root privileges 
checks() { 

[[ UID == 0 || $EUID == 0 ]] || (
    echo '--------------------------------------------'
    printf "\e[1;91m ERROR: \e[0m root priviledges are required.\n"
    echo '--------------------------------------------'
    exit 1
    )  || exit 1

#Confirm we are running this script in the \tmp directory, as best practice
if [ $PWD == "/tmp" ]
 then 
    echo 
    echo 'Preparing to run forensic script....'
elif [ $PWD != "/tmp" ]
then
    echo '--------------------------------------------------------------------------------------------------------'
   printf '\e[1;91m ERROR: \e[0m  For best forensic practice please run this script within the tmp directory\n'
    echo '--------------------------------------------------------------------------------------------------------'
    exit 1   
fi || exit 1
}
# Running checks Function call - Comment this out if you do not want to use it
#checks 
# Main scan functions based on user input

forensicscan() {
    printf "\e[1;34m Running live-response forensic collections scan...\e[0m\n"
    bar

    savedir="Incident"
    mkdir -p "$savedir" || { printf "\e[1;91m Error creating %s directory\e[0m\n" "$savedir"; exit 1; }
    saveto="$savedir/$(hostname)-$(date +%Y.%m.%d-%H.%M.%S)"
    mkdir -p "$saveto" || { printf "\e[1;91m Error creating %s directory\e[0m\n" "$saveto"; exit 1; }
    logfile="$saveto/log.txt"

    log() {
        echo "$(date +"%b %d %H:%M:%S") $(hostname) Command: $1" | tee -a "$logfile"
    }

    echo -n > "$logfile"
    log "##  Live Linux Incident Response data collection script - EXECUTED ## "
    log "##  Starting data collection..."
}

# Initialize Scanning Dependencies 
forensicscan

# ------------------------------------------------------ LIGHT WEIGHT COLLECTION BEGIN ---------------------------------------------------------

    # Lightweight scan function
    light_scan() {
      echo
      printf "\e[1;34m Running lightweight scan: user accounts, processes, network connections only.\e[0m\n"
      bar

      printf '\033[0;92m --------------------------- [ Gathering User and System Account Statistics ]---------------------------\e[0m\n'
      # Slicing statistics based on user files
      useraccountstats() {
        _l="/etc/login.defs"
        _p="/etc/passwd"
        l=$(grep "^UID_MIN" $_l)
        l1=$(grep "^UID_MAX" $_l)
        log "[+] Collecting User statistics from /etc/passwd"
        echo "----------[ Normal User Accounts ]---------------"
        awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( $3 >= min && $3 <= max  && $7 != "/sbin/nologin" ) print $0 }' "$_p"
        echo ""
        echo "----------[ System User Accounts ]---------------"
        awk -F':' -v "min=${l##UID_MIN}" -v "max=${l1##UID_MAX}" '{ if ( !($3 >= min && $3 <= max  && $7 != "/sbin/nologin")) print $0 }' "$_p"
      }
      # Collecting User and System account information
      getuid=`useraccountstats 2>/dev/null`
      if [ "$getuid" ]; then
        log "[+] Collecting User and System account information"
        log "useraccountstats > $saveto/useraccountstats.txt" 2>&1
        useraccountstats > "$saveto/useraccountstats.txt" 2>&1
        record_action "user account statistics collected"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing user account statistics: function - useraccountstats \e[0m \e[00;33m ] \e[0m\n"
        record_failure "user account statistics collection failed"
      fi

      # Collecting Current logged in users
      currentusers=`w 2>/dev/null`
      if [ "$currentusers" ]; then
        log "[+] Collecting current user logged into system information"
        log "w > $saveto/current_users.txt" 2>&1
        w > "$saveto/current_users.txt" 2>&1
        record_action "current user logged into system collected: Command w"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: w \e[0m \e[00;33m ] \e[0m\n"
        record_failure "current user logged into system collection failed: Command w"
      fi

      # Collecting Last logged in users
      lastusers=`last 2>/dev/null`
      if [ "$lastusers" ]; then
        log "[+] Collecting last user's logged into system information"
        log "last > $saveto/last_users.txt" 2>&1
        last > "$saveto/last_users.txt" 2>&1
        record_action "last users logged into system collected: Command last"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: last \e[0m \e[00;33m ] \e[0m\n"
        record_failure "last users logged into system collection failed: Command last"
      fi

      printf '\033[0;92m --------------------------- [ User Information ]---------------------------\e[0m\n'
      # User Activity
      log "[+] Collecting shell history for all users"
      record_action "Collecting shell history for all users /etc/passwd"
      for u in $(cut -f6 -d: /etc/passwd); do
        for h in .bash_history .zsh_history .history; do
          if [ -f "$u/$h" ]; then 
            cat "$u/$h" >> "$saveto/all_user_shell_history.txt"; 
          fi
        done
      done

      # Loop through users to get active SSH sessions and authorized keys
      log "[+] Dumping active SSH sessions and authorized keys by looping through /etc/passwd"
      record_action "Active SSH sessions and authorized keys collection cp /root/.ssh/authorized_keys"
      ps aux | grep '[s]shd' > "$saveto/active_sshd_processes.txt" 2>&1
      if [ -f /root/.ssh/authorized_keys ]; then 
        cp /root/.ssh/authorized_keys "$saveto/root_authorized_keys.txt"; 
      fi
      for u in $(cut -f1 -d: /etc/passwd); do
        if [ -f "/home/$u/.ssh/authorized_keys" ]; then 
          cp "/home/$u/.ssh/authorized_keys" "$saveto/${u}_authorized_keys.txt"; 
        fi
      done

      printf '\033[0;92m --------------------------- [ Collecting Running Processes ]---------------------------\e[0m\n'
      # Collecting Running Processes
      processes=`ps -auxx 2>/dev/null`
      if [ "$processes" ]; then 
        log "[+] Collecting running processes on the host"
        log "ps -auxx > $saveto/processes.txt" 2>&1
        ps -auxx > "$saveto/processes.txt" 2>&1
        record_action "running processes collected: Command ps -auxx"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing process information: Command: ps -auxx \e[0m \e[00;33m ] \e[0m\n"
        record_failure "running processes collection failed: Command ps -auxx"
      fi

      processtree=`pstree 2>/dev/null`
      if [ "$processtree" ]; then
        log "[+] Collecting process tree on the host"
        log "pstree > $saveto/process-tree.txt" 2>&1
        pstree > "$saveto/process-tree.txt" 2>&1
        record_action "running processes collected: Command pstree"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing process information: Command: pstree \e[0m \e[00;33m ] \e[0m\n"
        record_failure "process tree collection failed: Command pstree"
      fi

      printf '\033[0;92m --------------------------- [ Network Connections ]---------------------------\e[0m\n'
      # Network Connections
      ssconns=`ss 2>/dev/null`
      if [ "$ssconns" ]; then
        log "[+] Collecting external network connections with various tools"
        log "ss -tunap > $saveto/ss_tunap.txt" 2>&1
        ss -tunap > "$saveto/ss_tunap.txt" 2>&1
        record_action "external network connections collected: Command ss -tunap"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing network connections: Command: ss -tunap \e[0m \e[00;33m ] \e[0m\n"
        record_failure "external network connections collection failed: Command ss -tunap"
      fi

      netstatinfo=`netstat 2>/dev/null`
      if [ "$netstatinfo" ]; then
        log "[+] Collecting network connection information using netstat"
        log "netstat -anp > $saveto/netstat_anp.txt" 2>&1
        netstat -anp > "$saveto/netstat_anp.txt" 2>&1
        record_action "network connections collected: Command netstat -anp"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing network connections: Command: netstat -anp \e[0m \e[00;33m ] \e[0m\n"
        record_failure "network connections collection failed: Command netstat -anp"
      fi
      
      printf '\033[0;92m --------------------------- [ Interface Information ]---------------------------\e[0m\n'
      interfaceinfo=`ip addr 2>/dev/null`
      interfaceinfo2=`command -v ifconfig &>/dev/null`
      if [ "$interfaceinfo" ]; then
        log "[+] Collecting network connection and interface information: ip command"
        log "ip addr > $saveto/ip_addr.txt" 2>&1
        ip addr > "$saveto/ip_addr.txt" 2>&1
        log "ip link > $saveto/ip_link.txt" 2>&1
        ip link > "$saveto/ip_link.txt" 2>&1
        record_action "network interface information collected: Command ip addr/link"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing network interface information: Command: ip addr/link \e[0m \e[00;33m ] \e[0m\n"
        record_failure "network interface information collection failed: Command ip addr/link"
      fi

      if [ "$interfaceinfo2" ]; then 
        log "[+] Collecting network connection and interface information using outdated ifconfig"
        log "ifconfig > $saveto/ifconfig.txt" 2>&1
        ifconfig > "$saveto/ifconfig.txt" 2>&1
        record_action "network interface information collected: Command ifconfig"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing network interface information: Command: ifconfig \e[0m \e[00;33m ] \e[0m\n"
        record_failure "network interface information collection failed: Command ifconfig"
      fi

      lsofinfo=`lsof 2>/dev/null`
      if [ "$lsofinfo" ]; then
        log "[+] Collecting open files and listening processes using lsof"
        lsof -i > "$saveto/listeningproc.txt" 2>&1
        log "lsof -i > $saveto/listeningproc.txt" 2>&1
        lsof -Pni udp > "$saveto/listeningproc-UDP.txt" 2>&1
        log "lsof -Pni udp > $saveto/listeningproc-UDP.txt" 2>&1
        lsof -Pni tcp > "$saveto/listeningproc-TCP.txt" 2>&1
        log "lsof -Pni tcp > $saveto/listeningproc-TCP.txt" 2>&1
        record_action "open files and listening processes collected: Command lsof"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m Issue in grabbing open files and listening processes: Command: lsof \e[0m \e[00;33m ] \e[0m\n"
        record_failure "open files and listening processes collection failed: Command lsof"
      fi
    }

# ------------------------------------------------------ LIGHT WEIGHT COLLECTION END ---------------------------------------------------------

# ------------------------------------------------------ FULL SCAN COLLECTION BEGIN ----------------------------------------------------------

# Full scan function (wrapper for forensicscan)
    full_scan() {
      # Run all light_scan steps first
      light_scan

      # Then run full forensic scan steps

      echo
      printf "\e[1;34m Running full forensic scan...\e[0m\n"
      bar

      partitionfdisk=`command -v fdisk &>/dev/null`
      if [ "$partitionfdisk" ]; then
        log "[+] Collecting Partition information: fdisk command"
        log "fdisk -l > $saveto/fdisk.txt" 2>&1
        fdisk -l > "$saveto/fdisk.txt" 2>&1
        record_action "partition information collected: Command fdisk"
      else
        printf "\e[33m └─[ \e[91mfdisk not found\e[33m ] \e[0m\n"
        record_failure "partition information collection failed: Command fdisk"
      fi

      # USB/PCI/Kernel modules
      printf '\033[0;92m --------------------------- [ USB/PCI/Kernel modules Checks ]---------------------------\e[0m\n'

      usbinfo=`command -v lsusb &>/dev/null`
      if [ "$usbinfo" ]; then
        log "[+] Collecting USB/PCI information: lsusb command"
        log "lsusb > $saveto/lsusb.txt" 2>&1
        lsusb > "$saveto/lsusb.txt" 2>&1
        record_action "USB/PCI information collected: Command lsusb"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m lsusb not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "USB/PCI information collection failed: Command lsusb"
      fi

      dmesginfo=`command -v dmesg &>/dev/null`
      if [ "$dmesginfo" ]; then
        log "[+] Collecting USB related dmesg information"
        log "dmesg | grep -i usb > $saveto/dmesg_usb.txt" 2>&1
        dmesg | grep -i usb > "$saveto/dmesg_usb.txt" 2>&1
        record_action "USB related dmesg information collected: Command dmesg | grep -i usb"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m dmesg not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "USB related dmesg information collection failed: Command dmesg | grep -i usb"
      fi
      
      lspciinfo=`command -v lspci &>/dev/null`
      if [ "$lspciinfo" ]; then
        log "[+] Collecting PCI information: lspci command"
        log "lspci > $saveto/lspci.txt" 2>&1
        lspci > "$saveto/lspci.txt" 2>&1
        record_action "PCI information collected: Command lspci"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m lspci not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "PCI information collection failed: Command lspci"
      fi
      
      lsmodinfo=`command -v lsmod &>/dev/null`
      modinfoinfo=`command -v modinfo &>/dev/null`
      if [ "$lsmodinfo" ] && [ "$modinfoinfo" ]; then
        log "[+] Collecting kernel module information: lsmod and modinfo commands"
        log "lsmod | awk 'NR>1 {print $1}' | while read mod; do modinfo \"$mod\" >> $saveto/modinfo.txt 2>&1; done" 2>&1
        lsmod | awk 'NR>1 {print $1}' | while read mod; do modinfo "$mod" >> "$saveto/modinfo.txt" 2>&1; done
        record_action "kernel module information collected: Commands lsmod and modinfo"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m lsmod or modinfo not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "kernel module information collection failed: Commands lsmod and modinfo"
      fi

      # Open deleted files
      printf '\033[0;92m --------------------------- [ Open Deleted Files Checks ]---------------------------\e[0m\n'

      lsofinfo=`command -v lsof &>/dev/null`
      if [ "$lsofinfo" ]; then
        log "[+] Collecting open deleted files using lsof"
        log "lsof +L1 > $saveto/open_deleted_files.txt" 2>&1
        lsof +L1 > "$saveto/open_deleted_files.txt" 2>&1
        record_action "open deleted files collected: Command lsof +L1"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m lsof not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "open deleted files collection failed: Command lsof +L1"
      fi

      # SELinux/AppArmor
      printf '\033[0;92m --------------------------- [ SELinux/AppArmor Checks ]---------------------------\e[0m\n'
      
      sestatusinfo=`command -v sestatus &>/dev/null`
      if [ "$sestatusinfo" ]; then
        log "[+] Collecting SELinux status using sestatus"
        log "sestatus > $saveto/sestatus.txt" 2>&1
        sestatus > "$saveto/sestatus.txt" 2>&1
        record_action "SELinux status collected: Command sestatus"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m sestatus not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "SELinux status collection failed: Command sestatus"
      fi

      apparmorinfo=`command -v apparmor_status &>/dev/null`
      if [ "$apparmorinfo" ]; then
        log "[+] Collecting AppArmor status using apparmor_status"
        log "apparmor_status > $saveto/apparmor_status.txt" 2>&1
        apparmor_status > "$saveto/apparmor_status.txt" 2>&1
        record_action "AppArmor status collected: Command apparmor_status"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m apparmor_status not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "AppArmor status collection failed: Command apparmor_status"
      fi

      # Firewall rules
      printf '\033[0;92m --------------------------- [ Firewall Rules Checks ]---------------------------\e[0m\n'

      ufwinfo=`command -v ufw &>/dev/null`
      if [ "$ufwinfo" ]; then
        log "[+] Collecting firewall rules using ufw"
        log "ufw status > $saveto/ufw_status.txt" 2>&1
        ufw status > "$saveto/ufw_status.txt" 2>&1
        record_action "firewall rules collected: Command ufw status"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m ufw not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "firewall rules collection failed: Command ufw status"
      fi

      # File integrity
      printf '\033[0;92m --------------------------- [ File Integrity Checks ]---------------------------\e[0m\n'

      rpminfo=`command -v rpm &>/dev/null`
      if [ "$rpminfo" ]; then
        log "[+] Collecting file integrity information using rpm"
        log "rpm -Va > $saveto/rpm_verify.txt" 2>&1
        rpm -Va > "$saveto/rpm_verify.txt" 2>&1
        record_action "file integrity information collected: Command rpm -Va"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m rpm not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "file integrity information collection failed: Command rpm -Va"
      fi
      
      debsumsinfo=`command -v debsums &>/dev/null`
      if [ "$debsumsinfo" ]; then
        log "[+] Collecting file integrity information using debsums"
        log "debsums -s > $saveto/debsums.txt" 2>&1
        debsums -s > "$saveto/debsums.txt" 2>&1
        record_action "file integrity information collected: Command debsums -s"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m debsums not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "file integrity information collection failed: Command debsums -s"
      fi

      # Network config
      printf '\033[0;92m --------------------------- [ Network Config Checks ]---------------------------\e[0m\n'

      if [ -f /etc/resolv.conf ]; then
        log "cat /etc/resolv.conf > $saveto/resolv.conf.txt" 2>&1
        cat /etc/resolv.conf > "$saveto/resolv.conf.txt" 2>&1
        record_action "network config collected: File /etc/resolv.conf"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m /etc/resolv.conf not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "network config collection failed: File /etc/resolv.conf"
      fi

      if [ -f /etc/hosts.allow ]; then
        log "cat /etc/hosts.allow > $saveto/hosts.allow.txt" 2>&1
        cat /etc/hosts.allow > "$saveto/hosts.allow.txt" 2>&1
        record_action "network config collected: File /etc/hosts.allow"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m /etc/hosts.allow not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "network config collection failed: File /etc/hosts.allow"
      fi

      if [ -f /etc/hosts.deny ]; then
        log "cat /etc/hosts.deny > $saveto/hosts.deny.txt" 2>&1
        cat /etc/hosts.deny > "$saveto/hosts.deny.txt" 2>&1
        record_action "network config collected: File /etc/hosts.deny"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m /etc/hosts.deny not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "network config collection failed: File /etc/hosts.deny"
      fi

      # Scheduled jobs (at)
      printf '\033[0;92m --------------------------- [ Scheduled Jobs (at) Checks ]---------------------------\e[0m\n'
      
      atqinfo=`command -v atq &>/dev/null`
      if [ "$atqinfo" ]; then
        log "[+] Collecting scheduled jobs using atq"
        log "atq > $saveto/atq.txt" 2>&1
        atq > "$saveto/atq.txt" 2>&1
        record_action "scheduled jobs collected: Command atq"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m atq not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "scheduled jobs collection failed: Command atq"
      fi

      # Environment variables
      printf '\033[0;92m --------------------------- [ Environment Variables Checks ]---------------------------\e[0m\n'

      envinfo=`command -v env &>/dev/null`
      if [ "$envinfo" ]; then
        log "[+] Collecting environment variables using env"
        log "env > $saveto/env.txt" 2>&1
        env > "$saveto/env.txt" 2>&1
        record_action "environment variables collected: Command env"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m env not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "environment variables collection failed: Command env"
      fi

      # System uptime
      printf '\033[0;92m --------------------------- [ System Uptime Checks ]---------------------------\e[0m\n'

      uptimeinfo=`command -v uptime &>/dev/null`
      if [ "$uptimeinfo" ]; then
        log "[+] Collecting system uptime using uptime"
        log "uptime > $saveto/uptime.txt" 2>&1
        uptime > "$saveto/uptime.txt" 2>&1
        record_action "system uptime collected: Command uptime"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m uptime not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "system uptime collection failed: Command uptime"
      fi

      # Systemd services
      printf '\033[0;92m --------------------------- [ Systemd Services Checks ]---------------------------\e[0m\n'

      systemctlinfo=`command -v systemctl &>/dev/null`
      if [ "$systemctlinfo" ]; then
        log "[+] Collecting systemd services using systemctl"
        log "systemctl list-units --type=service > $saveto/systemd_services.txt" 2>&1
        systemctl list-units --type=service > "$saveto/systemd_services.txt" 2>&1
        record_action "systemd services collected: Command systemctl list-units --type=service"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m systemctl not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "systemd services collection failed: Command systemctl list-units --type=service"
      fi

      #Recent file changes - Commented out for now as it takes a long time to run
      #For optimitzation you can always adjust the find command to a specific directory or file type
      
      #printf '\033[0;92m --------------------------- [ Recent File Changes Checks ]---------------------------\e[0m\n'

      #if command -v find &>/dev/null; then
      #  log "find / -ctime -1 -not -path "/proc/*" -not -path "/sys/*" -not -path "/dev/*" -not -path "/run/*" -not -path "/mnt/*" -not -path "/media/*" > "$saveto/recent_file_changes.txt" > $saveto/#recent_file_changes.txt" 2>&1
      #  find / -ctime -1 > "$saveto/recent_file_changes.txt" 2>&1
      #else
      #  printf "\e[00;33m └─[ \e[0m \033[0;91m find not found \e[0m \e[00;33m ] \e[0m\n"
      #fi

      # Hidden processes
      printf '\033[0;92m --------------------------- [ Hidden Processes Checks ]---------------------------\e[0m\n'

      psinfo=`command -v ps &>/dev/null`
      if [ "$psinfo" ]; then
        log "[+] Collecting process information using ps"
        log "ps auxf > $saveto/ps_auxf.txt" 2>&1
        ps auxf > "$saveto/ps_auxf.txt" 2>&1
        record_action "process information collected: Command ps auxf"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m ps not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "process information collection failed: Command ps auxf"
      fi

      if [ -d /proc ]; then
        log "[+] Collecting /proc directory listing"
        log "ls /proc > $saveto/proc_list.txt" 2>&1
        ls /proc > "$saveto/proc_list.txt" 2>&1
        record_action "proc directory listing collected: Command ls /proc"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m /proc directory not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "proc directory listing collection failed: Command ls /proc"
      fi

      # Top resource processes
      printf '\033[0;92m --------------------------- [ Top Resource Processes Checks ]---------------------------\e[0m\n'

      psinfotop=`command -v ps &>/dev/null`
      if [ "$psinfotop" ]; then
        log "[+] Collecting top resource processes using ps"
        log "ps -eo pid,ppid,%mem,%cpu,comm > $saveto/top_cpu_processes.txt" 2>&1
        ps -eo pid,ppid,%mem,%cpu,comm | head > "$saveto/top_cpu_processes.txt" 2>&1
        record_action "top resource processes collected: Command ps -eo pid,ppid,%mem,%cpu,comm | head"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m ps not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "top resource processes collection failed: Command ps -eo pid,ppid,%mem,%cpu,comm | head"
      fi

      # Unusual SUID/SGID files
      printf '\033[0;92m --------------------------- [ Unusual SUID/SGID Files Checks ]---------------------------\e[0m\n'
      suid_sgid_files=`command -v find &>/dev/null`
      if [ "$suid_sgid_files" ]; then
        log "[+] Collecting unusual SUID/SGID files using find"
        log "find / -perm /6000 -type f -exec ls -l {} \; > $saveto/suid_sgid_files.txt" 2>&1
        find / -perm /6000 -type f -exec ls -l {} \; > "$saveto/suid_sgid_files.txt" 2>&1
        record_action "unusual SUID/SGID files collected: Command find / -perm /6000 -type f -exec ls -l {} \;"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m find not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "unusual SUID/SGID files collection failed: Command find / -perm /6000 -type f -exec ls -l {} \;"
      fi

      # Kernel parameters
      printf '\033[0;92m --------------------------- [ Kernel Parameters Checks ]---------------------------\e[0m\n'

      kernelhighlevel=`command -v uname &>/dev/null`
      if [ "$kernelhighlevel" ]; then
        log "[+] Collecting kernel parameters from uname"
        log "uname -ar > $saveto/uname_kernel.txt" 2>&1
        uname -ar > "$saveto/uname_kernel.txt" 2>&1
        record_action "kernel parameters collected: Command uname -ar"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m /proc/cmdline not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "kernel parameters collection failed: Command uname -ar"
      fi
      
      kernelinto=`cat /proc/cmdline &>/dev/null`
      if [ "$kernelinto" ]; then
        log "[+] Collecting kernel parameters from /proc/cmdline"
        log "cat /proc/cmdline > $saveto/proc_cmdline.txt" 2>&1
        cat /proc/cmdline > "$saveto/proc_cmdline.txt" 2>&1
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m /proc/cmdline not found \e[0m \e[00;33m ] \e[0m\n"
      fi

      # Aliases
      printf '\033[0;92m --------------------------- [ Aliases and Groups Checks ]---------------------------\e[0m\n'

      aliasesinfo=`command -v alias &>/dev/null`
      if [ "$aliasesinfo" ]; then
        log "[+] Collecting shell aliases using alias"
        log "alias > $saveto/aliases.txt" 2>&1
        alias > "$saveto/aliases.txt" 2>&1
        record_action "shell aliases collected: Command alias"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m alias not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "shell aliases collection failed: Command alias"
      fi

      # Groups
      groupsinfo=`command -v getent &>/dev/null`
      if [ "$groupsinfo" ]; then
        log "[+] Collecting group information using getent"
        log "getent group > $saveto/groups.txt" 2>&1
        getent group > "$saveto/groups.txt" 2>&1
        record_action "group information collected: Command getent group"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m getent not found \e[0m \e[00;33m ] \e[0m\n"
        record_failure "group information collection failed: Command getent group"
      fi



      printf '\033[0;92m --------------------------- [ User Checks ]---------------------------\e[0m\n'

      # Check if 'w' command works
      currentusers=`w 2>/dev/null`
      if [ "$currentusers" ]; then
        log "w > $saveto/current_users.txt" 2>&1
        w > "$saveto/current_users.txt" 2>&1
        record_action "current users collected: Command w"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: w \e[0m \e[00;33m ] \e[0m\n"  
        record_failure "current users collection failed: Command w"
      fi

      lastusers=`last 2>/dev/null`
      if [ "$lastusers" ]; then
        log "[+] Collecting last user's logged into system information" 
        log "last > $saveto/last_users.txt" 2>&1
        last > "$saveto/last_users.txt" 2>&1
        record_action "last users collected: Command last"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: last \e[0m \e[00;33m ] \e[0m\n"
          record_failure "last users collection failed: Command last"
      fi

      failedlogin=`faillog -a 2>/dev/null`
      if [ "$failedlogin" ]; then
        log "[+] Collecting failed login by user information" 
        log "faillog -a > $saveto/failedlogins.txt" 2>&1
        faillog -a  > "$saveto/failedlogins.txt" 2>&1
        record_action "failed logins collected: Command faillog -a"
      else
        printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: faillog -a \e[0m \e[00;33m ] \e[0m\n"
        record_failure "failed logins collection failed: Command faillog -a"
      fi

      printf '\033[0;92m --------------------------- [ Interesting Files Information ]---------------------------\e[0m\n'

      passwdfile=`cat /etc/passwd 2>/dev/null`
      if [ "$passwdfile" ]; then
        log "[+] Collecting information on /etc/passwd file" 
        log "cat /etc/passwd > $saveto/passwd_file.txt" 2>&1
        cat /etc/passwd > "$saveto/passwd_file.txt" 2>&1
        record_action "passwd file collected: Command cat /etc/passwd"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m Issue for file contente: cat /etc/passwd \e[0m \e[00;33m ] \e[0m\n" 
          record_failure "passwd file collection failed: Command cat /etc/passwd"
      fi

      shadowfile=`cat /etc/shadow 2>/dev/null`
      if [ "$shadowfile" ]; then
        log "[+] Collecting information on /etc/shadow file" 
        log "cat /etc/shadow > $saveto/shadow_file.txt" 2>&1
        cat /etc/shadow > "$saveto/shadow_file.txt" 2>&1
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m Issue for file contents: cat /etc/shadow \e[0m \e[00;33m ] \e[0m\n" 
      fi

      groupfile=`cat /etc/group 2>/dev/null`
      if [ "$groupfile" ]; then
        log "[+] Collecting information on /etc/group file" 
        log "cat /etc/group > $saveto/group_file.txt" 2>&1
        cat /etc/group > "$saveto/group_file.txt" 2>&1
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m Issue for file contents: cat /etc/group \e[0m \e[00;33m ] \e[0m\n"  
      fi

      sudoerfile=`cat /etc/sudoers 2>/dev/null`
      if [ "$sudoerfile" ]; then
        log "[+] Collecting information on /etc/sudoers file" 
        log "cat /etc/sudoers   > $saveto/sudoers_file.txt" 2>&1
        cat /etc/sudoers > "$saveto/sudoers_file.txt" 2>&1
        record_action "sudoers file collected: Command cat /etc/sudoers"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m Issue for file contents: cat /etc/sudoers \e[0m \e[00;33m ] \e[0m\n" 
          record_failure "sudoers file collection failed: Command cat /etc/sudoers"
      fi

      roothistoryinfo=`cat /root/.bash_history 2>/dev/null`
      if [ "$roothistoryinfo" ]; then
        log "[+] Collecting information on root bash history" 
        log "cat /root/.bash_history  > $saveto/roothistory.txt" 2>&1
        cat /root/.bash_history > "$saveto/roothistory.txt" 2>&1
        record_action "root bash history collected: Command cat /root/.bash_history"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: cat /root/.bash_history \e[0m \e[00;33m ] \e[0m\n" 
          record_failure "root bash history collection failed: Command cat /root/.bash_history"
      fi

      alluserhistoryfiles=`ls -ahtlr /home/* 2>/dev/null`
      if [ "$alluserhistoryfiles" ]; then
        log "[+] Collecting information on all the users bash history files" 
        log "ls -ahtlr /home/* > $saveto/user-history-files.txt" 2>&1
        ls -ahtlr /home/* > "$saveto/user-history-files.txt" 2>&1
        record_action "all user bash history files collected: Command ls -ahtlr /home/*"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ahtlr /home/* \e[0m \e[00;33m ] \e[0m\n" 
          record_failure "all user bash history files collection failed: Command ls -ahtlr /home/*"
      fi

      allusercommands=`for d in /home/*/ ; do (cd "$d" && echo "$d" && cat .bash_history); done 2>/dev/null`
      if [ "$allusercommands" ]; then
        log "[+] Collecting current user logged into system information" 
        log 'for d in /home/*/ ; do (cd "$d" && echo "$d" && cat .bash_history); done > $saveto/bash_history_all_users.txt' 2>&1
        record_action "all user bash history collected"
        for d in /home/*/ ; do (cd "$d" && echo "$d" && cat .bash_history); done > "$saveto/bash_history_all_users.txt" 2>&1
      else
          printf '\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: for d in /home/*/ ; do (cd "$d" && echo "$d" && cat .bash_history); done \e[0m \e[00;33m ] \e[0m\n'
          record_failure "all user bash history collection failed"
      fi

      printf '\033[0;92m --------------------------- [ Hashing bin, sbin, and cron.d Files ]---------------------------\e[0m\n'
      # Collecting File information 
      # Hashing bin directories, cron.d & tmp directory 
      HASHFILE="hashes.csv"
      DIRS=("/bin" "/sbin" "/tmp" "/etc/cron.d")

      # Empty or create hashes.csv
      > "$HASHFILE"

      for d in "${DIRS[@]}"; do
          if [ -d "$d" ]; then
              log "[+] Hashing directory: $d"
              find "$d" -xdev -type f -exec sha1sum -b {} \; 2>/dev/null >> "$HASHFILE"
          else
              log "[-] Skipping missing directory: $d"
          fi
      done

      # Check if hashes.csv has content
      if [ -s "$HASHFILE" ]; then
          log "[+] Hash collection complete — entries written to $HASHFILE"
          record_action "hashes collected for bin, sbin, cron.d, and tmp directory"
      else
          printf '\e[00;33m └─[ \e[0m \e[00;36m Hashing completed: no files found \e[0m \e[00;33m ] \e[0m\n'
          record_failure "hashes collection failed — no files hashed"
      fi

      printf '\033[0;92m --------------------------- [ Additional Notable File Information ]---------------------------\e[0m\n'

      sbinfiles=`ls -alithr /sbin | sort -n 2>/dev/null`
      if [ "$sbinfiles" ]; then
        log "[+] Collecting bin file information" 
        log "ls -alithr /sbin | sort -n > $saveto/sbinfiles.txt" 2>&1
        ls -alithr /sbin | sort -n > "$saveto/sbinfiles.txt" 2>&1
        record_action "sbin file information collected: Command ls -alithr /sbin | sort -n"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -alithr /sbin | sort -n \e[0m \e[00;33m ] \e[0m\n"
          record_failure "sbin file information collection failed: Command ls -alithr /sbin | sort -n"
      fi

      binfiles=`ls -alithr /bin | sort -n 2>/dev/null`
      if [ "$binfiles" ]; then
        log "[+] Collecting bin file information" 
        log "ls -alithr /bin | sort -n > $saveto/binfiles.txt" 2>&1
        ls -alithr /bin | sort -n > "$saveto/binfiles.txt" 2>&1
        record_action "bin file information collected: Command ls -alithr /bin | sort -n"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -alithr /bin | sort -n \e[0m \e[00;33m ] \e[0m\n"
          record_failure "bin file information collection failed: Command ls -alithr /bin | sort -n"
      fi

      mountinfo=`mount 2>/dev/null`
      if [ "$mountinfo" ]; then
        log "[+] Collecting information on currently mounted devices" 
        log "mount > $saveto/mount.txt" 2>&1
        mount > "$saveto/mount.txt" 2>&1
        record_action "mount information collected: Command mount"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: mount \e[0m \e[00;33m ] \e[0m\n"
          record_failure "mount information collection failed: Command mount"
      fi

      dmesginfo=`dmesg 2>/dev/null`
      if [ "$dmesginfo" ]; then
        log "[+] Collecting information on messages produced by device drivers" 
        log "dmesg > $saveto/dmesg.txt" 2>&1
        dmesg > "$saveto/dmesg.txt" 2>&1
        record_action "dmesg information collected: Command dmesg"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: dmesg \e[0m \e[00;33m ] \e[0m\n"
          record_failure "dmesg information collection failed: Command dmesg"
      fi

      tmpfiles=`ls -ailhtr /tmp/  2>/dev/null`
      if [ "$tmpfiles" ]; then
        log "[+] Collecting tmp file information" 
        log "ls -ailhtr /tmp/ > $saveto/tmp.txt" 2>&1
        ls -ailhtr /tmp/ > "$saveto/tmp.txt" 2>&1
        record_action "tmp file information collected: Command ls -ailhtr /tmp/"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ailhtr /tmp/ \e[0m \e[00;33m ] \e[0m\n"
          record_failure "tmp file information collection failed: Command ls -ailhtr /tmp/"
      fi

      etcfiles=`ls -ailhtr /etc/ | sort -n 2>/dev/null`
      if [ "$etcfiles" ]; then
        log "[+] Collecting etc file information" 
        log "ls -ailhtr /etc/ > $saveto/etc.txt" 2>&1
        ls -ailhtr /etc/ > "$saveto/etc.txt" 2>&1
        record_action "etc file information collected: Command ls -ailhtr /etc/"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ailhtr /etc/  \e[0m \e[00;33m ] \e[0m\n"
          record_failure "etc file information collection failed: Command ls -ailhtr /etc/"
      fi

      homefiles=`ls -ailhtr /home/ 2>/dev/null`
      if [ "$homefiles" ]; then
        log "[+] Collecting home file information" 
        log "ls -ailhtr /home/ > $saveto/home.txt" 2>&1
        ls -ailhtr /home/ > "$saveto/home.txt" 2>&1
        record_action "home file information collected: Command ls -ailhtr /home/"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ailhtr /home/ \e[0m \e[00;33m ] \e[0m\n" 
          record_failure "home file information collection failed: Command ls -ailhtr /home/"
      fi

      # Efficient hidden file search in key locations only
      hiddenfiles=$(find /home /root /usr/local /opt -name ".*" -type f -exec ls -al {} \; 2>/dev/null)
      if [ "$hiddenfiles" ]; then
        log "[+] Collecting hidden files in /home, /root, /usr/local, /opt"
        log 'find /home /root /usr/local /opt -name ".*" -type f -exec ls -al {} \; > $saveto/hidden-files.txt' 2>&1
        printf "%s\n" "$hiddenfiles" > "$saveto/hidden-files.txt" 2>&1
        record_action "hidden files information collected"
      else
          printf '\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: find /home /root /usr/local /opt -name ".*" -type f -exec ls -al {} \; \e[0m \e[00;33m ] \e[0m\n'
          record_failure "hidden files information collection failed"
      fi

      # Efficient hidden file hash in key locations only
      hashhiddenfiles=$(find /home /root /usr/local /opt -name ".*" -type f -exec sha1sum -b {} \; 2>/dev/null)
      if [ "$hashhiddenfiles" ]; then
        log "[+] Collecting hidden file hashes in /home, /root, /usr/local, /opt"
        log 'find /home /root /usr/local /opt -name ".*" -type f -exec sha1sum -b {} \; > $saveto/hidden-files-hashes.txt' 2>&1
        printf "%s\n" "$hashhiddenfiles" > "$saveto/hidden-files-hashes.txt" 2>&1
        record_action "hidden file hashes information collected"
      else
          printf '\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: find /home /root /usr/local /opt -name ".*" -type f -exec sha1sum -b {} \; \e[0m \e[00;33m ] \e[0m\n'
          record_failure "hidden file hashes information collection failed"
      fi

      badpermsdirectory=`find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print 2>/dev/null`
      if [ "$badpermsdirectory" ]; then
        log "[+] Collecting information for any directories that are world readable" 
        log "find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print > $saveto/W-R-Directory.txt" 2>&1
        find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print > "$saveto/W-R-Directory.txt" 2>&1
        record_action "world readable directories information collected"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: find / -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print \e[0m \e[00;33m ] \e[0m\n"
          record_failure "world readable directories information collection failed"
      fi

      hostsfile=`cat /etc/hosts 2>/dev/null`
      if [ "$hostsfile" ]; then
        log "[+] Collecting information for what is configured in the hosts file" 
        log "cat /etc/hosts > $saveto/hosts-file.txt" 2>&1
        cat /etc/hosts > "$saveto/hosts-file.txt" 2>&1
        record_action "hosts file information collected"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: cat /etc/hosts \e[0m \e[00;33m ] \e[0m\n"
          record_failure "hosts file information collection failed"
      fi

      # Cron Job Information 
      cronk=`ls -athrl /etc/cron* 2>/dev/null`
      if [ "$cronk" ]; then
        log "[+] Collecting all cron job information" 
        log "ls -athrl /etc/cron* > $saveto/cronjobs.txt" 2>&1
        ls -athrl /etc/cron* > "$saveto/cronjobs.txt" 2>&1
        record_action "cron job information collected"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -athrl /etc/cron* \e[0m \e[00;33m ] \e[0m\n"
          record_failure "cron job information collection failed"
      fi

      crontabinfo=`cat /var/spool/cron/crontabs/* 2>/dev/null`
      if [ "$crontabinfo" ]; then
        log "[+] Collecting contabs information" 
        log "cat /var/spool/cron/crontabs/* > $saveto/crontabfile.txt" 2>&1
        cat /var/spool/cron/crontabs/* > "$saveto/crontabfile.txt" 2>&1
        record_action "crontab information collected"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: cat /var/spool/cron/crontabs/* \e[0m \e[00;33m ] \e[0m\n" 
          record_failure "crontab information collection failed"
      fi

      cronfileinfo=`cat /var/spool/cron/crontabs/* 2>/dev/null`
      if [ "$cronfileinfo" ]; then
        log "[+] Collecting cron files information" 
        log "ls -ailtrh /var/spool/cron > $saveto/cronfile.txt" 2>&1
        ls -ailtrh /var/spool/cron > "$saveto/cronfile.txt" 2>&1
        record_action "cron files information collected"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ls -ailtrh /var/spool/cron \e[0m \e[00;33m ] \e[0m\n"  
          record_failure "cron files information collection failed"
      fi

      printf '\033[0;92m --------------------------- [ Additional Process Information ]---------------------------\e[0m\n'

      # Information on processes 
      processinfo=`ps -auxxwf 2>/dev/null`
      if [ "$processinfo" ]; then
        log "[+] Collecting running processes on the host" 
        log "ps -auxx > $saveto/processes.txt" 2>&1
        ps -auxx > "$saveto/processes.txt" 2>&1
        record_action "process information collected"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: ps -auxx \e[0m \e[00;33m ] \e[0m\n"
          record_failure "process information collection failed"
      fi

        if command -v pstree &>/dev/null; then
          proctree=`pstree 2>/dev/null`
          if [ "$proctree" ]; then
            log "[+] Collecting processes on the host in a tree format" 
            log "pstree > $saveto/process-tree.txt" 2>&1
            pstree > "$saveto/process-tree.txt" 2>&1
            record_action "process tree information collected"
          else
            printf "\e[00;33m └─[ \e[0m \033[0;91 No information available for Command: pstree \e[0m \e[00;33m ] \e[0m\n"
            record_failure "process tree information collection failed"
          fi
        fi

      eatingdisk=`du -ah /etc/ | sort -n -r 2>/dev/null`
      if [ "$eatingdisk" ]; then
        log "[+] Collecting information on the top 50 directories eating up disk space" 
        log "du -ah /etc/ | sort -n -r > $saveto/diskusage.txt" 2>&1
        du -ah /etc/ | sort -n -r | head -n 50 > "$saveto/diskusage.txt" 2>&1
        record_action "disk usage information collected"
      else
          printf "\e[00;33m └─[ \e[0m \033[0;91m No information available for Command: du -ah /etc/ | sort -n -r \e[0m \e[00;33m ] \e[0m\n"
          record_failure "disk usage information collection failed"
      fi

      ##  Security Audit checks that could point to problems 
      ##  Sourced from @rebootuser's Red Team LinEnum script 

      printf '\033[0;92m --------------------------- [ Audit checks for poor security practices ]---------------------------\e[0m\n'
      bar

      privatekeyfiles=`for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rl "PRIVATE KEY-----"); done 2>/dev/null`
      if [ "$privatekeyfiles" ]; then
        log "[+] Collecting information on any stored private ssh keys --------- AWARENESS: This does take some time ---------" 
        log 'for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rl "PRIVATE KEY-----"); done > $saveto/private_ssh_keyfiles.txt' 2>&1
        for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rl "PRIVATE KEY-----"); done > "$saveto/private_ssh_keyfiles.txt" 2>&1
        record_action "private ssh key information collected"
      else
          printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for Private SSH keys \e[0m \e[00;33m ] \e[0m\n'
          record_failure "private ssh key information collection failed"
      fi

      awskeyfiles=`for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rli "aws_secret_access_key"); done 2>/dev/null`
      if [ "$awskeyfiles" ]; then
        log "[+] Collecting information on any stored AWS keys --------- AWARENESS: This does take some time ---------" 
        log 'for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rli "aws_secret_access_key"); done > $saveto/awskeyfiles.txt' 2>&1
        for d in /home/*/ ; do (cd "$d" && echo "$d" && grep -rli "aws_secret_access_key"); done > "$saveto/awskeyfiles.txt" 2>&1
        record_action "aws key information collected"
      else
          printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for AWS keys \e[0m \e[00;33m ] \e[0m\n'
          record_failure "aws key information collection failed"
      fi

      gitcredfiles=`find / -name ".git-credentials" 2>/dev/null`
      if [ "$gitcredfiles" ]; then
        log "[+] Collecting information on any stored Git Credentials" 
        log 'find / -name ".git-credentials" > $saveto/gitcredfiles.txt' 2>&1
        find / -name ".git-credentials" > "$saveto/gitcredfiles.txt" 2>&1
        record_action "git credentials information collected"
      else
          printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for git-credentials \e[0m \e[00;33m ] \e[0m\n'
          record_failure "git credentials information collection failed"
      fi

      printf '\033[0;92m --------------------------- [ Mail Information ]---------------------------\e[0m\n'

      readmail=`ls -la /var/mail 2>/dev/null`
      if [ "$readmail" ]; then
        log "[+] Collecting information on any mail files" 
        log 'ls -la /var/mail > $saveto/mail.txt' 2>&1
        ls -la /var/mail > "$saveto/mail.txt" 2>&1
        record_action "mail information collected"
      else
          printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for mail files \e[0m \e[00;33m ] \e[0m\n'
          record_failure "mail information collection failed"
      fi

      readmailroot=`ls -la /var/mail/root 2>/dev/null`
      if [ "$readmailroot" ]; then
        log "[+] Collecting information on any root mail files" 
        log 'ls -la /var/mail > $saveto/rootmail.txt' 2>&1
        ls -la /var/mail > "$saveto/rootmail.txt" 2>&1
        record_action "root mail information collected"
      else
          printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for root mail files \e[0m \e[00;33m ] \e[0m\n'
          record_failure "root mail information collection failed"
      fi

      printf '\033[0;92m --------------------------- [ Discovering System Attributes ]---------------------------\e[0m\n'
      ## Docker checks for incident awareness 
      ## Idea sourced by @rebootuser's Red Team LinEnum script 
      docker_checks()
      {
          additional_docker_checks() {

              # specific checks - are there any docker files present
              dockerfiles=$(find / -name Dockerfile -exec ls -l {} \; 2>/dev/null)
              if [ "$dockerfiles" ]; then
                  log "[+] Collecting information on any Docker files"
                  log 'find / -name Dockerfile -exec ls -l {} \; > $saveto/docker-files.txt' 2>&1
                  find / -name Dockerfile -exec ls -l {} \; > "$saveto/docker-files.txt" 2>&1
                  record_action "docker files information collected"
              else
                  printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for Docker files \e[0m \e[00;33m ] \e[0m\n'
                  record_failure "docker files information collection failed"
              fi

              # specific checks - check for docker compose files
              dockeryml=$(find / -name docker-compose.yml -exec ls -l {} \; 2>/dev/null)
              if [ "$dockeryml" ]; then
                  log "[+] Collecting information on any YML Docker files"
                  log 'find / -name docker-compose.yml -exec ls -l {} \; > $saveto/docker-files.txt' 2>&1
                  find / -name docker-compose.yml -exec ls -l {} \; > "$saveto/docker-files.txt" 2>&1
                  record_action "docker yml files information collected"
              else
                  printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for Docker yml files \e[0m \e[00;33m ] \e[0m\n'
                  record_failure "docker yml files information collection failed"
              fi

          }

          # specific checks - check to see if we're in a docker container / host
          if command -v docker &>/dev/null; then
              dockerversiont=$(docker --version && docker ps -a 2>/dev/null)

              if [ "$dockerversiont" ]; then
                  log "[+] Collecting information if Docker is installed"
                  log 'docker --version && docker ps -a > $saveto/docker-version.txt' 2>&1
                  docker --version && docker ps -a > "$saveto/docker-version.txt" 2>&1
                  record_action "docker information collected"

                  additional_docker_checks
              else
                  printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for Dockers \e[0m \e[00;33m ] \e[0m\n'
                  record_failure "docker information collection failed"
              fi
          fi
      }

      # Run Docker checks
      docker_checks

      printf '\033[0;92m --------------------------- [ Extra Checks on Crypto Miners ]---------------------------\e[0m\n'
      bar

      # Known Cryptominer Checks gathered from analysis and Linux.Ekcorminer - Symantec 
      Crypto() {

          # Known Cryptominer Checks gathered from analysis and Linux.Ekcorminer - Symantec
          cd /tmp/Forensics && touch potential-Cryptominers.txt

          log "# Analyzing low hanging fruit, for potential cryptominer IOCs in processes"
          log "[+] Creating directory to store findings --> touch potential-Cryptominers.txt"

          sleep 2

          array=(
              xmrig xmrigDaemon xmrigMiner xmrig-cpu xmrig-nvidia xmrig-amd
              minerd minergate minerGate minexmr cryptonight
              kworkerds kworker34 kworkerds32 kworkerds64 kworkerds_cpu
              sustes sustse systemctI systemd-cpu systemd-miner
              biosetjenkins biosetjenkinsd biosetjenkins64
              hashvault.pro nanopool.org monerohash.com pool.t00ls.ru stratum.f2pool.com
              xmrpool.eu mine.moneropool.com xmr.crypto-pool xmro.pooltoig monero.crypto-pool
              transfer.sh zer0day.ru disk_genius sourplum polkitd nanoWatch
              duckdns.org duck.sh vbonn.sh conn.sh pro.sh Guard.sh Duck.sh
              XbashY bashf bashg bashh bashx libapache
              de.gsearch.com get.bi-chi
              # Common process names and binaries
              XJnRj mgwsl pythno jweri lx26 NXLAi BI5zj askdljlqw
              # Suspicious temp file paths
              /tmp/devtool /tmp/a7b104c270
              # Suspicious email addresses
              zhuabcn@yahoo.com
          )

          echo "Checking against ${#array[*]} Cyptominer process strings"

          for miner in ${array[*]}; do
              ps -auxf | grep -v grep | grep "$miner" >> potential-Cryptominers.txt 2>&1
              printf "[+]Checking cryptominer string: \033[0;91m%s\e[0m\n" "$miner"
              record_action "Checked for cryptominer strings"
          done

          bar
          log "################## Crypto Scan Complete ##############################"

      }

      # Run Crypto Scan
      Crypto

    }
# ------------------------------------------------------ FULL SCAN COLLECTION END ----------------------------------------------------------

# Main logic
if [ "$SCAN_TYPE" = "light" ]; then
    light_scan
  else
    full_scan
fi

printf '\033[0;92m --------------------------- [ Backup All logs ]---------------------------\e[0m\n'
bar

# Log Collections
findlogs=$(cd /var/log && find . -name '*' | grep 'log' | sort -n 2>/dev/null)

if [ "$findlogs" ]; then
    log "[+] Collecting information on what logs we have available in /var/log"
    log "cd /var/log && find . -name '*' | grep 'log' | sort -n > \$saveto/available_logs.txt" 2>&1

    cd /var/log && \
    find . -name '*' | grep 'log' | sort -n > "$saveto/available_logs.txt" 2>&1

    record_action "log information collected"
else
    printf '\e[00;33m └─[ \e[0m \033[0;91m No information found for Command: cd /var/log \e[0m \e[00;33m ] \e[0m\n'
    record_failure "log information collection failed"
fi

# Log Backup Collections
collectlogs=$(cd /tmp/Forensics/ && mkdir -p Backuplogs && cd /var/log && cp -R -v * /tmp/Forensics/Backuplogs 2>/dev/null)

if [ "$collectlogs" ]; then
    log "[+] Collecting all logs as a backup for any further manual investigation - Stored in new directory location: /tmp/Forensics/Backuplogs"
    log "cd /tmp/Forensics/ && mkdir -p Backuplogs && cd /var/log && cp -R -v * /tmp/Forensics/Backuplogs"

    printf "Initiating large log collection\n"

    cd /tmp/Forensics/ && \
    mkdir -p Backuplogs && \
    cd /var/log && \
    cp -R -v * /tmp/Forensics/Backuplogs && \
    cd /tmp/Forensics/ 2>&1

    printf "Log Collection complete\n"
else
    printf "\e[0m \e[00;33m ] \e[0m Problem in log collection for Command: cd /tmp/Forensics/ && mkdir -p Backuplogs && cd /var/log && cp -R -v * /tmp/Forensics/Backuplogs \e[0m \e[00;33m ] \e[0m\n"
fi


# Collection Summary
SCRIPT_END_TIME=$(date +%s)
SCRIPT_END_HUMAN=$(date)
SCRIPT_DURATION=$((SCRIPT_END_TIME - SCRIPT_START_TIME))


printf "\n==================== Forensic Collection Summary ====================\n" | tee -a "$SUMMARY_FILE"
bar
touch 
printf "Start time: %s\nEnd time: %s\nDuration: %d seconds\n" "$SCRIPT_START_HUMAN" "$SCRIPT_END_HUMAN" "$SCRIPT_DURATION" | tee -a "$SUMMARY_FILE"
printf "\nActions performed:\n" | tee -a "$SUMMARY_FILE"
for action in "${SUMMARY_ACTIONS[@]}"; do
  printf "  - %s\n" "$action" | tee -a "$SUMMARY_FILE"
done
if [ ${#SUMMARY_FAILURES[@]} -gt 0 ]; then
  printf "\nFailures or commands that did not run successfully:\n" | tee -a "$SUMMARY_FILE"
  for fail in "${SUMMARY_FAILURES[@]}"; do
    printf "  - %s\n" "$fail" | tee -a "$SUMMARY_FILE"
  done
else
  printf "\nAll major actions completed successfully.\n" | tee -a "$SUMMARY_FILE"
fi
printf "====================================================================\n\n" | tee -a "$SUMMARY_FILE"
