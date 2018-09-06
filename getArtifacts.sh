#!/bin/bash

# Author: Michael Rhodes
#
# Description:	gathers artifacts from linux operating systems and outputs them
# 		in a table or to a file in csv format. It also allows the option
#		to send the csv file to an email address.
# 	Artifacts include:
#		Time, OS version, hw specs, hostname, domain, users, startup,
#		sched tasks, network, software, processes, drivers, files,
#		aliases, setUID binaries, and tmp files.
#
# Table format:
#		---------------------------------------
#		| Artifact type | subtype | result(s) |
#		---------------------------------------

# USAGE STATEMENT
usage() {
echo """
USAGE: getArtifacts.sh [-csv [filename]] [-r | -remoteHost [user@ip-address]] [-m | -mail [email]]
  Example: gatherArtifacts.sh -csv out.csv -m foo@foo.org
"""
}

#check if root
if [[ $EUID -ne 0 ]]; then
   sudo su
fi

# get arguments
while [ "$1" != "" ]; do
    case $1 in
        -csv )                  shift
                                csv=$1
                                echo "Saving artifacts to" $csv
                                ;;
        -r | -remoteHost )      shift
                                remoteHost=$1
                                echo "Connecting to " $remoteHost
                                ;;
        -m | -mail )            shift
                                mail=$1
                                echo "Sending file to " $mail
                                ;;
        * )                     usage
                                exit 1
    esac
    shift
done


add_to_table() {
	if [[ ! -z $csv ]]; then
		echo "$1,$2,$3" >> $csv
	else
		echo "$1 | $2 | $3"
	fi
}

# time: current time, time zone of PC, PC uptime
add_to_table "time" "current" "`uptime | cut -d' ' -f2`"
add_to_table "time" "time zone" "`date +”%Z”`"
add_to_table "time" "uptime" "`uptime | cut -d ' ' -f 5 | tr -d ','`"

# OS version: numerical, typical name, kernel version
add_to_table "OS version" "numerical" "`uname -r`"
add_to_table "OS version" "typical name" "`cat /etc/*-release | grep -E "^ID="`"
add_to_table "OS version" "kernel vers." "`uname -v`"

# hardware: CPU brand and type, RAM, HDD (list HDDs, list mounted file systems)
add_to_table "hardware" "CPU" "`cat /proc/cpuinfo | grep "model name" | cut -d':' -f1 --complement`"
add_to_table "hardware" "RAM" "`cat /proc/meminfo | grep MemTotal | cut -d: -f2 | tr -d ' '`"
(lsblk -al | grep disk) | while read -r disk; do
	add_to_table "hardware" "HDD" "$disk";
done 
(df -h | tail -n +2) | while read -r fs; do
	add_to_table "hardware" "filesystem" "$fs";
done

# hostname and domain
add_to_table "hostname" "N/A" "`hostname`"
add_to_table "domain" "N/A" "`domainname`"

# list of users: user/group id, include user login history
for line in $(cut -f-1,3,4,6,7 -d: /etc/passwd);do 
	user=$(echo $line | cut -f1 -d:)
	add_to_table "Users" "$user" "$line"
	lastlogin=$(last $user | grep $user)
	if [[ ! -z $lastlogin ]]; then
		while read -r log; do
			add_to_table "Users" "$user-login" "$log"
		done <<< "$lastlogin"
	fi
done

# start at boot
while read -r file; do
	add_to_table "StartAtBoot" "init.d" "$file"
done <<< "$(find '/etc/init.d/' -type f)"
while read -r file; do
	add_to_table "StartAtBoot" "xdg" "$file"
done <<< "$(find '/etc/xdg/autostart/' -type f)"

# scheduled tasks
for user in $(cut -f1 -d: /etc/passwd);do
	if [[ ! -z $user ]]; then 
		add_to_table "Scheduled tasks" "$user" "$(crontab -u $user -l 2>/dev/null)"; 
	fi
done

# network: arp table, MAC addresses for interface(s), routing table, IP addresses
#	DHCP server, DNS server, gateway(s), listening services (ipaddr,port,proto,service)
#	established connections (remote IP,local/remote port,proto,timestamp,service),
#	DNS cache
interfaces=$(ip a | grep -E '^[1-9][0-9]?:' | cut -d: -f2 | tr -d ' ')
while read -r intf; do
	mac=$(cat /sys/class/net/$intf/address)
	inet=$(ip a s $intf | grep -E '^\W*inet ' | cut -d' ' -f6 | tr '\n' '   ')
	add_to_table "network" "intf: $intf" "MAC = $mac"
	add_to_table "network" "intf: $intf" "IP = $inet"
done <<< "$interfaces"
add_to_table "network" "arp table" "`arp`"
while read -r a; do
	add_to_table "network" "arp table entry" "$a"
done <<< "$(arp -n | tail -n+2)"
while read -r a; do
	add_to_table "network" "routing table entry" "$a"
done <<< "$(ip r)"
servers=()
while read -r dhcp; do
	servers+=("$(echo $dhcp | cut -d: -f4)")
done <<< "$(grep -R 'DHCPOFFER' /var/log/messages)"
add_to_table "network" "DHCP servers" "$servers"
add_to_table "network" "DNS server" "`grep nameserver /etc/resolv.conf`"
##TODO add to table??
add_to_table "network" "listening services" "`netstat -ltunp`"
##TODO add to table??
add_to_table "network" "established connections" "`netstat -anp | grep ESTAB`"


# network shares, printers, wifi access profiles
#TODO

# all installed software
mgr=$(which dpkg 2>/dev/null)
if [[ ! -z $mgr ]]; then
	while read -r pkg; do
		add_to_table "InstalledSoftware" "dpkg" "$pkg"
	done <<< "$(dpkg --get-selections | grep -v deinstall | cut -d' ' -f1)"
fi
mgr=$(which rpm 2>/dev/null)
if [[ ! -z $mgr ]]; then
	while read -r pkg; do
		add_to_table "InstalledSoftware" "rpm" "$pkg"
	done <<< "$($mgr -qa)"
fi

# process list
##TODO add to table??
add_to_table "processes" "N/A" "`ps aux`"

# driver list
while read -r mod; do
	add_to_table "Kernel" "Module" "$mod"
done <<< "$(lsmod)"

# list of all files in Downloads and Documents for each user directory
documents="/Documents"
downloads="/Downloads"
while read line; do
	homedir=`echo $line | cut -d: -f6`;
	user=$(echo $line | cut -f1 -d:)
	if [ -d "$homedir$documents" ]; then
		while read -r file; do
			add_to_table "Documents" "$user" "$file"
		done <<< "$(find "$homedir$documents" -type f)"
	fi
	if [ -d "$homedir$downloads" ]; then
		while read -r file; do
			add_to_table "Downloads" "$user" "$file"
		done <<< "$(find "$homedir$downloads" -type f)"
	fi
done < /etc/passwd

#TODO won't loop over alias
#alias
while read -r line; do
	echo "$line"
	add_to_table "Aliases" "" "$(echo $line | cut -d' ' -f1 --complement)"
done <<< "$(alias)"

#setuid
while read -r file; do
	add_to_table "SetUID" "/usr/bin" "$file"
done <<< "$(find '/usr/bin' -perm -4000)"

#tmp
while read -r file; do
	add_to_table "tmp files" "tmp" "$file"
done <<< "$(ls -Al /tmp | tail -n+2)"


