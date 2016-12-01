#!/bin/bash

# forked from: BrainFcuksec
# Program: gh0st.sh
# Version: 5.0.1
# Operating System: debian bsed(any)
# Description: anonymization through tor
# Author: mr. ey3
# Dependencies: tor, wget, figlet, bleachbit, macchanger

# GNU GENERAL PUBLIC LICENSE
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


# program / version
program="gh0st"
version=" 5.0.1"

# define colors
export red=$'\e[0;91m'
export green=$'\e[0;92m'
export blue=$'\e[0;94m'
export white=$'\e[0;97m'
export endc=$'\e[0m'
export cyan=$'\e[0;36m'
export notify

# destinations you don't want routed through Tor
non_tor="192.168.1.0/24 192.168.0.0/24"

# UID --> 'ps -e | grep tor'
tor_uid="debian-tor"

# Tor TransPort
trans_port="9040"

#kill dangerous applications
to_kill="chrome dropbox iceweasel skype icedove thunderbird firefox firefox-esr chromium xchat hexchat transmission steam xchat pidgin"

# List, separated by spaces, of BleachBit cleaners
bleach_clean="bash.history system.cache system.clipboard system.custom system.recent_documents system.rotated_logs system.tmp system.trash"

# Overwrite
overwrite="true"

#net_int
net_int="eth0"

# print banner
function banner {
	figlet gh0st
    printf "${white}
enjoy the frEEdom .!..

Version: $version
Author: mr. ey3\n"
}


# check if the program run as a root
function check_root {
    if [ "$(id -u)" -ne 0 ]; then
        printf "${red}%s${endc}\n"  "[ failed ] bitch Please! rUn this program as a root!" >&2
        exit 1
    fi
}


# Kill processes at startup
function kill_process {
	if [ "$to_kill" != "" ]; then
		killall -q $to_kill
		echo " * Killed processes to prevent leaks"
	fi
}


# Release DHCP address
function clean_dhcp {
	dhclient -r
	rm -f /var/lib/dhcp/dhclient*
	echo " * DHCP address released"
}


# start macchanger
function active_macchanger {
	echo -e "\n$GREEN*$BLUE Spoofing Mac Address...\n"
	sudo service network-manager stop
	sleep 1
	sudo ifconfig $net_int down
	sleep 1
	printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "spoofing mac address"
	sudo macchanger -a $net_int
	sleep 1
	sudo ifconfig $net_int up
	sleep 1
	sudo service network-manager start
	printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "mac address spoofed"
	sleep 1
	notify "Mac Address Spoofed" 
}


# macchanger status
function status_macchanger {
	printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "here is your current mac address"
	sleep 1
	macchanger $net_int
	sleep 1
}	


# stop mac changer
function deactivate_macchanger {
	echo -e "\n$GREEN*$BLUE Restoring Mac Address...\n"
	sudo service network-manager stop
	sleep 1
	echo -e "$GREEN*$BLUE wlan0 MAC address:\n"$GREEN	
	sleep 1
	sudo ifconfig $net_int down
	sleep 1
	printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "restoring permanent mac address"
	sudo macchanger -p $net_int
	sleep 1
	sudo ifconfig $net_int up
	sleep 1
	sudo service network-manager start
	sleep 1
	printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "permanent mac address restored"
	sleep 1
	notify "orginal mac restored" 
}


function notify {
	if [ -e /usr/bin/notify-send ]; then
		/usr/bin/notify-send "gh0st" "$1"
	fi
}

# functions for firewall ufw
# check if ufw is installed and active, if not
# jump this function 
function disable_ufw {
	if hash ufw 2>/dev/null; then
    	if ufw status | grep -q active$; then
        	ufw disable > /dev/null 2>&1
        	sleep 3
    	else 
    		ufw status | grep -q inactive$;  
    	fi
    fi
}


# enable ufw 
# if ufw isn't installed, jump this function
function enable_ufw {
	if hash ufw 2>/dev/null; then
    	if ufw status | grep -q inactive$; then
        	ufw enable > /dev/null 2>&1
        	sleep 3
        fi
    fi
}

# BleachBit cleaners deletes unnecessary files to preserve privacy
function do_bleachbit {
	if [ "$overwrite" = "true" ] ; then
		echo -n " * Deleting and overwriting unnecessary files... "
		bleachbit -o -c $bleach_clean >/dev/null
	else
		echo -n " * Deleting unnecessary files... "
		bleachbit -c $bleach_clean >/dev/null
	fi

	echo "Done!"
}

# install dependencies
function install {
	sudo echo "deb http://deb.torproject.org/torproject.org jessie main" >>/etc/apt/sources.list.d/tor.list
    sudo echo "deb-src http://deb.torproject.org/torproject.org jessie main" >>/etc/apt/sources.list.d/tor.list
    sudo gpg --keyserver keys.gnupg.net --recv A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89
    sudo gpg --export A3C4F0F979CAA22CDBA8F512EE8CBC9E886DDD89 | sudo apt-key add -
	sudo apt-get update
	sudo apt-get install tor -y
	sudo apt-get install wget -y
	sudo apt-get install bleachbit -y
	sudo apt-get install figlet -y
	sudo apt-get install macchanger -y
}
	
# Change the local hostname
function change_hostname {    
    #backing up previous hostname
    cp /etc/hostname /etc/hostname.bak
	cp /etc/hosts /etc/hosts.bak
	CURRENT_HOSTNAME=$(hostname)
	clean_dhcp
	#set random hostname
	RANDOM_HOSTNAME=$(shuf -n 1 /etc/dictionaries-common/words | sed -r 's/[^a-zA-Z]//g' | awk '{print tolower($0)}')
	NEW_HOSTNAME=${1:-$RANDOM_HOSTNAME}
	echo "$NEW_HOSTNAME" > /etc/hostname
	sed -i 's/127.0.1.1.*/127.0.1.1\t'"$NEW_HOSTNAME"'/g' /etc/hosts
	echo -n " * Service "
	service hostname start 2>/dev/null || echo "hostname already started"

	if [ -f "$HOME/.Xauthority" ] ; then
		su "$SUDO_USER" -c "xauth -n list | grep -v $CURRENT_HOSTNAME | cut -f1 -d\ | xargs -i xauth remove {}"
		su "$SUDO_USER" -c "xauth add $(xauth -n list | tail -1 | sed 's/^.*\//'$NEW_HOSTNAME'\//g')"
		echo " * X authority file updated"
	fi
	avahi-daemon --kill
	echo " * Hostname changed to $NEW_HOSTNAME"
}


#restore the original hostname
function restore_hostname {
    clean_dhcp
    if [ -e /etc/hostname.bak ]; then
		rm /etc/hostname
		cp /etc/hostname.bak /etc/hostname
	fi
	if [ -e /etc/hosts.bak ]; then
		rm /etc/hosts
		cp /etc/hosts.bak /etc/hosts
	fi
	sleep 3
	echo -e -n "\n $GREEN*$BLUE Restored Hostname: $GREEN"
	notify "hostname restored"
}


# change ip every ___ second
function bounce_ip {
	while true; do
    sudo service tor reload
	sleep 180
	done
	check_ip
}
	


# check default configurations
# check if kalitorify is properly configured
function check_default {
    # check dependencies (tor, wget, figlet, bleachbit, macchanger)
    if hash tor 2>/dev/null; then
        printf ""
        else
        sudo apt-get install tor -y
fi
    if hash macchanger 2>/dev/null; then
        printf ""
        else
        sudo apt-get install macchanger -y
fi
   if hash wget 2>/dev/null; then
        printf ""
        else
        sudo apt-get install wget -y
fi
    
    if hash bleachbit 2>/dev/null; then
        printf ""
        else
        sudo apt-get install bleachbit -y
fi
    
    if hash figlet 2>/dev/null; then
        printf ""
        else
        sudo apt-get install figlet -y
fi

    # check file '/etc/tor/torrc'
    #
    # VirtualAddrNetworkIPv4 10.192.0.0/10
    # AutomapHostsOnResolve 1
    # TransPort 9040
    # SocksPort 9050
    # DNSPort 53
    # RunAsDaemon 1
    grep -q -x 'VirtualAddrNetworkIPv4 10.192.0.0/10' /etc/tor/torrc
    VAR1=$?

    grep -q -x 'AutomapHostsOnResolve 1' /etc/tor/torrc
    VAR2=$?

    grep -q -x 'TransPort 9040' /etc/tor/torrc
    VAR3=$?

    grep -q -x 'SocksPort 9050' /etc/tor/torrc
    VAR4=$?

    grep -q -x 'DNSPort 53' /etc/tor/torrc
    VAR5=$?

    grep -q -x 'RunAsDaemon 1' /etc/tor/torrc
    VAR6=$?

    if [ $VAR1 -ne 0 ] ||
        [ $VAR2 -ne 0 ] ||
        [ $VAR3 -ne 0 ] ||
        [ $VAR4 -ne 0 ] ||
        [ $VAR5 -ne 0 ] ||
        [ $VAR6 -ne 0 ]; then
        echo "#gh0st" >> /etc/tor/torrc
        echo "VirtualAddrNetworkIPv4 10.192.0.0/10" >> /etc/tor/torrc
        echo "AutomapHostsOnResolve 1" >> /etc/tor/torrc
        echo "TransPort 9040" >> /etc/tor/torrc
        echo "SocksPort 9050" >> /etc/tor/torrc
        echo "DNSPort 53" >> /etc/tor/torrc
        echo "RunAsDaemon 1" >> /etc/tor/torrc
       
    fi
}


# start transparent proxy
# start program
function start {
    check_root
    banner
    kill_process
    change_hostname
    check_default
    
#    by default macchnager is deactivated activate it if you know what yhou are doing
#    if you want to activate it please uncomment below lines
#    and uncoment deactivate_machanger and status_macchnager option in stop functions
#    active_macchanger
#    status_macchanger
    



    # check status of tor.service and stop it if is active
    if systemctl is-active tor.service > /dev/null 2>&1; then
        systemctl stop tor.service
    fi

    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Starting gh0st protocol"
    disable_ufw
    sleep 2

    
    # start tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Start anoNymizing service"
    service tor start
    sleep 6
   	printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "protocol activated"

   	# iptables settings
   	###################	

    # save iptables
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "taking backups..."
    iptables-save > /opt/iptables.backup
    sleep 2

    # flush iptables
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "intializig services..."
    iptables -F
    iptables -t nat -F

    # configure system's DNS resolver to use Tor's DNSPort on the loopback interface
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "configuring..."
    cp -vf /etc/resolv.conf /opt/resolv.conf.backup
    echo -e 'nameserver 127.0.0.1' > /etc/resolv.conf
    sleep 2

    # new iptables rules
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "begin the HUNT..."

    # set iptables *nat
    iptables -t nat -A OUTPUT -m owner --uid-owner $tor_uid -j RETURN
    iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A OUTPUT -p tcp --dport 53 -j REDIRECT --to-ports 53
    iptables -t nat -A OUTPUT -p udp -m owner --uid-owner $tor_uid -m udp --dport 53 -j REDIRECT --to-ports 53

    iptables -t nat -A OUTPUT -p tcp -d 10.192.0.0/10 -j REDIRECT --to-ports $trans_port
    iptables -t nat -A OUTPUT -p udp -d 10.192.0.0/10 -j REDIRECT --to-ports $trans_port

    # allow clearnet access for hosts in $non_tor
    for clearnet in $non_tor 127.0.0.0/9 127.128.0.0/10; do
        iptables -t nat -A OUTPUT -d $clearnet -j RETURN
    done

    # redirect all other output to Tor TransPort
    iptables -t nat -A OUTPUT -p tcp --syn -j REDIRECT --to-ports $trans_port
    iptables -t nat -A OUTPUT -p udp -j REDIRECT --to-ports $trans_port
    iptables -t nat -A OUTPUT -p icmp -j REDIRECT --to-ports $trans_port

    # set iptables *filter
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # allow clearnet access for hosts in $non_tor
    for clearnet in $non_tor 127.0.0.0/8; do
        iptables -A OUTPUT -d $clearnet -j ACCEPT
    done

    # allow only Tor output
    iptables -A OUTPUT -m owner --uid-owner $tor_uid -j ACCEPT
    iptables -A OUTPUT -j REJECT
    sleep 4

    printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "gh0st is protecting you"
    notify "gh0st pr0t0c0l activated"
    
    # check public ip
    check_ip
    # options for advanced user
    # afetr activation of this option when you want to de activate the script please first press ctrl+c
    # then gh0st-5.0.1.sh
    # change ip in every 3 minutes
    # bounce_ip
}


# stop function
# stop transparent proxy and return to clearnet
function stop {
    check_root

    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "deactivating gh0st"
    sleep 2

    # flush iptables
    iptables -F
    iptables -t nat -F

    # restore iptables
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restoring backups..."
    iptables-restore < /opt/iptables.backup
    sleep 2

    # stop tor.service
    service tor stop
    sleep 4
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "making your pc normal..."
    # restore /etc/resolv.conf --> default nameserver
    rm -v /etc/resolv.conf
    cp -vf /opt/resolv.conf.backup /etc/resolv.conf
    sleep 2
    restore_hostname
    enable_ufw
#    deactivate_macchanger
#    status_macchanger
    do_bleachbit
    check_ip
    printf "${blue}%s${endc} ${white}%s${endc}\n" "[-]" "gh0st prOtOcOl deactivated"
    notify "gh0st pr0t0c0l stopped"
}


# check_status function
# function for check status of program and services:
# tor.service, check public IP, netstat for open door
function check_status {
    check_root

    # check status of tor.service
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check current status of Tor service"
    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${blue}%s${endc} ${white}%s${endc}\n" "[ ok ]" "Tor service is active"
    else
        printf "${red}%s${endc}\n" "[-] Tor service is not running!"
        exit 1
    fi


    # check current public IP
    check_ip

    # exec command "netstat -tulpn", check if there are open doors
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Check if there are open doors"
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "run command 'netstat -tulpn'"
    sleep 5 &
    netstat -tulpn
    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "[ info ]" "If your network security is ok, you have only 'tor' in listen"
    exit 0
}

# check current public IP
function check_ip {
    printf "\n${blue}%s${endc} ${green}%s${endc}\n" "::" "Checking your public IP, please wait..."
    local ext_ip
    ext_ip=$(wget -qO- -t 1 --timeout=15 ipinfo.io/ip)
    local city
    city=$(wget -qO- -t 1 --timeout=15 ipinfo.io/city)
    
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Current public IP:"
    printf "${white}%s%s${endc}\n\n" "$ext_ip - $city"
    sleep 1
}
    
# restart tor.service and change IP
function restart {
    check_root
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restart Tor service and change IP"

    # systemctl restart or stop/start is the same?
    sudo service tor stop
    sleep 3
    printf "${blue}%s${endc} ${green}%s${endc}\n" "::" "Restarting gh0st pr0t0c0l"
    sudo service tor start
    sleep 2
    # check tor.service after restart
    if systemctl is-active tor.service > /dev/null 2>&1; then
        printf "${red}%s${endc}\n" "[-] gh0st protocol is not running!"
    else
        printf "${blue}%s${endc} ${white}%s${endc}\n\n" "[ ok ]" "gh0st protocol is active and your IP is changed"
        check_ip
        
    fi
    sleep 4
}


# display program and tor version then exit
function print_version {
    printf "${white}%s${endc}\n" "$program version $version"
    printf "${white}%s${endc}\n" "$(tor --version)"
    exit 0
}


# print nice help message and exit
function help_menu {
	banner

    printf "\n${white}%s${endc}\n" "Usage:"
    printf "${white}%s${endc}\n\n"   "******"
    printf "${white}%s${endc} ${red}%s${endc} ${white}%s${endc} ${red}%s${endc}\n" "┌─╼" "$USER" "╺─╸" "$(hostname)"
    printf "${white}%s${endc} ${green}%s${endc}\n" "└───╼" "./$program --argument"

    printf "\n${white}%s${endc}\n\n" "Arguments:"
    printf "${green}%s${endc}\n" "-h    show this help message and exit"
    printf "${green}%s${endc}\n" "-i    install gh0st prOtOcOl"
    printf "${green}%s${endc}\n" "-a    activate ghost prOtOcOl"
    printf "${green}%s${endc}\n" "-d    deactivate ghost prOtOcOl"
    printf "${green}%s${endc}\n" "-m    check your public ip"
    printf "${green}%s${endc}\n" "-s    check status of ghost prOtOcOl"
    printf "${green}%s${endc}\n" "-r    restart gh0st prOtOcOl and change IP"
    printf "${green}%s${endc}\n" "-v    display program and tor version then exit"
    exit 0
}


# cases user input
case "$1" in
       -i)
        install
        ;;
       -a)
        start
        ;;
       -d)
        stop
        ;;
       -m)
        check_ip
        ;;
       -r)
        restart
        ;;
       -s)
        check_status
        ;;
       -v)
        print_version
        ;;
       -h)
        help_menu
        ;;
    *)
help_menu
exit 1

esac
