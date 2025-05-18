#!/bin/sh

# Script to create a seperate guest wifi network with the option of adding a ethernet port to the network
# Inspired by the script YazFi by JackYaz (snbForums.com)
#
# Version 2.20.00bata	Dated May 4, 2025	- Cleanup and automate crude script I was using to add eth port to guest network
#
# The following scripts must be created or altered;
#
#		/jffs/configs/dnsmasq.conf.add			# Add DHCP server setup for the bridge that you used
#		/jffs/scripts/firewall-start			# Call this script with the option "firewall" as $1
#		/jffs/scripts/nat-start					# Call this script with the option "nat" as $1
#		/jffs/scripts/services-start			# Call this script with no option "start" to setup bridge
#		/jffs/scripts/services-event-end		# Trap event "wireless" or "net_and_phy" on "restart", then run this script with option "start"
#												# Trap event "firewall" on "start" or "restart" and run script with "firewall" option

# set -x	# uncomment this line to enable debugging

#------------------------------------------
readonly LAN_IP="$(nvram get lan_ipaddr)"
readonly LAN_NETMASK="$(nvram get lan_netmask)"
ENABLED_WINS="$(nvram get smbd_wins)"
ENABLED_SAMBA="$(nvram get enable_samba)"
INTNTPD="$(nvram get ntpd_enable)"
readonly SCRIPT_NAME="$(basename $0)"
readonly SCRIPT_DIR="$(dirname $(find /jffs -name ${SCRIPT_NAME}))"
readonly USER_SCRIPT_DIR="$SCRIPT_DIR/scripts"
readonly CONF_FILE="${SCRIPT_DIR}/${SCRIPT_NAME}.conf"

### Start of output format variables ###
readonly CRIT="\\e[41m"
readonly ERR="\\e[31m"
readonly WARN="\\e[33m"
readonly PASS="\\e[32m"
readonly BOLD="\\e[1m"
readonly SETTING="${BOLD}\\e[36m"
readonly CLEARFORMAT="\\e[0m"
### End of output format variables ###


readonly regex_ipaddr="(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"
readonly regex_local_ipaddr="(^10\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(^172\.(1[6-9]|2[0-9]|3[0-1])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))|(^192\.168\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))$"

if [ "$(nvram get wan0_proto)" = "pppoe" ] || [ "$(nvram get wan0_proto)" = "pptp" ] || [ "$(nvram get wan0_proto)" = "l2tp" ]; then
	IFACE_WAN="ppp0"
else
	IFACE_WAN="$(nvram get wan0_ifname)"
fi

ENABLED_NTPD=0
if [ -f /jffs/scripts/nat-start ]; then
	if [ "$(grep -c '# ntpMerlin' /jffs/scripts/nat-start)" -gt 0 ]; then ENABLED_NTPD=1; fi
fi
if [ "$INTNTPD" -ne 0 ]; then ENABLED_NTPD=1; fi

Check_Lock(){
	if [ -f "/tmp/$SCRIPT_NAME.lock" ]; then
		ageoflock=$(($(date +%s) - $(date +%s -r /tmp/$SCRIPT_NAME.lock)))
		if [ "$ageoflock" -gt 600 ]; then
			Print_Output true "Stale lock file found (>600 seconds old) - purging lock" "$WARN"
			kill "$(sed -n '1p' /tmp/$SCRIPT_NAME.lock)" >/dev/null 2>&1
			Clear_Lock
			echo "$$" > "/tmp/$SCRIPT_NAME.lock"
			return 0
		else
			t="0"
			while [ "$t" -le 60 ]
			do
				ageoflock=$(($(date +%s) - $(date +%s -r /tmp/$SCRIPT_NAME.lock)))
				Print_Output true "Lock file found (age: $ageoflock seconds) - waiting 10 seconds, then try to continue. (Max 60s)" "$WARN"
				sleep 10
				if ! [ -f "/tmp/$SCRIPT_NAME.lock" ]; then
					break
				else
					let "t=t+10"
				fi
			done
			Print_Output true "Sixty (60) seconds has passed, still locked.  Killing stuck process and continuing..." "$WARN"
			kill "$(sed -n '1p' /tmp/$SCRIPT_NAME.lock)" >/dev/null 2>&1
			Clear_Lock
			echo "$$" > "/tmp/$SCRIPT_NAME.lock"
			return 0
		fi
	else
		echo "$$" > "/tmp/$SCRIPT_NAME.lock"
		return 0
	fi
}

Clear_Lock(){
	Print_Output true "Clearing lock file" "$PASS"
	rm -f "/tmp/$SCRIPT_NAME.lock" 2>/dev/null
	return 0
}

# $1 = print to syslog, $2 = message to print, $3 = log level
Print_Output(){
	if [ "$1" = "true" ]; then
		logger -t "$SCRIPT_NAME" "$2"
	fi
	printf "${BOLD}${3}%s${CLEARFORMAT}\\n\\n" "$2"
}

validate_ipaddr() {
	# $1 = IP4 address to check if valid
	if [ $# -ne 1 ] || ! echo "$1" | grep -qE "^$regex_ipaddr$" ; then
		return 1
	else
		return 0
	fi
}

int_to_ip4() {
  echo "$(( ($1 >> 24) % 256 )).$(( ($1 >> 16) % 256 )).$(( ($1 >> 8) % 256 )).$(( $1 % 256 ))"
}

# returns the ip part of an CIDR
#
# cidr_ip "172.16.0.10/22"
# => 172.16.0.10
cidr_ip() {
	echo $1 | cut -f1 -d"/"
}

# returns the prefix part of an CIDR
#
# cidr_prefix "172.16.0.10/22"
# => 22
cidr_prefix() {
	echo $1 | cut -f2 -d"/"
}

Get_NetworkIP() {
	# $1 = IP Address/CIDR	
	# i.e $1=192.168.189.2/24, then return is 192.168.189.0

	local IP="$(cidr_ip "$GUESTNETWORK")"
	local PREFIX="$(cidr_prefix "$GUESTNETWORK")"

	i1=`echo $IP | cut -d . -f 1`
	i2=`echo $IP | cut -d . -f 2`
	i3=`echo $IP | cut -d . -f 3`
	i4=`echo $IP | cut -d . -f 4`
	
	mask=$(( ((1<<32)-1) & (((1<<32)-1) << (32 - $PREFIX)) ))
	echo $(( $i1 & ($mask>>24) )).$(( $i2 & ($mask>>16) )).$(( $i3 & ($mask>>8) )).$(( $i4 & $mask ))
}

# convert cidr to netmask
convert_netmask() { 
    value=$(( 0xffffffff ^ ((1 << (32 - $1)) - 1) ))
    echo "$(( (value >> 24) & 0xff )).$(( (value >> 16) & 0xff )).$(( (value >> 8) & 0xff )).$(( value & 0xff ))"
}

# Determine is IP address is a Class C, non routable address
IP_Local(){
	if echo "$1" | grep -qE '(^10\.)|(^172\.1[6-9]\.)|(^172\.2[0-9]\.)|(^172\.3[0-1]\.)|(^192\.168\.)'; then
		return 0
	elif [ "$1" = "127.0.0.1" ]; then
		return 0
	else
		return 1
	fi
}

IP_Router(){
	if [ "$1" = "$(nvram get lan_ipaddr)" ] || [ "$1" = "127.0.0.1" ]; then
		return 0
	elif [ "$1" = "$(eval echo "$1" | cut -f1-3 -d".").$(nvram get lan_ipaddr | cut -f4 -d".")" ]; then
		return 0
	else
		return 1
	fi
}

# Check to see if $1 is the same network as the Router main lan IP address
Router_Network(){
	if [ "$(eval echo "$GUESTLANIP" | cut -f1-3 -d".")" = "$(nvram get lan_ipaddr | cut -f1-3 -d".")" ]; then
		return 1
	else
		return 0
	fi
}

# Checked to see if guest wifi client isolation state has changed and apply if so
Client_Isolate() {

	ISOBEFORE="$(nvram get "${GUESTIF}_ap_isolate")"
	if [ "$CLIENTISOLATE" = "false" ] && [ $ISOBEFORE = "0" ];then
		return 0
	fi
	if [ "$CLIENTISOLATE" = "true" ] && [ $ISOBEFORE = "1" ];then
		return 0
	fi	

	Print_Output true "Client Isolation Setting has changed, setting NVRAM and restarting wireless interface" "$WARN"
	
	if [ "CLIENTISOLATE" = "true" ]; then
		nvram set "${GUESTIF}_ap_isolate"="1"
	else
		nvram set "${GUESTIF}_ap_isolate"="0"
	fi
	
	nvram commit
	WIRELESSRESTART="true"
	service restart_wireless
	
	return 1
}

Configure_NVRAM() {

	local BR0IFS="$(nvram get br0_ifnames)"
	local LANIFS="$(nvram get lan_ifnames)"

	Print_Output true "Setting NVRAM network variables......"

	if [ "$(nvram get lan1_ifnames)" = "$LANPORTS"" ""$GUESTIF" ] && [ "$(nvram get "${GUESTBR}"_ifnames)" = "$GUESTIF"" ""$LANPORTS" ]; then
		return
	else
	
		for IFN in "$LANPORTS"; do
			LANIFS="$(echo ${LANIFS} | sed s/"$IFN"//)"
		done
	
		LANIFS="$(echo ${LANIFS} | sed s/"$GUESTIF"//)"
	
		for IFN in "$LANPORTS"; do
			BR0IFS="$(echo ${BR0IFS} | sed s/"$IFN"//)"
		done

		BR0IFS="$(echo ${BR0IFS} | sed s/"$GUESTIF"//)"

		nvram set lan_ifnames="$LANIFS"
		nvram set br0_ifnames="$BR0IFS"
		nvram set "${GUESTBR}"_ifnames="$GUESTIF"" ""$LANPORTS"
		nvram set "${GUESTBR}"_ifname="$GUESTBR"
		
		nvram set lan1_ifnames="$LANPORTS"" ""$GUESTIF"
		nvram set lan1_ifname="$GUESTBR"
		nvram set lan1_ipaddr="$GUESTLANIP"
		nvram set lan1_netmask="$GUESTLANMASK"
	
		killall eapd
		eapd &
		sleep 5
	fi
}

Iface_BounceClients(){

	Print_Output true "Bouncing wireless clients from guest network interface"

	wl -i "$GUESTIF" radio off >/dev/null 2>&1
	sleep 10
	wl -i "$GUESTIF" radio on >/dev/null 2>&1

	ARPDUMP="$(arp -an)"
	IFACE_MACS="$(wl -i "${GUESTIF}" assoclist)"
	if [ "$IFACE_MACS" != "" ]; then
		IFS=$'\n'
		for GUEST_MAC in $IFACE_MACS; do
			GUEST_MACADDR="${GUEST_MAC#* }"
			GUEST_ARPINFO="$(arp -an | grep -i "$GUEST_MACADDR")"
			for ARP_ENTRY in $GUEST_ARPINFO; do
				GUEST_IPADDR="$(echo "$GUEST_ARPINFO" | awk '{print $2}' | sed -e 's/(//g;s/)//g')"
				arp -d "$GUEST_IPADDR"
			done
		done
		unset IFS
	fi
	ip -s -s neigh flush all >/dev/null 2>&1
	killall -q networkmap
	sleep 5
	if [ -z "$(pidof networkmap)" ]; then
		networkmap >/dev/null 2>&1 &
	fi
}

Execute_UserScripts(){
	FILES="$USER_SCRIPT_DIR/*.sh"
	for f in $FILES; do
		if [ -f "$f" ]; then
			Print_Output true "Executing user script: $f"
			sh "$f"
		fi
	done
}

Configure_bridge() {
	# if $1=force, then don't check, just do..... Errors be dammed!!
	
	Print_Output true "Function Configure_bridge called...."

	# Check to see if guest bridge is up and functional

	Set_Lan_Access
	Client_Isolate
	
	if ! [ "$1" = "force" ];then
		if [ -f /sys/class/net/${GUESTBR}/operstate ]; then
			Print_Output true "Bridge $GUESTBR appears to be already setup... returning" "$PASS"
			return 1
		fi
	else
	
		if [ "$1" = "force" ];then
			Print_Output true "Configure_bridge called with force option ..... forcing reconfiguration of bridge $GUESTBR" "$WARN"
		fi
	
		local mask="$(cidr_prefix $GUESTNETWORK)"
		
		Print_Output true "New bridge $GUESTBR does not appear to be active, setting up bridges...." "$WARN"
		
		brctl addbr "$GUESTBR"
		brctl setfd "$GUESTBR" 2
		brctl stp "$GUESTBR" on

		brctl delif br0 "$GUESTIF"
		brctl delif br0 "$LANPORTS"

		brctl addif "$GUESTBR" "$GUESTIF"
		brctl addif "$GUESTBR" "$LANPORTS"

		ifconfig "$GUESTBR" "$GUESTLANIP" netmask $(convert_netmask $mask)
		ifconfig "$GUESTBR" allmulti up

		Configure_NVRAM
		
		return 0
	fi

}

Firewall_Rules() {

	Print_Output true "Setting up firewall rules"

	# Setup Iptables - Delete things first

	iptables -t filter -D INPUT -j GuestInput > /dev/null 2>&1
	iptables -t filter -D FORWARD -j GuestForward > /dev/null 2>&1

	iptables -t filter -F GuestInput > /dev/null 2>&1
	iptables -t filter -F GuestForward > /dev/null 2>&1
	iptables -t filter -F GuestReject > /dev/null 2>&1
	iptables -t filter -X GuestInput > /dev/null 2>&1
	iptables -t filter -X GuestForward > /dev/null 2>&1
	iptables -t filter -X GuestReject > /dev/null 2>&1

	# Iptables - Add Guest Network Rules

	iptables -t filter -N GuestInput
	iptables -t filter -N GuestReject
	iptables -t filter -N GuestForward
	iptables -t filter -N DNSRules

	iptables -t filter -I INPUT -j GuestInput
	iptables -t filter -I GuestReject -j REJECT

	# Begin INPUT Rules

	iptables -t filter -I GuestInput -i "$GUESTBR" -j GuestReject
	iptables -t filter -I GuestInput -i "$GUESTBR" -p icmp -j ACCEPT
	iptables -t filter -I GuestInput -i "$GUESTBR" -p udp -m multiport --dports 67,68,123,853 -j ACCEPT
	iptables -t filter -I GuestInput -i "$GUESTBR" -p udp -m udp --dport 53 -j ACCEPT
	iptables -t filter -I GuestInput -i "$GUESTBR" -p tcp -m tcp --dport 53 -j ACCEPT
	
	if [ "$TWOWAY" = "true" ] || [ "$ONEWAY" = "true" ]; then
		iptables -t filter -I GuestInput -d 224.0.0.0/4 -i "$GUESTBR" -j ACCEPT
	fi
	
	if [ "$ENABLED_WINS" -eq 1 ] && [ "$ENABLED_SAMBA" -eq 1 ]; then
		iptables -t filter -I GuestInput -i "$GUESTBR" -p udp -m multiport --dports 137,138 -j ACCEPT
	fi

	# Begin forward Rules
	
	#iptables -t filter -I FORWARD ! -i "$GUESTBR" -o eth5 -j logdrop

	iptables -t filter -I GuestForward -i "$GUESTBR" -j ACCEPT

	if [ "$TWOWAY" = "false" ]; then
		iptables -t filter -I GuestForward ! -i "$IFACE_WAN" -o "$GUESTBR" -j GuestReject
		iptables -t filter -I GuestForward -i "$GUESTBR" ! -o "$IFACE_WAN" -j GuestReject
	fi

	if [ "$ONEWAY" = "true" ]; then
		iptables -t filter -I GuestForward ! -i "$IFACE_WAN" -o "$GUESTBR" -j ACCEPT
		iptables -t filter -I GuestForward -i "$GUESTBR" ! -o "$IFACE_WAN" -m state --state RELATED,ESTABLISHED -j ACCEPT
	fi
	
	if [ "$TWOWAY" = "false" ] && [ "$ONEWAY" = "true" ]; then 
		iptables -t filter -D GuestForward ! -i "$IFACE_WAN" -o "$GUESTBR" -j GuestReject > /dev/null 2>&1
	fi
	
	if [ "$CLIENTISOLATE" = "true" ]; then
		iptables -t filter -I GuestForward -i "$GUESTBR" -o "$GUESTBR" -j GuestReject
	fi
	
	if [ "$BLOCKINTERNET" = "true" ]; then
		iptables -t filter -I GuestForward -i "$GUESTBR" -o "$IFACE_WAN" -j GuestReject
		iptables -t filter -I GuestForward -i "$IFACE_WAN" -o "$GUESTBR" -j DROP
	fi
	
	if [ "$ENABLED_NTPD" -eq 1 ]; then
		iptables -t filter -I GuestForward -i "$GUESTBR" -p tcp --dport 123 -j REJECT
		iptables -t filter -I GuestForward -i "$GUESTBR" -p udp --dport 123 -j REJECT
	fi
	
	iptables -t filter -I FORWARD -j GuestForward

}

NAT_Rules() {

	Print_Output true "Setting up NAT Rules"

	# Delete firewall rules dealing with guest network
	iptables -t nat -D PREROUTING -i "$GUESTBR" -p tcp -m tcp --dport 123 -j DNAT --to-destination "$LAN_IP" > /dev/null 2>&1
	iptables -t nat -D PREROUTING -i "$GUESTBR" -p udp -m udp --dport 123 -j DNAT --to-destination "$LAN_IP" > /dev/null 2>&1
	iptables -t nat -D POSTROUTING -s "$LANSUBNET" -d "$LANSUBNET" -o "$GUESTBR" -j MASQUERADE > /dev/null 2>&1

	# Add firewall rules dealing with guest netwrok

	if [ "$ENABLED_NTPD" -eq 1 ]; then
		iptables -t nat -I PREROUTING -i "$GUESTBR" -p tcp -m tcp --dport 123 -j DNAT --to-destination "$LAN_IP"
		iptables -t nat -I PREROUTING -i "$GUESTBR" -p udp -m udp --dport 123 -j DNAT --to-destination "$LAN_IP"
	fi

	iptables -t nat -I POSTROUTING -s "$LANSUBNET" -d "$LANSUBNET" -o "$GUESTBR" -j MASQUERADE

}



Clean_EBT() {

	Print_Output true "Clearing any ebtable rules...."

	# ebtable rules 
	# In our default config, these rules should not exist, but delete them just in case
	ebtables -t broute -D BROUTING -p IPv4 -i "$GUESTIF" --ip-dst "$LAN_IP"/24 --ip-proto tcp -j DROP > /dev/null 2>&1
	ebtables -t broute -D BROUTING -p IPv4 -i "$GUESTIF" --ip-dst "$LAN_IP" --ip-proto icmp -j ACCEPT > /dev/null 2>&1
	ebtables -t broute -D BROUTING -p IPv4 -i "$GUESTIF" --ip-dst "$LAN_IP"/24 --ip-proto icmp -j DROP > /dev/null 2>&1

	ebtables -t broute -D BROUTING -p ipv4 -i "$GUESTIF" -j DROP > /dev/null 2>&1	
	ebtables -t broute -D BROUTING -p ipv6 -i "$GUESTIF" -j DROP > /dev/null 2>&1
	ebtables -t broute -D BROUTING -p arp -i "$GUESTIF" -j DROP > /dev/null 2>&1
}

Set_Lan_Access() {

	Print_Output true "Checking to LAN access nvram variable....."

	if [ "$(nvram get "${GUESTIF}_lanaccess")" != "on" ]; then
		Print_Output true "LAN access nvram varibale is not set correctly. Setting and restarting wireless interface" "$WARN"
		nvram set "$GUESTIF"_lanaccess=on
		nvram commit
		WIRELESSRESTART="true"
		service restart_wireless >/dev/null 2>&1
		return 0
	else	
		return 1
	fi
}

Read_Conf_File() {

	if ! [ -f "$CONF_FILE" ]; then
		Print_Output true "Configuration file can not be found...." "$ERR"
		Print_Output true "Writing a default config file to ${CONF_FILE}" "$ERR"
		Write_Default_Config
		if [ -f "$CONF_FILE" ]; then
			Print_Output false "A default config file has been written.  Edit this file with your set up, then restart the script" "$ERR"
		fi

		exit
	fi
	
	while read -r lineinput
	do
		stripped="${lineinput%%\#*}"
		key="${stripped%%=*}"; key="${key##*([[:space:]])}"; key=$(echo ${key} | awk '{$1=$1};1' | tr '[a-z]' '[A-Z]')
		value="${stripped#*=}"; value="${value##*([[:space:]])}";value="${value//\"/}"; value=$(echo ${value} | awk '{$1=$1};1')

		case "$key" in
			GUESTNETWORK)
				GUESTNETWORK="$value"
				;;
			GUESTIF)
				GUESTIF="$value"
				;;
			GUESTBR)
				GUESTBR="$value"
				;;
			LANPORTS)
				LANPORTS="$value"
				;;
			TWOWAY)
				TWOWAY="$value"
				;;
			ONEWAY)
				ONEWAY="$value"
				;;
			BLOCKINTERNET)
				BLOCKINTERNET="$value"
				;;
			CLIENTISOLATE)
				CLIENTISOLATE="$value"
				;;
			DNS1)
				DNS1="$value"
				;;
			DNS2)
				DNS2="$value"
				;;
			FORCEDNS)
				FORCEDNS="$value"
				;;
			DHCPSTART)
				DHCPSTART="$value"
				;;
			DHCPEND)
				DHCPEND="$value"
				;;
		esac
	done < "$CONF_FILE"
}

Check_Config() {

	if ! $(validate_ipaddr "$(cidr_ip "$GUESTNETWORK")"); then
		Print_Output true "ERROR: IP Address ${GUESTNETWORK} is not a valid IP4 address" "$ERR"
		Clear_Lock
		exit
	fi

	if ! $(IP_Local "$GUESTNETWORK"); then
		Print_Output true "ERROR: Guest LAN IP address is not a local Class C address: ${GUESTLANIP}" "$ERR"
		Print_Output true "Edit config file and ensure IP address in the Class C range" "$ERR"
		Clear_Lock
		exit
	fi
	
	if ! $(Router_Network "$(cidr_ip "$GUESTNETWORK")"); then
		Print_Output true "Error: Guest Bridge Network is the same as the Main Bridge network (br0)" "$ERR"
		Print_Output false "Select a guest network that is different than the main lan network" "$ERR"
		Clear_Lock
		exit
	fi

}

Write_Default_Config() {

	cat <<EOF > "$CONF_FILE"
# Configuration file for guest-net.sh script
#
# IP Address and CIDR of the new guest LAN interface on the router (This will be the gateway as well for this LAN)
GUESTNETWORK=192.168.30.2/24

# Guest Wifi interface name that will be moved.  This interface needs to be already setup via the GUI
# List only one interface.  This script only supports the setup of one interface
GUESTIF=wl1.2

# Name of the new bridge that will be created
GUESTBR=br4

# List of lan ports, space seperated, that will be moved from br0 into the new bridge
# If moving muliple lan ports to the bridge, seperate interfaces with a space using quotes (i.e "eth3 eth4")
LANPORTS=eth4

# Do you wish two way communications between br0 and the new bridge? ("true" or "false")
TWOWAY=false

# Do you wish one way communications to the new bridge?  ("true" or "false") (br0 > new bridge)
ONEWAY=false

# Is access to the internet to be blocked on the new bridge ("true" or "false")
BLOCKINTERNET=false

# Are clients on the new bridge to be isolated? ("true" or "false")
CLIENTISOLATE=false

# These options are planned, but not used in the script as of yet.
DNS1=8.8.8.8
DNS2=8.8.4.4
FORCEDNS=false
DHCPSTART=50
DHCPEND=200
FORCEDNS=false
EOF

}

############# Start of main script  ##################

Read_Conf_File
Check_Config

GUESTLANIP="$(cidr_ip "$GUESTNETWORK")"	
LANSUBNET="$(Get_NetworkIP)"/"$(cidr_prefix "$GUESTNETWORK")"
WIRELESSRESTART="false"

case "$1" in
	firewall)
		Print_Output true "Script called with firewall option.... Setting up firewall and nat rules"
		Check_Lock
		if ! [ -f /sys/class/net/${GUESTBR}/operstate ]; then
			Configure_bridge
		fi
		Clean_EBT
		Firewall_Rules
		NAT_Rules
		;;
	nat)
		Print_Output true "Script called with nat option..... Setting up nat rules"
		if ! [ -f /sys/class/net/${GUESTBR}/operstate ]; then
			Check_Lock
			Configure_bridge
			Firewall_Rules
		fi
		Clean_EBT
		NAT_Rules
		;;
	check)
		Print_Output true "Script called with check option .... Checking to see if iptables rules and bridge still in place"
		Check_Lock
		if ! iptables -nL | grep -q "GuestInput" || [ ! Configure_bridge ]; then
			Print_Output true "Either the iptables rules or the new bridge is not present... reapplying network changes" "$WARN"
			Clean_EBT
			Firewall_Rules
			NAT_Rules
		else
			Print_Output true "Iptable rules and $GUESTBR appear to be in place... exiting" "$PASS"
			Clear_Lock
			exit 0
		fi
		;;
	isolate)
		Print_Output true "Script called with option isolate.... Checking client isolation"
		Check_Lock
		if Client_Isolate; then
			Clear_Lock
			exit 0
		fi
		;;
	bounce_clients)
		Print_Output true "Script called with option bounce_clients.... Bouncing all clients from the $GUESTIF interface"
		Check_Lock
		Iface_BounceClients
		exit 0
		;;
	start)
		Print_Output true "Script called with option start.... Setting up new bridge $GUESTBR for interface $GUESTIF"
		Check_Lock
		Configure_bridge force
		Clean_EBT
		Firewall_Rules
		NAT_Rules
		;;
	*)
		echo
		echo "usage: guest-net.sh {start|firewall|nat|check|isolate|bounce_clients}"
		echo
		exit 0
		;;
esac

if [ "$WIRELESSRESTART" = "false" ]; then
	Print_Output true "Bouncing clients on $GUESTIF before exiting"
	Iface_BounceClients
fi

Clear_Lock

