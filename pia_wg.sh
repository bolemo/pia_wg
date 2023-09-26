#!/bin/sh
#
# pia_wg.sh
# Script to setup and run PIA through WireGuard on OpenWrt
#
# Inspired from:
# - This thread: https://forum.openwrt.org/t/private-internet-access-pia-wireguard-vpn-on-openwrt/155475
# - And @Lazerdog's script: https://github.com/jimhall718/piawg/blob/main/piawgx.sh
#
# ©2023 bOLEMO
# https://github.com/bolemo/pia_wg/
#
#########

PIACONF='/etc/config/pia_wg'
PIAWG_IF='wg_pia'
PIAWG_PEER='wgpeer_pia'

read_yn() {
  while
    printf "$1? (y/n):"; read ANS
    echo "$ANS" | grep -qvi '^\(y\(es\)\?\|no\?\)$'
  do :; done
  case "$ANS" in
    n|N|no|No|nO|NO) return 1;;
    *) return 0;;
  esac
}

select_region() {
  echo "Fetching latest PIA servers list…"
  PIAREGIONS="$(curl -s https://serverlist.piaservers.net/vpninfo/servers/v6 | head -1 | jq '.regions | sort_by(.name)')"
  [ $? -eq 0 ] || { echo "Error fetching PIA servers list!" >&3; exit 1; }
  while :; do
    printf "Type the region ID if you know it or press enter for list selection: "; read PIAREGIONID;
    if [ -z "$PIAREGIONID" ]
      then break
      else
        PIAREGIONNAME="$(echo "$PIAREGIONS" | jq -r ".[] | select(.id==\"$PIAREGIONID\") | .name")"
        if [ -z "$PIAREGIONNAME" ]
          then echo "Invalid region ID: '$PIAREGIONID'"
          else break
        fi
    fi
  done
  if [ -z "$PIAREGIONID" ]; then
    echo "Eliminating offline servers…"
    echo "Eliminating non WireGuard servers…"
    read_yn "Port forward only servers" && PIASERVPF='| select(.port_forward==true) ' || PIASERVPF=''
    read_yn "Geo only servers" && PIASERVGEO='| select(.geo==true) ' || PIASERVGEO=''
    echo "$PIAREGIONS" | jq -r ".[] | select(.offline==false) | select(.servers.wg) $PIASERVPF $PIASERVGEO | .name" | nl -v0
    printf "Select your region number: "; read ANS
    PIAREGIONID="$(echo "$PIAREGIONS" | jq -r "[.[] | select(.offline==false) | select(.servers.wg) $PIASERVPF $PIASERVGEO ][$ANS].id")"
  fi
  PIAREGIONNAME="$(echo "$PIAREGIONS" | jq -r ".[] | select(.id==\"$PIAREGIONID\") | .name")"
  PIAREGIONDNS="$(echo "$PIAREGIONS" | jq -r ".[] | select(.id==\"$PIAREGIONID\") | .dns")"
  echo "Region selected: $PIAREGIONNAME"
  uci -q batch << EOI >/dev/null
    delete pia_wg.@region[0]
    add pia_wg region
    set pia_wg.@region[0].id="$PIAREGIONID"
    set pia_wg.@region[0].name="$PIAREGIONNAME"
    set pia_wg.@region[0].dns="$PIAREGIONDNS"
    commit pia_wg.@region[0]
EOI
}

set_piauser() {
  printf "PIA user id: "
  read PIAUSER
  printf "PIA password: "
  stty -echo; read PIAPASS; stty echo; printf "\n"
  uci -q batch << EOI >/dev/null
    delete pia_wg.@user[0]
    add pia_wg user
    set pia_wg.@user[0].id="$PIAUSER"
    set pia_wg.@user[0].password="$PIAPASS"
    commit pia_wg.@user[0]
EOI
}

set_defnetpeer() {
  uci -q batch << EOI >/dev/null
    delete pia_wg.@net_peer[0]
    add pia_wg net_peer
    set pia_wg.@net_peer[0].route_allowed_ips='1'
    set pia_wg.@net_peer[0].persistent_keepalive="25"
    add_list pia_wg.@net_peer[0].allowed_ips="::/0"
    add_list pia_wg.@net_peer[0].allowed_ips="0.0.0.0/0"
    commit pia_wg.@net_peer[0]
EOI
}

set_defnetiface() {
  uci -q batch << EOI >/dev/null
    delete pia_wg.@net_interface[0]
    add pia_wg net_interface
    set pia_wg.@net_interface[0].proto="wireguard"
    set pia_wg.@net_interface[0].defaultroute='1'
    set pia_wg.@net_interface[0].delegate='0' # No IPv6 with PIA
    commit pia_wg.@net_interface[0]
EOI
}

generate_wgkeys() {
  WGPRIVKEY="$(wg genkey)"
  WGPUBKEY="$(echo "$WGPRIVKEY" | wg pubkey)"
  uci -q batch << EOI >/dev/null
    delete pia_wg.@keys[0]
    add pia_wg keys
    set pia_wg.@keys[0].priv="$WGPRIVKEY"
    set pia_wg.@keys[0].pub="$WGPUBKEY"
    commit pia_wg.@keys[0]
EOI
}

renew_piatoken() {
  echo "Renewing PIA token"
  uci -q get pia_wg.@user[0] >/dev/null || set_piauser
  PIATOKEN="$(curl -s -d "username=$(uci -q get pia_wg.@user[0].id)&password=$(uci -q get pia_wg.@user[0].password)" https://www.privateinternetaccess.com/api/client/v2/token | jq -r .token)"
  [ ${#PIATOKEN} -eq 128 ] || { echo "Error fetching PIA token!" >&3; exit 1; }
  uci -q batch << EOI >/dev/null
    delete pia_wg.@token[0]
    add pia_wg token
    set pia_wg.@token[0].hash="$PIATOKEN"
    set pia_wg.@token[0].timestamp="$(date +%s)"
    commit pia_wg.@token[0]
EOI
}

keep_conf_section() {
  case "$1" in
    user) DESC='PIA user';;
    keys) DESC='WireGuard local keys';;
    net_interface) DESC='WireGuard network interface options';;
    net_peer) DESC='WireGuard network PIA peer options';;
    region) DESC='PIA region';;
  esac
  if uci -q get pia_wg.@$1[0] >/dev/null; then
    echo "A configuration already exists for '$DESC':"
    uci show pia_wg.@$1[0] | awk 'sub(/^[^.]*\.[^.]*\./,"")==1{print "  "$0}'
    read_yn "Keep this configuration"; return $?
  fi
  return 1
}

check_conf() {
  uci -q get pia_wg.@user[0] >/dev/null \
    && echo "User is configured" \
    || { echo "User is not configured!" >&3; [ "$AUTO" ] && return 1 || set_piauser; }
  uci -q get pia_wg.@keys[0] >/dev/null \
    && echo "Local keys are configured" \
    || {  echo "Local keys are not configured!" >&3; generate_wgkeys; }
  uci -q get pia_wg.@net_interface[0] >/dev/null \
    &&  echo "Network interface options are configured" \
    || {  echo "Network interface options are not configured!" >&3; [ "$AUTO" ] && return 1 || set_defnetiface; }
  uci -q get pia_wg.@net_peer[0] >/dev/null \
    && echo "Network peer options are configured" \
    || {  echo "Network peer options are not configured!" >&3; [ "$AUTO" ] && return 1 || set_defnetpeer; }
  uci -q get pia_wg.@region[0] >/dev/null \
    && echo "PIA region is configured" \
    || {  echo "PIA region is not configured!" >&3; [ "$AUTO" ] && return 1 || select_region; }
}

get_piaserverconf() {
  uci -q get pia_wg.@token[0] >/dev/null && [ $(($(date +%s) - $(uci get pia_wg.@token[0].timestamp))) -lt 86400 ] || renew_piatoken
  PIAADDKEY="$(curl -s -k -G --data-urlencode "pt=$(uci -q get pia_wg.@token[0].hash)" --data-urlencode "pubkey=$(uci -q get pia_wg.@keys[0].pub)" "https://$(uci -q get pia_wg.@region[0].dns):1337/addKey")"
#  echo "$PIAADDKEY"

  WGSERVSTATUS="$(echo "$PIAADDKEY" | jq -r '.status')"
  [ "$WGSERVSTATUS" == "OK" ] || { echo "PIA server status: $WGSERVSTATUS; Aborting!" >&3; exit 1; }

  WGSERVIP="$(echo "$PIAADDKEY" | jq -r '.server_ip')"
  WGSERVPT="$(echo "$PIAADDKEY" | jq -r '.server_port')"
  WGSERVKEY="$(echo "$PIAADDKEY" | jq -r '.server_key')"
  WGDNS1="$(echo "$PIAADDKEY" | jq -r '.dns_servers[0]')"
  WGDNS2="$(echo "$PIAADDKEY" | jq -r '.dns_servers[1]')"
  WGPEERIP="$(echo "$PIAADDKEY" | jq -r '.peer_ip')"

  uci -q batch << EOI >/dev/null
  delete network.$PIAWG_IF
  delete network.$PIAWG_PEER
  set network.$PIAWG_IF=interface
  set network.$PIAWG_IF.addresses="$WGPEERIP"
  set network.$PIAWG_IF.private_key="$(uci -q get pia_wg.@keys[0].priv)"
  add_list network.$PIAWG_IF.dns="$WGDNS1"
  add_list network.$PIAWG_IF.dns="$WGDNS2"
  set network.$PIAWG_PEER="wireguard_${PIAWG_IF}"
  set network.$PIAWG_PEER.description="PIA $(uci -q get pia_wg.@region[0].name)"
  set network.$PIAWG_PEER.endpoint_host="$WGSERVIP"
  set network.$PIAWG_PEER.endpoint_port="$WGSERVPT"
  set network.$PIAWG_PEER.public_key="$WGSERVKEY"
$(uci export pia_wg | awk '
    $0==""{d=0;next}
    index($0,"config net_"){
      if($2=="net_interface"){d="network.'$PIAWG_IF'"}
      else if($2=="net_peer"){d="network.'$PIAWG_PEER'"}
    }
    d{
      if($1=="option"){c="set"}
      else if($1=="list"){c="add_list"}
      else next
      printf("  %s %s.%s=%s\n",c,d,$2,$3)
    }
')

  commit network.$PIAWG_IF
  commit network.$PIAWG_PEER
EOI
}

start_wgpia() {
  echo "Starting PIA..."
  check_conf && get_piaserverconf || { echo "Configuration is incomplete; exiting!" >&3; exit 1; }
  ifdown $PIAWG_IF >/dev/null 2>&1
  ifup $PIAWG_IF
  sleep 1
  check_wg
  [ $? -eq 0 ] && echo "PIA started successfully" >&3 || echo "Could not start PIA!" >&3
  return $?
}

stop_wgpia() {
  echo "Stopping PIA" >&3
  ifdown $PIAWG_IF
}

check_wg() {
  if wg show "$PIAWG_IF" >/dev/null 2>&1; then
      PIAWG_EP="$(wg show "$PIAWG_IF" endpoints | awk -F'[[:space:]:]' '{print $2; exit;}')"
      PIAWG_MK="$(wg show "$PIAWG_IF" fwmark)"; [ "$PIAWG_MK" = "off" ] && PIAWG_MK='' || PIAWG_MK="mark $PIAWG_MK"
      WAN_IF="$(ip route get "$PIAWG_EP" $VPN_MK | awk '{for(i=0;i<NF;i++){if($i=="dev"){print $++i; exit;}}}')"
      echo "PIA WireGuard interface: UP"
    else echo "PIA WireGuard interface: DOWN!" >&3; return 1
  fi

  if traceroute -i "$WAN_IF" -q1 -m1 1.1.1.1 >/dev/null
    then echo "WAN connection: OK"
    else echo "WAN connection: NOK!" >&3; return 2
  fi

  if ping -q -c1 -n -I "$WAN_IF" "$PIAWG_EP" >/dev/null
    then echo "Access to PIA Endpoint through WAN: OK"
    else echo "Access to PIA Endpoint through WAN: NOK!" >&3; return 1
  fi

  if traceroute -i "$PIAWG_IF" -q1 -m1 1.1.1.1 >/dev/null
    then echo "Connectivity through PIA: OK"
    else echo "Connectivity through PIA: NOK" >&3; return 1
  fi
}

print_usage() {
  echo "Usage: $0 {configure <section> | start | restart | stop | status}"
  echo "  Details:"
  echo "    - configure         : same as configure all"
  echo "    - configure all     : configure all settings"
  echo "    - configure user    : set PIA user ID and password"
  echo "    - configure region  : set/choose PIA region"
  echo "    - configure keys    : generate local WireGuard keys"
  echo "    - configure network : generate default network settings"
  echo "    - start             : start PIA WireGuard (if not already up)"
  echo "    - restart           : start or restart PIA WireGuard"
  echo "    - stop              : stop PIA WireGuard"
  echo "    - status            : show PIA WireGuard status"
}


# ---- Main ->

[ -e "$PIACONF" ] || touch "$PIACONF"
[ -t 0 ] && AUTO=1 || unset AUTO

# Logging
PIALOG='/var/log/pia_wg.log'
export FIFO="$(mktemp -u /tmp/pia_wg.XXXXXXXXXX)"
_exit() { exec 3>&-; rm "$FIFO"; exit; }
trap "_exit" 1 2 3 6 EXIT
touch "$PIALOG"
mkfifo "$FIFO"
awk -v lf="$PIALOG" '{print; printf("[%s] %s\n",systime(),$0) >> lf}' "$FIFO" >&2 &
exec 3<>"$FIFO"

case "$1" in
  'configure') case "$2" in
    ''|'all')
      keep_conf_section 'user' || set_piauser
      keep_conf_section 'keys' || generate_wgkeys
      keep_conf_section 'net_interface' || set_defnetiface
      keep_conf_section 'net_peer' || set_defnetpeer
      keep_conf_section 'region' || select_region
      ;;
    'user') keep_conf_section 'user' || set_piauser;;
    'region') keep_conf_section 'region' || select_region;;
    'network')
      keep_conf_section 'net_interface' || set_defnetiface
      keep_conf_section 'net_peer' || set_defnetpeer
      ;;
    'keys') keep_conf_section 'keys' || generate_wgkeys;;
    *) echo "Unknown configure subcommand '$2'!"; print_usage; exit 1;;
    esac;;
  'restart') start_wgpia;;
  'start')
    check_wg; case $? in
      0) echo "PIA is already up!";;
      1) start_wgpia;;
      2) echo "Could not start PIA!" >&2;;
    esac; exit $?
    ;;
  'stop') stop_wgpia;;
  'status') check_wg; exit $?;;
  '') print_usage;;
  *) echo "Unknown command '$*'!" >&2; print_usage; exit 1;;
esac

exit
