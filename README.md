# pia_wg.sh
A script to setup and run PIA through WireGuard on OpenWrt
<br />https://github.com/bolemo/pia_wg/

## Inspired from:
  - This thread: https://forum.openwrt.org/t/private-internet-access-pia-wireguard-vpn-on-openwrt/155475
  - And @Lazerdog's script: https://github.com/jimhall718/piawg/blob/main/piawgx.sh

## Version
1.0.10

## Install
  - Connect to your OpenWrt router with SSH
  - Go to (and create if needed) the location you want to install the script
<br /> For example: `mkdir /opt/scripts; cd /opt/scripts`
  - Download the script: `wget https://raw.githubusercontent.com/bolemo/pia_wg/main/pia_wg.sh`
  - Give execution permission to the script: `chmod +x pia_wg.sh`
  - Install packages which the script depends on: `opkg update && opkg install jq curl wireguard-tools luci-proto-wireguard coreutils-stty coreutils-nl`
  - Configure and run:
    - To configure and run PIA, use `./pia_wg.sh start` (or `./pia_wg.sh start --watchdog` if you want the watchdog installed) and answer the questions
    - To just configure, use `./pia_wg.sh configure` and answer the questions
<br /> Then you can setup network advanced/expert settings (see below) and then to run, use `./pia_wg.sh start` (or `./pia_wg.sh start --watchdog`)

## Setup firewall

__The firewall setup depends on your needs and your personal configuration.__

For a typical setup (direct all LAN traffic to/from internet through the newly created wireguard interface), you'll need to update your firewall this way:

- Navigate to Network > Firewall
- Create a new Zone, name it PIA or whatever you want
- In the General Settings tab, enable **Masquerading** and **MSS Clamping**, then add **LAN** to **Allow forward from source zones**
- In the Advanced Settings tab, set **Covered Devices** to **wg_pia**
- Save the zone
- Now edit your zone starting with **LAN**
- Set **Allow forward to destination zones** to **PIA** or whatever you named the previously created zone
- Traffic should now only be allowed through the wireguard connection

## Update
The script can be updated to the latest version using: `pia_wg.sh update`

## Advanced/Expert WireGuard network settings (not required for basic/common usage)
You can setup the script to set any OpenWrt WireGuard network interface or peer settings this way (after running the initial configuration):
  - for network WireGuard PIA interface: `uci set pia_wg.@net_interface[0].<option>=<value>` then `uci commit pia_wg.@net_interface[0]`
  - for network WireGuard PIA peer: `uci set pia_wg.@net_peer[0].<option>=<value>` then `uci commit pia_wg.@net_peer[0]`

For example, to prevent OpenWrt to route all the traffic through the VPN:
```
uci set pia_wg.@net_peer[0].route_allowed_ips='0'
uci commit pia_wg.@net_peer[0]
```

Or to put a fwmark on the outgoing VPN traffic:
```
uci set pia_wg.@net_interface[0].fwmark='0x1'
uci commit pia_wg.@net_interface[0]
```

Then, next time you use `./pia_wg.sh start` (if not already started, otherwise you need to restart or do stop then start to enable the new configuration) or `./pia_wg.sh restart`, it will use these extra settings when OpenWrt WireGuard will create the PIA interface and the PIA peer.

## Watchdog
The script can install a watchdog that will check regularly the status and restart the VPN if needed.
<br/> For that, just use `--watchdog` when using `start`or `restart`, or run the command `./pia_wg.sh watchdog install`
<br/> To unsinstall/remove the watchdog, use `./pia_wg.sh watchdog remove`; when `./pia_wg.sh stop` is used, the watchdog is automatically removed

## Logging
When the watchdog is enabled, the scripts log is located in `/var/log/pia_wg_watchdog.log`
The log can be displayed using `pia_wg.sh log show` and cleared using `pia_wg_sh log clear`

## Usage
Usage: `pia_wg.sh { configure <section> | start [ --watchdog ] | restart [ --watchdog ] | stop | status | watchdog { install | remove } | log { show | clear | path } | update | version}
<br/>  Details:
  - `configure`          : same as configure all
  - `configure all`      : configure all settings
  - `configure user`     : set PIA user ID and password
  - `configure region`   : set/choose PIA region
  - `configure keys`     : generate local WireGuard keys
  - `configure network`  : generate default network settings
  - `init-network`       : setup PIA WireGuard network (no start)
  - `start`              : start PIA WireGuard (if not already up)
  - `start --watchdog`   : same as start and install the watchdog
  - `restart`            : start or restart PIA WireGuard
  - `restart --watchdog` : same as restart and install the watchdog
  - `stop`               : stop PIA WireGuard (and remove the watchdog)
  - `status`             : show PIA WireGuard status
  - `watchdog install`   : install the watchdog
  - `watchdog remove`    : remove the watchdog
  - `log show`           : display the watchdog log
  - `log clear`          : clear the watchdog log
  - `log path`           : set a custom Directory Path for the log
  - `update`             : update the script to latest version
  - `version`            : print the version and exit

## Notes
Please, take into account that the script is only creating and setting up the WireGuard interface. It is up to the user to set up/adapt his firewall zones (either including the interface in the WAN zone, or creating a specific zone for it named VPN, PIA or whichever name you want).

A user reported an issue not directly linked to this script but that others users might experience : on his OpenWrt setup, when his router restarts, the time is not properly set and it prevents the interface to go up.
He proposed a solution here: https://github.com/bolemo/pia_wg/issues/5

## Copyright
©2025 bOLEMO
