# pia_wg.sh
A script to setup and run PIA through WireGuard on OpenWrt
<br />https://github.com/bolemo/pia_wg/

## Inspired from:
  - This thread: https://forum.openwrt.org/t/private-internet-access-pia-wireguard-vpn-on-openwrt/155475
  - And @Lazerdog's script: https://github.com/jimhall718/piawg/blob/main/piawgx.sh

## Install
  - Connect to your OpenWrt router with SSH
  - Go (and create id needed) to the location you want to install the script
<br /> For example: `mkdir /opt/scripts; cd /opt/scripts`
  - Download the script: `wget https://raw.githubusercontent.com/bolemo/pia_wg/main/pia_wg.sh`
  - Give execution permission to the script: `chmod +x pia_wg.sh`
  - Configure and run:
    - To configure and run PIA, use `./pia_wg.sh start` and answer the questions
    - To just configure, use `./pia_wg.sh configure` and answer the questions
<br /> Then you can setup network advanced/expert settings (see below) and then to run, use `./pia_wg.sh start`

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
It is possible to run the script as a watchdog that will check regularly the status and restart the VPN if needed.
<br/> For that, just load the cronjob editor: `crontab -e`, then add this line (replacing `<path>` by the location of the script, for example `/opt/scripts` and save:
```
* * * * * /bin/sh <path>/pia_wg.sh start
```

## Logging
The script log is located in `/var/log/pia_wg.log`

## Usage
Usage: `pia_wg.sh {configure <section> | start | restart | stop | status}`
<br/>  Details:
  - `configure`         : same as configure all
  - `configure all`     : configure all settings
  - `configure user`    : set PIA user ID and password
  - `configure region`  : set/choose PIA region
  - `configure keys`    : generate local WireGuard keys
  - `configure network` : generate default network settings
  - `start`             : start PIA WireGuard (if not already up)
  - `restart`           : start or restart PIA WireGuard
  - `stop`              : stop PIA WireGuard
  - `status`            : show PIA WireGuard status

## Copyright
©2023 bOLEMO