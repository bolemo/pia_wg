# pia_wg.sh
A script to setup and run PIA through WireGuard on OpenWrt
<br />https://github.com/bolemo/pia_wg/

## Inspired from:
  - This thread: https://forum.openwrt.org/t/private-internet-access-pia-wireguard-vpn-on-openwrt/155475
  - And @Lazerdog's script: https://github.com/jimhall718/piawg/blob/main/piawgx.sh

## Version
1.0.20
<br />Changes of each version: see [CHANGELOG.md](CHANGELOG.md)

## Install
  - Connect to your OpenWrt router with SSH
  - Go to (and create if needed) the location you want to install the script
<br /> For example: `mkdir /opt/scripts; cd /opt/scripts`
  - Download the script: `wget https://raw.githubusercontent.com/bolemo/pia_wg/main/pia_wg.sh`
  - Give execution permission to the script: `chmod +x pia_wg.sh`
  - Install packages which the script depends on:
    - OpenWrt 25.12 and later: `apk update && apk add jq curl wireguard-tools luci-proto-wireguard coreutils-stty coreutils-nl`
    - Older OpenWrt: `opkg update && opkg install jq-full curl wireguard-tools luci-proto-wireguard coreutils-stty coreutils-nl`
  - Restart the network (`/etc/init.d/network restart`) or reboot, so that the WireGuard protocol is known (otherwise LuCI shows `Unsupported protocol type` and the interface stays down)
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

## Notifications
The watchdog can post to a Slack [incoming webhook](https://api.slack.com/messaging/webhooks) (or any service accepting a JSON `{"text": "..."}` payload, like Mattermost or Rocket.Chat) whenever it logs an error or takes a corrective action (e.g. restarting PIA).

- To set it up, run `./pia_wg.sh configure notify` and paste the webhook URL (press enter to disable).
- If a notification cannot be sent (e.g. no connectivity), it is kept and sent along with the next one.
- Notifications are sent right away. If the watchdog has something to report more than 3 times within 15 minutes (flapping), messages are grouped and sent at most once every 15 minutes until it settles.
- For [ntfy](https://ntfy.sh), use its [message templating](https://docs.ntfy.sh/publish/#message-templating) to extract the text, e.g. `https://ntfy.sh/your-topic?tpl=yes&t=pia_wg&m=%7B%7B.text%7D%7D` (keep the braces URL-encoded as `%7B`/`%7D`).

## Favorite regions
Instead of a single region, you can set several favorite regions: each time PIA (re)connects, the script measures how fast each one answers (TCP connect time to its PIA meta server) and uses the fastest. A working connection is never switched: the choice is only made when connecting (at start, or when the watchdog restarts PIA). Switching region is logged, and notified if a webhook is set.

- `./pia_wg.sh configure region` offers to add favorite regions after the first one (region IDs are shown in brackets in the list).
- Or with uci, listing every favorite including the current region: `uci add_list pia_wg.@region[0].favorite='france'`, then `uci commit pia_wg`.

With a single region (no favorites), nothing changes.

## Port forwarding
PIA can forward one port to your router, on the regions that support it (see `Port forward only servers` when choosing a region; it is not available in the US). The port is chosen by PIA and can change, for instance when PIA reconnects.

- Enable it with `./pia_wg.sh configure portforward`, then restart PIA. The port is requested once PIA is up, and the watchdog keeps it alive (PIA drops a port that is not refreshed).
- Give a script to run when the port changes: it is called with the port as argument, for instance to update a firewall redirect (from the PIA zone to your torrent client) and the client's listening port.
- `./pia_wg.sh status` shows the current port. With favorite regions, only those supporting port forwarding are used.

Example of script, with a firewall redirect named `torrent` and Transmission on another host:
```sh
#!/bin/sh
uci set firewall.torrent.src_dport="$1"
uci set firewall.torrent.dest_port="$1"
uci commit firewall && /etc/init.d/firewall reload
transmission-remote 192.168.1.10:9091 --port "$1"
```

## Usage
Usage: `pia_wg.sh { configure <section> | start [ --watchdog ] | restart [ --watchdog ] | stop | status | watchdog { install | remove } | log { show | clear | path } | update | version}
<br/>  Details:
  - `configure`          : same as configure all
  - `configure all`      : configure all settings
  - `configure user`     : set PIA user ID and password
  - `configure dip`      : set PIA dedicated IP
  - `configure region`   : set/choose PIA region (and optional favorite regions)
  - `configure keys`     : generate local WireGuard keys
  - `configure network`  : generate default network settings
  - `configure notify`   : set a Slack (or compatible) webhook to notify watchdog errors/actions
  - `configure portforward` : enable/disable PIA port forwarding (and the script run when the port changes)
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
©2026 bOLEMO
