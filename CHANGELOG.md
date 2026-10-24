# Changelog

All notable changes to pia_wg are listed here, newest first. The version is the `# Version:` line of the script (there are no git tags); `pia_wg.sh update` installs the latest one. Entries before 1.0.17 were reconstructed from the git history.

## [1.0.20] - 2026-10-24
### Added
- PIA port forwarding, optional (`configure portforward`). Once PIA is up, the script gets a port from the WireGuard server, and the watchdog keeps it alive (`bindPort` every 10 minutes). A new port is requested when it is about to expire or cannot be bound. A script given by the user is run with the port as argument whenever it changes, for instance to update a firewall redirect and the torrent client.
- `status` shows the forwarded port.

### Changed
- With port forwarding enabled, favorite regions are limited to those supporting it.
- The port forwarding state lives in `/tmp`, so nothing is written to flash every few minutes; tokens and signatures reach curl on stdin.

## [1.0.19] - 2026-10-23
### Added
- Favorite regions ([#15](https://github.com/bolemo/pia_wg/issues/15)): with two or more, each (re)connection measures the TCP connect time to every favorite's PIA meta server and uses the fastest. A working connection is never switched; switching region is logged and notified. `configure region` shows the region IDs and offers to add favorites.
- Dependency check before starting ([#14](https://github.com/bolemo/pia_wg/issues/14)): a clear message when `curl`, `jq` or `wg` is missing, or when the network service does not know the WireGuard protocol yet (`Unsupported protocol type`).

### Changed
- README: install command for apk (OpenWrt 25.12 and later) as well as opkg, and the network restart needed after installing wireguard-tools.

## [1.0.18] - 2026-10-23
### Added
- Webhook notifications of watchdog errors and corrective actions, for Slack, Mattermost, Rocket.Chat or ntfy (`configure notify`), by @bwitt ([#49](https://github.com/bolemo/pia_wg/pull/49)). They are sent right away, and grouped (at most once every 15 minutes) only while the watchdog is flapping; the pending queue is capped at 200 lines.
- Fall back to the other WireGuard servers of the region when one does not accept the key, by @bwitt ([#44](https://github.com/bolemo/pia_wg/pull/44)).

### Fixed
- Dedicated IP: the PIA token is renewed before the dedicated IP is validated, so DIP setups start the first time, by @bwitt ([#38](https://github.com/bolemo/pia_wg/pull/38)).
- Dedicated IP: no region is required any more, by @bwitt ([#40](https://github.com/bolemo/pia_wg/pull/40)).
- The literal string `null` is no longer added as a DNS server when PIA returns fewer than two, by @bwitt ([#46](https://github.com/bolemo/pia_wg/pull/46)).

### Security
- `/etc/config/pia_wg`, which holds the credentials, is now readable by root only, by @bwitt ([#42](https://github.com/bolemo/pia_wg/pull/42)).
- Secrets no longer show on screen or in the process list, by @bwitt ([#48](https://github.com/bolemo/pia_wg/pull/48)): the password, the PIA and dedicated IP tokens and the webhook URL reach curl through a config read on stdin, and reconfiguring hides `password`, `priv`, `token`, `hash` and `webhook` values.

## [1.0.17] - 2026-10-22
### Changed
- The connectivity check pings through the tunnel instead of relying on the first traceroute hop, which some PIA servers never answer, by @bwitt ([#30](https://github.com/bolemo/pia_wg/pull/30)). It sends 3 pings, so a single lost packet no longer restarts the tunnel.
- PIA server list v7, by @bwitt ([#36](https://github.com/bolemo/pia_wg/pull/36)).
- curl calls have timeouts and follow redirects, by @bwitt ([#34](https://github.com/bolemo/pia_wg/pull/34)).

### Security
- The key is added on a WireGuard server taken from the server list, and PIA's certificate is verified (it was `curl -k`), by @bwitt ([#32](https://github.com/bolemo/pia_wg/pull/32)).

## [1.0.16] - 2026-01-09
### Fixed
- Dedicated IP: when the PIA API cannot be reached (e.g. network down during a restart), the existing dedicated IP configuration is kept instead of failing.

## [1.0.15] - 2026-01-09
### Changed
- `status` prints the watchdog state once, by @bwitt ([#23](https://github.com/bolemo/pia_wg/pull/23)).
- README: `jq-full` is required.

## [1.0.14] - 2025-09-09
### Fixed
- The fwmark of the WireGuard interface is passed correctly to `ip route get` when looking for the WAN interface.

## [1.0.13] - 2025-09-09
### Fixed
- `inet is expected` error from `ip route get` when the interface has no fwmark, by @bwitt ([#21](https://github.com/bolemo/pia_wg/pull/21)).

## [1.0.12] - 2025-09-02
### Added
- pre-commit checks (shellcheck, shfmt), with the code formatted accordingly, by @bwitt ([#18](https://github.com/bolemo/pia_wg/pull/18)).

### Changed
- README: `configure dip` documented.

## [1.0.11] - 2025-08-26
### Fixed
- The PIA username and password are URL-encoded, so credentials with special characters work.

1.0.10 and 1.0.11 were merged from the beta branch ([#16](https://github.com/bolemo/pia_wg/pull/16)).

## [1.0.10] - 2025-08-25
### Changed
- Clearer errors when the PIA token cannot be fetched (connection failure, empty response, PIA error message, hint about the credentials).
- Start, stop and token renewal are written to the watchdog log.

## [1.0.9] - 2024-05-12
### Added
- Dedicated IP (beta): `configure dip`, validation of the dedicated IP token, and connection to it instead of a region.

## [1.0.8] - 2024-05-05
### Added
- `version` command, by @bwitt ([#13](https://github.com/bolemo/pia_wg/pull/13)).

### Fixed
- The WireGuard interface is stopped before being started again, by @bwitt ([#12](https://github.com/bolemo/pia_wg/pull/12)).

## [1.0.7] - 2024-03-26
### Added
- `log path` command to set the directory of the watchdog log.
- The region is shown by `status`, and in the start messages and the log.
- README: full list of packages to install and firewall setup, by @dudeami ([#9](https://github.com/bolemo/pia_wg/pull/9)).

## [1.0.6] - 2024-02-23
### Changed
- `network init` renamed `init-network`.
- The connectivity check looks for an answer in the traceroute output instead of its exit code, by @bwitt ([#7](https://github.com/bolemo/pia_wg/pull/7)).
- shellcheck warnings fixed, by @bwitt ([#8](https://github.com/bolemo/pia_wg/pull/8)).
- README: dependencies to install, by @bwitt ([#4](https://github.com/bolemo/pia_wg/pull/4)), and notes about the firewall and the clock at boot ([#5](https://github.com/bolemo/pia_wg/issues/5)).

## [1.0.5] - 2023-10-08
### Added
- `network init` command: set up the PIA WireGuard network without starting it.
- The watchdog log records its creation, clearing, and the watchdog being installed or removed.

## [1.0.4] - 2023-09-30
### Added
- `status` shows when the watchdog last checked.

## [1.0.3] - 2023-09-29
### Changed
- `update` shows the current and new versions and asks before installing.

## [1.0.2] - 2023-09-29
### Added
- `update` command: update the script to the latest version from GitHub.

## [1.0.1] - 2023-09-29
### Added
- First release: set up and run PIA through WireGuard on OpenWrt, with `configure`, `start`, `restart`, `stop` and `status`, a watchdog run by cron (`watchdog install`/`remove`) and its log (`log show`/`clear`), and advanced network settings through `pia_wg.@net_interface` and `pia_wg.@net_peer`.
