# Brawlhalla Pinger

A local dashboard that measures all nine Brawlhalla regional endpoints at the same time, or one region you select. **TCP port 443 is the default**, with TCP port 80 and ICMP echo available in the method selector.

## Start

Requires **Python 3.9 or newer**. No Python packages or build tools are needed. The optional ICMP mode also requires the system `ping` command; TCP mode uses Python's standard library directly.

- **Windows:** double-click `start.bat`.
- **macOS / Linux:** open a terminal in this folder and run `./start.sh`.
- Or run `python3 pinger.py` (`py -3 pinger.py` on Windows).

Your browser opens to `http://127.0.0.1:8765`. Keep the terminal open while using the dashboard; press **Ctrl+C** in it to stop the app.

Windows and macOS include `ping`. For optional ICMP mode on Linux, install your distribution's ping package if missing; on Debian/Ubuntu, use `sudo apt install iputils-ping`.

## Use

Probing starts automatically with **all nine servers selected**. Click a region's card to probe only that region; the other eight stop probing and retain their previous results. Click **All servers** to resume probing all nine. Selection lasts until you close the app, and changing selection keeps your measurements and pause state.

Each region shows its latest latency, average, minimum, maximum, jitter, and a chart of the last 90 probes. Use the dashboard to pause/resume, reset measurements, choose a 1, 2, 5, or 10 second interval (default: 2 seconds), change measurement method, and export results as CSV. The overview and CSV export cover the currently selected region or all nine when **All servers** is active.

Statistics cover the current session; charts and CSV probe history retain the last 90 probes per region. Jitter is the average change between consecutive successful measurements. Switching method or TCP port clears the session so different measurement types are never averaged together.

## TCP and ICMP measurements

- **TCP 443 (default):** measures the time to establish a TCP connection to port 443. A host can accept TCP even when it ignores ICMP echo. No TLS negotiation or HTTP request is sent. The percentage shown is **failed connection attempts**, not network packet loss.
- **TCP 80:** the same measurement on port 80, for endpoints where that service is available.
- **ICMP echo:** uses the operating system's ping utility and reports missing ICMP replies as ICMP probe loss. This can differ from in-game packet loss.

TCP timing excludes DNS lookup, TLS, and HTTP. DNS lookup results are cached for 60 seconds, and probes use the first IPv4 address returned for a hostname; literal IPv6 targets are supported too. The selected IP appears in diagnostic details. The socket connection wait is limited to 2 seconds; operating-system DNS resolution can take longer. DNS and local permission errors are reported separately and excluded from connection-failure or ICMP-loss percentages.

A refused TCP connection means a host or firewall responded with a rejection; it is shown as **PORT CLOSED** and counted as a failed connection. A timeout does not establish that a game server is down. TCP latency to these regional endpoints is a connection comparison, and can differ from gameplay's UDP latency. The game does not need to be running to measure the original nine targets.

Nmap's normal host discovery can also use TCP probes, including with `-sn`; a host reported as up by Nmap may still ignore ICMP echo. [Nmap host discovery documentation](https://nmap.org/book/man-host-discovery.html)

## Use actual match endpoints on Linux

You can optionally use an address observed in a running match instead of the default regional endpoint:

1. Run this app on the same Linux computer as Brawlhalla and join an online match in the region you want to measure.
2. Click **Find game connections**. The app reads socket metadata owned by your Brawlhalla process through `/proc`; it does not read game memory or packet contents and does not require root.
3. Click **Use IP for a region**, choose the region currently selected in your game, and save. Only that region's measurements are cleared.
4. Repeat in other regions if you want to collect targets for all nine. The saved targets are then pinged concurrently.

You can also click **edit** beside any card's hostname to enter a hostname or IP, or restore its original target. Targets are saved in `targets.json` beside `pinger.py` and loaded the next time the app starts. Keep the folder writable. Use `--targets PATH` to choose another settings file.

Discovery shows candidate connections: lobby services and routing relays can appear alongside match endpoints. It cannot infer your chosen region from an IP. Prefer a connection that appears during a match, and compare it with the game's menu state. The [publisher's support page](https://www.brawlhalla.com/support) identifies game port ranges 23000–24000 and 33000–34000; the app places matching remote ports first, while retaining other game-owned connections.

A game endpoint may not listen on TCP ports 443/80 or answer ICMP. A routing relay's latency can differ from in-game latency. Replacing a target does not guarantee it will respond to the chosen probe. Saved addresses may change between matches.

For command-line discovery:

```sh
python3 connections.py
```

If no peer is shown despite a running game, the game may be using an unconnected UDP socket, which does not expose its per-packet destination in socket tables. An active match is needed to identify that destination from traffic metadata. The discovery tool reports this limitation instead of guessing an address.

If you already have `tcpdump`, run this during an online match to see traffic metadata on the documented game ports:

```sh
sudo tcpdump -nn -i any -c 120 '(udp or tcp) and (portrange 23000-24000 or portrange 33000-34000)'
```

Look for the remote endpoint of a sustained flow that appears during the match, and correlate its local port with `ss -tunp`. Port matching alone does not establish which process owns a flow. The default tcpdump display shows packet headers; this command does not request payload dumps or save a capture file.

Root-domain DNS enumeration shows records for services such as DNS, mail, and the website. Those records do not establish the remote endpoint used by your current match.

| Region | Host |
| --- | --- |
| US-E | `pingtest-atl.brawlhalla.com` |
| US-W | `pingtest-cal.brawlhalla.com` |
| EU | `pingtest-ams.brawlhalla.com` |
| SEA | `pingtest-sgp.brawlhalla.com` |
| AUS | `pingtest-aus.brawlhalla.com` |
| BRAZIL | `pingtest-brs.brawlhalla.com` |
| JAPAN | `pingtest-jpn.brawlhalla.com` |
| MIDDLE EAST | `pingtest-mde.brawlhalla.com` |
| SOUTHERN AFRICA | `pingtest-saf.brawlhalla.com` |

Measurements reflect the network route from the computer running the app. They can differ from in-game match latency. Timeouts can reflect filtering, an unavailable port, or a connection problem.

## Options and troubleshooting

```sh
python3 pinger.py --port 9000
python3 pinger.py --no-browser
python3 pinger.py --method tcp --tcp-port 80
python3 pinger.py --method icmp
```

The launchers also accept these options, for example `./start.sh --port 9000` or `start.bat --no-browser`.

- If Python is missing or too old, install Python 3.9+ and reopen your terminal. On Windows, enable the installer's Python launcher or PATH option.
- If the default port is busy, choose another port with `--port` and open the address printed in the terminal.
- If the browser does not open automatically, open that printed address yourself.
- If a region times out, click **Check connection**. It compares the selected region (or all nine in **All servers** mode) with an internet reference (`google.com`) using the selected method and shows probe details. ICMP diagnostics also test local loopback. Downloading the report does not change session statistics.

To diagnose directly from a Linux terminal, without opening the dashboard:

```sh
python3 pinger.py --diagnose
python3 pinger.py --method icmp --diagnose
```

If the reference succeeds but the Brawlhalla targets do not, the selected method works to the reference while those specific endpoints are not responding on your route. This alone does **not** prove the game servers are down. If ICMP gets no replies, try TCP 443. A permission or DNS error is reported separately from probe failures.

You can also compare the app with the Linux command directly:

```sh
ping -4 -c 3 -W 3 pingtest-ams.brawlhalla.com
ping -4 -c 3 -W 3 google.com
```

The supplied addresses match [Brawlhalla's connection troubleshooting guide](https://www.brawlhalla.com/lag-help/).

When updating, stop the previous app with Ctrl+C, replace the files, and start it again. Reload the dashboard to use the updated JavaScript.

The app uses Python's standard library to serve the dashboard on `127.0.0.1` and run nine independent probe workers. TCP uses sockets; ICMP uses separate system ping processes. It runs locally without a hosted service or third-party frontend dependencies.

Run the backend checks with `python3 -m unittest discover -s tests -v`.
