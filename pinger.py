#!/usr/bin/env python3
"""A local dashboard for concurrent Brawlhalla TCP and ICMP measurements."""

import argparse
from collections import OrderedDict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import json
import ipaddress
import errno
import locale
import math
import mimetypes
import os
from pathlib import Path
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Deque, Optional
from urllib.parse import unquote, urlsplit
import webbrowser


SERVERS = (
    ("us-e", "US East", "Atlanta", "pingtest-atl.brawlhalla.com"),
    ("us-w", "US West", "California", "pingtest-cal.brawlhalla.com"),
    ("eu", "Europe", "Amsterdam", "pingtest-ams.brawlhalla.com"),
    ("sea", "Southeast Asia", "Singapore", "pingtest-sgp.brawlhalla.com"),
    ("aus", "Australia", "Australia", "pingtest-aus.brawlhalla.com"),
    ("brazil", "Brazil", "Brazil", "pingtest-brs.brawlhalla.com"),
    ("japan", "Japan", "Japan", "pingtest-jpn.brawlhalla.com"),
    ("middle-east", "Middle East", "Middle East", "pingtest-mde.brawlhalla.com"),
    ("southern-africa", "Southern Africa", "Southern Africa", "pingtest-saf.brawlhalla.com"),
)
INTERVALS = (1, 2, 5, 10)
HISTORY_LIMIT = 90
REPLY_TIMEOUT = 2.0
TCP_PORTS = (80, 443)
DNS_CACHE_TTL = 60.0
DNS_CACHE_LIMIT = 128
PROCESS_TIMEOUT = 8.0
# Kept for callers that imported the original process deadline.
PING_TIMEOUT = PROCESS_TIMEOUT
WEB_ROOT = Path(__file__).resolve().parent / "web"
DEFAULT_TARGETS_PATH = Path(__file__).resolve().parent / "targets.json"
DEFAULT_HOSTNAMES = {server[0]: server[3] for server in SERVERS}


def validate_target(hostname):
    """Accept one DNS name or literal IP address, never a URL or option."""
    if not isinstance(hostname, str) or not hostname or len(hostname) > 253:
        raise ValueError("Target must be a hostname or IP address of 1 to 253 characters.")
    if any(char.isspace() or ord(char) < 32 or ord(char) == 127 for char in hostname):
        raise ValueError("Target cannot contain whitespace or control characters.")
    try:
        # Scoped addresses are interface-specific, not portable region targets.
        if "%" not in hostname:
            ipaddress.ip_address(hostname)
            return hostname
    except ValueError:
        pass
    labels = (hostname[:-1] if hostname.endswith(".") else hostname).split(".")
    if hostname.startswith("-") or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in labels):
        raise ValueError("Enter a DNS hostname or IP address, without a URL, port, or command options.")
    return hostname


def load_target_overrides(path):
    path = Path(path)
    try:
        values = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(values, dict):
            raise ValueError("the file must contain a JSON object mapping region IDs to targets")
        for region_id, hostname in values.items():
            if region_id not in DEFAULT_HOSTNAMES:
                raise ValueError("unknown region ID {!r}".format(region_id))
            validate_target(hostname)
        return values, None
    except FileNotFoundError:
        return {}, None
    except (OSError, UnicodeError, ValueError) as exc:
        return {}, "Could not load targets from {}: {}. Default targets are in use.".format(path, exc)


def save_target_overrides(path, values):
    """Replace the whole JSON file atomically, leaving the prior file on failure."""
    path = Path(path)
    temporary_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".{}-".format(path.name), suffix=".tmp", delete=False) as target:
            temporary_path = target.name
            json.dump(values, target, indent=2, sort_keys=True)
            target.write("\n")
            target.flush()
            os.fsync(target.fileno())
        os.replace(temporary_path, path)
    except OSError as exc:
        raise ValueError("Could not save targets to {}: {}. Check folder permissions.".format(path, exc)) from exc
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass


@dataclass(frozen=True)
class PingResult:
    ms: Optional[float]
    status: str
    error: Optional[str] = None
    stdout: str = ""
    stderr: str = ""
    command: tuple = ()
    returncode: Optional[int] = None
    elapsed_seconds: Optional[float] = None
    process_timed_out: bool = False


def parse_ping_time(output):
    """Read a reply's RTT, including localized Windows reply lines.

    Windows keeps the TTL marker across its translated reply messages. POSIX
    ping is run in the C locale. A reply reported as <1 ms uses its stated
    upper bound (1 ms); no latency is inferred from the round-trip summary.
    """
    for line in output.splitlines():
        if not (re.search(r"\bttl[=\s]", line, re.IGNORECASE)
                or re.search(r"\btime\s*[=<]", line, re.IGNORECASE)):
            continue
        matches = re.findall(r"[=<]\s*(\d+(?:[.,]\d+)?)\s*(?:ms|мс)\b", line, re.IGNORECASE)
        if matches:
            value = float(matches[-1].replace(",", "."))
            if math.isfinite(value) and value >= 0:
                return value
    return None


def ping_command(executable, hostname, system=None):
    system = system or platform.system()
    timeout_ms = str(int(REPLY_TIMEOUT * 1000))
    try:
        ipv6 = ipaddress.ip_address(hostname).version == 6
    except ValueError:
        ipv6 = False
    family_flag = "-6" if ipv6 else "-4"
    if system == "Windows":
        return [executable, family_flag, "-n", "1", "-w", timeout_ms, hostname]
    if system in ("Darwin", "FreeBSD", "OpenBSD", "NetBSD"):
        if ipv6:
            executable = shutil.which("ping6") or str(Path(executable).with_name("ping6"))
        return [executable, "-n", "-c", "1", "-W", timeout_ms, hostname]
    return [executable, family_flag, "-n", "-c", "1", "-W", str(int(REPLY_TIMEOUT)), hostname]


def decode_ping_output(value, system=None):
    if isinstance(value, str):
        return value
    system = system or platform.system()
    # ping.exe writes using the Windows OEM codepage rather than UTF-8.
    encoding = "oem" if system == "Windows" else "utf-8"
    try:
        return (value or b"").decode(encoding, errors="replace")
    except LookupError:
        return (value or b"").decode(locale.getpreferredencoding(False), errors="replace")


class PingRunner:
    method = "icmp"
    tcp_port = None

    def __init__(self):
        self.executable = shutil.which("ping")
        self.available = self.executable is not None
        self.message = None if self.available else (
            "System ping was not found. Install your system's ping utility "
            "(for example, iputils-ping on Debian/Ubuntu), then restart this app."
        )
        self.system = platform.system()

    def probe(self, hostname):
        if not self.available:
            return PingResult(None, "error", self.message)
        env = os.environ.copy()
        env.update({"LC_ALL": "C", "LANG": "C", "LANGUAGE": "C"})
        options = {}
        if self.system == "Windows":
            options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        command = ping_command(self.executable, hostname, self.system)
        started = time.monotonic()
        process_timed_out = False
        returncode = None
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=PROCESS_TIMEOUT, shell=False, env=env, **options
            )
            output = decode_ping_output(completed.stdout, self.system)
            errors = decode_ping_output(completed.stderr, self.system)
            returncode = completed.returncode
        except subprocess.TimeoutExpired as exc:
            # subprocess.run kills and reaps the child; its captured reply or
            # failure still matters, even if DNS/startup exceeded the budget.
            output = decode_ping_output(exc.output, self.system)
            errors = decode_ping_output(exc.stderr, self.system)
            process_timed_out = True
        except OSError as exc:
            return PingResult(None, "error", "Could not run system ping: {}".format(exc),
                              command=tuple(command), elapsed_seconds=time.monotonic() - started)
        details = {
            "stdout": output, "stderr": errors, "command": tuple(command),
            "returncode": returncode, "elapsed_seconds": time.monotonic() - started,
            "process_timed_out": process_timed_out,
        }

        def result(ms, status, error=None):
            return PingResult(ms, status, error, **details)

        ms = parse_ping_time(output)
        if ms is not None:
            return result(ms, "online")
        text = (errors.strip() or output.strip())
        # Linux/macOS return 1/2 for no replies; Windows can return 0 for a
        # destination-unreachable response. Only an actual RTT counts as a reply.
        error_markers = (
            "unknown host", "name or service not known", "could not find host",
            "cannot resolve", "temporary failure in name resolution",
            "permission denied", "operation not permitted", "invalid option",
            "general failure", "socket: ",
        )
        if errors.strip() or any(marker in text.lower() for marker in error_markers):
            detail = " ".join(text.split())[:240]
            return result(None, "error", detail or "System ping failed.")
        if process_timed_out:
            # A reply timeout and a killed process are different events. The
            # latter might still be resolving DNS and establishes no packet loss.
            packet_evidence = (re.search(r"\b[1-9]\d*\s+packets? transmitted\b", output)
                               or re.search(r"\bicmp_seq[=\s]", output)
                               or (self.system == "Windows" and re.search(r"\(\s*\d+\s*%", output)))
            if not packet_evidence:
                return result(None, "error", "System ping did not finish within 8 seconds. "
                              "No transmitted packet was confirmed; check DNS and the diagnostic output.")
            return result(None, "timeout", "System ping exceeded its process deadline after transmitting a packet.")
        # Localized Windows DNS/process failures have no packet-loss summary.
        # Its translated packet summary still includes a numeric percentage.
        if self.system == "Windows" and not re.search(r"\(\s*\d+\s*%", output):
            detail = " ".join(text.split())[:240]
            return result(None, "error", detail or "System ping failed.")
        if returncode not in (0, 1, 2):
            return result(None, "error", "System ping exited with code {}.".format(returncode))
        return result(None, "timeout", "No ICMP reply within 2 seconds. This can also mean ICMP is filtered.")

    def diagnose(self, target_overrides=None, selected_server=None):
        """Run fixed comparison probes and retain evidence without changing stats."""
        target_overrides = target_overrides or {}
        targets = [("127.0.0.1", "This computer", "loopback"),
                   ("google.com", "Internet reference (Google)", "reference")]
        targets.extend((target_overrides.get(region_id, host), name, "server")
                       for region_id, name, _, host in SERVERS
                       if selected_server is None or region_id == selected_server)

        def check(target):
            hostname, name, kind = target
            try:
                value = self.probe(hostname)
            except Exception as exc:
                value = PingResult(None, "error", "Diagnostic probe failed: {}".format(exc)[:240])
            return {"hostname": hostname, "name": name, "kind": kind,
                    "status": value.status, "ms": value.ms, "error": value.error,
                    "command": list(value.command), "stdout": value.stdout,
                    "stderr": value.stderr, "returncode": value.returncode,
                    "elapsed_seconds": value.elapsed_seconds,
                    "process_timed_out": value.process_timed_out}

        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            checks = list(pool.map(check, targets))
        loopback, reference = checks[:2]
        servers = checks[2:]
        replies = sum(item["status"] == "online" for item in servers)
        errors = sum(item["status"] == "error" for item in servers)
        if not self.available:
            title, message = "System ping is unavailable", self.message
        elif loopback["status"] != "online":
            title = "Local ICMP check failed"
            message = ("Even 127.0.0.1 did not produce a readable reply. Check the local ping command, "
                       "its permissions, and the output below before interpreting server packet loss.")
        elif replies:
            title = "{} of {} Brawlhalla regions replied".format(replies, len(servers))
            message = ("These are ICMP measurements from the computer running pinger.py. "
                       "Any missing replies may reflect filtering or a route issue; compare the raw output below.")
        elif errors:
            title = "Server checks could not complete"
            message = ("{} of {} server checks reported command or DNS errors. Read their output below; "
                       "these errors do not establish packet loss or server downtime.").format(errors, len(servers))
        elif reference["status"] != "online":
            title = "No external ICMP replies"
            message = ("Loopback replied, but the Internet reference and all Brawlhalla hosts did not. "
                       "ICMP may be filtered by this computer or its network. This does not establish that the game servers are down.")
        else:
            title = "Reference replied; Brawlhalla hosts did not"
            message = ("Local and Internet reference checks replied. The Brawlhalla hosts did not answer ICMP on this route; "
                       "filtering or a route issue is possible. This does not establish in-game availability.")
        return {"system": self.system, "method": "icmp", "tcp_port": None,
                "selected_server": selected_server,
                "created_at": time.time(), "executable": self.executable,
                "checks": checks, "summary": {"title": title, "message": message}}


class TCPRunner:
    """Measure a TCP connect, excluding DNS, TLS, and HTTP from its duration."""

    method = "tcp"
    available = True
    message = None
    executable = None

    def __init__(self, port=443):
        if type(port) is not int or port not in TCP_PORTS:
            raise ValueError("TCP port must be 80 or 443.")
        self.tcp_port = port
        self.system = platform.system()
        self._dns_cache = OrderedDict()
        self._dns_lock = threading.Lock()

    def _resolve(self, hostname):
        try:
            literal = ipaddress.ip_address(hostname)
        except ValueError:
            literal = None
        if literal is not None:
            family = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
            return family, str(literal)
        # Match the ICMP runner's IPv4 preference for hostnames. DNS work is
        # outside the connection timer, and successful and failed lookups have
        # the same bounded lifetime. Never hold the cache lock across DNS I/O.
        now = time.monotonic()
        with self._dns_lock:
            cached = self._dns_cache.get(hostname)
            if cached is not None and cached[0] > now:
                self._dns_cache.move_to_end(hostname)
                if cached[2] is not None:
                    raise socket.gaierror(cached[2])
                return cached[1]
            self._dns_cache.pop(hostname, None)
        address, error = None, None
        try:
            answers = socket.getaddrinfo(hostname, None, socket.AF_INET,
                                         socket.SOCK_STREAM, socket.IPPROTO_TCP)
            if not answers:
                raise socket.gaierror("No IPv4 address returned.")
            address = (answers[0][0], answers[0][4][0])
        except socket.gaierror as exc:
            error = str(exc)
        with self._dns_lock:
            self._dns_cache[hostname] = (time.monotonic() + DNS_CACHE_TTL, address, error)
            self._dns_cache.move_to_end(hostname)
            while len(self._dns_cache) > DNS_CACHE_LIMIT:
                self._dns_cache.popitem(last=False)
        if error is not None:
            raise socket.gaierror(error)
        return address

    def probe(self, hostname):
        command = ("TCP", hostname, str(self.tcp_port))
        started = time.monotonic()
        details = {"command": command}
        connection = None
        connection_attempted = False
        try:
            family, address = self._resolve(hostname)
            details["stdout"] = "Resolved {} to {}; TCP port {}.".format(
                hostname, address, self.tcp_port)
            connection = socket.socket(family, socket.SOCK_STREAM, socket.IPPROTO_TCP)
            connection.settimeout(REPLY_TIMEOUT)
            destination = (address, self.tcp_port, 0, 0) if family == socket.AF_INET6 else (address, self.tcp_port)
            connect_started = time.perf_counter()
            connection_attempted = True
            connection.connect(destination)
            ms = (time.perf_counter() - connect_started) * 1000.0
            details["stdout"] += " Connection established."
            return PingResult(ms, "online", elapsed_seconds=time.monotonic() - started, **details)
        except socket.gaierror as exc:
            message = "DNS resolution failed for {}: {}".format(hostname, exc)
            status = "error"
        except (socket.timeout, TimeoutError) as exc:
            if connection_attempted:
                message = "No TCP connection to port {} within 2 seconds; filtering or a route issue is possible.".format(self.tcp_port)
                status = "timeout"
            else:
                message = "DNS or local socket setup timed out before a TCP connection attempt: {}".format(exc)
                status = "error"
        except OSError as exc:
            if connection_attempted and exc.errno == errno.ECONNREFUSED:
                message = "TCP port {} refused the connection; the host or a firewall responded.".format(self.tcp_port)
                status = "refused"
            elif connection_attempted and exc.errno == errno.ETIMEDOUT:
                message = "TCP connection to port {} timed out; filtering or a route issue is possible.".format(self.tcp_port)
                status = "timeout"
            else:
                message = "TCP probe could not run: {}".format(exc)
                status = "error"
        finally:
            if connection is not None:
                connection.close()
        details["stderr"] = message
        return PingResult(None, status, message, elapsed_seconds=time.monotonic() - started, **details)

    def diagnose(self, target_overrides=None, selected_server=None):
        target_overrides = target_overrides or {}
        # A closed localhost:443 is normal; it is not a TCP capability failure.
        targets = [("google.com", "Internet reference (Google)", "reference")]
        targets.extend((target_overrides.get(region_id, host), name, "server")
                       for region_id, name, _, host in SERVERS
                       if selected_server is None or region_id == selected_server)

        def check(target):
            hostname, name, kind = target
            try:
                value = self.probe(hostname)
            except Exception as exc:
                value = PingResult(None, "error", "Diagnostic probe failed: {}".format(exc)[:240])
            return {"hostname": hostname, "name": name, "kind": kind,
                    "method": "tcp", "tcp_port": self.tcp_port,
                    "status": value.status, "ms": value.ms, "error": value.error,
                    "command": list(value.command), "stdout": value.stdout,
                    "stderr": value.stderr, "returncode": value.returncode,
                    "elapsed_seconds": value.elapsed_seconds,
                    "process_timed_out": value.process_timed_out}

        with ThreadPoolExecutor(max_workers=len(targets)) as pool:
            checks = list(pool.map(check, targets))
        servers = checks[1:]
        replies = sum(item["status"] == "online" for item in servers)
        errors = sum(item["status"] == "error" for item in servers)
        refused = sum(item["status"] == "refused" for item in servers)
        if replies:
            title = "{} of {} Brawlhalla targets accepted TCP connections".format(replies, len(servers))
            message = ("TCP port {} connect latency measures a handshake from the computer running pinger.py. "
                       "It does not measure Brawlhalla gameplay latency or establish match-server availability.").format(self.tcp_port)
        elif errors:
            title = "Server TCP checks could not complete"
            message = ("{} of {} checks reported DNS or local socket errors. These errors are excluded from "
                       "failed-connection statistics; inspect the evidence below.").format(errors, len(servers))
        elif refused:
            title = "TCP connections were refused or timed out"
            message = ("{} of {} targets returned connection refusals, which means a host or firewall responded. "
                       "Try the other TCP port; neither refusal nor timeout establishes game-server downtime.").format(refused, len(servers))
        else:
            title = "No Brawlhalla TCP connections completed"
            message = ("The selected port may be filtered or unavailable on this route. "
                       "This does not establish that the game servers are down.")
        return {"system": self.system, "method": "tcp", "tcp_port": self.tcp_port,
                "selected_server": selected_server,
                "created_at": time.time(), "executable": None,
                "checks": checks, "summary": {"title": title, "message": message}}


@dataclass
class ServerStats:
    id: str
    name: str
    city: str
    hostname: str
    sent: int = 0
    received: int = 0
    latest_ms: Optional[float] = None
    min_ms: Optional[float] = None
    max_ms: Optional[float] = None
    total_ms: float = 0.0
    jitter_total: float = 0.0
    jitter_count: int = 0
    previous_ms: Optional[float] = None
    history: Deque = field(default_factory=lambda: deque(maxlen=HISTORY_LIMIT))
    status: str = "idle"
    settled_status: str = "idle"
    error: Optional[str] = None

    def record(self, result, timestamp):
        self.status = self.settled_status = result.status
        self.error = result.error
        # A failed process or DNS lookup does not establish a transmitted
        # packet. Show the error without inventing packet loss or RTT history.
        if result.status == "error":
            return
        self.sent += 1
        self.latest_ms = result.ms
        self.history.append({"timestamp": timestamp, "ms": result.ms})
        if result.ms is not None:
            self.received += 1
            self.total_ms += result.ms
            self.min_ms = result.ms if self.min_ms is None else min(self.min_ms, result.ms)
            self.max_ms = result.ms if self.max_ms is None else max(self.max_ms, result.ms)
            if self.previous_ms is not None:
                self.jitter_total += abs(result.ms - self.previous_ms)
                self.jitter_count += 1
            self.previous_ms = result.ms

    def snapshot(self):
        return {
            "id": self.id, "name": self.name, "city": self.city, "hostname": self.hostname,
            "default_hostname": DEFAULT_HOSTNAMES[self.id],
            "is_custom": self.hostname != DEFAULT_HOSTNAMES[self.id],
            "sent": self.sent, "received": self.received, "lost": self.sent - self.received,
            "loss": (self.sent - self.received) * 100.0 / self.sent if self.sent else 0.0,
            "latest_ms": self.latest_ms,
            "avg_ms": self.total_ms / self.received if self.received else None,
            "min_ms": self.min_ms, "max_ms": self.max_ms,
            "jitter_ms": self.jitter_total / self.jitter_count if self.jitter_count else None,
            "history": list(self.history), "status": self.status, "error": self.error,
        }


class Monitor:
    """Independent workers probe only enabled hosts, with one probe in flight each."""

    def __init__(self, runner=None, autostart=True, launch_workers=True,
                 targets_path=DEFAULT_TARGETS_PATH, method=None, tcp_port=443):
        # Injected runners keep the original ICMP testing API. The standalone
        # app uses TCP 443 by default, without requiring a system ping utility.
        selected_method = method or getattr(runner, "method", "icmp" if runner is not None else "tcp")
        if selected_method not in ("tcp", "icmp"):
            raise ValueError("Method must be tcp or icmp.")
        if type(tcp_port) is not int or tcp_port not in TCP_PORTS:
            raise ValueError("TCP port must be 80 or 443.")
        self.runner = runner if runner is not None else (TCPRunner(tcp_port) if selected_method == "tcp" else PingRunner())
        self.method = selected_method
        self.tcp_port = getattr(self.runner, "tcp_port", None) or tcp_port
        self.targets_path = Path(targets_path)
        self.target_overrides, self.targets_config_error = load_target_overrides(self.targets_path)
        self.condition = threading.Condition()
        self.interval = 2
        self.started_at = time.time()
        self.last_update = None
        self.running = bool(autostart and self.runner.available)
        self.generation = 0
        self.selected_server = None
        self.selection_generations = [0] * len(SERVERS)
        self.closed = False
        self.servers = self._new_stats()
        self.workers = []
        if launch_workers:
            for index in range(len(self.servers)):
                worker = threading.Thread(target=self._worker, args=(index,), daemon=True,
                                          name="ping-{}".format(self.servers[index].id))
                self.workers.append(worker)
                worker.start()

    def _new_stats(self):
        return [ServerStats(region_id, name, city, self.target_overrides.get(region_id, hostname))
                for region_id, name, city, hostname in SERVERS]

    def set_target(self, region_id, hostname):
        if not isinstance(region_id, str) or region_id not in DEFAULT_HOSTNAMES:
            raise ValueError("Unknown region ID. Choose one of: {}.".format(
                ", ".join(DEFAULT_HOSTNAMES)))
        if hostname != "":
            validate_target(hostname)
        with self.condition:
            overrides = dict(self.target_overrides)
            if hostname == "" or hostname == DEFAULT_HOSTNAMES[region_id]:
                overrides.pop(region_id, None)
            else:
                overrides[region_id] = hostname
            save_target_overrides(self.targets_path, overrides)
            self.target_overrides = overrides
            self.targets_config_error = None
            index = next(index for index, item in enumerate(SERVERS) if item[0] == region_id)
            _, name, city, default_hostname = SERVERS[index]
            # Replacing just this object also invalidates this region's in-flight
            # result. Other workers and their sample histories remain valid.
            self.servers[index] = ServerStats(region_id, name, city,
                                             overrides.get(region_id, default_hostname))
            self.condition.notify_all()
            return self.snapshot()

    def diagnose(self):
        with self.condition:
            overrides = dict(self.target_overrides)
            config_error = self.targets_config_error
            runner = self.runner
            selected_server = self.selected_server
        report = (runner.diagnose(overrides) if selected_server is None else
                  runner.diagnose(overrides, selected_server=selected_server))
        report["selected_server"] = selected_server
        report["targets_config_error"] = config_error
        if config_error:
            report["summary"] = {"title": "Target configuration could not be loaded",
                                 "message": config_error}
        return report

    def _worker(self, index):
        next_due = 0.0
        last_attempt = None
        observed_generation = -1
        observed_selection_generation = -1
        observed_server = None
        while True:
            with self.condition:
                if self.closed:
                    return
                server = self.servers[index]
                if not self.running or (self.selected_server is not None and self.selected_server != server.id):
                    self.condition.wait()
                    continue
                if (observed_generation != self.generation or observed_server is not server
                        or observed_selection_generation != self.selection_generations[index]):
                    observed_generation = self.generation
                    observed_selection_generation = self.selection_generations[index]
                    observed_server = server
                    next_due = 0.0
                    last_attempt = None
                elif last_attempt is not None:
                    next_due = last_attempt + self.interval
                delay = next_due - time.monotonic()
                if delay > 0:
                    self.condition.wait(delay)
                    continue
                generation = self.generation
                selection_generation = self.selection_generations[index]
                if server.settled_status == "idle":
                    server.status = "pending"
                attempt_started = time.monotonic()
                last_attempt = attempt_started
                hostname = server.hostname
                runner = self.runner
            try:
                result = runner.probe(hostname)
            except Exception as exc:
                # A platform-specific process failure must not kill a worker.
                result = PingResult(None, "error", "Probe failed: {}".format(exc)[:240])
            with self.condition:
                if self.closed:
                    return
                if (self.running and self.generation == generation and self.servers[index] is server
                        and self.selection_generations[index] == selection_generation
                        and (self.selected_server is None or self.selected_server == server.id)):
                    timestamp = time.time()
                    self.servers[index].record(result, timestamp)
                    self.last_update = timestamp
                next_due = attempt_started + self.interval

    def snapshot(self):
        with self.condition:
            return {
                "running": self.running, "interval": self.interval,
                "selected_server": self.selected_server,
                "started_at": self.started_at,
                "uptime_seconds": max(0.0, time.time() - self.started_at),
                "last_update": self.last_update,
                "method": self.method, "tcp_port": self.tcp_port,
                "capability": {"available": self.runner.available, "message": self.runner.message},
                "targets_config_error": self.targets_config_error,
                "measurement_source": {"system": platform.system(), "method": self.method,
                                       "tcp_port": self.tcp_port if self.method == "tcp" else None,
                                       "description": (
                                           "TCP port {} connect latency from the computer running pinger.py; excludes DNS, TLS, and HTTP".format(self.tcp_port)
                                           if self.method == "tcp" else
                                           "System ICMP from the computer running pinger.py")},
                "servers": [dict(server.snapshot(), enabled=(self.selected_server is None or self.selected_server == server.id))
                            for server in self.servers],
            }

    def control(self, action, seconds=None, region_id=None, hostname=None, method=None, port=None):
        if action == "target":
            return self.set_target(region_id, hostname)
        if action not in ("start", "stop", "reset", "interval", "method", "select"):
            raise ValueError("Unknown action. Use start, stop, reset, interval, target, method, or select.")
        if action == "select" and (not isinstance(region_id, str)
                                   or (region_id != "all" and region_id not in DEFAULT_HOSTNAMES)):
            raise ValueError("Unknown region ID. Choose all or one of: {}.".format(
                ", ".join(DEFAULT_HOSTNAMES)))
        if action == "interval" and (type(seconds) is not int or seconds not in INTERVALS):
            raise ValueError("Interval must be one of 1, 2, 5, or 10 seconds.")
        if action == "method":
            if method not in ("tcp", "icmp"):
                raise ValueError("Method must be tcp or icmp.")
            if port is not None and (type(port) is not int or port not in TCP_PORTS):
                raise ValueError("TCP port must be 80 or 443.")
        with self.condition:
            if action == "select":
                selection = None if region_id == "all" else region_id
                if selection == self.selected_server:
                    return self.snapshot()
                for index, server in enumerate(self.servers):
                    was_enabled = self.selected_server is None or self.selected_server == server.id
                    enabled = selection is None or selection == server.id
                    if was_enabled != enabled:
                        # Invalidate probes across deselect/reselect without
                        # disturbing a region that stays selected throughout.
                        self.selection_generations[index] += 1
                    if not enabled:
                        server.status = server.settled_status
                self.selected_server = selection
            elif action == "start":
                if not self.running and self.runner.available:
                    self.running = True
                    self.generation += 1
            elif action == "stop":
                self.running = False
                self.generation += 1
                for server in self.servers:
                    server.status = server.settled_status
            elif action == "reset":
                self.generation += 1
                self.servers = self._new_stats()
                self.last_update = None
                self.started_at = time.time()
            elif action == "interval":
                self.interval = seconds
                # Keep the current probes, and wake workers to recalculate wait.
                # The generation stays stable, so a timing change loses no data.
            elif action == "method":
                selected_port = 443 if port is None else port
                if method != self.method or (method == "tcp" and selected_port != self.tcp_port):
                    self.runner = TCPRunner(selected_port) if method == "tcp" else PingRunner()
                    self.method = method
                    self.tcp_port = selected_port
                    self.generation += 1
                    self.servers = self._new_stats()
                    self.last_update = None
                    self.started_at = time.time()
                    # Preserve pause; an unavailable ICMP runner cannot run.
                    self.running = self.running and self.runner.available
            self.condition.notify_all()
            return self.snapshot()

    def close(self):
        with self.condition:
            self.closed = True
            self.running = False
            self.generation += 1
            self.condition.notify_all()
        deadline = time.monotonic() + PING_TIMEOUT + 0.5
        for worker in self.workers:
            worker.join(max(0.0, deadline - time.monotonic()))


class PingerHTTPServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, address, monitor, web_root=WEB_ROOT):
        self.monitor = monitor
        self.diagnostic_lock = threading.Lock()
        self.web_root = Path(web_root).resolve()
        super().__init__(address, PingerHandler)


class PingerHandler(BaseHTTPRequestHandler):
    server_version = "BrawlhallaPinger/1.4"

    def log_message(self, format_string, *args):
        # Routine polling is intentionally quiet; startup and errors use stderr.
        return

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        super().end_headers()

    def _local_authority(self, value, origin=False):
        try:
            parsed = urlsplit(value if origin else "http://" + value)
            port = parsed.port or (80 if parsed.scheme == "http" else 443)
            return (parsed.scheme == "http" and parsed.hostname in ("127.0.0.1", "localhost", "::1")
                    and port == self.server.server_port and not parsed.username
                    and not parsed.password and parsed.path in ("", "/")
                    and not parsed.query and not parsed.fragment)
        except (ValueError, AttributeError):
            return False

    def _check_local(self):
        hosts = self.headers.get_all("Host", [])
        origins = self.headers.get_all("Origin", [])
        if len(hosts) != 1 or not self._local_authority(hosts[0]):
            self._json(403, {"error": "Only local requests are accepted."})
            return False
        if origins and (len(origins) != 1 or not self._local_authority(origins[0], origin=True)):
            self._json(403, {"error": "Cross-origin requests are not accepted."})
            return False
        if self.headers.get("Sec-Fetch-Site") == "cross-site":
            self._json(403, {"error": "Cross-site requests are not accepted."})
            return False
        return True

    def _json(self, code, payload):
        data = json.dumps(payload, allow_nan=False, separators=(",", ":")).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if not self._check_local():
            return
        path = urlsplit(self.path).path
        if path == "/api/status":
            self._json(200, self.server.monitor.snapshot())
            return
        if path == "/api/connections":
            from connections import get_connections
            self._json(200, get_connections())
            return
        if path.startswith("/api/"):
            self._json(404, {"error": "Unknown API endpoint."})
            return
        try:
            decoded = unquote(path)
            if "\x00" in decoded or "\\" in decoded:
                raise ValueError("Invalid path")
            relative = decoded.lstrip("/") or "index.html"
            target = (self.server.web_root / relative).resolve()
            target.relative_to(self.server.web_root)
            if not target.is_file():
                self._json(404, {"error": "File not found."})
                return
            data = target.read_bytes()
        except (OSError, ValueError):
            self._json(404, {"error": "File not found."})
            return
        content_type = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
        if content_type.startswith("text/") or content_type == "application/javascript":
            content_type += "; charset=utf-8"
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_POST(self):
        if not self._check_local():
            return
        path = urlsplit(self.path).path
        if path not in ("/api/control", "/api/diagnose"):
            self._json(404, {"error": "Unknown API endpoint."})
            return
        if self.headers.get("Transfer-Encoding"):
            self._json(400, {"error": "Chunked request bodies are not supported."})
            return
        lengths = self.headers.get_all("Content-Length", [])
        try:
            length = int(lengths[0]) if len(lengths) == 1 else -1
        except ValueError:
            length = -1
        if length < 0 or length > 1024:
            self._json(413 if length > 1024 else 400, {"error": "Invalid request body size (maximum 1024 bytes)."})
            return
        if self.headers.get_content_type() != "application/json":
            self._json(415, {"error": "Use Content-Type: application/json."})
            return
        self.connection.settimeout(5)
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("Request body must be a JSON object.")
            if path == "/api/diagnose":
                if body:
                    raise ValueError("Diagnostics accepts only an empty JSON object; hosts are fixed.")
                if not self.server.diagnostic_lock.acquire(blocking=False):
                    self._json(409, {"error": "A diagnostic run is already in progress."})
                    return
                try:
                    result = self.server.monitor.diagnose()
                finally:
                    self.server.diagnostic_lock.release()
            else:
                result = self.server.monitor.control(body.get("action"), body.get("seconds"),
                                                     region_id=body.get("id"), hostname=body.get("hostname"),
                                                     method=body.get("method"), port=body.get("port"))
        except (ValueError, UnicodeDecodeError, TimeoutError) as exc:
            self._json(400, {"error": str(exc) or "Invalid JSON request."})
            return
        self._json(200, result)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Measure all nine Brawlhalla regions in a local dashboard.")
    parser.add_argument("--port", type=int, default=8765, help="local HTTP port (default: 8765)")
    parser.add_argument("--no-browser", action="store_true", help="do not automatically open the dashboard")
    parser.add_argument("--method", choices=("tcp", "icmp"), default="tcp", help="measurement method (default: tcp)")
    parser.add_argument("--tcp-port", type=int, choices=TCP_PORTS, default=443, help="TCP port for connect latency (default: 443)")
    parser.add_argument("--diagnose", action="store_true", help="print diagnostics using the selected method, then exit")
    parser.add_argument("--targets", type=Path, default=DEFAULT_TARGETS_PATH,
                        help="region target overrides JSON (default: targets.json beside pinger.py)")
    args = parser.parse_args(argv)
    if args.diagnose:
        overrides, config_error = load_target_overrides(args.targets)
        runner = TCPRunner(args.tcp_port) if args.method == "tcp" else PingRunner()
        report = runner.diagnose(overrides)
        report["targets_config_error"] = config_error
        if config_error:
            report["summary"] = {"title": "Target configuration could not be loaded", "message": config_error}
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    monitor = Monitor(targets_path=args.targets, method=args.method, tcp_port=args.tcp_port)
    try:
        server = PingerHTTPServer(("127.0.0.1", args.port), monitor)
    except OSError as exc:
        monitor.close()
        print("Could not start the dashboard on port {}: {}".format(args.port, exc), file=sys.stderr)
        print("Try another port with --port 8766.", file=sys.stderr)
        return 1
    url = "http://127.0.0.1:{}/".format(server.server_port)
    print("Brawlhalla Pinger is running at {}".format(url), flush=True)
    print("Press Ctrl+C to quit.", flush=True)
    if monitor.runner.message:
        print(monitor.runner.message, file=sys.stderr, flush=True)
    if not args.no_browser:
        try:
            webbrowser.open(url)
        except Exception:
            print("Open the dashboard URL above in your browser.", file=sys.stderr)
    try:
        server.serve_forever(poll_interval=0.2)
    except KeyboardInterrupt:
        print("\nStopping Brawlhalla Pinger.", flush=True)
    finally:
        server.server_close()
        monitor.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
