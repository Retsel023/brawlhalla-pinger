#!/usr/bin/env python3
"""Find candidate remote peers of the current user's Brawlhalla processes."""

import ipaddress
import json
import os
from pathlib import Path
import platform
import re
import sys


GAME_NAMES = frozenset(("brawlhalla.exe", "brawlhallagame.exe", "brawlhalla"))
WINE_NAMES = frozenset(("wine", "wine64", "wine-preloader", "wine64-preloader"))
SOCKET_LINK = re.compile(r"socket:\[(\d+)\]\Z")


def _basename(value):
    return value.replace("\\", "/").rsplit("/", 1)[-1]


def _issue(issues, operation, exc):
    if isinstance(exc, (FileNotFoundError, ProcessLookupError)):
        return
    detail = "permission denied" if isinstance(exc, PermissionError) else (exc.strerror or "unavailable")
    message = "Could not {} ({}).".format(operation, detail)
    if message not in issues:
        issues.append(message)


def _read(path, issues, operation, binary=False):
    try:
        if binary:
            with path.open("rb") as source:
                return source.read(65536)
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        _issue(issues, operation, exc)
        return b"" if binary else ""


def _game_name(process, issues):
    comm = _read(process / "comm", issues, "read a process name").strip()
    if comm.casefold() in GAME_NAMES:
        return comm
    executable = ""
    try:
        executable = _basename(os.readlink(process / "exe").removesuffix(" (deleted)"))
    except OSError as exc:
        _issue(issues, "read a process executable", exc)
    if executable.casefold() in GAME_NAMES:
        return executable
    raw = _read(process / "cmdline", issues, "read a process command line", binary=True)
    arguments = [part.decode("utf-8", errors="replace") for part in raw.split(b"\0") if part]
    if not arguments:
        return None
    program = _basename(arguments[0])
    if program.casefold() in GAME_NAMES:
        return program
    # Only Wine's program argument is relevant, never arbitrary search/script arguments.
    if program.casefold() in WINE_NAMES or executable.casefold() in WINE_NAMES:
        candidates = arguments[1:]
        if candidates and candidates[0] == "--":
            candidates = candidates[1:]
        if candidates:
            candidate = _basename(candidates[0])
            if candidate.casefold() in GAME_NAMES:
                return candidate
    return None


def _socket_inodes(process, issues):
    inodes = set()
    try:
        descriptors = list((process / "fd").iterdir())
    except OSError as exc:
        _issue(issues, "read Brawlhalla socket descriptors", exc)
        return inodes
    for descriptor in descriptors:
        try:
            match = SOCKET_LINK.fullmatch(os.readlink(descriptor))
            if match:
                inodes.add(match.group(1))
        except OSError as exc:
            _issue(issues, "read a Brawlhalla socket descriptor", exc)
    return inodes


def _remote_address(value, ipv6=False, byteorder=None):
    address, port = value.split(":", 1)
    width = 32 if ipv6 else 8
    if len(address) != width or not re.fullmatch(r"[0-9a-fA-F]+", address):
        raise ValueError("Invalid /proc address")
    byteorder = byteorder or sys.byteorder
    # Linux prints each address word in host byte order, including IPv6's four words.
    packed = b"".join(int(address[index:index + 8], 16).to_bytes(4, byteorder)
                      for index in range(0, width, 8))
    decoded = ipaddress.ip_address(packed)
    if isinstance(decoded, ipaddress.IPv6Address) and decoded.ipv4_mapped is not None:
        decoded = decoded.ipv4_mapped
    port = int(port, 16)
    if decoded.is_unspecified or not 1 <= port <= 65535:
        return None
    return str(decoded), port


def _connections(process, name, pid, inodes, uid, issues):
    found = []
    if not inodes:
        return found
    for table in ("tcp", "udp", "tcp6", "udp6"):
        content = _read(process / "net" / table, issues, "read Brawlhalla socket tables")
        for line in content.splitlines()[1:]:
            fields = line.split()
            if len(fields) < 10 or fields[9] not in inodes:
                continue
            try:
                if int(fields[7]) != uid:
                    continue
                peer = _remote_address(fields[2], ipv6=table.endswith("6"))
            except (ValueError, OverflowError):
                continue
            if peer is None:
                continue
            ip, port = peer
            found.append({"ip": ip, "port": port, "protocol": table[:3],
                          "process": name, "pid": pid,
                          "game_port": 23000 <= port <= 24000 or 33000 <= port <= 34000})
    return found


def get_connections(procroot="/proc", system=None, uid=None):
    """Read /proc without opening sockets, inspecting memory, or requiring root."""
    system = system or platform.system()
    result = {"supported": system == "Linux", "system": system,
              "processes": [], "connections": [], "message": ""}
    if system != "Linux":
        result["message"] = "Passive game connection discovery is currently supported on Linux only."
        return result
    uid = os.getuid() if uid is None else uid
    issues = []
    try:
        processes = sorted((path for path in Path(procroot).iterdir() if path.name.isdigit()),
                           key=lambda path: int(path.name))
    except OSError as exc:
        _issue(issues, "inspect Linux /proc", exc)
        result["message"] = " ".join(issues) or "Linux /proc is unavailable."
        return result
    peers = {}
    for process in processes:
        try:
            if process.stat().st_uid != uid:
                continue
        except OSError as exc:
            _issue(issues, "inspect a process owned by your user", exc)
            continue
        name = _game_name(process, issues)
        if name is None:
            continue
        pid = int(process.name)
        result["processes"].append({"pid": pid, "name": name})
        inodes = _socket_inodes(process, issues)
        for connection in _connections(process, name, pid, inodes, uid, issues):
            key = (connection["ip"], connection["port"], connection["protocol"])
            peers.setdefault(key, connection)
    result["connections"] = sorted(peers.values(), key=lambda item: (
        not item["game_port"], item["protocol"] != "udp",
        ipaddress.ip_address(item["ip"]).version, int(ipaddress.ip_address(item["ip"])), item["port"]))
    if result["connections"]:
        message = ("Found {} candidate remote endpoints held by Brawlhalla. "
                   "Ports 23000–24000 and 33000–34000 are listed first. "
                   "Candidates can include login, Steam, or relay services; /proc alone cannot identify the active game server.").format(len(result["connections"]))
    elif result["processes"]:
        message = ("Brawlhalla is running, but no connected remote endpoints are visible. "
                   "Join an online match and check again. Unconnected UDP sockets do not expose their remote peer in /proc.")
    else:
        message = ("No Brawlhalla process was found for your Linux user. "
                   "Launch Brawlhalla and join an online match, then check again.")
    result["message"] = " ".join([message] + issues)
    return result


def main():
    print(json.dumps(get_connections(), ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
