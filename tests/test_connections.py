import contextlib
import io
import ipaddress
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
import unittest
from unittest.mock import patch

import connections


class ConnectionTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.proc = Path(self.temporary.name)
        self.uid = os.getuid()

    def process(self, pid=101, comm="Brawlhalla.exe", executable="/games/Brawlhalla.exe", arguments=None):
        process = self.proc / str(pid)
        process.mkdir()
        (process / "comm").write_text(comm + "\n", encoding="utf-8")
        if executable:
            (process / "exe").symlink_to(executable)
        if arguments is None:
            arguments = [executable or comm]
        (process / "cmdline").write_bytes(b"\0".join(arg.encode() for arg in arguments) + b"\0")
        (process / "fd").mkdir()
        (process / "net").mkdir()
        for table in ("tcp", "udp", "tcp6", "udp6"):
            (process / "net" / table).write_text("sl local_address rem_address st queues timer retrans uid timeout inode\n")
        return process

    def endpoint(self, ip, port):
        packed = ipaddress.ip_address(ip).packed
        address = "".join("{:08X}".format(int.from_bytes(packed[index:index + 4], sys.byteorder))
                          for index in range(0, len(packed), 4))
        return "{}:{:04X}".format(address, port)

    def add_socket(self, process, inode, ip, port, table="udp", uid=None, held=True):
        uid = self.uid if uid is None else uid
        if held:
            (process / "fd" / str(inode)).symlink_to("socket:[{}]".format(inode))
        row = ("0: 00000000:0000 {} 01 00000000:00000000 00:00000000 "
               "00000000 {} 0 {} 1 0000000000000000\n").format(self.endpoint(ip, port), uid, inode)
        with (process / "net" / table).open("a") as target:
            target.write(row)

    def discover(self, **options):
        return connections.get_connections(procroot=self.proc, system="Linux", **options)

    def test_unsupported_system_never_reads_proc(self):
        with patch.object(Path, "iterdir", side_effect=AssertionError("must not read /proc")):
            result = connections.get_connections(system="Windows")
        self.assertFalse(result["supported"])
        self.assertEqual(result["system"], "Windows")
        self.assertEqual(result["connections"], [])

    def test_no_game_explains_launch_and_online_match(self):
        self.process(comm="python3", executable="/usr/bin/python3", arguments=["python3", "/tmp/brawlhalla pinger/pinger.py"])
        result = self.discover()
        self.assertTrue(result["supported"])
        self.assertEqual(result["processes"], [])
        self.assertIn("Launch Brawlhalla and join an online match", result["message"])

    def test_exact_names_from_comm_executable_and_wine_arguments(self):
        self.process(pid=11, comm="BRAWLHALLA", executable="/unrecognized")
        self.process(pid=12, comm="BrawlhallaGame", executable="/games/BrawlhallaGame.exe (deleted)")
        self.process(pid=13, comm="wine", executable="/usr/bin/wine64", arguments=["wine64", "C:\\games\\Brawlhalla.exe"])
        self.process(pid=14, comm="wine", executable="/usr/bin/wine64-preloader", arguments=["Z:\\games\\BrawlhallaGame.exe"])
        self.process(pid=15, comm="wine", executable="/usr/bin/wine", arguments=["wine", "--", "/games/Brawlhalla.exe"])
        result = self.discover()
        self.assertEqual([item["pid"] for item in result["processes"]], [11, 12, 13, 14, 15])

    def test_substrings_script_names_and_arbitrary_arguments_are_not_games(self):
        for pid, arguments in enumerate((
            ["python3", "/games/Brawlhalla.py"],
            ["bash", "/games/Brawlhalla.sh"],
            ["rg", "Brawlhalla.exe"],
            ["python3", "/tools/pinger.py", "/games/Brawlhalla.exe"],
            ["/tools/Brawlhalla-pinger"],
            ["/games/Brawlhalla.exe.backup"],
        ), 20):
            self.process(pid=pid, comm="not-the-game", executable="/usr/bin/unknown", arguments=arguments)
        self.assertEqual(self.discover()["processes"], [])

    def test_only_held_same_uid_remote_sockets_are_reported_and_ports_prioritized(self):
        process = self.process()
        self.add_socket(process, 201, "203.0.113.3", 443, table="tcp")
        self.add_socket(process, 202, "198.51.100.8", 23000)
        self.add_socket(process, 203, "198.51.100.9", 34000)
        self.add_socket(process, 204, "192.0.2.4", 80, held=False)
        self.add_socket(process, 205, "192.0.2.5", 99, uid=self.uid + 1)
        self.add_socket(process, 206, "0.0.0.0", 0)
        self.add_socket(process, 207, "0.0.0.0", 23400)
        self.add_socket(process, 208, "192.0.2.6", 0)
        result = self.discover()
        self.assertEqual([(item["ip"], item["port"]) for item in result["connections"]],
                         [("198.51.100.8", 23000), ("198.51.100.9", 34000), ("203.0.113.3", 443)])
        self.assertEqual([item["game_port"] for item in result["connections"]], [True, True, False])
        self.assertEqual(result["connections"][0]["process"], "Brawlhalla.exe")
        self.assertIn("candidate", result["message"])
        self.assertIn("cannot identify the active game server", result["message"])

    def test_other_users_processes_are_skipped(self):
        self.process()
        result = self.discover(uid=self.uid + 1)
        self.assertEqual(result["processes"], [])

    def test_unrelated_process_socket_is_not_reported(self):
        self.process()
        other = self.process(pid=102, comm="browser", executable="/usr/bin/browser")
        self.add_socket(other, 201, "203.0.113.1", 23000)
        self.assertEqual(self.discover()["connections"], [])

    def test_deduplicates_peers_across_processes_but_keeps_protocol(self):
        for pid in (101, 102):
            process = self.process(pid=pid)
            self.add_socket(process, 201, "203.0.113.1", 23000)
            self.add_socket(process, 202, "203.0.113.1", 23000, table="tcp")
        result = self.discover()
        self.assertEqual(len(result["connections"]), 2)
        self.assertEqual({item["protocol"] for item in result["connections"]}, {"tcp", "udp"})
        self.assertEqual({item["pid"] for item in result["connections"]}, {101})

    def test_ipv6_and_mapped_ipv4_peers(self):
        process = self.process()
        self.add_socket(process, 201, "2001:db8::1234", 33000, table="udp6")
        self.add_socket(process, 202, "::ffff:192.0.2.2", 443, table="tcp6")
        self.add_socket(process, 203, "::", 23400, table="udp6")
        peers = self.discover()["connections"]
        self.assertEqual({item["ip"] for item in peers}, {"2001:db8::1234", "192.0.2.2"})

    def test_proc_decoding_uses_host_byte_order_per_32_bit_word(self):
        cases = (
            ("0100007F:59D8", False, "little", ("127.0.0.1", 23000)),
            ("7F000001:59D8", False, "big", ("127.0.0.1", 23000)),
            ("B80D0120000000000000000034120000:80E8", True, "little", ("2001:db8::1234", 33000)),
            ("20010DB8000000000000000000001234:80E8", True, "big", ("2001:db8::1234", 33000)),
        )
        for address, ipv6, byteorder, expected in cases:
            with self.subTest(address=address):
                self.assertEqual(connections._remote_address(address, ipv6, byteorder), expected)

    def test_malformed_rows_and_out_of_range_ports_are_ignored(self):
        process = self.process()
        self.add_socket(process, 201, "192.0.2.1", 23000)
        with (process / "net" / "udp").open("a") as target:
            for address in ("01020304:10000", "NOPE:1234", "0000000G:1234", "00000000:0000"):
                target.write("0: 0 {} 01 0 0 0 {} 0 201\n".format(address, self.uid))
            target.write("malformed row\n")
        self.assertEqual(len(self.discover()["connections"]), 1)

    def test_running_game_without_connected_udp_explains_proc_limitation(self):
        process = self.process()
        self.add_socket(process, 201, "0.0.0.0", 0)
        result = self.discover()
        self.assertEqual(result["connections"], [])
        self.assertIn("Unconnected UDP sockets do not expose their remote peer", result["message"])

    def test_permission_failure_is_visible(self):
        process = self.process()
        original = Path.iterdir

        def iterdir(path):
            if path == process / "fd":
                raise PermissionError("restricted")
            return original(path)

        with patch.object(Path, "iterdir", iterdir):
            result = self.discover()
        self.assertIn("socket descriptors (permission denied)", result["message"])
        self.assertEqual(len(result["processes"]), 1)

    def test_table_permission_failure_is_visible(self):
        process = self.process()
        self.add_socket(process, 201, "192.0.2.1", 23000)
        original = Path.read_text

        def read_text(path, *args, **kwargs):
            if path == process / "net" / "udp":
                raise PermissionError("restricted")
            return original(path, *args, **kwargs)

        with patch.object(Path, "read_text", read_text):
            result = self.discover()
        self.assertIn("socket tables (permission denied)", result["message"])

    def test_vanishing_socket_and_process_are_safe(self):
        process = self.process()
        self.add_socket(process, 201, "192.0.2.1", 23000)
        original = os.readlink

        def readlink(path):
            if Path(path).parent == process / "fd":
                raise FileNotFoundError("socket closed")
            return original(path)

        with patch.object(os, "readlink", readlink):
            result = self.discover()
        self.assertEqual(result["connections"], [])
        self.assertNotIn("Could not", result["message"])
        with patch.object(Path, "stat", side_effect=FileNotFoundError("process exited")):
            self.assertEqual(self.discover()["processes"], [])

    def test_unavailable_proc_and_permission_denied_do_not_crash(self):
        result = connections.get_connections(procroot=self.proc / "missing", system="Linux")
        self.assertIn("unavailable", result["message"])
        with patch.object(Path, "iterdir", side_effect=PermissionError("restricted")):
            result = self.discover()
        self.assertIn("inspect Linux /proc (permission denied)", result["message"])

    def test_does_not_open_network_sockets(self):
        self.process()
        with patch.object(socket, "socket", side_effect=AssertionError("network access")):
            result = self.discover()
        self.assertEqual(len(result["processes"]), 1)

    def test_cli_prints_report_as_json(self):
        report = {"supported": True, "connections": [], "message": "example"}
        output = io.StringIO()
        with patch.object(connections, "get_connections", return_value=report), contextlib.redirect_stdout(output):
            self.assertEqual(connections.main(), 0)
        self.assertEqual(json.loads(output.getvalue()), report)


if __name__ == "__main__":
    unittest.main()
