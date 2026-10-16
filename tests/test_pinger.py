import http.client
import errno
import io
import json
from pathlib import Path
import subprocess
import socket
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

import pinger


class AvailableRunner:
    available = True
    message = None

    def probe(self, hostname):
        return pinger.PingResult(12.5, "online")


class ParsingTests(unittest.TestCase):
    def test_reply_formats_and_windows_localization(self):
        cases = (
            ("64 bytes from 1.2.3.4: icmp_seq=1 ttl=53 time=42.70 ms", 42.7),
            ("64 bytes from 1.2.3.4: icmp_seq=0 ttl=56 time=21.053 ms", 21.053),
            ("Reply from 1.2.3.4: bytes=32 time=31ms TTL=53", 31.0),
            ("Antwort von 1.2.3.4: Bytes=32 Zeit<1ms TTL=64", 1.0),
            ("Respuesta desde 1.2.3.4: bytes=32 tiempo=19ms TTL=64", 19.0),
            ("Réponse de 1.2.3.4 : octets=32 temps=19,5 ms TTL=64", 19.5),
            ("1.2.3.4 からの応答: バイト数 =32 時間 =18ms TTL=64", 18.0),
            ("Ответ от 1.2.3.4: число байт=32 время=17мс TTL=64", 17.0),
        )
        for output, expected in cases:
            with self.subTest(output=output):
                self.assertEqual(pinger.parse_ping_time(output), expected)

    def test_summary_and_unreachable_are_not_successes(self):
        self.assertIsNone(pinger.parse_ping_time("Minimum = 0ms, Maximum = 0ms, Average = 0ms"))
        self.assertIsNone(pinger.parse_ping_time("Reply from 1.2.3.4: Destination host unreachable."))
        self.assertIsNone(pinger.parse_ping_time("rtt min/avg/max/mdev = 0.100/0.200/0.300/0.010 ms"))

    def test_platform_commands_have_one_packet_and_bounded_timeout(self):
        self.assertEqual(pinger.ping_command("ping", "host", "Windows"),
                         ["ping", "-4", "-n", "1", "-w", "2000", "host"])
        self.assertEqual(pinger.ping_command("ping", "host", "Linux"),
                         ["ping", "-4", "-n", "-c", "1", "-W", "2", "host"])
        self.assertEqual(pinger.ping_command("ping", "host", "Darwin"),
                         ["ping", "-n", "-c", "1", "-W", "2000", "host"])

    def runner(self):
        with patch("pinger.shutil.which", return_value="/usr/bin/ping"):
            return pinger.PingRunner()

    def test_probe_uses_real_process_without_a_shell(self):
        runner = self.runner()
        result = subprocess.CompletedProcess([], 0, b"64 bytes: ttl=64 time=8.2 ms\n", b"")
        with patch("pinger.subprocess.run", return_value=result) as run:
            self.assertEqual(runner.probe("pingtest-ams.brawlhalla.com").ms, 8.2)
        kwargs = run.call_args.kwargs
        self.assertFalse(kwargs["shell"])
        self.assertEqual(kwargs["timeout"], pinger.PROCESS_TIMEOUT)
        self.assertGreater(kwargs["timeout"], pinger.REPLY_TIMEOUT)
        self.assertEqual(kwargs["env"]["LC_ALL"], "C")

    def test_probe_distinguishes_timeout_from_process_error(self):
        runner = self.runner()
        with patch("pinger.subprocess.run", side_effect=subprocess.TimeoutExpired("ping", 2)):
            self.assertEqual(runner.probe("host").status, "error")
        with patch("pinger.subprocess.run", return_value=subprocess.CompletedProcess([], 2, b"", b"ping: unknown host")):
            self.assertEqual(runner.probe("host").status, "error")
        with patch("pinger.subprocess.run", return_value=subprocess.CompletedProcess([], 0, b"Destination host unreachable.", b"")):
            self.assertEqual(runner.probe("host").status, "timeout")
        with patch("pinger.subprocess.run", side_effect=PermissionError("denied")):
            self.assertEqual(runner.probe("host").status, "error")

    def test_process_deadline_preserves_captured_replies_and_diagnostics(self):
        runner = self.runner()
        output = b"64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.024 ms\n"
        with patch("pinger.subprocess.run", side_effect=subprocess.TimeoutExpired(
                "ping", pinger.PROCESS_TIMEOUT, output=output)):
            result = runner.probe("127.0.0.1")
        self.assertEqual((result.status, result.ms), ("online", 0.024))
        self.assertEqual(result.stdout, output.decode())
        self.assertEqual(result.command[-1], "127.0.0.1")
        self.assertIn("-4", result.command)
        self.assertTrue(result.process_timed_out)
        self.assertIsNone(result.returncode)
        self.assertGreaterEqual(result.elapsed_seconds, 0)

    def test_killed_command_without_packet_evidence_does_not_create_packet_loss(self):
        runner = self.runner()
        for output, errors in ((b"", b""), (b"", b"ping: socket: Operation not permitted"),
                               (b"", b"ping: unknown host")):
            with self.subTest(output=output, errors=errors):
                with patch("pinger.subprocess.run", side_effect=subprocess.TimeoutExpired(
                        "ping", pinger.PROCESS_TIMEOUT, output=output, stderr=errors)):
                    result = runner.probe("host")
                self.assertEqual(result.status, "error")
                self.assertTrue(result.process_timed_out)
                self.assertEqual(result.stderr, errors.decode())
                stats = pinger.ServerStats(*pinger.SERVERS[0])
                stats.record(result, 1)
                self.assertEqual(stats.snapshot()["sent"], 0)
                self.assertEqual(stats.snapshot()["history"], [])

    def test_killed_command_with_transmission_evidence_counts_a_real_failed_probe(self):
        runner = self.runner()
        with patch("pinger.subprocess.run", side_effect=subprocess.TimeoutExpired(
                "ping", pinger.PROCESS_TIMEOUT,
                output=b"1 packets transmitted, 0 received, 100% packet loss\n")):
            result = runner.probe("host")
        self.assertEqual(result.status, "timeout")
        stats = pinger.ServerStats(*pinger.SERVERS[0])
        stats.record(result, 1)
        self.assertEqual((stats.sent, stats.received), (1, 0))

    def test_localized_windows_errors_are_not_packet_timeouts(self):
        runner = self.runner()
        runner.system = "Windows"
        with patch("pinger.subprocess.run", return_value=subprocess.CompletedProcess(
                [], 1, "Ping-Anforderung konnte Host nicht finden.", "")):
            self.assertEqual(runner.probe("host").status, "error")
        with patch("pinger.subprocess.run", return_value=subprocess.CompletedProcess(
                [], 1, "Zeitüberschreitung der Anforderung.\nVerloren = 1 (100% Verlust)", "")):
            self.assertEqual(runner.probe("host").status, "timeout")

    def test_missing_ping_reports_a_capability_error(self):
        with patch("pinger.shutil.which", return_value=None):
            runner = pinger.PingRunner()
        self.assertFalse(runner.available)
        self.assertIn("not found", runner.message)
        with patch("pinger.subprocess.run") as run:
            self.assertEqual(runner.probe("host").status, "error")
            run.assert_not_called()


class TCPRunnerTests(unittest.TestCase):
    def test_connect_timing_excludes_resolution_and_closes_socket_without_http_or_tls(self):
        events = []
        connection = Mock()
        connection.connect.side_effect = lambda address: events.append(("connect", address))
        runner = pinger.TCPRunner()

        def resolve(hostname):
            events.append(("dns", hostname))
            return socket.AF_INET, "203.0.113.9"

        readings = iter((100.0, 100.0125))

        def timer():
            events.append(("timer", None))
            return next(readings)

        with patch.object(runner, "_resolve", side_effect=resolve), \
                patch("pinger.socket.socket", return_value=connection), \
                patch("pinger.time.perf_counter", side_effect=timer):
            result = runner.probe("game.example.com")
        self.assertEqual(result.status, "online")
        self.assertAlmostEqual(result.ms, 12.5)
        self.assertEqual(events, [("dns", "game.example.com"), ("timer", None),
                                  ("connect", ("203.0.113.9", 443)), ("timer", None)])
        connection.settimeout.assert_called_once_with(2.0)
        connection.close.assert_called_once_with()
        connection.send.assert_not_called()
        connection.sendall.assert_not_called()
        self.assertEqual(result.command, ("TCP", "game.example.com", "443"))
        self.assertIn("203.0.113.9", result.stdout)

    def test_timeout_refusal_and_permission_errors_have_distinct_accounting(self):
        for exception, expected_status, counted in (
                (socket.timeout("timed out"), "timeout", 1),
                (OSError(errno.ETIMEDOUT, "timed out"), "timeout", 1),
                (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), "refused", 1),
                (PermissionError(errno.EACCES, "denied"), "error", 0)):
            with self.subTest(exception=exception):
                connection = Mock()
                connection.connect.side_effect = exception
                runner = pinger.TCPRunner(80)
                with patch("pinger.socket.socket", return_value=connection):
                    result = runner.probe("203.0.113.9")
                self.assertEqual(result.status, expected_status)
                self.assertIsNone(result.ms)
                self.assertEqual(result.stderr, result.error)
                self.assertIn("80", result.stdout)
                connection.close.assert_called_once_with()
                stats = pinger.ServerStats(*pinger.SERVERS[0])
                stats.record(result, 1)
                self.assertEqual((stats.sent, stats.received), (counted, 0))

    def test_dns_failures_are_cached_and_do_not_invent_failed_connections(self):
        runner = pinger.TCPRunner()
        with patch("pinger.socket.getaddrinfo", side_effect=socket.gaierror("unknown host")) as lookup, \
                patch("pinger.socket.socket") as factory:
            first = runner.probe("missing.example.com")
            second = runner.probe("missing.example.com")
        self.assertEqual((first.status, second.status), ("error", "error"))
        self.assertIn("DNS resolution failed", first.error)
        lookup.assert_called_once_with("missing.example.com", None, socket.AF_INET,
                                       socket.SOCK_STREAM, socket.IPPROTO_TCP)
        factory.assert_not_called()
        stats = pinger.ServerStats(*pinger.SERVERS[0])
        stats.record(first, 1)
        self.assertEqual((stats.sent, list(stats.history)), (0, []))

    def test_dns_timeout_does_not_invent_a_connection_attempt(self):
        with patch("pinger.socket.getaddrinfo", side_effect=TimeoutError("resolver timed out")), \
                patch("pinger.socket.socket") as factory:
            result = pinger.TCPRunner().probe("game.example.com")
        self.assertEqual(result.status, "error")
        self.assertIn("before a TCP connection attempt", result.error)
        factory.assert_not_called()
        stats = pinger.ServerStats(*pinger.SERVERS[0])
        stats.record(result, 1)
        self.assertEqual(stats.sent, 0)

    def test_dns_cache_expires_and_stays_bounded(self):
        runner = pinger.TCPRunner()
        answer = [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("203.0.113.9", 0))]
        with patch("pinger.socket.getaddrinfo", return_value=answer) as lookup, \
                patch("pinger.time.monotonic", return_value=0) as timer, \
                patch("pinger.DNS_CACHE_LIMIT", 2):
            self.assertEqual(runner._resolve("one.example.com"), (socket.AF_INET, "203.0.113.9"))
            timer.return_value = 59
            runner._resolve("one.example.com")
            self.assertEqual(lookup.call_count, 1)
            timer.return_value = 61
            runner._resolve("one.example.com")
            self.assertEqual(lookup.call_count, 2)
            runner._resolve("two.example.com")
            runner._resolve("three.example.com")
            self.assertEqual(len(runner._dns_cache), 2)
            self.assertNotIn("one.example.com", runner._dns_cache)

    def test_ipv6_literal_uses_ipv6_socket_and_does_not_resolve_dns(self):
        connection = Mock()
        with patch("pinger.socket.getaddrinfo") as lookup, \
                patch("pinger.socket.socket", return_value=connection) as factory:
            result = pinger.TCPRunner().probe("2001:db8::1")
        self.assertEqual(result.status, "online")
        factory.assert_called_once_with(socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP)
        connection.connect.assert_called_once_with(("2001:db8::1", 443, 0, 0))
        lookup.assert_not_called()

    def test_missing_ping_does_not_disable_tcp_default(self):
        with tempfile.TemporaryDirectory() as directory, patch("pinger.shutil.which", return_value=None):
            monitor = pinger.Monitor(launch_workers=False, targets_path=Path(directory) / "targets.json")
            try:
                state = monitor.snapshot()
                self.assertTrue(state["capability"]["available"])
                self.assertTrue(state["running"])
                self.assertEqual((state["method"], state["tcp_port"]), ("tcp", 443))
                state = monitor.control("method", method="icmp")
                self.assertFalse(state["capability"]["available"])
                self.assertFalse(state["running"])
                self.assertIn("not found", state["capability"]["message"])
            finally:
                monitor.close()

    def test_tcp_diagnostics_use_parallel_connections_and_keep_refusals_distinct(self):
        runner = pinger.TCPRunner(80)
        entered = threading.Barrier(len(pinger.SERVERS) + 1)

        def probe(hostname):
            entered.wait(timeout=3)
            if hostname == "google.com":
                return pinger.PingResult(2, "online")
            return pinger.PingResult(None, "refused", "The host responded.")

        with patch.object(runner, "probe", side_effect=probe):
            report = runner.diagnose({"eu": "203.0.113.9"})
        self.assertEqual((report["method"], report["tcp_port"]), ("tcp", 80))
        self.assertEqual(len(report["checks"]), 10)
        self.assertNotIn("loopback", [item["kind"] for item in report["checks"]])
        self.assertIn("203.0.113.9", [item["hostname"] for item in report["checks"]])
        self.assertIn("refused", report["summary"]["title"])
        self.assertIn("host or firewall responded", report["summary"]["message"])


class DiagnosticTests(unittest.TestCase):
    def runner(self):
        with patch("pinger.shutil.which", return_value="/usr/bin/ping"):
            return pinger.PingRunner()

    def test_diagnostics_probe_all_fixed_targets_in_parallel_without_counting_stats(self):
        runner = self.runner()
        entered = threading.Barrier(len(pinger.SERVERS) + 2)

        def probe(hostname):
            entered.wait(timeout=3)
            return pinger.PingResult(4.2, "online", stdout="real reply", command=("ping", hostname),
                                     returncode=0, elapsed_seconds=0.01)

        with patch.object(runner, "probe", side_effect=probe) as mocked:
            result = runner.diagnose()
        self.assertEqual(mocked.call_count, 11)
        self.assertEqual([item["kind"] for item in result["checks"]],
                         ["loopback", "reference"] + ["server"] * 9)
        self.assertEqual({item["hostname"] for item in result["checks"]},
                         {"127.0.0.1", "google.com"} | {item[3] for item in pinger.SERVERS})
        self.assertTrue(all(item["status"] == "online" for item in result["checks"]))
        self.assertEqual(result["checks"][0]["stdout"], "real reply")
        self.assertEqual(result["checks"][0]["command"], ["ping", "127.0.0.1"])
        self.assertIn("9 of 9", result["summary"]["title"])
        json.dumps(result, allow_nan=False)

    def test_diagnostic_summaries_distinguish_local_external_and_server_failures(self):
        runner = self.runner()
        cases = (
            ({"127.0.0.1"}, "No external ICMP replies", "does not establish"),
            ({"127.0.0.1", "google.com"}, "Reference replied; Brawlhalla hosts did not", "does not establish"),
            (set(), "Local ICMP check failed", "local ping command"),
        )
        for replies, title, detail in cases:
            with self.subTest(replies=replies):
                def probe(hostname):
                    return pinger.PingResult(1, "online") if hostname in replies else pinger.PingResult(None, "timeout", "No reply")
                with patch.object(runner, "probe", side_effect=probe):
                    result = runner.diagnose()
                self.assertEqual(result["summary"]["title"], title)
                self.assertIn(detail, result["summary"]["message"])

    def test_diagnostics_cli_does_not_launch_monitor_or_browser(self):
        report = {"checks": [], "summary": {"title": "Test report", "message": "Test"}}
        runner = self.runner()
        with patch("pinger.PingRunner", return_value=runner), \
                patch.object(runner, "diagnose", return_value=report), \
                patch("pinger.Monitor") as monitor, \
                patch("pinger.PingerHTTPServer") as server, \
                patch("pinger.webbrowser.open") as browser, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(pinger.main(["--diagnose", "--method", "icmp"]), 0)
            self.assertEqual(json.loads(output.getvalue()), report)
        monitor.assert_not_called()
        server.assert_not_called()
        browser.assert_not_called()


class TargetTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.path = Path(self.directory.name) / "targets.json"
        self.monitor = pinger.Monitor(AvailableRunner(), launch_workers=False, targets_path=self.path)

    def tearDown(self):
        self.monitor.close()
        self.directory.cleanup()

    def test_target_validation_accepts_names_and_ips_but_rejects_urls_options_and_controls(self):
        for target in ("game.example.com", "game.example.com.", "203.0.113.7", "2001:db8::1"):
            with self.subTest(target=target):
                self.assertEqual(pinger.validate_target(target), target)
        for target in ("", "-c", "--help", "a b", "a\nb", "http://game.example.com", "host:23000",
                       "example.com;echo", "$(whoami)", "x..y", "example.com..", ".", "a" * 64 + ".com", None, 4):
            with self.subTest(target=target), self.assertRaises(ValueError):
                pinger.validate_target(target)
        self.assertIn("-6", pinger.ping_command("ping", "2001:db8::1", "Linux"))
        self.assertIn("-6", pinger.ping_command("ping", "2001:db8::1", "Windows"))

    def test_target_update_persists_resets_only_its_region_and_preserves_pause(self):
        self.monitor.control("stop")
        for server in self.monitor.servers:
            server.record(pinger.PingResult(10, "online"), 1)
        untouched = self.monitor.servers[0]
        state = self.monitor.control("target", region_id="eu", hostname="203.0.113.7")
        europe = state["servers"][2]
        self.assertFalse(state["running"])
        self.assertEqual((europe["hostname"], europe["sent"], europe["is_custom"]), ("203.0.113.7", 0, True))
        self.assertEqual(europe["default_hostname"], pinger.DEFAULT_HOSTNAMES["eu"])
        self.assertIs(self.monitor.servers[0], untouched)
        self.assertEqual(self.monitor.servers[0].sent, 1)
        self.assertEqual(json.loads(self.path.read_text()), {"eu": "203.0.113.7"})
        reloaded = pinger.Monitor(AvailableRunner(), launch_workers=False, targets_path=self.path)
        try:
            self.assertEqual(reloaded.servers[2].hostname, "203.0.113.7")
            self.assertEqual(reloaded.control("reset")["servers"][2]["hostname"], "203.0.113.7")
        finally:
            reloaded.close()
        state = self.monitor.set_target("eu", "")
        self.assertEqual(state["servers"][2]["hostname"], pinger.DEFAULT_HOSTNAMES["eu"])
        self.assertFalse(state["servers"][2]["is_custom"])
        self.assertEqual(json.loads(self.path.read_text()), {})

    def test_invalid_config_defaults_with_visible_error_and_save_failure_is_atomic(self):
        for content in ('{"bad-region":"example.com"}', '{"eu":"--help"}', '[]', '{broken'):
            with self.subTest(content=content):
                self.path.write_text(content)
                loaded = pinger.Monitor(AvailableRunner(), launch_workers=False, targets_path=self.path)
                try:
                    state = loaded.snapshot()
                    self.assertIn("Could not load targets", state["targets_config_error"])
                    self.assertEqual(state["servers"][2]["hostname"], pinger.DEFAULT_HOSTNAMES["eu"])
                finally:
                    loaded.close()
        self.path.write_text('{"eu":"203.0.113.7"}')
        old_contents = self.path.read_text()
        before = self.monitor.servers[2]
        with patch("pinger.os.replace", side_effect=PermissionError("denied")):
            with self.assertRaisesRegex(ValueError, "Could not save targets"):
                self.monitor.set_target("eu", "203.0.113.8")
        self.assertEqual(self.path.read_text(), old_contents)
        self.assertIs(self.monitor.servers[2], before)
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_target_change_discards_only_that_regions_in_flight_result(self):
        entered = threading.Barrier(len(pinger.SERVERS) + 1)
        release = threading.Event()
        custom_entered = threading.Event()
        custom_release = threading.Event()
        others_recorded = threading.Event()
        recorded_ids = set()
        record_lock = threading.Lock()
        original_record = pinger.ServerStats.record

        class BlockingRunner(AvailableRunner):
            def probe(self, hostname):
                if hostname == "203.0.113.7":
                    custom_entered.set()
                    custom_release.wait(timeout=3)
                else:
                    entered.wait(timeout=3)
                    release.wait(timeout=3)
                return pinger.PingResult(17, "online")

        def record(server, result, timestamp):
            original_record(server, result, timestamp)
            if server.id != "us-e":
                with record_lock:
                    recorded_ids.add(server.id)
                    if len(recorded_ids) == len(pinger.SERVERS) - 1:
                        others_recorded.set()

        with patch.object(pinger.ServerStats, "record", new=record):
            monitor = pinger.Monitor(BlockingRunner(), targets_path=self.path)
            try:
                entered.wait(timeout=3)
                monitor.control("interval", 10)
                monitor.set_target("us-e", "203.0.113.7")
                release.set()
                self.assertTrue(custom_entered.wait(timeout=3))
                self.assertTrue(others_recorded.wait(timeout=3))
                state = monitor.snapshot()
                self.assertEqual(state["servers"][0]["sent"], 0)
                self.assertTrue(all(server["received"] == 1 for server in state["servers"][1:]))
            finally:
                monitor.control("stop")
                release.set()
                custom_release.set()
                monitor.close()

    def test_diagnostics_and_cli_use_saved_overrides(self):
        self.monitor.set_target("eu", "203.0.113.7")
        runner = pinger.PingRunner()
        with patch.object(runner, "probe", return_value=pinger.PingResult(1, "online")) as probe:
            report = runner.diagnose({"eu": "203.0.113.7"})
        self.assertIn("203.0.113.7", [item["hostname"] for item in report["checks"]])
        self.assertNotIn(pinger.DEFAULT_HOSTNAMES["eu"], [call.args[0] for call in probe.call_args_list])
        self.monitor.runner = runner
        with patch.object(runner, "diagnose", return_value={"summary": {}}) as diagnose:
            self.monitor.diagnose()
            diagnose.assert_called_once_with({"eu": "203.0.113.7"})
        with patch("pinger.PingRunner", return_value=runner), \
                patch.object(runner, "diagnose", return_value={"summary": {}}) as diagnose, \
                patch("sys.stdout", new_callable=io.StringIO) as output:
            self.assertEqual(pinger.main(["--diagnose", "--method", "icmp", "--targets", str(self.path)]), 0)
            diagnose.assert_called_once_with({"eu": "203.0.113.7"})
            self.assertIsNone(json.loads(output.getvalue())["targets_config_error"])


class StatisticsTests(unittest.TestCase):
    def test_loss_latency_and_jitter_use_only_received_replies(self):
        stats = pinger.ServerStats(*pinger.SERVERS[0])
        stats.record(pinger.PingResult(10, "online"), 1)
        stats.record(pinger.PingResult(None, "timeout", "No reply"), 2)
        stats.record(pinger.PingResult(30, "online"), 3)
        stats.record(pinger.PingResult(20, "online"), 4)
        data = stats.snapshot()
        self.assertEqual((data["sent"], data["received"], data["lost"]), (4, 3, 1))
        self.assertEqual(data["loss"], 25)
        self.assertEqual(data["avg_ms"], 20)
        self.assertEqual((data["min_ms"], data["max_ms"]), (10, 30))
        self.assertEqual(data["jitter_ms"], 15)
        self.assertEqual(data["history"][1], {"timestamp": 2, "ms": None})
        self.assertIsNone(data["error"])

    def test_ring_is_bounded_without_losing_cumulative_statistics(self):
        stats = pinger.ServerStats(*pinger.SERVERS[0])
        for index in range(100):
            stats.record(pinger.PingResult(float(index), "online"), index)
        data = stats.snapshot()
        self.assertEqual(len(data["history"]), 90)
        self.assertEqual(data["history"][0]["timestamp"], 10)
        self.assertEqual(data["sent"], 100)
        self.assertEqual(data["avg_ms"], 49.5)
        self.assertEqual(data["min_ms"], 0)

    def test_an_empty_server_does_not_invent_measurements(self):
        data = pinger.ServerStats(*pinger.SERVERS[0]).snapshot()
        self.assertEqual(data["history"], [])
        for key in ("latest_ms", "avg_ms", "min_ms", "max_ms", "jitter_ms"):
            self.assertIsNone(data[key])

    def test_process_and_dns_errors_do_not_invent_packet_loss(self):
        stats = pinger.ServerStats(*pinger.SERVERS[0])
        stats.record(pinger.PingResult(12, "online"), 1)
        stats.record(pinger.PingResult(None, "error", "DNS resolution failed"), 2)
        data = stats.snapshot()
        self.assertEqual((data["sent"], data["received"], data["lost"]), (1, 1, 0))
        self.assertEqual(data["latest_ms"], 12)
        self.assertEqual(len(data["history"]), 1)
        self.assertEqual(data["status"], "error")
        self.assertEqual(data["error"], "DNS resolution failed")


class ControlTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.monitor = pinger.Monitor(AvailableRunner(), launch_workers=False,
                                      targets_path=Path(self.directory.name) / "targets.json")

    def tearDown(self):
        self.monitor.close()
        self.directory.cleanup()

    def test_controls_validate_intervals_and_preserve_pause_on_reset(self):
        self.assertTrue(self.monitor.snapshot()["running"])
        self.assertFalse(self.monitor.control("stop")["running"])
        self.assertFalse(self.monitor.control("reset")["running"])
        self.assertTrue(self.monitor.control("start")["running"])
        self.assertTrue(self.monitor.control("reset")["running"])
        for seconds in pinger.INTERVALS:
            self.assertEqual(self.monitor.control("interval", seconds)["interval"], seconds)
        for invalid in (True, 0, 3, "2", 2.0, None):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.monitor.control("interval", invalid)
        with self.assertRaises(ValueError):
            self.monitor.control("delete")

    def test_reset_clears_samples(self):
        self.monitor.servers[0].record(pinger.PingResult(19, "online"), 1)
        data = self.monitor.control("reset")
        self.assertEqual(data["servers"][0]["sent"], 0)
        self.assertEqual(data["servers"][0]["history"], [])
        self.assertIsNone(data["last_update"])

    def test_selection_defaults_to_all_preserves_history_and_validates_without_mutation(self):
        state = self.monitor.snapshot()
        self.assertIsNone(state["selected_server"])
        self.assertTrue(all(server["enabled"] for server in state["servers"]))
        for server in self.monitor.servers:
            server.record(pinger.PingResult(19, "online"), 1)
            server.status = "pending"
        state = self.monitor.control("select", region_id="eu")
        self.assertTrue(state["running"])
        self.assertEqual(state["selected_server"], "eu")
        self.assertEqual([server["id"] for server in state["servers"] if server["enabled"]], ["eu"])
        self.assertTrue(all(server["sent"] == 1 and len(server["history"]) == 1 for server in state["servers"]))
        self.assertTrue(all(server["status"] == "online" for server in state["servers"] if not server["enabled"]))
        self.assertEqual(state["servers"][2]["status"], "pending")
        generations = list(self.monitor.selection_generations)
        generation = self.monitor.generation
        self.monitor.control("select", region_id="eu")
        self.assertEqual(self.monitor.selection_generations, generations)
        self.assertEqual(self.monitor.generation, generation)
        self.assertEqual(self.monitor.servers[2].status, "pending")
        for invalid in (None, [], {}, True, 1, "EU", "", "missing"):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                self.monitor.control("select", region_id=invalid)
            self.assertEqual(self.monitor.selected_server, "eu")
            self.assertEqual(self.monitor.selection_generations, generations)
        state = self.monitor.control("select", region_id="all")
        self.assertIsNone(state["selected_server"])
        self.assertTrue(all(server["enabled"] and server["sent"] == 1 for server in state["servers"]))

    def test_selection_survives_pause_resume_reset_target_and_method_changes(self):
        self.monitor.control("stop")
        state = self.monitor.control("select", region_id="eu")
        self.assertFalse(state["running"])
        for action, kwargs in (("reset", {}), ("target", {"region_id": "eu", "hostname": "203.0.113.9"}),
                               ("method", {"method": "tcp", "port": 80})):
            state = self.monitor.control(action, **kwargs)
            self.assertFalse(state["running"])
            self.assertEqual(state["selected_server"], "eu")
            self.assertEqual([server["id"] for server in state["servers"] if server["enabled"]], ["eu"])
        state = self.monitor.control("start")
        self.assertTrue(state["running"])
        self.assertEqual(state["selected_server"], "eu")
        self.assertEqual(state["servers"][2]["hostname"], "203.0.113.9")
        self.monitor.control("stop")
        self.assertFalse(self.monitor.control("select", region_id="all")["running"])

    def test_selection_stops_other_worker_calls_and_all_restores_them(self):
        first_entered = threading.Barrier(len(pinger.SERVERS) + 1)
        first_release = threading.Event()
        second_europe = threading.Event()
        other_seconds = threading.Barrier(len(pinger.SERVERS))
        second_release = threading.Event()
        calls = {}
        call_lock = threading.Lock()
        all_waiting = threading.Event()
        waiting = set()

        class BlockingRunner(AvailableRunner):
            def probe(self, hostname):
                with call_lock:
                    number = calls[hostname] = calls.get(hostname, 0) + 1
                if number == 1:
                    first_entered.wait(timeout=3)
                    first_release.wait(timeout=3)
                else:
                    if hostname == pinger.DEFAULT_HOSTNAMES["eu"]:
                        second_europe.set()
                    else:
                        other_seconds.wait(timeout=3)
                    second_release.wait(timeout=3)
                return pinger.PingResult(17, "online")

        monitor = pinger.Monitor(BlockingRunner(), targets_path=Path(self.directory.name) / "workers.json")
        original_wait = monitor.condition.wait

        def observe_wait(*args, **kwargs):
            waiting.add(threading.get_ident())
            if len(waiting) == len(pinger.SERVERS):
                all_waiting.set()
            return original_wait(*args, **kwargs)

        try:
            first_entered.wait(timeout=3)
            monitor.condition.wait = observe_wait
            monitor.control("interval", 10)
            state = monitor.control("select", region_id="eu")
            self.assertTrue(all(server["status"] == "idle" for server in state["servers"] if not server["enabled"]))
            first_release.set()
            self.assertTrue(all_waiting.wait(timeout=3))
            state = monitor.snapshot()
            self.assertEqual(state["servers"][2]["sent"], 1)  # Continuously selected probe stays valid.
            self.assertTrue(all(server["sent"] == 0 for server in state["servers"] if not server["enabled"]))
            monitor.control("interval", 1)
            self.assertTrue(second_europe.wait(timeout=3))
            with call_lock:
                self.assertEqual(calls[pinger.DEFAULT_HOSTNAMES["eu"]], 2)
                self.assertTrue(all(count == 1 for host, count in calls.items() if host != pinger.DEFAULT_HOSTNAMES["eu"]))
            monitor.control("interval", 10)
            state = monitor.control("select", region_id="all")
            other_seconds.wait(timeout=3)
            with call_lock:
                self.assertTrue(all(count == 2 for count in calls.values()))
            self.assertEqual(state["servers"][2]["sent"], 1)
        finally:
            monitor.control("stop")
            first_release.set()
            second_release.set()
            monitor.close()

    def test_rapid_reselection_rejects_old_result_before_recording_new_probe(self):
        first_entered = threading.Barrier(len(pinger.SERVERS) + 1)
        first_release = threading.Event()
        new_europe_entered = threading.Event()
        new_europe_release = threading.Event()
        new_europe_recorded = threading.Event()
        calls = set()
        call_lock = threading.Lock()
        original_record = pinger.ServerStats.record

        class BlockingRunner(AvailableRunner):
            def probe(self, hostname):
                with call_lock:
                    first = hostname not in calls
                    calls.add(hostname)
                if first:
                    first_entered.wait(timeout=3)
                    first_release.wait(timeout=3)
                    return pinger.PingResult(99, "online")
                new_europe_entered.set()
                new_europe_release.wait(timeout=3)
                return pinger.PingResult(20, "online")

        def record(server, result, timestamp):
            original_record(server, result, timestamp)
            if server.id == "eu":
                new_europe_recorded.set()

        with patch.object(pinger.ServerStats, "record", new=record):
            monitor = pinger.Monitor(BlockingRunner(), targets_path=Path(self.directory.name) / "reselect.json")
            try:
                first_entered.wait(timeout=3)
                monitor.control("interval", 10)
                monitor.control("select", region_id="eu")
                monitor.control("select", region_id="us-e")
                monitor.control("select", region_id="eu")
                first_release.set()
                self.assertTrue(new_europe_entered.wait(timeout=3))
                self.assertTrue(all(server["sent"] == 0 for server in monitor.snapshot()["servers"]))
                new_europe_release.set()
                self.assertTrue(new_europe_recorded.wait(timeout=3))
                state = monitor.snapshot()
                self.assertEqual((state["servers"][2]["sent"], state["servers"][2]["latest_ms"]), (1, 20))
                self.assertTrue(all(server["sent"] == 0 for server in state["servers"] if not server["enabled"]))
            finally:
                monitor.control("stop")
                first_release.set()
                new_europe_release.set()
                monitor.close()

    def test_diagnostics_use_only_selected_region_plus_comparison_targets(self):
        for runner, reference_count in ((pinger.PingRunner(), 2), (pinger.TCPRunner(), 1)):
            with self.subTest(method=runner.method), patch.object(runner, "probe", return_value=pinger.PingResult(1, "online")) as probe:
                runner.available = True
                report = runner.diagnose({"eu": "203.0.113.9"}, selected_server="eu")
                self.assertEqual(probe.call_count, reference_count + 1)
                self.assertEqual([item["hostname"] for item in report["checks"] if item["kind"] == "server"], ["203.0.113.9"])
                self.assertEqual(report["selected_server"], "eu")
                self.assertIn("1 of 1", report["summary"]["title"])
        self.monitor.control("select", region_id="eu")
        self.monitor.runner = runner
        with patch.object(runner, "diagnose", return_value={"summary": {}}) as diagnose:
            report = self.monitor.diagnose()
            diagnose.assert_called_once_with({}, selected_server="eu")
            self.assertEqual(report["selected_server"], "eu")

    def test_method_change_clears_samples_preserves_targets_and_pause_and_validates_inputs(self):
        self.monitor.set_target("eu", "203.0.113.9")
        self.monitor.control("stop")
        for server in self.monitor.servers:
            server.record(pinger.PingResult(19, "online"), 1)
        data = self.monitor.control("method", method="tcp", port=80)
        self.assertEqual((data["method"], data["tcp_port"]), ("tcp", 80))
        self.assertFalse(data["running"])
        self.assertIsNone(data["last_update"])
        self.assertTrue(all(server["sent"] == 0 and server["history"] == [] for server in data["servers"]))
        self.assertEqual(data["servers"][2]["hostname"], "203.0.113.9")
        self.assertIn("TCP port 80 connect latency", data["measurement_source"]["description"])
        data = self.monitor.control("method", method="tcp")
        self.assertEqual(data["tcp_port"], 443)
        for method, port in (("udp", 443), (None, 443), ("tcp", 22), ("tcp", True), ("tcp", "443")):
            with self.subTest(method=method, port=port), self.assertRaises(ValueError):
                self.monitor.control("method", method=method, port=port)

    def test_method_change_discards_in_flight_old_runner_results(self):
        entered = threading.Barrier(len(pinger.SERVERS) + 1)
        next_entered = threading.Barrier(len(pinger.SERVERS) + 1)
        release = threading.Event()
        next_release = threading.Event()

        class OldRunner(AvailableRunner):
            def probe(self, hostname):
                entered.wait(timeout=3)
                release.wait(timeout=3)
                return pinger.PingResult(5, "online")

        class NewRunner(AvailableRunner):
            method = "tcp"
            tcp_port = 443

            def probe(self, hostname):
                next_entered.wait(timeout=3)
                next_release.wait(timeout=3)
                return pinger.PingResult(20, "online")

        monitor = pinger.Monitor(OldRunner(), targets_path=Path(self.directory.name) / "inflight.json")
        try:
            entered.wait(timeout=3)
            with patch("pinger.TCPRunner", return_value=NewRunner()):
                monitor.control("method", method="tcp")
            release.set()
            next_entered.wait(timeout=3)
            state = monitor.snapshot()
            self.assertTrue(state["running"])
            self.assertEqual(state["method"], "tcp")
            self.assertTrue(all(server["sent"] == 0 for server in state["servers"]))
        finally:
            monitor.control("stop")
            release.set()
            next_release.set()
            monitor.close()

    def test_all_hosts_run_concurrently_and_stopped_probes_are_discarded(self):
        entered = threading.Barrier(len(pinger.SERVERS) + 1)
        release = threading.Event()
        completed = threading.Event()
        completion_lock = threading.Lock()
        count = [0]

        class BlockingRunner(AvailableRunner):
            def probe(self, hostname):
                entered.wait(timeout=2)
                release.wait(timeout=2)
                with completion_lock:
                    count[0] += 1
                    if count[0] == len(pinger.SERVERS):
                        completed.set()
                return pinger.PingResult(5, "online")

        monitor = pinger.Monitor(BlockingRunner())
        try:
            # This barrier cannot complete if probes are serialized.
            entered.wait(timeout=2)
            waiting = set()
            all_waiting = threading.Event()
            original_wait = monitor.condition.wait

            def observe_wait(*args, **kwargs):
                waiting.add(threading.get_ident())
                if len(waiting) == len(pinger.SERVERS):
                    all_waiting.set()
                return original_wait(*args, **kwargs)

            # Each worker reaches this wait only after handling its result.
            monitor.condition.wait = observe_wait
            monitor.control("stop")
            release.set()
            self.assertTrue(completed.wait(timeout=2))
            self.assertTrue(all_waiting.wait(timeout=2))
            data = monitor.snapshot()
            self.assertTrue(all(server["sent"] == 0 for server in data["servers"]))
            self.assertTrue(all(server["status"] == "idle" for server in data["servers"]))
        finally:
            release.set()
            monitor.close()

    def test_reset_discards_results_already_in_flight(self):
        entered = threading.Barrier(len(pinger.SERVERS) + 1)
        second_entered = threading.Barrier(len(pinger.SERVERS) + 1)
        release = threading.Event()
        second_release = threading.Event()
        calls = set()
        calls_lock = threading.Lock()

        class BlockingRunner(AvailableRunner):
            def probe(self, hostname):
                with calls_lock:
                    first = hostname not in calls
                    calls.add(hostname)
                if first:
                    entered.wait(timeout=2)
                    release.wait(timeout=2)
                else:
                    second_entered.wait(timeout=2)
                    second_release.wait(timeout=2)
                return pinger.PingResult(5, "online")

        monitor = pinger.Monitor(BlockingRunner())
        try:
            entered.wait(timeout=2)
            monitor.control("reset")
            release.set()
            # Every second probe starts only after discarding the old result.
            second_entered.wait(timeout=2)
            self.assertTrue(monitor.snapshot()["running"])
            self.assertTrue(all(server["sent"] == 0 for server in monitor.snapshot()["servers"]))
        finally:
            monitor.control("stop")
            release.set()
            second_release.set()
            monitor.close()


class HTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        root = Path(self.temp.name)
        (root / "web").mkdir()
        (root / "web" / "index.html").write_text("<h1>Real ping</h1>", encoding="utf-8")
        (root / "secret.txt").write_text("private", encoding="utf-8")
        self.monitor = pinger.Monitor(AvailableRunner(), launch_workers=False,
                                      targets_path=root / "targets.json")
        self.server = pinger.PingerHTTPServer(("127.0.0.1", 0), self.monitor, root / "web")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.monitor.close()
        self.thread.join(timeout=2)
        self.temp.cleanup()

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=3)
        try:
            connection.request(method, path, body=body, headers=headers or {})
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_api_schema_and_no_store(self):
        code, headers, body = self.request("GET", "/api/status")
        self.assertEqual(code, 200)
        self.assertEqual(headers["Cache-Control"], "no-store")
        data = json.loads(body)
        self.assertEqual(len(data["servers"]), 9)
        self.assertEqual(data["servers"][0]["hostname"], "pingtest-atl.brawlhalla.com")
        self.assertTrue(data["capability"]["available"])
        self.assertIn("computer running pinger.py", data["measurement_source"]["description"])

    def test_tcp_connect_probe_measures_a_real_loopback_socket(self):
        runner = pinger.TCPRunner()
        # The public UI limits probes to 80/443. This local test fixture uses
        # its ephemeral HTTP listener so it needs no privileged port binding.
        runner.tcp_port = self.server.server_port
        result = runner.probe("127.0.0.1")
        self.assertEqual(result.status, "online")
        self.assertGreaterEqual(result.ms, 0)
        self.assertIn("Connection established", result.stdout)

    def test_method_endpoint_changes_mode_and_rejects_invalid_ports(self):
        code, _, body = self.request("POST", "/api/control", json.dumps({
            "action": "method", "method": "tcp", "port": 80}), {"Content-Type": "application/json"})
        self.assertEqual(code, 200)
        state = json.loads(body)
        self.assertEqual((state["method"], state["tcp_port"]), ("tcp", 80))
        for method, port in (("udp", 443), ("tcp", 22), ("tcp", "443")):
            code, _, _ = self.request("POST", "/api/control", json.dumps({
                "action": "method", "method": method, "port": port}), {"Content-Type": "application/json"})
            self.assertEqual(code, 400)

    def test_selection_endpoint_changes_scope_and_rejects_invalid_ids(self):
        headers = {"Content-Type": "application/json"}
        code, _, body = self.request("POST", "/api/control", json.dumps({
            "action": "select", "id": "eu"}), headers)
        self.assertEqual(code, 200)
        state = json.loads(body)
        self.assertEqual(state["selected_server"], "eu")
        self.assertEqual([server["id"] for server in state["servers"] if server["enabled"]], ["eu"])
        self.assertEqual(len(state["servers"]), 9)
        for invalid in (None, [], {}, True, "missing", ""):
            code, _, _ = self.request("POST", "/api/control", json.dumps({
                "action": "select", "id": invalid}), headers)
            self.assertEqual(code, 400)
            self.assertEqual(self.monitor.selected_server, "eu")
        code, _, _ = self.request("POST", "/api/control", '{"action":"select"}', headers)
        self.assertEqual(code, 400)
        code, _, body = self.request("POST", "/api/control", json.dumps({
            "action": "select", "id": "all"}), headers)
        self.assertEqual(code, 200)
        state = json.loads(body)
        self.assertIsNone(state["selected_server"])
        self.assertTrue(all(server["enabled"] for server in state["servers"]))

    def test_diagnostic_endpoint_uses_fixed_targets_and_does_not_modify_monitor(self):
        report = {"checks": [{"hostname": "127.0.0.1", "status": "online"}],
                  "summary": {"title": "Local reply", "message": "Test"}}
        before = self.monitor.snapshot()
        with patch.object(self.monitor.runner, "diagnose", return_value=report, create=True) as diagnose:
            code, _, body = self.request("POST", "/api/diagnose", "{}", {"Content-Type": "application/json"})
        self.assertEqual(code, 200)
        self.assertEqual(json.loads(body), report)
        diagnose.assert_called_once_with({})
        after = self.monitor.snapshot()
        self.assertEqual(after["servers"], before["servers"])
        self.assertEqual(after["running"], before["running"])
        code, _, _ = self.request("POST", "/api/diagnose", '{"hostname":"example.org"}',
                                  {"Content-Type": "application/json"})
        self.assertEqual(code, 400)

    def test_diagnostic_busy_guard_preserves_controls_and_checks_request_origin(self):
        self.server.diagnostic_lock.acquire()
        try:
            code, _, body = self.request("POST", "/api/diagnose", "{}", {"Content-Type": "application/json"})
            self.assertEqual(code, 409)
            self.assertIn("already in progress", json.loads(body)["error"])
            code, _, body = self.request("POST", "/api/control", '{"action":"stop"}',
                                         {"Content-Type": "application/json"})
            self.assertEqual(code, 200)
            self.assertFalse(json.loads(body)["running"])
        finally:
            self.server.diagnostic_lock.release()
        code, _, _ = self.request("POST", "/api/diagnose", "{}", {
            "Content-Type": "application/json", "Origin": "https://evil.example"})
        self.assertEqual(code, 403)

    def test_target_endpoint_validates_and_resets_only_selected_region(self):
        code, _, body = self.request("POST", "/api/control", json.dumps({
            "action": "target", "id": "eu", "hostname": "203.0.113.7"}), {"Content-Type": "application/json"})
        self.assertEqual(code, 200)
        state = json.loads(body)
        self.assertEqual(state["servers"][2]["hostname"], "203.0.113.7")
        self.assertTrue(state["servers"][2]["is_custom"])
        for region_id, hostname in (("missing", "203.0.113.7"), ("eu", "--help"), ("eu", "https://example.com")):
            code, _, _ = self.request("POST", "/api/control", json.dumps({
                "action": "target", "id": region_id, "hostname": hostname}), {"Content-Type": "application/json"})
            self.assertEqual(code, 400)
        code, _, body = self.request("POST", "/api/control", json.dumps({
            "action": "target", "id": "eu", "hostname": ""}), {"Content-Type": "application/json"})
        self.assertEqual(code, 200)
        self.assertFalse(json.loads(body)["servers"][2]["is_custom"])

    def test_connections_endpoint_calls_local_discovery_without_arguments(self):
        report = {"supported": True, "system": "Linux", "processes": [], "connections": [], "message": "Test"}
        module = SimpleNamespace(get_connections=lambda: report)
        with patch.dict("sys.modules", {"connections": module}), \
                patch.object(module, "get_connections", return_value=report) as discover:
            code, _, body = self.request("GET", "/api/connections")
            self.assertEqual(code, 200)
            self.assertEqual(json.loads(body), report)
            discover.assert_called_once_with()
            code, _, _ = self.request("GET", "/api/connections", headers={"Host": "evil.example"})
            self.assertEqual(code, 403)
            self.assertEqual(discover.call_count, 1)

    def test_controls_and_malformed_requests(self):
        code, _, body = self.request("POST", "/api/control", json.dumps({"action": "stop"}),
                                    {"Content-Type": "application/json"})
        self.assertEqual(code, 200)
        self.assertFalse(json.loads(body)["running"])
        code, _, _ = self.request("POST", "/api/control", "{", {"Content-Type": "application/json"})
        self.assertEqual(code, 400)
        code, _, _ = self.request("POST", "/api/control", "[]", {"Content-Type": "application/json"})
        self.assertEqual(code, 400)
        code, _, _ = self.request("POST", "/api/control", "{}", {"Content-Type": "text/plain"})
        self.assertEqual(code, 415)
        code, _, _ = self.request("POST", "/api/control", "x" * 1025, {"Content-Type": "application/json"})
        self.assertEqual(code, 413)

    def test_foreign_origin_and_dns_rebinding_hosts_are_rejected(self):
        code, _, _ = self.request("GET", "/api/status", headers={"Host": "evil.example"})
        self.assertEqual(code, 403)
        code, _, _ = self.request("POST", "/api/control", "{}", {
            "Content-Type": "application/json", "Origin": "https://evil.example"})
        self.assertEqual(code, 403)
        code, _, _ = self.request("GET", "/api/status", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(code, 403)
        code, _, _ = self.request("GET", "/api/status", headers={
            "Origin": "http://127.0.0.1:{}".format(self.server.server_port)})
        self.assertEqual(code, 200)

    def test_static_files_cannot_escape_web_root(self):
        code, _, body = self.request("GET", "/")
        self.assertEqual(code, 200)
        self.assertIn(b"Real ping", body)
        for path in ("/../secret.txt", "/%2e%2e/secret.txt", "/%00", "/..%5csecret.txt"):
            with self.subTest(path=path):
                code, _, body = self.request("GET", path)
                self.assertEqual(code, 404)
                self.assertNotIn(b"private", body)


if __name__ == "__main__":
    unittest.main()
