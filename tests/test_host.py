"""Fixture-driven host snapshot contracts; no host commands or services needed."""
from pathlib import Path
import unittest
from unittest.mock import call, patch

import offenders_host as host
from offenders_fail2ban import CommandFailure, CommandResult

FIXTURES = Path(__file__).parent / "fixtures"


def systemd_output():
    """Return every fixed catalog identity, including absent aliases."""
    states = {"ssh.service": ("loaded", "active", "running"),
              "nginx.service": ("loaded", "active", "running"),
              "caddy.service": ("loaded", "inactive", "dead"),
              "dovecot.service": ("loaded", "active", "running")}
    return "\n\n".join(
        f"Id={unit}\nLoadState={load}\nActiveState={active}\nSubState={sub}"
        for unit in host.UNITS
        for load, active, sub in [states.get(unit, ("not-found", "inactive", "dead"))])


class HostTests(unittest.TestCase):
    """Prove endpoint evidence, conservative service states, and command bounds."""

    def setUp(self):
        """Read representative numeric ss output from an offline fixture."""
        self.output = (FIXTURES / "host_ss.txt").read_text()

    def snapshot(self, primary=None, owners=None, systemd=None):
        """Fake only the existing runner seam and return its recorded calls."""
        results = [primary or CommandResult(0, self.output, "")]
        if not results[0].failure:
            results.append(owners or CommandResult(0, self.output, ""))
        results.append(systemd or CommandResult(0, systemd_output(), ""))
        with patch.object(host, "run_host_command", side_effect=results) as runner:
            inventory = host.discover_host_inventory()
        return inventory, runner.call_args_list

    def test_parser_bindings_owners_and_determinism(self):
        """IPv4/IPv6, scoped, wildcard, UDP and unknown binds retain facts."""
        listeners, errors = host.parse_listeners(self.output)
        self.assertEqual(errors, ())
        by_address = {row.raw_address: row for row in listeners}
        for address in ("127.3.2.1", "::1"):
            self.assertEqual(by_address[address].exposure, "loopback")
        for address in ("0.0.0.0", "::", "*", "fe80::1%eth0", "10.0.0.1", "fd00::1"):
            self.assertEqual(by_address[address].exposure, "non_loopback")
        self.assertEqual(by_address["fe80::1%eth0"].address, "fe80::1")
        self.assertEqual(by_address["fe80::1%eth0"].scope, "eth0")
        self.assertEqual(by_address["mystery"].exposure, "unknown")
        self.assertIsNone(by_address["mystery"].port)
        self.assertEqual(by_address["0.0.0.0"].owners,
                         (host.ProcessOwner("nginx", 20), host.ProcessOwner("nginx", 21)))
        self.assertEqual(by_address["*"].protocol, "udp")
        reversed_rows = "\n".join(reversed(self.output.splitlines()))
        self.assertEqual(host.parse_listeners(reversed_rows + "\n" + self.output)[0], listeners)

    def test_acquisition_and_family_states(self):
        """Only fixed bounded commands run; process names determine families."""
        inventory, calls = self.snapshot()
        self.assertEqual(calls, [
            call(["ss", "-H", "-lntu"], timeout=8, sudo=False),
            call(["ss", "-H", "-lntup"], timeout=8, sudo=True),
            call(list(host.SYSTEMCTL_ARGS), timeout=8, sudo=False)])
        states = {row.family: row.state for row in inventory.services}
        self.assertEqual(states, {"ssh": "listening_loopback", "nginx": "listening_non_loopback",
                                 "caddy": "installed_inactive", "dovecot": "active_no_matching_listener_observed"})
        ssh = next(row for row in inventory.services if row.family == "ssh")
        self.assertEqual({row.port for row in ssh.listeners}, {2222})
        self.assertTrue(any(row.port == 22 and row.owners[0].name == "docker-proxy"
                            for row in inventory.listeners))
        self.assertEqual(inventory.systemd.status, "successful")
        self.assertEqual(ssh.units, (host.UnitState("ssh.service", "loaded", "active", "running"),))

    def test_failures_preserve_source_boundaries(self):
        """Optional failures preserve canonical endpoints and bounded reasons."""
        denied = CommandResult(1, "ignored", "denied" * 200, CommandFailure.NONZERO_EXIT)
        inventory, _ = self.snapshot(owners=denied, systemd=denied)
        self.assertEqual(len(inventory.listeners), len(host.parse_listeners(self.output)[0]))
        self.assertTrue(all(not row.owners for row in inventory.listeners))
        self.assertEqual(inventory.services, ())
        self.assertEqual(inventory.ownership.failure, CommandFailure.NONZERO_EXIT)
        self.assertEqual(len(inventory.ownership.detail), host.DETAIL_LIMIT)
        self.assertEqual(inventory.systemd.status, "unavailable")
        inventory, _ = self.snapshot(owners=denied)
        self.assertEqual(next(row.state for row in inventory.services if row.family == "ssh"),
                         "active_listener_unknown")
        missing = CommandResult(None, "", "", CommandFailure.NOT_FOUND, "missing ss")
        inventory, calls = self.snapshot(primary=missing)
        self.assertEqual(len(calls), 2)
        self.assertEqual(inventory.listeners, ())
        self.assertEqual(inventory.primary.failure, CommandFailure.NOT_FOUND)
        self.assertEqual(inventory.primary.status, "unavailable")
        self.assertEqual(inventory.ownership.status, "not_attempted")

    def test_empty_partial_and_unowned_are_distinct(self):
        """Malformed lines and missing owner visibility never become false absence."""
        empty = CommandResult(0, "", "")
        inventory, _ = self.snapshot(primary=empty, owners=empty)
        self.assertEqual(inventory.listeners, ())
        self.assertEqual(inventory.primary.status, "successful")
        self.assertEqual(inventory.services[0].state, "active_no_matching_listener_observed")
        malformed = CommandResult(0, self.output + "\nbad " + "x" * 1000, "")
        inventory, _ = self.snapshot(primary=malformed)
        self.assertEqual(inventory.primary.status, "partial")
        self.assertLessEqual(len(inventory.primary.diagnostics[0]), host.DETAIL_LIMIT)
        self.assertEqual(inventory.services[-1].state, "active_listener_unknown")
        inventory, _ = self.snapshot(owners=empty)
        self.assertEqual(inventory.ownership.status, "partial")
        self.assertEqual(inventory.services[0].state, "active_listener_unknown")

    def test_manual_service_and_unknown_listener_exposure(self):
        """Process evidence survives missing systemd and unknown bind syntax."""
        failure = CommandResult(1, "", "no systemd", CommandFailure.NONZERO_EXIT)
        inventory, _ = self.snapshot(systemd=failure)
        self.assertEqual({row.family for row in inventory.services}, {"ssh", "nginx"})
        unknown = CommandResult(0, 'tcp LISTEN 0 10 mystery:42 *:* users:(("sshd",pid=9,fd=3))', "")
        inventory, _ = self.snapshot(primary=unknown, owners=unknown, systemd=failure)
        self.assertEqual(inventory.services[0].state, "active_listener_unknown")
        inventory, _ = self.snapshot(systemd=CommandResult(0, "Id=ssh.service", ""))
        self.assertEqual(inventory.systemd.status, "partial")
        self.assertEqual(inventory.services[0].units, ())


class NamespaceTests(unittest.TestCase):
    """Only a stable PID authorizes comparison of narrowly read namespace links."""

    PID_CALL = call(['systemctl', 'show', '--property=MainPID', '--value',
                     'fail2ban.service'], timeout=8, sudo=False)
    DAEMON_CALL = call(['/usr/bin/readlink', '/proc/123/ns/net'], timeout=8, sudo=True)

    def test_same_and_different_retain_bracket_identities(self):
        """Read self unprivileged, daemon privileged, then immediately recheck PID."""
        for daemon, state in [('net:[42]', host.NamespaceState.SAME),
                              ('net:[43]', host.NamespaceState.DIFFERENT)]:
            responses = [CommandResult(0, text, '') for text in ['123\n', daemon + '\n', '123\n']]
            with self.subTest(daemon=daemon), patch.object(host, 'run_host_command', side_effect=responses) as runner:
                with patch.object(host.os, 'readlink', return_value='net:[42]') as readlink:
                    runner.attach_mock(readlink, 'self_link')
                    result = host.get_fail2ban_namespace()
            self.assertEqual(result, host.NetworkNamespaceIdentity(state, 123, 'net:[42]', daemon))
            self.assertEqual(runner.mock_calls, [self.PID_CALL, call.self_link('/proc/self/ns/net'),
                                                self.DAEMON_CALL, self.PID_CALL])

    def test_command_or_pid_unavailable_never_reads_proc(self):
        """Failed systemd and malformed/non-running PIDs cannot become mismatch."""
        failed = CommandResult(1, '123\n', 'denied', CommandFailure.NONZERO_EXIT)
        results = [failed, *[CommandResult(0, text, '') for text in
                            ['', '0\n', '-1', '0123', 'MainPID=123', '1\n2\n', '123\n\n',
                             '2147483648', '9' * 11, '123/../1', '123;id']]]
        for response in results:
            with self.subTest(response=response), patch.object(host, 'run_host_command', return_value=response) as runner:
                with patch.object(host.os, 'readlink') as readlink:
                    result = host.get_fail2ban_namespace()
            self.assertEqual(result.state, host.NamespaceState.UNAVAILABLE)
            self.assertIsNone(result.main_pid)
            self.assertEqual(runner.call_args_list, [self.PID_CALL])
            readlink.assert_not_called()

    def test_self_namespace_unavailable_prevents_privileged_read(self):
        """Self read failure or malformed identity never authorizes daemon reads."""
        for identity in [FileNotFoundError('gone'), PermissionError('denied'),
                         'not-a-namespace', 'net:[0]', 'net:[42]\n']:
            with self.subTest(identity=identity), patch.object(host, 'run_host_command', return_value=CommandResult(0, '123', '')) as runner:
                with patch.object(host.os, 'readlink', side_effect=[identity]) as readlink:
                    result = host.get_fail2ban_namespace()
            self.assertEqual(result, host.NetworkNamespaceIdentity(host.NamespaceState.UNAVAILABLE, 123))
            self.assertEqual(runner.call_args_list, [self.PID_CALL])
            readlink.assert_called_once_with('/proc/self/ns/net')

    def test_privileged_daemon_failure_or_invalid_output_is_unavailable(self):
        """Denied, disappeared, timed out or malformed daemon evidence is discarded."""
        failed = [CommandResult(1, 'net:[42]\n', 'denied', CommandFailure.NONZERO_EXIT),
                  CommandResult(1, '', 'gone', CommandFailure.NONZERO_EXIT),
                  CommandResult(None, 'net:[42]\n', '', CommandFailure.TIMEOUT)]
        invalid = [CommandResult(0, text, '') for text in
                   ['', 'not-a-namespace', 'net:[0]', 'net:[42]\n\n', 'net:[42]\nnet:[43]',
                    ' net:[42]', 'net:[123456789012345678901]']]
        for response in failed + invalid:
            responses = [CommandResult(0, '123', ''), response, CommandResult(0, '123', '')]
            with self.subTest(response=response), patch.object(host, 'run_host_command', side_effect=responses) as runner:
                with patch.object(host.os, 'readlink', return_value='net:[42]') as readlink:
                    result = host.get_fail2ban_namespace()
            self.assertEqual(result, host.NetworkNamespaceIdentity(host.NamespaceState.UNAVAILABLE, 123, 'net:[42]'))
            self.assertEqual(runner.call_args_list, [self.PID_CALL, self.DAEMON_CALL, self.PID_CALL])
            readlink.assert_called_once_with('/proc/self/ns/net')

    def test_changed_or_unreadable_second_pid_discards_daemon_identity(self):
        """Neither matching nor differing identities survive an unstable PID read."""
        closing = [CommandResult(1, '123\n', 'denied', CommandFailure.NONZERO_EXIT),
                   *[CommandResult(0, text, '') for text in
                     ['124\n', '0\n', '', 'MainPID=123', '123\n\n', '2147483648']]]
        for daemon in ['net:[42]\n', 'net:[43]\n']:
            for response in closing:
                responses = [CommandResult(0, '123\n', ''), CommandResult(0, daemon, ''), response]
                with self.subTest(daemon=daemon, response=response), patch.object(host, 'run_host_command', side_effect=responses) as runner:
                    with patch.object(host.os, 'readlink', return_value='net:[42]'):
                        result = host.get_fail2ban_namespace()
                self.assertEqual(result, host.NetworkNamespaceIdentity(host.NamespaceState.UNAVAILABLE, 123, 'net:[42]'))
                self.assertEqual(runner.call_args_list, [self.PID_CALL, self.DAEMON_CALL, self.PID_CALL])

    def test_exact_privileged_process_argv(self):
        """The real runner adds only sudo -n to one validated daemon namespace path."""
        from subprocess import CompletedProcess, DEVNULL
        responses = [CompletedProcess([], 0, text, '') for text in
                     ['123\n', 'net:[42]\n', '123\n']]
        with patch('offenders_fail2ban.subprocess.run', side_effect=responses) as process:
            with patch.object(host.os, 'readlink', return_value='net:[42]') as readlink:
                result = host.get_fail2ban_namespace()
        self.assertEqual(result.state, host.NamespaceState.SAME)
        pid_argv = self.PID_CALL.args[0]
        options = dict(stdin=DEVNULL, capture_output=True, text=True, encoding='utf-8',
                       errors='replace', timeout=8, check=False)
        self.assertEqual(process.call_args_list, [
            call(pid_argv, **options),
            call(['sudo', '-n', '/usr/bin/readlink', '/proc/123/ns/net'], **options),
            call(pid_argv, **options)])
        readlink.assert_called_once_with('/proc/self/ns/net')
