"""Offline behavioral coverage for the bounded host-command boundary."""

import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

import offenders


class CommandTests(unittest.TestCase):
    """Use real child processes and a fake sudo, never host privileges."""

    def test_success_preserves_streams_and_literal_arguments(self):
        """Arguments remain literal and stdin is closed for non-interactive use."""
        result = offenders.run_host_command(
            [sys.executable, "-c", "import sys; print(sys.argv[1]); print(sys.stdin.read()); print('warning', file=sys.stderr)", "$(false); *"],
            timeout=2,
        )
        self.assertIsNone(result.failure)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "$(false); *\n\n")
        self.assertEqual(result.stderr, "warning\n")

    def test_missing_and_unexecutable_commands(self):
        """Missing programs and OS execution errors have distinct outcomes."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "command"
            missing = offenders.run_host_command([str(path)], timeout=2)
            self.assertEqual(missing.failure, offenders.CommandFailure.NOT_FOUND)
            self.assertIsNone(missing.returncode)
            path.write_text("not executable", encoding="utf-8")
            denied = offenders.run_host_command([str(path)], timeout=2)
            self.assertEqual(denied.failure, offenders.CommandFailure.EXECUTION)
            self.assertTrue(denied.detail)

    def test_timeout_retains_partial_output(self):
        """A blocked child is terminated while captured output remains available."""
        result = offenders.run_host_command(
            [sys.executable, "-c", "import time; print('partial', flush=True); time.sleep(30)"],
            timeout=0.5,
        )
        self.assertEqual(result.failure, offenders.CommandFailure.TIMEOUT)
        self.assertIsNone(result.returncode)
        self.assertEqual(result.stdout, "partial\n")

    def test_nonzero_exit_preserves_both_streams(self):
        """Failed commands retain their exit status and diagnostics separately."""
        result = offenders.run_host_command(
            [sys.executable, "-c", "import sys; print('output'); print('error', file=sys.stderr); sys.exit(7)"],
            timeout=2,
        )
        self.assertEqual(result.failure, offenders.CommandFailure.NONZERO_EXIT)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (7, "output\n", "error\n"))

    def test_sudo_denied_is_noninteractive(self):
        """A fake sudo checks -n and reports denial without invoking real sudo."""
        with tempfile.TemporaryDirectory() as directory:
            sudo = Path(directory) / "sudo"
            sudo.write_text(f"#!{sys.executable}\nimport sys\nassert sys.argv[1:] == ['-n', 'fail2ban-client', 'status']\nprint('sudo: a password is required', file=sys.stderr)\nsys.exit(1)\n", encoding="utf-8")
            sudo.chmod(0o755)
            with patch.dict(os.environ, {"PATH": directory}):
                result = offenders.run_host_command(["fail2ban-client", "status"], timeout=2, sudo=True)
            self.assertEqual(result.failure, offenders.CommandFailure.NONZERO_EXIT)
            self.assertEqual(result.returncode, 1)
            self.assertIn("password is required", result.stderr)

    def test_invalid_timeout_rejected(self):
        """Reject deadlines that cannot bound execution."""
        for timeout in [0, -1, float("inf"), float("nan")]:
            with self.subTest(timeout=timeout), self.assertRaises(ValueError):
                offenders.run_host_command([sys.executable], timeout=timeout)

    def test_status_failure_is_logged_and_not_parsed(self):
        """Failed output cannot masquerade as a valid jail status."""
        result = offenders.CommandResult(1, "Jail list: sshd", "denied", offenders.CommandFailure.NONZERO_EXIT)
        with patch.object(offenders, "run_host_command", return_value=result) as command:
            with self.assertLogs(offenders.__name__, level="WARNING") as logs:
                self.assertEqual(offenders.get_jail_list(), [])
            command.assert_called_once_with(["fail2ban-client", "status"], timeout=8, sudo=True)
            self.assertIn("denied", logs.output[0])
