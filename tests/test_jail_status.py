"""Offline behavior for the shared Fail2Ban 1.0.2/1.1.x client contract."""

from pathlib import Path
import unittest
from unittest.mock import call, patch

import offenders_fail2ban as app
from offenders_events import parse_ban_event

import offenders_report as reports


def fixture(name):
    """Read captured or documented representative status output."""
    return (Path(__file__).parent / 'fixtures' / name).read_text()


def success(output):
    """Supply successful stdout through the existing command boundary."""
    return app.CommandResult(0, output, '')


class JailStatusTests(unittest.TestCase):
    """Required failures propagate; unavailable optional data remains explicit."""

    def test_global_status_and_zero_preserve_order(self):
        """Accept both fixtures and distinguish a valid empty list."""
        self.assertEqual(app.parse_jail_list(fixture('status.txt')), ['sshd', 'nginx-http-auth', 'recidive'])
        live = app.parse_jail_list(fixture('status-1.0.2-live.txt'))
        self.assertEqual(len(live), 8)
        self.assertEqual(live[:2], ['nginx-badbots', 'nginx-wp-login'])
        self.assertEqual(app.parse_jail_list('Status\n|- Number of jail: 0\n`- Jail list:\n'), [])

    def test_live_zero_and_representative_nonzero_status(self):
        """Preserve all counters, empty IPs, and normalized IPv4/IPv6 addresses."""
        zero = app.parse_jail_status(fixture('status-sshd-1.0.2-live.txt'), 'sshd')
        self.assertEqual(zero, app.JailStatus('sshd', 0, 0, 0, 0, ()))
        output = fixture('status-sshd.txt').replace('2606:4700::1111', '2606:4700:0:0:0:0:0:ABCD')
        status = app.parse_jail_status(output, 'sshd')
        self.assertEqual(status, app.JailStatus('sshd', 7, 150, 2, 42, ('8.8.8.8', '2606:4700::abcd')))

    def test_malformed_required_output_is_not_zero(self):
        """Missing, duplicate, invalid, and wrong-jail fields fail explicitly."""
        valid = fixture('status-sshd.txt')
        cases = ['', 'ERROR unavailable', valid.replace('sshd', 'other'),
                 valid.replace('Currently failed: 7', 'Currently failed: -1'),
                 valid.replace('8.8.8.8', '999.1.1.1'),
                 valid + '\nCurrently banned: 0']
        for label in ['Currently failed', 'Total failed', 'Currently banned', 'Total banned', 'Banned IP list']:
            cases.append('\n'.join(line for line in valid.splitlines() if label not in line))
        for output in cases:
            with self.subTest(output=output), self.assertRaises(app.Fail2BanParseError):
                app.parse_jail_status(output, 'sshd')
        for output in ['', 'Jail list:', 'Number of jail: 1\nJail list:',
                       'Number of jail: 2\nJail list: sshd, sshd',
                       'Number of jail: nope\nJail list:']:
            with self.subTest(output=output), self.assertRaises(app.Fail2BanParseError):
                app.parse_jail_list(output)

    def test_settings_and_exact_readonly_command_forms(self):
        """Use supported get commands and retain permanent-ban and zero values."""
        results = [success(fixture('status-sshd.txt')), success('-1\n'), success('600\n'), success('0\n')]
        with patch.object(app, 'run_host_command', side_effect=results) as command:
            status = app.get_jail_status('sshd')
        self.assertEqual((status.bantime, status.findtime, status.maxretry), (-1, 600, 0))
        self.assertIsNone(status.backend)
        self.assertIsNone(status.filter_name)
        self.assertEqual(status.setting_errors, {})
        self.assertEqual(command.call_args_list, [
            call(['fail2ban-client', 'status', 'sshd'], timeout=8, sudo=True),
            *[call(['fail2ban-client', 'get', 'sshd', name], timeout=8, sudo=True)
              for name in ['bantime', 'findtime', 'maxretry']],
        ])

    def test_optional_failures_do_not_corrupt_status(self):
        """Retain optional command taxonomy and parse failure alongside core data."""
        failure = app.CommandResult(1, '', 'unsupported', app.CommandFailure.NONZERO_EXIT)
        with patch.object(app, 'run_host_command', side_effect=[
            success(fixture('status-sshd.txt')), failure, success('malformed'), success('3')
        ]):
            status = app.get_jail_status('sshd')
        self.assertEqual(status.currently_banned, 2)
        self.assertEqual((status.bantime, status.findtime, status.maxretry), (None, None, 3))
        self.assertIs(status.setting_errors['bantime'].result, failure)
        self.assertIsInstance(status.setting_errors['findtime'], app.Fail2BanParseError)

    def test_report_propagates_required_command_and_parse_failures(self):
        """Both report paths reject failed global or jail status, including partial stdout."""
        failures = [app.CommandResult(None, fixture('status.txt'), 'diagnostic', kind)
                    for kind in app.CommandFailure]
        for lines in [[], ['2026-09-27 12:00:00 [sshd] Ban 8.8.8.8']]:
            for result in [*failures, success('malformed')]:
                for global_failure in [True, False]:
                    responses = [result] if global_failure else [success('Number of jail: 1\nJail list: sshd'), result]
                    expected = app.Fail2BanCommandError if result.failure else app.Fail2BanParseError
                    with self.subTest(lines=lines, result=result, global_failure=global_failure):
                        with patch.object(reports, 'collect_ban_events', return_value=[parse_ban_event(line) for line in lines]), patch.object(app, 'run_host_command', side_effect=responses) as command:
                            with self.assertRaises(expected) as caught:
                                reports.build_report(period="all")
                        self.assertEqual(command.call_args_list[0], call(['fail2ban-client', 'status'], timeout=8, sudo=True))
                        if result.failure:
                            self.assertIs(caught.exception.result, result)

    def test_report_valid_zero_and_ordered_structured_data(self):
        """Reports retain zero-jail success and structured status in daemon order."""
        for statuses in [[], [app.JailStatus('z', 0, 0, 0, 0, ()), app.JailStatus('a', 1, 2, 3, 4, ())]]:
            with patch.object(reports, 'collect_ban_events', return_value=[]), patch.object(reports, 'get_jail_list', return_value=[s.name for s in statuses]), patch.object(reports, 'get_jail_status', side_effect=statuses):
                report = reports.build_report(period="all")
            self.assertEqual(report.jail_statuses, statuses)
            self.assertEqual(report.jail_list, [s.name for s in statuses])
            self.assertEqual(report.bans_per_jail, sorted([(s.name, s.currently_banned) for s in statuses], key=lambda pair: pair[1], reverse=True))
