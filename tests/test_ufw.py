"""Protect qualified active/managed/live UFW facts and fixed read commands."""
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import call, patch

import offenders_ufw as ufw
from offenders_fail2ban import CommandFailure, CommandResult, Fail2BanParseError

FIXTURES = Path(__file__).parent / 'fixtures'
STOCK = ('if [ -n "<application>" ] && ufw app info "<application>"\n'
         'then\nufw <add> <blocktype> from <ip> to <destination> app "<application>" comment "<comment>"\n'
         'else\nufw <add> <blocktype> from <ip> to <destination> comment "<comment>"\nfi\n<kill>')
PROPERTIES = {
    'actionban': STOCK, 'name': 'guard', 'add': 'prepend', 'blocktype': 'reject',
    'destination': 'any', 'application': '',
    'comment': 'by Fail2Ban after <failures> attempts against <name>', 'kill': '', 'kill-mode': '',
}


class UfwTests(unittest.TestCase):
    """Verify material boundaries using one actual capture per output contract."""

    def setUp(self):
        """Read documentation-address captures from disposable Ubuntu 24.04."""
        self.status_text = (FIXTURES / 'ufw-status.txt').read_text()
        self.added_text = (FIXTURES / 'ufw-added.txt').read_text()
        self.save_text = {version: (FIXTURES / f'ufw-v{version}.save').read_text() for version in (4, 6)}
        self.status = ufw.parse_ufw_status(self.status_text)
        self.added = ufw.parse_ufw_added(self.added_text)
        self.action = ufw.classify_ufw_action(PROPERTIES)
        self.assertIsNotNone(self.action)

    def evidence(self, ip='192.0.2.1', action=None, status=None, live=None, added=None):
        """Exercise the public normalized parser/verifier seam."""
        action = action or self.action
        snapshot = ufw.parse_ufw_save(self.save_text[action.ip_version] if live is None else live, action.ip_version)
        return ufw.verify_ufw_ban(action, ip, self.status if status is None else ufw.parse_ufw_status(status),
                                  self.added if added is None else ufw.parse_ufw_added(added), snapshot)

    def test_stock_runtime_shapes_and_optional_kill(self):
        """Raw/static-resolved stock shapes qualify; killing is never verified."""
        runtime = STOCK.replace('<kill>', '').replace('<application>', '').replace('<add>', 'prepend')
        runtime = runtime.replace('<blocktype>', 'reject').replace('<destination>', 'any')
        runtime = runtime.replace('<comment>', PROPERTIES['comment'].replace('<name>', 'guard'))
        self.assertEqual(ufw.classify_ufw_action({**PROPERTIES, 'actionban': runtime}), self.action)
        for kill, mode in [('ss -K dst "[<ip>]"', 'ss'), ('conntrack -D -s "<ip>"', 'conntrack'),
                           ('cutter "<ip>"', '')]:
            with self.subTest(kill=kill):
                action = ufw.classify_ufw_action({**PROPERTIES, 'kill': kill, 'kill-mode': mode})
                self.assertIsNotNone(action)
                self.assertEqual(self.evidence(action=action).connection_termination, 'not-verified')
        self.assertEqual(self.evidence().connection_termination, 'not-requested')

    def test_custom_compound_and_unresolved_actions_fail_closed(self):
        """An action name, shell extension or unsafe scope cannot establish stock compatibility."""
        for change in [{'actionban': 'ufw reject from <ip>'}, {'actionban': STOCK + '\nother'},
                       {'actionban': STOCK.replace('ufw <add>', 'wrapper ufw <add>')},
                       {'actionban': STOCK.replace('else', 'else; other')},
                       {'add': 'insert 1'}, {'blocktype': 'allow'}, {'destination': 'example.org'},
                       {'application': 'app; other'}, {'application': 'all'}, {'application': '22'},
                       {'application': 'A' * 65}, {'comment': 'custom <failures>'},
                       {'comment': 'literal $(id)'}, {'actionban': STOCK.replace('from <ip>', 'from any')},
                       {'actionban': STOCK.replace('fi', 'fi\nother', 1)}]:
            with self.subTest(change=change):
                self.assertIsNone(ufw.classify_ufw_action({**PROPERTIES, **change}))
        for change in [{'destination': '<unknown>'}, {'comment': '<matches>'}, {'comment': 'banned <ip>'},
                       {'application': '<ip>'}, {'application': '<failures>'}, {'name': '<ip>'},
                       {'application': '<application>'}]:
            with self.subTest(change=change), self.assertRaises(Fail2BanParseError):
                ufw.classify_ufw_action({**PROPERTIES, **change})

    def test_stock_quote_boundaries_are_preserved(self):
        """An unquoted static metacharacter changes shell semantics and is unsupported."""
        props = {**PROPERTIES, 'comment': ';'}
        self.assertIsNotNone(ufw.classify_ufw_action(props))
        unquoted = STOCK.replace('comment "<comment>"', 'comment <comment>')
        self.assertIsNone(ufw.classify_ufw_action({**props, 'actionban': unquoted}))

    def test_ipv4_ipv6_deny_reject_destination_and_application(self):
        """Real captured rows and rules prove both families and supported scopes."""
        cases = [('192.0.2.1', {}), ('192.0.2.3', {'destination': '198.51.100.0/24', 'comment': 'static evidence'}),
                 ('192.0.2.2', {'blocktype': 'deny', 'application': 'Evidence App'}),
                 ('2001:db8::2', {'blocktype': 'deny', 'comment': ''}),
                 ('2001:db8::1', {'blocktype': 'deny', 'destination': '2001:db8::10',
                                  'application': 'Evidence App', 'comment': 'static evidence'})]
        for ip, change in cases:
            with self.subTest(ip=ip):
                action = ufw.classify_ufw_action({**PROPERTIES, **change}, family='inet6' if ':' in ip else 'inet4')
                result = self.evidence(ip, action)
                self.assertEqual((result.outcome, result.reason, result.managed_rule, result.live_rule),
                                 ('confirmed', 'entry-observed', True, True))
        # UFW permits a numeric-leading profile when it is not a bare port.
        numeric = ufw.classify_ufw_action({**PROPERTIES, 'blocktype': 'deny', 'application': '3App'})
        self.assertEqual(self.evidence('192.0.2.2', numeric,
                         added=self.added_text.replace('Evidence App', '3App'),
                         live=self.save_text[4].replace('dapp_Evidence%20App', 'dapp_3App')).outcome, 'confirmed')

    def test_inactive_missing_frontend_and_missing_live_are_distinct(self):
        """Neither one evidence layer nor installed-but-inactive UFW can confirm."""
        inactive = self.evidence(status='Status: inactive\n')
        self.assertEqual((inactive.outcome, inactive.reason), ('missing', 'ufw-inactive'))
        for status, live, reason, managed, underlying in [
            (ufw.ADDED_HEADER + '\n(None)\n', None, 'ufw-rule-absent', False, True),
            (None, '*filter\n:ufw-user-input - [0:0]\nCOMMIT\n', 'ufw-live-rule-absent', True, False),
            (None, '', 'ufw-live-rule-absent', True, False),
        ]:
            result = self.evidence(added=status, live=live)
            self.assertEqual((result.outcome, result.reason, result.managed_rule, result.live_rule),
                             ('missing', reason, managed, underlying))

    def test_frontend_scope_target_comment_and_count_must_agree(self):
        """Exact jail/name and bounded decimal count replace only the stock dynamic field."""
        for change in [{'destination': '198.51.100.10'}, {'application': 'Other App'},
                       {'blocktype': 'deny'}, {'comment': 'different static comment'}]:
            action = ufw.classify_ufw_action({**PROPERTIES, **change})
            self.assertEqual(self.evidence(action=action).outcome, 'missing')
        for comment in ['', 'by Fail2Ban after x attempts against guard',
                        'by Fail2Ban after 3 attempts against other',
                        'by Fail2Ban after ' + '9' * 11 + ' attempts against guard']:
            text = self.added_text.replace('by Fail2Ban after 3 attempts against guard', comment)
            if not comment:
                text = text.replace(" comment ''", '')
            self.assertEqual(self.evidence(added=text).outcome, 'missing')
        for count in ['0', '1234567890']:
            text = self.added_text.replace('after 3 attempts', f'after {count} attempts')
            self.assertEqual(self.evidence(added=text).outcome, 'confirmed')

    def test_same_ip_wrong_live_scope_target_chain_or_network_cannot_confirm(self):
        """UFW chain identity and both scopes survive normalization of live save facts."""
        for old, new in [('-s 192.0.2.1/32', '-s 192.0.2.0/24'),
                         ('-s 192.0.2.1/32', '-s 192.0.2.1/32 -d 198.51.100.10/32'),
                         ('-j REJECT --reject-with icmp-port-unreachable', '-j DROP'),
                         ('ufw-user-input', 'ufw6-user-input')]:
            with self.subTest(new=new):
                self.assertEqual(self.evidence(live=self.save_text[4].replace(old, new)).outcome, 'missing')
        app = ufw.classify_ufw_action({**PROPERTIES, 'blocktype': 'deny', 'application': 'Evidence App'})
        for old, new in [('dapp_Evidence%20App', 'dapp_Other%20App'),
                         ('-s 192.0.2.2/32', '-s 192.0.2.2/32 -d 198.51.100.10/32'),
                         ('-j DROP', '-j REJECT')]:
            with self.subTest(new=new):
                self.assertEqual(self.evidence('192.0.2.2', app, live=self.save_text[4].replace(old, new)).outcome, 'missing')

    def test_numeric_application_row_cannot_prove_a_destination_rule(self):
        """The explicit app token defeats the permanently retained baseline counterexample."""
        action = ufw.classify_ufw_action({**PROPERTIES, 'blocktype': 'deny', 'destination': '198.51.100.10'})
        # The capture already contains the unrelated destination-only live rule.
        self.assertNotEqual(self.evidence('192.0.2.220', action).outcome, 'confirmed')
        app = ufw.classify_ufw_action({**PROPERTIES, 'blocktype': 'deny', 'application': '198.51.100.10'})
        self.assertEqual(self.evidence('192.0.2.220', app).outcome, 'confirmed')
        self.assertEqual(self.evidence('192.0.2.221', action).outcome, 'confirmed')
        # A destination row also cannot satisfy an app action with unrelated live app evidence.
        app_rule = next(line for line in self.save_text[4].splitlines() if '-s 192.0.2.220/32 -p tcp' in line)
        live = self.save_text[4].replace('COMMIT\n', app_rule.replace('192.0.2.220', '192.0.2.221') + '\nCOMMIT\n')
        self.assertNotEqual(self.evidence('192.0.2.221', app, live=live).outcome, 'confirmed')

    def test_status_rows_never_prove_managed_rule_identity(self):
        """Only state is retained from status, even when a rendered row appears to agree."""
        self.assertEqual(self.evidence(status='Status: active\n').outcome, self.evidence().outcome)
        empty = ufw.ADDED_HEADER + '\n(None)\n'
        result = self.evidence(added=empty)
        self.assertEqual((result.outcome, result.managed_rule, result.live_rule), ('missing', False, True))

    def test_canonical_omitted_to_any_is_not_a_general_optional_scope(self):
        """Only source-only/comment normalization may omit to; scope tokens never move."""
        explicit = self.added_text.replace('ufw reject from 192.0.2.1 comment',
                                           'ufw reject from 192.0.2.1 to any comment')
        self.assertEqual(self.evidence(added=explicit).outcome, 'confirmed')
        for suffix in ["app 'Evidence App'", 'port 22', 'proto tcp', 'to', 'to any app',
                       "comment 'by Fail2Ban after 3 attempts against guard' port 22"]:
            text = ufw.ADDED_HEADER + '\nufw reject from 192.0.2.1 ' + suffix + '\n'
            with self.subTest(suffix=suffix):
                self.assertEqual(self.evidence(added=text).outcome, 'unverifiable')

    def test_localized_malformed_oversized_and_opaque_output_is_unverifiable(self):
        """Unfamiliar output and rule restrictions cannot prove authoritative absence."""
        for text in ['Estado: activo\n', self.status_text.replace('Action', 'Acción'),
                     'Status: unknown\n', 'Status: active\nextra\n',
                     'x' * (ufw.UFW_TEXT_LIMIT + 1), 'é' * (ufw.UFW_TEXT_LIMIT // 2 + 1)]:
            with self.subTest(text=text[:50]):
                self.assertEqual(self.evidence(status=text).outcome, 'unverifiable')
        for text in ['', ufw.ADDED_HEADER, 'Reglas añadidas:\n(None)\n', self.added_text + 'garbage\n',
                     self.added_text.replace("'Evidence App'", "'Evidence App"),
                     self.added_text.replace('from 192.0.2.1', 'from invalid'),
                     self.added_text.replace('from 192.0.2.1', 'from 192.0.2.1 port 22'),
                     self.added_text.replace('ufw reject from 192.0.2.1', 'ufw reject out from 192.0.2.1')]:
            with self.subTest(text=text[:50]):
                self.assertEqual(self.evidence(added=text).outcome, 'unverifiable')
        for text in ['garbage', self.save_text[4].replace('COMMIT', ''),
                     self.save_text[4] + self.save_text[4],
                     self.save_text[4].replace('-s 192.0.2.1/32', '-s "bad'),
                     self.save_text[4].replace('-s 192.0.2.1/32', '-s invalid'),
                     self.save_text[4].replace('-s 192.0.2.1/32', '! -s 192.0.2.1/32'),
                     self.save_text[4].replace('-s 192.0.2.1/32', '-s 192.0.2.1/32 -i eth0')]:
            with self.subTest(text=text[:50]):
                self.assertEqual(self.evidence(live=text).outcome, 'unverifiable')
        app = ufw.classify_ufw_action({**PROPERTIES, 'blocktype': 'deny', 'application': 'Evidence App'})
        invalid_ports = self.save_text[4].replace('--dports 22,2222', '--dports 99999').replace('--dport 53', '--dport 99999')
        self.assertEqual(self.evidence('192.0.2.2', app, live=invalid_ports).outcome, 'unverifiable')

    def test_fixed_reads_relevant_family_deduplication_and_failures(self):
        """Only status, show added and bare relevant-family save binaries can reach sudo."""
        v6 = ufw.classify_ufw_action(PROPERTIES, family='inet6')
        for actions, versions in [([self.action, self.action], [4]), ([v6, v6], [6]),
                                  ([self.action, v6, self.action], [4, 6])]:
            results = [CommandResult(0, self.status_text, ''), CommandResult(0, self.added_text, '')]
            results += [CommandResult(0, self.save_text[v], '') for v in versions]
            with patch.object(ufw, 'run_host_command', side_effect=results) as runner:
                status = ufw.read_ufw_status()
                added = ufw.read_ufw_added()
                saves = ufw.read_ufw_saves(actions)
            expected = [call(['ufw', 'status'], timeout=8, sudo=True), call(['ufw', 'show', 'added'], timeout=8, sudo=True)]
            expected += [call(['iptables-save' if v == 4 else 'ip6tables-save'], timeout=8, sudo=True) for v in versions]
            self.assertEqual(runner.call_args_list, expected)
            self.assertFalse(status.reason)
            self.assertFalse(added.reason)
            self.assertEqual(set(saves), set(versions))
        failure = CommandResult(1, self.status_text, 'permission denied', CommandFailure.NONZERO_EXIT)
        with patch.object(ufw, 'run_host_command', return_value=failure):
            status = ufw.read_ufw_status()
            added = ufw.read_ufw_added()
            live = ufw.read_ufw_saves([self.action])[4]
        self.assertIsNone(status.active)
        self.assertEqual(ufw.verify_ufw_ban(self.action, '192.0.2.1', status, added, live).outcome, 'unverifiable')
        self.assertEqual(ufw.verify_ufw_ban(self.action, '192.0.2.1', self.status, added,
                                         ufw.parse_ufw_save(self.save_text[4], 4)).outcome, 'unverifiable')
        with patch.object(ufw, 'run_host_command') as runner:
            self.assertTrue(ufw.read_ufw_saves([replace(self.action, ip_version=7)])[7].reason)
            ufw.read_ufw_saves([])
        runner.assert_not_called()


if __name__ == '__main__':
    unittest.main()
