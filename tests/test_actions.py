"""Runtime action facts and bounded static resolution; no firewall acquisition."""
from pathlib import Path
import unittest
from unittest.mock import call, patch

import offenders_fail2ban as f2b

FIXTURES = Path(__file__).parent / 'fixtures'


class ActionTests(unittest.TestCase):
    """Protect the upstream text contract and privileged selector boundaries."""

    def test_action_lists(self):
        """Empty sentinel, one action, and comma-separated actions are distinct."""
        self.assertEqual(f2b.parse_jail_actions('No actions for jail sshd\n', 'sshd'), ())
        self.assertEqual(f2b.parse_jail_actions('The jail sshd has the following actions:\nguard-main\n', 'sshd'), ('guard-main',))
        self.assertEqual(f2b.parse_jail_actions((FIXTURES / 'actions.txt').read_text(), 'sshd'), ('guard-main', 'notify-mail'))

    def test_malformed_or_unsafe_lists_are_not_empty(self):
        """Wrong identity, ambiguity, unsafe selectors, and limits fail closed."""
        header = 'The jail sshd has the following actions:\n'
        for output in ['', 'No actions for jail other', header, header + 'guard-main\nextra',
                       header + 'guard-main, guard-main', header + 'guard-main, ',
                       header.replace('sshd', 'other') + 'guard-main',
                       header + '$(id)', header + '-option', header + 'a' * 129,
                       header + ', '.join(f'action-{i}' for i in range(33)),
                       'x' * (f2b.ACTION_TEXT_LIMIT + 1)]:
            with self.subTest(output=output[:100]), self.assertRaises(f2b.Fail2BanParseError):
                f2b.parse_jail_actions(output, 'sshd')

    def test_property_list_identity_and_public_names(self):
        """Validate both header identities without treating returned names as authority."""
        output = (FIXTURES / 'actionproperties.txt').read_text()
        self.assertEqual(f2b.parse_action_properties(output, 'sshd', 'guard-main'),
                         ('actionban', 'addr_set', 'addr_set?family=inet6', 'name', 'timeout'))
        self.assertEqual(f2b.parse_action_properties('No properties for jail sshd action guard-main\n', 'sshd', 'guard-main'), ())
        for bad in [output.replace('sshd', 'other'), output.replace('guard-main', 'other'),
                    output + 'extra\n', output.replace('timeout', 'name'),
                    output.replace('timeout', '__dict__'), output.replace('timeout', 'bad name'),
                    output.splitlines()[0], 'x' * (f2b.ACTION_TEXT_LIMIT + 1)]:
            with self.subTest(output=bad[:100]), self.assertRaises(f2b.Fail2BanParseError):
                f2b.parse_action_properties(bad, 'sshd', 'guard-main')

    def test_exact_read_commands_and_raw_property_normalization(self):
        """All Fail2Ban reads use sudo and preserve meaningful property whitespace."""
        results = [f2b.CommandResult(0, (FIXTURES / name).read_text(), '')
                   for name in ('actions.txt', 'actionproperties.txt')]
        results.append(f2b.CommandResult(0, 'addr6-set-<name>\n', ''))
        with patch.object(f2b, 'run_host_command', side_effect=results) as runner:
            f2b.get_jail_actions('sshd')
            f2b.get_action_properties('sshd', 'guard-main')
            self.assertEqual(f2b.get_action_property('sshd', 'guard-main', 'addr_set?family=inet6'), 'addr6-set-<name>')
        self.assertEqual(runner.call_args_list, [
            call(['fail2ban-client', 'get', 'sshd', 'actions'], timeout=8, sudo=True),
            call(['fail2ban-client', 'get', 'sshd', 'actionproperties', 'guard-main'], timeout=8, sudo=True),
            call(['fail2ban-client', 'get', 'sshd', 'action', 'guard-main', 'addr_set?family=inet6'], timeout=8, sudo=True)])
        self.assertEqual(f2b.parse_action_property('\n'), '')
        self.assertEqual(f2b.parse_action_property('  literal\nline  \n'), '  literal\nline  ')
        for output in ['x' * (f2b.ACTION_TEXT_LIMIT + 1),
                       'é' * (f2b.ACTION_TEXT_LIMIT // 2 + 1), 'bad\x00value']:
            with self.assertRaises(f2b.Fail2BanParseError):
                f2b.parse_action_property(output)

    def test_invalid_selectors_never_execute(self):
        """Discovered action identities and every property query are revalidated."""
        with patch.object(f2b, 'run_host_command') as runner:
            for action in ['$(id)', '-option', 'a' * 129, 'guard;other']:
                with self.assertRaises(f2b.Fail2BanParseError):
                    f2b.get_action_properties('sshd', action)
                with self.assertRaises(f2b.Fail2BanParseError):
                    f2b.get_action_property('sshd', action, 'name')
            for prop in ['timeout', '__dict__', 'ban', 'name?family=other', 'name?family=inet6', 'unknown']:
                with self.assertRaises(f2b.Fail2BanParseError):
                    f2b.get_action_property('sshd', 'guard-main', prop)
        runner.assert_not_called()

    def test_command_failure_is_not_parsed(self):
        """A failed action read retains the existing command-error taxonomy."""
        failure = f2b.CommandResult(1, 'No actions for jail sshd', 'denied', f2b.CommandFailure.NONZERO_EXIT)
        with patch.object(f2b, 'run_host_command', return_value=failure):
            for query in [lambda: f2b.get_jail_actions('sshd'),
                          lambda: f2b.get_action_properties('sshd', 'guard-main'),
                          lambda: f2b.get_action_property('sshd', 'guard-main', 'name')]:
                with self.assertRaises(f2b.Fail2BanCommandError) as error:
                    query()
                self.assertIs(error.exception.result, failure)

    def test_recursive_resolution_and_ipv6_override(self):
        """Resolve only static known references and prefer the IPv6 conditional."""
        properties = {'addr_set': 'addr-<name>', 'addr_set?family=inet6': 'addr6-<name>',
                      'name': '<chain>', 'chain': 'literal', 'iptables': 'literal <lockingopt>',
                      'lockingopt': '-w'}
        self.assertEqual(f2b.resolve_action_property(properties, 'addr_set'), 'addr-literal')
        self.assertEqual(f2b.resolve_action_property(properties, 'addr_set', family='inet6'), 'addr6-literal')
        self.assertEqual(f2b.resolve_action_property(properties, 'iptables', family='inet6'), 'literal -w')
        self.assertEqual(f2b.resolve_action_property({'application': ''}, 'application'), '')
        empty_references = {'name': '<chain>' * 100, 'chain': '<table>' * 100,
                            'table': '<application>' * 100, 'application': ''}
        self.assertEqual(f2b.resolve_action_property(empty_references, 'name'), '')

    def test_resolution_failures_and_expansion_bound(self):
        """Depth, cycles, missing/unknown tags, interpolation and growth are unsupported."""
        chain = ['name', 'chain', 'table', 'addr_set', 'blocktype', 'destination',
                 'application', 'comment', 'kill', 'add']
        deep = {key: f'<{following}>' for key, following in zip(chain, chain[1:])}
        deep[chain[-1]] = 'literal'
        growth = {'name': '<chain>' * 100, 'chain': 'x' * 1000}
        for properties in [deep, growth, {'name': '<name>'},
                           {'name': '<chain>', 'chain': '<name>'}, {'name': '<chain>'},
                           {'name': '<unknown>', 'unknown': 'literal'},
                           {'name': '<nested<tag>>'}, {'name': '%(name)s'},
                           {'name': 'x' * (f2b.ACTION_TEXT_LIMIT + 1)}]:
            with self.subTest(properties=str(properties)[:100]), self.assertRaises(f2b.Fail2BanParseError):
                f2b.resolve_action_property(properties, 'name')
        with self.assertRaises(f2b.Fail2BanParseError):
            f2b.resolve_action_property({'name': 'literal'}, 'name', family='other')

    def test_fingerprint_uses_only_normalized_relevant_facts(self):
        """Action/property order is incidental; identity, presence and values matter."""
        actions = {'guard-main': {'name': 'sshd', 'chain': 'INPUT'}, 'notify-mail': {}}
        reordered = {'notify-mail': {}, 'guard-main': {'chain': 'INPUT', 'name': 'sshd'}}
        fingerprint = f2b.action_fingerprint('sshd', actions)
        self.assertEqual(fingerprint, f2b.action_fingerprint('sshd', reordered))
        for changed in [{'guard-main': {'name': 'sshd', 'chain': 'OUTPUT'}, 'notify-mail': {}},
                        {'guard-main': {'name': 'sshd'}, 'notify-mail': {}},
                        {'guard-main': {'name': 'sshd', 'chain': 'INPUT'}}]:
            self.assertNotEqual(fingerprint, f2b.action_fingerprint('sshd', changed))
        self.assertNotEqual(fingerprint, f2b.action_fingerprint('other', actions))
        with self.assertRaises(f2b.Fail2BanParseError):
            f2b.action_fingerprint('sshd', {'guard-main': {'diagnostic': 'ignored'}})
