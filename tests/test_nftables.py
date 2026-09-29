"""Prove scoped nftables direct evidence without root or firewall mutation."""
import copy
import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

import offenders_fail2ban as f2b
import offenders_nftables as nft

FIXTURES = Path(__file__).parent / 'fixtures'
PROPERTIES = {
    'actionban': r'<nftables> add element <table_family> <table> <addr_set> \{ <ip> \}',
    'nftables': 'nft', 'table_family': 'inet', 'table': 'evidence',
    'chain': 'input', 'chain_type': 'filter', 'chain_hook': 'input',
    'name': 'test', 'addr_set': 'banned', 'addr_set?family=inet6': 'banned6',
    'blocktype': 'reject',
}


class NftablesTests(unittest.TestCase):
    """Keep missing facts distinct from unsafe or unfamiliar evidence."""

    def setUp(self):
        """Use one qualified multiport JSON shape with both address families."""
        self.data = json.loads((FIXTURES / 'nft-table.json').read_text())
        self.action = nft.classify_nft_action(PROPERTIES)

    def check(self, data=None, action=None, ip='192.0.2.1'):
        """Exercise the public parser and evidence seam for the requested ban."""
        snapshot = nft.parse_nft_table(json.dumps(self.data if data is None else data), 'inet', 'evidence')
        return nft.verify_nft_ban(action or self.action, ip, snapshot)

    def test_ipv4_and_ipv6_confirmed(self):
        """Exact host members and source-set terminal rules prove both families."""
        self.assertEqual(self.check().outcome, 'confirmed')
        action = nft.classify_nft_action(PROPERTIES, family='inet6')
        self.assertEqual(action.addr_set, 'banned6')
        self.assertEqual(self.check(action=action, ip='2001:db8:0:0::1').outcome, 'confirmed')
        data = copy.deepcopy(self.data)
        data['nftables'][-2]['rule']['expr'][-1] = {'drop': None}
        drop = nft.classify_nft_action({**PROPERTIES, 'blocktype': 'drop'})
        self.assertEqual(self.check(data, drop).outcome, 'confirmed')
        data = copy.deepcopy(self.data)
        data['nftables'][-2]['rule']['expr'][0] = {
            'match': {'op': '==', 'left': {'meta': {'key': 'l4proto'}}, 'right': {'set': [6, 17]}}}
        data['nftables'][-2]['rule']['expr'].insert(2, {'counter': {'packets': 0, 'bytes': 0}})
        self.assertEqual(self.check(data).outcome, 'confirmed')

    def test_absent_objects_and_member(self):
        """Successful complete snapshots can establish specific absent facts."""
        for kind, reason in [('table', 'table-absent'), ('set', 'set-absent'),
                             ('chain', 'chain-absent')]:
            data = copy.deepcopy(self.data)
            data['nftables'] = [entry for entry in data['nftables'] if kind not in entry]
            with self.subTest(kind=kind):
                self.assertEqual(self.check(data).reason, reason)
                self.assertEqual(self.check(data).outcome, 'missing')
        self.assertEqual(self.check(ip='192.0.2.99').reason, 'ban-entry-absent')

    def test_dormant_table_and_incompatible_set(self):
        """Dormancy and wrong address type cannot produce confirmation."""
        data = copy.deepcopy(self.data)
        data['nftables'][1]['table']['flags'] = ['dormant']
        self.assertEqual(self.check(data).reason, 'table-dormant')
        for changes in [{'type': 'ipv6_addr'}, {'family': 'ip6'}]:
            data = copy.deepcopy(self.data)
            data['nftables'][2]['set'].update(changes)
            with self.subTest(changes=changes):
                self.assertNotEqual(self.check(data).outcome, 'confirmed')

    def test_chain_must_be_supported_active_base_chain(self):
        """Regular chains, wrong type/hook and missing priority are not hooked."""
        for changes in [{'type': 'nat'}, {'hook': 'output'}, {'hook': None}, {'prio': None}]:
            data = copy.deepcopy(self.data)
            data['nftables'][4]['chain'].update(changes)
            with self.subTest(changes=changes):
                self.assertEqual(self.check(data).reason, 'chain-not-hooked')

    def test_rule_source_reference_and_terminal_verdict(self):
        """Wrong sets, destination/negated matches, and nonterminal blocks fail closed."""
        for replacement, reason in [('@other', 'rule-reference-absent')]:
            data = copy.deepcopy(self.data)
            data['nftables'][-2]['rule']['expr'][1]['match']['right'] = replacement
            self.assertEqual(self.check(data).reason, reason)
        for changes in [{'op': '!='}, {'left': {'payload': {'protocol': 'ip', 'field': 'daddr'}}}]:
            data = copy.deepcopy(self.data)
            data['nftables'][-2]['rule']['expr'][1]['match'].update(changes)
            self.assertNotEqual(self.check(data).outcome, 'confirmed')
        for terminal in [{'accept': None}, {'jump': {'target': 'other'}}]:
            data = copy.deepcopy(self.data)
            data['nftables'][-2]['rule']['expr'][-1] = terminal
            self.assertEqual(self.check(data).reason, 'blocking-verdict-absent')
        data = copy.deepcopy(self.data)
        data['nftables'][-2]['rule']['expr'].insert(0, {'accept': None})
        self.assertNotEqual(self.check(data).outcome, 'confirmed')
        data = copy.deepcopy(self.data)
        data['nftables'][-2]['rule']['chain'] = 'unrelated'
        self.assertEqual(self.check(data).reason, 'rule-reference-absent')
        data = copy.deepcopy(self.data)
        data['nftables'][-2]['rule']['expr'] = [{'vmap': {'key': {'meta': {'key': 'nfproto'}}, 'data': '@banned'}}]
        self.assertEqual(self.check(data).outcome, 'unverifiable')

    def test_unfamiliar_elements_are_unverifiable(self):
        """Prefixes, intervals and timeout wrappers are outside simple-host support."""
        for elem in [[{'prefix': {'addr': '192.0.2.0', 'len': 24}}],
                     [{'elem': {'val': '192.0.2.1', 'timeout': 30}}], ['bad-ip']]:
            data = copy.deepcopy(self.data)
            data['nftables'][2]['set']['elem'] = elem
            with self.subTest(elem=elem):
                self.assertEqual(self.check(data).outcome, 'unverifiable')
        data = copy.deepcopy(self.data)
        data['nftables'][2]['set']['flags'] = ['interval']
        self.assertEqual(self.check(data).outcome, 'unverifiable')

    def test_malformed_and_oversized_output(self):
        """Bad envelopes, duplicate objects/keys and bounds never become missing."""
        duplicate = copy.deepcopy(self.data)
        duplicate['nftables'].append(duplicate['nftables'][2])
        for raw in ['{', '{}', '{"nftables": null}', '{"nftables": [null]}',
                    '{"nftables": [], "nftables": []}', json.dumps(duplicate),
                    json.dumps({'nftables': [{'unknown': {}}]})]:
            snapshot = nft.parse_nft_table(raw, 'inet', 'evidence')
            with self.subTest(raw=raw[:60]):
                self.assertEqual(nft.verify_nft_ban(self.action, '192.0.2.1', snapshot).outcome, 'unverifiable')
        snapshot = nft.parse_nft_table(' ' * (nft.NFT_TEXT_LIMIT + 1), 'inet', 'evidence')
        self.assertEqual(snapshot.reason, 'evidence-limit')

    def test_stock_effective_shape_and_custom_action_rejection(self):
        """Classification depends on resolved commands/properties, never action names."""
        effective = 'nft add element inet evidence banned { <ip> }'
        self.assertIsNotNone(nft.classify_nft_action({**PROPERTIES, 'actionban': effective}))
        for changes in [{'actionban': effective + '; echo extra'},
                        {'actionban': effective.replace('nft add', 'nft\nadd')},
                        {'actionban': 'wrapper ' + effective}, {'nftables': '/tmp/nft'},
                        {'chain_type': 'nat'}, {'blocktype': 'redirect to 2222'}]:
            with self.subTest(changes=changes):
                self.assertIsNone(nft.classify_nft_action({**PROPERTIES, **changes}))
        self.assertEqual(nft.classify_nft_action({**PROPERTIES, 'blocktype': 'reject with icmpx type host-unreachable'}).verdict, 'reject')
        with self.assertRaises(f2b.Fail2BanParseError):
            nft.classify_nft_action({**PROPERTIES, 'table': '<table>'})

    def test_scoped_snapshot_reused_and_exact_read_only_argv(self):
        """Actions sharing a table use one fixed sudo read and no actionban execution."""
        v6 = nft.classify_nft_action(PROPERTIES, family='inet6')
        result = f2b.CommandResult(0, json.dumps(self.data), '')
        with patch.object(nft, 'run_host_command', return_value=result) as runner:
            snapshots = nft.read_nft_tables((self.action, v6))
        runner.assert_called_once_with(['nft', '--json', '--numeric', 'list', 'table', 'inet', 'evidence'], timeout=8, sudo=True)
        self.assertEqual(len(snapshots), 1)
        self.assertEqual(nft.verify_nft_ban(v6, '2001:db8::1', snapshots[('inet', 'evidence')]).outcome, 'confirmed')
        with patch('offenders_fail2ban.subprocess.run', return_value=subprocess.CompletedProcess([], 0, json.dumps(self.data), '')) as process:
            nft.read_nft_tables((self.action,))
        self.assertEqual(process.call_args.args[0], ['sudo', '-n', 'nft', '--json', '--numeric', 'list', 'table', 'inet', 'evidence'])
        self.assertEqual(process.call_args.kwargs['stdin'], subprocess.DEVNULL)

    def test_unsafe_descriptor_cannot_execute(self):
        """The acquisition boundary revalidates even constructed descriptors."""
        from dataclasses import replace
        with patch.object(nft, 'run_host_command') as runner:
            for changes in [{'table_family': 'inet;delete'}, {'table_family': 'bridge'},
                            {'table': '-option'}, {'table': 'a;delete table inet other'},
                            {'table': 'a' * 129}]:
                action = replace(self.action, **changes)
                snapshot = next(iter(nft.read_nft_tables((action,)).values()))
                self.assertEqual(snapshot.reason, 'unsafe-identifier')
            runner.assert_not_called()

    def test_table_count_limit_prevents_partial_acquisition(self):
        """A too-large request cannot silently verify only a truncated subset."""
        from dataclasses import replace
        actions = [replace(self.action, table=f'table-{index}') for index in range(nft.NFT_TABLE_LIMIT + 1)]
        with patch.object(nft, 'run_host_command') as runner:
            snapshots = nft.read_nft_tables(actions)
        runner.assert_not_called()
        self.assertEqual(len(snapshots), len(actions))
        self.assertTrue(all(snapshot.reason == 'evidence-limit' for snapshot in snapshots.values()))

    def test_command_failures_and_output_bounds_are_unverifiable(self):
        """Permission/time/output failures retain no raw stdout and imply no absence."""
        for result in [f2b.CommandResult(1, '', 'denied', f2b.CommandFailure.NONZERO_EXIT),
                       f2b.CommandResult(None, '', '', f2b.CommandFailure.TIMEOUT),
                       f2b.CommandResult(0, ' ' * (nft.NFT_TEXT_LIMIT + 1), '')]:
            with patch.object(nft, 'run_host_command', return_value=result):
                snapshot = nft.read_nft_tables((self.action,))[('inet', 'evidence')]
            self.assertEqual(nft.verify_nft_ban(self.action, '192.0.2.1', snapshot).outcome, 'unverifiable')
