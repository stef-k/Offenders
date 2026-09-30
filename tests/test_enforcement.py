"""Cross-backend bracketing contracts, using the reviewed public reader seams."""
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path
import unittest
from unittest.mock import patch

import offenders_enforcement as enforcement
import offenders_nftables as nft
import offenders_iptables as ipt
import offenders_ufw as ufw
from offenders_fail2ban import JailStatus, Fail2BanParseError, CommandFailure, CommandResult
from offenders_host import NetworkNamespaceIdentity, NamespaceState
from test_nftables import PROPERTIES as NFT
from test_iptables import PROPERTIES as IPT, save_text
from test_ufw import PROPERTIES as UFW

FIXTURES = Path(__file__).parent / 'fixtures'
SAME = NetworkNamespaceIdentity(NamespaceState.SAME, 42, 'net:[1]', 'net:[1]')
IP = '192.0.2.1'


def status(ips=(IP,)):
    """Return only core current-ban data; no ordinary report participates."""
    return JailStatus('guard', 0, 0, len(ips), len(ips), tuple(ips))


class EnforcementTests(unittest.TestCase):
    """Exercise real classifiers/verifiers while replacing only external reads."""

    def setUp(self):
        """Configure a stable default bracket and reviewed normalized evidence."""
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.properties = {'packet-action': dict(NFT)}
        self.list = self.mock('get_jail_list', return_value=['guard'])
        self.core = self.mock('get_jail_core_status', return_value=status())
        self.actions = self.mock('get_jail_actions', side_effect=lambda jail: tuple(self.properties))
        self.names = self.mock('get_action_properties', side_effect=lambda jail, act: tuple(self.properties[act]))
        self.value = self.mock('get_action_property', side_effect=lambda jail, act, prop: self.properties[act][prop])
        self.namespace = self.stack.enter_context(patch.object(enforcement.host, 'get_fail2ban_namespace', return_value=SAME))
        self.nft = self.stack.enter_context(patch.object(nft, 'read_nft_tables', return_value={
            ('inet', 'evidence'): nft.parse_nft_table((FIXTURES / 'nft-table.json').read_text(), 'inet', 'evidence')}))
        self.ipt = self.stack.enter_context(patch.object(ipt, 'read_iptables_saves', return_value={
            'iptables-save': ipt.parse_iptables_save(save_text(), 'iptables-save'),
            'ip6tables-save': ipt.parse_iptables_save(save_text('2001:db8::1', 'REJECT'), 'ip6tables-save')}))
        self.ufw_status = self.stack.enter_context(patch.object(ufw, 'read_ufw_status', return_value=ufw.UfwStatus(True)))
        self.ufw_added = self.stack.enter_context(patch.object(ufw, 'read_ufw_added', return_value=
            ufw.parse_ufw_added((FIXTURES / 'ufw-added.txt').read_text())))
        self.ufw_save = self.stack.enter_context(patch.object(ufw, 'read_ufw_saves', return_value={
            v: ufw.parse_ufw_save((FIXTURES / f'ufw-v{v}.save').read_text(), v) for v in (4, 6)}))

    def mock(self, name, **kwargs):
        """Patch the bounded Fail2Ban read boundary, leaving policy unmocked."""
        return self.stack.enter_context(patch.object(enforcement.f2b, name, **kwargs))

    def row(self):
        """Most race cases have exactly one action/IP result."""
        result = enforcement.check_enforcement()
        self.assertEqual(len(result.rows), 1)
        return result.rows[0]

    def test_stable_observed_absent_and_permission_failure(self):
        """A stable bracket preserves the backend outcome and its machine reason."""
        self.assertEqual((self.row().outcome, self.row().backend_reason), ('confirmed', 'entry-observed'))
        self.nft.return_value = {('inet', 'evidence'): nft.NftSnapshot('inet', 'evidence')}
        self.assertEqual((self.row().outcome, self.row().reason), ('missing', 'table-absent'))
        self.nft.return_value = {('inet', 'evidence'): nft.NftSnapshot('inet', 'evidence', reason='non-zero-exit')}
        self.assertEqual((self.row().outcome, self.row().reason), ('unverifiable', 'non-zero-exit'))

    def test_ban_add_remove_and_jail_disappearance_override_evidence(self):
        """Relevant membership changes invalidate both positive and negative evidence."""
        for closing in [status(()), status((IP, '192.0.2.9'))]:
            for snapshot in self.nft.return_value, {('inet', 'evidence'): nft.NftSnapshot('inet', 'evidence') }:
                with self.subTest(closing=closing.banned_ips, snapshot=snapshot):
                    self.nft.return_value = snapshot
                    self.core.side_effect = [status(), closing]
                    self.assertEqual(self.row().outcome, 'changed-during-check')
        self.core.side_effect = None
        self.list.side_effect = [['guard'], []]
        self.assertEqual(self.row().reason, 'jail-disappeared')

    def test_action_fingerprint_and_action_identity_changes(self):
        """Exact queried facts and discovered action identities are bracketed."""
        def change(actions):
            self.properties['packet-action']['chain'] = 'other'
            return self.nft.return_value
        self.nft.side_effect = change
        self.assertEqual(self.row().reason, 'action-changed')
        self.nft.side_effect = None
        self.actions.side_effect = [('packet-action',), ()]
        self.assertEqual(self.row().outcome, 'changed-during-check')

    def test_namespace_gate_and_closing_identity_precedence(self):
        """Opening uncertainty prohibits all firewall reads; unreadability is not change."""
        for state in [NamespaceState.DIFFERENT, NamespaceState.UNAVAILABLE]:
            self.namespace.return_value = replace(SAME, state=state)
            self.assertEqual(self.row().outcome, 'unverifiable')
            self.nft.assert_not_called()
            self.ipt.assert_not_called()
            self.ufw_status.assert_not_called()
            self.ufw_added.assert_not_called()
            self.ufw_save.assert_not_called()
        for closing in [replace(SAME, main_pid=43), replace(SAME, fail2ban_namespace='net:[2]', state=NamespaceState.DIFFERENT)]:
            self.namespace.side_effect = [SAME, closing]
            self.assertEqual(self.row().outcome, 'changed-during-check')
        self.namespace.side_effect = [SAME, NetworkNamespaceIdentity(NamespaceState.UNAVAILABLE)]
        self.assertEqual(self.row().reason, 'closing-namespace-unavailable')

    def test_no_bans_unknown_and_metadata_unavailable_are_distinct(self):
        """Valid empty membership needs no actions/firewall; failures are never unsupported."""
        self.core.return_value = status(())
        row = self.row()
        self.assertEqual((row.outcome, row.ip, row.action, row.backend), ('no-current-bans', '', '', ''))
        self.actions.assert_not_called()
        self.nft.assert_not_called()
        self.core.return_value = status()
        self.properties = {'notification': {'actionban': 'notify'}}
        row = self.row()
        self.assertEqual((row.outcome, row.action, row.backend), ('unsupported-action', '', ''))
        self.names.side_effect = Fail2BanParseError('private raw diagnostics')
        self.assertEqual(self.row().outcome, 'unverifiable')
        self.nft.assert_not_called()

    def test_supported_action_survives_unclassified_or_unreadable_sibling(self):
        """A sibling is retained as bounded detail without erasing a supported result."""
        self.properties['notification'] = {'actionban': 'notify'}
        self.assertEqual(self.row().unclassified_actions, ('notification',))
        original = self.names.side_effect
        def read_names(jail, act):
            """Only the sibling's metadata is unreadable."""
            if act == 'notification':
                raise Fail2BanParseError('secret')
            return original(jail, act)
        self.names.side_effect = read_names
        row = self.row()
        self.assertEqual((row.outcome, row.unavailable_actions), ('confirmed', ('notification',)))

    def test_closing_required_metadata_failure_outranks_readable_change(self):
        """Closing partial data is unverifiable even if another fact also changed."""
        self.names.side_effect = [tuple(NFT), Fail2BanParseError('secret')]
        self.core.side_effect = [status(), status((IP, '192.0.2.9'))]
        self.assertEqual(self.row().outcome, 'unverifiable')
        self.names.side_effect = lambda jail, act: tuple(NFT)
        self.core.side_effect = [status(), Fail2BanParseError('secret')]
        self.assertEqual(self.row().reason, 'closing-state-unavailable')

    def test_unrelated_jail_changes_do_not_invalidate_stable_rows(self):
        """The closing list limits acquisition to opening jails, without global equality."""
        self.list.side_effect = [['guard'], ['guard', 'unrelated']]
        self.assertEqual(self.row().outcome, 'confirmed')
        self.assertEqual([c.args for c in self.core.call_args_list], [('guard',), ('guard',)])

    def test_multiple_supported_actions_stay_separate(self):
        """A missing iptables path cannot be hidden by a confirmed nftables path."""
        self.properties['second'] = dict(IPT)
        self.ipt.return_value = {'iptables-save': ipt.IptablesSnapshot('iptables-save')}
        rows = enforcement.check_enforcement().rows
        self.assertEqual([(r.action, r.backend, r.outcome) for r in rows],
                         [('packet-action', 'nftables', 'confirmed'), ('second', 'iptables', 'missing')])
        self.ufw_status.assert_not_called()

    def test_ambiguous_classifiers_fail_closed(self):
        """Dispatch cannot select by classifier ordering."""
        with patch.object(ipt, 'classify_iptables_action', return_value=ipt.classify_iptables_action(IPT)):
            self.assertEqual(self.row().reason, 'ambiguous-action')
        self.nft.assert_not_called()
        self.ipt.assert_not_called()

    def test_property_allowlist_and_backend_batches(self):
        """Only advertised allowed properties are queried; readers receive whole batches."""
        self.properties['packet-action']['arbitrary'] = 'never queried'
        self.properties['second'] = dict(IPT)
        self.properties['third'] = dict(UFW)
        self.core.return_value = status((IP, '2001:db8::1'))
        result = enforcement.check_enforcement()
        self.assertEqual(len(result.rows), 6)
        self.assertNotIn('arbitrary', [c.args[2] for c in self.value.call_args_list])
        for reader in [self.nft, self.ipt, self.ufw_save]:
            reader.assert_called_once()
            self.assertEqual(len(reader.call_args.args[0]), 2)
        self.ufw_status.assert_called_once()
        self.ufw_added.assert_called_once()
        self.assertEqual(result.rows[2].connection_termination, 'not-requested')

    def test_real_readers_deduplicate_by_reviewed_scope(self):
        """Integration fans out once; reviewed readers issue one command per scope."""
        self.stack.close()
        actions = {'one': NFT, 'two': NFT, 'three': IPT, 'four': UFW}
        def properties(jail, action, prop):
            return actions[action][prop]
        denied = CommandResult(1, '', 'must not retain', CommandFailure.NONZERO_EXIT)
        with patch.object(enforcement.f2b, 'get_jail_list', return_value=['guard']), \
                patch.object(enforcement.f2b, 'get_jail_core_status', return_value=status((IP, '192.0.2.2', '2001:db8::1'))), \
                patch.object(enforcement.f2b, 'get_jail_actions', return_value=tuple(actions)), \
                patch.object(enforcement.f2b, 'get_action_properties', side_effect=lambda jail, action: tuple(actions[action])), \
                patch.object(enforcement.f2b, 'get_action_property', side_effect=properties), \
                patch.object(enforcement.host, 'get_fail2ban_namespace', return_value=SAME), \
                patch.object(nft, 'run_host_command', return_value=denied) as nr, \
                patch.object(ipt, 'run_host_command', return_value=denied) as ir, \
                patch.object(ufw, 'run_host_command', return_value=denied) as ur:
            result = enforcement.check_enforcement()
        self.assertEqual(len(result.rows), 12)
        self.assertEqual(nr.call_count, 1)
        self.assertEqual(ir.call_count, 2)
        self.assertEqual(ur.call_count, 4)
        self.assertNotIn('must not retain', repr(result))

    def test_opening_list_and_unsafe_jail_fail_without_raw_diagnostics(self):
        """Unreadable or unsafe opening state authorizes no privileged selectors."""
        self.list.side_effect = Fail2BanParseError('private')
        result = enforcement.check_enforcement()
        self.assertEqual((result.rows, result.reason), ((), 'jail-list-unavailable'))
        self.list.side_effect = None
        self.list.return_value = ['unsafe jail']
        self.assertEqual(self.row().outcome, 'unverifiable')
        self.core.assert_not_called()
        self.nft.assert_not_called()
