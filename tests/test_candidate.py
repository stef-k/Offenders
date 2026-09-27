"""Fixed catalog, retained source and exact validation gate contracts."""
from dataclasses import replace
import hashlib
import unittest
from unittest.mock import patch

import offenders_candidate as candidate
from offenders_coverage import FilterDefinition, JailDefinition
from offenders_validation import FilterValidation, SampleResult, _custom_bytes
from test_validation import inventory


def web_inventory(family='nginx', category='sensitive_dotfile', **options):
    """Use the existing retained-evidence fixture with a web signature."""
    return inventory(custom=True, family=family, kind='path_probe',
                     signature=f'{family}:path_probe:{category}', **options)


def matched(inv, decision, text):
    """Model the exact-byte response at the public validation seam."""
    return FilterValidation(decision, 'custom', custom_sha256=hashlib.sha256(text.encode()).hexdigest(),
        custom_bytes=len(text.encode()), target=SampleResult(tested_lines=3, matched_lines=3,
        missed_lines=0, ignored_lines=0), context=SampleResult(tested_lines=2, matched_lines=1,
        missed_lines=1, ignored_lines=0), state='complete')


def retained(inv, decision):
    """Attach a changed exact decision for boundary tests without rerunning policy."""
    return replace(inv, findings=(decision,), decisions=(decision,))


class CandidateTests(unittest.TestCase):
    """Prove public candidate behavior without executing host commands."""

    def test_catalog_determinism_and_minimal_wiring(self):
        for family in ('nginx', 'apache'):
            for category in ('sensitive_dotfile', 'path_traversal'):
                inv = web_inventory(family, category)
                with patch.object(candidate, 'validate_custom', side_effect=matched) as run:
                    result = candidate.generate_candidate(inv, inv.findings[0])
                    changed = replace(inv.findings[0], group=replace(inv.findings[0].group,
                        examples=('evil [Definition] 8.8.8.8 arbitrary username',)))
                    other = candidate.generate_candidate(retained(inv, changed), changed)
                self.assertEqual(result.state, 'reviewable')
                self.assertEqual(result.filter_text, other.filter_text)
                self.assertEqual(_custom_bytes(result.filter_text), result.filter_text.encode())
                self.assertEqual(run.call_args.args[2], result.filter_text)
                self.assertEqual(result.name, f"offenders-{family}-{category.replace('_', '-')}")
                for value in ('enabled = false', 'port = http,https', 'usedns = no', 'logpath = /alias',
                              result.filter_sha256, 'Target tested=3 matched=3 missed=0 ignored=0',
                              'Context tested=2 matched=1', 'inherit local defaults', 'not activated'):
                    self.assertIn(value, result.jail_text)
                for value in ('/real', 'bantime =', 'findtime =', 'maxretry =', 'action =', 'backend ='):
                    self.assertNotIn(value, result.jail_text)
                self.assertNotIn('evil', result.filter_text)
                self.assertNotIn('[INCLUDES]', result.filter_text)

    def test_identity_stock_unknown_and_collisions_without_validation(self):
        inv = web_inventory()
        decision = inv.findings[0]
        with patch.object(candidate, 'validate_custom') as run:
            for row in (replace(decision), replace(decision, classification='enabled_tuning_question')):
                self.assertEqual(candidate.generate_candidate(inv, row).state, 'withheld')
            for key in (*candidate.COMPATIBILITY, 'nginx:path_probe:wordpress_auth', 'unknown'):
                row = replace(decision, group=replace(decision.group, signature=key, pattern_kind=key))
                result = candidate.generate_candidate(retained(inv, row), row)
                self.assertEqual(result.state, 'withheld')
                self.assertIsNone(result.filter_text)
            name = 'offenders-nginx-sensitive-dotfile'
            static = inv.coverage_inventory.static
            for field, definition in (
                ('filters', FilterDefinition(name, True, '', (), (), ())),
                ('jails', JailDefinition(name, False, '', None, '', (), '', (), ()))):
                changed = replace(inv, coverage_inventory=replace(inv.coverage_inventory,
                    static=replace(static, **{field: (definition,)})))
                self.assertIn('collides', candidate.generate_candidate(changed, decision).reason)
            run.assert_not_called()

    def test_retained_source_alias_ambiguity_and_unsafe_identity(self):
        inv = web_inventory()
        decision = inv.findings[0]
        target = decision.coverage_targets[0]
        with patch.object(candidate, 'validate_custom') as run:
            for path in ('relative', '/bad\npath', '/bad\x00path', '/bad\x1bpath', '/bad%path', '/glob*', '/a b'):
                row = replace(decision, coverage_targets=(replace(target, source=replace(target.source, identity=path)),))
                self.assertEqual(candidate.generate_candidate(retained(inv, row), row).state, 'withheld')
            alias = replace(target, source=replace(target.source, identity='/other'))
            row = replace(decision, coverage_targets=(target, alias))
            self.assertIn('ambiguous', candidate.generate_candidate(retained(inv, row), row).reason)
            run.assert_not_called()
        inv = web_inventory(backend='journal')
        decision = inv.findings[0]
        with patch.object(candidate, 'validate_custom', side_effect=matched):
            result = candidate.generate_candidate(inv, decision)
        self.assertEqual(result.state, 'reviewable')
        self.assertIn('journalmatch = _SYSTEMD_UNIT=ssh.service\n', result.filter_text)
        self.assertIn('backend = systemd', result.jail_text)
        self.assertNotIn('logpath', result.jail_text)
        target = decision.coverage_targets[0]
        for unit in ('bad unit', 'unit\nother', 'bad/unit', 'bad+unit'):
            row = replace(decision, group=replace(decision.group, source_identity=unit),
                coverage_targets=(replace(target, source=replace(target.source, identity=unit)),))
            with patch.object(candidate, 'validate_custom') as run:
                self.assertEqual(candidate.generate_candidate(retained(inv, row), row).state, 'withheld')
                run.assert_not_called()

    def test_exact_validation_identity_and_target_gate(self):
        inv = web_inventory()
        decision = inv.findings[0]
        changes = ({'custom_sha256': 'bad'}, {'custom_bytes': 0}, {'decision': replace(decision)},
                   {'target_kind': 'existing'}, {'state': 'unavailable'},
                   *({'target': SampleResult(tested_lines=t, matched_lines=m, missed_lines=s, ignored_lines=i)}
                     for t, m, s, i in ((3, 2, 1, 0), (3, 2, 0, 1), (0, 0, 0, 0), (None, None, None, None))))
        for change in changes:
            with patch.object(candidate, 'validate_custom', side_effect=lambda *args: replace(matched(*args), **change)):
                result = candidate.generate_candidate(inv, decision)
            self.assertEqual(result.state, 'withheld')
            self.assertIsNone(result.filter_text)
            self.assertIsNone(result.jail_text)
            self.assertIsNotNone(result.validation)
        for context in (None, SampleResult(tested_lines=1, matched_lines=0, missed_lines=1, ignored_lines=0)):
            with patch.object(candidate, 'validate_custom', side_effect=lambda *args: replace(
                    matched(*args), state='partial', context=context, limitations=('upstream truncated',))):
                result = candidate.generate_candidate(inv, decision)
            self.assertEqual(result.state, 'reviewable')
            self.assertIn('upstream truncated', result.limitations)
            self.assertIn('Validation: partial', result.jail_text)
