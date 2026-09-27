"""Optional real Fail2Ban contract checks; ordinary offline tests need no install."""
from functools import partial
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import offenders_candidate as candidate
from offenders_validation import validate_custom
from test_candidate import web_inventory


@unittest.skipUnless(shutil.which('fail2ban-regex'), 'requires local fail2ban-regex')
class CandidateTemplateTests(unittest.TestCase):
    """Run the public validation workflow against synthetic logs, never a daemon."""

    def test_fixed_paths_dates_and_context_boundaries(self):
        paths = {
            'sensitive_dotfile': ('/.env', '/.env.local', '/a/.git/config', '/.svn/entries', '/.hg'),
            'path_traversal': ('/../etc/passwd', '/a/../../etc/passwd', '/%2e%2e%2fetc/passwd',
                               '/%252e%252e%252fetc/passwd', '/..%5cetc/passwd'),
        }
        for family in ('nginx', 'apache'):
            for category, targets in paths.items():
                with self.subTest(family=family, category=category), tempfile.TemporaryDirectory() as root:
                    lines = [f'8.8.8.8 - - [27/Sep/2026:20:00:00 +0000] "GET {path} HTTP/1.1" 404 12'
                             for path in targets]
                    lines.append(f'8.8.4.4 - - "GET {targets[0]} HTTP/1.1" 403 12')
                    lines.append(f'2026-09-27T20:00:00Z 8.8.4.4 - - "GET {targets[0]} HTTP/1.1" 400 12')
                    if family == 'nginx':
                        lines.append('2026/09/27 20:00:00 [error] 1#1: *2 open() "/var/www/file" failed '
                            '(2: No such file or directory), client: 8.8.8.8, server: _, '
                            f'request: "GET {targets[0]} HTTP/1.1", host: "localhost"')
                    context = tuple(f'8.8.8.8 - - "GET {path} HTTP/1.1" 404 12' for path in
                                    ('/.well-known', '/.gitignore', '/.environment', '/a/.../b',
                                     '/?next=/.git/config', '/?next=/../etc/passwd'))
                    context += (f'8.8.8.8 - - "GET {targets[0]} HTTP/1.1" 200 12',)
                    inv = web_inventory(family, category, texts=tuple(lines), context=context)
                    with patch.object(candidate, 'validate_custom', wraps=partial(validate_custom, config_root=Path(root))):
                        result = candidate.generate_candidate(inv, inv.findings[0])
                    self.assertEqual(result.state, 'reviewable', result.validation)
                    self.assertEqual(result.validation.target.matched_lines, len(lines))
                    self.assertEqual(result.validation.context.matched_lines, 0)
