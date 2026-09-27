"""Public pattern projection contracts; representative formats, no host acquisition."""
from dataclasses import replace
from datetime import datetime, timedelta, timezone
import unittest
from unittest.mock import patch

from offenders_evidence import EvidenceRecord, EvidenceSnapshot, SourceResult
from offenders_host import HostInventory, SourceHealth
from offenders_sources import LogSource, LogSourceInventory, SourceAssociation
import offenders_patterns as patterns

NOW = datetime(2026, 1, 1, 12, tzinfo=timezone.utc)
HOST = HostInventory((), (), *(SourceHealth("successful"),) * 3)


def source(family, identity="/log", kind="file", resolved=None):
    """Supply explicit family authority independently of text/path names."""
    return LogSource(kind, identity, "readable",
                     (SourceAssociation(family, "active", "fixture"),), resolved)


def snapshot(lines, *sources, now=NOW, timestamp=None):
    """Provide shared backend records and exact source-result references."""
    keys = tuple((item.kind, item.identity) for item in sources)
    records = tuple(EvidenceRecord((sources[0].kind, index), True, keys, line, timestamp)
                    for index, line in enumerate(lines))
    results = tuple(SourceResult(item, "collected", tuple(r.identity for r in records), False, ())
                    for item in sources)
    return EvidenceSnapshot(LogSourceInventory(HOST, sources, ()), now, timedelta(days=1),
                            now - timedelta(days=1), records, results, False, ())


def access(path, status=404, stamp="01/Jan/2026:12:00:00 +0000"):
    """Conventional combined record with deliberately irrelevant user-agent IP."""
    return f'8.8.8.8 - - [{stamp}] "GET {path} HTTP/1.1" {status} 47 "-" "1.2.3.4"'


class PatternTests(unittest.TestCase):
    """Recognition is measured at the public projection seam, not regex helpers."""

    def test_explicit_catalog_and_noise(self):
        cases = [
            ("ssh", "sshd[1]: Failed password for alice from 8.8.8.8 port 22 ssh2", "ssh_failed_password", "8.8.8.8"),
            ("ssh", "Failed password for invalid user bob from ::ffff:8.8.8.8 port 22", "ssh_failed_password", "8.8.8.8"),
            ("ssh", "Invalid user guest from 2001:4860::1 port 22", "ssh_invalid_user", "2001:4860::1"),
            ("ssh", "error: authentication failed for bob from 8.8.8.8", "ssh_authentication_failure", "8.8.8.8"),
            ("dovecot", "imap-login: Disconnected (auth failed, 2 attempts): user=<x>, rip=8.8.8.8, lip=1.1.1.1", "dovecot_authentication_failure", "8.8.8.8"),
            ("dovecot", "auth-worker(42): pam(user,8.8.8.8): unknown user", "dovecot_authentication_failure", "8.8.8.8"),
            ("dovecot", "auth: passwd-file(user,8.8.8.8): Password mismatch", "dovecot_authentication_failure", "8.8.8.8"),
            ("dovecot", "auth-worker(default): Info: pam(user,8.8.8.8): pam_authenticate() failed: Authentication failure", "dovecot_authentication_failure", "8.8.8.8"),
            ("dovecot", "dovecot-auth: pam_unix(dovecot:auth): authentication failure; ruser=rhost=1.2.3.4 rhost=8.8.8.8", "dovecot_authentication_failure", "8.8.8.8"),
            ("vsftpd", 'Thu Jan 1 12:00:00 2026 [pid 12] [guest] FAIL LOGIN: Client "8.8.8.8"', "vsftpd_login_failure", "8.8.8.8"),
            ("vsftpd", "host vsftpd: pam_unix(vsftpd:auth): authentication failure; rhost=8.8.8.8", "vsftpd_login_failure", "8.8.8.8"),
            ("proftpd", "host proftpd[12] host (remote[8.8.8.8]): USER bob (Login failed): Incorrect password.", "proftpd_login_failure", "8.8.8.8"),
            ("proftpd", "host proftpd[12]: host (remote[8.8.8.8]) - SECURITY VIOLATION: Root login attempted", "proftpd_root_login", "8.8.8.8"),
            ("proftpd", "host proftpd[12]: host (remote[8.8.8.8]) - Maximum login attempts (3) exceeded", "proftpd_login_failure", "8.8.8.8"),
            ("proftpd", "host proftpd[12] host (remote[8.8.8.8]): USER x: no such user found from remote [1.1.1.1] to 2.2.2.2:21", "proftpd_login_failure", "8.8.8.8"),
            ("pure-ftpd", "host pure-ftpd: (?@8.8.8.8) [WARNING] Authentication failed for user [bob]", "pure-ftpd_authentication_failure", "8.8.8.8"),
            ("nginx", '[error] 12#0: *3 user "x" was not found in "pw", client: 8.8.8.8, server: host', "nginx_http_authentication_failure", "8.8.8.8"),
            ("nginx", '[error] 12#0: *3 user "x": password mismatch, client: 8.8.8.8, server: host', "nginx_http_authentication_failure", "8.8.8.8"),
            ("apache", '[error] [client 8.8.8.8:123] user x not found: /', "apache_http_authentication_failure", "8.8.8.8"),
            ("apache", '[auth_basic:error] [pid 12] [client [2001:4860::1]:123] AH01617: user x: authentication failure for "/": Password Mismatch', "apache_http_authentication_failure", "2001:4860::1"),
            ("apache", '[authz_core:error] [client 8.8.8.8] AH01630: client denied by server configuration: /', "apache_http_authentication_failure", "8.8.8.8"),
            ("apache", '[error] [client 8.8.8.8] wrong authentication scheme: /', "apache_http_authentication_failure", "8.8.8.8"),
            ("apache", '[auth_basic:error] [client 8.8.8.8] AH01614: client used wrong authentication scheme: /', "apache_http_authentication_failure", "8.8.8.8"),
            ("apache", '[authz_core:error] [client 8.8.8.8] AH01631: user x: authorization failure for "/"', "apache_http_authentication_failure", "8.8.8.8"),
            ("apache", '[error] [client 8.8.8.8] Authorization of user x to access /private failed, reason: file owner does not match.', "apache_http_authentication_failure", "8.8.8.8"),
            ("apache", '[error] [client 8.8.8.8] Digest: user x: password mismatch: /', "apache_http_authentication_failure", "8.8.8.8"),
            ("ssh", "Accepted password for x from 8.8.8.8", None, None),
            ("ssh", "pam_unix(sshd:session): session opened for user root", None, None),
            ("ssh", 'GET /Failed password for x from 8.8.8.8 HTTP/1.1', None, None),
            ("dovecot", "imap-login: Disconnected: user=<x>, rip=8.8.8.8", None, None),
            ("vsftpd", "dovecot: pam_unix(dovecot:auth): authentication failure; rhost=8.8.8.8", None, None),
            ("proftpd", "SECURITY VIOLATION: root login attempted", None, None),
            ("pure-ftpd", "(?@8.8.8.8) [WARNING] Echec authentification utilisateur [x]", None, None),
            ("nginx", '[error] 12#0: *3 connect() failed, client: 8.8.8.8, server: host', None, None),
            ("apache", '[error] [client 8.8.8.8] File does not exist: /[client 1.1.1.1] user x not found', None, None),
            ("caddy", "Failed password for x from 8.8.8.8", None, None),
            ("unknown", "sshd: Failed password for x from 8.8.8.8", None, None),
        ]
        for family, line, kind, ip in cases:
            with self.subTest(family=family, line=line):
                result = patterns.analyze_patterns(snapshot([line], source(family)))
                self.assertEqual(len(result.events), int(kind is not None))
                self.assertEqual(result.analyses[0].ignored_record_count, int(kind is None))
                if kind:
                    self.assertEqual(result.events[0].pattern_kind, kind)
                    self.assertEqual(result.events[0].source_ip, ip)
                    self.assertEqual(result.groups[0].event_count, 1)

    def test_web_probes_have_explicit_categories_and_rejection_boundary(self):
        paths = {"//phpMyAdmin-2.8.2.3/scripts/setup.php": "database_admin",
                 "/admin/pma/scripts/setup.php": "database_admin",
                 "/mysqladmin/scripts/setup.php": "database_admin",
                 "/cgi-bin/php4": "cgi_script", "/wp-login.php": "wordpress_auth",
                 "/xmlrpc.php": "wordpress_auth", "/.env": "sensitive_dotfile",
                 "/.git/config": "sensitive_dotfile", "/.svn/entries": "sensitive_dotfile",
                 "/.hg/store": "sensitive_dotfile", "/../../etc/passwd": "path_traversal",
                 "/%2e%2e%2fetc/passwd": "path_traversal",
                 "/.%2e/%2E./etc/passwd": "path_traversal"}
        for family in ("nginx", "apache"):
            for path, category in paths.items():
                with self.subTest(family=family, path=path):
                    result = patterns.analyze_patterns(snapshot([access(path)], source(family)))
                    self.assertEqual(result.groups[0].signature, f"{family}:path_probe:{category}")
                    self.assertFalse(patterns.analyze_patterns(snapshot([access(path, 200)], source(family))).groups)
            noise = [access("/ordinary"), access("/normal?next=/.env"), access("/cgi-bin/"),
                     access("/wp-login.php.bak"), access("/x", 401), access("/.env", 500)]
            result = patterns.analyze_patterns(snapshot(noise, source(family)))
            self.assertFalse(result.groups)
            self.assertEqual(result.analyses[0].state, "analyzed")
        nginx = '2026/01/01 12:00:00 [error] 12#0: *3 open() "/var/www/cgi-bin/php4" failed (2: No such file or directory), client: 8.8.8.8, server: host, request: "GET /cgi-bin/php4 HTTP/1.1"'
        self.assertEqual(patterns.analyze_patterns(snapshot([nginx], source("nginx"))).groups[0].signature,
                         "nginx:path_probe:cgi_script")

    def test_aliases_families_backends_and_factual_counts(self):
        lines = [f"Failed password for {name} from {ip} port 123" for name, ip in
                 (("a", "8.8.8.8"), ("b", "::ffff:8.8.8.8"), ("c", "10.0.0.1"), ("d", "bad-ip"))]
        a, b = source("ssh", "/alias", resolved="/real"), source("ssh", "/real", resolved="/real")
        shared = replace(b, associations=b.associations + (SourceAssociation("vsftpd", "active", "fixture"),))
        supplied = snapshot(lines, a, shared)
        result = patterns.analyze_patterns(supplied)
        self.assertIs(result.evidence_snapshot, supplied)
        group = result.groups[0]
        self.assertEqual((group.event_count, group.distinct_source_ip_count,
                          group.global_source_ip_count, group.non_global_source_ip_count), (4, 2, 1, 1))
        self.assertEqual(group.source_identity, "/real")
        self.assertEqual(len(group.record_ids), 4)
        self.assertEqual(len(result.analyses), 2)
        self.assertIn("source IP evidence incomplete", group.limitations)
        journal = source("ssh", "ssh.service", "journal")
        other = snapshot([lines[0]], journal, timestamp=NOW)
        combined = replace(supplied, records=supplied.records + other.records,
                           sources=supplied.sources + other.sources)
        self.assertEqual(len(patterns.analyze_patterns(combined).groups), 2)
        reversed_input = replace(combined, records=tuple(reversed(combined.records)),
                                 sources=tuple(reversed(combined.sources)))
        reordered = patterns.analyze_patterns(reversed_input)
        original = patterns.analyze_patterns(combined)
        self.assertEqual((original.groups, original.events, original.analyses),
                         (reordered.groups, reordered.events, reordered.analyses))

    def test_timestamp_authority_domains_rollover_and_window(self):
        cases = [("ssh", "Dec 31 23:59:59 host sshd: Failed password for x from 8.8.8.8", datetime(2025, 12, 31, 23, 59, 59)),
                 ("ssh", "2025-01-01T11:22:33 host sshd: Invalid user x from 8.8.8.8", datetime(2025, 1, 1, 11, 22, 33)),
                 ("ssh", "2026-01-01T11:22:33 host sshd: Invalid user x from 8.8.8.8", datetime(2026, 1, 1, 11, 22, 33)),
                 ("nginx", '2026/01/01 11:22:33 [error] 1#0: *1 user "x": password mismatch, client: 8.8.8.8, server: h', datetime(2026, 1, 1, 11, 22, 33)),
                 ("apache", '[Thu Jan 01 11:22:33.123456 2026] [error] [client 8.8.8.8] user x not found: /', datetime(2026, 1, 1, 11, 22, 33, 123456)),
                 ("proftpd", '2026-01-01 11:22:33,123 host proftpd[12]: host (remote[8.8.8.8]) - USER x (Login failed)', datetime(2026, 1, 1, 11, 22, 33, 123000))]
        for family, line, expected in cases:
            with self.subTest(family=family):
                event = patterns.analyze_patterns(snapshot([line], source(family))).events[0]
                self.assertEqual((event.timestamp, event.timestamp_basis), (expected, "local_wall"))
                self.assertTrue(event.limitations)
        text = "Dec 31 00:00:00 host sshd: Failed password for x from 8.8.8.8"
        result = patterns.analyze_patterns(snapshot([text], source("ssh", "ssh.service", "journal"), timestamp=NOW))
        self.assertEqual((result.events[0].timestamp, result.events[0].timestamp_basis), (NOW, "utc"))
        lines = [access("/.env", stamp=stamp) for stamp in
                 ("01/Jan/2026:13:00:00 +0100", "31/Dec/2025:12:00:00 +0000",
                  "31/Dec/2025:11:59:59 +0000", "01/Jan/2026:12:00:01 +0000", "invalid")]
        result = patterns.analyze_patterns(snapshot(lines, source("nginx")))
        self.assertEqual(len(result.events), 3)
        self.assertEqual(result.analyses[0].excluded_record_count, 2)
        self.assertEqual({g.timestamp_basis for g in result.groups}, {"utc", "unknown"})
        utc = next(g for g in result.groups if g.timestamp_basis == "utc")
        self.assertEqual((utc.first_seen, utc.last_seen), (NOW - timedelta(days=1), NOW))
        unknown = next(g for g in result.groups if g.timestamp_basis == "unknown")
        self.assertIsNone(unknown.first_seen)

    def test_distinct_signatures_domains_and_collection_health(self):
        context = "host proftpd[12]: host (remote[8.8.8.8]) - "
        supplied = snapshot([context + "USER x (Login failed)",
                             context + "SECURITY VIOLATION: root login attempted"], source("proftpd"))
        self.assertEqual(len(patterns.analyze_patterns(supplied).groups), 2)
        message = "Failed password for x from 8.8.8.8"
        supplied = snapshot([message, "Jan 01 10:00:00 " + message,
                             "2026-01-01T10:00:00+00:00 " + message,
                             "2026-99-99T10:00:00 " + message], source("ssh"))
        result = patterns.analyze_patterns(supplied)
        self.assertEqual({g.timestamp_basis for g in result.groups}, {"unknown", "local_wall", "utc"})
        self.assertEqual(sum(g.event_count for g in result.groups), 4)
        partial = replace(supplied.sources[0], state="partial", truncated=True,
                          limitations=("compressed rotation not collected",))
        supplied = replace(supplied, sources=(partial,), truncated=True)
        result = patterns.analyze_patterns(supplied)
        for limitations in [result.analyses[0].limitations, *(g.limitations for g in result.groups)]:
            self.assertIn("compressed rotation not collected", limitations)
            self.assertIn("snapshot evidence truncated", limitations)
        shared = replace(source("ssh"), associations=source("ssh").associations +
                         (SourceAssociation("vsftpd", "active", "fixture"),))
        result = patterns.analyze_patterns(snapshot(
            [message, 'vsftpd: [guest] FAIL LOGIN: Client "8.8.8.8"'], shared))
        self.assertEqual([(a.family, a.recognized_event_count, a.ignored_record_count)
                          for a in result.analyses], [("ssh", 1, 1), ("vsftpd", 1, 1)])
        unassociated = replace(source("ssh", "/var/log/auth.log"), associations=())
        self.assertFalse(patterns.analyze_patterns(snapshot([message], unassociated)).events)

    def test_states_limitations_examples_and_no_acquisition(self):
        lines = [f"Failed password for {'é' * 300}{i} from 8.8.8.8" for i in range(5)]
        supplied = snapshot(lines, source("ssh"))
        row = replace(supplied.sources[0], state="partial", truncated=True,
                      limitations=tuple(f"detail {i}: " + "é" * 200 for i in range(40)))
        supplied = replace(supplied, sources=(row,), truncated=True, limitations=("snapshot detail",))
        with patch("builtins.open", side_effect=AssertionError("I/O")), \
                patch("os.open", side_effect=AssertionError("I/O")), \
                patch("subprocess.Popen", side_effect=AssertionError("command")), \
                patch("offenders_evidence.EvidenceCollector.collect", side_effect=AssertionError("collect")):
            result = patterns.analyze_patterns(supplied)
        group = result.groups[0]
        self.assertEqual(result.analyses[0].state, "partial")
        self.assertEqual(len(group.examples), 3)
        self.assertEqual(group.examples, tuple(line.encode()[:512].decode(errors="ignore") for line in lines[:3]))
        self.assertTrue(all(len(e.encode()) <= 512 for e in group.examples))
        self.assertEqual(len(group.limitations), 32)
        self.assertTrue(all(len(e.encode()) <= 300 for e in group.limitations))
        self.assertIn("limitations capped (count or UTF-8 byte limit)", group.limitations)
        for state in ("unavailable", "skipped"):
            empty = snapshot([], source("ssh"))
            empty = replace(empty, sources=(replace(empty.sources[0], state=state),))
            self.assertEqual(patterns.analyze_patterns(empty).analyses[0].state, state)
        self.assertEqual(patterns.analyze_patterns(snapshot([], source("caddy"))).analyses[0].state, "unsupported")
        self.assertEqual(patterns.analyze_patterns(snapshot(["unrecognized"], source("ssh"))).analyses[0].state, "analyzed")
        localized = patterns.analyze_patterns(snapshot(["localized message"], source("pure-ftpd")))
        self.assertIn("English", " ".join(localized.analyses[0].limitations))


if __name__ == "__main__":
    unittest.main()
