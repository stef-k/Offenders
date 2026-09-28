"""Offline contracts for explicit packaged PTR and RDAP acquisition."""
import unittest
from unittest.mock import Mock, patch

import dns.exception
import dns.resolver
from ipwhois.exceptions import (
    HTTPLookupError, HTTPRateLimitError, InvalidNetworkObject,
    InvalidEntityObject, InvalidEntityContactObject,
)

from offenders_lookup import LOOKUP_TIMEOUT, OUTPUT_LIMIT, lookup_output


class LookupTests(unittest.TestCase):
    """Replace provider seams; no test may use DNS, NSS, or subprocess fallback."""

    def setUp(self):
        """Make accidental fallback acquisition fail before reaching the host."""
        for target in ("socket.gethostbyaddr", "socket.getnameinfo",
                       "subprocess.Popen", "offenders_fail2ban.run_host_command"):
            guard = patch(target, side_effect=AssertionError("Forbidden fallback"))
            self.addCleanup(guard.stop)
            guard.start()

    def test_ptr_normalization_and_finite_host_resolver(self):
        """IPv4 and IPv6 return sorted, case-folded, unique literal names."""
        for address, normalized in (("8.8.8.8", "8.8.8.8"),
                                    ("2001:4860:4860:0:0:0:0:8888", "2001:4860:4860::8888")):
            with self.subTest(ip=address), patch("offenders_lookup.dns.resolver.Resolver") as factory:
                factory.return_value.resolve_address.return_value = [
                    Mock(target=name) for name in ("Z.example.", "a.example.", "A.example.")]
                self.assertEqual(lookup_output(address, "rdns"),
                                 f"IP: {normalized}\nBackend: PTR (dnspython)\nOutcome: success\n"
                                 "PTR: a.example\nPTR: z.example")
                factory.assert_called_once_with()
                factory.return_value.resolve_address.assert_called_once_with(
                    normalized, lifetime=LOOKUP_TIMEOUT)

    def test_ptr_outcomes(self):
        """DNS failures retain their categories with no alternate provider."""
        cases = [(dns.resolver.NXDOMAIN(), "no-result"),
                 (dns.resolver.NoAnswer(), "no-result"),
                 (dns.resolver.LifetimeTimeout(timeout=8, errors=[]), "timeout"),
                 (dns.resolver.NoNameservers(), "resolver-unavailable"),
                 (dns.resolver.NoResolverConfiguration(), "resolver-unavailable"),
                 (dns.exception.DNSException("bad\x1b\nresponse"), "dns-failure")]
        for error, category in cases:
            with self.subTest(category=category), patch("offenders_lookup.dns.resolver.Resolver") as factory:
                factory.return_value.resolve_address.side_effect = error
                output = lookup_output("8.8.8.8", "rdns")
                self.assertIn(f"Outcome: {category}\n", output)
                self.assertNotIn("\x1b", output)
                self.assertEqual(factory.return_value.resolve_address.call_count, 1)
        with patch("offenders_lookup.dns.resolver.Resolver", side_effect=dns.resolver.NoResolverConfiguration()):
            self.assertIn("Outcome: resolver-unavailable", lookup_output("8.8.8.8", "rdns"))
        with patch("offenders_lookup.dns.resolver.Resolver") as factory:
            factory.return_value.resolve_address.return_value = []
            self.assertIn("Outcome: no-result", lookup_output("8.8.8.8", "rdns"))

    def test_rdap_success_and_exact_shallow_query(self):
        """Only stable network fields appear, with exact zero-retry options."""
        for address in ("8.8.8.8", "2001:4860:4860::8888"):
            with self.subTest(ip=address), patch("offenders_lookup.IPWhois") as factory:
                factory.return_value.lookup_rdap.return_value = {"network": {
                    "cidr": "8.8.8.0/24", "name": "[red]Literal", "handle": "NET-8",
                    "country": "US", "type": "DIRECT", "status": ["z", "active", "active"],
                    "start_address": "8.8.8.0", "end_address": "8.8.8.255",
                    "notices": "SECRET"}, "objects": "SECRET", "raw": "SECRET"}
                self.assertEqual(lookup_output(address, "registration"),
                                 f"IP: {address}\nBackend: RDAP (ipwhois)\nOutcome: success\n"
                                 "CIDR: 8.8.8.0/24\nName: [red]Literal\nHandle: NET-8\nCountry: US\n"
                                 "Type: DIRECT\nStatus: active, z\nStart address: 8.8.8.0\nEnd address: 8.8.8.255")
                factory.assert_called_once_with(address, timeout=LOOKUP_TIMEOUT)
                factory.return_value.lookup_rdap.assert_called_once_with(
                    retry_count=0, depth=0, bootstrap=True, rate_limit_timeout=0,
                    inc_nir=False, root_ent_check=False, inc_raw=False)

    def test_registration_non_global_never_constructs_client(self):
        """Private, shared, documentation, reserved and multicast stay local."""
        for address in ("10.0.0.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "240.0.0.1",
                        "100.64.0.1", "224.0.0.1", "::1", "fe80::1", "fc00::1", "2001:db8::1", "ff02::1"):
            with self.subTest(ip=address), patch("offenders_lookup.IPWhois") as factory:
                self.assertIn("Outcome: not-global", lookup_output(address, "registration"))
                factory.assert_not_called()

    def test_rdap_failure_contract_and_invalid_shapes(self):
        """Do not invent a timeout distinction hidden by the provider contract."""
        cases = [(HTTPRateLimitError("limited"), "rate-limited"),
                 (HTTPLookupError("socket timed out"), "rdap-unavailable"),
                 (HTTPLookupError("network unreachable"), "rdap-unavailable"),
                 (InvalidNetworkObject("bad"), "invalid-response"),
                 (InvalidEntityObject("bad"), "invalid-response"),
                 (InvalidEntityContactObject("bad"), "invalid-response"),
                 (ValueError("invalid JSON"), "invalid-response"),
                 (RuntimeError("unexpected\x1b\n"), "unexpected-failure")]
        for error, category in cases:
            with self.subTest(error=error), patch("offenders_lookup.IPWhois") as factory:
                factory.return_value.lookup_rdap.side_effect = error
                output = lookup_output("8.8.8.8", "registration")
                self.assertIn(f"Outcome: {category}\n", output)
                self.assertNotIn("\x1b", output)
        for result in (None, {}, {"network": []}, {"network": {}}, {"network": {"name": {"nested": 1}}}):
            with self.subTest(result=result), patch("offenders_lookup.IPWhois") as factory:
                factory.return_value.lookup_rdap.return_value = result
                self.assertIn("Outcome: invalid-response", lookup_output("8.8.8.8", "registration"))

    def test_output_bounds_and_untrusted_control_sanitization(self):
        """Large provider data cannot overflow the literal copyable presentation."""
        with patch("offenders_lookup.IPWhois") as factory:
            factory.return_value.lookup_rdap.return_value = {"network": {
                "name": "[red]hello\nOutcome: spoof\x1b\x00\u202e" + "x" * 30000}}
            output = lookup_output("8.8.8.8", "registration")
            self.assertLessEqual(len(output), OUTPUT_LIMIT)
            self.assertIn("[red]hello Outcome: spoof", output)
            self.assertEqual(output.count("\nOutcome:"), 1)
            self.assertNotIn("\u202e", output)
            self.assertIn("truncated", output)
        with patch("offenders_lookup.dns.resolver.Resolver") as factory:
            factory.return_value.resolve_address.return_value = [Mock(target=f"{n}." + "x" * 250) for n in range(200)]
            output = lookup_output("8.8.8.8", "rdns")
            self.assertLessEqual(len(output), OUTPUT_LIMIT)
            self.assertTrue(output.endswith("(output truncated)"))
