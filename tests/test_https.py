"""Exercise the real GeoIP and RDAP HTTPS paths without network traffic."""
import io
import ssl
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request
import urllib.response

from offenders_geoip_update import BASE_URL, fetch
from offenders_lookup import lookup_output


class HTTPSTests(unittest.TestCase):
    """Audit urllib's OS trust authority and the existing transport error contract."""

    def test_clients_use_os_roots_and_retain_verification_failures(self):
        """Inspect actual transport contexts, including ipwhois's own opener."""
        contexts = []

        def reject(handler, connection, request, **kwargs):
            contexts.append(kwargs.get("context"))
            raise urllib.error.URLError(ssl.SSLCertVerificationError("untrusted peer"))

        with patch("urllib.request.HTTPSHandler.do_open", autospec=True, side_effect=reject), \
             patch("socket.create_connection", side_effect=AssertionError("network")):
            with self.assertRaises(urllib.error.URLError):
                fetch(BASE_URL + "/dbip-country-lite-2026-10.mmdb.gz")
            self.assertIn("Outcome: rdap-unavailable", lookup_output("8.8.8.8", "registration"))

        self.assertEqual(len(contexts), 2)  # No retry after certificate failure.
        for context in contexts:
            self.assertIsInstance(context, ssl.SSLContext)
            self.assertTrue(context.check_hostname)
            self.assertEqual(context.verify_mode, ssl.CERT_REQUIRED)
            self.assertEqual(set(context.get_ca_certs(binary_form=True)),
                             set(ssl.create_default_context().get_ca_certs(binary_form=True)))

    def test_rdap_rejects_https_to_http_redirect_before_connection(self):
        """A provider redirect cannot silently turn registration into cleartext."""
        def downgrade(handler, connection, request, **kwargs):
            response = urllib.response.addinfourl(io.BytesIO(),
                {"Location": "http://rdap.example/ip/8.8.8.8"}, request.full_url, 302)
            response.msg = "redirect"
            return response

        with patch("urllib.request.HTTPSHandler.do_open", autospec=True, side_effect=downgrade), \
             patch("urllib.request.HTTPHandler.http_open", autospec=True) as http, \
             patch("socket.create_connection", side_effect=AssertionError("network")):
            self.assertIn("Outcome: rdap-unavailable", lookup_output("8.8.8.8", "registration"))
        http.assert_not_called()
