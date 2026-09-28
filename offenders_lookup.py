"""Explicit Python-native PTR and shallow RDAP lookups with literal output."""
from __future__ import annotations

import ipaddress

import dns.exception
import dns.resolver
from ipwhois import IPWhois
from ipwhois.exceptions import (
    HTTPLookupError, HTTPRateLimitError, InvalidNetworkObject,
    InvalidEntityObject, InvalidEntityContactObject,
)

# DNS has a total lifetime; RDAP uses the library's finite transport timeout.
LOOKUP_TIMEOUT = 8
# Bound both individual untrusted fields and the final displayed/copied text.
OUTPUT_LIMIT = 8192
FIELD_LIMIT = 1024


def _literal(value: str) -> str:
    """Flatten controls (including bidi/escape controls) without interpreting markup."""
    text = "".join(char if char.isprintable() else " " for char in value[:FIELD_LIMIT])
    return text.strip() + (" (truncated)" if len(value) > FIELD_LIMIT else "")


def _output(ip: str, backend: str, outcome: str, lines: list[str]) -> str:
    """Keep identity and category first, with an inclusive final length limit."""
    text = "\n".join([f"IP: {ip}", f"Backend: {backend}", f"Outcome: {outcome}", *lines])
    suffix = "\n(output truncated)"
    return text if len(text) <= OUTPUT_LIMIT else text[:OUTPUT_LIMIT - len(suffix)] + suffix


def _ptr(ip: str) -> tuple[str, list[str]]:
    """Use only the host-configured DNS resolver; never invoke NSS or a subprocess."""
    try:
        answer = dns.resolver.Resolver().resolve_address(ip, lifetime=LOOKUP_TIMEOUT)
        names = sorted({_literal(str(record.target).rstrip(".").lower()) for record in answer})
        if names:
            return "success", [f"PTR: {name}" for name in names]
        return "no-result", ["No PTR records."]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return "no-result", ["No PTR records."]
    except dns.exception.Timeout:
        return "timeout", ["DNS lookup lifetime exhausted."]
    except (dns.resolver.NoNameservers, dns.resolver.NoResolverConfiguration):
        return "resolver-unavailable", ["No usable DNS nameserver path."]
    except Exception as error:
        return "dns-failure", [f"DNS lookup failed: {_literal(str(error))}"]


def _network_lines(result: object) -> list[str]:
    """Select top-level network fields only; reject malformed provider values."""
    if not isinstance(result, dict) or not isinstance(result.get("network"), dict):
        raise ValueError("Missing RDAP network object")
    network = result["network"]
    fields = (("cidr", "CIDR"), ("name", "Name"), ("handle", "Handle"),
              ("country", "Country"), ("type", "Type"), ("status", "Status"),
              ("start_address", "Start address"), ("end_address", "End address"))
    lines = []
    for key, label in fields:
        value = network.get(key)
        if value is None:
            continue
        if key == "status" and isinstance(value, list) and all(isinstance(item, str) for item in value):
            value = ", ".join(sorted({_literal(item) for item in value}))
        if not isinstance(value, str):
            raise ValueError(f"Invalid RDAP network {key}")
        if value.strip():
            lines.append(f"{label}: {_literal(value)}")
    if not lines:
        raise ValueError("No network registration fields returned")
    return lines


def _registration(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[str, list[str]]:
    """Avoid enrichment, retries, legacy WHOIS and traffic for non-global IPs."""
    if not address.is_global or address.is_multicast or address.is_reserved:
        return "not-global", ["Registration lookup requires a global unicast IP."]
    try:
        result = IPWhois(address.compressed, timeout=LOOKUP_TIMEOUT).lookup_rdap(
            retry_count=0, depth=0, bootstrap=True, rate_limit_timeout=0,
            inc_nir=False, root_ent_check=False, inc_raw=False)
        return "success", _network_lines(result)
    except HTTPRateLimitError:
        return "rate-limited", ["RDAP provider rate limit reached."]
    except HTTPLookupError:
        # ipwhois intentionally collapses timeouts and other transport failures.
        return "rdap-unavailable", ["RDAP request unavailable (network failure or timeout)."]
    except (InvalidNetworkObject, InvalidEntityObject, InvalidEntityContactObject,
            ValueError, TypeError, KeyError, AttributeError) as error:
        return "invalid-response", [f"Invalid RDAP response: {_literal(str(error))}"]
    except Exception as error:
        return "unexpected-failure", [f"Registration lookup failed: {_literal(str(error))}"]


def lookup_output(ip: str, tool: str) -> str:
    """Normalize one selected IP and return bounded text for an explicit action."""
    address = ipaddress.ip_address(ip)
    if tool == "rdns":
        outcome, lines = _ptr(address.compressed)
        backend = "PTR (dnspython)"
    elif tool == "registration":
        outcome, lines = _registration(address)
        backend = "RDAP (ipwhois)"
    else:
        raise ValueError("Unknown IP lookup")
    return _output(address.compressed, backend, outcome, lines)
