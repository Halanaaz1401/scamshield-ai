"""URL validation and Server-Side Request Forgery (SSRF) prevention for ScamShield AI.

Ensures arbitrary user-supplied URLs are safely validated before any backend
network lookups or reputation queries.
"""

import ipaddress
import re
import socket
from typing import Optional, Tuple
from urllib.parse import urlparse

# Restricted IP networks to prevent SSRF
RESTRICTED_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),      # IPv4 loopback
    ipaddress.ip_network("10.0.0.0/8"),       # RFC 1918 private
    ipaddress.ip_network("172.16.0.0/12"),    # RFC 1918 private
    ipaddress.ip_network("192.168.0.0/16"),   # RFC 1918 private
    ipaddress.ip_network("169.254.0.0/16"),   # IPv4 link-local / AWS metadata
    ipaddress.ip_network("0.0.0.0/8"),        # Current network
    ipaddress.ip_network("100.64.0.0/10"),    # Shared address space (Carrier-grade NAT)
    ipaddress.ip_network("192.0.0.0/24"),     # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),     # TEST-NET-1
    ipaddress.ip_network("198.18.0.0/15"),    # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),  # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),   # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),      # Multicast
    ipaddress.ip_network("240.0.0.0/4"),      # Reserved for future use
    ipaddress.ip_network("255.255.255.255/32"),  # Limited broadcast
    ipaddress.ip_network("::1/128"),          # IPv6 loopback
    ipaddress.ip_network("fc00::/7"),         # IPv6 unique local address (ULA)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
]

# Specifically banned cloud metadata hostnames
BANNED_METADATA_HOSTS = {
    "metadata.google.internal",
    "instance-data",
    "169.254.169.254",
    "fd00:ec2::254",
    "localhost",
}

# Dangerous protocol schemes that must never be evaluated for network fetch
UNSAFE_SCHEMES = {"javascript", "data", "file", "vbscript", "blob", "about"}


def is_ip_restricted(ip_str: str) -> bool:
    """Check if an IP address string belongs to any private or restricted range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in RESTRICTED_NETWORKS) or ip.is_private or ip.is_loopback or ip.is_link_local
    except ValueError:
        return False


def validate_url_for_safe_fetch(raw_url: str) -> Tuple[bool, Optional[str], Optional[str]]:
    """Validate that a URL is safe for external network lookups without SSRF risk.

    Returns:
        (is_safe: bool, normalized_url: Optional[str], error_message: Optional[str])
    """
    clean_url = (raw_url or "").strip()
    if not clean_url:
        return False, None, "URL is empty"

    if len(clean_url) > 4000:
        return False, None, "URL exceeds maximum length limit (4,000 characters)"

    # Check for dangerous schemes
    lower_url = clean_url.lower()
    for scheme in UNSAFE_SCHEMES:
        if lower_url.startswith(f"{scheme}:"):
            return False, None, f"Dangerous URI scheme '{scheme}:' is blocked"

    # Normalize prefix
    if not lower_url.startswith(("http://", "https://")):
        normalized_url = f"https://{clean_url}"
    else:
        normalized_url = clean_url

    try:
        parsed = urlparse(normalized_url)
    except Exception as exc:
        return False, None, f"Malformed URL syntax: {exc}"

    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return False, None, f"Unsupported URL scheme '{scheme}'. Only HTTP and HTTPS are permitted."

    hostname = (parsed.hostname or "").lower().strip()
    if not hostname:
        return False, None, "URL contains no valid host destination"

    # Check for '@' userinfo abuse
    if parsed.username or parsed.password:
        return False, None, "URLs containing embedded userinfo credentials are not permitted for external lookup"

    # Check for banned metadata hosts
    if hostname in BANNED_METADATA_HOSTS:
        return False, None, f"Access to restricted host '{hostname}' is forbidden (SSRF protection)"

    # Check if host is direct IP address
    if is_ip_restricted(hostname):
        return False, None, f"Access to private or loopback IP destination '{hostname}' is forbidden (SSRF protection)"

    # Check non-standard ports
    port = parsed.port
    if port is not None and port not in (80, 443, 8080, 8443):
        # We permit analysis of non-standard ports by heuristics, but restrict outbound HTTP queries
        pass

    return True, normalized_url, None


def resolve_hostname_safely(hostname: str) -> Tuple[bool, Optional[str]]:
    """Resolve a hostname via DNS and ensure none of the resolved IPs are private/restricted.

    Returns:
        (is_safe: bool, reason_if_unsafe: Optional[str])
    """
    try:
        # Get all address info
        addr_info = socket.getaddrinfo(hostname, None)
        for entry in addr_info:
            ip_str = entry[4][0]
            if is_ip_restricted(ip_str):
                return False, f"Hostname '{hostname}' resolves to restricted IP '{ip_str}'"
        return True, None
    except socket.gaierror:
        # Host could not be resolved; not inherently SSRF, but not reachable
        return True, None
    except Exception as exc:
        return False, f"DNS resolution error: {exc}"
