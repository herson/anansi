"""Validation of scan targets supplied by users (CLI and web)."""
import ipaddress
import re
from urllib.parse import urlsplit

MAX_TARGET_ADDRESSES = 65536  # an IPv4 /16


def validate_target(target: str) -> bool:
    """Return True if target is an IP address or a CIDR range of at most MAX_TARGET_ADDRESSES."""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return network.num_addresses <= MAX_TARGET_ADDRESSES


_HOST_NAME = re.compile(r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$")


def validate_web_target(url: str) -> bool:
    """Return True if url is an http:// or https:// URL whose host is an IP address or a host name."""
    try:
        parts = urlsplit(url)
        parts.port  # raises ValueError for a port that isn't a number from 0 to 65535
    except ValueError:
        return False
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return False
    try:
        ipaddress.ip_address(parts.hostname)
        return True
    except ValueError:
        return len(parts.hostname) <= 253 and bool(_HOST_NAME.match(parts.hostname))
