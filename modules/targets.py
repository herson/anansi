"""Validation of scan targets supplied by users (CLI and web)."""
import ipaddress

MAX_TARGET_ADDRESSES = 65536  # an IPv4 /16


def validate_target(target: str) -> bool:
    """Return True if target is an IP address or a CIDR range of at most MAX_TARGET_ADDRESSES."""
    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return False
    return network.num_addresses <= MAX_TARGET_ADDRESSES
