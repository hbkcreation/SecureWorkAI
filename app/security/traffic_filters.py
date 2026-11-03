"""Traffic that is normal background noise and should never raise attack alerts."""
from __future__ import annotations

import ipaddress


def is_noise_destination(ip: str | None) -> bool:
    """Multicast (SSDP/mDNS/WS-Discovery, e.g. 239.255.255.250), limited broadcast and IPv6 multicast.

    Devices on every home/office network chatter to these addresses all day; they are discovery
    traffic, not attacks, and the experimental ML model is not trained to judge them.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return addr.is_multicast or ip == "255.255.255.255"
