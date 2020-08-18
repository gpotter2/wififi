"""
Find nearby Wi-Fi devices
"""

import scapy
import subprocess

from collections import defaultdict

from scapy.config import conf, _version_checker
from scapy.layers.dot11 import *

# Requires Scapy 2.5.0
if not _version_checker(scapy, (2, 4, 4)):
    raise ValueError("Requires Scapy 2.5.0+")

def setchannel(iface, channel):
    subprocess.check_call(["iw", iface, "set", "channel", str(channel)])

_ts = {  # Timeout table per channel
    1: 3,
    2: 1,
    3: 1,
    4: 1,
    5: 1,
    6: 3,
    7: 1,
    8: 1,
    9: 1,
    10: 1,
    11: 3,
    12: 1,
    13: 1,
}

def _get_dot11_addresses(pkt):
    """
    Sort the types of the Dot11 addresses
    """
    src = None
    dst = None
    extras = []
    for i in range(1, 5):
        addr = pkt.getfieldval("addr%s" % i)
        if not addr:
            continue
        addr = conf.manufdb._resolve_MAC(addr)
        addrtype = pkt.address_meaning(i)
        if "DA" in addrtype:
            dst = addr
        elif "SA" in addrtype:
            src = addr
        elif addr and addr != "ff:ff:ff:ff:ff:ff":
            extras.append(addr)
    return src, dst, extras

def scan(iface, callback):
    """
    Continously scan WiFi devices and calls callback.

    :param iface: a string interface name
    :param callback: callback(channel, hubs, devices)
    """
    hubs = []
    devices = defaultdict(dict)

    def _prn(pkt):
        if Dot11 in pkt:
            src, dst, extras = _get_dot11_addresses(pkt[Dot11])
            if Dot11Beacon in pkt:
                # Hub
                if src:
                    devices[src].update(pkt[Dot11Beacon].network_stats())
                    devices[src].setdefault("sub", [])
                    hubs.append(src)
            else:
                if src and dst:
                    if src in hubs:
                        devices[dst]
                        devices[src].setdefault("sub", []).append(dst)
                    elif dst in hubs:
                        devices[src]
                        devices[dst].setdefault("sub", []).append(src)
            # XXX Detect standalone devices
    try:
        while True:
            for ch in range(1, 14):  # 1-13
                setchannel(iface, ch)
                sniff(iface=iface, prn=_prn, timeout=_ts.get(ch))
                callback(ch, hubs, devices)
    except KeyboardInterrupt:
        return
