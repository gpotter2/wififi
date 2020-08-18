"""
Main class
"""

from multiprocessing import Process, Queue

from wififi.scan import scan
from wififi.hamiltonian.manager import HubManager

from scapy.sendrecv import sendp

def graphical_scan(iface):
    """
    Performs a graphical scan
    """
    ex_clients = []
    ex_hubs = []
    packets = {}
    queue = Queue()

    def callback(channel, hubs, devices):
        # Register hubs
        for hub in hubs:
            if hub not in ex_hubs:
                queue.put(hub)
                ex_hubs.append(hub)
            # Register devices
            for dev in devices[hub]["sub"]:
                if dev not in ex_clients:
                    queue.put((dev, hub))
                    ex_clients.append(dev)
        # Send packets
        packets_to_send = packets.get(channel, [])
        if packets_to_send:
            sendp(packets_to_send, iface=iface)

    # Start scan
    sniffer = Process(target=scan, args=(iface, callback))
    sniffer.daemon = True
    sniffer.start()

    def mg_callback(manager):
        while not queue.empty():
            i = queue.get()
            if isinstance(i, tuple):
                manager.add_point(*i)
            else:
                manager.add_hub(i)

    manager = HubManager(callback=mg_callback)
    # Start render
    manager.start(interval=10)
