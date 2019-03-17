import binascii
import select
import socketserver
import color_def

from scapy.all import *


class Sniffer(Thread):
    def __init__(self, host, interface=None):
        super().__init__()

        self.daemon = True

        self.socket = None

        self.filters = "host " + str(host)

        self.interface = interface
        self.stop_sniffer = Event()
        self.num = 0

    def run(self):
        print("Run call")
        self.socket = conf.L2listen(
            type=ETH_P_ALL,
            iface=self.interface,
            filter=self.filters
        )
        print("Run middle")
        self.capture = sniff(
            # timeout=20,
            # count=1000,
            opened_socket=self.socket,
            prn=self.print_packet,
            stop_filter=self.should_stop_sniffer  # ,
            # store=0
        )
        print("Stop sniffing...")

    def join(self, timeout=None):
        self.stop_sniffer.set()
        super().join(timeout)

    def should_stop_sniffer(self, packet):
        return self.stop_sniffer.isSet()

    def print_packet(self, packet):
        ip_layer = packet.getlayer(IP)
        self.num = self.num + 1
        if self.num == 200:
            print("[!] New Packet: {src} -> {dst}".format(src=ip_layer.src, dst=ip_layer.dst))
            self.num = 0
