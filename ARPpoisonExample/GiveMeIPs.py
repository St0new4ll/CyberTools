#!/usr/bin/env python3

import sys
import ipaddress
import socket
from scapy.all import Ether, ARP, srp, conf, get_if_addr

def get_hostname(ip):
    try:
        # socket.gethostbyaddr returns (hostname, aliaslist, ipaddrlist)
        hostname, _, _ = socket.gethostbyaddr(ip)
        return hostname
    except socket.herror:
        return None
    except socket.gaierror:
        return None

def main():
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <interface>")
        sys.exit(1)

    iface = sys.argv[1]
    conf.iface = iface

    # Determine default gateway
    default_gateway = conf.route.route("0.0.0.0")[2]
    # Local IP on the chosen interface
    local_ip = get_if_addr(iface)

    #assume a /24 network here
    network_cidr = f"{local_ip}/24"
    network = ipaddress.ip_network(network_cidr, strict=False)

    print(f"[+] Interface: {iface}")
    print(f"[+] Local IP: {local_ip}")
    print(f"[+] Default Gateway: {default_gateway}")
    print(f"[+] Scanning subnet: {network_cidr}")

    alive_hosts = []

    for ip in network.hosts():
        ip_str = str(ip)
        # Skip scanning our own IP
        if ip_str == local_ip:
            continue

        #
        ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_str), timeout=0.5, verbose=False)
        if ans:
            for _, received in ans:
                mac_address = received.hwsrc
                # Attempt to resolve hostname via reverse DNS
                hostname = get_hostname(ip_str)
                alive_hosts.append((ip_str, mac_address, hostname))

    print("\n[+] Discovered Hosts:")
    for ip_str, mac_addr, hostname in alive_hosts:
        gateway_tag = "(Gateway)" if ip_str == default_gateway else ""
        # Show hostname if found
        if hostname:
            print(f"  {ip_str} - {mac_addr} {gateway_tag} [Hostname: {hostname}]")
        else:
            print(f"  {ip_str} - {mac_addr} {gateway_tag}")

    print("\nDone. Hosts above responded to ARP requests.")

if __name__ == "__main__":
    main()
