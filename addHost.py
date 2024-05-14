import sys
import os

def add_to_hosts(ip_address, website):
    try:
        hosts_path = "/etc/hosts"
        entry = f"{ip_address} {website}\n"

        # Check if the entry already exists
        with open(hosts_path, 'r') as file:
            if entry in file.readlines():
                print(f"The entry '{entry.strip()}' already exists in {hosts_path}")
                return

        # Append the new entry to the hosts file
        with open(hosts_path, 'a') as file:
            file.write(entry)
            print(f"Added '{entry.strip()}' to {hosts_path}")

    except PermissionError:
        print("Permission denied: You need to run this script with sudo privileges.")
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python add_to_hosts.py <IP_ADDRESS> <WEBSITE>")
        sys.exit(1)

    ip_address = sys.argv[1]
    website = sys.argv[2]
    add_to_hosts(ip_address, website)
