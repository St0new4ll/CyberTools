import subprocess
import sys

def nmap_scan(ip_address):
    try:
        # Run nmap scan with -sC and -sV flags
        result = subprocess.run(['nmap', '-sC', '-sV', ip_address], capture_output=True, text=True)
        print(result.stdout)
    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python nmap_scan.py <IP_ADDRESS>")
        sys.exit(1)

    ip_address = sys.argv[1]
    nmap_scan(ip_address)
