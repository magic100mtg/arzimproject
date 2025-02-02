import ctypes
import subprocess
import sys

def block_ip_windows(ip_address):
    """
    Blocks the specified IP address using Windows Firewall.
    """
    command= f"powershell.exe Start-process -Verb RunAs netsh -ArgumentList advfirewall, firewall, add, rule, name='Block_{ip_address}', dir=in, action=block, remoteip={ip_address}"
    print(command)
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Successfully blocked IP {ip_address}.\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip_address}: {e.stderr}")

if __name__ == "__main__":
    ip_to_block = "10.0.0.139"  # Replace with the IP you want to block
    block_ip_windows(ip_to_block)
    input()







