import ctypes
import subprocess
import sys

def is_admin():
    """
    Check if the script is running with administrator privileges.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

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
    ip_to_block = "10.0.0.138"  # Replace with the IP you want to block
    block_ip_windows(ip_to_block)
    input()








# import subprocess

# def block_ip_windows(ip_address):
#     """
#     Blocks the specified IP address using Windows Firewall.
#     """
#     command = f"netsh advfirewall firewall add rule name='Block {ip_address}' dir=in action=block remoteip={ip_address}"
#     try:
#         result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
#         print(f"Successfully blocked IP {ip_address}.\n{result.stdout}")
#     except subprocess.CalledProcessError as e:
#         print(f"Failed to block IP {ip_address}: {e.stderr}")

# # Example Usage
# if __name__ == "__main__":
#     ip_to_block = "10.0.0.138"  # Repl  ace with the IP you want to block
#     block_ip_windows(ip_to_block)
