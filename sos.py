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
    if not is_admin():
        print("Administrator privileges are required to execute this function.")
        print("Please rerun the script with elevated privileges.")
        return
    
    # Command to add a firewall rule
    command = f"netsh advfirewall firewall add rule name='Block {ip_address}' dir=in action=block remoteip={ip_address}"
    try:
        result = subprocess.run(command, shell=True, check=True, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"Successfully blocked IP {ip_address}.\n{result.stdout}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to block IP {ip_address}: {e.stderr}")

if __name__ == "__main__":
    ip_to_block = "10.0.0.138"  # Replace with the IP you want to block
    
    # Relaunch with elevated privileges if not already running as admin
    if not is_admin():
        print("Attempting to relaunch the script with administrator privileges...")
        script = sys.executable
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(None, "runas", script, params, None, 1)
        sys.exit()

    # Call the function to block IP
    block_ip_windows(ip_to_block)








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
