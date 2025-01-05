from collections import defaultdict
import json
from scapy.layers.inet import IP, TCP, UDP
from scapy.all import *


class NetworkMonitor:
    def __init__(self, threshold=3):
        self.threshold = threshold
        self.connections = defaultdict(lambda: {
            'ports': set(),
            'protocols': set(),
            'connection_count': 0,
            'port_categories': defaultdict(int)
        })
        
    def categorize_port(self, port):
        well_known = {
            80: 'HTTP', 443: 'HTTPS', 53: 'DNS', 
            22: 'SSH', 21: 'FTP', 25: 'SMTP',
            5353: 'mDNS', 1900: 'UPNP'
        }
        if port in well_known:
            return well_known[port]
        elif port < 1024:
            return 'Well-Known'
        elif port < 49152:
            return 'Registered'
        else:
            return 'Dynamic/Private'

    def analyze_ip(self, ip):
        data = self.connections[ip]
        analysis = {
            'ip': ip,
            'unique_ports': len(data['ports']),
            'protocols': list(data['protocols']),
            'ports': sorted(list(data['ports'])),
            'port_categories': dict(data['port_categories']),
            'connection_count': data['connection_count'],
            'risk_factors': []
        }
        
        if len(data['ports']) >= self.threshold:
            analysis['risk_factors'].append('Multiple Ports')
        if any(p >= 49152 for p in data['ports']):
            analysis['risk_factors'].append('High Port Numbers')
        if len(data['protocols']) > 1:
            analysis['risk_factors'].append('Multiple Protocols')
        if data['connection_count'] / len(data['ports']) > 3:
            analysis['risk_factors'].append('Repeated Connections')
            
        return analysis

    def process_packet_data(self, packet_data):
        """
        Process a single packet's data from JSON format
        
        Args:
            packet_data (dict): Dictionary containing packet information
        """
        try:
            src_ip = packet_data.get('src_ip')
            dst_port = packet_data.get('dst_port')
            protocol = packet_data.get('protocol')
            
            if src_ip and dst_port and protocol:
                ip_data = self.connections[src_ip]
                ip_data['ports'].add(dst_port)
                ip_data['protocols'].add(protocol)
                ip_data['connection_count'] += 1
                ip_data['port_categories'][self.categorize_port(dst_port)] += 1
                
                if len(ip_data['ports']) >= self.threshold:
                    return self.analyze_ip(src_ip)
        except Exception as e:
            print(f"Error processing packet data: {e}")
        return None

def analyze_json_data(data, threshold=3):
    """
    Analyze network traffic data from a JSON string.
    
    Args:
        json_string (str): JSON string containing network traffic data
        threshold (int): Number of unique ports to trigger suspicious activity
    
    Returns:
        dict: Dictionary of suspicious IPs and their analysis
    """
    monitor = NetworkMonitor(threshold)
    suspicious_ips = {}
    
    try:
        # Parse JSON data
        #data = json.loads(json_string)
        
        # Handle both single packet and array of packets
        packets = data if isinstance(data, list) else [data]
        
        print(f"Processing {len(packets)} packets...")
        for packet in packets:
            analysis = monitor.process_packet_data(packet)
            if analysis and analysis['ip'] not in suspicious_ips:
                suspicious_ips[analysis['ip']] = analysis
                print(f"\nSuspicious activity detected from {analysis['ip']}:")
                print(f"Risk Factors: {', '.join(analysis['risk_factors'])}")
                print(f"Protocols: {', '.join(analysis['protocols'])}")
                print(f"Ports: {analysis['ports']}")
                print(f"Total Connections: {analysis['connection_count']}")
        
        return suspicious_ips
        
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON string: {e}")
        return {}
    except Exception as e:
        print(f"Error processing data: {e}")
        return {}

# Example of how to use it in your project:
def detect_suspicious(json_string):
    """
    Wrapper function to detect suspicious IPs from JSON string data.
    Returns list of suspicious IPs.
    """
    suspicious = analyze_json_data(json_string, threshold=3)
    return list(suspicious.keys())

def main():
    json_string = json.dumps([
    {"src_ip": "192.168.1.100", "dst_port": 80, "protocol": "TCP"},
    {"src_ip": "192.168.1.100", "dst_port": 22, "protocol": "TCP"},
    {"src_ip": "192.168.1.100", "dst_port": 443, "protocol": "TCP"},
    ])
    suspicious_ips = analyze_json_data(json_string, threshold=3)
    print(f"Suspicious IPs: {suspicious_ips}")

if __name__ == "__main__":
    main()


































# class NetworkMonitor:
#     def __init__(self):
#         self.packet_data = defaultdict(list)

#     def process_packet_data(self, packet_data):
#         # Basic example of processing packet data
#         src_ip = packet_data.get("src_ip")
#         dst_port = packet_data.get("dst_port")
#         protocol = packet_data.get("protocol")
        
#         if src_ip and dst_port and protocol:
#             # Mock suspicious activity detection for demonstration
#             self.packet_data[src_ip].append(packet_data)
#             if dst_port < 1024:  # Treat access to privileged ports as suspicious
#                 return {
#                     'ip': src_ip,
#                     'risk_factors': ['Privileged port access'],
#                     'protocols': [protocol],
#                     'ports': [dst_port],
#                     'connection_count': len(self.packet_data[src_ip]),
#                     'port_categories': {'privileged': 1}  # Simplified for example
#                 }
#         return None

# class NetworkSniffer:
#     def __init__(self, interface=None):
#         self.interface = interface
#         self.monitor = NetworkMonitor()
#         self.stop_sniffing = threading.Event()
        
#     def packet_callback(self, packet):
#         """Process each captured packet"""
#         if IP in packet:
#             # Extract basic packet information
#             packet_data = {
#                 'src_ip': packet[IP].src,
#                 'dst_port': None,
#                 'protocol': None
#             }
            
#             # Handle TCP packets
#             if TCP in packet:
#                 packet_data['dst_port'] = packet[TCP].dport
#                 packet_data['protocol'] = 'TCP'
            
#             # Handle UDP packets
#             elif UDP in packet:
#                 packet_data['dst_port'] = packet[UDP].dport
#                 packet_data['protocol'] = 'UDP'
            
#             # Only process if we have all required fields
#             if all(packet_data.values()):
#                 analysis = self.monitor.process_packet_data(packet_data)
#                 if analysis:
#                     self._print_analysis(analysis)
    
#     def _print_analysis(self, analysis):
#         """Print analysis results in a formatted way"""
#         print("\n" + "="*50)
#         print(f"Suspicious Activity Detected from {analysis['ip']}")
#         print("="*50)
#         print(f"Risk Factors: {', '.join(analysis['risk_factors'])}")
#         print(f"Protocols Used: {', '.join(analysis['protocols'])}")
#         print(f"Ports Accessed: {analysis['ports']}")
#         print(f"Connection Count: {analysis['connection_count']}")
#         print(f"Port Categories:")
#         for category, count in analysis['port_categories'].items():
#             print(f"  - {category}: {count}")
#         print("="*50)
    
#     def start_sniffing(self):
#         """Start packet capture"""
#         try:
#             print(f"Starting network capture{' on ' + self.interface if self.interface else ''}")
#             print("Press Ctrl+C to stop capturing...")
            
#             # Configure sniff parameters
#             kwargs = {
#                 'prn': self.packet_callback,
#                 'store': 0,  # Don't store packets in memory
#                 'filter': 'ip',  # Only capture IP packets
#             }
#             if self.interface:
#                 kwargs['iface'] = self.interface
            
#             # Start sniffing
#             sniff(**kwargs)
            
#         except KeyboardInterrupt:
#             print("\nStopping packet capture...")
#         except Exception as e:
#             print(f"Error during packet capture: {e}")
    
#     def get_interfaces(self):
#         """Get list of available network interfaces"""
#         return get_if_list()

# def main():
#     # Create sniffer instance
#     sniffer = NetworkSniffer()
    
#     # Show available interfaces
#     print("Available network interfaces:")
#     for i, iface in enumerate(sniffer.get_interfaces(), 1):
#         print(f"{i}. {iface}")
    
#     # Optional: Let user select interface
#     try:
#         choice = input("\nSelect interface number (press Enter for all interfaces): ").strip()
#         if choice:
#             selected_interface = sniffer.get_interfaces()[int(choice) - 1]
#             sniffer = NetworkSniffer(selected_interface)
#     except (ValueError, IndexError):
#         print("Invalid selection, using all interfaces")
    
#     # Start sniffing
#     sniffer.start_sniffing()

# if __name__ == "__main__":
#     main()

