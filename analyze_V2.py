from collections import defaultdict
from scapy.layers.inet import IP, TCP, UDP
import sys
from scapy.all import sniff
import os
def check_pcap():
    try:
        # Try a quick zero-count sniff to force loading of pcap
        sniff(count=0, timeout=1)
    except RuntimeError as e:
        msg = str(e)
        if "winpcap is not installed" in msg.lower() or "no libpcap provider available" in msg.lower():
            sys.exit(
                "\nERROR: A packet-capture driver is required (Npcap/WinPcap).\n"
                "Please download and install it from:\n"
                "    https://nmap.org/npcap/\n"
                "  • During installation, enable \"WinPcap API-compatible mode\".\n"
                "  • Then re-run this script.\n"
            )
        else:
            # re-raise unexpected errors
            raise

# 1) Static whitelist loading
def load_whitelist(file_path="whitelist.txt"):
    """
    Load a whitelist of trusted IP addresses from an external file.
    Each line should contain one IP address.
    """
    wl = set()
    if os.path.exists(file_path):
        with open(file_path) as f:
            for line in f:
                ip = line.strip()
                if ip:
                    wl.add(ip)
    return wl

WHITELIST = load_whitelist()

# 2) Packet info extractor
def extract_packet_info(pkt):
    """
    Extracts relevant details from a packet:
      - src_ip, dst_ip, protocol, dst_port, flags
    """
    if IP in pkt:
        info = {
            "src_ip": pkt[IP].src,
            "dst_ip": pkt[IP].dst,
            "protocol": None,
            "dst_port": None,
            "flags": None
        }
        if TCP in pkt:
            info["protocol"] = "TCP"
            info["dst_port"] = pkt[TCP].dport
            info["flags"]    = str(pkt[TCP].flags)
        elif UDP in pkt:
            info["protocol"] = "UDP"
            info["dst_port"] = pkt[UDP].dport
        return info
    return None

# 3) Build dynamic trust sets: full TCP handshake & rate-based trust
def build_trust_sets(packet_infos, client_ip,
                     min_outgoing=5, ratio_threshold=1.0):
    """
    Returns two sets:
      - handshake_done: IPs with full 3-way TCP handshake
      - dynamic_trust: IPs where outgoing>=min_outgoing and outgoing/incoming>=ratio_threshold
    """
    syn_sent = set()
    synack_seen = set()
    handshake_done = set()
    outgoing = defaultdict(int)
    incoming = defaultdict(int)

    for info in packet_infos:
        src = info.get("src_ip")
        dst = info.get("dst_ip")
        proto = info.get("protocol")
        flags = info.get("flags")

        # Track full TCP 3-way handshake
        if proto == "TCP":
            # 1) We sent SYN to remote
            if src == client_ip and flags == "S":
                syn_sent.add(dst)
            # 2) They replied SYN+ACK
            elif dst == client_ip and (flags == "SA"):
                if src in syn_sent:
                    synack_seen.add(src)
            # 3) We sent final ACK
            elif src == client_ip and (flags == "A"):
                if dst in synack_seen:
                    handshake_done.add(dst)

        # Track outgoing / incoming counts for any protocol
        if src == client_ip:
            outgoing[dst] += 1
        elif dst == client_ip:
            incoming[src] += 1

    # Build rate-based dynamic trust
    dynamic_trust = set()
    for ip, out_count in outgoing.items():
        in_count = incoming.get(ip, 0)
        if out_count >= min_outgoing and (out_count / max(1, in_count)) >= ratio_threshold:
            dynamic_trust.add(ip)

    return handshake_done, dynamic_trust

# 4) Detection functions (skipping any IP in combined trust)
def detect_port_scanning(packet_infos, client_ip, trust_set,
                         tcp_flag_threshold=1,
                         tcp_port_threshold=10,
                         udp_port_threshold=10):
    tcp_flagged_ports = defaultdict(set)
    tcp_all_ports     = defaultdict(set)
    udp_all_ports     = defaultdict(set)

    for info in packet_infos:
        if info.get("dst_ip") != client_ip:
            continue
        src = info["src_ip"]
        if src in trust_set:
            continue

        proto = info.get("protocol")
        port  = info.get("dst_port")
        flags = info.get("flags")

        if proto == "TCP":
            tcp_all_ports[src].add(port)
            # Suspicious flag patterns
            if flags in ("S", "F", "0"):            # single‐flag cases
                tcp_flagged_ports[src].add(port)
            # multi‐flag case: FIN+PSH+URG
            elif all(c in flags for c in ("F","P","U")):
                tcp_flagged_ports[src].add(port)

        elif proto == "UDP":
            udp_all_ports[src].add(port)

    results = {}
    for src in set(tcp_all_ports) | set(udp_all_ports):
        if src in trust_set:
            continue
        entry = {}
        # TCP: flags-based and/or volume-based
        tcp_report = set()
        if len(tcp_flagged_ports[src]) >= tcp_flag_threshold:
            tcp_report |= tcp_flagged_ports[src]
        if len(tcp_all_ports[src])   >= tcp_port_threshold:
            tcp_report |= tcp_all_ports[src]
        if tcp_report:
            entry["TCP"] = sorted(tcp_report)
        # UDP: only volume-based
        if len(udp_all_ports[src]) >= udp_port_threshold:
            entry["UDP"] = sorted(udp_all_ports[src])
        if entry:
            results[src] = entry
    return results


def detect_brute_force(packet_infos, client_ip, trust_set,
                       ssh_threshold=5, rdp_threshold=5, http_threshold=10):
    brute_counts = defaultdict(lambda: {"SSH":0, "RDP":0, "HTTP":0})

    for info in packet_infos:
        if info.get("dst_ip") != client_ip:
            continue
        src = info["src_ip"]
        if src in trust_set:
            continue
        if info.get("protocol") != "TCP":
            continue

        port = info.get("dst_port")
        if port == 22:
            brute_counts[src]["SSH"] += 1
        elif port == 3389:
            brute_counts[src]["RDP"] += 1
        elif port in (80, 443):
            brute_counts[src]["HTTP"] += 1

    results = {}
    for src, counts in brute_counts.items():
        alerts = {}
        if counts["SSH"] >= ssh_threshold:
            alerts["SSH"] = counts["SSH"]
        if counts["RDP"] >= rdp_threshold:
            alerts["RDP"] = counts["RDP"]
        if counts["HTTP"] >= http_threshold:
            alerts["HTTP"] = counts["HTTP"]
        if alerts:
            results[src] = alerts
    return results


def detect_ddos(packet_infos, client_ip, trust_set,
                syn_threshold=50, udp_threshold=50, http_syn_threshold=30):
    ddos_counts = defaultdict(lambda: {"SYN":0, "HTTP":0, "UDP":0})

    for info in packet_infos:
        if info["dst_ip"] != client_ip or info["src_ip"] in trust_set:
            continue

        proto = info["protocol"]
        port  = info["dst_port"]
        flags = info["flags"]

        if proto == "TCP":
            if flags == "S":
                ddos_counts[info["src_ip"]]["SYN"] += 1
                if port in (80,443):
                    ddos_counts[info["src_ip"]]["HTTP"] += 1
        elif proto == "UDP":
            ddos_counts[info["src_ip"]]["UDP"] += 1

    results = {}
    for src, counts in ddos_counts.items():
        alerts = {}
        if counts["SYN"] >= syn_threshold:
            alerts["SYN Flood"] = counts["SYN"]
        if counts["UDP"] >= udp_threshold:
            alerts["UDP Flood"] = counts["UDP"]
        if counts["HTTP"] >= http_syn_threshold:
            alerts["HTTP Flood"] = counts["HTTP"]
        if alerts:
            results[src] = alerts
    return results


# 5) Orchestration
if __name__ == "__main__":
    # 0) Ensure the user has Npcap/WinPcap installed
    check_pcap()

    # 1) Now proceed with your normal sniff-and-analyze flow:
    client_ip = "192.168.0.113"
    packets = sniff(count=500, filter="ip")
    infos = [extract_packet_info(p) for p in packets if extract_packet_info(p)]

    handshake_done, dynamic_trust = build_trust_sets(infos, client_ip)
    trust_set = WHITELIST | handshake_done | dynamic_trust

    scans = detect_port_scanning(infos, client_ip, trust_set)
    bruteforce = detect_brute_force(infos, client_ip, trust_set)
    ddos = detect_ddos(infos, client_ip, trust_set)

    if scans:
        print("[ALERT] Port scanning detected:")
        for ip, proto_data in scans.items():
            for proto, ports in proto_data.items():
                print(f"{ip} scanned {proto} ports: {ports}")
    if bruteforce:
        print("[ALERT] Brute force detected:")
        for ip, attacks in bruteforce.items():
            for atk, count in attacks.items():
                print(f"{ip} {atk} attempts: {count}")
    if ddos:
        print("[ALERT] DDoS detected:")
        for ip, attacks in ddos.items():
            for atk, count in attacks.items():
                print(f"{ip} {atk}: {count} packets")
    if not (scans or bruteforce or ddos):
        print("No suspicious activity detected.")
