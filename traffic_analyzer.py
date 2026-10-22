from scapy.all import sniff, IP, TCP, UDP, ICMP
from collections import Counter
from datetime import datetime

packet_count = 0
protocols = Counter()
source_ips = Counter()
destination_ips = Counter()


def analyze_packet(packet):
    global packet_count

    if IP not in packet:
        return

    packet_count += 1

    src = packet[IP].src
    dst = packet[IP].dst

    source_ips[src] += 1
    destination_ips[dst] += 1

    if TCP in packet:
        protocols["TCP"] += 1
    elif UDP in packet:
        protocols["UDP"] += 1
    elif ICMP in packet:
        protocols["ICMP"] += 1
    else:
        protocols["Other"] += 1


print("====================================")
print("     Network Traffic Analyzer")
print("====================================")
print("[+] Starting packet capture...")
print("[+] Capture 10 packets")
print()

sniff(
    iface="lo",
    prn=analyze_packet,
    count=10,
    store=False
)

print()
print("====================================")
print("          Traffic Report")
print("====================================")

print(f"Total IP packets: {packet_count}")

print("\nProtocol Distribution:")
for protocol, count in protocols.items():
    print(f"  {protocol}: {count}")

print("\nTop Source IPs:")
for ip, count in source_ips.most_common(5):
    print(f"  {ip}: {count} packets")

print("\nTop Destination IPs:")
for ip, count in destination_ips.most_common(5):
    print(f"  {ip}: {count} packets")

print()
print(f"Analysis completed: {datetime.now()}")

with open("traffic_report.txt", "w") as report:
    report.write("Network Traffic Analyzer Report\n")
    report.write("=" * 40 + "\n\n")
    report.write(f"Total IP packets: {packet_count}\n\n")

    report.write("Protocol Distribution:\n")
    for protocol, count in protocols.items():
        report.write(f"  {protocol}: {count}\n")

    report.write("\nTop Source IPs:\n")
    for ip, count in source_ips.most_common(5):
        report.write(f"  {ip}: {count} packets\n")

    report.write("\nTop Destination IPs:\n")
    for ip, count in destination_ips.most_common(5):
        report.write(f"  {ip}: {count} packets\n")

    report.write(f"\nAnalysis completed: {datetime.now()}\n")

print("[+] Report saved as: traffic_report.txt")
