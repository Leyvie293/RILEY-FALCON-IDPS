from scapy.all import *
from scapy.arch.windows import get_windows_if_list
import sys

print("=" * 60)
print("Npcap and Scapy Test")
print("=" * 60)

# List interfaces
print("\n1. Available Network Interfaces:")
interfaces = get_windows_if_list()
count = 0
for iface in interfaces:
    name = iface.get('name')
    desc = iface.get('description', '')
    ips = iface.get('ips', [])
    if name and ips:
        count += 1
        print(f"\n   [{count}] Interface: {name}")
        print(f"       Description: {desc[:80]}")
        print(f"       IPs: {', '.join(ips[:3])}")

print(f"\n   Total: {count} active interfaces")

# Try to capture on Wi-Fi
print("\n2. Testing Packet Capture...")
print("   Trying to capture on 'Wi-Fi' interface...")

try:
    # Try to capture 3 packets with 5 second timeout
    packets = sniff(count=3, timeout=5, iface='Wi-Fi')
    if len(packets) > 0:
        print(f"\n   SUCCESS! Captured {len(packets)} packets")
        for i, pkt in enumerate(packets[:3]):
            print(f"   Packet {i+1}: {pkt.summary()[:80]}")
    else:
        print("\n   No packets captured on 'Wi-Fi'")
        print("   Trying on all interfaces...")
        packets = sniff(count=3, timeout=5)
        if len(packets) > 0:
            print(f"   SUCCESS! Captured {len(packets)} packets on default interface")
        else:
            print("   No packets captured. Make sure you have network activity.")
            
except PermissionError:
    print("\n   PERMISSION ERROR! Need Administrator rights")
    print("   Please close and reopen PowerShell as Administrator")
except Exception as e:
    print(f"\n   Error: {e}")

print("\n" + "=" * 60)
