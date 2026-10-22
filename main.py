from network_monitor import get_network_info

connections = get_network_info()

print("=" * 70)
print("              NETGUARDIAN")
print("          SMART NETWORK ANALYZER")
print("=" * 70)

print(f"\nTotal Network Connections : {len(connections)}")

tcp_count = sum(1 for c in connections if c["protocol"].startswith("tcp"))
udp_count = sum(1 for c in connections if c["protocol"].startswith("udp"))

print(f"TCP Connections           : {tcp_count}")
print(f"UDP Connections           : {udp_count}")

suspicious = []
high_risk_ports = [21, 23, 25, 445, 3389, 4444, 5555]

for connection in connections:
    remote = connection["remote"]

    if remote not in ["*.*", "*"]:
        try:
            port = int(remote.split(".")[-1])

            if port in high_risk_ports:
                suspicious.append(connection)
        except:
            pass

print("\n" + "-" * 70)
print("              ANOMALY ANALYSIS")
print("-" * 70)

if len(connections) > 100:
    print("⚠ WARNING: High number of network connections detected")
else:
    print("✓ Connection volume: NORMAL")

if suspicious:
    print(f"⚠ Suspicious connections detected: {len(suspicious)}")

    for connection in suspicious:
        print(
            f"  → {connection['remote']} "
            f"using {connection['protocol'].upper()}"
        )
else:
    print("✓ No known suspicious ports detected")

print("\n" + "-" * 70)

if suspicious or len(connections) > 100:
    print("SECURITY STATUS : ⚠ WARNING")
else:
    print("SECURITY STATUS : ✓ NORMAL")

print("-" * 70)
print("\nNetwork analysis completed.")