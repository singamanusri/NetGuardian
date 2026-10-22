import subprocess

def get_network_info():
    result = subprocess.run(
        ["netstat", "-an"],
        capture_output=True,
        text=True
    )

    connections = []

    for line in result.stdout.splitlines():
        parts = line.split()

        if len(parts) >= 5 and parts[0] in ["tcp4", "tcp6", "udp4", "udp6"]:
            protocol = parts[0]
            local = parts[3]
            remote = parts[4]

            connections.append({
                "local": local,
                "remote": remote,
                "protocol": protocol
            })

    return connections