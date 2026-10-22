
import psutil

def get_network_info():
    connections = []

    try:
        for c in psutil.net_connections(kind="inet"):
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "-"
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "-"

            if c.type == 1:
                protocol = "tcp"
            else:
                protocol = "udp"

            connections.append({
                "local": local,
                "remote": remote,
                "protocol": protocol
            })

    except (psutil.AccessDenied, PermissionError, OSError):
        pass

    return connections
