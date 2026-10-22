
from flask import Flask, render_template
from network_monitor import get_network_info

app = Flask(__name__)


@app.route("/")
def home():
    connections = get_network_info()

    tcp_count = sum(
        1 for c in connections
        if c["protocol"].startswith("tcp")
    )

    udp_count = sum(
        1 for c in connections
        if c["protocol"].startswith("udp")
    )

    suspicious_ports = [21, 23, 25, 445, 3389, 4444, 5555]
    suspicious = []

    for connection in connections:
        remote = connection["remote"]

        try:
            port = int(remote.split(".")[-1])

            if port in suspicious_ports:
                suspicious.append(connection)
        except (ValueError, IndexError):
            pass

    status = (
        "WARNING"
        if suspicious or len(connections) > 100
        else "NORMAL"
    )

    return render_template(
        "index.html",
        total=len(connections),
        tcp=tcp_count,
        udp=udp_count,
        suspicious=len(suspicious),
        status=status,
        connections=connections[:15]
    )


if __name__ == "__main__":
    app.run(debug=False)
