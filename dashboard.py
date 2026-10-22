import tkinter as tk
from network_monitor import get_network_info


def scan_network():
    connections = get_network_info()

    total = len(connections)

    tcp = sum(
        1 for c in connections
        if c["protocol"].startswith("tcp")
    )

    udp = sum(
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

        except:
            pass

    total_value.config(text=str(total))
    tcp_value.config(text=str(tcp))
    udp_value.config(text=str(udp))
    alert_value.config(text=str(len(suspicious)))

    if suspicious or total > 100:
        status_value.config(
            text="THREAT DETECTED",
            fg="#ff4444"
        )
    else:
        status_value.config(
            text="SYSTEM SECURE",
            fg="#00cc66"
        )

    activity.delete("1.0", tk.END)

    for connection in connections[:20]:
        activity.insert(
            tk.END,
            f"{connection['protocol'].upper():<8}"
            f"{connection['local']:<28}"
            f"{connection['remote']}\n"
        )


root = tk.Tk()

root.title("NetGuardian SOC Dashboard")
root.geometry("1100x700")
root.configure(bg="#0b0f14")
root.resizable(False, False)


# HEADER

header = tk.Frame(
    root,
    bg="#111820",
    height=90
)

header.pack(fill="x")
header.pack_propagate(False)


title = tk.Label(
    header,
    text="NETGUARDIAN SOC",
    font=("Helvetica", 25, "bold"),
    fg="#00e5ff",
    bg="#111820"
)

title.pack(
    anchor="w",
    padx=30,
    pady=(18, 0)
)


subtitle = tk.Label(
    header,
    text="Security Operations Center • Smart Network Anomaly Detection",
    font=("Helvetica", 11),
    fg="#8b9aa8",
    bg="#111820"
)

subtitle.pack(
    anchor="w",
    padx=32
)


# DASHBOARD TITLE

dashboard_title = tk.Label(
    root,
    text="SECURITY OVERVIEW",
    font=("Helvetica", 15, "bold"),
    fg="#ffffff",
    bg="#0b0f14"
)

dashboard_title.pack(
    anchor="w",
    padx=30,
    pady=(25, 12)
)


# STAT CARDS

frame = tk.Frame(
    root,
    bg="#0b0f14"
)

frame.pack(
    fill="x",
    padx=25
)


labels = [
    ("TOTAL CONNECTIONS", "total"),
    ("TCP CONNECTIONS", "tcp"),
    ("UDP CONNECTIONS", "udp"),
    ("SECURITY ALERTS", "alert")
]


total_value = None
tcp_value = None
udp_value = None
alert_value = None


for i, (text, name) in enumerate(labels):

    box = tk.Frame(
        frame,
        bg="#151c24",
        width=240,
        height=105,
        highlightbackground="#263442",
        highlightthickness=1
    )

    box.grid(
        row=0,
        column=i,
        padx=7
    )

    box.grid_propagate(False)


    label = tk.Label(
        box,
        text=text,
        font=("Helvetica", 9, "bold"),
        fg="#8b9aa8",
        bg="#151c24"
    )

    label.pack(
        anchor="w",
        padx=18,
        pady=(16, 4)
    )


    value = tk.Label(
        box,
        text="0",
        font=("Helvetica", 25, "bold"),
        fg="#ffffff",
        bg="#151c24"
    )

    value.pack(
        anchor="w",
        padx=18
    )


    if name == "total":
        total_value = value

    elif name == "tcp":
        tcp_value = value

    elif name == "udp":
        udp_value = value

    elif name == "alert":
        alert_value = value


# SECURITY STATUS

status_frame = tk.Frame(
    root,
    bg="#151c24",
    highlightbackground="#263442",
    highlightthickness=1
)

status_frame.pack(
    fill="x",
    padx=32,
    pady=22
)


tk.Label(
    status_frame,
    text="CURRENT SECURITY STATUS",
    font=("Helvetica", 10, "bold"),
    fg="#8b9aa8",
    bg="#151c24"
).pack(
    anchor="w",
    padx=20,
    pady=(14, 2)
)


status_value = tk.Label(
    status_frame,
    text="NOT SCANNED",
    font=("Helvetica", 19, "bold"),
    fg="#ffaa00",
    bg="#151c24"
)

status_value.pack(
    anchor="w",
    padx=20,
    pady=(0, 14)
)


# SCAN BUTTON

scan_button = tk.Button(
    root,
    text="▶  SCAN NETWORK",
    command=scan_network,
    font=("Helvetica", 12, "bold"),
    fg="#000000",
    bg="#00e5ff",
    activebackground="#00b8cc",
    activeforeground="#000000",
    relief="flat",
    padx=30,
    pady=10,
    cursor="hand2"
)

scan_button.pack(
    pady=(0, 20)
)


# NETWORK ACTIVITY

activity_title = tk.Label(
    root,
    text="NETWORK ACTIVITY",
    font=("Helvetica", 14, "bold"),
    fg="#ffffff",
    bg="#0b0f14"
)

activity_title.pack(
    anchor="w",
    padx=32,
    pady=(0, 8)
)


activity_frame = tk.Frame(
    root,
    bg="#151c24",
    highlightbackground="#263442",
    highlightthickness=1
)

activity_frame.pack(
    fill="both",
    expand=True,
    padx=32
)


activity = tk.Text(
    activity_frame,
    width=110,
    height=13,
    font=("Menlo", 10),
    fg="#d7e0e8",
    bg="#111820",
    insertbackground="#ffffff",
    relief="flat",
    padx=15,
    pady=12
)

activity.pack(
    fill="both",
    expand=True
)


root.mainloop()