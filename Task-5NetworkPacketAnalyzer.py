import tkinter as tk
from tkinter import ttk, messagebox
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP, ICMP
import threading


class PacketSnifferApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Python Packet Sniffer")
        self.root.geometry("900x500")
        self.root.resizable(True, True)

        self.is_sniffing = False
        self.sniffer_thread = None

        self.create_widgets()

    def create_widgets(self):
        control_frame = ttk.Frame(self.root)
        control_frame.pack(pady=10, padx=10, fill=tk.X)

        self.start_btn = ttk.Button(control_frame, text="Start Capture", command=self.start_capture)
        self.start_btn.pack(side=tk.LEFT, padx=5)

        self.stop_btn = ttk.Button(control_frame, text="Stop Capture", command=self.stop_capture, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        self.clear_btn = ttk.Button(control_frame, text="Clear", command=self.clear_table)
        self.clear_btn.pack(side=tk.LEFT, padx=5)

        columns = ("time", "src", "dst", "proto", "len", "info")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        self.tree.heading("time", text="Time")
        self.tree.heading("src", text="Source IP")
        self.tree.heading("dst", text="Destination IP")
        self.tree.heading("proto", text="Protocol")
        self.tree.heading("len", text="Length")
        self.tree.heading("info", text="Info")

        for col in columns:
            self.tree.column(col, anchor=tk.W, width=140)

        self.tree.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

        # Vertical scrollbar
        scrollbar = ttk.Scrollbar(self.tree, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        # Status bar
        self.status = ttk.Label(self.root, text="Ready", relief=tk.SUNKEN, anchor=tk.W)
        self.status.pack(fill=tk.X, side=tk.BOTTOM)

    def start_capture(self):
        if self.is_sniffing:
            return
        self.is_sniffing = True
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.status.config(text="Capturing packets...")

        # Start sniffing in new thread to keep UI responsive
        self.sniffer_thread = threading.Thread(target=self.sniff_packets, daemon=True)
        self.sniffer_thread.start()

    def stop_capture(self):
        if not self.is_sniffing:
            return
        self.is_sniffing = False
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.status.config(text="Capture stopped.")

    def clear_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

    def sniff_packets(self):
        try:
            sniff(prn=self.process_packet, stop_filter=self.stop_filter)
        except PermissionError:
            messagebox.showerror("Permission Error", "You need to run this program as Administrator/root.")
            self.stop_capture()
        except Exception as e:
            messagebox.showerror("Error", f"Error occurred: {e}")
            self.stop_capture()

    def stop_filter(self, packet):
        return not self.is_sniffing

    def process_packet(self, packet):
        # Extract basic info from packet
        time = packet.sprintf("%TCp")
        src = packet[IP].src if IP in packet else "N/A"
        dst = packet[IP].dst if IP in packet else "N/A"
        length = len(packet)

        proto = "Other"
        info = ""

        if IP in packet:
            if TCP in packet:
                proto = "TCP"
                sport = packet[TCP].sport
                dport = packet[TCP].dport
                info = f"{sport} -> {dport}"
            elif UDP in packet:
                proto = "UDP"
                sport = packet[UDP].sport
                dport = packet[UDP].dport
                info = f"{sport} -> {dport}"
            elif ICMP in packet:
                proto = "ICMP"
                info = packet[ICMP].type
            else:
                proto = packet[IP].proto
        else:
            proto = packet.name

        # Truncate info for display
        if len(info) > 50:
            info = info[:47] + "..."

        # Insert packet info into UI table thread-safely
        self.root.after(0, lambda: self.tree.insert("", tk.END, values=(time, src, dst, proto, length, info)))


if __name__ == "__main__":
    root = tk.Tk()
    app = PacketSnifferApp(root)
    root.mainloop()
