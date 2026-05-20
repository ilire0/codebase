from scapy.all import sniff

import threading
import signal
import sys
import time

from scanner.channel_hopper import hop_channels
from scanner.packet_handler import packet_handler
from scanner.scanner_state import networks
from utils.report import (
    export_json,
    print_network_summary
)

# -------------------------------------------------
# Global runtime control
# -------------------------------------------------
running = True


# -------------------------------------------------
# Channel Hopper
# -------------------------------------------------
def start_channel_hopper(interface):
    while running:
        try:
            hop_channels(interface)
        except Exception:
            pass


# -------------------------------------------------
# Signal handler (CTRL + C safe shutdown)
# -------------------------------------------------
def signal_handler(sig, frame):
    global running
    print("\n[!] Stopping scan ...")
    running = False


# -------------------------------------------------
# Stop condition for sniff
# -------------------------------------------------
def stop_filter(packet):
    return not running


# -------------------------------------------------
# MAIN
# -------------------------------------------------
def main(interface="wlan0mon"):

    global running
    running = True

    # handle CTRL+C properly
    signal.signal(signal.SIGINT, signal_handler)

    # start hopper thread
    hopper_thread = threading.Thread(
        target=start_channel_hopper,
        args=(interface,),
        daemon=True
    )
    hopper_thread.start()

    print(f"[*] Starting Wi-Fi Security Testbed on {interface}")
    print("[*] Press CTRL+C to stop\n")

    try:
        sniff(
            iface=interface,
            prn=packet_handler,
            store=False,
            stop_filter=stop_filter
        )

    except Exception as e:
        print(f"[!] Sniff error: {e}")

    # -------------------------------------------------
    # CLEAN SHUTDOWN (BONUS)
    # -------------------------------------------------
    print("\n[*] Generating report...")

    try:
        print_network_summary(networks)
    except Exception as e:
        print(f"[!] Summary error: {e}")

    try:
        export_json(networks)
    except Exception as e:
        print(f"[!] Export error: {e}")

    print("\n[✓] Scan stopped cleanly")


# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------
if __name__ == "__main__":

    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0mon"
    main(iface)
