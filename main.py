from scapy.all import sniff

import argparse
import threading
import signal
import sys
import time

from scanner.channel_hopper import hop_channels
from scanner.packet_handler import packet_handler
from scanner.scanner_state import (
    networks,
    print_runtime_statistics
)
from utils.report import (
    export_json,
    export_pdf,
    print_network_summary
)

# -------------------------------------------------
# Global runtime control
# -------------------------------------------------
running = True
run_duration = None
scan_start = None


# -------------------------------------------------
# Channel Hopper
# -------------------------------------------------
def start_channel_hopper(interface, band):
    while running:
        try:
            hop_channels(interface, band=band)
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
    if run_duration is not None and scan_start is not None:
        if time.time() - scan_start >= run_duration:
            return True
    return not running


# -------------------------------------------------
# MAIN
# -------------------------------------------------
def main(interface="wlan0mon", band="all", duration=None):
    global running, scan_start, run_duration
    running = True
    run_duration = duration
    scan_start = time.time()

    signal.signal(signal.SIGINT, signal_handler)

    hopper_thread = threading.Thread(
        target=start_channel_hopper,
        args=(interface, band),
        daemon=True
    )
    hopper_thread.start()

    print(f"[*] Starting Wi-Fi Security Testbed on {interface} (band={band})")
    if duration:
        print(f"[*] Scan will stop after {duration} seconds")
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

    print("\n[*] Generating report...")

    try:
        print_network_summary(networks)
    except Exception as e:
        print(f"[!] Summary error: {e}")

    try:
        export_json(networks)
    except Exception as e:
        print(f"[!] Export error: {e}")

    try:
        pdf_path = export_pdf(networks)
        print(f"[✓] PDF report created: {pdf_path}")
    except Exception as e:
        print(f"[!] PDF export error: {e}")

    try:
        print_runtime_statistics()
    except Exception:
        pass

    print("\n[✓] Scan stopped cleanly")


# -------------------------------------------------
# ENTRY POINT
# -------------------------------------------------
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Wi-Fi Security Testbed"
    )
    parser.add_argument(
        "-i",
        "--interface",
        default="wlan0mon",
        help="Wireless monitoring interface"
    )
    parser.add_argument(
        "-b",
        "--band",
        choices=["all", "2.4", "5", "6"],
        default="all",
        help="Frequency band to hop"
    )
    parser.add_argument(
        "-d",
        "--duration",
        type=int,
        default=None,
        help="Scan duration in seconds"
    )

    args = parser.parse_args()
    main(args.interface, band=args.band, duration=args.duration)
