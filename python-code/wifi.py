from scapy.all import sniff
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import time
import logging
import subprocess
import json

# OPTIONAL: Vendor lookup
try:
    from mac_vendor_lookup import MacLookup
    mac_lookup = MacLookup()
    mac_lookup.update_vendors()
    VENDOR_ENABLED = True
except:
    VENDOR_ENABLED = False

networks = {}
LAST_SEEN_TIMEOUT = 60  # seconds
RSSI_THRESHOLD = -80

logging.basicConfig(filename="wifi_scan_log.txt", level=logging.INFO)

# Channels
CHANNELS_2GHZ = list(range(1, 15))
CHANNELS_5GHZ = [36, 40, 44, 48, 52, 56, 60, 64]
CHANNELS_6GHZ = [1, 5, 9, 13, 17, 21, 25, 29, 33]

# Combined channels: 2.4 GHz, 5 GHz and 6 GHz
CHANNELS = CHANNELS_2GHZ + CHANNELS_5GHZ + CHANNELS_6GHZ


# ---------------- HELPERS ---------------- #

def check_channel_overlap(channel):
    overlapping_channels = {
        1: [2, 3, 4], 6: [7, 8, 9], 11: [10, 9, 8], 14: [13, 12, 11]
    }
    return overlapping_channels.get(channel, [])


def log_network_details(*args):
    logging.info(", ".join(map(str, args)))


def get_vendor(mac):
    if not VENDOR_ENABLED:
        return "Unknown"
    try:
        return mac_lookup.lookup(mac)
    except:
        return "Unknown"


# ---------------- CORE ---------------- #

def parse_beacon(packet):
    if not packet.haslayer(Dot11Beacon):
        return

    bssid = packet[Dot11].addr2
    ssid = packet[Dot11Elt].info.decode(errors="ignore")
    stats = packet[Dot11Beacon].network_stats()

    channel = stats.get("channel")
    crypto = stats.get("crypto") or []

    rssi = getattr(packet, "dBm_AntSignal", None)

    # RSSI Filter
    if rssi is not None and rssi < RSSI_THRESHOLD:
        return

    version_info = "Unknown"
    auth_mode = "Unknown"
    cipher_suites = []
    mfp_supported = False
    wps_enabled = False

    elt = packet.getlayer(Dot11Elt)
    while isinstance(elt, Dot11Elt):
        if elt.ID == 48:
            version_info = "WPA2/WPA3"
            if b"\x30\x14" in elt.info:
                version_info = "WPA3"
            cipher_suites = elt.info.hex()
        elif elt.ID == 221 and b"\x00P\xf2\x01\x01\x00" in elt.info:
            version_info = "WPA"
        elif elt.ID == 5:
            version_info = "WEP"
        elif elt.ID == 37:
            mfp_supported = True
        elt = elt.payload.getlayer(Dot11Elt)

    if "WPA" in version_info:
        auth_mode = "Enterprise" if any("EAP" in c or "8021X" in c for c in crypto) else "Personal"

    open_network = "Open" in crypto
    is_hidden = ssid == ""

    if is_hidden:
        ssid = f"Hidden_{bssid[:8].replace(':', '')}"

    weak_encryption = "WEP" in version_info or "TKIP" in cipher_suites

    rogue_ap = any(data.get("SSID") == ssid and b != bssid for b, data in networks.items())

    channel_overlap = check_channel_overlap(channel)

    vendor = get_vendor(bssid)

    # NEW NETWORK DETECTION
    if bssid not in networks:
        print(f"[NEW] {ssid} ({bssid}) | Vendor: {vendor} | Ch: {channel}")

    networks[bssid] = {
        "SSID": ssid,
        "BSSID": bssid,
        "Vendor": vendor,
        "Channel": channel,
        "Crypto": ",".join(crypto) if crypto else "Open",
        "Version": version_info,
        "Auth Mode": auth_mode,
        "RSSI": rssi,
        "Last Seen TS": time.time(),
        "Weak Encryption": weak_encryption,
        "Open Network": open_network,
        "Rogue AP": rogue_ap,
        "WPS Enabled": wps_enabled,
        "MFP Supported": mfp_supported,
        "Channel Overlap": channel_overlap,
        "Hidden SSID": is_hidden
    }

    log_network_details(bssid, ssid, channel, version_info)


def packet_handler(packet):
    try:
        parse_beacon(packet)
    except Exception as e:
        print(f"[!] Packet error: {e}")


def set_channel(interface, channel):
    try:
        subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(channel)],
                       capture_output=True, timeout=2)
    except:
        pass


def clean_old_networks():
    now = time.time()
    to_delete = [b for b, d in networks.items() if now - d["Last Seen TS"] > LAST_SEEN_TIMEOUT]
    for b in to_delete:
        del networks[b]


def scan_all_channels(interface):
    for channel in CHANNELS:
        set_channel(interface, channel)

        # give the adapter a bit more time to settle on channel
        time.sleep(0.6)

        # sniff longer per-channel for better coverage
        sniff(iface=interface, prn=packet_handler,
              store=False, timeout=3)


def print_network_summary():
    clean_old_networks()

    print("\n" + "="*100)
    print(f"{'SSID':<20} {'BSSID':<18} {'RSSI':<6} {'Ch':<4} {'Vendor':<15} {'Security':<10}")
    print("="*100)

    sorted_networks = sorted(networks.values(),
                             key=lambda x: x["RSSI"] if x["RSSI"] else -100,
                             reverse=True)

    for data in sorted_networks:
        print(f"{data['SSID']:<20} {data['BSSID']:<18} {str(data['RSSI']):<6} "
              f"{data['Channel']:<4} {data['Vendor']:<15} {data['Version']:<10}")

    # JSON Export
    with open("networks.json", "w") as f:
        json.dump(networks, f, indent=2)


def start_sniffer(interface="wlan0mon", interval=10):
    print(f"[*] Scanning on {interface} (2.4 + 5 + 6 GHz)")

    try:
        while True:
            scan_all_channels(interface)
            print_network_summary()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
        print_network_summary()


# ---------------- MAIN ---------------- #

if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0mon"
    start_sniffer(interface=iface)