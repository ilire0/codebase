from scapy.all import sniff, RadioTap
from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import time
import logging
import subprocess

# A global dictionary to hold detected networks
networks = {}

# Initialize logging
logging.basicConfig(filename="wifi_scan_log.txt", level=logging.INFO)

# Common 2.4 GHz channels to scan
CHANNELS_2GHZ = list(range(1, 15))  # Channels 1-14
CHANNEL_DWELL = 2  # Seconds to stay on each channel

def parse_beacon(packet):
    """
    Parse 802.11 Beacon Frames to extract network information and flag security issues.
    """
    if packet.haslayer(Dot11Beacon):
        # Extract essential information
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")

        # Default values
        version_info = "Unknown"
        auth_mode = "Unknown"  # Personal or Enterprise
        cipher_suites = []
        rssi = packet.dBm_AntSignal if packet.haslayer(Dot11) else None  # Signal strength (RSSI)
        mfp_supported = False  # Management Frame Protection (MFP)
        wps_enabled = False  # WPS flag

        # Iterate over elements to gather additional info
        elt = packet.getlayer(Dot11Elt)
        while isinstance(elt, Dot11Elt):
            if elt.ID == 48:  # RSN (WPA2/WPA3)
                version_info = "WPA2/WPA3"
                if b"\x30\x14" in elt.info:  # Check for WPA3 cipher suites
                    version_info = "WPA3"
                cipher_suites = elt.info.hex()  # Extract cipher suites for analysis
            elif elt.ID == 221 and b"\x00P\xf2\x01\x01\x00" in elt.info:  # WPA (Pre-WPA2)
                version_info = "WPA"
            elif elt.ID == 5:  # WEP detection
                version_info = "WEP"
            elif elt.ID == 37:  # Management Frame Protection (MFP)
                mfp_supported = True  # Flag MFP if present
            elif elt.ID == 221 and b"\x00P\xf2\x01\x01\x00" in elt.info:  # WPS detection
                wps_enabled = True
            elt = elt.payload.getlayer(Dot11Elt)

        # Identify if WPA is Personal or Enterprise
        if "WPA" in version_info or "WPA2" in version_info or "WPA3" in version_info:
            # Enterprise WPA typically shows as WPA2-EAP or similar in crypto set
            auth_mode = "Enterprise" if any("EAP" in c or "8021X" in c for c in crypto) else "Personal"

        # Detect Open Networks (unprotected)
        open_network = "Open" in crypto

        # Detect Hidden SSID - keep original SSID but flag as hidden
        is_hidden = ssid == ""
        if is_hidden:
            ssid = f"Hidden_{bssid[:8].replace(':', '')}"  # Unique key per BSSID

        # Detect Weak Encryption (WEP, TKIP)
        weak_encryption = "WEP" in version_info or "TKIP" in cipher_suites

        # Detect Rogue APs (multiple BSSIDs with same SSID)
        rogue_ap = False
        for known_bssid, data in networks.items():
            if data.get("SSID") == ssid and known_bssid != bssid:
                rogue_ap = True
                break

        # Detect Channel Overlap (useful for detecting interference)
        channel_overlap = check_channel_overlap(channel)

        # Log network details (for future auditing)
        log_network_details(bssid, ssid, channel, version_info, auth_mode, weak_encryption, open_network, rogue_ap, wps_enabled, rssi, mfp_supported, channel_overlap)

        # Collect network information
        networks[bssid] = {
            "SSID": ssid,
            "BSSID": bssid,
            "Channel": channel,
            "Crypto": ",".join(crypto) if crypto else "Open",
            "Version": version_info,
            "Auth Mode": auth_mode,
            "Ciphers": cipher_suites,
            "RSSI": rssi,
            "Last Seen": time.strftime("%H:%M:%S"),
            "Weak Encryption": weak_encryption,
            "Open Network": open_network,
            "Rogue AP": rogue_ap,
            "WPS Enabled": wps_enabled,
            "MFP Supported": mfp_supported,
            "Channel Overlap": channel_overlap,
            "Hidden SSID": is_hidden
        }

def set_channel(interface, channel):
    """Set the Wi-Fi interface to a specific channel."""
    try:
        subprocess.run(['iw', interface, 'set', f'channel {channel}'],
                      capture_output=True, timeout=2)
    except Exception:
        pass  # May fail on some drivers

def start_sniffer(interface="wlan0mon", scan_duration=70, interval=30):
    """
    Start continuous Wi-Fi scanning with channel hopping.
    Scans all 2.4 GHz channels for thorough coverage.
    """
    print(f"[*] Starting continuous Wi-Fi scan on {interface}")
    print(f"[*] Channel hopping: {CHANNELS_2GHZ}")
    print(f"[*] 5 seconds per channel = {len(CHANNELS_2GHZ) * 5}s per cycle")
    print(f"[*] Scanning every {interval} seconds (press Ctrl+C to stop)...")
    
    try:
        while True:
            print(f"\n[*] Starting scan cycle ({scan_duration}s capture)...")
            scan_all_channels(interface, scan_duration)
            print(f"[*] Cycle complete. Networks found: {len(networks)}")
            print_network_summary()
            print(f"[*] Next scan in {interval} seconds...")
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Scan stopped by user.")
        print_network_summary()

def scan_all_channels(interface, duration):
    """
    Scan all Wi-Fi channels by hopping through each one.
    5 seconds per channel for thorough coverage.
    """
    time_per_channel = 5  # 5 seconds per channel
    
    for channel in CHANNELS_2GHZ:
        try:
            set_channel(interface, channel)
            time.sleep(0.2)  # Brief settle time
            # Sniff on this channel
            sniff(iface=interface, prn=parse_beacon, store=False, 
                  timeout=time_per_channel, filter="type mgt subtype beacon")
        except Exception as e:
            print(f"[!] Error on channel {channel}: {e}")

def print_network_summary():
    """Print a summary of all detected networks."""
    print("\n" + "="*80)
    print(f"{'SSID':<20} {'BSSID':<18} {'Channel':<8} {'Security':<12} {'Issues':<20}")
    print("="*80)
    for bssid, data in networks.items():
        issues = []
        if data.get("Weak Encryption"):
            issues.append("Weak Crypto")
        if data.get("Open Network"):
            issues.append("Open")
        if data.get("Rogue AP"):
            issues.append("Rogue AP")
        if data.get("WPS Enabled"):
            issues.append("WPS")
        if data.get("Hidden SSID"):
            issues.append("Hidden")
        issue_str = ", ".join(issues) if issues else "None"
        print(f"{data['SSID']:<20} {bssid:<18} {data['Channel']:<8} {data['Version']:<12} {issue_str:<20}")

if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0mon"
    start_sniffer(interface=iface)

def check_channel_overlap(channel):
    """
    Check if the given channel overlaps with other commonly used channels.
    Overlap analysis is useful for detecting interference.
    """
    # Channels overlap for common 2.4 GHz Wi-Fi ranges. This is a simple example.
    overlapping_channels = {
        1: [2, 3, 4], 6: [7, 8, 9], 11: [10, 9, 8], 14: [13, 12, 11]
    }
    return overlapping_channels.get(channel, [])

def log_network_details(bssid, ssid, channel, version_info, auth_mode, weak_encryption, open_network, rogue_ap, wps_enabled, rssi, mfp_supported, channel_overlap):
    """
    Log network details to a file for later review.
    """
    log_message = f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}, Version: {version_info}, " \
                  f"Auth Mode: {auth_mode}, Weak Encryption: {weak_encryption}, Open Network: {open_network}, " \
                  f"Rogue AP: {rogue_ap}, WPS Enabled: {wps_enabled}, RSSI: {rssi}, " \
                  f"MFP Supported: {mfp_supported}, Channel Overlap: {channel_overlap}, " \
                  f"Last Seen: {time.strftime('%H:%M:%S')}"
    logging.info(log_message)

    # Optionally print a message when a security concern is found
    if weak_encryption or open_network or rogue_ap or wps_enabled:
        print(f"Security concern: {ssid} ({bssid}) - Weak or Open network detected.")