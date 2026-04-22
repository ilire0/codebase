from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt
import time
import logging

# A global dictionary to hold detected networks
networks = {}

# Initialize logging
logging.basicConfig(filename="wifi_scan_log.txt", level=logging.INFO)

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
            elt = elt.payload.getlayer(Dot11Elt)

        # Identify if WPA is Personal or Enterprise (via Authentication Type)
        if "WPA" in version_info or "WPA2" in version_info or "WPA3" in version_info:
            if "WPA2" in version_info or "WPA3" in version_info:
                auth_mode = "Personal" if "WPA" in crypto else "Enterprise"

        # Detect Open Networks (unprotected)
        open_network = "Open" in crypto

        # Detect Hidden SSID
        if ssid == "":
            ssid = "Hidden"

        # Detect Weak Encryption (WEP, TKIP)
        weak_encryption = "WEP" in version_info or "TKIP" in cipher_suites

        # Detect Rogue APs (multiple BSSIDs with same SSID)
        rogue_ap = False
        if ssid in networks and bssid != networks[ssid]["BSSID"]:
            rogue_ap = True

        # Detect WPS (Wi-Fi Protected Setup) enabled networks
        wps_enabled = False
        if elt.ID == 221 and b"\x00P\xf2\x01\x01\x00" in elt.info:  # Check for WPS support
            wps_enabled = True

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
            "Channel Overlap": channel_overlap
        }

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