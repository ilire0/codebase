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
CHANNELS_2GHZ = list(range(1, 15))


# ✅ FIX: moved up
def check_channel_overlap(channel):
    overlapping_channels = {
        1: [2, 3, 4], 6: [7, 8, 9], 11: [10, 9, 8], 14: [13, 12, 11]
    }
    return overlapping_channels.get(channel, [])


# ✅ FIX: moved up
def log_network_details(bssid, ssid, channel, version_info, auth_mode,
                        weak_encryption, open_network, rogue_ap,
                        wps_enabled, rssi, mfp_supported, channel_overlap):

    log_message = f"SSID: {ssid}, BSSID: {bssid}, Channel: {channel}, Version: {version_info}, " \
                  f"Auth Mode: {auth_mode}, Weak Encryption: {weak_encryption}, Open Network: {open_network}, " \
                  f"Rogue AP: {rogue_ap}, WPS Enabled: {wps_enabled}, RSSI: {rssi}, " \
                  f"MFP Supported: {mfp_supported}, Channel Overlap: {channel_overlap}, " \
                  f"Last Seen: {time.strftime('%H:%M:%S')}"
    logging.info(log_message)

    if weak_encryption or open_network or rogue_ap or wps_enabled:
        print(f"Security concern: {ssid} ({bssid}) - Weak or Open network detected.")


def parse_beacon(packet):
    if packet.haslayer(Dot11Beacon):
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode(errors="ignore")
        stats = packet[Dot11Beacon].network_stats()
        channel = stats.get("channel")
        crypto = stats.get("crypto")

        version_info = "Unknown"
        auth_mode = "Unknown"
        cipher_suites = []
        rssi = packet.dBm_AntSignal if packet.haslayer(Dot11) else None
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
            elif elt.ID == 221 and b"\x00P\xf2\x01\x01\x00" in elt.info:
                wps_enabled = True
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

        log_network_details(bssid, ssid, channel, version_info, auth_mode,
                            weak_encryption, open_network, rogue_ap,
                            wps_enabled, rssi, mfp_supported, channel_overlap)

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


# ✅ FIX: correct iw usage
def set_channel(interface, channel):
    try:
        subprocess.run(['iw', 'dev', interface, 'set', 'channel', str(channel)],
                       capture_output=True, timeout=2)
    except:
        pass


# ✅ FIX: safer handler
def packet_handler(packet):
    try:
        if packet.haslayer(Dot11Beacon):
            parse_beacon(packet)
    except Exception as e:
        print(f"[!] Packet error: {e}")


def scan_all_channels(interface, duration):
    time_per_channel = 5

    for channel in CHANNELS_2GHZ:
        try:
            set_channel(interface, channel)
            time.sleep(0.2)

            sniff(iface=interface, prn=packet_handler,
                  store=False, timeout=time_per_channel)

        except Exception as e:
            print(f"[!] Error on channel {channel}: {e}")


def print_network_summary():
    print("\n" + "="*80)
    print(f"{'SSID':<20} {'BSSID':<18} {'Channel':<8} {'Security':<12} {'Issues':<20}")
    print("="*80)

    for bssid, data in networks.items():
        issues = []
        if data.get("Weak Encryption"): issues.append("Weak Crypto")
        if data.get("Open Network"): issues.append("Open")
        if data.get("Rogue AP"): issues.append("Rogue AP")
        if data.get("WPS Enabled"): issues.append("WPS")
        if data.get("Hidden SSID"): issues.append("Hidden")

        issue_str = ", ".join(issues) if issues else "None"

        print(f"{data['SSID']:<20} {bssid:<18} {data['Channel']:<8} {data['Version']:<12} {issue_str:<20}")


def start_sniffer(interface="wlan0mon", scan_duration=70, interval=30):
    print(f"[*] Starting scan on {interface}")

    try:
        while True:
            scan_all_channels(interface, scan_duration)
            print_network_summary()
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Stopped.")
        print_network_summary()


if __name__ == "__main__":
    import sys
    iface = sys.argv[1] if len(sys.argv) > 1 else "wlan0mon"
    start_sniffer(interface=iface)
