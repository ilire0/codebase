from scapy.layers.dot11 import Dot11, Dot11Beacon

from scanner.parsing_beaconframes import parse_beacon

from scanner.scanner_state import (
    networks,
    scan_statistics,
    detected_attacks
)

from security.vulnerability_scanner import (
    vulnerability_scanner,
    print_vulnerabilities
)

from security.attack_detection import (
    detect_attacks
)

from utils.logger import (
    log_info,
    log_warning,
    log_error
)


"""
====================================================
*   packet_handler
*
*   Central packet processing function
*
====================================================
"""
def packet_handler(packet):

    try:

        # -----------------------------------------
        # General packet statistics
        # -----------------------------------------
        scan_statistics["total_packets"] += 1

        # -----------------------------------------
        # 802.11 management frame analysis
        # -----------------------------------------
        if packet.haslayer(Dot11):

            dot11 = packet[Dot11]

            # Deauthentication (subtype 12)
            if dot11.type == 0 and dot11.subtype == 12:
                scan_statistics["deauth_frames"] += 1

            # Disassociation (subtype 10)
            elif dot11.type == 0 and dot11.subtype == 10:
                scan_statistics["disassoc_frames"] += 1

        # Global attack detection module
        detect_attacks(packet)

        # -----------------------------------------
        # Only process beacon frames for networks
        # -----------------------------------------
        if not packet.haslayer(Dot11Beacon):
            return

        scan_statistics["beacons"] += 1

        # -----------------------------------------
        # Parse network information
        # -----------------------------------------
        network = parse_beacon(packet)

        if not network:
            return

        bssid = network.get("BSSID")
        if not bssid:
            return

        # -----------------------------------------
        # Vulnerability analysis
        # -----------------------------------------
        vulnerabilities = vulnerability_scanner(network)
        network["Vulnerabilities"] = vulnerabilities

        # -----------------------------------------
        # Rogue AP detection
        # -----------------------------------------
        network["Rogue AP"] = detect_rogue_ap(network)

        # -----------------------------------------
        # Store / update network
        # -----------------------------------------
        networks[bssid] = network

        # -----------------------------------------
        # Output
        # -----------------------------------------
        print_network(network)
        print_vulnerabilities(vulnerabilities)

        # -----------------------------------------
        # Logging
        # -----------------------------------------
        ssid = network.get("SSID", "<hidden>")
        log_info(f"Detected network: {ssid} ({bssid})")

    except Exception as e:
        log_error(f"Packet handler error: {e}")
        print(f"[!] Packet handler error: {e}")


"""
====================================================
*   detect_rogue_ap
====================================================
"""
def detect_rogue_ap(current_network):

    current_ssid = current_network.get("SSID")
    current_bssid = current_network.get("BSSID")
    current_rssi = current_network.get("RSSI")

    if current_rssi is None or not current_ssid or not current_bssid:
        return False

    for bssid, network in networks.items():

        if bssid == current_bssid:
            continue

        if network.get("SSID") != current_ssid:
            continue

        old_rssi = network.get("RSSI")
        if old_rssi is None:
            continue

        # Large RSSI difference → possible Evil Twin
        if abs(old_rssi - current_rssi) > 25:

            warning = {
                "Type": "Possible Rogue AP",
                "SSID": current_ssid,
                "Known BSSID": bssid,
                "New BSSID": current_bssid
            }

            detected_attacks.append(warning)

            log_warning(str(warning))

            print("\n[!] Possible Rogue AP Detected")
            print(warning)

            return True

    return False


"""
====================================================
*   print_network
====================================================
"""
def print_network(network):

    print("\n" + "=" * 60)
    print("[+] Network Detected")
    print("=" * 60)

    print(f"SSID: {network.get('SSID')}")
    print(f"BSSID: {network.get('BSSID')}")
    print(f"Channel: {network.get('Channel')}")
    print(f"Security: {network.get('Version')}")
    print(f"RSSI: {network.get('RSSI')} dBm")
    print(f"Auth Mode: {network.get('Auth Mode')}")
    print(f"PMF Supported: {network.get('MFP Supported')}")
    print(f"Last Seen: {network.get('Last Seen')}")
    print(f"Hidden SSID: {network.get('Hidden SSID')}")
    print(f"Channel Overlap: {network.get('Channel Overlap')}")
    print(f"Rogue AP: {network.get('Rogue AP')}")

    print("=" * 60)


"""
====================================================
*   print_statistics
====================================================
"""
def print_statistics():

    print("\n" + "=" * 60)
    print("[*] Scan Statistics")
    print("=" * 60)

    print(f"Total Packets: {scan_statistics.get('total_packets', 0)}")
    print(f"Beacon Frames: {scan_statistics.get('beacons', 0)}")
    print(f"Deauth Frames: {scan_statistics.get('deauth_frames', 0)}")
    print(f"Disassociation Frames: {scan_statistics.get('disassoc_frames', 0)}")
    print(f"Discovered Networks: {len(networks)}")
    print(f"Detected Attacks: {len(detected_attacks)}")

    print("=" * 60)
