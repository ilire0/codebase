from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11ProbeReq,
    Dot11ProbeResp
)

from scanner.parsing_beaconframes import parse_beacon

from scanner.scanner_state import (
    networks,
    scan_statistics,
    detected_attacks,
    update_channel_statistics,
    update_security_statistics
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
    log_error,
    log_network_event
)


"""
====================================================
*   packet_handler
*
*   Central packet processing function
*
====================================================
"""

def update_frame_statistics(packet):
    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]
    if dot11.type == 0:
        scan_statistics["management_frames"] += 1
    elif dot11.type == 1:
        scan_statistics["control_frames"] += 1
    elif dot11.type == 2:
        scan_statistics["data_frames"] += 1

    if packet.haslayer(Dot11ProbeReq):
        scan_statistics["probe_requests"] += 1

    if packet.haslayer(Dot11ProbeResp):
        scan_statistics["probe_responses"] += 1

    if packet.haslayer(Dot11Beacon):
        scan_statistics["beacons"] += 1


def network_has_changed(old_network, new_network):
    if old_network is None:
        return True

    keys_to_compare = [
        "SSID",
        "Channel",
        "Version",
        "Auth Mode",
        "RSSI",
        "WPS Enabled",
        "MFP Supported",
        "MFP Required",
        "Hidden SSID",
        "Rogue AP",
        "Crypto"
    ]

    for key in keys_to_compare:
        if old_network.get(key) != new_network.get(key):
            return True

    if old_network.get("Detected Vulnerabilities") != new_network.get("Detected Vulnerabilities"):
        return True

    return False


def packet_handler(packet):
    try:
        scan_statistics["total_packets"] += 1
        update_frame_statistics(packet)

        detect_attacks(packet)

        if not packet.haslayer(Dot11Beacon):
            return

        network = parse_beacon(packet)
        if not network:
            return

        bssid = network.get("BSSID")
        if not bssid:
            return

        vulnerabilities = vulnerability_scanner(network)
        network["Vulnerabilities"] = vulnerabilities

        network["Rogue AP"] = detect_rogue_ap(network)

        existing = networks.get(bssid)
        changed = network_has_changed(existing, network)

        networks[bssid] = network

        if existing is None:
            update_channel_statistics(network)
            update_security_statistics(network)
            if network.get("Hidden SSID"):
                scan_statistics["hidden_networks"] += 1
            if network.get("Version") == "Open":
                scan_statistics["open_networks"] += 1
            if network.get("Version") == "WPA3":
                scan_statistics["wpa3_networks"] += 1

        if network.get("Rogue AP") and (existing is None or not existing.get("Rogue AP")):
            scan_statistics["rogue_aps"] += 1

        if changed:
            print_network(network)
            print_vulnerabilities(vulnerabilities)
            log_network_event(network)

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
    print(f"PMF Required: {network.get('MFP Required')}")
    print(f"Hidden SSID: {network.get('Hidden SSID')}")
    print(f"Channel Overlap: {network.get('Channel Overlap')}")
    print(f"Rogue AP: {network.get('Rogue AP')}")
    print(f"Detected Vulnerabilities: {network.get('Detected Vulnerabilities')}")

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
    print(f"Probe Requests: {scan_statistics.get('probe_requests', 0)}")
    print(f"Probe Responses: {scan_statistics.get('probe_responses', 0)}")
    print(f"Management Frames: {scan_statistics.get('management_frames', 0)}")
    print(f"Control Frames: {scan_statistics.get('control_frames', 0)}")
    print(f"Data Frames: {scan_statistics.get('data_frames', 0)}")
    print(f"Hidden Networks: {scan_statistics.get('hidden_networks', 0)}")
    print(f"Open Networks: {scan_statistics.get('open_networks', 0)}")
    print(f"WPA3 Networks: {scan_statistics.get('wpa3_networks', 0)}")
    print(f"Rogue APs: {scan_statistics.get('rogue_aps', 0)}")
    print(f"Discovered Networks: {len(networks)}")
    print(f"Detected Attacks: {len(detected_attacks)}")

    print("=" * 60)
