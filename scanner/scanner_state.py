
"""
====================================================
*   scanner_state.py
*
*   Central shared runtime state
*
*   This module contains all global runtime
*   variables used across the Wi-Fi Security
*   Testbed.
*
*   Shared between:
*       - packet_handler
*       - attack_detection
*       - reporting
*       - vulnerability scanner
*       - future heatmap module
*
====================================================
"""

from collections import defaultdict


"""
====================================================
*   networks
*
*   Stores all discovered Wi-Fi networks
*
*   Structure:
*
*   {
*       "BSSID": {
*           network_data
*       }
*   }
*
====================================================
"""
networks = {}


"""
====================================================
*   detected_attacks
*
*   Stores detected attacks/events
*
*   Example:
*
*   [
*       {
*           "Type": "Deauthentication Attack",
*           "Source": "...",
*           "Target": "...",
*           "Timestamp": "..."
*       }
*   ]
*
====================================================
"""
detected_attacks = []


"""
====================================================
*   channel_stats
*
*   Stores statistics per Wi-Fi channel
*
*   Example:
*
*   {
*       1: {
*           "networks": 5,
*           "average_rssi": -55,
*           "utilization": "medium"
*       }
*   }
*
====================================================
"""
channel_stats = defaultdict(
    lambda: {
        "networks": 0,
        "rssi_values": [],
        "average_rssi": 0,
        "utilization": "low"
    }
)


"""
====================================================
*   scan_statistics
*
*   Global packet statistics
*
====================================================
"""
scan_statistics = {

    "total_packets": 0,

    "beacons": 0,

    "probe_requests": 0,

    "probe_responses": 0,

    "data_frames": 0,

    "management_frames": 0,

    "control_frames": 0,

    "deauth_frames": 0,

    "disassoc_frames": 0,

    "hidden_networks": 0,

    "wpa3_networks": 0,

    "open_networks": 0,

    "rogue_aps": 0
}


"""
====================================================
*   security_statistics
*
*   Tracks discovered security configurations
*
====================================================
"""
security_statistics = {

    "OPEN": 0,

    "WEP": 0,

    "WPA": 0,

    "WPA2": 0,

    "WPA3": 0,

    "ENTERPRISE": 0,

    "PERSONAL": 0,

    "PMF_ENABLED": 0,

    "PMF_REQUIRED": 0,

    "WPS_ENABLED": 0,

    "TKIP_NETWORKS": 0
}


"""
====================================================
*   heatmap_data
*
*   Future Wi-Fi heatmap integration
*
*   Stores signal measurements
*
====================================================
"""
heatmap_data = []


"""
====================================================
*   add_network
*
*   Adds or updates a network
*
====================================================
"""
def add_network(network):

    bssid = network.get("BSSID")

    if not bssid:
        return

    networks[bssid] = network


"""
====================================================
*   get_network
*
*   Returns network by BSSID
*
====================================================
"""
def get_network(bssid):

    return networks.get(bssid)


"""
====================================================
*   add_attack
*
*   Adds detected attack
*
====================================================
"""
def add_attack(attack):

    detected_attacks.append(
        attack
    )


"""
====================================================
*   update_channel_statistics
*
*   Updates channel utilization
*
====================================================
"""
def update_channel_statistics(network):

    channel = network.get("Channel")

    rssi = network.get("RSSI")

    if channel is None:
        return

    channel_stats[channel]["networks"] += 1

    if rssi is not None:

        channel_stats[channel][
            "rssi_values"
        ].append(rssi)

        values = channel_stats[channel][
            "rssi_values"
        ]

        if values:

            avg = sum(values) / len(values)

            channel_stats[channel][
                "average_rssi"
            ] = round(avg, 2)

    network_count = channel_stats[channel][
        "networks"
    ]

    # -----------------------------------------
    # Channel utilization estimation
    # -----------------------------------------
    if network_count <= 3:

        utilization = "low"

    elif network_count <= 8:

        utilization = "medium"

    else:

        utilization = "high"

    channel_stats[channel][
        "utilization"
    ] = utilization


"""
====================================================
*   update_security_statistics
*
*   Updates global security metrics
*
====================================================
"""
def update_security_statistics(network):

    version = network.get(
        "Version",
        ""
    )

    auth_mode = network.get(
        "Auth Mode",
        ""
    )

    if version == "Open":

        security_statistics["OPEN"] += 1

    elif version == "WEP":

        security_statistics["WEP"] += 1

    elif version == "WPA":

        security_statistics["WPA"] += 1

    elif version == "WPA2":

        security_statistics["WPA2"] += 1

    elif version == "WPA3":

        security_statistics["WPA3"] += 1

    if auth_mode == "Enterprise":

        security_statistics[
            "ENTERPRISE"
        ] += 1

    elif auth_mode == "Personal":

        security_statistics[
            "PERSONAL"
        ] += 1

    if network.get("MFP Supported"):

        security_statistics[
            "PMF_ENABLED"
        ] += 1

    if network.get("MFP Required"):

        security_statistics[
            "PMF_REQUIRED"
        ] += 1

    if network.get("WPS Enabled"):

        security_statistics[
            "WPS_ENABLED"
        ] += 1

    rsn = network.get(
        "RSN-IE",
        {}
    )

    pairwise = rsn.get(
        "Pairwise Cipher Suites",
        []
    )

    for cipher in pairwise:

        if cipher.get("Name") == "TKIP":

            security_statistics[
                "TKIP_NETWORKS"
            ] += 1


"""
====================================================
*   add_heatmap_measurement
*
*   Future heatmap support
*
====================================================
"""
def add_heatmap_measurement(
    x,
    y,
    ssid,
    bssid,
    rssi
):

    heatmap_data.append({

        "x": x,

        "y": y,

        "SSID": ssid,

        "BSSID": bssid,

        "RSSI": rssi
    })


"""
====================================================
*   reset_runtime_state
*
*   Clears all runtime state
*
====================================================
"""
def reset_runtime_state():

    networks.clear()

    detected_attacks.clear()

    heatmap_data.clear()

    for key in scan_statistics:

        scan_statistics[key] = 0

    for key in security_statistics:

        security_statistics[key] = 0

    channel_stats.clear()


"""
====================================================
*   print_runtime_statistics
*
*   Console statistics output
*
====================================================
"""
def print_runtime_statistics():

    print("\n" + "=" * 60)

    print("[*] Runtime Statistics")

    print("=" * 60)

    print(
        f"Discovered Networks: "
        f"{len(networks)}"
    )

    print(
        f"Detected Attacks: "
        f"{len(detected_attacks)}"
    )

    print(
        f"Beacon Frames: "
        f"{scan_statistics['beacons']}"
    )

    print(
        f"WPA3 Networks: "
        f"{security_statistics['WPA3']}"
    )

    print(
        f"Open Networks: "
        f"{security_statistics['OPEN']}"
    )

    print(
        f"WPS Enabled Networks: "
        f"{security_statistics['WPS_ENABLED']}"
    )

    print(
        f"PMF Enabled Networks: "
        f"{security_statistics['PMF_ENABLED']}"
    )

    print("=" * 60)

