from scapy.layers.dot11 import (
    Dot11,
    Dot11Beacon,
    Dot11Elt,
    Dot11EltRSN
)

from scapy.all import RadioTap

import time

from utils.helpers import (
    check_channel_overlap
)

from utils.logger import (
    log_info,
    log_warning,
    log_error
)


"""
====================================================
*   parse_cipher_suite
*
*   Parses RSN cipher suite
*
====================================================
"""
def parse_cipher_suite(cipher_bytes):

    cipher_names = {

        0x00: "Use Group Cipher",
        0x01: "WEP-40",
        0x02: "TKIP",
        0x04: "CCMP (AES)",
        0x05: "WEP-104",
        0x08: "BIP-CMAC-128",
        0x09: "BIP-GMAC-128",
        0x0A: "BIP-GMAC-256",
        0x0C: "GCMP-128",
        0x0D: "GCMP-256",
        0x0E: "CCMP-256"
    }

    if len(cipher_bytes) < 4:

        return {
            "OUI": None,
            "Type": None,
            "Name": "Unknown"
        }

    oui = cipher_bytes[0:3]

    cipher_type = cipher_bytes[3]

    return {

        "OUI": oui.hex(),

        "Type": cipher_type,

        "Name": cipher_names.get(
            cipher_type,
            f"Unknown ({cipher_type})"
        )
    }


"""
====================================================
*   parse_akm_suite
*
*   Parses authentication suite
*
====================================================
"""
def parse_akm_suite(akm_bytes):

    akm_names = {

        0x01: "802.1X (Enterprise)",
        0x02: "PSK (Personal)",
        0x03: "FT-802.1X",
        0x04: "FT-PSK",
        0x05: "802.1X with SHA256",
        0x06: "PSK with SHA256",
        0x08: "SAE (WPA3-Personal)",
        0x09: "FT-SAE",
        0x0C: "OWE (WPA3-Open)",
        0x10: "SUITE-B-192"
    }

    if len(akm_bytes) < 4:

        return {
            "OUI": None,
            "Type": None,
            "Name": "Unknown"
        }

    oui = akm_bytes[0:3]

    akm_type = akm_bytes[3]

    return {

        "OUI": oui.hex(),

        "Type": akm_type,

        "Name": akm_names.get(
            akm_type,
            f"Unknown ({akm_type})"
        )
    }


"""
====================================================
*   parse_rsn_information
*
*   Parses RSN Information Element
*
====================================================
"""
def parse_rsn_information(packet):

    rsn = {}

    if not packet.haslayer(Dot11EltRSN):
        return rsn

    try:

        rsn_info = bytes(
            packet[Dot11EltRSN].info
        )

        if len(rsn_info) < 8:
            return rsn

        # -----------------------------------------
        # Group Cipher Suite
        # -----------------------------------------
        group_cipher_suite = parse_cipher_suite(
            rsn_info[2:6]
        )

        # -----------------------------------------
        # Pairwise Cipher Suites
        # -----------------------------------------
        pairwise_count = int.from_bytes(
            rsn_info[6:8],
            "little"
        )

        pairwise_cipher_suites = []

        pos = 8

        for _ in range(pairwise_count):

            if len(rsn_info) >= pos + 4:

                cipher = rsn_info[pos:pos+4]

                pairwise_cipher_suites.append(
                    parse_cipher_suite(cipher)
                )

                pos += 4

        # -----------------------------------------
        # AKM Suites
        # -----------------------------------------
        akm_suites = []

        if len(rsn_info) >= pos + 2:

            akm_count = int.from_bytes(
                rsn_info[pos:pos+2],
                "little"
            )

            pos += 2

            for _ in range(akm_count):

                if len(rsn_info) >= pos + 4:

                    akm = rsn_info[pos:pos+4]

                    akm_suites.append(
                        parse_akm_suite(akm)
                    )

                    pos += 4

        # -----------------------------------------
        # RSN Capabilities
        # -----------------------------------------
        capabilities = 0

        if len(rsn_info) >= pos + 2:

            capabilities = int.from_bytes(
                rsn_info[pos:pos+2],
                "little"
            )

        mfp_capable = (
            capabilities & 0x1000
        ) != 0

        mfp_required = (
            capabilities & 0x2000
        ) != 0

        rsn = {

            "Group Cipher Suite":
                group_cipher_suite,

            "Pairwise Cipher Suites":
                pairwise_cipher_suites,

            "Akm Suites":
                akm_suites,

            "MFP Capable":
                mfp_capable,

            "MFP Required":
                mfp_required
        }

    except Exception as e:

        log_error(
            f"RSN parsing error: {e}"
        )

    return rsn


"""
====================================================
*   determine_security_version
*
*   Determines Wi-Fi security version
*
====================================================
"""
def determine_security_version(
    crypto,
    rsn
):

    version = "Open"

    akm_suites = rsn.get(
        "Akm Suites",
        []
    )

    # WPA3
    if any(
        akm.get("Type") == 0x08
        for akm in akm_suites
    ):

        version = "WPA3"

    # WPA2
    elif any(
        akm.get("Type") == 0x02
        for akm in akm_suites
    ):

        version = "WPA2"

    # WEP
    elif crypto and "WEP" in str(crypto):

        version = "WEP"

    # WPA Legacy
    elif crypto and "WPA" in str(crypto):

        version = "WPA"

    return version


"""
====================================================
*   determine_auth_mode
*
*   Enterprise vs Personal
*
====================================================
"""
def determine_auth_mode(rsn):

    akm_suites = rsn.get(
        "Akm Suites",
        []
    )

    for akm in akm_suites:

        akm_type = akm.get("Type")

        if akm_type in [0x01, 0x03, 0x05]:

            return "Enterprise"

        elif akm_type in [0x02, 0x04, 0x06, 0x08]:

            return "Personal"

    return "Unknown"


"""
====================================================
*   detect_wps
*
*   Detects WPS support
*
====================================================
"""
def detect_wps(packet):

    elt = packet.getlayer(Dot11Elt)

    while isinstance(elt, Dot11Elt):

        try:

            if elt.ID == 221:

                # WPS Vendor OUI
                if elt.info.startswith(
                    b"\x00\x50\xf2\x04"
                ):

                    return True

        except Exception:
            pass

        elt = elt.payload.getlayer(
            Dot11Elt
        )

    return False


"""
====================================================
*   parse_beacon
*
*   Main beacon parser
*
====================================================
"""
def parse_beacon(packet):

    try:

        if not packet.haslayer(
            Dot11Beacon
        ):

            return None

        # -----------------------------------------
        # Basic Information
        # -----------------------------------------
        bssid = packet[Dot11].addr2

        ssid = packet[Dot11Elt].info.decode(
            errors="ignore"
        )

        stats = packet[
            Dot11Beacon
        ].network_stats()

        channel = stats.get(
            "channel"
        )

        crypto = stats.get(
            "crypto"
        )

        rssi = None

        if packet.haslayer(RadioTap):

            try:
                rssi = packet.dBm_AntSignal
            except Exception:
                pass

        # -----------------------------------------
        # Hidden SSID
        # -----------------------------------------
        hidden_ssid = False

        if ssid == "":

            hidden_ssid = True

            ssid = (
                f"Hidden_"
                f"{bssid[:8].replace(':', '')}"
            )

        # -----------------------------------------
        # RSN Information
        # -----------------------------------------
        rsn = parse_rsn_information(
            packet
        )

        # -----------------------------------------
        # Security Version
        # -----------------------------------------
        version = determine_security_version(
            crypto,
            rsn
        )

        # -----------------------------------------
        # Authentication Mode
        # -----------------------------------------
        auth_mode = determine_auth_mode(
            rsn
        )

        # -----------------------------------------
        # WPS Detection
        # -----------------------------------------
        wps_enabled = detect_wps(
            packet
        )

        # -----------------------------------------
        # Channel Overlap
        # -----------------------------------------
        channel_overlap = (
            check_channel_overlap(
                channel
            )
        )

        # -----------------------------------------
        # PMF
        # -----------------------------------------
        mfp_supported = rsn.get(
            "MFP Capable",
            False
        )

        mfp_required = rsn.get(
            "MFP Required",
            False
        )

        # -----------------------------------------
        # Final Network Object
        # -----------------------------------------
        network = {

            "SSID": ssid,

            "BSSID": bssid,

            "Channel": channel,

            "Crypto": (
                ",".join(crypto)
                if crypto else "Open"
            ),

            "Version": version,

            "Auth Mode": auth_mode,

            "RSN-IE": rsn,

            "RSSI": rssi,

            "WPS Enabled":
                wps_enabled,

            "MFP Supported":
                mfp_supported,

            "MFP Required":
                mfp_required,

            "Channel Overlap":
                channel_overlap,

            "Hidden SSID":
                hidden_ssid,

            "Last Seen":
                time.strftime(
                    "%H:%M:%S"
                )
        }

        # -----------------------------------------
        # Logging
        # -----------------------------------------
        log_info(
            f"Parsed network "
            f"{ssid} ({bssid}) "
            f"Security={version} "
            f"Channel={channel}"
        )

        return network

    except Exception as e:

        log_error(
            f"Beacon parsing error: {e}"
        )

        return None