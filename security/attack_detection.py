from scapy.layers.dot11 import (
    Dot11,
    Dot11ProbeReq,
    Dot11ProbeResp,
    Dot11Beacon
)

import time

from scanner.scanner_state import (
    detected_attacks,
    scan_statistics,
    add_attack
)

from utils.logger import (
    log_info,
    log_warning,
    log_error
)


"""
====================================================
*   Attack Thresholds
====================================================
"""

DEAUTH_THRESHOLD = 10
DISASSOC_THRESHOLD = 10
PROBE_FLOOD_THRESHOLD = 30


"""
====================================================
*   Runtime Tracking
====================================================
"""

deauth_counter = {}
disassoc_counter = {}
probe_counter = {}
beacon_counter = {}


"""
====================================================
*   create_attack_object
====================================================
"""
def create_attack_object(
    attack_type,
    source=None,
    target=None,
    description=None,
    severity="MEDIUM"
):

    return {
        "Type": attack_type,
        "Source": source,
        "Target": target,
        "Description": description,
        "Severity": severity,
        "Timestamp": time.strftime("%H:%M:%S")
    }


"""
====================================================
*   register_attack
====================================================
"""
def register_attack(attack):

    add_attack(attack)
    log_warning(str(attack))

    print("\n" + "=" * 60)
    print("[!] ATTACK DETECTED")
    print("=" * 60)

    for k, v in attack.items():
        print(f"{k}: {v}")

    print("=" * 60)


"""
====================================================
*   DEAUTH detection (FIXED)
====================================================
"""
def detect_deauthentication_attack(packet):

    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    # subtype 12 = Deauth
    if dot11.type != 0 or dot11.subtype != 12:
        return

    source = dot11.addr2
    target = dot11.addr1

    scan_statistics["deauth_frames"] += 1

    deauth_counter[source] = deauth_counter.get(source, 0) + 1

    if deauth_counter[source] >= DEAUTH_THRESHOLD:

        attack = create_attack_object(
            "Deauthentication Attack",
            source=source,
            target=target,
            description="High number of deauth frames detected",
            severity="HIGH"
        )

        register_attack(attack)
        deauth_counter[source] = 0


"""
====================================================
*   DISASSOC detection (FIXED)
====================================================
"""
def detect_disassociation_attack(packet):

    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    # subtype 10 = Disassoc
    if dot11.type != 0 or dot11.subtype != 10:
        return

    source = dot11.addr2
    target = dot11.addr1

    scan_statistics["disassoc_frames"] += 1

    disassoc_counter[source] = disassoc_counter.get(source, 0) + 1

    if disassoc_counter[source] >= DISASSOC_THRESHOLD:

        attack = create_attack_object(
            "Disassociation Attack",
            source=source,
            target=target,
            description="High number of disassociation frames detected",
            severity="HIGH"
        )

        register_attack(attack)
        disassoc_counter[source] = 0


"""
====================================================
*   PROBE FLOOD
====================================================
"""
def detect_probe_flood(packet):

    if not packet.haslayer(Dot11ProbeReq):
        return

    source = packet.addr2

    probe_counter[source] = probe_counter.get(source, 0) + 1

    if probe_counter[source] >= PROBE_FLOOD_THRESHOLD:

        attack = create_attack_object(
            "Probe Request Flood",
            source=source,
            description="Excessive probe requests detected",
            severity="MEDIUM"
        )

        register_attack(attack)
        probe_counter[source] = 0


"""
====================================================
*   BEACON FLOOD
====================================================
"""
def detect_beacon_flood(packet):

    if not packet.haslayer(Dot11Beacon):
        return

    source = packet.addr2

    beacon_counter[source] = beacon_counter.get(source, 0) + 1

    if beacon_counter[source] >= 50:

        attack = create_attack_object(
            "Beacon Flood / Fake AP Spam",
            source=source,
            description="Excessive beacon frames detected",
            severity="HIGH"
        )

        register_attack(attack)
        beacon_counter[source] = 0


"""
====================================================
*   NULL PROBE SSID
====================================================
"""
def detect_null_probe_ssid(packet):

    if not packet.haslayer(Dot11ProbeReq):
        return

    try:
        ssid = packet.info.decode(errors="ignore")

        if ssid == "":

            attack = create_attack_object(
                "Null Probe Request",
                source=packet.addr2,
                description="Probe request for hidden SSIDs",
                severity="LOW"
            )

            register_attack(attack)

    except Exception:
        pass


"""
====================================================
*   ROUGE AP BEHAVIOR
====================================================
"""
def detect_rogue_ap_behavior(packet):

    if not packet.haslayer(Dot11Beacon):
        return

    try:
        ssid = packet.info.decode(errors="ignore")

        suspicious_keywords = [
            "free wifi",
            "airport free",
            "public wifi",
            "open internet",
            "guest free"
        ]

        for keyword in suspicious_keywords:
            if keyword in ssid.lower():

                attack = create_attack_object(
                    "Suspicious Rogue AP",
                    source=packet.addr2,
                    description=f"Suspicious SSID: {ssid}",
                    severity="MEDIUM"
                )

                register_attack(attack)
                break

    except Exception as e:
        log_error(f"Rogue AP detection error: {e}")


"""
====================================================
*   MAIN PIPELINE
====================================================
"""
def detect_attacks(packet):

    try:

        if packet.haslayer(Dot11):
            scan_statistics["management_frames"] += 1

        detect_deauthentication_attack(packet)
        detect_disassociation_attack(packet)
        detect_probe_flood(packet)
        detect_beacon_flood(packet)
        detect_null_probe_ssid(packet)
        detect_rogue_ap_behavior(packet)

    except Exception as e:
        log_error(f"Attack detection error: {e}")


"""
====================================================
*   RESET
====================================================
"""
def reset_attack_counters():

    deauth_counter.clear()
    disassoc_counter.clear()
    probe_counter.clear()
    beacon_counter.clear()

    log_info("Attack counters reset")
