from collections import defaultdict, deque
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
BEACON_FLOOD_THRESHOLD = 50
EVENT_WINDOW_SECONDS = 60


"""
====================================================
*   Runtime Tracking
====================================================
"""

deauth_events = defaultdict(deque)
disassoc_events = defaultdict(deque)
probe_events = defaultdict(deque)
beacon_events = defaultdict(deque)


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
def _prune_old_events(queue):
    cutoff = time.time() - EVENT_WINDOW_SECONDS
    while queue and queue[0] < cutoff:
        queue.popleft()


def detect_deauthentication_attack(packet):

    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    if dot11.type != 0 or dot11.subtype != 12:
        return

    source = dot11.addr2
    target = dot11.addr1

    scan_statistics["deauth_frames"] += 1

    queue = deauth_events[source]
    _prune_old_events(queue)
    queue.append(time.time())

    if len(queue) >= DEAUTH_THRESHOLD:
        attack = create_attack_object(
            "Deauthentication Attack",
            source=source,
            target=target,
            description="High number of deauth frames detected within a short window",
            severity="HIGH"
        )

        register_attack(attack)
        queue.clear()


"""
====================================================
*   DISASSOC detection (FIXED)
====================================================
"""
def detect_disassociation_attack(packet):

    if not packet.haslayer(Dot11):
        return

    dot11 = packet[Dot11]

    if dot11.type != 0 or dot11.subtype != 10:
        return

    source = dot11.addr2
    target = dot11.addr1

    scan_statistics["disassoc_frames"] += 1

    queue = disassoc_events[source]
    _prune_old_events(queue)
    queue.append(time.time())

    if len(queue) >= DISASSOC_THRESHOLD:
        attack = create_attack_object(
            "Disassociation Attack",
            source=source,
            target=target,
            description="High number of disassociation frames detected within a short window",
            severity="HIGH"
        )

        register_attack(attack)
        queue.clear()


"""
====================================================
*   PROBE FLOOD
====================================================
"""
def detect_probe_flood(packet):

    if not packet.haslayer(Dot11ProbeReq):
        return

    source = packet.addr2

    queue = probe_events[source]
    _prune_old_events(queue)
    queue.append(time.time())

    if len(queue) >= PROBE_FLOOD_THRESHOLD:
        attack = create_attack_object(
            "Probe Request Flood",
            source=source,
            description="Excessive probe requests detected within a short time window",
            severity="MEDIUM"
        )

        register_attack(attack)
        queue.clear()


"""
====================================================
*   BEACON FLOOD
====================================================
"""
def detect_beacon_flood(packet):

    if not packet.haslayer(Dot11Beacon):
        return

    source = packet.addr2

    queue = beacon_events[source]
    _prune_old_events(queue)
    queue.append(time.time())

    if len(queue) >= BEACON_FLOOD_THRESHOLD:
        attack = create_attack_object(
            "Beacon Flood / Fake AP Spam",
            source=source,
            description="Excessive beacon frames detected within a short time window",
            severity="HIGH"
        )

        register_attack(attack)
        queue.clear()


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

    deauth_events.clear()
    disassoc_events.clear()
    probe_events.clear()
    beacon_events.clear()

    log_info("Attack counters reset")
