import subprocess
import time
import re

from utils.logger import (
    log_info,
    log_warning,
    log_error
)

# Frequenzen die bereits als nicht nutzbar erkannt wurden
UNSUPPORTED_FREQS = set()


def get_supported_frequencies():
    """
    Liest alle vom Adapter unterstützten Frequenzen aus.

    Benötigt:
        iw phy
    """

    try:
        result = subprocess.run(
            ["iw", "phy"],
            capture_output=True,
            text=True,
            timeout=5
        )

        frequencies = []
        for line in result.stdout.splitlines():
            match = re.search(r"\* (\d+) MHz", line)
            if match:
                frequencies.append(int(match.group(1)))

        frequencies = sorted(set(frequencies))
        log_info(f"Detected {len(frequencies)} supported frequencies")
        return frequencies

    except Exception as e:
        log_error(f"Failed to read supported frequencies: {e}")
        return []


def set_frequency(interface, frequency):
    """
    Setzt die Karte auf eine Frequenz.
    """

    try:
        result = subprocess.run(
            [
                "iw",
                "dev",
                interface,
                "set",
                "freq",
                str(frequency)
            ],
            capture_output=True,
            text=True,
            timeout=2
        )

        if result.returncode != 0:
            log_warning(
                f"Failed switching {interface} to {frequency} MHz: "
                f"{result.stderr.strip()}"
            )
            return False

        log_info(f"Switched {interface} to {frequency} MHz")
        return True

    except subprocess.TimeoutExpired:
        log_error(f"Timeout switching to {frequency} MHz")
        return False

    except Exception as e:
        log_error(f"Frequency switch error: {e}")
        return False


def set_channel(interface, channel):
    """
    Setzt die Karte auf einen bestimmtem Kanal.
    """

    try:
        result = subprocess.run(
            [
                "iw",
                "dev",
                interface,
                "set",
                "channel",
                str(channel)
            ],
            capture_output=True,
            text=True,
            timeout=2
        )

        if result.returncode != 0:
            log_warning(
                f"Failed switching {interface} to channel {channel}: "
                f"{result.stderr.strip()}"
            )
            return False

        log_info(f"Switched {interface} to channel {channel}")
        return True

    except subprocess.TimeoutExpired:
        log_error(f"Timeout switching to channel {channel}")
        return False

    except Exception as e:
        log_error(f"Channel switch error: {e}")
        return False


def get_current_frequency(interface):
    """
    Liest die aktuell eingestellte Frequenz aus.
    """

    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            text=True,
            timeout=2
        )

        match = re.search(r"channel\s+\d+\s+\((\d+)\s+MHz\)", result.stdout)
        if match:
            return int(match.group(1))

    except Exception:
        pass

    return None


def get_current_channel(interface):
    """
    Liest den aktuell eingestellten Kanal aus.
    """

    try:
        result = subprocess.run(
            ["iw", "dev", interface, "info"],
            capture_output=True,
            text=True,
            timeout=2
        )

        match = re.search(r"channel\s+(\d+)\s+\((\d+)\s+MHz\)", result.stdout)
        if match:
            return int(match.group(1))

    except Exception:
        pass

    return None


def hop_frequencies(interface, frequencies, delay=2.0, verify=True):
    """
    Hoppt durch eine Liste von Frequenzen.
    """

    for freq in frequencies:
        if freq in UNSUPPORTED_FREQS:
            continue

        success = set_frequency(interface, freq)
        if not success:
            UNSUPPORTED_FREQS.add(freq)
            continue

        if verify:
            current = get_current_frequency(interface)
            if current != freq:
                log_warning(f"Verification failed for {freq} MHz (current={current})")
                UNSUPPORTED_FREQS.add(freq)
                continue

        log_info(f"Hopping to {freq} MHz")
        time.sleep(delay)


def hop_channels(interface, delay=2.0, band="all", verify=True):
    """
    Hoppt über alle unterstützten Frequenzen und filtert optional nach Band.
    """

    frequencies = get_supported_frequencies()
    if not frequencies:
        log_error("No supported frequencies found.")
        return

    frequencies = get_band_frequencies(frequencies, band)
    if not frequencies:
        log_error(f"No supported frequencies found for band '{band}'.")
        return

    log_info(
        f"Starting channel hop on {interface} over {len(frequencies)} frequencies (band={band})"
    )

    hop_frequencies(interface, frequencies, delay=delay, verify=verify)


def continuous_channel_hop(interface, delay=2.0, band="all"):
    """
    Endloses Hopping über alle vom Adapter unterstützten Frequenzen.
    """

    while True:
        hop_channels(interface, delay=delay, band=band, verify=True)


def get_band_frequencies(frequencies, band="all"):
    """
    Filtert Frequenzen nach Band.
    """

    if band == "2.4":
        return [f for f in frequencies if 2400 <= f <= 2500]

    if band == "5":
        return [f for f in frequencies if 5000 <= f <= 5900]

    if band == "6":
        return [f for f in frequencies if 5925 <= f <= 7125]

    return frequencies


if __name__ == "__main__":

    INTERFACE = "wlan0mon"

    print(
        f"[*] Starting frequency hopping "
        f"on {INTERFACE}"
    )

    continuous_channel_hop(
        interface=INTERFACE,
        delay=2
    )