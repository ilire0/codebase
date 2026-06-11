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

            match = re.search(
                r"\* (\d+) MHz",
                line
            )

            if match:

                freq = int(match.group(1))
                frequencies.append(freq)

        frequencies = sorted(set(frequencies))

        log_info(
            f"Detected {len(frequencies)} "
            f"supported frequencies"
        )

        return frequencies

    except Exception as e:

        log_error(
            f"Failed to read supported frequencies: {e}"
        )

        return []


def set_frequency(interface, frequency):
    """
    Setzt die Karte auf eine Frequenz.

    Beispiel:
        2412 MHz
        5180 MHz
        5955 MHz
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
                f"Failed switching {interface} "
                f"to {frequency} MHz: "
                f"{result.stderr.strip()}"
            )

            return False

        log_info(
            f"Switched {interface} "
            f"to {frequency} MHz"
        )

        return True

    except subprocess.TimeoutExpired:

        log_error(
            f"Timeout switching "
            f"to {frequency} MHz"
        )

        return False

    except Exception as e:

        log_error(
            f"Frequency switch error: {e}"
        )

        return False


def get_current_frequency(interface):
    """
    Liest die aktuell eingestellte Frequenz aus.
    """

    try:

        result = subprocess.run(
            [
                "iw",
                "dev",
                interface,
                "info"
            ],
            capture_output=True,
            text=True,
            timeout=2
        )

        match = re.search(
            r"channel\s+\d+\s+\((\d+)\s+MHz\)",
            result.stdout
        )

        if match:
            return int(match.group(1))

    except Exception:
        pass

    return None


def hop_frequencies(
    interface,
    frequencies,
    delay=2.0,
    verify=True
):
    """
    Hoppt durch alle Frequenzen.
    """

    for freq in frequencies:

        if freq in UNSUPPORTED_FREQS:
            continue

        success = set_frequency(
            interface,
            freq
        )

        if not success:

            UNSUPPORTED_FREQS.add(freq)
            continue

        if verify:

            current = get_current_frequency(
                interface
            )

            if current != freq:

                log_warning(
                    f"Verification failed "
                    f"for {freq} MHz "
                    f"(current={current})"
                )

                UNSUPPORTED_FREQS.add(freq)
                continue

        print(
            f"[*] Hopping to "
            f"{freq} MHz"
        )

        time.sleep(delay)


def continuous_channel_hop(
    interface,
    delay=2.0
):
    """
    Endloses Hopping über alle
    vom Adapter unterstützten Frequenzen.
    """

    frequencies = get_supported_frequencies()

    if not frequencies:

        log_error(
            "No supported frequencies found."
        )

        return

    log_info(
        f"Starting hopping over "
        f"{len(frequencies)} frequencies"
    )

    try:

        while True:

            hop_frequencies(
                interface=interface,
                frequencies=frequencies,
                delay=delay,
                verify=True
            )

    except KeyboardInterrupt:

        log_warning(
            "Channel hopping interrupted"
        )

    except Exception as e:

        log_error(
            f"Continuous hopping error: {e}"
        )


def get_band_frequencies(
    frequencies,
    band="all"
):
    """
    Filtert Frequenzen nach Band.
    """

    if band == "2.4":

        return [
            f for f in frequencies
            if 2400 <= f <= 2500
        ]

    elif band == "5":

        return [
            f for f in frequencies
            if 5000 <= f <= 5900
        ]

    elif band == "6":

        return [
            f for f in frequencies
            if 5925 <= f <= 7125
        ]

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