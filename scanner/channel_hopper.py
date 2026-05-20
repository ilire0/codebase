import subprocess
import time

from utils.logger import (
    log_info,
    log_warning,
    log_error
)

"""
====================================================
*   Supported Channels
*
*   2.4 GHz channels:
*   1 - 14
*
*   Optional:
*   Add 5 GHz / 6 GHz later
====================================================
"""

CHANNELS_24GHZ = list(range(1, 15))

# Optional future expansion
CHANNELS_5GHZ = [
    36, 40, 44, 48,
    52, 56, 60, 64,
    100, 104, 108, 112,
    116, 120, 124, 128,
    132, 136, 140, 144,
    149, 153, 157, 161, 165
]

CHANNELS_6GHZ = [
    1, 5, 9, 13, 17,
    21, 25, 29, 33
]

# Combined list for full-band scanning
CHANNELS_ALL = CHANNELS_24GHZ + CHANNELS_5GHZ + CHANNELS_6GHZ


"""
====================================================
*   set_channel
*
*   Switches the wireless interface
*   into a specific Wi-Fi channel
*
*   Uses:
*       iw dev <iface> set channel <channel>
*
====================================================
"""
def set_channel(interface, channel):

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
                f"Failed to switch "
                f"{interface} to channel {channel}: "
                f"{result.stderr.strip()}"
            )

            return False

        log_info(
            f"Switched {interface} "
            f"to channel {channel}"
        )

        return True

    except subprocess.TimeoutExpired:

        log_error(
            f"Timeout while switching "
            f"{interface} to channel {channel}"
        )

        return False

    except Exception as e:

        log_error(
            f"Unexpected error during "
            f"channel switch: {e}"
        )

        return False


"""
====================================================
*   hop_channels
*
*   Iterates through all channels
*   and switches the interface
*
*   Parameters:
*       interface
*       channels
*       delay
*
====================================================
"""
def hop_channels(
    interface,
    channels=CHANNELS_ALL,
    delay=2.0
):

    for channel in channels:

        success = set_channel(
            interface,
            channel
        )

        if success:

            print(
                f"[*] Hopping to channel "
                f"{channel}"
            )

        time.sleep(delay)


"""
====================================================
*   continuous_channel_hop
*
*   Infinite channel hopping loop
*
*   Runs in a dedicated thread
*
====================================================
"""
def continuous_channel_hop(
    interface,
    channels=CHANNELS_ALL,
    delay=2.0
):

    log_info(
        f"Started channel hopping "
        f"on interface {interface}"
    )

    try:

        while True:

            hop_channels(
                interface,
                channels,
                delay
            )

    except KeyboardInterrupt:

        log_warning(
            "Channel hopping interrupted"
        )

    except Exception as e:

        log_error(
            f"Continuous hopping error: {e}"
        )


"""
====================================================
*   get_supported_channels
*
*   Returns supported channel list
*   based on selected band
*
====================================================
"""
def get_supported_channels(band="2.4"):

    if band == "2.4":
        return CHANNELS_24GHZ

    elif band == "5":
        return CHANNELS_5GHZ

    elif band == "6":
        return CHANNELS_6GHZ

    else:
        return CHANNELS_24GHZ


"""
====================================================
*   Example standalone execution
====================================================
"""
if __name__ == "__main__":

    INTERFACE = "wlan0mon"

    print(
        f"[*] Starting channel hopping "
        f"on {INTERFACE}"
    )

    continuous_channel_hop(
        interface=INTERFACE,
        channels=CHANNELS_24GHZ,
        delay=1
    )