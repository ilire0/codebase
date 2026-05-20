import logging
import os
import sys
from datetime import datetime


"""
====================================================
*   Logger Configuration
*
====================================================
"""

LOG_DIRECTORY = "output/logs"

LOG_FILE_NAME = (
    f"wifi_scan_"
    f"{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
)

LOG_FILE_PATH = os.path.join(
    LOG_DIRECTORY,
    LOG_FILE_NAME
)

# Create output directory
os.makedirs(
    LOG_DIRECTORY,
    exist_ok=True
)


"""
====================================================
*   Logger Setup
*
====================================================
"""

logger = logging.getLogger(
    "WiFiSecurityTestbed"
)

logger.setLevel(logging.DEBUG)

logger.propagate = False


"""
====================================================
*   Prevent duplicate handlers
*
====================================================
"""
if not logger.handlers:

    # -----------------------------------------
    # File Handler
    # -----------------------------------------
    file_handler = logging.FileHandler(
        LOG_FILE_PATH
    )

    file_handler.setLevel(
        logging.DEBUG
    )

    # -----------------------------------------
    # Console Handler
    # -----------------------------------------
    console_handler = logging.StreamHandler(
        sys.stdout
    )

    console_handler.setLevel(
        logging.INFO
    )

    # -----------------------------------------
    # Formatter
    # -----------------------------------------
    formatter = logging.Formatter(

        "[%(asctime)s] "
        "[%(levelname)s] "
        "%(message)s",

        datefmt="%Y-%m-%d %H:%M:%S"
    )

    file_handler.setFormatter(
        formatter
    )

    console_handler.setFormatter(
        formatter
    )

    # -----------------------------------------
    # Add handlers
    # -----------------------------------------
    logger.addHandler(
        file_handler
    )

    logger.addHandler(
        console_handler
    )


"""
====================================================
*   log_debug
*
====================================================
"""
def log_debug(message):

    logger.debug(message)


"""
====================================================
*   log_info
*
====================================================
"""
def log_info(message):

    logger.info(message)


"""
====================================================
*   log_warning
*
====================================================
"""
def log_warning(message):

    logger.warning(message)


"""
====================================================
*   log_error
*
====================================================
"""
def log_error(message):

    logger.error(message)


"""
====================================================
*   log_critical
*
====================================================
"""
def log_critical(message):

    logger.critical(message)


"""
====================================================
*   log_network_event
*
*   Specialized network logging
*
====================================================
"""
def log_network_event(network):

    try:

        ssid = network.get(
            "SSID",
            "Unknown"
        )

        bssid = network.get(
            "BSSID",
            "Unknown"
        )

        channel = network.get(
            "Channel",
            "?"
        )

        version = network.get(
            "Version",
            "Unknown"
        )

        rssi = network.get(
            "RSSI",
            "?"
        )

        logger.info(

            "[NETWORK] "

            f"SSID={ssid} "

            f"BSSID={bssid} "

            f"CH={channel} "

            f"SEC={version} "

            f"RSSI={rssi}"
        )

    except Exception as e:

        logger.error(
            f"Network event logging failed: {e}"
        )


"""
====================================================
*   log_attack_event
*
*   Specialized attack logging
*
====================================================
"""
def log_attack_event(attack):

    try:

        logger.warning(

            "[ATTACK] "

            f"TYPE={attack.get('Type')} "

            f"SOURCE={attack.get('Source')} "

            f"TARGET={attack.get('Target')} "

            f"SEVERITY={attack.get('Severity')}"
        )

    except Exception as e:

        logger.error(
            f"Attack event logging failed: {e}"
        )


"""
====================================================
*   log_vulnerability_event
*
*   Specialized vulnerability logging
*
====================================================
"""
def log_vulnerability_event(
    ssid,
    vulnerability
):

    try:

        logger.warning(

            "[VULNERABILITY] "

            f"SSID={ssid} "

            f"NAME={vulnerability.get('Name')} "

            f"SEVERITY={vulnerability.get('Severity')}"
        )

    except Exception as e:

        logger.error(
            f"Vulnerability logging failed: {e}"
        )


"""
====================================================
*   get_log_file_path
*
====================================================
"""
def get_log_file_path():

    return LOG_FILE_PATH


"""
====================================================
*   print_log_location
*
====================================================
"""
def print_log_location():

    print("\n" + "=" * 60)

    print("[*] Logging Information")

    print("=" * 60)

    print(
        f"Log File: {LOG_FILE_PATH}"
    )

    print("=" * 60)


"""
====================================================
*   Example standalone execution
*
====================================================
"""
if __name__ == "__main__":

    print_log_location()

    log_info(
        "Wi-Fi Security Testbed logger initialized"
    )

    log_warning(
        "This is a test warning"
    )

    log_error(
        "This is a test error"
    )

    log_critical(
        "This is a critical test message"
    )