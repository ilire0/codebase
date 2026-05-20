import json
import os
from enum import Enum

REPORT_DIR = "output/reports"

os.makedirs(REPORT_DIR, exist_ok=True)


class EnumEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, Enum):
            return obj.name
        return super().default(obj)


def export_json(networks):

    with open(f"{REPORT_DIR}/scan_results.json", "w") as f:
        json.dump(networks, f, indent=4, cls=EnumEncoder)


def print_network_summary(networks):

    print("\n" + "=" * 100)

    print(
        f"{'SSID':<20} "
        f"{'Channel':<8} "
        f"{'Security':<15} "
        f"{'RSSI':<8} "
        f"{'PMF':<8}"
    )

    print("=" * 100)

    for network in networks.values():

        pmf = "Yes" if network.get("MFP Supported") else "No"

        print(
            f"{network['SSID']:<20} "
            f"{str(network['Channel']):<8} "
            f"{network['Version']:<15} "
            f"{str(network['RSSI']):<8} "
            f"{pmf:<8}"
        )