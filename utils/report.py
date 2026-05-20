import json
import os
from enum import Enum

# PDF generation
try:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas
    from reportlab.lib.units import mm
    REPORTLAB_AVAILABLE = True
except Exception:
    REPORTLAB_AVAILABLE = False
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


def export_pdf(networks, filename="scan_results.pdf"):

    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab is not installed. Please install via requirements.txt")

    path = os.path.join(REPORT_DIR, filename)

    c = canvas.Canvas(path, pagesize=A4)
    width, height = A4

    margin = 15 * mm
    x = margin
    y = height - margin

    c.setFont("Helvetica-Bold", 14)
    c.drawString(x, y, "Wi-Fi Scan Report")
    y -= 12 * mm

    # table header
    c.setFont("Helvetica-Bold", 10)
    headers = ["SSID", "BSSID", "Channel", "RSSI", "Vendor", "Security"]
    col_widths = [60 * mm, 50 * mm, 18 * mm, 18 * mm, 50 * mm, 40 * mm]

    # draw header
    cx = x
    for i, h in enumerate(headers):
        c.drawString(cx, y, h)
        cx += col_widths[i]

    y -= 6 * mm
    c.setFont("Helvetica", 9)

    # rows
    row_height = 6 * mm
    for bssid, net in networks.items():
        if y < margin + row_height:
            c.showPage()
            y = height - margin
            c.setFont("Helvetica", 9)

        ssid = str(net.get("SSID", ""))[:30]
        vendor = str(net.get("Vendor", ""))[:25]
        channel = str(net.get("Channel", ""))
        rssi = str(net.get("RSSI", ""))
        security = str(net.get("Version", net.get("Crypto", "")))[:30]

        cx = x
        cols = [ssid, bssid, channel, rssi, vendor, security]

        for i, value in enumerate(cols):
            c.drawString(cx, y, value)
            cx += col_widths[i]

        y -= row_height

    c.save()

    return path


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