import json
import os
import datetime
from enum import Enum

# PDF generation
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
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


def get_report_dir():
    report_dir = os.getenv("WIFI_REPORT_DIR", REPORT_DIR)
    try:
        os.makedirs(report_dir, exist_ok=True)
    except PermissionError:
        report_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(report_dir, exist_ok=True)

    if not os.access(report_dir, os.W_OK):
        report_dir = os.path.join(os.getcwd(), "reports")
        os.makedirs(report_dir, exist_ok=True)

    return report_dir


def export_json(networks):
    report_dir = get_report_dir()
    with open(os.path.join(report_dir, "scan_results.json"), "w") as f:
        json.dump(networks, f, indent=4, cls=EnumEncoder)


def export_pdf(networks, filename="scan_results.pdf"):

    if not REPORTLAB_AVAILABLE:
        raise RuntimeError("reportlab is not installed. Please install via requirements.txt")

    report_dir = get_report_dir()
    path = os.path.join(report_dir, filename)
    doc = SimpleDocTemplate(
        path,
        pagesize=A4,
        leftMargin=20 * mm,
        rightMargin=20 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm,
    )

    styles = getSampleStyleSheet()
    title_style = styles["Title"]
    subtitle_style = styles["Heading2"]
    body_style = styles["BodyText"]
    body_style.spaceAfter = 6

    story = []
    story.append(Paragraph("Wi-Fi Scan Report", title_style))
    story.append(Spacer(1, 4 * mm))

    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary = {
        "Report generated": scan_time,
        "Total networks": len(networks),
        "Open networks": sum(1 for net in networks.values() if net.get("Open Network")),
        "Hidden SSIDs": sum(1 for net in networks.values() if net.get("Hidden SSID")),
        "Rogue APs": sum(1 for net in networks.values() if net.get("Rogue AP")),
        "WPA3 networks": sum(1 for net in networks.values() if net.get("Version") == "WPA3"),
        "Weak encryption": sum(1 for net in networks.values() if net.get("Weak Encryption")),
    }

    story.append(Paragraph("Summary", subtitle_style))

    summary_data = [["Property", "Value"]]
    for label, value in summary.items():
        summary_data.append([label, str(value)])

    summary_table = Table(summary_data, colWidths=[80 * mm, 80 * mm])
    summary_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E7D32")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#F1F8E9")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ])
    )
    story.append(summary_table)
    story.append(Spacer(1, 8 * mm))

    if networks:
        story.append(Paragraph("Network Details", subtitle_style))
        story.append(Spacer(1, 2 * mm))

        table_header = [
            "SSID",
            "BSSID",
            "Channel",
            "RSSI",
            "Security",
            "Auth Mode",
            "Vendor",
            "Open",
            "PMF",
            "Rogue",
        ]

        table_data = [table_header]
        sorted_networks = sorted(
            networks.values(),
            key=lambda x: x.get("RSSI") if x.get("RSSI") is not None else -100,
            reverse=True,
        )

        for net in sorted_networks:
            row = [
                str(net.get("SSID", ""))[:30],
                str(net.get("BSSID", "")),
                str(net.get("Channel", "")),
                str(net.get("RSSI", "")),
                str(net.get("Version", net.get("Crypto", "")))[:20],
                str(net.get("Auth Mode", "")),
                str(net.get("Vendor", ""))[:20],
                "Yes" if net.get("Open Network") else "No",
                "Yes" if net.get("MFP Supported") else "No",
                "Yes" if net.get("Rogue AP") else "No",
            ]
            table_data.append(row)

        col_widths = [40 * mm, 45 * mm, 16 * mm, 16 * mm, 30 * mm, 25 * mm, 30 * mm, 14 * mm, 14 * mm, 14 * mm]
        details_table = Table(table_data, colWidths=col_widths, repeatRows=1)
        details_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1976D2")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                ("ALIGN", (2, 0), (-1, -1), "CENTER"),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ])
        )
        story.append(details_table)
    else:
        story.append(Paragraph("No Wi-Fi networks were detected during the scan.", body_style))

    doc.build(story)
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