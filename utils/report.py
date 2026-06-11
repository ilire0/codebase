import json
import os
import datetime
from enum import Enum
from collections import Counter

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


def _format_security(network):
    return str(network.get("Version") or network.get("Crypto") or "Unknown")


def _is_tkip_enabled(network):
    rsn = network.get("RSN-IE") or {}
    if not isinstance(rsn, dict):
        return False

    for cipher in [rsn.get("Group Cipher Suite")] + rsn.get("Pairwise Cipher Suites", []):
        if isinstance(cipher, dict) and "TKIP" in str(cipher.get("Name", "") or ""):
            return True
    return False


def _detected_vulnerabilities(network):
    return [v for v in network.get("Vulnerabilities", {}).values() if v.get("Detected")]


def _vulnerability_severity_counts(networks):
    counters = Counter()
    for net in networks.values():
        for vuln in _detected_vulnerabilities(net):
            counters[str(vuln.get("Severity", "UNKNOWN"))] += 1
    return counters


def _top_risky_networks(networks, limit=5):
    severity_weight = {"CRITICAL": 100, "HIGH": 10, "MEDIUM": 3, "LOW": 1}
    scored = []
    for net in networks.values():
        detected = _detected_vulnerabilities(net)
        score = sum(severity_weight.get(str(v.get("Severity", "LOW")), 1) for v in detected)
        scored.append((score, len(detected), net.get("RSSI", -100), net))

    scored.sort(key=lambda entry: (entry[0], entry[1], entry[2]), reverse=True)
    return [entry[3] for entry in scored[:limit]]


def _most_common_channel(networks):
    channels = [net.get("Channel") for net in networks.values() if net.get("Channel") is not None]
    if not channels:
        return None
    return Counter(channels).most_common(1)[0][0]


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
    with open(os.path.join(report_dir, "scan_results.json"), "w", encoding="utf-8") as f:
        json.dump(networks, f, indent=4, sort_keys=True, ensure_ascii=False, cls=EnumEncoder)


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
    detected_security_counts = _vulnerability_severity_counts(networks)
    total_rssi = sum(net.get("RSSI", 0) for net in networks.values() if isinstance(net.get("RSSI"), (int, float)))
    rssi_count = sum(1 for net in networks.values() if isinstance(net.get("RSSI"), (int, float)))
    average_rssi = round(total_rssi / rssi_count, 1) if rssi_count else "N/A"

    summary = {
        "Report generated": scan_time,
        "Total networks": len(networks),
        "Unique SSIDs": len({net.get("SSID") for net in networks.values() if net.get("SSID")}),
        "Most common channel": _most_common_channel(networks) or "N/A",
        "WPS enabled": sum(1 for net in networks.values() if net.get("WPS Enabled")),
        "PMF supported": sum(1 for net in networks.values() if net.get("MFP Supported")),
        "PMF required": sum(1 for net in networks.values() if net.get("MFP Required")),
        "Hidden SSIDs": sum(1 for net in networks.values() if net.get("Hidden SSID")),
        "Rogue APs": sum(1 for net in networks.values() if net.get("Rogue AP")),
        "Networks with TKIP": sum(1 for net in networks.values() if _is_tkip_enabled(net)),
        "WPA3 networks": sum(1 for net in networks.values() if net.get("Version") == "WPA3"),
        "Average RSSI": average_rssi,
        "Average detected vulnerabilities": round(
            sum(net.get("Detected Vulnerabilities", 0) for net in networks.values()) / len(networks)
            if networks else 0,
            2,
        ),
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

    severity_data = [["Severity", "Detected Count"]]
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        severity_data.append([severity, str(detected_security_counts.get(severity, 0))])

    story.append(Paragraph("Detected Vulnerability Severity", subtitle_style))
    severity_table = Table(severity_data, colWidths=[80 * mm, 80 * mm])
    severity_table.setStyle(
        TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#B71C1C")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("BACKGROUND", (0, 1), (-1, -1), colors.HexColor("#FFEBEE")),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ])
    )
    story.append(severity_table)
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
            "WPS",
            "PMF",
            "Hidden",
            "Vuln Count",
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
                str(_format_security(net))[:20],
                str(net.get("Auth Mode", "")),
                "Yes" if net.get("WPS Enabled") else "No",
                "Yes" if net.get("MFP Supported") else "No",
                "Yes" if net.get("Hidden SSID") else "No",
                str(len(_detected_vulnerabilities(net))),
                "Yes" if net.get("Rogue AP") else "No",
            ]
            table_data.append(row)

        col_widths = [35 * mm, 45 * mm, 15 * mm, 15 * mm, 30 * mm, 22 * mm, 14 * mm, 14 * mm, 14 * mm, 18 * mm, 14 * mm]
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
        story.append(Spacer(1, 8 * mm))

        top_networks = _top_risky_networks(networks)
        if top_networks:
            story.append(Paragraph("Top Risk Networks", subtitle_style))
            risk_data = [["SSID", "BSSID", "Detected Vulns", "Highest Severity", "RSSI"]]
            for net in top_networks:
                detected = _detected_vulnerabilities(net)
                highest = max(
                    (str(v.get("Severity", "LOW")) for v in detected),
                    key=lambda severity: ["LOW", "MEDIUM", "HIGH", "CRITICAL"].index(severity)
                    if detected else "LOW",
                ) if detected else "NONE"
                risk_data.append([
                    str(net.get("SSID", ""))[:30],
                    str(net.get("BSSID", "")),
                    str(len(detected)),
                    highest,
                    str(net.get("RSSI", "")),
                ])
            risk_table = Table(risk_data, colWidths=[35 * mm, 45 * mm, 26 * mm, 30 * mm, 14 * mm], repeatRows=1)
            risk_table.setStyle(
                TableStyle([
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#F57F17")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.whitesmoke),
                    ("ALIGN", (2, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
                    ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.whitesmoke, colors.lightgrey]),
                ])
            )
            story.append(risk_table)
    else:
        story.append(Paragraph("No Wi-Fi networks were detected during the scan.", body_style))

    doc.build(story)
    return path


def print_network_summary(networks):

    print("\n" + "=" * 120)

    print(
        f"{'SSID':<22} "
        f"{'Channel':<8} "
        f"{'Security':<18} "
        f"{'RSSI':<7} "
        f"{'PMF':<5} "
        f"{'WPS':<5} "
        f"{'Hidden':<7} "
        f"{'Vulns':<5} "
        f"{'Rogue':<5}"
    )

    print("=" * 120)

    for network in networks.values():
        pmf = "Yes" if network.get("MFP Supported") else "No"
        wps = "Yes" if network.get("WPS Enabled") else "No"
        hidden = "Yes" if network.get("Hidden SSID") else "No"
        detected_vulns = len(_detected_vulnerabilities(network))

        print(
            f"{str(network.get('SSID', '')):<22} "
            f"{str(network.get('Channel', '')):<8} "
            f"{_format_security(network):<18} "
            f"{str(network.get('RSSI', '')):<7} "
            f"{pmf:<5} "
            f"{wps:<5} "
            f"{hidden:<7} "
            f"{str(detected_vulns):<5} "
            f"{('Yes' if network.get('Rogue AP') else 'No'):<5}"
        )