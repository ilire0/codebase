from scapy.all import *

def handle_packet(pkt):
    # Prüfen ob es ein Beacon Frame ist
    if pkt.haslayer(Dot11Beacon):
        # MAC-Adresse des Access Points (BSSID)
        bssid = pkt[Dot11].addr2
        
        # SSID (Netzwerkname)
        ssid = pkt[Dot11Elt].info.decode(errors="ignore")
        
        # Signalstärke (falls vorhanden)
        try:
            signal = pkt.dBm_AntSignal
        except:
            signal = "N/A"
        
        # Kanal extrahieren
        channel = None
        elt = pkt[Dot11Elt]
        while isinstance(elt, Dot11Elt):
            if elt.ID == 3:  # DS Parameter Set → Kanal
                channel = elt.info[0]
                break
            elt = elt.payload
        
        print(f"SSID: {ssid}")
        print(f"BSSID: {bssid}")
        print(f"Signal: {signal} dBm")
        print(f"Channel: {channel}")
        print("-" * 40)


print("Sniffe Beacon Frames... (CTRL+C zum Stoppen)")

sniff(iface="wlan0", prn=handle_packet, store=0)