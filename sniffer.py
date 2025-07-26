from scapy.all import rdpcap, Raw, IP
import json, datetime
from collections import defaultdict
import geoip2.database
import html as html_lib
import os

# Load GeoLite2 database (update the path if needed)
reader = geoip2.database.Reader('GeoLite2-City.mmdb')

def get_country(ip):
    try:
        response = reader.city(ip)
        return response.country.name
    except:
        return "Unknown"

# --- Configurable Paths ---
SIGNATURE_FILE = "signature.json"
PCAP_FILE = "capture/attack.pcap"
REPORT_FILE = "report.txt"
HTML_REPORT = "report.html"

# --- Load Signatures ---
with open(SIGNATURE_FILE, "r", encoding="utf-8") as f:
    signatures = json.load(f)

sig_list = []
for s in signatures:
    sig_id = s.get("id", "UNKNOWN")
    sig_desc = s.get("description", "No description")
    pattern = s.get("pattern", "").lower()
    sig_list.append((sig_id, sig_desc, pattern))

# --- Read PCAP ---
packets = rdpcap(PCAP_FILE)
print(f"[+] Loaded {len(packets)} packets from {PCAP_FILE}")

alerts = []

# --- Scan Packets ---
for idx, pkt in enumerate(packets, 1):
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw]).decode(errors="ignore").lower()
        for sig_id, sig_desc, pattern in sig_list:
            if pattern in payload:
                src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                alert = {
                    "pkt_no": idx,
                    "time": datetime.datetime.now().isoformat(timespec="seconds"),
                    "src": src_ip,
                    "dst": dst_ip,
                    "sig_id": sig_id,
                    "sig_desc": sig_desc,
                    "snippet": payload[:80].replace("\n", " ")
                }
                alerts.append(alert)
                print(f"[!] ALERT pkt#{idx} {sig_id}: {sig_desc}")
                break

# --- Write Plain Text Report ---
with open(REPORT_FILE, "w", encoding="utf-8") as f:
    for a in alerts:
        f.write(f"{a['time']} | pkt {a['pkt_no']:>5} | {a['sig_id']} | "
                f"{a['src']} -> {a['dst']} | {a['sig_desc']}\n"
                f"    {a['snippet']}\n\n")

print(f"[+] Scan complete: {len(alerts)} alert(s) written to {REPORT_FILE}")

# --- Grouping for HTML Report ---
alert_by_ip = defaultdict(list)
for a in alerts:
    alert_by_ip[a["src"]].append(a)

# --- Write HTML Report ---
html_content = """
<html>
<head>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
        }}
        h1 {{
            color: #333;
        }}
        ...
    </style>
</head>
<body>
    <h1>Intrusion Detection Report</h1>
    <p>Report generated on: {}</p>
    ...
</body>
</html>
""".format(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

html = ""
for src, entries in alert_by_ip.items():
    html += f"<div class='src-ip'>Source IP: {src} ({get_country(src)})</div>\n"
    html += "<table><tr><th>Packet</th><th>Time</th><th>Destination</th><th>Alert Type</th><th>Description</th><th>Payload Snippet</th></tr>\n"
    for a in entries:
        safe_snippet = html_lib.escape(a['snippet'])  # Escape once, inside the loop
        html += f"<tr><td>{a['pkt_no']}</td><td>{a['time']}</td><td>{a['dst']}</td><td>{a['sig_id']}</td><td>{a['sig_desc']}</td><td>{safe_snippet}</td></tr>\n"
    html += "</table>\n"

html += "</body></html>"

with open(HTML_REPORT, "w", encoding="utf-8") as f:
    f.write(html)

print(f"[+] HTML report written to {HTML_REPORT}")