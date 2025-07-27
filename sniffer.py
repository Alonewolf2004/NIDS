from scapy.all import rdpcap, Raw, IP
import json
import datetime
from collections import defaultdict
import geoip2.database
import html as html_lib
import os

# Load GeoLite2 database (update the path if needed)
try:
    reader = geoip2.database.Reader('GeoLite2-City.mmdb')
except Exception as e:
    print(f"[!] Warning: Could not load GeoIP database: {e}")
    reader = None

def get_country(ip):
    if reader is None:
        return "Unknown"
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
try:
    with open(SIGNATURE_FILE, "r", encoding="utf-8") as f:
        signatures = json.load(f)
except FileNotFoundError:
    print(f"[!] Error: Signature file '{SIGNATURE_FILE}' not found!")
    exit(1)
except json.JSONDecodeError:
    print(f"[!] Error: Invalid JSON in signature file '{SIGNATURE_FILE}'!")
    exit(1)

sig_list = []
for s in signatures:
    sig_id = s.get("id", "UNKNOWN")
    sig_desc = s.get("description", "No description")
    pattern = s.get("pattern", "").lower()
    sig_list.append((sig_id, sig_desc, pattern))

# --- Read PCAP ---
try:
    packets = rdpcap(PCAP_FILE)
    print(f"[+] Loaded {len(packets)} packets from {PCAP_FILE}")
except FileNotFoundError:
    print(f"[!] Error: PCAP file '{PCAP_FILE}' not found!")
    exit(1)
except Exception as e:
    print(f"[!] Error reading PCAP file: {e}")
    exit(1)

alerts = []

# --- Scan Packets ---
for idx, pkt in enumerate(packets, 1):
    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw]).decode(errors="ignore").lower()
        for sig_id, sig_desc, pattern in sig_list:
            if pattern in payload:
                src_ip = pkt[IP].src if pkt.haslayer(IP) else "N/A"
                dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
                
                # Get actual packet timestamp if available
                pkt_time = datetime.datetime.fromtimestamp(float(pkt.time)).isoformat(timespec="seconds") if hasattr(pkt, 'time') else datetime.datetime.now().isoformat(timespec="seconds")
                
                alert = {
                    "pkt_no": idx,
                    "time": pkt_time,
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
try:
    with open(REPORT_FILE, "w", encoding="utf-8") as f:
        f.write(f"Intrusion Detection Report\n")
        f.write(f"Generated on: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Total alerts: {len(alerts)}\n")
        f.write("=" * 80 + "\n\n")
        
        for a in alerts:
            f.write(f"{a['time']} | pkt {a['pkt_no']:>5} | {a['sig_id']} | "
                    f"{a['src']} -> {a['dst']} | {a['sig_desc']}\n"
                    f"    {a['snippet']}\n\n")
    
    print(f"[+] Scan complete: {len(alerts)} alert(s) written to {REPORT_FILE}")
except Exception as e:
    print(f"[!] Error writing text report: {e}")

# --- Grouping for HTML Report ---
alert_by_ip = defaultdict(list)
for a in alerts:
    alert_by_ip[a["src"]].append(a)

# --- Write HTML Report ---
html_content = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Intrusion Detection Report</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 40px;
            background-color: #f5f5f5;
        }}
        h1 {{
            color: #333;
            border-bottom: 2px solid #007acc;
            padding-bottom: 10px;
        }}
        .summary {{
            background-color: #e7f3ff;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border-left: 4px solid #007acc;
        }}
        .src-ip {{
            background-color: #ffebee;
            padding: 10px;
            margin: 20px 0 10px 0;
            border-left: 4px solid #f44336;
            font-weight: bold;
            color: #c62828;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            margin-bottom: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        th {{
            background-color: #007acc;
            color: white;
            padding: 12px;
            text-align: left;
            font-weight: bold;
        }}
        td {{
            padding: 10px 12px;
            border-bottom: 1px solid #ddd;
        }}
        tr:nth-child(even) {{
            background-color: #f9f9f9;
        }}
        tr:hover {{
            background-color: #f0f8ff;
        }}
        .snippet {{
            font-family: monospace;
            background-color: #f5f5f5;
            padding: 4px;
            border-radius: 3px;
            max-width: 200px;
            word-break: break-all;
        }}
        .alert-id {{
            font-weight: bold;
            color: #d32f2f;
        }}
    </style>
</head>
<body>
    <h1>Intrusion Detection Report</h1>
    <div class="summary">
        <p><strong>Report generated on:</strong> {datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
        <p><strong>Total packets analyzed:</strong> {len(packets)}</p>
        <p><strong>Total alerts:</strong> {len(alerts)}</p>
        <p><strong>Unique source IPs:</strong> {len(alert_by_ip)}</p>
    </div>
"""

if alerts:
    for src, entries in alert_by_ip.items():
        country = get_country(src)
        html_content += f'    <div class="src-ip">Source IP: {src} ({country}) - {len(entries)} alert(s)</div>\n'
        html_content += """    <table>
        <tr>
            <th>Packet #</th>
            <th>Time</th>
            <th>Destination</th>
            <th>Alert Type</th>
            <th>Description</th>
            <th>Payload Snippet</th>
        </tr>
"""
        for a in entries:
            safe_snippet = html_lib.escape(a['snippet'])
            html_content += f"""        <tr>
            <td>{a['pkt_no']}</td>
            <td>{a['time']}</td>
            <td>{a['dst']}</td>
            <td class="alert-id">{a['sig_id']}</td>
            <td>{html_lib.escape(a['sig_desc'])}</td>
            <td class="snippet">{safe_snippet}</td>
        </tr>
"""
        html_content += "    </table>\n"
else:
    html_content += "    <p><strong>No alerts detected.</strong></p>\n"

html_content += """</body>
</html>"""

try:
    with open(HTML_REPORT, "w", encoding="utf-8") as f:
        f.write(html_content)
    print(f"[+] HTML report written to {HTML_REPORT}")
except Exception as e:
    print(f"[!] Error writing HTML report: {e}")

# Close GeoIP reader if it was opened
if reader:
    reader.close()