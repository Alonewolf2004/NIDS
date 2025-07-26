import json
from scapy.all import get_if_list, get_if_addr, sniff, raw, TCP
from datetime import datetime

TARGET_IP_PREFIX = "192.168."
SIGNATURE_FILE = "signature.json"
TARGET_PORT = 12345
LOG_FILE = "alerts.log"

# Load all JSON rules
try:
    with open(SIGNATURE_FILE, "r") as f:
        SIGNATURES = json.load(f)
except Exception as e:
    print(f"[ERROR] Could not load signature file: {e}")
    exit(1)

def choose_iface():
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip.startswith(TARGET_IP_PREFIX):
                return iface
        except:
            continue
    raise RuntimeError("No matching interface found on this network.")

def log_alert(rule_id, description, packet_summary):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f"[{timestamp}] ALERT | Rule ID: {rule_id} | Desc: {description}\nSummary: {packet_summary}\n\n"

    # Write to file
    with open(LOG_FILE, "a") as log_file:
        log_file.write(log_line)

    # Also print to console
    print(log_line.strip())

def process(pkt):
    if not pkt.haslayer(TCP):
        return

    if pkt[TCP].dport != TARGET_PORT:
        return

    try:
        payload = raw(pkt[TCP].payload).decode(errors="ignore").lower()
    except:
        return

    for rule in SIGNATURES:
        pattern = rule.get("payload_pattern", "").lower()
        if pattern and pattern in payload:
            log_alert(rule.get("id", "N/A"), rule.get("description", "No Description"), pkt.summary())

def main():
    try:
        iface = choose_iface()
        print(f"[INFO] Sniffing on interface: {iface}")
        sniff(
            iface=iface,
            filter=f"tcp port {TARGET_PORT}",
            prn=process,
            store=False
        )
    except Exception as e:
        print(f"[ERROR] {e}")

if __name__ == "__main__":
    main()
