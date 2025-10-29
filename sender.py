# Upgraded Traffic Generator - V3
# Includes a behavioral anomaly attack (Slowloris) to test the core AI model.

from scapy.all import IP, TCP, Raw, send, sr1
import random
import time
import sys
from datetime import datetime

# --- Configuration ---
TARGET_IP = "10.171.213.153"  # The IP of the machine running the NIDS (can be overridden by command line)
TARGET_PORT = 12345           # The port for mixed traffic tests
PACKET_COUNT = 40

# --- Payloads for Mixed Traffic Test ---
signature_attacks = [
    b"SELECT * FROM users", b"' OR '1'='1", b"<script>alert('xss')</script>",
    b"../../../etc/passwd", b"cmd.exe /c dir", b"DROP TABLE users"
]
normal_payloads = [ b"hello world", b"normal data", b"status ok" ]

def log_msg(msg):
    """Prints a message with a timestamp."""
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")

# --- Test Scenario 1: Mixed Signature/Normal Traffic ---
def run_mixed_traffic_test(target_ip, target_port, packet_count):
    # This function remains the same
    log_msg("Starting Mixed Traffic Test...")
    all_payloads = signature_attacks + normal_payloads
    for i in range(1, packet_count + 1):
        payload = random.choice(all_payloads) # nosec
        sport = random.randint(1024, 65535)
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port) / Raw(load=payload)
        send(pkt, verbose=False)
        ptype = "ATTACK (Signature)" if payload in signature_attacks else "NORMAL"
        log_msg(f"Packet #{i:02d} | {ptype} | Port {sport} -> {target_port}")
        time.sleep(random.uniform(0.5, 2.0))
    log_msg("Mixed Traffic Test completed.")

# --- Test Scenario 2: AI Port Scan Attack ---
def run_port_scan_test(target_ip):
    # This function remains the same
    log_msg("Starting AI Port Scan Test...")
    ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 139, 443, 445, 1433, 3306, 3389, 8080]
    random.shuffle(ports_to_scan)
    log_msg(f"Scanning {len(ports_to_scan)} ports on {target_ip}...")
    for i, port in enumerate(ports_to_scan): # nosec
        sport = random.randint(1024, 65535)
        pkt = IP(dst=target_ip) / TCP(sport=sport, dport=port, flags="S")
        send(pkt, verbose=False)
        log_msg(f"Scan #{i+1:02d} | SENT SYN PACKET | Port {sport} -> {port}")
        time.sleep(random.uniform(0.1, 0.3))
    log_msg("AI Port Scan Test completed.")

# --- NEW Test Scenario 3: AI "Slow Drip" Anomaly ---
def run_slowloris_test(target_ip, target_port):
    log_msg("Starting AI 'Slow Drip' Anomaly Test...")
    # This test simulates a behavioral anomaly where a connection is established
    # and kept alive with minimal, infrequent traffic, rather than a traditional
    # Slowloris attack which typically involves many concurrent partial HTTP requests.
    # It's designed to test the NIDS's ability to detect long-duration, low-activity flows.
    duration = 75  # Run for 75 seconds to ensure the flow is long
    keep_alive_interval = 15  # Send a keep-alive packet every 15 seconds
    
    sport = random.randint(1024, 65535)
    
    try:
        # Step 1: Establish a connection (or at least start one) with a SYN packet
        syn_pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="S")
        send(syn_pkt, verbose=False)
        log_msg(f"Connection initiated to {target_ip}:{target_port}")
        
        end_time = time.time() + duration
        next_keep_alive = time.time() + keep_alive_interval

        # Step 2: Keep the connection alive with tiny, infrequent packets
        while time.time() < end_time:
            if time.time() >= next_keep_alive:
                keep_alive_pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="A") / Raw(load=".")
                send(keep_alive_pkt, verbose=False)
                log_msg(f"Sent keep-alive packet to hold connection open...")
                next_keep_alive = time.time() + keep_alive_interval
            time.sleep(1)
        
        # Step 3: Close the connection
        fin_pkt = IP(dst=target_ip) / TCP(sport=sport, dport=target_port, flags="F")
        send(fin_pkt, verbose=False)
        log_msg("Connection closed.")
        
    except Exception as e:
        log_msg(f"Error during Slow Drip test: {e}")
        
    log_msg("AI 'Slow Drip' Anomaly Test completed. The IDS will analyze the long-duration flow.")

def main():
    target_ip = TARGET_IP
    if len(sys.argv) > 1:
        target_ip = sys.argv[1]

    print("=" * 50)
    print("    ASAP IDS Test Sender V3")
    print("=" * 50)
    print(f"Target IP: {target_ip}")
    print("\nSelect a test to run:")
    print("  1: Mixed Traffic Test (Tests Signature Engine)")
    print("  2: AI Port Scan Test (Tests Heuristic Scanner)")
    print("  3: AI 'Slow Drip' Anomaly Test (Tests Core AI Model)")
    
    choice = input("Enter your choice (1, 2, or 3): ")
    print("-" * 50)

    if choice == '1':
        run_mixed_traffic_test(target_ip, TARGET_PORT, PACKET_COUNT)
    elif choice == '2':
        run_port_scan_test(target_ip)
    elif choice == '3':
        run_slowloris_test(target_ip, 80) # Slowloris test is best against a web port
    else:
        print("Invalid choice. Exiting.")

if __name__ == "__main__":
    main()