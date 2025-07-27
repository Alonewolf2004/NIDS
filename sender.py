# Stable Traffic Generator - Windows Safe Version
from scapy.all import IP, TCP, Raw, send
import random
import time
import sys
from datetime import datetime

# Simple Configuration
TARGET_IP = "192.168.0.101"
TARGET_PORT = 12345
PACKET_COUNT = 25

# Attack patterns
attacks = [
    b"pattern8", b"pattern9", b"pattern10", b"pattern11", b"pattern12",
    b"SELECT * FROM users", b"' OR '1'='1", b"<script>alert('xss')</script>",
    b"../../../etc/passwd", b"cmd.exe /c dir", b"DROP TABLE users"
]

# Normal traffic
normal = [
    b"hello world", b"normal data", b"status ok", b"heartbeat", 
    b"HTTP/1.1 200 OK", b"user login", b"session active", b"file uploaded"
]

# Stats
sent = 0
errors = 0

def log_msg(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] {msg}")

def send_packet(payload, num):
    global sent, errors
    try:
        sport = random.randint(1024, 65535)
        pkt = IP(dst=TARGET_IP) / TCP(sport=sport, dport=TARGET_PORT) / Raw(load=payload)
        send(pkt, verbose=False)
        
        ptype = "ATTACK" if payload in attacks else "NORMAL"
        log_msg(f"Packet #{num:02d} | {ptype} | Port {sport} | {len(payload)} bytes")
        sent += 1
        
    except Exception as e:
        log_msg(f"ERROR sending packet #{num}: {e}")
        errors += 1

def send_split(payload, num):
    global sent, errors
    if len(payload) < 3:
        send_packet(payload, num)
        return
        
    try:
        mid = len(payload) // 2
        part1, part2 = payload[:mid], payload[mid:]
        sport = random.randint(1024, 65535)
        
        pkt1 = IP(dst=TARGET_IP) / TCP(sport=sport, dport=TARGET_PORT) / Raw(load=part1)
        pkt2 = IP(dst=TARGET_IP) / TCP(sport=sport+1, dport=TARGET_PORT) / Raw(load=part2)
        
        send(pkt1, verbose=False)
        time.sleep(0.3)
        send(pkt2, verbose=False)
        
        ptype = "ATTACK-SPLIT" if payload in attacks else "NORMAL-SPLIT"
        log_msg(f"Packet #{num:02d} | {ptype} | Ports {sport},{sport+1} | {len(part1)}+{len(part2)} bytes")
        sent += 2
        
    except Exception as e:
        log_msg(f"ERROR sending split packet #{num}: {e}")
        errors += 1

def main():
    global TARGET_IP, TARGET_PORT, PACKET_COUNT
    
    # Simple command line parsing
    if len(sys.argv) > 1:
        TARGET_IP = sys.argv[1]
    if len(sys.argv) > 2:
        TARGET_PORT = int(sys.argv[2])
    if len(sys.argv) > 3:
        PACKET_COUNT = int(sys.argv[3])
    
    print("=" * 50)
    print("    Stable Traffic Generator")
    print("=" * 50)
    print(f"Target: {TARGET_IP}:{TARGET_PORT}")
    print(f"Packets: {PACKET_COUNT}")
    print("-" * 50)
    
    # Mix payloads
    all_payloads = attacks + normal
    
    start_time = time.time()
    
    try:
        for i in range(1, PACKET_COUNT + 1):
            payload = random.choice(all_payloads)
            
            # 30% chance to split packet
            if random.random() < 0.3:
                send_split(payload, i)
            else:
                send_packet(payload, i)
            
            # Random delay
            if i < PACKET_COUNT:
                time.sleep(random.uniform(0.5, 2.0))
        
        runtime = time.time() - start_time
        
        print("-" * 50)
        print("COMPLETED")
        print(f"Runtime: {runtime:.1f} seconds")
        print(f"Packets sent: {sent}")
        print(f"Errors: {errors}")
        print(f"Success rate: {((sent-errors)/max(sent,1)*100):.1f}%")
        print("-" * 50)
        
    except KeyboardInterrupt:
        print("\nStopped by user")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()