from scapy.all import IP, TCP, send
import random
import time

TARGET_IP = "192.168.0.101"  # IP of the IDS machine
TARGET_PORT = 12345

# Signature patterns to trigger rules
malicious_payloads = [
    b"pattern8",
    b"pattern9",
    b"pattern10",
    b"pattern11",
    b"pattern12"
]

# Benign payloads to act as noise
benign_payloads = [
    b"hello world",
    b"this is just normal data",
    b"random traffic",
    b"payload without patterns",
    b"scapy rules"
]

# Mix both to create uncertainty
all_payloads = malicious_payloads + benign_payloads
random.shuffle(all_payloads)

for i, data in enumerate(all_payloads, 1):
    # Use random high ports as source
    sport = random.randint(1024, 65535)

    # 25% chance to split payload into two stealthy packets
    if random.random() < 0.25 and len(data) > 4:
        split_index = random.randint(1, len(data) - 2)
        part1 = data[:split_index]
        part2 = data[split_index:]

        pkt1 = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, sport=sport) / part1
        pkt2 = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, sport=sport+1) / part2

        send(pkt1, verbose=False)
        time.sleep(random.uniform(0.5, 1.5))
        send(pkt2, verbose=False)
        print(f"[!] Sent stealthy split packet #{i}")
    else:
        pkt = IP(dst=TARGET_IP) / TCP(dport=TARGET_PORT, sport=sport) / data
        send(pkt, verbose=False)
        print(f"[+] Sent packet #{i}: {'MALICIOUS' if data in malicious_payloads else 'BENIGN'}")

    # Random delay to mimic real traffic
    time.sleep(random.uniform(0.3, 2.0))
