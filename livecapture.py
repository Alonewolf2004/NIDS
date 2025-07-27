"""
Real-time Intrusion Detection System (IDS) Network Sniffer
Monitors network traffic for malicious patterns and logs alerts.

Usage:
    python ids.py [options]
    
Requirements:
    - Python 3.6+
    - Scapy library (pip install scapy)
    - Administrator/root privileges for packet capture
"""

import json
import sys
import signal
import argparse
from pathlib import Path
from scapy.all import get_if_list, get_if_addr, sniff, raw, TCP, IP
from datetime import datetime
import threading
import time

# Configuration constants
DEFAULT_TARGET_IP_PREFIX = "192.168."
DEFAULT_SIGNATURE_FILE = "signature.json"
DEFAULT_TARGET_PORT = 12345
DEFAULT_LOG_FILE = "alerts.log"
DEFAULT_CAPTURE_FILTER = "tcp"

class IDSConfig:
    """Configuration class for IDS settings"""
    def __init__(self):
        self.target_ip_prefix = DEFAULT_TARGET_IP_PREFIX
        self.signature_file = DEFAULT_SIGNATURE_FILE
        self.target_port = DEFAULT_TARGET_PORT
        self.log_file = DEFAULT_LOG_FILE
        self.capture_filter = DEFAULT_CAPTURE_FILTER
        self.interface = None
        self.verbose = False
        self.signatures = []
        self.packet_count = 0
        self.alert_count = 0
        self.start_time = None

class NetworkIDS:
    """Real-time Network Intrusion Detection System"""
    
    def __init__(self, config):
        self.config = config
        self.running = False
        self.stats_lock = threading.Lock()
        
    def load_signatures(self):
        """Load signature rules from JSON file"""
        try:
            signature_path = Path(self.config.signature_file)
            if not signature_path.exists():
                raise FileNotFoundError(f"Signature file '{self.config.signature_file}' not found")
                
            with open(signature_path, "r", encoding="utf-8") as f:
                self.config.signatures = json.load(f)
                
            if not isinstance(self.config.signatures, list):
                raise ValueError("Signature file must contain a JSON array")
                
            # Validate signature format
            for i, rule in enumerate(self.config.signatures):
                if not isinstance(rule, dict):
                    raise ValueError(f"Rule {i} must be a dictionary")
                if "payload_pattern" not in rule:
                    print(f"[WARNING] Rule {i} missing 'payload_pattern' field")
                    
            print(f"[INFO] Loaded {len(self.config.signatures)} signature rules")
            
        except json.JSONDecodeError as e:
            print(f"[ERROR] Invalid JSON in signature file: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"[ERROR] Could not load signature file: {e}")
            sys.exit(1)

    def choose_interface(self):
        """Automatically select the best network interface"""
        if self.config.interface:
            # Validate user-specified interface
            if self.config.interface not in get_if_list():
                raise RuntimeError(f"Interface '{self.config.interface}' not found")
            return self.config.interface
            
        # Auto-detect interface
        suitable_interfaces = []
        
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0" and ip.startswith(self.config.target_ip_prefix):
                    suitable_interfaces.append((iface, ip))
                    if self.config.verbose:
                        print(f"[DEBUG] Found suitable interface: {iface} ({ip})")
            except Exception:
                continue
                
        if not suitable_interfaces:
            raise RuntimeError(f"No suitable interface found with IP prefix '{self.config.target_ip_prefix}'")
            
        # Choose the first suitable interface
        chosen_iface, chosen_ip = suitable_interfaces[0]
        
        if len(suitable_interfaces) > 1:
            print(f"[INFO] Multiple interfaces found, using: {chosen_iface} ({chosen_ip})")
            
        return chosen_iface

    def log_alert(self, rule_id, description, packet_info, payload_snippet=""):
        """Log security alert to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Increment alert counter
        with self.stats_lock:
            self.config.alert_count += 1
            
        log_entry = {
            "timestamp": timestamp,
            "rule_id": rule_id,
            "description": description,
            "packet_info": packet_info,
            "payload_snippet": payload_snippet[:100] if payload_snippet else ""
        }
        
        # Format log message
        log_line = (
            f"[{timestamp}] ALERT #{self.config.alert_count}\n"
            f"  Rule ID: {rule_id}\n"
            f"  Description: {description}\n"
            f"  Packet: {packet_info}\n"
        )
        
        if payload_snippet:
            log_line += f"  Payload: {payload_snippet[:100]}...\n"
            
        log_line += "\n"

        # Write to file
        try:
            with open(self.config.log_file, "a", encoding="utf-8") as log_file:
                log_file.write(log_line)
        except Exception as e:
            print(f"[ERROR] Could not write to log file: {e}")

        # Print to console with color coding
        print(f"\033[91m{log_line.strip()}\033[0m")  # Red color for alerts

    def process_packet(self, pkt):
        """Process individual network packet"""
        # Increment packet counter
        with self.stats_lock:
            self.config.packet_count += 1

        # Only process TCP packets
        if not pkt.haslayer(TCP):
            return

        # Filter by target port if specified
        if self.config.target_port and pkt[TCP].dport != self.config.target_port:
            return

        # Extract payload
        try:
            if hasattr(pkt[TCP], 'payload') and pkt[TCP].payload:
                payload = raw(pkt[TCP].payload).decode(errors="ignore").lower()
            else:
                return
        except Exception:
            return

        # Get packet information
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "Unknown"
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        
        packet_info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port}"

        # Check against all signatures
        for rule in self.config.signatures:
            pattern = rule.get("payload_pattern", "").lower()
            if pattern and pattern in payload:
                rule_id = rule.get("id", "UNKNOWN")
                description = rule.get("description", "No Description")
                
                # Log the alert
                self.log_alert(rule_id, description, packet_info, payload)
                
                if self.config.verbose:
                    print(f"[DEBUG] Pattern '{pattern}' matched in packet from {src_ip}")
                
                # Only trigger first matching rule per packet
                break

    def print_statistics(self):
        """Print running statistics"""
        if self.config.start_time:
            runtime = time.time() - self.config.start_time
            pps = self.config.packet_count / runtime if runtime > 0 else 0
            
            print(f"\n[STATS] Runtime: {runtime:.1f}s | "
                  f"Packets: {self.config.packet_count} ({pps:.1f}/s) | "
                  f"Alerts: {self.config.alert_count}")

    def signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        print(f"\n[INFO] Received signal {signum}, shutting down...")
        self.running = False
        self.print_statistics()
        sys.exit(0)

    def run(self):
        """Main execution method"""
        print(f"[INFO] Starting Real-time IDS...")
        print(f"[INFO] Signature file: {self.config.signature_file}")
        print(f"[INFO] Log file: {self.config.log_file}")
        print(f"[INFO] Target port: {self.config.target_port if self.config.target_port else 'Any'}")
        
        # Load signatures
        self.load_signatures()
        
        # Choose interface
        try:
            interface = self.choose_interface()
            print(f"[INFO] Monitoring interface: {interface} ({get_if_addr(interface)})")
        except Exception as e:
            print(f"[ERROR] {e}")
            sys.exit(1)

        # Set up signal handlers
        signal.signal(signal.SIGINT, self.signal_handler)
        signal.signal(signal.SIGTERM, self.signal_handler)

        # Initialize log file
        try:
            with open(self.config.log_file, "a", encoding="utf-8") as log_file:
                log_file.write(f"\n{'='*60}\n")
                log_file.write(f"IDS Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"Interface: {interface}\n")
                log_file.write(f"Signatures: {len(self.config.signatures)}\n")
                log_file.write(f"{'='*60}\n\n")
        except Exception as e:
            print(f"[ERROR] Could not initialize log file: {e}")
            sys.exit(1)

        # Start packet capture
        self.running = True
        self.config.start_time = time.time()
        
        # Build capture filter
        capture_filter = self.config.capture_filter
        if self.config.target_port:
            capture_filter += f" and port {self.config.target_port}"

        print(f"[INFO] Starting packet capture with filter: '{capture_filter}'")
        print("[INFO] Press Ctrl+C to stop\n")

        try:
            # Start statistics thread
            stats_thread = threading.Timer(10.0, self._periodic_stats)
            stats_thread.daemon = True
            stats_thread.start()
            
            # Start packet sniffing
            sniff(
                iface=interface,
                filter=capture_filter,
                prn=self.process_packet,
                store=False,
                stop_filter=lambda x: not self.running
            )
            
        except Exception as e:
            print(f"[ERROR] Packet capture failed: {e}")
            sys.exit(1)

    def _periodic_stats(self):
        """Print periodic statistics"""
        if self.running:
            self.print_statistics()
            # Schedule next stats print
            stats_thread = threading.Timer(10.0, self._periodic_stats)
            stats_thread.daemon = True
            stats_thread.start()

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Real-time Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 ids.py                                    # Use default settings
  python3 ids.py -p 80 -i eth0                     # Monitor port 80 on eth0
  python3 ids.py -s custom_rules.json -v           # Use custom rules with verbose output
  python3 ids.py --target-prefix "10.0." -p 8080   # Monitor 10.0.x.x network, port 8080
        """
    )
    
    parser.add_argument("-s", "--signatures", default=DEFAULT_SIGNATURE_FILE,
                       help=f"Signature file path (default: {DEFAULT_SIGNATURE_FILE})")
    parser.add_argument("-p", "--port", type=int, default=DEFAULT_TARGET_PORT,
                       help=f"Target port to monitor (default: {DEFAULT_TARGET_PORT}, 0 for all ports)")
    parser.add_argument("-i", "--interface", help="Network interface to monitor (auto-detect if not specified)")
    parser.add_argument("-l", "--log", default=DEFAULT_LOG_FILE,
                       help=f"Log file path (default: {DEFAULT_LOG_FILE})")
    parser.add_argument("--target-prefix", default=DEFAULT_TARGET_IP_PREFIX,
                       help=f"Target IP prefix for interface selection (default: {DEFAULT_TARGET_IP_PREFIX})")
    parser.add_argument("-v", "--verbose", action="store_true",
                       help="Enable verbose output")
    parser.add_argument("--filter", default=DEFAULT_CAPTURE_FILTER,
                       help=f"Custom packet capture filter (default: {DEFAULT_CAPTURE_FILTER})")
    
    return parser.parse_args()

def main():
    """Main entry point"""
    args = parse_arguments()
    
    # Create configuration
    config = IDSConfig()
    config.signature_file = args.signatures
    config.target_port = args.port if args.port != 0 else None
    config.interface = args.interface
    config.log_file = args.log
    config.target_ip_prefix = args.target_prefix
    config.verbose = args.verbose
    config.capture_filter = args.filter
    
    # Create and run IDS
    ids = NetworkIDS(config)
    ids.run()

if __name__ == "__main__":
    main()