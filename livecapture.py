"""
Enhanced Real-time Intrusion Detection System (IDS) Network Sniffer
Monitors network traffic for malicious patterns and basic anomalies.

Usage:
    python enhanced_ids.py [options]
    
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
from scapy.all import get_if_list, get_if_addr, sniff, raw, TCP, IP, UDP, ICMP
from datetime import datetime, timedelta
import threading
import time
from collections import defaultdict, deque
import hashlib

# Configuration constants
DEFAULT_TARGET_IP_PREFIX = "192.168."
DEFAULT_SIGNATURE_FILE = "signature.json"
DEFAULT_TARGET_PORT = 12345
DEFAULT_LOG_FILE = "alerts.log"
DEFAULT_CAPTURE_FILTER = "tcp or udp or icmp"

class TrafficProfile:
    """Simple traffic profiling for anomaly detection"""
    def __init__(self, window_size=300):  # 5-minute window
        self.window_size = window_size
        self.connection_counts = defaultdict(int)
        self.port_access = defaultdict(int)
        self.packet_sizes = deque(maxlen=1000)
        self.connection_timestamps = deque(maxlen=1000)
        self.failed_connections = defaultdict(int)
        self.last_cleanup = time.time()
        
    def update(self, src_ip, dst_ip, dst_port, packet_size, is_failed_conn=False):
        """Update traffic profile with new packet data"""
        current_time = time.time()
        
        # Clean old data every minute
        if current_time - self.last_cleanup > 60:
            self._cleanup_old_data(current_time)
            self.last_cleanup = current_time
            
        # Update counters
        conn_key = f"{src_ip}->{dst_ip}"
        self.connection_counts[conn_key] += 1
        self.port_access[dst_port] += 1
        self.packet_sizes.append(packet_size)
        self.connection_timestamps.append(current_time)
        
        if is_failed_conn:
            self.failed_connections[src_ip] += 1
    
    def _cleanup_old_data(self, current_time):
        """Remove data older than window_size"""
        cutoff_time = current_time - self.window_size
        
        # Clean timestamps and corresponding data
        while self.connection_timestamps and self.connection_timestamps[0] < cutoff_time:
            self.connection_timestamps.popleft()
            if self.packet_sizes:
                self.packet_sizes.popleft()
    
    def detect_anomalies(self, src_ip, dst_ip, dst_port, packet_size):
        """Detect basic anomalies in traffic patterns"""
        anomalies = []
        
        # 1. Port scanning detection (high number of unique ports from same source)
        source_ports = [port for (src, port) in [(k.split('->')[0], p) for k in self.connection_counts.keys() for p in self.port_access.keys()] if src == src_ip]
        unique_ports = len(set(source_ports))
        if unique_ports > 20:  # Threshold for port scanning
            anomalies.append(f"Potential port scan from {src_ip} (accessing {unique_ports} ports)")
        
        # 2. Connection flooding (too many connections from same source)
        source_connections = sum(1 for k in self.connection_counts.keys() if k.startswith(src_ip))
        if source_connections > 100:  # Threshold for connection flooding
            anomalies.append(f"Connection flooding from {src_ip} ({source_connections} connections)")
        
        # 3. Unusual packet size
        if self.packet_sizes:
            avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
            if packet_size > avg_size * 3 and packet_size > 1000:  # 3x larger than average
                anomalies.append(f"Unusually large packet ({packet_size} bytes vs avg {avg_size:.0f})")
        
        # 4. Failed connection attempts
        if self.failed_connections.get(src_ip, 0) > 50:
            anomalies.append(f"High failed connection rate from {src_ip} ({self.failed_connections[src_ip]} failures)")
            
        return anomalies

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
        self.enable_anomaly_detection = True
        self.signatures = []
        self.packet_count = 0
        self.alert_count = 0
        self.anomaly_count = 0
        self.start_time = None

class NetworkIDS:
    """Enhanced Real-time Network Intrusion Detection System"""
    
    def __init__(self, config):
        self.config = config
        self.running = False
        self.stats_lock = threading.Lock()
        self.traffic_profile = TrafficProfile()
        self.recent_alerts = set()  # Prevent duplicate alerts
        
    def load_signatures(self):
        """Load signature rules from JSON file"""
        try:
            signature_path = Path(self.config.signature_file)
            if not signature_path.exists():
                # Create a basic signature file if it doesn't exist
                self._create_default_signatures(signature_path)
                
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

    def _create_default_signatures(self, signature_path):
        """Create a default signature file with common attack patterns"""
        default_signatures = [
            {
                "id": "SQL_INJECTION_1",
                "description": "SQL Injection attempt detected",
                "payload_pattern": "union select",
                "severity": "high"
            },
            {
                "id": "SQL_INJECTION_2", 
                "description": "SQL Injection attempt detected",
                "payload_pattern": "' or 1=1",
                "severity": "high"
            },
            {
                "id": "XSS_ATTEMPT",
                "description": "Cross-site scripting attempt",
                "payload_pattern": "<script>",
                "severity": "medium"
            },
            {
                "id": "CMD_INJECTION",
                "description": "Command injection attempt",
                "payload_pattern": "; cat /etc/passwd",
                "severity": "high"
            },
            {
                "id": "SUSPICIOUS_USER_AGENT",
                "description": "Suspicious user agent string",
                "payload_pattern": "sqlmap",
                "severity": "medium"
            }
        ]
        
        with open(signature_path, "w", encoding="utf-8") as f:
            json.dump(default_signatures, f, indent=2)
        print(f"[INFO] Created default signature file: {signature_path}")

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

    def log_alert(self, alert_type, rule_id, description, packet_info, payload_snippet="", severity="medium"):
        """Log security alert to file and console"""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Generate alert hash to prevent duplicates
        alert_hash = hashlib.md5(f"{rule_id}{packet_info}{description}".encode()).hexdigest()[:8]
        
        # Skip if we've seen this alert recently (within 30 seconds)
        current_time = time.time()
        recent_key = f"{alert_hash}_{int(current_time // 30)}"
        if recent_key in self.recent_alerts:
            return
        self.recent_alerts.add(recent_key)
        
        # Clean old alert hashes
        if len(self.recent_alerts) > 1000:
            self.recent_alerts.clear()
        
        # Increment appropriate counter
        with self.stats_lock:
            if alert_type == "signature":
                self.config.alert_count += 1
                alert_num = self.config.alert_count
            else:
                self.config.anomaly_count += 1
                alert_num = self.config.anomaly_count
            
        log_entry = {
            "timestamp": timestamp,
            "type": alert_type,
            "rule_id": rule_id,
            "description": description,
            "packet_info": packet_info,
            "payload_snippet": payload_snippet[:100] if payload_snippet else "",
            "severity": severity,
            "alert_hash": alert_hash
        }
        
        # Format log message with color coding
        if alert_type == "signature":
            color_code = "\033[91m"  # Red for signature alerts
            type_label = "SIGNATURE ALERT"
        else:
            color_code = "\033[93m"  # Yellow for anomaly alerts
            type_label = "ANOMALY ALERT"
        
        log_line = (
            f"[{timestamp}] {type_label} #{alert_num}\n"
            f"  Rule ID: {rule_id}\n"
            f"  Severity: {severity.upper()}\n"
            f"  Description: {description}\n"
            f"  Packet: {packet_info}\n"
        )
        
        if payload_snippet:
            log_line += f"  Payload: {payload_snippet[:100]}...\n"
            
        log_line += f"  Hash: {alert_hash}\n\n"

        # Write to file
        try:
            with open(self.config.log_file, "a", encoding="utf-8") as log_file:
                log_file.write(log_line)
        except Exception as e:
            print(f"[ERROR] Could not write to log file: {e}")

        # Print to console with color
        print(f"{color_code}{log_line.strip()}\033[0m")

    def process_packet(self, pkt):
        """Process individual network packet"""
        # Increment packet counter
        with self.stats_lock:
            self.config.packet_count += 1

        # Get basic packet info
        src_ip = pkt[IP].src if pkt.haslayer(IP) else "Unknown"
        dst_ip = pkt[IP].dst if pkt.haslayer(IP) else "Unknown"
        packet_size = len(pkt)
        
        # Process different protocol types
        if pkt.haslayer(TCP):
            self._process_tcp_packet(pkt, src_ip, dst_ip, packet_size)
        elif pkt.haslayer(UDP):
            self._process_udp_packet(pkt, src_ip, dst_ip, packet_size)
        elif pkt.haslayer(ICMP):
            self._process_icmp_packet(pkt, src_ip, dst_ip, packet_size)

    def _process_tcp_packet(self, pkt, src_ip, dst_ip, packet_size):
        """Process TCP packets"""
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        
        # Filter by target port if specified
        if self.config.target_port and dst_port != self.config.target_port:
            return
            
        packet_info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} (TCP)"
        
        # Check for failed connections (RST or certain flags)
        is_failed_conn = bool(pkt[TCP].flags & 0x04)  # RST flag
        
        # Update traffic profile
        if self.config.enable_anomaly_detection:
            self.traffic_profile.update(src_ip, dst_ip, dst_port, packet_size, is_failed_conn)
            
            # Check for anomalies
            anomalies = self.traffic_profile.detect_anomalies(src_ip, dst_ip, dst_port, packet_size)
            for anomaly in anomalies:
                self.log_alert("anomaly", "TRAFFIC_ANOMALY", anomaly, packet_info, severity="medium")

        # Extract and check payload against signatures
        try:
            if hasattr(pkt[TCP], 'payload') and pkt[TCP].payload:
                payload = raw(pkt[TCP].payload).decode(errors="ignore").lower()
                self._check_signatures(payload, packet_info)
        except Exception:
            pass

    def _process_udp_packet(self, pkt, src_ip, dst_ip, packet_size):
        """Process UDP packets"""
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
        packet_info = f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} (UDP)"
        
        # Update traffic profile for anomaly detection
        if self.config.enable_anomaly_detection:
            self.traffic_profile.update(src_ip, dst_ip, dst_port, packet_size)

    def _process_icmp_packet(self, pkt, src_ip, dst_ip, packet_size):
        """Process ICMP packets"""
        packet_info = f"{src_ip} -> {dst_ip} (ICMP)"
        
        # Check for ICMP flood (basic detection)
        if self.config.enable_anomaly_detection:
            # Simple ICMP flood detection could be added here
            pass

    def _check_signatures(self, payload, packet_info):
        """Check payload against signature database"""
        for rule in self.config.signatures:
            pattern = rule.get("payload_pattern", "").lower()
            if pattern and pattern in payload:
                rule_id = rule.get("id", "UNKNOWN")
                description = rule.get("description", "No Description")
                severity = rule.get("severity", "medium")
                
                # Log the signature-based alert
                self.log_alert("signature", rule_id, description, packet_info, payload, severity)
                
                if self.config.verbose:
                    print(f"[DEBUG] Pattern '{pattern}' matched in packet")
                
                # Only trigger first matching rule per packet
                break

    def print_statistics(self):
        """Print running statistics"""
        if self.config.start_time:
            runtime = time.time() - self.config.start_time
            pps = self.config.packet_count / runtime if runtime > 0 else 0
            
            print(f"\n[STATS] Runtime: {runtime:.1f}s | "
                  f"Packets: {self.config.packet_count} ({pps:.1f}/s) | "
                  f"Signature Alerts: {self.config.alert_count} | "
                  f"Anomaly Alerts: {self.config.anomaly_count}")

    def signal_handler(self, signum, frame):
        """Handle interrupt signals gracefully"""
        print(f"\n[INFO] Received signal {signum}, shutting down...")
        self.running = False
        self.print_statistics()
        sys.exit(0)

    def run(self):
        """Main execution method"""
        print(f"[INFO] Starting Enhanced Real-time IDS...")
        print(f"[INFO] Signature file: {self.config.signature_file}")
        print(f"[INFO] Log file: {self.config.log_file}")
        print(f"[INFO] Target port: {self.config.target_port if self.config.target_port else 'Any'}")
        print(f"[INFO] Anomaly detection: {'Enabled' if self.config.enable_anomaly_detection else 'Disabled'}")
        
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
                log_file.write(f"Enhanced IDS Session Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                log_file.write(f"Interface: {interface}\n")
                log_file.write(f"Signatures: {len(self.config.signatures)}\n")
                log_file.write(f"Anomaly Detection: {'Enabled' if self.config.enable_anomaly_detection else 'Disabled'}\n")
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
        description="Enhanced Real-time Network Intrusion Detection System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 enhanced_ids.py                               # Use default settings
  python3 enhanced_ids.py -p 80 -i eth0                # Monitor port 80 on eth0
  python3 enhanced_ids.py -s custom_rules.json -v      # Use custom rules with verbose output
  python3 enhanced_ids.py --no-anomaly -p 8080         # Disable anomaly detection
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
    parser.add_argument("--no-anomaly", action="store_true",
                       help="Disable anomaly detection")
    
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
    config.enable_anomaly_detection = not args.no_anomaly
    
    # Create and run IDS
    ids = NetworkIDS(config)
    ids.run()

if __name__ == "__main__":
    main()