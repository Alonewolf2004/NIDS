"""
Enhanced Real-time Intrusion Detection System (IDS) - Foundation for AI Integration
FIXED VERSION - Now properly loads signatures.json and reduced false positives

Key Fixes:
- Actually loads and uses signatures.json file
- Much higher thresholds for anomaly detection (reduced false positives)
- Better normal traffic filtering
- Improved logging for debugging
"""

import json
import sys
import signal
import argparse
import os
import subprocess
from pathlib import Path
from scapy.all import get_if_list, get_if_addr, sniff, raw, TCP, IP, UDP, ICMP
from datetime import datetime, timedelta
import threading
import time
from collections import defaultdict, deque
import hashlib
import sqlite3

# Configuration constants
DEFAULT_TARGET_IP_PREFIX = "192.168."
DEFAULT_SIGNATURE_FILE = "signatures.json"
DEFAULT_DB_FILE = "ids_database.db"
DEFAULT_TARGET_PORT = None
DEFAULT_LOG_FILE = "alerts.log"
DEFAULT_CAPTURE_FILTER = "tcp or udp or icmp"
DEFAULT_BLOCK_DURATION = 300  # 5 minutes default block duration

class ThreatDatabase:
    """Database for storing threats, signatures, and analysis data"""
    
    def __init__(self, db_file=DEFAULT_DB_FILE, signature_file=DEFAULT_SIGNATURE_FILE):
        self.db_file = db_file
        self.signature_file = signature_file
        self.init_database()
    
    def init_database(self):
        """Initialize SQLite database with required tables"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            # Signatures table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT UNIQUE,
                    pattern TEXT,
                    description TEXT,
                    severity TEXT,
                    auto_generated BOOLEAN DEFAULT 0,
                    created_timestamp REAL,
                    last_seen REAL,
                    hit_count INTEGER DEFAULT 0
                )
            ''')
            
            # Threat events table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    threat_type TEXT,
                    signature_match TEXT,
                    blocked BOOLEAN,
                    payload_hash TEXT,
                    packet_info TEXT,
                    severity TEXT,
                    
                    -- Fields ready for AI integration
                    ai_probability REAL DEFAULT 0.0,
                    ai_features TEXT,
                    ai_model_version TEXT,
                    manual_verification TEXT
                )
            ''')
            
            # Blocked IPs table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS blocked_ips (
                    ip TEXT PRIMARY KEY,
                    block_timestamp REAL,
                    unblock_timestamp REAL,
                    reason TEXT,
                    active BOOLEAN DEFAULT 1,
                    auto_generated BOOLEAN DEFAULT 0
                )
            ''')
            
            # Network features table (ready for AI training data)
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS network_features (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    source_ip TEXT,
                    dest_ip TEXT,
                    dest_port INTEGER,
                    packet_size INTEGER,
                    connection_rate REAL,
                    unique_ports INTEGER,
                    failed_connection_rate REAL,
                    avg_packet_interval REAL,
                    protocol_diversity INTEGER,
                    unusual_port_ratio REAL,
                    payload_entropy REAL,
                    
                    -- Label for supervised learning (will be set by AI model or manual review)
                    is_threat BOOLEAN DEFAULT NULL,
                    threat_confidence REAL DEFAULT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            print(f"[INFO] Database initialized: {self.db_file}")
            
        except Exception as e:
            print(f"[ERROR] Database initialization failed: {e}")
    
    def load_signatures_from_json(self):
        """Load signatures from JSON file into database - FIXED TO ACTUALLY RUN"""
        try:
            if os.path.exists(self.signature_file):
                with open(self.signature_file, 'r') as f:
                    data = json.load(f)
                    
                signatures_loaded = 0
                for sig in data.get('signatures', []):
                    self.add_signature(
                        sig.get('id', ''),
                        sig.get('payload_pattern', ''),
                        sig.get('description', ''),
                        sig.get('severity', 'medium')
                    )
                    signatures_loaded += 1
                
                print(f"[INFO] Loaded {signatures_loaded} signatures from {self.signature_file}")
                return signatures_loaded
            else:
                print(f"[WARNING] Signature file {self.signature_file} not found")
                return 0
                    
        except Exception as e:
            print(f"[ERROR] Could not load signatures from JSON: {e}")
            return 0
    
    def add_signature(self, rule_id, pattern, description, severity="medium", auto_generated=False):
        """Add new signature to database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO signatures 
                (rule_id, pattern, description, severity, auto_generated, created_timestamp, last_seen, hit_count)
                VALUES (?, ?, ?, ?, ?, ?, ?, COALESCE((SELECT hit_count FROM signatures WHERE rule_id = ?), 0))
            ''', (rule_id, pattern, description, severity, auto_generated, time.time(), time.time(), rule_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[ERROR] Could not add signature: {e}")
    
    def update_signature_hit(self, rule_id):
        """Update signature hit count and last seen time"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                UPDATE signatures 
                SET hit_count = hit_count + 1, last_seen = ?
                WHERE rule_id = ?
            ''', (time.time(), rule_id))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[ERROR] Could not update signature hit: {e}")
    
    def get_signatures(self):
        """Get all active signatures"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT rule_id, pattern, description, severity, auto_generated 
                FROM signatures ORDER BY created_timestamp DESC
            ''')
            
            signatures = []
            for row in cursor.fetchall():
                signatures.append({
                    'id': row[0],
                    'payload_pattern': row[1],
                    'description': row[2],
                    'severity': row[3],
                    'auto_generated': bool(row[4])
                })
            
            conn.close()
            return signatures
            
        except Exception as e:
            print(f"[ERROR] Could not load signatures: {e}")
            return []
    
    def log_threat_event(self, event_data):
        """Log threat event to database"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO threat_events 
                (timestamp, source_ip, dest_ip, dest_port, threat_type, signature_match, 
                 blocked, payload_hash, packet_info, severity, ai_probability, ai_features)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                event_data.get('timestamp', time.time()),
                event_data.get('source_ip'),
                event_data.get('dest_ip'),
                event_data.get('dest_port'),
                event_data.get('threat_type', 'signature'),
                event_data.get('signature_match'),
                event_data.get('blocked', False),
                event_data.get('payload_hash'),
                event_data.get('packet_info', ''),
                event_data.get('severity', 'medium'),
                event_data.get('ai_probability', 0.0),
                json.dumps(event_data.get('ai_features', {}))
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[ERROR] Could not log threat event: {e}")
    
    def store_network_features(self, feature_data):
        """Store network features for AI training/analysis"""
        try:
            conn = sqlite3.connect(self.db_file)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO network_features 
                (timestamp, source_ip, dest_ip, dest_port, packet_size, connection_rate,
                 unique_ports, failed_connection_rate, avg_packet_interval, 
                 protocol_diversity, unusual_port_ratio, payload_entropy)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                time.time(),
                feature_data.get('source_ip'),
                feature_data.get('dest_ip'),
                feature_data.get('dest_port'),
                feature_data.get('packet_size', 0),
                feature_data.get('connection_rate', 0.0),
                feature_data.get('unique_ports', 0),
                feature_data.get('failed_connection_rate', 0.0),
                feature_data.get('avg_packet_interval', 0.0),
                feature_data.get('protocol_diversity', 0),
                feature_data.get('unusual_port_ratio', 0.0),
                feature_data.get('payload_entropy', 0.0)
            ))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            print(f"[ERROR] Could not store network features: {e}")

class NetworkBlocker:
    """Handle network blocking and unblocking operations"""
    
    def __init__(self, config, threat_db):
        self.config = config
        self.threat_db = threat_db
        self.blocked_ips = set()
        self.block_expiry = {}
        self.block_lock = threading.Lock()
        
        # Load existing blocks from database
        self._load_existing_blocks()
        
        # Start cleanup thread
        self.cleanup_thread = threading.Thread(target=self._cleanup_expired_blocks, daemon=True)
        self.cleanup_thread.start()
    
    def _load_existing_blocks(self):
        """Load existing active blocks from database"""
        try:
            conn = sqlite3.connect(self.threat_db.db_file)
            cursor = conn.cursor()
            
            current_time = time.time()
            cursor.execute('''
                SELECT ip, unblock_timestamp FROM blocked_ips 
                WHERE active = 1 AND unblock_timestamp > ?
            ''', (current_time,))
            
            for ip, unblock_time in cursor.fetchall():
                self.blocked_ips.add(ip)
                self.block_expiry[ip] = unblock_time
            
            conn.close()
            
            if self.blocked_ips:
                print(f"[INFO] Loaded {len(self.blocked_ips)} existing blocks from database")
                
        except Exception as e:
            print(f"[ERROR] Could not load existing blocks: {e}")
    
    def block_ip(self, ip_address, duration=DEFAULT_BLOCK_DURATION, reason="Threat detected", auto_generated=False):
        """Block IP address using iptables"""
        if not ip_address or ip_address in self.blocked_ips:
            return False
        
        # Skip private/local addresses for safety
        if ip_address.startswith(('127.', '10.', '192.168.')) and not self.config.allow_local_blocking:
            print(f"[WARNING] Skipping block of local/private IP: {ip_address}")
            return False
            
        try:
            with self.block_lock:
                # Add iptables rule
                cmd = ["iptables", "-I", "INPUT", "-s", ip_address, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.add(ip_address)
                    unblock_time = time.time() + duration
                    self.block_expiry[ip_address] = unblock_time
                    
                    # Update database
                    conn = sqlite3.connect(self.threat_db.db_file)
                    cursor = conn.cursor()
                    cursor.execute('''
                        INSERT OR REPLACE INTO blocked_ips
                        (ip, block_timestamp, unblock_timestamp, reason, active, auto_generated)
                        VALUES (?, ?, ?, ?, 1, ?)
                    ''', (ip_address, time.time(), unblock_time, reason, auto_generated))
                    conn.commit()
                    conn.close()
                    
                    print(f"[BLOCK] Blocked {ip_address} for {duration}s - {reason}")
                    return True
                else:
                    print(f"[ERROR] Failed to block {ip_address}: {result.stderr}")
                    return False
                    
        except Exception as e:
            print(f"[ERROR] Block operation failed: {e}")
            return False
    
    def unblock_ip(self, ip_address):
        """Unblock IP address"""
        if ip_address not in self.blocked_ips:
            return False
            
        try:
            with self.block_lock:
                # Remove iptables rule
                cmd = ["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"]
                result = subprocess.run(cmd, capture_output=True, text=True)
                
                if result.returncode == 0:
                    self.blocked_ips.discard(ip_address)
                    self.block_expiry.pop(ip_address, None)
                    
                    # Update database
                    conn = sqlite3.connect(self.threat_db.db_file)
                    cursor = conn.cursor()
                    cursor.execute('''
                        UPDATE blocked_ips SET active = 0 WHERE ip = ?
                    ''', (ip_address,))
                    conn.commit()
                    conn.close()
                    
                    print(f"[UNBLOCK] Unblocked {ip_address}")
                    return True
                else:
                    print(f"[WARNING] Could not remove block for {ip_address}: {result.stderr}")
                    return False
                    
        except Exception as e:
            print(f"[ERROR] Unblock operation failed: {e}")
            return False
    
    def _cleanup_expired_blocks(self):
        """Periodically cleanup expired blocks"""
        while True:
            try:
                current_time = time.time()
                expired_ips = []
                
                with self.block_lock:
                    for ip, expiry_time in self.block_expiry.items():
                        if current_time >= expiry_time:
                            expired_ips.append(ip)
                
                for ip in expired_ips:
                    self.unblock_ip(ip)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                print(f"[ERROR] Block cleanup failed: {e}")
                time.sleep(60)

class EnhancedTrafficProfile:
    """Enhanced traffic profiling with MUCH HIGHER thresholds to reduce false positives"""
    
    def __init__(self, window_size=300):
        self.window_size = window_size
        self.connection_counts = defaultdict(int)
        self.port_access = defaultdict(set)  # Changed to set to track unique ports per IP
        self.packet_sizes = deque(maxlen=1000)
        self.connection_timestamps = deque(maxlen=1000)
        self.failed_connections = defaultdict(int)
        self.protocol_counts = defaultdict(int)
        self.packet_intervals = deque(maxlen=100)
        self.payload_entropies = deque(maxlen=100)
        self.last_packet_time = 0
        self.syn_flood_count = 0
        self.last_cleanup = time.time()
        
        # Track IPs we've seen to avoid false positives on normal browsing
        self.known_ips = set()
    
    def update(self, src_ip, dst_ip, dst_port, packet_size, protocol, tcp_flags=None, payload_entropy=0.0):
        """Update traffic profile with comprehensive packet data"""
        current_time = time.time()
        
        # Track known IPs
        self.known_ips.add(src_ip)
        
        # Calculate packet interval
        if self.last_packet_time > 0:
            interval = current_time - self.last_packet_time
            self.packet_intervals.append(interval)
        self.last_packet_time = current_time
        
        # Clean old data periodically
        if current_time - self.last_cleanup > 60:
            self._cleanup_old_data(current_time)
            self.last_cleanup = current_time
        
        # Update all counters
        conn_key = f"{src_ip}->{dst_ip}"
        self.connection_counts[conn_key] += 1
        self.port_access[src_ip].add(dst_port)  # Track unique ports per IP
        self.packet_sizes.append(packet_size)
        self.connection_timestamps.append(current_time)
        self.protocol_counts[protocol] += 1
        self.payload_entropies.append(payload_entropy)
        
        # Check for SYN flood
        if tcp_flags and tcp_flags & 0x02:  # SYN flag
            self.syn_flood_count += 1
        
        # Check for failed connections
        if tcp_flags and tcp_flags & 0x04:  # RST flag
            self.failed_connections[src_ip] += 1
    
    def calculate_payload_entropy(self, payload):
        """Calculate Shannon entropy of payload"""
        if not payload or len(payload) == 0:
            return 0.0
        
        try:
            # Count byte frequencies
            byte_counts = defaultdict(int)
            for byte in payload:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0.0
            payload_length = len(payload)
            
            for count in byte_counts.values():
                probability = count / payload_length
                if probability > 0:
                    entropy -= probability * (probability.bit_length() - 1)
            
            return entropy
            
        except Exception:
            return 0.0
    
    def get_network_features(self, src_ip, dst_ip, dst_port, packet_size):
        """Extract comprehensive network features for analysis"""
        current_time = time.time()
        
        # Basic connection metrics
        source_connections = sum(1 for k in self.connection_counts.keys() if k.startswith(src_ip))
        unique_ports = len(self.port_access.get(src_ip, set()))
        failed_rate = self.failed_connections.get(src_ip, 0) / max(source_connections, 1)
        
        # Protocol and timing statistics
        protocol_diversity = len(self.protocol_counts)
        avg_packet_size = sum(self.packet_sizes) / len(self.packet_sizes) if self.packet_sizes else 0
        avg_interval = sum(self.packet_intervals) / len(self.packet_intervals) if self.packet_intervals else 0
        avg_entropy = sum(self.payload_entropies) / len(self.payload_entropies) if self.payload_entropies else 0
        
        # Advanced metrics
        total_packets = sum(self.protocol_counts.values())
        syn_ratio = self.syn_flood_count / max(total_packets, 1)
        
        # Unusual port detection - only count truly unusual ports
        common_ports = {20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 110, 123, 137, 138, 139, 143, 161, 162, 179, 389, 443, 465, 514, 636, 993, 995, 1433, 1521, 3306, 3389, 5432, 8080, 8443}
        unusual_ports = sum(1 for port in self.port_access.get(src_ip, set()) if port not in common_ports and port > 1024)
        unusual_port_ratio = unusual_ports / max(unique_ports, 1)
        
        return {
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'dest_port': dst_port,
            'packet_size': packet_size,
            'connection_rate': source_connections / 60,  # per minute
            'unique_ports': unique_ports,
            'failed_connection_rate': failed_rate,
            'avg_packet_interval': avg_interval,
            'protocol_diversity': protocol_diversity,
            'unusual_port_ratio': unusual_port_ratio,
            'payload_entropy': avg_entropy,
            'syn_flood_ratio': syn_ratio,
            'avg_packet_size': avg_packet_size
        }
    
    def detect_basic_anomalies(self, src_ip, dst_ip, dst_port, packet_size):
        """IMPROVED anomaly detection with MUCH HIGHER thresholds to reduce false positives"""
        anomalies = []
        
        # Skip anomaly detection for very new IPs (let them establish baseline)
        if src_ip not in self.known_ips:
            return anomalies
            
        # MUCH HIGHER thresholds to reduce false positives
        
        # Port scanning detection - RAISED from 20 to 100+
        unique_ports = len(self.port_access.get(src_ip, set()))
        if unique_ports > 100:  # Much higher threshold
            # Additional check - must be in short time window
            recent_connections = sum(1 for k in self.connection_counts.keys() 
                                   if k.startswith(src_ip) and self.connection_counts[k] > 0)
            if recent_connections > 200:  # Must have many connections too
                anomalies.append(f"Potential port scan from {src_ip} (accessing {unique_ports} ports, {recent_connections} connections)")
        
        # Connection flooding - RAISED from 100 to 500+
        source_connections = sum(1 for k in self.connection_counts.keys() if k.startswith(src_ip))
        if source_connections > 500:  # Much higher threshold
            anomalies.append(f"Connection flooding from {src_ip} ({source_connections} connections)")
        
        # Unusual packet size - RAISED threshold significantly
        if self.packet_sizes:
            avg_size = sum(self.packet_sizes) / len(self.packet_sizes)
            # Only flag if packet is REALLY large and way above average
            if packet_size > 10000 and packet_size > avg_size * 10:  # Much higher thresholds
                anomalies.append(f"Unusually large packet ({packet_size} bytes vs avg {avg_size:.0f})")
        
        # Failed connection attempts - RAISED from 50 to 200+
        failed_count = self.failed_connections.get(src_ip, 0)
        if failed_count > 200:  # Much higher threshold
            # Additional check - high failure rate
            total_attempts = source_connections
            if total_attempts > 0 and (failed_count / total_attempts) > 0.8:  # 80% failure rate
                anomalies.append(f"High failed connection rate from {src_ip} ({failed_count} failures out of {total_attempts})")
        
        # SYN flood detection - much higher threshold
        if self.syn_flood_count > 1000:  # Very high threshold
            total_packets = sum(self.protocol_counts.values())
            syn_ratio = self.syn_flood_count / max(total_packets, 1)
            if syn_ratio > 0.7:  # 70% of packets are SYN
                anomalies.append(f"Potential SYN flood attack ({self.syn_flood_count} SYN packets, {syn_ratio:.2f} ratio)")
        
        return anomalies
    
    def _cleanup_old_data(self, current_time):
        """Remove data older than window_size"""
        cutoff_time = current_time - self.window_size
        
        while self.connection_timestamps and self.connection_timestamps[0] < cutoff_time:
            self.connection_timestamps.popleft()
            if self.packet_sizes:
                self.packet_sizes.popleft()

class EnhancedIDS:
    """Enhanced IDS with database storage and blocking - Ready for AI integration"""
    
    def __init__(self, config):
        self.config = config
        self.running = False
        self.stats_lock = threading.Lock()
        
        # Initialize components
        self.threat_db = ThreatDatabase(config.db_file, config.signature_file)
        self.network_blocker = NetworkBlocker(config, self.threat_db) if config.enable_blocking else None
        self.traffic_profile = EnhancedTrafficProfile()
        
        # FIXED: Actually load signatures from JSON file
        signatures_loaded = self.threat_db.load_signatures_from_json()
        
        # Load signatures from database
        self.signatures = self.threat_db.get_signatures()
        
        # Statistics
        self.packet_count = 0
        self.threat_count = 0
        self.blocked_count = 0
        self.signature_alerts = 0
        self.anomaly_alerts = 0
        
        print(f"[INFO] Loaded {len(self.signatures)} signatures total")
    
    def is_normal_traffic(self, src_ip, dst_ip, dst_port, payload):
        """Filter out clearly normal traffic to reduce false positives"""
        
        # Skip empty payloads or very small packets (likely protocol overhead)
        if not payload or len(payload) < 10:
            return True
            
        # Common web traffic patterns (HTTP/HTTPS)
        if dst_port in [80, 443, 8080, 8443]:
            payload_str = payload.decode(errors='ignore').lower()
            if any(normal in payload_str for normal in ['get /', 'post /', 'user-agent:', 'accept:', 'content-type:']):
                return True
        
        # DNS traffic
        if dst_port == 53:
            return True
            
        # Other common service ports
        if dst_port in [21, 22, 25, 110, 143, 993, 995]:
            return True
            
        return False
    
    def process_packet(self, pkt):
        """Enhanced packet processing with feature extraction"""
        with self.stats_lock:
            self.packet_count += 1
        
        # Extract packet information
        if not pkt.haslayer(IP):
            return
            
        src_ip = pkt[IP].src
        dst_ip = pkt[IP].dst
        packet_size = len(pkt)
        protocol = "ICMP"
        dst_port = 0
        tcp_flags = None
        payload = b""
        payload_entropy = 0.0
        
        if pkt.haslayer(TCP):
            protocol = "TCP"
            dst_port = pkt[TCP].dport
            tcp_flags = pkt[TCP].flags
            if hasattr(pkt[TCP], 'payload') and pkt[TCP].payload:
                payload = raw(pkt[TCP].payload)
                payload_entropy = self.traffic_profile.calculate_payload_entropy(payload)
                
        elif pkt.haslayer(UDP):
            protocol = "UDP"
            dst_port = pkt[UDP].dport
            if hasattr(pkt[UDP], 'payload') and pkt[UDP].payload:
                payload = raw(pkt[UDP].payload)
                payload_entropy = self.traffic_profile.calculate_payload_entropy(payload)
        
        # Skip clearly normal traffic early to reduce processing
        if self.is_normal_traffic(src_ip, dst_ip, dst_port, payload):
            return
        
        # Update traffic profile
        self.traffic_profile.update(src_ip, dst_ip, dst_port, packet_size, protocol, tcp_flags, payload_entropy)
        
        # Extract network features (ready for AI model)
        network_features = self.traffic_profile.get_network_features(src_ip, dst_ip, dst_port, packet_size)
        
        # Store features in database for AI training/analysis (less frequently to reduce DB load)
        if self.packet_count % 50 == 0:  # Store every 50th packet instead of 10th
            self.threat_db.store_network_features(network_features)
        
        # Step 1: Check against signature database
        signature_match = self._check_signatures(payload, src_ip, dst_ip, dst_port)
        
        if signature_match:
            self._handle_signature_detection(signature_match, src_ip, dst_ip, dst_port, payload, network_features)
            return
        
        # Step 2: Basic anomaly detection (only if significant payload or suspicious behavior)
        if len(payload) > 100 or dst_port in [22, 23, 3389]:  # Only check anomalies for substantial payloads or sensitive ports
            anomalies = self.traffic_profile.detect_basic_anomalies(src_ip, dst_ip, dst_port, packet_size)
            
            if anomalies:
                self._handle_anomaly_detection(anomalies, src_ip, dst_ip, dst_port, network_features)
        
        # TODO: Step 3: Your AI model integration goes here
        # ai_result = your_ai_model.predict(network_features)
        # if ai_result['is_threat']:
        #     self._handle_ai_detection(ai_result, src_ip, dst_ip, dst_port, payload, network_features)
    
    def _check_signatures(self, payload, src_ip, dst_ip, dst_port):
        """Check payload against signature database"""
        try:
            payload_str = payload.decode(errors='ignore').lower()
            
            for signature in self.signatures:
                pattern = signature.get('payload_pattern', '').lower()
                if pattern and pattern in payload_str:
                    # Update hit count in database
                    self.threat_db.update_signature_hit(signature['id'])
                    return signature
                    
        except Exception:
            pass
        
        return None
    
    def _handle_signature_detection(self, signature, src_ip, dst_ip, dst_port, payload, network_features):
        """Handle signature-based threat detection"""
        rule_id = signature.get('id', 'UNKNOWN')
        severity = signature.get('severity', 'medium')
        description = signature.get('description', 'Signature match')
        
        with self.stats_lock:
            self.threat_count += 1
            self.signature_alerts += 1
        
        packet_info = f"{src_ip} -> {dst_ip}:{dst_port}"
        
        print(f"[SIGNATURE ALERT] {rule_id} - {severity.upper()} - {src_ip}")
        print(f"  Description: {description}")
        print(f"  Packet: {packet_info}")
        
        # Block if high severity or critical
        blocked = False
        if severity in ['high', 'critical'] and self.network_blocker:
            blocked = self.network_blocker.block_ip(src_ip, reason=f"Signature match: {rule_id}")
            if blocked:
                self.blocked_count += 1
        
        # Log to database
        self.threat_db.log_threat_event({
            'source_ip': src_ip,
            'dest_ip': dst_ip,
            'dest_port': dst_port,
            'threat_type': 'signature',
            'signature_match': rule_id,
            'blocked': blocked,
            'payload_hash': hashlib.md5(payload).hexdigest() if payload else None,
            'packet_info': packet_info,
            'severity': severity,
            'ai_features': network_features
        })
    
    def _handle_anomaly_detection(self, anomalies, src_ip, dst_ip, dst_port, network_features):
        """Handle basic anomaly detection (rule-based)"""
        with self.stats_lock:
            self.anomaly_alerts += 1
        
        for anomaly in anomalies:
            print(f"[ANOMALY ALERT] {anomaly}")
            
            # Log anomaly
            self.threat_db.log_threat_event({
                'source_ip': src_ip,
                'dest_ip': dst_ip,
                'dest_port': dst_port,
                'threat_type': 'anomaly',
                'signature_match': 'TRAFFIC_ANOMALY',
                'blocked': False,
                'packet_info': f"{src_ip} -> {dst_ip}:{dst_port}",
                'severity': 'medium',
                'ai_features': network_features
            })
    
    # TODO: Method ready for your AI model integration
    def integrate_ai_model(self, ai_model):
        """
        Method to integrate your trained AI model
        
        Args:
            ai_model: Your trained AI model object with predict() method
        
        Usage:
            ids.integrate_ai_model(your_trained_model)
        """
        self.ai_model = ai_model
        print("[INFO] AI model integrated successfully")
        
        # You can then call this in process_packet():
        # ai_prediction = self.ai_model.predict(network_features)
    
    def add_signature_from_ai(self, pattern, description, severity="high"):
        """Add new signature generated from AI detection"""
        rule_id = f"AI_GEN_{int(time.time())}"
        self.threat_db.add_signature(rule_id, pattern, description, severity, auto_generated=True)
        
        # Reload signatures to include the new one
        self.signatures = self.threat_db.get_signatures()
        print(f"[INFO] Added AI-generated signature: {rule_id}")
        
        return rule_id
    
    def print_statistics(self):
        """Print comprehensive statistics"""
        with self.stats_lock:
            runtime = time.time() - self.config.start_time if self.config.start_time else 0
            pps = self.packet_count / runtime if runtime > 0 else 0
            
            print(f"\n[STATS] Runtime: {runtime:.1f}s | "
                  f"Packets: {self.packet_count} ({pps:.1f}/s)")
            print(f"        Signature Alerts: {self.signature_alerts} | "
                  f"Anomaly Alerts: {self.anomaly_alerts} | "
                  f"Total Threats: {self.threat_count}")
            if self.network_blocker:
                print(f"        Blocked IPs: {self.blocked_count} | "
                      f"Active Blocks: {len(self.network_blocker.blocked_ips)}")
            print(f"        Signatures: {len(self.signatures)} | "
                  f"Database: {self.threat_db.db_file}")

class EnhancedIDSConfig:
    """Configuration class for Enhanced IDS"""
    def __init__(self):
        self.target_ip_prefix = DEFAULT_TARGET_IP_PREFIX
        self.signature_file = DEFAULT_SIGNATURE_FILE
        self.db_file = DEFAULT_DB_FILE
        self.target_port = DEFAULT_TARGET_PORT
        self.log_file = DEFAULT_LOG_FILE
        self.capture_filter = DEFAULT_CAPTURE_FILTER
        self.interface = None
        self.verbose = False
        self.enable_blocking = False  # Safety feature - disabled by default
        self.allow_local_blocking = False  # Extra safety for local IPs
        self.block_duration = DEFAULT_BLOCK_DURATION
        self.start_time = None
        self.store_features_interval = 50  # Store every 50th packet instead of 10th

def choose_interface(config):
    """Choose appropriate network interface"""
    if config.interface:
        if config.interface not in get_if_list():
            raise RuntimeError(f"Interface '{config.interface}' not found")
        return config.interface
    
    # Auto-detect suitable interface
    suitable_interfaces = []
    
    for iface in get_if_list():
        try:
            ip = get_if_addr(iface)
            if ip and ip != "0.0.0.0" and ip.startswith(config.target_ip_prefix):
                suitable_interfaces.append((iface, ip))
                if config.verbose:
                    print(f"[DEBUG] Found suitable interface: {iface} ({ip})")
        except Exception:
            continue
    
    if not suitable_interfaces:
        # Fallback to any non-loopback interface
        for iface in get_if_list():
            try:
                ip = get_if_addr(iface)
                if ip and ip != "0.0.0.0" and not ip.startswith("127."):
                    return iface
            except Exception:
                continue
        raise RuntimeError("No suitable network interface found")
    
    # Choose the first suitable interface
    chosen_iface, chosen_ip = suitable_interfaces[0]
    
    if len(suitable_interfaces) > 1:
        print(f"[INFO] Multiple interfaces found, using: {chosen_iface} ({chosen_ip})")
    
    return chosen_iface

def build_capture_filter(config):
    """Build packet capture filter"""
    base_filter = config.capture_filter
    
    if config.target_port:
        base_filter += f" and port {config.target_port}"
    
    return base_filter

def shutdown_handler(ids, signum, frame):
    """Handle graceful shutdown"""
    print(f"\n[INFO] Received signal {signum}, shutting down Enhanced IDS...")
    ids.running = False
    ids.print_statistics()
    
    # Show final summary
    print(f"\n[SUMMARY] Enhanced IDS Session Summary:")
    print(f"  - Total Packets Processed: {ids.packet_count}")
    print(f"  - Signature Alerts: {ids.signature_alerts}")
    print(f"  - Anomaly Alerts: {ids.anomaly_alerts}")
    print(f"  - Total Threats: {ids.threat_count}")
    if ids.network_blocker:
        print(f"  - IPs Blocked: {ids.blocked_count}")
        print(f"  - Currently Blocked: {len(ids.network_blocker.blocked_ips)}")
    print(f"  - Active Signatures: {len(ids.signatures)}")
    print(f"  - Database: {ids.threat_db.db_file}")
    
    # Show some database statistics
    try:
        conn = sqlite3.connect(ids.threat_db.db_file)
        cursor = conn.cursor()
        
        cursor.execute("SELECT COUNT(*) FROM threat_events")
        threat_events = cursor.fetchone()[0]
        
        cursor.execute("SELECT COUNT(*) FROM network_features")
        feature_records = cursor.fetchone()[0]
        
        print(f"  - Database Records: {threat_events} threats, {feature_records} feature sets")
        conn.close()
    except Exception:
        pass
    
    sys.exit(0)

def periodic_stats(ids):
    """Print periodic statistics"""
    if ids.running:
        ids.print_statistics()
        
        # Schedule next stats print
        stats_thread = threading.Timer(15.0, lambda: periodic_stats(ids))
        stats_thread.daemon = True
        stats_thread.start()

def export_training_data(db_file, output_file):
    """Export network features data for AI training"""
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT nf.*, te.threat_type IS NOT NULL as is_threat
            FROM network_features nf
            LEFT JOIN threat_events te ON 
                nf.source_ip = te.source_ip AND 
                abs(nf.timestamp - te.timestamp) < 5
            ORDER BY nf.timestamp DESC
            LIMIT 10000
        ''')
        
        import csv
        with open(output_file, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            columns = [description[0] for description in cursor.description]
            writer.writerow(columns)
            
            # Write data
            for row in cursor.fetchall():
                writer.writerow(row)
        
        conn.close()
        print(f"[INFO] Training data exported to {output_file}")
        
    except Exception as e:
        print(f"[ERROR] Failed to export training data: {e}")

def main():
    """Main entry point for Enhanced IDS - Ready for AI Integration"""
    parser = argparse.ArgumentParser(
        description="Enhanced Network Intrusion Detection System - Ready for AI Integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
FIXED VERSION - Key improvements:
- Now actually loads and uses signatures.json file
- Much higher thresholds for anomaly detection (reduced false positives)
- Better normal traffic filtering
- Improved logging and debugging output

Features:
- Signature-based detection with database storage
- Comprehensive network feature extraction for AI training
- Automated blocking capabilities with iptables integration
- SQLite database for threat intelligence and feature storage
- Ready for custom AI model integration
- Real-time statistics and monitoring

AI Integration Ready:
- Network features are automatically extracted and stored
- Database schema includes AI-specific fields
- integrate_ai_model() method ready for your trained model
- Training data export functionality included

Examples:
  python3 enhanced_ids.py                                     # Basic monitoring
  python3 enhanced_ids.py --enable-blocking --block-duration 600  # With blocking
  python3 enhanced_ids.py --interface eth0 --verbose              # Specific interface
  python3 enhanced_ids.py --export-training training_data.csv     # Export training data
  
Safety Notes:
- Blocking is disabled by default (use --enable-blocking to activate)
- Local/private IPs are protected from blocking by default
- Use --allow-local-blocking to override (not recommended)
        """
    )
    
    parser.add_argument("-i", "--interface", help="Network interface to monitor")
    parser.add_argument("-p", "--port", type=int, help="Specific port to monitor (default: all ports)")
    parser.add_argument("--db-file", default=DEFAULT_DB_FILE, help="Database file path")
    parser.add_argument("--signature-file", default=DEFAULT_SIGNATURE_FILE, help="JSON signature file path")
    parser.add_argument("--enable-blocking", action="store_true", 
                       help="Enable automatic IP blocking (requires root)")
    parser.add_argument("--allow-local-blocking", action="store_true",
                       help="Allow blocking of local/private IPs (use with caution)")
    parser.add_argument("--block-duration", type=int, default=DEFAULT_BLOCK_DURATION,
                       help=f"IP block duration in seconds (default: {DEFAULT_BLOCK_DURATION})")
    parser.add_argument("--target-prefix", default=DEFAULT_TARGET_IP_PREFIX,
                       help=f"Target IP prefix for interface selection (default: {DEFAULT_TARGET_IP_PREFIX})")
    parser.add_argument("--export-training", help="Export training data to CSV file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    
    args = parser.parse_args()
    
    # Handle training data export
    if args.export_training:
        export_training_data(args.db_file, args.export_training)
        return
    
    # Check for root privileges if blocking is enabled
    if args.enable_blocking and os.geteuid() != 0:
        print("[ERROR] Root privileges required for network blocking. Run with sudo or disable blocking.")
        sys.exit(1)
    
    # Create configuration
    config = EnhancedIDSConfig()
    config.interface = args.interface
    config.target_port = args.port
    config.db_file = args.db_file
    config.signature_file = args.signature_file
    config.enable_blocking = args.enable_blocking
    config.allow_local_blocking = args.allow_local_blocking
    config.block_duration = args.block_duration
    config.target_ip_prefix = args.target_prefix
    config.verbose = args.verbose
    
    # Create and run Enhanced IDS
    try:
        ids = EnhancedIDS(config)
        config.start_time = time.time()
        
        print(f"[INFO] Starting Enhanced Network IDS (AI-Ready) - FIXED VERSION")
        print(f"[INFO] Database: {config.db_file}")
        print(f"[INFO] Signature File: {config.signature_file}")
        print(f"[INFO] Signatures: {len(ids.signatures)} loaded")
        print(f"[INFO] Blocking: {'Enabled' if config.enable_blocking else 'Disabled'}")
        if config.enable_blocking:
            print(f"[INFO] Block Duration: {config.block_duration}s")
            print(f"[INFO] Local IP Blocking: {'Allowed' if config.allow_local_blocking else 'Blocked'}")
        
        # Choose interface
        interface = choose_interface(config)
        print(f"[INFO] Monitoring interface: {interface} ({get_if_addr(interface)})")
        
        # Set up signal handlers
        signal.signal(signal.SIGINT, lambda s, f: shutdown_handler(ids, s, f))
        signal.signal(signal.SIGTERM, lambda s, f: shutdown_handler(ids, s, f))
        
        # Start statistics thread
        stats_thread = threading.Timer(15.0, lambda: periodic_stats(ids))
        stats_thread.daemon = True
        stats_thread.start()
        
        # Start packet capture
        ids.running = True
        capture_filter = build_capture_filter(config)
        
        print(f"[INFO] Capture filter: '{capture_filter}'")
        print("[INFO] Enhanced IDS is monitoring network traffic...")
        print("[INFO] Network features are being extracted and stored for AI training")
        print("[INFO] FIXED: Now properly loads signatures.json and has reduced false positives")
        print("[INFO] Press Ctrl+C to stop\n")
        
        # Display integration note
        print("[AI INTEGRATION NOTE]")
        print("  To integrate your AI model:")
        print("  1. Load your trained model: model = load_your_model()")
        print("  2. Call: ids.integrate_ai_model(model)")
        print("  3. Implement prediction in process_packet() method")
        print("  4. Export training data: --export-training data.csv\n")
        
        sniff(
            iface=interface,
            filter=capture_filter,
            prn=ids.process_packet,
            store=False,
            stop_filter=lambda x: not ids.running
        )
        
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down Enhanced IDS...")
        ids.print_statistics()
    except Exception as e:
        print(f"[ERROR] IDS failed: {e}")
        sys.exit(1)

if __name__ == "__main__":
    print("""
╔══════════════════════════════════════════════════════════════════════════════╗
║                    Enhanced Network IDS v2.0 - FIXED                        ║
║                         Ready for AI Model Integration                       ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  FIXES Applied:                                                              ║
║  ✓ Now actually loads and uses signatures.json file                         ║
║  ✓ Much higher anomaly detection thresholds (reduced false positives)       ║
║  ✓ Better normal traffic filtering                                           ║
║  ✓ Improved logging and debugging output                                     ║
║  ✓ Reduced database writes to improve performance                            ║
║                                                                              ║
║  Current Features:                                                           ║
║  • Advanced signature-based detection with database storage                 ║
║  • Comprehensive network feature extraction (8+ features)                   ║
║  • Real-time network blocking with iptables integration                     ║
║  • SQLite database for threat intelligence and training data                ║
║  • Automated signature management and hit tracking                          ║
║  • Much improved anomaly detection with realistic thresholds                ║
║  • Training data export for AI model development                            ║
║                                                                              ║
║  AI Integration Ready:                                                       ║
║  • integrate_ai_model() method prepared for your trained model              ║
║  • Network features automatically extracted and stored                      ║
║  • Database schema includes AI-specific fields                              ║
║  • add_signature_from_ai() method for adaptive learning                     ║
║                                                                              ║
║  IMPORTANT: Make sure you have signatures.json file in the same directory   ║
║             or specify --signature-file path                                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """)
    
    main()