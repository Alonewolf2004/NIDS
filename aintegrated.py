"""
AI-Integrated Real-time Intrusion Detection System
VERSION 6.2 - FINAL & STABLE
- FINAL FIX: Corrected TCP flag parsing in the FlowTracker to prevent AttributeError.
- WORKFLOW: Implements the "Signatures First, then AI" detection pipeline.
- SIGNATURES: Includes a SignatureMatcher that supports the `signature.json` format.
- INTEGRATION: Fully integrated with the trained RandomForest model pipeline.
"""
from scapy.all import IP, TCP, UDP
import json
import sys
sys.stdout.reconfigure(encoding='utf-8')
import signal
import argparse
import os
import subprocess
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from scapy.all import *
from datetime import datetime, timedelta
import threading
import time
from collections import defaultdict
import sqlite3
import warnings

# Suppress scapy IPv6 warning and other general warnings
warnings.filterwarnings('ignore')
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# --- Configuration ---
DEFAULT_MODELS_PATH = "models/"
DEFAULT_SIGNATURE_FILE = "signature.json"
DEFAULT_DB_FILE = "ids_database.db"
DEFAULT_BLOCK_DURATION = 300
FLOW_TIMEOUT = 60
AI_CONFIDENCE_THRESHOLD = 0.7

# Setup basic logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', stream=sys.stdout)
logger = logging.getLogger(__name__)

class SignatureMatcher:
    """Loads and matches network traffic against a structured signature file."""
    def __init__(self, signature_file=DEFAULT_SIGNATURE_FILE):
        self.signatures = self.load_signatures(signature_file)
        if self.signatures:
            logger.info(f"Loaded {len(self.signatures)} signatures from {signature_file}")

    def load_signatures(self, file_path):
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.error(f"Signature file not found at {file_path}. Signature matching will be disabled.")
            return []
        except json.JSONDecodeError as e:
            logger.error(f"Error decoding signature file {file_path}: {e}. Signature matching will be disabled.")
            return []

    def check_packet(self, pkt):
        """Checks a single packet against all loaded signatures."""
        if not self.signatures or not pkt.haslayer(IP):
            return None

        packet_protocol, dst_port, payload_str = None, None, ""
        
        if pkt.haslayer(TCP):
            packet_protocol, dst_port = "TCP", pkt[TCP].dport
            if hasattr(pkt[TCP].payload, 'load'): payload_str = pkt[TCP].payload.load.decode(errors='ignore').lower()
        elif pkt.haslayer(UDP):
            packet_protocol, dst_port = "UDP", pkt[UDP].dport
            if hasattr(pkt[UDP].payload, 'load'): payload_str = pkt[UDP].payload.load.decode(errors='ignore').lower()

        if not packet_protocol: return None
        
        for rule in self.signatures:
            try:
                if (rule.get("protocol", "").upper() == packet_protocol and
                    dst_port in rule.get("dst_port", []) and
                    rule.get("payload_pattern", "").lower() in payload_str):
                    return rule
            except Exception:
                continue
        
        return None

class ThreatDatabase:
    """Database for storing threats."""
    def __init__(self, db_file=DEFAULT_DB_FILE):
        self.db_file = db_file
        self.init_database()

    def init_database(self):
        try:
            conn = sqlite3.connect(self.db_file, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp REAL, source_ip TEXT,
                    dest_ip TEXT, threat_type TEXT, details TEXT, blocked BOOLEAN, confidence REAL
                )
            ''')
            conn.commit()
            conn.close()
            logger.info(f"Database initialized at {self.db_file}")
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")

    def log_threat(self, src_ip, dst_ip, threat_type, details, blocked, confidence):
        try:
            conn = sqlite3.connect(self.db_file, check_same_thread=False)
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO threat_events (timestamp, source_ip, dest_ip, threat_type, details, blocked, confidence)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            ''', (time.time(), src_ip, dst_ip, threat_type, details, blocked, confidence))
            conn.commit()
            conn.close()
        except Exception as e:
            logger.warning(f"Could not log threat to database: {e}")

class NetworkBlocker:
    """Handle network blocking using iptables."""
    def __init__(self, block_duration):
        self.block_duration = block_duration
        self.blocked_ips = {} # ip -> unblock_time
        self.lock = threading.Lock()

    def block_ip(self, ip_address, reason):
        with self.lock:
            if ip_address in self.blocked_ips: return False
            if ip_address.startswith(('127.', '10.', '192.168.')):
                logger.warning(f"Skipping block of local/private IP: {ip_address}")
                return False
            try:
                logger.info(f"Attempting to block {ip_address} for {self.block_duration}s. Reason: {reason}")
                subprocess.run(["iptables", "-I", "INPUT", "1", "-s", ip_address, "-j", "DROP"], check=True, capture_output=True, text=True)
                unblock_time = time.time() + self.block_duration
                self.blocked_ips[ip_address] = unblock_time
                return True
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.error(f"Failed to block {ip_address} using iptables. Is it installed and are you root? Error: {e.stderr}")
                return False

    def unblock_ip(self, ip_address):
        with self.lock:
            if ip_address not in self.blocked_ips: return
            try:
                logger.info(f"Unblocking {ip_address}")
                subprocess.run(["iptables", "-D", "INPUT", "-s", ip_address, "-j", "DROP"], check=True, capture_output=True, text=True)
                del self.blocked_ips[ip_address]
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                logger.warning(f"Failed to unblock {ip_address}. It might have been unblocked manually. Error: {e.stderr}")

    def cleanup_loop(self):
        while True:
            now = time.time()
            expired_ips = [ip for ip, unblock_time in list(self.blocked_ips.items()) if now >= unblock_time]
            for ip in expired_ips:
                self.unblock_ip(ip)
            time.sleep(30)

class FlowTracker:
    """Assembles packets into flows and calculates features compatible with the trained model."""
    def __init__(self, timeout=FLOW_TIMEOUT):
        self.flows = {}
        self.timeout = timeout
        self.lock = threading.Lock()

    def _get_flow_key(self, pkt):
        if IP in pkt and (TCP in pkt or UDP in pkt):
            p = pkt[TCP] if TCP in pkt else pkt[UDP]
            ip1, ip2 = sorted((pkt[IP].src, pkt[IP].dst))
            port1, port2 = sorted((p.sport, p.dport))
            proto = pkt[IP].proto
            return f"{ip1}:{port1}-{ip2}:{port2}-{proto}"
        return None

    def process_packet(self, pkt):
        flow_key = self._get_flow_key(pkt)
        if not flow_key: return

        with self.lock:
            now = time.time()
            if flow_key not in self.flows:
                self.flows[flow_key] = {
                    'packets': [], 'start_time': now, 'last_seen': now,
                    'src': pkt[IP].src, 'dst': pkt[IP].dst,
                    'srcport': pkt[TCP].sport if TCP in pkt else pkt[UDP].sport,
                    'dstport': pkt[TCP].dport if TCP in pkt else pkt[UDP].dport,
                }
            # The .flags attribute can be an int, so we store it directly
            self.flows[flow_key]['packets'].append({
                'time': now, 'len': len(pkt),
                'flags': int(pkt[TCP].flags) if TCP in pkt else 0,
                'dir': 'fwd' if pkt[IP].src == self.flows[flow_key]['src'] else 'bwd'
            })
            self.flows[flow_key]['last_seen'] = now
            # Use bitwise AND for checking flags from an integer
            if TCP in pkt and (int(pkt[TCP].flags) & 0x01 or int(pkt[TCP].flags) & 0x04): # FIN or RST
                self.flows[flow_key]['finished'] = True

    def get_finished_flows(self):
        finished_flows_features = []
        with self.lock:
            now = time.time()
            finished_keys = []
            for key, flow in self.flows.items():
                if flow.get('finished', False) or (now - flow['last_seen']) > self.timeout:
                    features = self._calculate_features(flow)
                    if features: finished_flows_features.append(features)
                    finished_keys.append(key)
            for key in finished_keys: del self.flows[key]
        return finished_flows_features

    def _calculate_features(self, flow):
        packets = flow['packets']
        if len(packets) < 2: return None
        fwd_pkts = [p for p in packets if p['dir'] == 'fwd']
        bwd_pkts = [p for p in packets if p['dir'] == 'bwd']
        if not fwd_pkts: return None

        flow_duration = (flow['last_seen'] - flow['start_time']) * 1_000_000
        fwd_pkt_lengths = [p['len'] for p in fwd_pkts]
        bwd_pkt_lengths = [p['len'] for p in bwd_pkts] if bwd_pkts else [0]
        fwd_iat = np.diff([p['time'] for p in fwd_pkts]) * 1_000_000 if len(fwd_pkts) > 1 else [0]
        
        # Define TCP flag constants for bitwise operations
        FIN, SYN, RST, PSH, ACK, URG, ECE = 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40

        features = {
            'destination port': flow['dstport'], 'flow duration': flow_duration,
            'total fwd packets': len(fwd_pkts), 'total backward packets': len(bwd_pkts),
            'total length of fwd packets': sum(fwd_pkt_lengths), 'total length of bwd packets': sum(bwd_pkt_lengths),
            'fwd packet length max': np.max(fwd_pkt_lengths), 'fwd packet length min': np.min(fwd_pkt_lengths),
            'fwd packet length mean': np.mean(fwd_pkt_lengths), 'fwd packet length std': np.std(fwd_pkt_lengths),
            'bwd packet length max': np.max(bwd_pkt_lengths), 'bwd packet length min': np.min(bwd_pkt_lengths),
            'bwd packet length mean': np.mean(bwd_pkt_lengths), 'bwd packet length std': np.std(bwd_pkt_lengths),
            'flow bytes/s': (sum(fwd_pkt_lengths) + sum(bwd_pkt_lengths)) / max(1e-6, flow_duration / 1_000_000),
            'flow packets/s': len(packets) / max(1e-6, flow_duration / 1_000_000),
            'flow iat mean': np.mean(fwd_iat), 'flow iat std': np.std(fwd_iat),
            'flow iat max': np.max(fwd_iat), 'flow iat min': np.min(fwd_iat),
            'fwd iat total': np.sum(fwd_iat), 'fwd iat mean': np.mean(fwd_iat),
            'fwd iat std': np.std(fwd_iat), 'fwd iat max': np.max(fwd_iat),
            'fwd iat min': np.min(fwd_iat),
            'fwd psh flags': sum(1 for p in fwd_pkts if p['flags'] & PSH),
            'fwd urg flags': sum(1 for p in fwd_pkts if p['flags'] & URG),
            'fwd header length': len(fwd_pkts) * 20, 'bwd header length': len(bwd_pkts) * 20,
            'fwd packets/s': len(fwd_pkts) / max(1e-6, flow_duration / 1_000_000),
            'bwd packets/s': len(bwd_pkts) / max(1e-6, flow_duration / 1_000_000),
            'min packet length': min(p['len'] for p in packets), 'max packet length': max(p['len'] for p in packets),
            'packet length mean': np.mean([p['len'] for p in packets]), 'packet length std': np.std([p['len'] for p in packets]),
            'packet length variance': np.var([p['len'] for p in packets]),
            'fin flag count': sum(1 for p in packets if p['flags'] & FIN), 'syn flag count': sum(1 for p in packets if p['flags'] & SYN),
            'rst flag count': sum(1 for p in packets if p['flags'] & RST), 'psh flag count': sum(1 for p in packets if p['flags'] & PSH),
            'ack flag count': sum(1 for p in packets if p['flags'] & ACK), 'urg flag count': sum(1 for p in packets if p['flags'] & URG),
            'cwe flag count': 0, 'ece flag count': sum(1 for p in packets if p['flags'] & ECE),
            'down/up ratio': len(bwd_pkts) / len(fwd_pkts) if len(fwd_pkts) > 0 else 0,
            'average packet size': np.mean([p['len'] for p in packets]),
            'avg fwd segment size': np.mean(fwd_pkt_lengths), 'avg bwd segment size': np.mean(bwd_pkt_lengths),
            'init_win_bytes_forward': -1, 'init_win_bytes_backward': -1,
            'act_data_pkt_fwd': sum(1 for p in fwd_pkts if p['len'] > 20), 'min_seg_size_forward': -1,
            'src_ip': flow['src'], 'dst_ip': flow['dst']
        }
        return features

class AIModelManager:
    """Manages loading the trained RandomForest pipeline and making predictions on flow data."""
    def __init__(self, models_path=DEFAULT_MODELS_PATH):
        self.models_path = Path(models_path)
        self.model, self.scaler, self.label_encoder, self.feature_columns = None, None, None, None
        self.model_loaded = self.load_pipeline()

    def load_pipeline(self):
        try:
            logger.info("Loading AI model pipeline from 'models/' directory...")
            model_path = self.models_path / "nids_randomforest.joblib"
            scaler_path = self.models_path / "scaler.joblib"
            encoder_path = self.models_path / "label_encoder.joblib"
            features_path = self.models_path / "feature_columns.joblib"

            if not all([p.exists() for p in [model_path, scaler_path, encoder_path, features_path]]):
                logger.error("One or more required model files (.joblib) are missing. AI detection disabled.")
                return False

            self.model, self.scaler, self.label_encoder, self.feature_columns = \
                joblib.load(model_path), joblib.load(scaler_path), joblib.load(encoder_path), joblib.load(features_path)
            
            logger.info("✅ AI Model pipeline loaded successfully.")
            return True
        except Exception as e:
            logger.error(f"Failed to load AI pipeline: {e}. AI detection disabled.")
            return False

    def predict_flow(self, flow_features_dict):
        if not self.model_loaded: return "unknown", 0.0
        try:
            flow_df = pd.DataFrame([flow_features_dict])
            flow_df.columns = [str(c).strip().lower() for c in flow_df.columns]
            for col in self.feature_columns:
                if col not in flow_df.columns: flow_df[col] = 0
            flow_df = flow_df[self.feature_columns]

            scaled_features = self.scaler.transform(flow_df)
            prediction_encoded = self.model.predict(scaled_features)
            prediction_proba = self.model.predict_proba(scaled_features)
            predicted_label = self.label_encoder.inverse_transform(prediction_encoded)[0]
            confidence = prediction_proba.max()
            return predicted_label, confidence
        except Exception as e:
            logger.warning(f"AI prediction failed for flow: {e}")
            return "error", 0.0

class EnhancedAIIDS:
    """Main class that integrates all components according to the project workflow."""
    def __init__(self, config):
        self.config = config
        self.running = False
        self.start_time = time.time()
        self.packet_count = 0
        self.flow_count = 0
        self.threat_count = 0
        self.signature_matcher = SignatureMatcher(config.signature_file)
        self.flow_tracker = FlowTracker(timeout=FLOW_TIMEOUT)
        self.ai_manager = AIModelManager(config.models_path)
        self.threat_db = ThreatDatabase(config.db_file)
        self.network_blocker = NetworkBlocker(config.block_duration) if config.enable_blocking else None

    def process_packet(self, pkt):
        self.packet_count += 1
        signature_match = self.signature_matcher.check_packet(pkt)
        if signature_match:
            self.handle_threat('signature', signature_match, pkt=pkt)
        self.flow_tracker.process_packet(pkt)

    def analysis_loop(self):
        logger.info("AI analysis thread started.")
        while self.running:
            finished_flows = self.flow_tracker.get_finished_flows()
            for flow in finished_flows:
                self.flow_count += 1
                label, confidence = self.ai_manager.predict_flow(flow)
                if label not in ['benign', 'error', 'unknown'] and confidence > self.config.ai_confidence:
                    self.handle_threat('ai_detection', {'predicted_attack': label, 'confidence': confidence}, flow=flow)
            time.sleep(5)

    def handle_threat(self, threat_type, details, pkt=None, flow=None):
        self.threat_count += 1
        blocked = False
        
        if threat_type == 'signature':
            src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
            desc = details.get('description', 'Signature match')
            confidence = details.get('confidence', 0.9)
            logger.warning(f"--- SIGNATURE THREAT DETECTED --- | Rule: {desc} | {src_ip} -> {dst_ip}")
            if self.network_blocker:
                blocked = self.network_blocker.block_ip(src_ip, reason=desc)

        elif threat_type == 'ai_detection':
            src_ip, dst_ip = flow['src_ip'], flow['dst_ip']
            desc = f"Predicted Attack: {details['predicted_attack'].upper()}"
            confidence = details['confidence']
            logger.warning(f"--- AI THREAT DETECTED --- | {desc} (Confidence: {confidence:.2%}) | Flow: {src_ip} -> {dst_ip}")
            if self.network_blocker:
                blocked = self.network_blocker.block_ip(src_ip, reason=desc)
        else:
            return

        self.threat_db.log_threat(src_ip, dst_ip, threat_type, desc, blocked, confidence)

    def stats_loop(self):
        while self.running:
            time.sleep(15)
            runtime = time.time() - self.start_time
            pps = self.packet_count / runtime if runtime > 0 else 0
            print("-" * 50)
            print(f"Status Update | Uptime: {timedelta(seconds=int(runtime))}")
            print(f"Packets Processed: {self.packet_count} ({pps:.1f} pps)")
            print(f"Flows Analyzed by AI: {self.flow_count}")
            print(f"Threats Detected: {self.threat_count}")
            if self.network_blocker:
                print(f"Currently Blocked IPs: {len(self.network_blocker.blocked_ips)}")
            print("-" * 50)

    def start(self):
        self.running = True
        analysis_thread = threading.Thread(target=self.analysis_loop, daemon=True)
        analysis_thread.start()
        stats_thread = threading.Thread(target=self.stats_loop, daemon=True)
        stats_thread.start()
        if self.network_blocker:
            cleanup_thread = threading.Thread(target=self.network_blocker.cleanup_loop, daemon=True)
            cleanup_thread.start()

        logger.info(f"Starting packet capture on interface '{self.config.interface}'...")
        logger.info("Detection pipeline: Signatures (per-packet) -> AI (per-flow)")
        logger.info("Press Ctrl+C to stop.")
        sniff(iface=self.config.interface, prn=self.process_packet, store=False, stop_filter=lambda x: not self.running)

    def stop(self):
        logger.info("Shutting down... processed %d packets and %d flows.", self.packet_count, self.flow_count)
        self.running = False

# --- Main Execution ---
def main():
    print("="*60)
    print("    ██████╗ ██╗██████╗  ███████╗███████╗██████╗ ")
    print("    ██╔══██╗██║██╔══██╗██╔════╝██╔════╝██╔══██╗")
    print("    ██║  ██║██║██║  ██║███████╗█████╗  ██████╔╝")
    print("    ██║  ██║██║██║  ██║╚════██║██╔══╝  ██╔══██╗")
    print("    ██████╔╝██║██████╔╝███████║███████╗██║  ██║")
    print("    ╚═════╝ ╚═╝╚═════╝ ╚══════╝╚══════╝╚═╝  ╚═╝")
    print("           AI-Powered Network Intrusion Detection")
    print("="*60)
    
    parser = argparse.ArgumentParser(description="AI-Powered NIDS (v6.2) - Signature First, then AI Anomaly Detection.")
    parser.add_argument('-i', '--interface', type=str, help='Network interface to monitor')
    parser.add_argument('--models_path', type=str, default=DEFAULT_MODELS_PATH, help='Path to the models directory')
    parser.add_argument("--signature_file", type=str, default=DEFAULT_SIGNATURE_FILE, help="Path to the signature JSON file")
    parser.add_argument("--enable-blocking", action="store_true", help="Enable automatic IP blocking (requires root/admin)")
    parser.add_argument("--block-duration", type=int, default=DEFAULT_BLOCK_DURATION, help="IP block duration in seconds")
    parser.add_argument("--db-file", default=DEFAULT_DB_FILE, help="Database file path")
    parser.add_argument("--ai-confidence", type=float, default=AI_CONFIDENCE_THRESHOLD, help="AI confidence threshold for alerting/blocking")
    args = parser.parse_args()

    if not args.interface:
        print("\n[!] No network interface specified. Attempting to auto-detect...")
        try:
            iface_list = get_working_ifaces()
            if not iface_list: raise Exception("Scapy could not find any working interfaces.")
            print("Available interfaces:")
            for i, iface in enumerate(iface_list): print(f"  {i+1}: {iface.name} ({iface.ip})")
            choice = input("Please select an interface by number (e.g., '1'): ")
            args.interface = iface_list[int(choice)-1].name
            logger.info(f"Using selected interface: '{args.interface}'")
        except (ValueError, IndexError, Exception) as e:
            logger.error(f"Could not select an interface. Please specify one with -i. Error: {e}")
            sys.exit(1)

    if args.enable_blocking and os.name != 'nt' and os.geteuid() != 0:
        logger.error("Blocking requires root privileges. Please run with sudo.")
        sys.exit(1)
    
    nids = EnhancedAIIDS(args)
    def shutdown(signum, frame): nids.stop()
    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)
    nids.start()
    logger.info("NIDS stopped.")

if __name__ == "__main__":
    main()