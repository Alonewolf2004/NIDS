"""
Enhanced ML Model Training for Network Intrusion Detection
Optimized for CIC-IDS-2017 and similar datasets with automatic file detection
"""

import pandas as pd
import numpy as np
import pickle
import time
import glob
import os
from pathlib import Path
from scapy.all import rdpcap, TCP, IP, UDP, raw
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import matplotlib.pyplot as plt
import seaborn as sns
from collections import defaultdict
import argparse
import json
import warnings
warnings.filterwarnings('ignore')

class EnhancedNetworkDataCollector:
    """Enhanced collector for CIC-IDS-2017 and similar datasets"""
    
    def __init__(self):
        self.features = []
        self.labels = []
        self.flow_stats = defaultdict(lambda: {
            'packet_count': 0,
            'byte_count': 0,
            'duration': 0,
            'start_time': None,
            'protocols': set(),
            'flags': set()
        })
        self.feature_names = [
            'packet_size', 'timestamp', 'ip_len', 'ip_ttl', 'ip_proto', 'ip_flags', 'ip_frag',
            'protocol', 'src_port', 'dst_port', 'tcp_flags', 'tcp_window', 'tcp_urgptr',
            'payload_size', 'flag_fin', 'flag_syn', 'flag_rst', 'flag_psh', 'flag_ack', 'flag_urg',
            'is_well_known_port', 'is_ephemeral_port', 'payload_entropy', 'has_suspicious_strings'
        ]
        self.processed_files = []
        self.file_stats = {}
    
    def detect_datasets(self, dataset_dir='datasets'):
        """Enhanced dataset detection for CIC-IDS-2017 and other formats"""
        dataset_path = Path(dataset_dir)
        if not dataset_path.exists():
            print(f"Dataset directory '{dataset_dir}' not found!")
            print("Please create the directory and place your dataset files there.")
            return None, None
        
        print(f"Scanning dataset directory: {dataset_path}")
        
        # Look for different file types with broader extensions
        file_extensions = ['*.pcap', '*.pcapng', '*.csv', '*.txt', '*.data', '*.arff']
        all_files = []
        
        for ext in file_extensions:
            all_files.extend(list(dataset_path.glob(ext)))
            # Also check subdirectories
            all_files.extend(list(dataset_path.glob(f"**/{ext}")))
        
        if not all_files:
            print(f"No dataset files found in {dataset_path}")
            print(f"Looked for: {', '.join(file_extensions)}")
            return [], []
        
        print(f"Found {len(all_files)} files total")
        
        # Enhanced categorization based on CIC-IDS-2017 naming patterns
        normal_files = []
        attack_files = []
        unknown_files = []
        
        for file_path in all_files:
            filename = file_path.name.lower()
            
            # Skip hidden files and system files
            if filename.startswith('.') or filename.startswith('~'):
                continue
            
            print(f"Analyzing: {file_path.name}")
            
            # CIC-IDS-2017 specific patterns
            if self._is_normal_traffic(filename):
                normal_files.append(file_path)
                print(f"  → Classified as NORMAL traffic")
            elif self._is_attack_traffic(filename):
                attack_files.append(file_path)
                attack_type = self._identify_attack_type(filename)
                print(f"  → Classified as ATTACK traffic ({attack_type})")
            else:
                # Try to analyze file content for classification
                classification = self._analyze_file_content(file_path)
                if classification == 'normal':
                    normal_files.append(file_path)
                    print(f"  → Content analysis: NORMAL traffic")
                elif classification == 'attack':
                    attack_files.append(file_path)
                    print(f"  → Content analysis: ATTACK traffic")
                else:
                    unknown_files.append(file_path)
                    print(f"  → UNKNOWN - will analyze content during processing")
        
        print(f"\n=== DATASET CLASSIFICATION ===")
        print(f"Normal traffic files: {len(normal_files)}")
        for f in normal_files:
            print(f"  ✓ {f.name}")
        
        print(f"\nAttack traffic files: {len(attack_files)}")
        for f in attack_files:
            print(f"  ✗ {f.name}")
        
        if unknown_files:
            print(f"\nUnknown files (will analyze during processing): {len(unknown_files)}")
            for f in unknown_files:
                print(f"  ? {f.name}")
            # Add unknown files to both categories for mixed processing
            normal_files.extend(unknown_files)
        
        return normal_files, attack_files
    
    def _is_normal_traffic(self, filename):
        """Check if filename indicates normal traffic"""
        normal_indicators = [
            'normal', 'benign', 'legitimate', 'clean', 'background',
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday',
            'workinghours', 'morning', 'afternoon'
        ]
        
        # Must contain normal indicators AND not contain attack indicators
        has_normal = any(indicator in filename for indicator in normal_indicators)
        has_attack = any(indicator in filename for indicator in [
            'attack', 'malicious', 'intrusion', 'exploit', 'dos', 'ddos',
            'probe', 'r2l', 'u2r', 'portscan', 'bruteforce', 'heartbleed',
            'infiltration', 'botnet', 'web', 'sql', 'ftp', 'ssh'
        ])
        
        return has_normal and not has_attack
    
    def _is_attack_traffic(self, filename):
        """Check if filename indicates attack traffic"""
        attack_indicators = [
            'attack', 'malicious', 'intrusion', 'exploit', 'dos', 'ddos',
            'probe', 'r2l', 'u2r', 'portscan', 'bruteforce', 'heartbleed',
            'infiltration', 'botnet', 'web', 'sql', 'ftp', 'ssh', 'slowloris',
            'goldeneye', 'hulk', 'slowhttptest', 'patator'
        ]
        
        return any(indicator in filename for indicator in attack_indicators)
    
    def _identify_attack_type(self, filename):
        """Identify specific attack type from filename"""
        attack_types = {
            'dos': ['dos', 'slowloris', 'goldeneye', 'hulk', 'slowhttptest'],
            'ddos': ['ddos'],
            'portscan': ['portscan', 'probe'],
            'bruteforce': ['bruteforce', 'patator', 'ftp', 'ssh'],
            'heartbleed': ['heartbleed'],
            'infiltration': ['infiltration'],
            'botnet': ['botnet'],
            'web': ['web', 'sql', 'xss']
        }
        
        for attack_type, keywords in attack_types.items():
            if any(keyword in filename for keyword in keywords):
                return attack_type
        
        return 'unknown_attack'
    
    def _analyze_file_content(self, file_path):
        """Analyze file content to determine if it's normal or attack data"""
        try:
            if file_path.suffix.lower() in ['.csv', '.txt']:
                # Read first few lines to check for labels
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    sample_lines = [f.readline().strip() for _ in range(10)]
                
                # Check for common attack labels in content
                content = ' '.join(sample_lines).lower()
                if any(attack in content for attack in ['dos', 'probe', 'r2l', 'u2r', 'attack']):
                    return 'attack'
                elif 'normal' in content:
                    return 'normal'
            
            return 'unknown'
        except:
            return 'unknown'
    
    def process_csv_dataset(self, csv_file, default_label='normal'):
        """Enhanced CSV processing with better format detection"""
        print(f"Processing dataset: {csv_file}")
        
        try:
            # Try different encodings and separators
            encodings = ['utf-8', 'latin-1', 'iso-8859-1']
            separators = [',', ';', '\t', '|']
            
            df = None
            for encoding in encodings:
                for sep in separators:
                    try:
                        df = pd.read_csv(csv_file, encoding=encoding, sep=sep, low_memory=False)
                        if df.shape[1] > 1:  # Must have multiple columns
                            print(f"  Loaded with encoding={encoding}, separator='{sep}'")
                            break
                    except:
                        continue
                if df is not None and df.shape[1] > 1:
                    break
            
            if df is None or df.shape[1] <= 1:
                print(f"  Could not parse {csv_file} - trying as raw text")
                return self._process_raw_text_file(csv_file, default_label)
            
            print(f"  Dataset shape: {df.shape}")
            print(f"  Columns: {list(df.columns[:5])}{'...' if len(df.columns) > 5 else ''}")
            
            # Detect label column
            label_column = self._detect_label_column(df)
            if not label_column:
                print(f"  No label column found, using default label: {default_label}")
                labels = [default_label] * len(df)
            else:
                print(f"  Found label column: {label_column}")
                labels = df[label_column].values
                df = df.drop(label_column, axis=1)
            
            # Process labels
            processed_labels = self._process_labels(labels, default_label)
            
            # Process features
            feature_data = self._process_csv_features(df)
            
            # Add to our dataset
            for i, feature_row in enumerate(feature_data):
                self.features.append(feature_row)
                self.labels.append(processed_labels[i])
            
            processed_count = len(feature_data)
            self.file_stats[str(csv_file)] = {
                'samples': processed_count,
                'normal_count': processed_labels.count('normal'),
                'attack_count': processed_labels.count('attack')
            }
            
            print(f"  Successfully processed {processed_count} samples")
            return processed_count
            
        except Exception as e:
            print(f"  Error processing CSV file {csv_file}: {e}")
            return 0
    
    def _detect_label_column(self, df):
        """Detect which column contains the labels"""
        possible_labels = ['label', 'class', 'attack', 'category', 'target', 'y', 'output']
        
        # Check exact matches first
        for col in df.columns:
            if col.lower() in possible_labels:
                return col
        
        # Check partial matches
        for col in df.columns:
            for label_name in possible_labels:
                if label_name in col.lower():
                    return col
        
        # Check for columns with categorical/string data that might be labels
        for col in df.columns:
            if df[col].dtype == 'object':
                unique_values = df[col].unique()
                if len(unique_values) < 50:  # Reasonable number of classes
                    sample_values = [str(v).lower() for v in unique_values[:10]]
                    if any(attack in ' '.join(sample_values) for attack in ['normal', 'attack', 'dos', 'probe']):
                        return col
        
        return None
    
    def _process_labels(self, labels, default_label):
        """Process and normalize labels to binary classification"""
        processed_labels = []
        
        for label in labels:
            label_str = str(label).strip().lower()
            
            # Map various label formats to binary
            if label_str in ['normal', 'benign', '0', 'legitimate']:
                processed_labels.append('normal')
            elif label_str in ['attack', 'anomaly', '1', 'malicious']:
                processed_labels.append('attack')
            elif any(attack in label_str for attack in ['dos', 'probe', 'r2l', 'u2r', 'ddos', 'portscan']):
                processed_labels.append('attack')
            else:
                # Default based on file context
                processed_labels.append(default_label)
        
        return processed_labels
    
    def _process_csv_features(self, df):
        """Process CSV features to match our expected format"""
        # Handle categorical columns
        for col in df.columns:
            if df[col].dtype == 'object':
                try:
                    # Try to convert to numeric first
                    df[col] = pd.to_numeric(df[col], errors='coerce')
                except:
                    # Use label encoding for categorical
                    le = LabelEncoder()
                    df[col] = le.fit_transform(df[col].astype(str))
        
        # Fill NaN values
        df = df.fillna(0)
        
        # Ensure all values are numeric
        for col in df.columns:
            df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        # Adjust to our expected feature count
        target_features = len(self.feature_names)
        current_features = df.shape[1]
        
        if current_features > target_features:
            # Take first N features
            df = df.iloc[:, :target_features]
            print(f"    Using first {target_features} features from {current_features} available")
        elif current_features < target_features:
            # Pad with zeros
            for i in range(target_features - current_features):
                df[f'pad_{i}'] = 0
            print(f"    Padded {target_features - current_features} features with zeros")
        
        return df.values.tolist()
    
    def _process_raw_text_file(self, file_path, default_label):
        """Process files that couldn't be parsed as CSV"""
        try:
            print(f"  Processing as raw text file...")
            
            # Read raw lines
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
            
            processed_count = 0
            for line_num, line in enumerate(lines[:1000]):  # Limit to first 1000 lines
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                
                # Try to extract numeric features from the line
                parts = line.replace(',', ' ').replace(';', ' ').replace('\t', ' ').split()
                numeric_parts = []
                
                for part in parts:
                    try:
                        num = float(part)
                        numeric_parts.append(num)
                    except:
                        # Convert non-numeric to hash or skip
                        if len(part) > 0:
                            numeric_parts.append(hash(part) % 1000)
                
                if len(numeric_parts) > 5:  # Must have reasonable number of features
                    # Pad or truncate to expected size
                    target_size = len(self.feature_names)
                    if len(numeric_parts) > target_size:
                        features = numeric_parts[:target_size]
                    else:
                        features = numeric_parts + [0] * (target_size - len(numeric_parts))
                    
                    self.features.append(features)
                    self.labels.append(default_label)
                    processed_count += 1
            
            print(f"    Extracted {processed_count} samples from raw text")
            return processed_count
            
        except Exception as e:
            print(f"    Error processing raw text file: {e}")
            return 0
    
    def extract_features_from_pcap(self, pcap_file, label='normal', max_packets=None):
        """Enhanced PCAP processing with better memory management"""
        print(f"Processing PCAP: {pcap_file} (label: {label})")
        start_time = time.time()
        
        try:
            # Check file size and estimate packet count
            file_size = os.path.getsize(pcap_file)
            print(f"  File size: {file_size / 1024 / 1024:.1f} MB")
            
            # Load packets with memory consideration
            if file_size > 100 * 1024 * 1024:  # > 100MB
                print(f"  Large file detected, limiting to first 10000 packets")
                max_packets = min(max_packets or 10000, 10000)
            
            packets = rdpcap(str(pcap_file), count=max_packets)
            total_packets = len(packets)
            print(f"  Loaded {total_packets} packets")
            
            packet_features = []
            last_progress = 0
            
            for i, pkt in enumerate(packets):
                # Progress reporting
                progress = (i * 100) // total_packets
                if progress >= last_progress + 10:
                    elapsed = time.time() - start_time
                    rate = i / elapsed if elapsed > 0 else 0
                    eta = (total_packets - i) / rate if rate > 0 else 0
                    print(f"    Progress: {progress}% ({i}/{total_packets}) - {rate:.0f} pkt/s - ETA: {eta:.0f}s")
                    last_progress = progress
                
                features = self._extract_packet_features(pkt)
                if features:
                    packet_features.append(features)
            
            # Add to our dataset
            for features in packet_features:
                self.features.append(features)
                self.labels.append(label)
            
            processing_time = time.time() - start_time
            processed_count = len(packet_features)
            
            self.file_stats[str(pcap_file)] = {
                'samples': processed_count,
                'processing_time': processing_time,
                'packets_per_second': processed_count / processing_time if processing_time > 0 else 0
            }
            
            print(f"  Extracted {processed_count} features in {processing_time:.2f}s")
            return processed_count
            
        except Exception as e:
            print(f"  Error processing PCAP {pcap_file}: {e}")
            return 0
    
    def _extract_packet_features(self, pkt):
        """Extract features from individual packet (same as original but with error handling)"""
        try:
            features = {}
            
            # Basic packet info
            features['packet_size'] = len(pkt)
            features['timestamp'] = float(pkt.time) if hasattr(pkt, 'time') else 0
            
            # IP layer features
            if pkt.haslayer(IP):
                ip = pkt[IP]
                features['ip_len'] = ip.len
                features['ip_ttl'] = ip.ttl
                features['ip_proto'] = ip.proto
                features['ip_flags'] = ip.flags
                features['ip_frag'] = ip.frag
            else:
                features.update({
                    'ip_len': 0, 'ip_ttl': 0, 'ip_proto': 0,
                    'ip_flags': 0, 'ip_frag': 0
                })
            
            # TCP/UDP features
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                features['protocol'] = 6  # TCP
                features['src_port'] = tcp.sport
                features['dst_port'] = tcp.dport
                features['tcp_flags'] = tcp.flags
                features['tcp_window'] = tcp.window
                features['tcp_urgptr'] = tcp.urgptr
                features['payload_size'] = len(raw(tcp.payload)) if tcp.payload else 0
                
                # TCP flag analysis
                features['flag_fin'] = 1 if tcp.flags & 0x01 else 0
                features['flag_syn'] = 1 if tcp.flags & 0x02 else 0
                features['flag_rst'] = 1 if tcp.flags & 0x04 else 0
                features['flag_psh'] = 1 if tcp.flags & 0x08 else 0
                features['flag_ack'] = 1 if tcp.flags & 0x10 else 0
                features['flag_urg'] = 1 if tcp.flags & 0x20 else 0
                
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                features['protocol'] = 17  # UDP
                features['src_port'] = udp.sport
                features['dst_port'] = udp.dport
                features['tcp_flags'] = 0
                features['tcp_window'] = 0
                features['tcp_urgptr'] = 0
                features['payload_size'] = len(raw(udp.payload)) if udp.payload else 0
                
                # UDP doesn't have flags
                features.update({
                    'flag_fin': 0, 'flag_syn': 0, 'flag_rst': 0,
                    'flag_psh': 0, 'flag_ack': 0, 'flag_urg': 0
                })
            else:
                features.update({
                    'protocol': features.get('ip_proto', 0),
                    'src_port': 0, 'dst_port': 0, 'tcp_flags': 0,
                    'tcp_window': 0, 'tcp_urgptr': 0, 'payload_size': 0,
                    'flag_fin': 0, 'flag_syn': 0, 'flag_rst': 0,
                    'flag_psh': 0, 'flag_ack': 0, 'flag_urg': 0
                })
            
            # Port categorization
            features['is_well_known_port'] = 1 if features['dst_port'] < 1024 else 0
            features['is_ephemeral_port'] = 1 if features['src_port'] > 32767 else 0
            
            # Payload analysis (simplified for speed)
            features['payload_entropy'] = 0
            features['has_suspicious_strings'] = 0
            
            if features['payload_size'] > 0:
                try:
                    if pkt.haslayer(TCP) and pkt[TCP].payload:
                        payload = raw(pkt[TCP].payload)
                        features['payload_entropy'] = self._calculate_entropy(payload[:100])  # Limit analysis
                        features['has_suspicious_strings'] = self._check_suspicious_payload(payload[:200])
                    elif pkt.haslayer(UDP) and pkt[UDP].payload:
                        payload = raw(pkt[UDP].payload)
                        features['payload_entropy'] = self._calculate_entropy(payload[:100])
                        features['has_suspicious_strings'] = self._check_suspicious_payload(payload[:200])
                except:
                    pass
            
            return list(features.values())
            
        except Exception as e:
            return None
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy (optimized version)"""
        if len(data) == 0:
            return 0
        
        try:
            # Count byte frequencies
            byte_counts = defaultdict(int)
            for byte in data:
                byte_counts[byte] += 1
            
            # Calculate entropy
            entropy = 0
            data_len = len(data)
            for count in byte_counts.values():
                p = count / data_len
                if p > 0:
                    entropy -= p * np.log2(p)
            
            return entropy
        except:
            return 0
    
    def _check_suspicious_payload(self, payload):
        """Check for suspicious strings (optimized version)"""
        try:
            payload_str = payload.decode('utf-8', errors='ignore').lower()
            
            # Quick check for common attack patterns
            suspicious_patterns = [
                'union', 'select', 'drop', 'insert', 'delete',
                '../', '/etc/', '/bin/', 'cmd.exe',
                '<script', 'javascript:', 'eval(',
                'base64', 'shell', 'exploit'
            ]
            
            return 1 if any(pattern in payload_str for pattern in suspicious_patterns) else 0
        except:
            return 0
    
    def print_processing_summary(self):
        """Print summary of processed files"""
        print("\n" + "="*60)
        print("DATASET PROCESSING SUMMARY")
        print("="*60)
        
        total_samples = len(self.features)
        normal_count = self.labels.count('normal')
        attack_count = self.labels.count('attack')
        
        print(f"Total samples processed: {total_samples:,}")
        print(f"Normal samples: {normal_count:,} ({normal_count/total_samples*100:.1f}%)")
        print(f"Attack samples: {attack_count:,} ({attack_count/total_samples*100:.1f}%)")
        
        print(f"\nFiles processed: {len(self.file_stats)}")
        for filename, stats in self.file_stats.items():
            filename = Path(filename).name
            print(f"  {filename}: {stats['samples']:,} samples")
            if 'processing_time' in stats:
                print(f"    Processing time: {stats['processing_time']:.1f}s")
                print(f"    Rate: {stats['packets_per_second']:.0f} packets/s")
    
    def save_training_data(self, filename):
        """Save extracted features and labels with metadata"""
        data = {
            'features': self.features,
            'labels': self.labels,
            'feature_names': self.feature_names,
            'file_stats': self.file_stats,
            'processed_files': self.processed_files
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(data, f)
        
        print(f"Saved {len(self.features)} samples to {filename}")
        
        # Also save as CSV for external analysis
        csv_filename = str(filename).replace('.pkl', '.csv')
        df = pd.DataFrame(self.features, columns=self.feature_names)
        df['label'] = self.labels
        df.to_csv(csv_filename, index=False)
        print(f"Also saved as CSV: {csv_filename}")
    
    def load_training_data(self, filename):
        """Load training data from file"""
        with open(filename, 'rb') as f:
            data = pickle.load(f)
        
        self.features = data['features']
        self.labels = data['labels']
        if 'feature_names' in data:
            self.feature_names = data['feature_names']
        if 'file_stats' in data:
            self.file_stats = data['file_stats']
        
        print(f"Loaded {len(self.features)} samples from {filename}")

# The IDSModelTrainer class remains the same as in your original code
class IDSModelTrainer:
    """Train ML models for intrusion detection"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.label_encoder = LabelEncoder()
        self.feature_names = [
            'packet_size', 'timestamp', 'ip_len', 'ip_ttl', 'ip_proto', 'ip_flags', 'ip_frag',
            'protocol', 'src_port', 'dst_port', 'tcp_flags', 'tcp_window', 'tcp_urgptr',
            'payload_size', 'flag_fin', 'flag_syn', 'flag_rst', 'flag_psh', 'flag_ack', 'flag_urg',
            'is_well_known_port', 'is_ephemeral_port', 'payload_entropy', 'has_suspicious_strings'
        ]
    
    def prepare_data(self, features, labels):
        """Prepare data for training"""
        print("\nPreparing training data...")
        
        # Convert to numpy arrays
        X = np.array(features)
        y = np.array(labels)
        
        # Handle any NaN or infinite values
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)
        
        print(f"Data shape: {X.shape}")
        print(f"Label distribution: {dict(zip(*np.unique(y, return_counts=True)))}")
        
        return X, y_encoded, y
    
    def train_supervised_model(self, X, y):
        """Train supervised model (Random Forest)"""
        print("\nTraining supervised model (Random Forest)...")
        start_time = time.time()
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        # Scale features
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train model with optimized parameters
        model = RandomForestClassifier(
            n_estimators=100,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(X_train_scaled, y_train)
        
        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds")
        
        # Evaluate
        y_pred = model.predict(X_test_scaled)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"\nSupervised Model Performance:")
        print(f"Accuracy: {accuracy:.4f}")
        print(classification_report(y_test, y_pred, target_names=self.label_encoder.classes_))
        
        # Feature importance
        importances = model.feature_importances_
        feature_importance = list(zip(self.feature_names, importances))
        feature_importance.sort(key=lambda x: x[1], reverse=True)
        
        print("\nTop 10 Most Important Features:")
        for feature, importance in feature_importance[:10]:
            print(f"  {feature}: {importance:.4f}")
        
        self.models['supervised'] = model
        self.scalers['supervised'] = scaler
        
        return model, scaler
    
    def train_anomaly_model(self, X):
        """Train unsupervised anomaly detection model"""
        print("\nTraining anomaly detection model (Isolation Forest)...")
        start_time = time.time()
        
        # Scale features
        scaler = StandardScaler()
        X_scaled = scaler.fit_transform(X)
        
        # Train model with optimized parameters
        model = IsolationForest(
            contamination=0.1,  # Assume 10% anomalies
            random_state=42,
            n_estimators=100,
            max_samples='auto',
            max_features=0.8
        )
        
        model.fit(X_scaled)
        
        training_time = time.time() - start_time
        print(f"Training completed in {training_time:.2f} seconds")
        
        # Test on training data to see distribution
        anomaly_scores = model.decision_function(X_scaled)
        predictions = model.predict(X_scaled)
        
        print(f"Anomalies detected: {np.sum(predictions == -1)}/{len(predictions)} ({np.mean(predictions == -1)*100:.1f}%)")
        print(f"Anomaly score range: [{np.min(anomaly_scores):.3f}, {np.max(anomaly_scores):.3f}]")
        
        self.models['anomaly'] = model
        self.scalers['anomaly'] = scaler
        
        return model, scaler
    
    def save_models(self, model_dir='models'):
        """Save trained models"""
        model_path = Path(model_dir)
        model_path.mkdir(exist_ok=True)
        
        # Save models
        for model_name, model in self.models.items():
            model_file = model_path / f"{model_name}_model.pkl"
            scaler_file = model_path / f"{model_name}_scaler.pkl"
            
            with open(model_file, 'wb') as f:
                pickle.dump(model, f)
            
            with open(scaler_file, 'wb') as f:
                pickle.dump(self.scalers[model_name], f)
            
            print(f"Saved {model_name} model to {model_file}")
        
        # Save label encoder
        label_file = model_path / "label_encoder.pkl"
        with open(label_file, 'wb') as f:
            pickle.dump(self.label_encoder, f)
        
        # Save feature names
        feature_file = model_path / "feature_names.json"
        with open(feature_file, 'w') as f:
            json.dump(self.feature_names, f)
        
        print(f"Models saved to {model_path}")
    
    def create_model_config(self, output_file='model_config.json'):
        """Create configuration file for the IDS"""
        config = {
            "model_files": {
                "anomaly_model": "models/anomaly_model.pkl",
                "anomaly_scaler": "models/anomaly_scaler.pkl",
                "supervised_model": "models/supervised_model.pkl",
                "supervised_scaler": "models/supervised_scaler.pkl",
                "label_encoder": "models/label_encoder.pkl",
                "feature_names": "models/feature_names.json"
            },
            "thresholds": {
                "anomaly_threshold": -0.3,
                "confidence_threshold": 0.7
            },
            "feature_count": len(self.feature_names),
            "classes": self.label_encoder.classes_.tolist() if hasattr(self.label_encoder, 'classes_') else []
        }
        
        with open(output_file, 'w') as f:
            json.dump(config, f, indent=2)
        
        print(f"Model configuration saved to {output_file}")

def estimate_training_time(sample_count, has_pcap=False):
    """Estimate training time based on dataset size"""
    
    # Base estimates (seconds)
    csv_processing_rate = 10000  # samples per second
    pcap_processing_rate = 100   # packets per second
    
    rf_training_rate = 5000      # samples per second
    isolation_forest_rate = 8000 # samples per second
    
    processing_time = 0
    if has_pcap:
        processing_time = sample_count / pcap_processing_rate
    else:
        processing_time = sample_count / csv_processing_rate
    
    rf_time = sample_count / rf_training_rate
    if_time = sample_count / isolation_forest_rate
    
    total_time = processing_time + rf_time + if_time
    
    print(f"\n=== TRAINING TIME ESTIMATES ===")
    print(f"Dataset size: {sample_count:,} samples")
    print(f"Data processing: {processing_time:.1f} seconds")
    print(f"Random Forest training: {rf_time:.1f} seconds")
    print(f"Isolation Forest training: {if_time:.1f} seconds")
    print(f"Total estimated time: {total_time:.1f} seconds ({total_time/60:.1f} minutes)")
    
    if total_time > 3600:
        print(f"                      {total_time/3600:.1f} hours")
    
    return total_time

def main():
    parser = argparse.ArgumentParser(
        description="Enhanced ML Trainer for CIC-IDS-2017 and Network Datasets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 enhanced_ml_trainer.py                                    # Auto-detect datasets in 'datasets' folder
  python3 enhanced_ml_trainer.py --dataset-dir /path/to/data        # Specify dataset directory
  python3 enhanced_ml_trainer.py --max-samples 50000               # Limit total samples
  python3 enhanced_ml_trainer.py --max-packets 5000                # Limit packets per PCAP
  python3 enhanced_ml_trainer.py --save-data features.pkl          # Save extracted features
  python3 enhanced_ml_trainer.py --load-data features.pkl          # Load pre-extracted features
        """
    )
    
    parser.add_argument("--dataset-dir", default="datasets", 
                       help="Directory containing dataset files (default: datasets)")
    parser.add_argument("--max-samples", type=int, 
                       help="Maximum number of samples to process")
    parser.add_argument("--max-packets", type=int, default=10000,
                       help="Maximum packets per PCAP file (default: 10000)")
    parser.add_argument("--save-data", 
                       help="Save extracted features to file")
    parser.add_argument("--load-data", 
                       help="Load pre-extracted training data")
    parser.add_argument("--model-dir", default="models", 
                       help="Directory to save models (default: models)")
    parser.add_argument("--quick-test", action="store_true",
                       help="Quick test with limited data")
    
    args = parser.parse_args()
    
    if args.quick_test:
        args.max_samples = 1000
        args.max_packets = 500
        print("=== QUICK TEST MODE ===")
    
    print("=== Enhanced IDS ML Model Training ===")
    print(f"Dataset directory: {args.dataset_dir}")
    print(f"Max samples: {args.max_samples or 'unlimited'}")
    print(f"Max packets per PCAP: {args.max_packets}")
    
    collector = EnhancedNetworkDataCollector()
    trainer = IDSModelTrainer()
    
    total_start_time = time.time()
    
    # Load existing data or process datasets
    if args.load_data:
        if not Path(args.load_data).exists():
            print(f"Error: Training data file '{args.load_data}' not found!")
            return
        collector.load_training_data(args.load_data)
    else:
        # Detect and process datasets automatically
        normal_files, attack_files = collector.detect_datasets(args.dataset_dir)
        
        if not normal_files and not attack_files:
            print("\n❌ No dataset files found!")
            print(f"Please place your dataset files in the '{args.dataset_dir}' directory")
            print("Supported formats: .pcap, .pcapng, .csv, .txt")
            print("File naming tips:")
            print("  - Include 'normal', 'benign', or day names for normal traffic")
            print("  - Include 'attack', 'dos', 'ddos', 'portscan' etc. for attack traffic")
            return
        
        total_samples = 0
        all_files = normal_files + attack_files
        
        print(f"\n=== PROCESSING {len(all_files)} FILES ===")
        
        # Process all files
        for i, file_path in enumerate(all_files):
            if args.max_samples and total_samples >= args.max_samples:
                print(f"✅ Reached maximum sample limit: {args.max_samples}")
                break
            
            print(f"\n[{i+1}/{len(all_files)}] Processing: {file_path.name}")
            
            # Determine label based on file classification
            if file_path in normal_files:
                default_label = 'normal'
            else:
                default_label = 'attack'
            
            # Process based on file type
            if file_path.suffix.lower() in ['.csv', '.txt', '.data']:
                samples = collector.process_csv_dataset(file_path, default_label)
            elif file_path.suffix.lower() in ['.pcap', '.pcapng']:
                remaining_samples = args.max_samples - total_samples if args.max_samples else None
                max_packets_for_file = min(args.max_packets, remaining_samples or args.max_packets)
                samples = collector.extract_features_from_pcap(
                    file_path, default_label, max_packets_for_file
                )
            else:
                print(f"  ⚠️  Unknown file type: {file_path.suffix}")
                continue
            
            total_samples += samples
            print(f"  ✅ Added {samples:,} samples (total: {total_samples:,})")
        
        # Print processing summary
        collector.print_processing_summary()
        
        # Save extracted data if requested
        if args.save_data:
            collector.save_training_data(args.save_data)
    
    if not collector.features:
        print("\n❌ No training data available!")
        return
    
    # Check if we have enough data
    sample_count = len(collector.features)
    if sample_count < 100:
        print(f"\n⚠️  Warning: Only {sample_count} samples available. Consider using more data for better results.")
    
    # Estimate training time
    has_pcap = any(f.suffix.lower() in ['.pcap', '.pcapng'] for f in (normal_files + attack_files) if 'normal_files' in locals())
    estimate_training_time(sample_count, has_pcap)
    
    print(f"\n=== STARTING TRAINING ===")
    
    # Prepare data
    X, y_encoded, y_original = trainer.prepare_data(collector.features, collector.labels)
    
    # Check class distribution
    unique_labels = np.unique(y_original)
    print(f"Found {len(unique_labels)} classes: {unique_labels}")
    
    # Train models
    if len(unique_labels) > 1:
        print("✅ Multiple classes found - training supervised model...")
        trainer.train_supervised_model(X, y_encoded)
    else:
        print("⚠️  Only one class found - skipping supervised training")
    
    # Always train anomaly detection model
    print("✅ Training anomaly detection model...")
    trainer.train_anomaly_model(X)
    
    # Save models
    print(f"\n=== SAVING MODELS ===")
    trainer.save_models(args.model_dir)
    trainer.create_model_config()
    
    total_time = time.time() - total_start_time
    print(f"\n🎉 === TRAINING COMPLETED ===")
    print(f"Total time: {total_time:.2f} seconds ({total_time/60:.1f} minutes)")
    print(f"Processed {len(collector.features):,} samples")
    print(f"Models saved in: {args.model_dir}/")
    print("✅ Models are ready for use with your NIDS!")
    
    # Show next steps
    print(f"\n📋 === NEXT STEPS ===")
    print("1. Test your models:")
    print(f"   python3 test_models.py --model-dir {args.model_dir}")
    print("2. Integrate with your NIDS:")
    print("   Update your NIDS to load the trained models")
    print("3. Monitor performance and retrain as needed")

if __name__ == "__main__":
    main()