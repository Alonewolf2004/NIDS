"""
Enhanced Performance-Optimized NIDS ML Model Training
Optimized for large files with progress bars and memory management
FIXED VERSION - Resolved tqdm import and callable issues
"""

import pandas as pd
import numpy as np
import pickle
import time
import glob
import os
from pathlib import Path
from datetime import datetime
import json
import argparse
import warnings
import hashlib
from collections import defaultdict, deque
import logging
import threading
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
import psutil  # For memory monitoring
import gc  # Garbage collection
warnings.filterwarnings('ignore')

# FIXED: Import tqdm correctly
try:
    from tqdm import tqdm as tqdm_bar  # Rename to avoid conflicts
except ImportError:
    # Fallback if tqdm not available
    class tqdm_bar:
        def __init__(self, total=None, desc="", unit="", ncols=None):
            self.total = total
            self.desc = desc
            self.current = 0
            print(f"{desc}: Starting...")
        
        def update(self, n=1):
            self.current += n
            if self.total:
                pct = (self.current / self.total) * 100
                print(f"{self.desc}: {self.current}/{self.total} ({pct:.1f}%)")
            else:
                print(f"{self.desc}: {self.current} processed")
        
        def close(self):
            print(f"{self.desc}: Complete!")
        
        def __enter__(self):
            return self
        
        def __exit__(self, *args):
            self.close()

# Enhanced ML imports
from sklearn.ensemble import (
    RandomForestClassifier, 
    IsolationForest, 
    GradientBoostingClassifier,
    ExtraTreesClassifier,
    VotingClassifier
)
from sklearn.svm import OneClassSVM
from sklearn.neighbors import LocalOutlierFactor
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler, MinMaxScaler
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score,
    f1_score
)
from sklearn.feature_selection import SelectKBest, f_classif, mutual_info_classif
from imblearn.over_sampling import SMOTE, BorderlineSMOTE
from imblearn.under_sampling import RandomUnderSampler, EditedNearestNeighbours
import joblib

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class MemoryManager:
    """Memory monitoring and management utilities"""
    
    @staticmethod
    def get_memory_usage():
        """Get current memory usage in MB"""
        process = psutil.Process()
        return process.memory_info().rss / 1024 / 1024
    
    @staticmethod
    def get_available_memory():
        """Get available system memory in MB"""
        return psutil.virtual_memory().available / 1024 / 1024
    
    @staticmethod
    def check_memory_threshold(threshold_mb=1000):
        """Check if available memory is below threshold"""
        return MemoryManager.get_available_memory() < threshold_mb
    
    @staticmethod
    def force_garbage_collect():
        """Force garbage collection"""
        gc.collect()

class EnhancedPacketFeatureExtractor:
    """Enhanced feature extraction for network packets"""
    
    def __init__(self):
        # Extended feature set optimized for NIDS (35 features)
        self.feature_names = [
            # Basic packet features
            'packet_size', 'protocol', 'src_port', 'dst_port', 'tcp_flags',
            'payload_size', 'header_length', 'ttl', 'window_size',
            
            # Port analysis
            'is_well_known_port', 'port_difference', 'src_port_category', 'dst_port_category',
            
            # Payload analysis
            'payload_entropy', 'payload_ascii_ratio', 'payload_suspicious_strings',
            'payload_hex_patterns', 'payload_compression_ratio',
            
            # Flow-based features
            'packets_per_second', 'bytes_per_second', 'avg_packet_size', 
            'packet_size_variance', 'inter_arrival_time_mean', 'inter_arrival_time_std',
            
            # Protocol-specific features
            'tcp_syn_flag', 'tcp_ack_flag', 'tcp_rst_flag', 'tcp_fin_flag',
            'flags_count', 'protocol_anomaly_score',
            
            # Attack indicators
            'port_scan_indicator', 'dos_indicator', 'connection_state',
            'packet_direction_entropy', 'suspicious_payload_ratio'
        ]
        
        # Suspicious patterns for signature enhancement
        self.suspicious_patterns = {
            'sql_injection': [b'union', b'select', b'drop', b'exec', b'script'],
            'xss': [b'<script', b'javascript:', b'onerror', b'onload'],
            'shellcode': [b'\x90\x90', b'\xcc\xcc', b'\x31\xc0'],
            'port_scan': [b'nmap', b'masscan'],
            'buffer_overflow': [b'\x41' * 10, b'\x42' * 10]  # AAAA, BBBB patterns
        }
    
    def extract_enhanced_features(self, packet_data):
        """Extract comprehensive features from packet data"""
        features = [0.0] * len(self.feature_names)
        
        try:
            # Basic packet info
            features[0] = len(packet_data.get('raw_data', b''))  # packet_size
            features[1] = self._encode_protocol(packet_data.get('protocol', 'unknown'))
            features[2] = packet_data.get('src_port', 0)
            features[3] = packet_data.get('dst_port', 0)
            features[4] = packet_data.get('tcp_flags', 0)
            
            # Payload analysis
            payload = packet_data.get('payload', b'')
            features[5] = len(payload)  # payload_size
            features[14] = self._calculate_entropy(payload) if payload else 0  # payload_entropy
            features[15] = self._ascii_ratio(payload) if payload else 0  # payload_ascii_ratio
            features[16] = self._detect_suspicious_strings(payload)  # payload_suspicious_strings
            
            # Port categorization
            features[9] = 1 if features[2] < 1024 or features[3] < 1024 else 0  # is_well_known_port
            features[10] = abs(features[2] - features[3])  # port_difference
            features[11] = self._categorize_port(features[2])  # src_port_category
            features[12] = self._categorize_port(features[3])  # dst_port_category
            
            # Attack indicators
            features[-3] = self._detect_port_scan(packet_data)  # port_scan_indicator
            features[-2] = self._detect_dos_patterns(packet_data)  # dos_indicator
            features[-1] = self._calculate_suspicious_ratio(payload)  # suspicious_payload_ratio
            
        except Exception as e:
            logger.warning(f"Feature extraction error: {e}")
        
        return features
    
    def _calculate_entropy(self, data):
        """Calculate Shannon entropy of data"""
        if not data:
            return 0
        
        # Get byte frequency
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        # Calculate entropy
        entropy = 0
        length = len(data)
        for count in byte_counts.values():
            if count > 0:
                prob = count / length
                entropy -= prob * np.log2(prob)
        
        return entropy
    
    def _ascii_ratio(self, data):
        """Calculate ratio of ASCII printable characters"""
        if not data:
            return 0
        
        ascii_count = sum(1 for byte in data if 32 <= byte <= 126)
        return ascii_count / len(data)
    
    def _detect_suspicious_strings(self, payload):
        """Detect suspicious patterns in payload"""
        if not payload:
            return 0
        
        payload_lower = payload.lower()
        score = 0
        
        for category, patterns in self.suspicious_patterns.items():
            for pattern in patterns:
                if pattern in payload_lower:
                    score += 1
        
        return min(score, 5)  # Cap at 5
    
    def _categorize_port(self, port):
        """Categorize port into ranges"""
        if port < 1024:
            return 1  # Well-known
        elif port < 49152:
            return 2  # Registered
        else:
            return 3  # Dynamic/Private
    
    def _encode_protocol(self, protocol):
        """Encode protocol to numeric"""
        protocol_map = {'tcp': 6, 'udp': 17, 'icmp': 1, 'igmp': 2, 'unknown': 0}
        return protocol_map.get(protocol.lower(), 0)
    
    def _detect_port_scan(self, packet_data):
        """Detect potential port scanning behavior"""
        # Simple heuristic - multiple destination ports from same source
        return 1 if packet_data.get('unique_dst_ports', 0) > 10 else 0
    
    def _detect_dos_patterns(self, packet_data):
        """Detect DoS attack patterns"""
        # High packet rate or unusual packet sizes
        pps = packet_data.get('packets_per_second', 0)
        return 1 if pps > 1000 else 0
    
    def _calculate_suspicious_ratio(self, payload):
        """Calculate overall suspiciousness ratio"""
        if not payload:
            return 0
        
        suspicious_score = 0
        suspicious_score += self._detect_suspicious_strings(payload)
        suspicious_score += 1 if self._calculate_entropy(payload) > 7.5 else 0
        suspicious_score += 1 if self._ascii_ratio(payload) < 0.1 else 0
        
        return min(suspicious_score / 7.0, 1.0)  # Normalize to [0,1]


class OptimizedIncrementalDataCollector:
    """Enhanced collector with memory management and progress tracking"""
    
    def __init__(self, cache_size=10000):
        self.features = []
        self.labels = []
        self.feature_extractor = EnhancedPacketFeatureExtractor()
        
        # Performance enhancements
        self.processed_files_cache = set()
        self.feature_cache = deque(maxlen=cache_size)
        self.processing_stats = defaultdict(float)
        
        # Memory management
        self.memory_threshold_mb = 2000  # 2GB threshold
        self.chunk_size = 10000  # Process in chunks
        
        self.session_stats = {
            'total_files_processed': 0,
            'total_samples': 0,
            'session_start': datetime.now(),
            'files_completed': [],
            'class_distribution': defaultdict(int),
            'processing_errors': [],
            'cache_hits': 0,
            'feature_extraction_time': 0,
            'memory_peaks': []
        }
    
    def detect_datasets(self, dataset_dir='datasets'):
        """Enhanced dataset detection with size information"""
        dataset_path = Path(dataset_dir)
        if not dataset_path.exists():
            logger.error(f"Dataset directory '{dataset_dir}' not found!")
            return []
        
        logger.info(f"Scanning dataset directory: {dataset_path}")
        
        # Parallel file discovery
        file_extensions = ['*.csv', '*.txt', '*.data', '*.tsv', '*.json', '*.pcap']
        all_files = []
        
        with ThreadPoolExecutor(max_workers=4) as executor:
            futures = []
            for ext in file_extensions:
                future = executor.submit(self._find_files_by_extension, dataset_path, ext)
                futures.append(future)
            
            for future in futures:
                all_files.extend(future.result())
        
        # Enhanced deduplication with content hashing
        unique_files = self._deduplicate_files_advanced(all_files)
        
        if not unique_files:
            logger.error("No dataset files found")
            return []
        
        logger.info(f"Found {len(unique_files)} unique files (removed {len(all_files) - len(unique_files)} duplicates)")
        
        # Sort by size (smallest first for efficient processing)
        unique_files.sort(key=lambda x: x.stat().st_size)
        
        # Display files with enhanced info
        self._display_file_info(unique_files)
        
        return unique_files
    
    def _find_files_by_extension(self, dataset_path, ext):
        """Find files by extension in parallel"""
        files = list(dataset_path.glob(ext))
        files.extend(list(dataset_path.glob(f"**/{ext}")))
        return [f for f in files if not f.name.startswith('.')]
    
    def _deduplicate_files_advanced(self, all_files):
        """Advanced deduplication using content hashing"""
        unique_files = {}
        
        for file_path in all_files:
            try:
                # Fast hash based on size and first 1KB
                stat = file_path.stat()
                with open(file_path, 'rb') as f:
                    first_chunk = f.read(1024)
                
                file_hash = hashlib.md5(f"{stat.st_size}{first_chunk}".encode()).hexdigest()
                
                if file_hash not in unique_files:
                    unique_files[file_hash] = file_path
                
            except Exception as e:
                logger.warning(f"Error processing {file_path}: {e}")
        
        return list(unique_files.values())
    
    def _display_file_info(self, files_list):
        """Display enhanced file information with size warnings"""
        logger.info("\n📋 === DATASET FILES ===")
        total_size = 0
        
        for i, file_path in enumerate(files_list, 1):
            size_mb = file_path.stat().st_size / (1024 * 1024)
            size_gb = size_mb / 1024
            total_size += size_mb
            file_type = file_path.suffix.upper()[1:] if file_path.suffix else "Unknown"
            
            # Add size warnings
            size_warning = ""
            if size_gb >= 20:
                size_warning = " ⚠️ VERY LARGE"
            elif size_gb >= 5:
                size_warning = " ⚠️ LARGE"
            elif size_gb >= 1:
                size_warning = " 📊 MEDIUM"
            
            if size_gb >= 1:
                logger.info(f"  {i:2d}. {file_path.name} ({size_gb:.1f} GB, {file_type}){size_warning}")
            else:
                logger.info(f"  {i:2d}. {file_path.name} ({size_mb:.1f} MB, {file_type}){size_warning}")
        
        total_gb = total_size / 1024
        if total_gb >= 1:
            logger.info(f"Total size: {total_gb:.1f} GB")
        else:
            logger.info(f"Total size: {total_size:.1f} MB")
        
        # Memory warnings
        available_mem = MemoryManager.get_available_memory() / 1024  # GB
        if total_gb > available_mem * 0.8:
            logger.warning(f"⚠️ Total file size ({total_gb:.1f} GB) may exceed available memory ({available_mem:.1f} GB)")
            logger.info("💡 Files will be processed in chunks to manage memory usage")
    
    def process_single_file_chunked(self, file_path, max_samples=None):
        """Process single file in memory-efficient chunks"""
        logger.info(f"\n📁 Processing: {file_path.name}")
        
        # Get file size info
        file_size_mb = file_path.stat().st_size / (1024 * 1024)
        file_size_gb = file_size_mb / 1024
        
        if file_size_gb >= 1:
            logger.info(f"📊 File size: {file_size_gb:.1f} GB")
        else:
            logger.info(f"📊 File size: {file_size_mb:.1f} MB")
        
        # Check available memory
        available_mem = MemoryManager.get_available_memory()
        logger.info(f"💾 Available memory: {available_mem:.1f} MB")
        
        # Determine chunk size based on file size and available memory
        chunk_size = self._calculate_optimal_chunk_size(file_size_mb, available_mem)
        logger.info(f"🔧 Using chunk size: {chunk_size:,} rows")
        
        start_time = time.time()
        total_samples_added = 0
        
        try:
            if file_path.suffix.lower() == '.pcap':
                samples_added = self._process_pcap_file(file_path, max_samples)
                total_samples_added = samples_added
            elif file_path.suffix.lower() == '.json':
                samples_added = self._process_json_file_chunked(file_path, max_samples, chunk_size)
                total_samples_added = samples_added
            else:
                # CSV processing in chunks - FIXED: This was the main source of the error
                total_samples_added = self._process_csv_file_chunked(file_path, max_samples, chunk_size)
            
            processing_time = time.time() - start_time
            self.processing_stats[file_path.suffix] += processing_time
            
            self._update_session_stats(file_path, total_samples_added, processing_time)
            
            # Memory cleanup
            MemoryManager.force_garbage_collect()
            
            return total_samples_added, "Success"
            
        except Exception as e:
            error_msg = f"Error processing {file_path.name}: {str(e)}"
            logger.error(error_msg)
            # Add detailed error info
            import traceback
            logger.error(f"Detailed error: {traceback.format_exc()}")
            return 0, error_msg
    
    def _calculate_optimal_chunk_size(self, file_size_mb, available_mem_mb):
        """Calculate optimal chunk size based on file size and available memory"""
        # Conservative approach - use 20% of available memory
        max_memory_for_chunk = available_mem_mb * 0.2
        
        # Estimate rows per MB (very rough estimate)
        estimated_rows_per_mb = 1000  # Adjust based on your data
        
        # Calculate chunk size
        if file_size_mb <= 100:  # Small file
            chunk_size = 50000
        elif file_size_mb <= 1000:  # Medium file (up to 1GB)
            chunk_size = 25000
        elif file_size_mb <= 5000:  # Large file (up to 5GB)
            chunk_size = 10000
        else:  # Very large file (>5GB)
            chunk_size = 5000
        
        # Ensure chunk size doesn't exceed memory limits
        max_chunk_by_memory = int(max_memory_for_chunk * estimated_rows_per_mb)
        chunk_size = min(chunk_size, max_chunk_by_memory)
        
        return max(1000, chunk_size)  # Minimum 1000 rows
    
    def _process_csv_file_chunked(self, csv_file, max_samples=None, chunk_size=10000):
        """Process CSV file in memory-efficient chunks with progress bar - FIXED VERSION"""
        logger.info(f"🔄 Processing {csv_file.name} in chunks of {chunk_size:,} rows")
        
        # First, count total rows for progress bar
        total_rows = self._count_csv_rows(csv_file)
        if total_rows == 0:
            return 0
        
        logger.info(f"📊 Total rows to process: {total_rows:,}")
        
        # Calculate number of chunks
        num_chunks = (total_rows + chunk_size - 1) // chunk_size
        logger.info(f"📦 Will process in {num_chunks} chunks")
        
        total_samples_added = 0
        processed_rows = 0
        
        # Initialize progress bar - FIXED: Use proper tqdm import
        with tqdm_bar(total=min(total_rows, max_samples or total_rows), 
                     desc=f"Processing {csv_file.name}", 
                     unit="rows",
                     ncols=80) as pbar:
            
            try:
                # FIXED: Detect separator first to avoid auto-detection issues
                separator = self._detect_csv_separator(csv_file)
                
                # Process file in chunks - FIXED: Removed problematic parameters
                chunk_iter = pd.read_csv(
                    csv_file,
                    chunksize=chunk_size,
                    low_memory=False,
                    na_values=['?', 'NaN', 'NULL', '', 'n/a', 'N/A'],
                    encoding='utf-8',
                    sep=separator,  # Use detected separator
                    on_bad_lines='skip'  # Skip problematic lines instead of failing
                )
                
                for chunk_num, chunk_df in enumerate(chunk_iter, 1):
                    try:
                        # Memory check before processing chunk
                        if MemoryManager.check_memory_threshold(1000):  # 1GB threshold
                            logger.warning("⚠️ Low memory, forcing garbage collection...")
                            MemoryManager.force_garbage_collect()
                            
                            # Still low memory? Break
                            if MemoryManager.check_memory_threshold(500):
                                logger.warning("⚠️ Memory critically low, stopping chunk processing")
                                break
                        
                        logger.debug(f"Processing chunk {chunk_num}/{num_chunks} ({len(chunk_df):,} rows)")
                        
                        # Process chunk
                        chunk_samples = self._process_dataframe_chunk(chunk_df, csv_file.name)
                        total_samples_added += chunk_samples
                        processed_rows += len(chunk_df)
                        
                        # Update progress bar
                        pbar.update(len(chunk_df))
                        
                        # Update memory usage stats
                        current_memory = MemoryManager.get_memory_usage()
                        self.session_stats['memory_peaks'].append(current_memory)
                        
                        # Check if we've reached the sample limit
                        if max_samples and total_samples_added >= max_samples:
                            logger.info(f"✅ Reached sample limit ({max_samples:,}), stopping")
                            break
                        
                        # Small delay to prevent overwhelming the system
                        if chunk_num % 10 == 0:
                            time.sleep(0.1)
                            
                    except Exception as chunk_error:
                        logger.warning(f"Error processing chunk {chunk_num}: {chunk_error}")
                        continue  # Skip problematic chunk and continue
            
            except pd.errors.EmptyDataError:
                logger.warning(f"Empty or invalid CSV file: {csv_file.name}")
            except Exception as e:
                logger.error(f"Error reading CSV chunks: {e}")
                import traceback
                logger.error(f"Detailed error: {traceback.format_exc()}")
        
        logger.info(f"✅ Processed {processed_rows:,} rows, extracted {total_samples_added:,} samples")
        return total_samples_added
    
    def _detect_csv_separator(self, csv_file):
        """Detect CSV separator to avoid auto-detection issues"""
        try:
            with open(csv_file, 'r', encoding='utf-8') as f:
                first_line = f.readline()
                
            # Count common separators
            separators = [',', ';', '\t', '|']
            separator_counts = {sep: first_line.count(sep) for sep in separators}
            
            # Return the most common separator
            best_separator = max(separator_counts.items(), key=lambda x: x[1])[0]
            
            # If no clear winner, default to comma
            if separator_counts[best_separator] == 0:
                return ','
            
            logger.debug(f"Detected separator: '{best_separator}' in {csv_file.name}")
            return best_separator
            
        except Exception as e:
            logger.warning(f"Could not detect separator for {csv_file.name}: {e}")
            return ','  # Default to comma
    
    def _count_csv_rows(self, csv_file):
        """Efficiently count rows in CSV file"""
        try:
            # Try to get row count efficiently
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                row_count = sum(1 for _ in f) - 1  # Subtract header
            return max(0, row_count)
        except Exception as e:
            logger.warning(f"Could not count rows in {csv_file}: {e}")
            return 0
    
    def _process_dataframe_chunk(self, df, filename):
        """Process a single DataFrame chunk - FIXED VERSION"""
        if df.empty:
            return 0
        
        try:
            # Enhanced label detection
            label_column = self._detect_label_column_enhanced(df)
            if label_column:
                labels = df[label_column].values
                df = df.drop(label_column, axis=1)
            else:
                labels = [self._guess_label_from_filename(filename)] * len(df)
            
            # Process labels with enhanced mapping
            processed_labels = self._process_labels_enhanced(labels)
            
            # Enhanced preprocessing
            df = self._preprocess_dataframe_enhanced(df)
            
            if df.empty:
                return 0
            
            # Create features using enhanced extractor
            features = self._create_features_enhanced(df)
            
            # Add to collection
            self._add_features_batch(features, processed_labels)
            
            return len(features)
            
        except Exception as e:
            logger.warning(f"Error processing DataFrame chunk: {e}")
            return 0
    
    def _process_json_file_chunked(self, json_file, max_samples=None, chunk_size=10000):
        """Process JSON files in chunks"""
        try:
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            if isinstance(data, list):
                records = data
            elif isinstance(data, dict) and 'records' in data:
                records = data['records']
            else:
                return 0
            
            total_records = len(records)
            logger.info(f"📊 JSON file has {total_records:,} records")
            
            # Limit samples
            if max_samples and total_records > max_samples:
                records = records[:max_samples]
                total_records = len(records)
            
            # Process in chunks
            total_samples_added = 0
            
            with tqdm_bar(total=total_records, desc=f"Processing {json_file.name}", unit="records") as pbar:
                for i in range(0, total_records, chunk_size):
                    chunk = records[i:i + chunk_size]
                    
                    features = []
                    labels = []
                    
                    for record in chunk:
                        feature_vec = self.feature_extractor.extract_enhanced_features(record)
                        features.append(feature_vec)
                        labels.append(record.get('label', 'normal'))
                    
                    processed_labels = self._process_labels_enhanced(labels)
                    self._add_features_batch(features, processed_labels)
                    
                    total_samples_added += len(features)
                    pbar.update(len(chunk))
                    
                    # Memory check
                    if MemoryManager.check_memory_threshold(1000):
                        MemoryManager.force_garbage_collect()
            
            return total_samples_added
            
        except Exception as e:
            logger.error(f"JSON processing error: {e}")
            return 0
    
    def _process_pcap_file(self, pcap_file, max_samples=None):
        """Process PCAP files (placeholder - requires additional libraries)"""
        logger.warning(f"PCAP processing not implemented for {pcap_file.name}")
        return 0
    
    def _detect_label_column_enhanced(self, df):
        """Enhanced label column detection"""
        # Priority patterns
        priority_patterns = ['label', 'class', 'attack', 'target', 'category']
        
        # Check exact matches first
        for pattern in priority_patterns:
            exact_matches = [col for col in df.columns if pattern == col.lower()]
            if exact_matches:
                return exact_matches[0]
        
        # Check partial matches
        for pattern in priority_patterns:
            partial_matches = [col for col in df.columns if pattern in col.lower()]
            if partial_matches:
                return partial_matches[0]
        
        # Check last column with reasonable cardinality
        last_col = df.columns[-1]
        if (df[last_col].dtype in ['object', 'category'] and 
            2 <= df[last_col].nunique() <= 50):
            return last_col
        
        # Check for binary columns
        for col in reversed(df.columns):
            if df[col].nunique() == 2:
                return col
        
        return None
    
    def _process_labels_enhanced(self, labels):
        """Enhanced label processing with more attack categories"""
        processed = []
        
        # Extended attack categorization
        attack_categories = {
            'dos': {'back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 
                   'udpstorm', 'mailbomb', 'slowhttptest', 'slowloris', 'hulk'},
            'probe': {'ipsweep', 'nmap', 'portsweep', 'satan', 'saint', 'mscan'},
            'r2l': {'ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'spy',
                   'warezclient', 'warezmaster', 'sendmail', 'named', 'snmpgetattack', 'worm'},
            'u2r': {'buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'httptunnel', 
                   'ps', 'sqlattack', 'xterm'},
            'web': {'web_attack', 'sql_injection', 'xss', 'csrf', 'lfi', 'rfi'},
            'botnet': {'botnet', 'bot', 'conficker', 'zeus', 'mirai'},
            'malware': {'malware', 'virus', 'trojan', 'ransomware', 'adware'}
        }
        
        for label in labels:
            label_str = str(label).strip().lower()
            
            # Direct normal check
            if label_str in ['normal', 'benign', 'legitimate']:
                processed.append('normal')
                continue
            
            # Check against attack categories
            categorized = False
            for category, attacks in attack_categories.items():
                if label_str in attacks or any(attack in label_str for attack in attacks):
                    processed.append(category)
                    categorized = True
                    break
            
            if not categorized:
                # Fallback heuristics
                if any(word in label_str for word in ['attack', 'malicious', 'suspicious']):
                    processed.append('attack')
                else:
                    processed.append('normal')
        
        return processed
    
    def _preprocess_dataframe_enhanced(self, df):
        """Enhanced preprocessing with outlier detection"""
        if df.empty:
            return df
        
        # Handle infinite/NaN values
        df = df.replace([np.inf, -np.inf], np.nan)
        
        # Smart missing value imputation
        for col in df.columns:
            if df[col].dtype in ['object', 'category']:
                # Categorical: mode or 'unknown'
                mode_val = df[col].mode()
                fill_val = mode_val[0] if len(mode_val) > 0 else 'unknown'
                df[col] = df[col].fillna(fill_val)
                
                # Convert to numeric if possible
                df[col] = pd.to_numeric(df[col], errors='coerce')
            
            # Fill remaining NaN with median (more robust than mean)
            if df[col].isna().any():
                fill_val = df[col].median() if df[col].dtype != 'object' else 0
                df[col] = df[col].fillna(fill_val)
        
        # Remove constant columns
        constant_cols = [col for col in df.columns if df[col].nunique() <= 1]
        if constant_cols:
            df = df.drop(constant_cols, axis=1)
        
        return df
    
    def _create_features_enhanced(self, df):
        """Enhanced feature creation with domain knowledge"""
        features = []
        feature_count = len(self.feature_extractor.feature_names)
        
        for _, row in df.iterrows():
            # Initialize feature vector
            feature_vector = [0.0] * feature_count
            
            # Map available columns to feature positions
            for i, feature_name in enumerate(self.feature_extractor.feature_names):
                if i < len(row):
                    try:
                        value = float(row.iloc[i]) if i < df.shape[1] else 0.0
                        # Normalize extreme values
                        if abs(value) > 1e6:
                            value = np.sign(value) * 1e6
                        feature_vector[i] = value
                    except (ValueError, TypeError):
                        feature_vector[i] = 0.0
            
            # Add derived features if we have enough data
            if len(row) >= 4:  # Basic network packet info
                try:
                    # Port-based features
                    src_port = float(row.iloc[2]) if len(row) > 2 else 0
                    dst_port = float(row.iloc[3]) if len(row) > 3 else 0
                    
                    # Update port-related features
                    if feature_count > 10:
                        feature_vector[9] = 1 if src_port < 1024 or dst_port < 1024 else 0  # well_known_port
                        feature_vector[10] = abs(src_port - dst_port) if src_port and dst_port else 0  # port_diff
                except:
                    pass
            
            features.append(feature_vector)
        
        return features
    
    def _add_features_batch(self, features, labels):
        """Efficiently add features in batch"""
        start_time = time.time()
        
        # Batch append (more efficient than individual appends)
        self.features.extend(features)
        self.labels.extend(labels)
        
        # Update class distribution
        for label in labels:
            self.session_stats['class_distribution'][label] += 1
        
        # Cache recent features for quick access
        for i, (feature, label) in enumerate(zip(features, labels)):
            self.feature_cache.append((feature, label))
        
        self.session_stats['feature_extraction_time'] += time.time() - start_time
    
    def _guess_label_from_filename(self, filename):
        """Enhanced filename-based labeling"""
        filename_lower = filename.lower()
        
        # More specific patterns
        attack_indicators = {
            'dos': ['dos', 'ddos', 'flood', 'slowloris'],
            'probe': ['scan', 'probe', 'recon', 'nmap'],
            'malware': ['malware', 'virus', 'trojan', 'bot'],
            'web': ['web', 'http', 'sql', 'xss'],
            'attack': ['attack', 'malicious', 'intrusion']
        }
        
        for attack_type, indicators in attack_indicators.items():
            if any(indicator in filename_lower for indicator in indicators):
                return attack_type
        
        # Default to normal
        return 'normal'
    
    def _update_session_stats(self, file_path, samples_added, processing_time):
        """Enhanced session statistics"""
        self.session_stats['total_files_processed'] += 1
        self.session_stats['total_samples'] = len(self.features)
        
        file_info = {
            'filename': file_path.name,
            'samples': samples_added,
            'time': processing_time,
            'file_size_mb': file_path.stat().st_size / (1024 * 1024),
            'processing_rate': samples_added / processing_time if processing_time > 0 else 0
        }
        
        self.session_stats['files_completed'].append(file_info)
    
    def print_enhanced_summary(self):
        """Enhanced session summary with performance metrics"""
        duration = (datetime.now() - self.session_stats['session_start']).total_seconds()
        
        logger.info("\n📊 === ENHANCED SESSION SUMMARY ===")
        logger.info(f"⏱️  Session Duration: {duration:.1f}s")
        logger.info(f"📁 Files Processed: {self.session_stats['total_files_processed']}")
        logger.info(f"📊 Total Samples: {self.session_stats['total_samples']:,}")
        logger.info(f"🚀 Processing Rate: {self.session_stats['total_samples']/duration:.1f} samples/sec")
        
        # Memory usage stats
        if self.session_stats['memory_peaks']:
            max_memory = max(self.session_stats['memory_peaks'])
            avg_memory = np.mean(self.session_stats['memory_peaks'])
            logger.info(f"💾 Memory Usage: {avg_memory:.1f} MB avg, {max_memory:.1f} MB peak")
        
        # Class distribution analysis
        if self.session_stats['class_distribution']:
            logger.info("\n📈 Class Distribution:")
            total = sum(self.session_stats['class_distribution'].values())
            sorted_classes = sorted(self.session_stats['class_distribution'].items(), key=lambda x: x[1], reverse=True)
            
            for cls, count in sorted_classes:
                pct = count/total*100 if total > 0 else 0
                logger.info(f"  {cls}: {count:,} ({pct:.1f}%)")
            
            # Check for imbalance
            max_class = max(self.session_stats['class_distribution'].values())
            min_class = min(self.session_stats['class_distribution'].values())
            imbalance_ratio = max_class / min_class if min_class > 0 else float('inf')
            
            if imbalance_ratio > 10:
                logger.warning(f"⚠️  Class imbalance detected: {imbalance_ratio:.1f}:1 ratio")
        
        # Performance metrics
        if self.session_stats['files_completed']:
            avg_time = np.mean([f['time'] for f in self.session_stats['files_completed']])
            avg_rate = np.mean([f['processing_rate'] for f in self.session_stats['files_completed']])
            logger.info(f"\n⚡ Avg Processing Time: {avg_time:.1f}s per file")
            logger.info(f"⚡ Avg Processing Rate: {avg_rate:.1f} samples/sec")
        
        # Error reporting
        if self.session_stats['processing_errors']:
            logger.warning(f"\n⚠️  Errors encountered: {len(self.session_stats['processing_errors'])}")
            for error in self.session_stats['processing_errors'][-3:]:  # Show last 3
                logger.warning(f"  - {error}")
    
    def save_enhanced_progress(self, filename):
        """Save enhanced progress with metadata"""
        data = {
            'features': self.features,
            'labels': self.labels,
            'feature_names': self.feature_extractor.feature_names,
            'session_stats': dict(self.session_stats),
            'timestamp': datetime.now().isoformat(),
            'version': '2.0-enhanced'
        }
        
        with open(filename, 'wb') as f:
            pickle.dump(data, f, protocol=pickle.HIGHEST_PROTOCOL)
        
        logger.info(f"💾 Enhanced progress saved to {filename}")


class EnhancedModelTrainer:
    """Enhanced model trainer with real-time optimization"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.feature_selectors = {}
        self.label_encoder = LabelEncoder()
        self.training_history = []
        self.model_performance = {}
        
        # Performance optimization settings
        self.optimization_config = {
            'use_feature_selection': True,
            'max_training_samples': 100000,
            'cross_validation_folds': 3,
            'enable_ensemble': True,
            'balance_threshold': 5.0,
            'performance_threshold': 0.85
        }
    
    def enhanced_feasibility_check(self, labels):
        """Enhanced training feasibility assessment"""
        if not labels:
            logger.error("No labels provided")
            return False, "No data"
        
        unique_classes = set(labels)
        class_counts = {cls: labels.count(cls) for cls in unique_classes}
        
        # Minimum requirements
        if len(unique_classes) < 2:
            return False, f"Only {len(unique_classes)} class found"
        
        min_samples = min(class_counts.values())
        if min_samples < 5:
            return False, f"Minimum class has only {min_samples} samples"
        
        # Check for reasonable distribution
        max_samples = max(class_counts.values())
        imbalance_ratio = max_samples / min_samples
        
        logger.info(f"✅ Training feasible:")
        logger.info(f"  - Classes: {len(unique_classes)}")
        logger.info(f"  - Samples range: {min_samples}-{max_samples}")
        logger.info(f"  - Imbalance ratio: {imbalance_ratio:.1f}:1")
        
        if imbalance_ratio > 50:
            logger.warning(f"⚠️  Extreme imbalance detected: {imbalance_ratio:.1f}:1")
        
        return True, "Ready for training"
    
    def train_enhanced_models_with_progress(self, features, labels, enable_optimization=True):
        """Enhanced training with progress bars"""
        logger.info("\n🧠 === ENHANCED MODEL TRAINING ===")
        
        # Feasibility check
        feasible, message = self.enhanced_feasibility_check(labels)
        if not feasible:
            logger.error(f"❌ Training not feasible: {message}")
            return 0.0
        
        start_time = time.time()
        
        # Prepare data with optimizations
        logger.info("🔧 Preparing training data...")
        X, y = self._prepare_data_advanced(features, labels, enable_optimization)
        
        if X is None:
            return 0.0
        
        # Split with stratification
        logger.info("📊 Splitting data...")
        try:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.25, random_state=42, stratify=y
            )
        except ValueError:
            # Fallback if stratification fails
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.25, random_state=42
            )
        
        logger.info(f"📊 Training set: {X_train.shape[0]:,} samples")
        logger.info(f"📊 Test set: {X_test.shape[0]:,} samples")
        
        # Feature selection with progress
        if self.optimization_config['use_feature_selection'] and X_train.shape[1] > 20:
            logger.info("🎯 Performing feature selection...")
            X_train, X_test = self._perform_feature_selection(X_train, X_test, y_train)
        
        # Scaling with progress
        logger.info("📏 Scaling features...")
        scaler = self._get_optimal_scaler(X_train)
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train multiple models with progress
        logger.info("🚀 Training model suite...")
        models = self._train_optimized_model_suite_with_progress(X_train_scaled, X_test_scaled, y_train, y_test)
        
        # Model selection and ensemble
        logger.info("🏆 Selecting best model...")
        best_model, best_score = self._select_best_model(models, X_test_scaled, y_test)
        
        # Store results
        self.models['primary'] = best_model
        self.scalers['primary'] = scaler
        
        # Create ensemble if beneficial
        if self.optimization_config['enable_ensemble'] and len(models) > 2:
            logger.info("🔗 Creating ensemble...")
            ensemble = self._create_ensemble(models, X_test_scaled, y_test)
            if ensemble and ensemble['score'] > best_score:
                self.models['ensemble'] = ensemble['model']
                best_score = ensemble['score']
                logger.info(f"🔗 Ensemble outperformed: {best_score:.4f}")
        
        training_time = time.time() - start_time
        
        # Performance evaluation
        logger.info("📊 Evaluating model performance...")
        self._evaluate_model_performance(best_model, X_test_scaled, y_test, best_score)
        
        # Update history
        self._update_training_history(best_model, best_score, training_time, len(models))
        
        logger.info(f"⏱️  Enhanced training completed in {training_time:.1f}s")
        logger.info(f"🏆 Best model score: {best_score:.4f}")
        
        return best_score
    
    def _prepare_data_advanced(self, features, labels, enable_optimization=True):
        """Advanced data preparation with progress tracking"""
        logger.info("🔧 Preparing data with advanced optimizations...")
        
        # Convert to numpy arrays
        X = np.array(features)
        original_shape = X.shape
        
        # Handle invalid values with progress
        logger.info("  Cleaning invalid values...")
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        # Sampling for large datasets
        if len(X) > self.optimization_config['max_training_samples']:
            logger.info(f"  📉 Sampling {self.optimization_config['max_training_samples']:,} from {len(X):,}")
            indices = self._intelligent_sampling(X, labels, self.optimization_config['max_training_samples'])
            X = X[indices]
            labels = [labels[i] for i in indices]
        
        # Label encoding
        logger.info("  Encoding labels...")
        y = self.label_encoder.fit_transform(labels)
        
        # Data quality checks
        if X.shape[0] == 0:
            logger.error("No valid samples after preprocessing")
            return None, None
        
        # Outlier detection and handling
        if enable_optimization:
            logger.info("  Handling outliers...")
            X = self._handle_outliers(X)
        
        logger.info(f"✅ Data prepared: {X.shape} (from {original_shape})")
        
        # Class balancing
        if enable_optimization:
            logger.info("  Balancing classes...")
            X, y = self._advanced_balancing(X, y)
        
        return X, y
    
    def _train_optimized_model_suite_with_progress(self, X_train, X_test, y_train, y_test):
        """Train suite of optimized models with progress tracking"""
        models = {}
        
        logger.info("🚀 Training optimized model suite...")
        
        # Models to train
        model_configs = [
            ("Random Forest", self._train_random_forest),
            ("Extra Trees", self._train_extra_trees),
        ]
        
        # Add additional models for smaller datasets
        if len(X_train) < 50000:
            model_configs.append(("Gradient Boosting", self._train_gradient_boosting))
        
        if 1000 <= len(X_train) <= 20000:
            model_configs.append(("Neural Network", self._train_neural_network))
        
        # Train models with progress bar
        with tqdm_bar(total=len(model_configs), desc="Training models", ncols=80) as pbar:
            for name, train_func in model_configs:
                try:
                    logger.info(f"  🌳 Training {name}...")
                    model, score = train_func(X_train, X_test, y_train, y_test)
                    models[name.lower().replace(' ', '_')] = {'model': model, 'score': score}
                    logger.info(f"    ✅ {name} Accuracy: {score:.4f}")
                except Exception as e:
                    logger.warning(f"    ❌ {name} failed: {e}")
                finally:
                    pbar.update(1)
        
        return models
    
    def _train_random_forest(self, X_train, X_test, y_train, y_test):
        """Train Random Forest with progress"""
        rf = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced',
            oob_score=True
        )
        rf.fit(X_train, y_train)
        score = rf.score(X_test, y_test)
        return rf, score
    
    def _train_extra_trees(self, X_train, X_test, y_train, y_test):
        """Train Extra Trees with progress"""
        et = ExtraTreesClassifier(
            n_estimators=100,
            max_depth=12,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        et.fit(X_train, y_train)
        score = et.score(X_test, y_test)
        return et, score
    
    def _train_gradient_boosting(self, X_train, X_test, y_train, y_test):
        """Train Gradient Boosting with progress"""
        gb = GradientBoostingClassifier(
            n_estimators=100,
            learning_rate=0.1,
            max_depth=6,
            random_state=42
        )
        gb.fit(X_train, y_train)
        score = gb.score(X_test, y_test)
        return gb, score
    
    def _train_neural_network(self, X_train, X_test, y_train, y_test):
        """Train Neural Network with progress"""
        nn = MLPClassifier(
            hidden_layer_sizes=(100, 50),
            max_iter=200,
            random_state=42,
            early_stopping=True,
            validation_fraction=0.1,
            alpha=0.001
        )
        nn.fit(X_train, y_train)
        score = nn.score(X_test, y_test)
        return nn, score
    
    def _intelligent_sampling(self, X, labels, target_size):
        """Intelligent sampling preserving important patterns"""
        # Stratified sampling with diversity preservation
        unique_labels = list(set(labels))
        label_indices = {label: [i for i, l in enumerate(labels) if l == label] 
                        for label in unique_labels}
        
        samples_per_class = target_size // len(unique_labels)
        selected_indices = []
        
        for label, indices in label_indices.items():
            if len(indices) <= samples_per_class:
                selected_indices.extend(indices)
            else:
                # Use systematic sampling for diversity
                step = len(indices) // samples_per_class
                sampled = indices[::max(1, step)][:samples_per_class]
                selected_indices.extend(sampled)
        
        # Fill remaining slots randomly
        remaining = target_size - len(selected_indices)
        if remaining > 0:
            all_indices = set(range(len(labels)))
            unused_indices = list(all_indices - set(selected_indices))
            if unused_indices:
                additional = np.random.choice(unused_indices, min(remaining, len(unused_indices)), replace=False)
                selected_indices.extend(additional)
        
        return selected_indices[:target_size]
    
    def _handle_outliers(self, X):
        """Advanced outlier detection and handling"""
        # Use IQR method for each feature
        Q1 = np.percentile(X, 25, axis=0)
        Q3 = np.percentile(X, 75, axis=0)
        IQR = Q3 - Q1
        
        # Define outlier bounds
        lower_bound = Q1 - 1.5 * IQR
        upper_bound = Q3 + 1.5 * IQR
        
        # Clip outliers instead of removing (preserves data)
        X_clipped = np.clip(X, lower_bound, upper_bound)
        
        outliers_detected = np.sum(X != X_clipped)
        if outliers_detected > 0:
            logger.info(f"    📊 Clipped {outliers_detected} outlier values")
        
        return X_clipped
    
    def _advanced_balancing(self, X, y):
        """Advanced class balancing with multiple techniques"""
        unique, counts = np.unique(y, return_counts=True)
        max_count = np.max(counts)
        min_count = np.min(counts)
        imbalance_ratio = max_count / min_count
        
        if imbalance_ratio <= self.optimization_config['balance_threshold']:
            logger.info("    ✅ Classes reasonably balanced, no action needed")
            return X, y
        
        logger.info(f"    ⚖️  Balancing classes (ratio: {imbalance_ratio:.1f}:1)")
        
        try:
            # Step 1: Undersampling majority classes
            target_size = int(np.median(counts) * 1.5)  # Reasonable target
            
            undersampler = RandomUnderSampler(
                random_state=42,
                sampling_strategy={i: min(count, target_size) for i, count in zip(unique, counts)}
            )
            X_under, y_under = undersampler.fit_resample(X, y)
            
            # Step 2: Light oversampling for minorities
            new_counts = np.bincount(y_under)
            min_new_count = np.min(new_counts[new_counts > 0])
            
            if min_new_count >= 5:  # Enough for SMOTE
                k_neighbors = min(3, min_new_count - 1)
                smote = BorderlineSMOTE(random_state=42, k_neighbors=k_neighbors)
                X_balanced, y_balanced = smote.fit_resample(X_under, y_under)
                
                logger.info(f"    ✅ Balanced: {len(X)} -> {len(X_balanced)} samples")
                return X_balanced, y_balanced
            else:
                logger.info("    ✅ Used undersampling only (insufficient data for SMOTE)")
                return X_under, y_under
                
        except Exception as e:
            logger.warning(f"    Balancing failed: {e}, using original data")
            return X, y
    
    def _perform_feature_selection(self, X_train, X_test, y_train):
        """Perform intelligent feature selection"""
        original_features = X_train.shape[1]
        target_features = min(20, original_features // 2)  # Reasonable reduction
        
        try:
            # Use mutual information for feature selection
            selector = SelectKBest(score_func=mutual_info_classif, k=target_features)
            X_train_selected = selector.fit_transform(X_train, y_train)
            X_test_selected = selector.transform(X_test)
            
            # Store selector for later use
            self.feature_selectors['primary'] = selector
            
            logger.info(f"  ✅ Features: {original_features} -> {target_features}")
            return X_train_selected, X_test_selected
            
        except Exception as e:
            logger.warning(f"  Feature selection failed: {e}")
            return X_train, X_test
    
    def _get_optimal_scaler(self, X):
        """Select optimal scaler based on data characteristics"""
        # Check data distribution
        skewness = np.mean([abs(np.mean(X[:, i]) - np.median(X[:, i])) for i in range(min(5, X.shape[1]))])
        
        if skewness > 0.5:  # Highly skewed data
            logger.info("  📏 Using RobustScaler (data is skewed)")
            return RobustScaler()
        else:
            logger.info("  📏 Using StandardScaler (data is normal)")
            return StandardScaler()
    
    def _select_best_model(self, models, X_test, y_test):
        """Select best model with cross-validation"""
        best_name = None
        best_score = 0
        best_model = None
        
        for name, model_info in models.items():
            score = model_info['score']
            model = model_info['model']
            
            # Additional validation with cross-validation for top models
            if score > 0.8:  # Only for promising models
                try:
                    cv_scores = cross_val_score(
                        model, X_test, y_test, 
                        cv=self.optimization_config['cross_validation_folds'],
                        scoring='accuracy'
                    )
                    cv_mean = np.mean(cv_scores)
                    cv_std = np.std(cv_scores)
                    
                    logger.info(f"  {name}: {score:.4f} (CV: {cv_mean:.4f} ± {cv_std:.3f})")
                    
                    # Consider both accuracy and stability
                    adjusted_score = cv_mean - cv_std  # Penalize high variance
                    
                    if adjusted_score > best_score:
                        best_score = adjusted_score
                        best_name = name
                        best_model = model
                        
                except Exception as e:
                    logger.warning(f"CV failed for {name}: {e}")
                    if score > best_score:
                        best_score = score
                        best_name = name
                        best_model = model
            else:
                if score > best_score:
                    best_score = score
                    best_name = name
                    best_model = model
        
        logger.info(f"🥇 Selected: {best_name} (Score: {best_score:.4f})")
        return best_model, best_score
    
    def _create_ensemble(self, models, X_test, y_test):
        """Create voting ensemble from best models"""
        # Select top 3 models
        sorted_models = sorted(models.items(), key=lambda x: x[1]['score'], reverse=True)
        top_models = sorted_models[:3]
        
        if len(top_models) < 2:
            return None
        
        try:
            # Create simple averaging ensemble
            predictions = []
            for name, info in top_models:
                try:
                    pred = info['model'].predict_proba(X_test)
                    predictions.append(pred)
                except:
                    # Fallback to binary predictions
                    pred = info['model'].predict(X_test)
                    predictions.append(pred)
            
            if predictions:
                # Average predictions
                avg_pred = np.mean(predictions, axis=0)
                ensemble_pred = np.argmax(avg_pred, axis=1)
                ensemble_score = accuracy_score(y_test, ensemble_pred)
                
                logger.info(f"  Ensemble score: {ensemble_score:.4f}")
                
                # Create a simple ensemble wrapper
                class SimpleEnsemble:
                    def __init__(self, models):
                        self.models = [info['model'] for name, info in models]
                    
                    def predict(self, X):
                        predictions = []
                        for model in self.models:
                            try:
                                pred = model.predict_proba(X)
                                predictions.append(pred)
                            except:
                                pred = model.predict(X)
                                predictions.append(pred)
                        
                        if predictions:
                            avg_pred = np.mean(predictions, axis=0)
                            return np.argmax(avg_pred, axis=1)
                        return np.zeros(X.shape[0])
                
                ensemble_model = SimpleEnsemble(top_models)
                return {'model': ensemble_model, 'score': ensemble_score}
            
        except Exception as e:
            logger.warning(f"Ensemble creation failed: {e}")
            return None
    
    def _evaluate_model_performance(self, model, X_test, y_test, score):
        """Comprehensive model evaluation"""
        logger.info("\n📊 === MODEL EVALUATION ===")
        
        # Predictions
        y_pred = model.predict(X_test)
        
        # Classification report
        class_names = self.label_encoder.classes_
        report = classification_report(y_test, y_pred, target_names=class_names, output_dict=True, zero_division=0)
        
        # Store performance metrics
        self.model_performance = {
            'accuracy': score,
            'precision_macro': report['macro avg']['precision'],
            'recall_macro': report['macro avg']['recall'],
            'f1_macro': report['macro avg']['f1-score'],
            'class_report': report
        }
        
        logger.info(f"🎯 Accuracy: {score:.4f}")
        logger.info(f"🎯 Precision (macro): {report['macro avg']['precision']:.4f}")
        logger.info(f"🎯 Recall (macro): {report['macro avg']['recall']:.4f}")
        logger.info(f"🎯 F1-Score (macro): {report['macro avg']['f1-score']:.4f}")
        
        # Per-class performance for NIDS
        logger.info("\n📋 Per-Class Performance:")
        for class_name in class_names:
            if class_name in report:
                metrics = report[class_name]
                logger.info(f"  {class_name}: P={metrics['precision']:.3f}, R={metrics['recall']:.3f}, F1={metrics['f1-score']:.3f}")
    
    def _update_training_history(self, model, score, training_time, num_models):
        """Update training history with enhanced info"""
        model_name = type(model).__name__
        
        history_entry = {
            'timestamp': datetime.now().isoformat(),
            'model_type': model_name,
            'accuracy': score,
            'training_time': training_time,
            'models_evaluated': num_models,
            'classes': list(self.label_encoder.classes_),
            'performance_metrics': self.model_performance.copy()
        }
        
        self.training_history.append(history_entry)
        
        # Keep only recent entries
        if len(self.training_history) > 10:
            self.training_history = self.training_history[-10:]
    
    def save_enhanced_models(self, model_dir='models'):
        """Save models with enhanced metadata"""
        model_path = Path(model_dir)
        model_path.mkdir(exist_ok=True)
        
        # Save models
        for name, model in self.models.items():
            joblib.dump(model, model_path / f"{name}_model.pkl")
            logger.info(f"💾 Saved {name} model")
        
        # Save scalers
        for name, scaler in self.scalers.items():
            joblib.dump(scaler, model_path / f"{name}_scaler.pkl")
        
        # Save feature selectors
        for name, selector in self.feature_selectors.items():
            joblib.dump(selector, model_path / f"{name}_feature_selector.pkl")
        
        # Save label encoder
        joblib.dump(self.label_encoder, model_path / "label_encoder.pkl")
        
        # Save metadata
        metadata = {
            'training_history': self.training_history,
            'model_performance': self.model_performance,
            'optimization_config': self.optimization_config,
            'timestamp': datetime.now().isoformat(),
            'version': '2.0-enhanced'
        }
        
        with open(model_path / "metadata.json", 'w') as f:
            json.dump(metadata, f, indent=2)
        
        logger.info(f"💾 Enhanced models and metadata saved to {model_path}")


def get_user_confirmation(message, default=True):
    """Get user confirmation with default option"""
    suffix = " [Y/n]" if default else " [y/N]"
    while True:
        try:
            response = input(f"\n{message}{suffix}: ").lower().strip()
            if not response:
                return default
            if response in ['y', 'yes']:
                return True
            elif response in ['n', 'no']:
                return False
            else:
                print("Please enter 'y' or 'n'")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user")
            return False


def display_file_selection_menu(files_list):
    """Display file selection menu with size information"""
    logger.info("\n📋 === FILE SELECTION MENU ===")
    
    for i, file_path in enumerate(files_list, 1):
        size_mb = file_path.stat().st_size / (1024 * 1024)
        size_gb = size_mb / 1024
        
        if size_gb >= 1:
            size_str = f"{size_gb:.1f} GB"
        else:
            size_str = f"{size_mb:.1f} MB"
        
        # Add warnings for large files
        warning = ""
        if size_gb >= 10:
            warning = " ⚠️ VERY LARGE - Will process in small chunks"
        elif size_gb >= 2:
            warning = " ⚠️ LARGE - Will process carefully"
        
        logger.info(f"  {i:2d}. {file_path.name} ({size_str}){warning}")
    
    logger.info(f"\nOptions:")
    logger.info(f"  - Enter file number (1-{len(files_list)}) to process single file")
    logger.info(f"  - Enter 'all' to process all files")
    logger.info(f"  - Enter 'skip' to skip file selection")
    logger.info(f"  - Enter 'quit' to exit")


def main():
    """Enhanced main function with user-friendly controls"""
    parser = argparse.ArgumentParser(description="Enhanced NIDS ML Training System")
    
    # Data processing options
    parser.add_argument("--dataset-dir", default="datasets", help="Dataset directory")
    parser.add_argument("--max-samples-per-file", type=int, default=50000, help="Max samples per file")
    parser.add_argument("--chunk-size", type=int, default=10000, help="Chunk size for processing")
    parser.add_argument("--memory-threshold", type=int, default=2000, help="Memory threshold in MB")
    
    # Training options
    parser.add_argument("--auto-train-threshold", type=int, default=25000, help="Auto-train threshold")
    parser.add_argument("--max-training-samples", type=int, default=75000, help="Max samples for training")
    parser.add_argument("--enable-optimization", action='store_true', default=True, help="Enable optimizations")
    parser.add_argument("--interactive", action='store_true', default=True, help="Interactive mode")
    
    # Output options
    parser.add_argument("--model-dir", default="models", help="Model save directory")
    parser.add_argument("--progress-file", default="training_progress.pkl", help="Progress save file")
    parser.add_argument("--log-level", default="INFO", help="Logging level")
    
    args = parser.parse_args()
    
    # Configure logging
    logging.getLogger().setLevel(getattr(logging, args.log_level.upper()))
    
    # Check system resources
    total_memory = psutil.virtual_memory().total / (1024**3)  # GB
    available_memory = psutil.virtual_memory().available / (1024**3)  # GB
    
    logger.info("🚀 === Enhanced NIDS ML Training System ===")
    logger.info(f"💻 System Memory: {total_memory:.1f} GB total, {available_memory:.1f} GB available")
    logger.info(f"📊 Max samples per file: {args.max_samples_per_file:,}")
    logger.info(f"🔧 Chunk size: {args.chunk_size:,}")
    logger.info(f"💾 Memory threshold: {args.memory_threshold} MB")
    logger.info(f"🎯 Auto-train threshold: {args.auto_train_threshold:,}")
    logger.info(f"🧠 Max training samples: {args.max_training_samples:,}")
    
    # Warning for low memory systems
    if available_memory < 4:
        logger.warning(f"⚠️  Low available memory ({available_memory:.1f} GB). Consider:")
        logger.warning(f"    - Reducing --max-samples-per-file to 10000-20000")
        logger.warning(f"    - Reducing --chunk-size to 5000")
        logger.warning(f"    - Processing one file at a time")
        
        if not get_user_confirmation("Continue with current settings?", default=False):
            logger.info("💡 Restart with --max-samples-per-file 15000 --chunk-size 5000")
            return
    
    # Initialize components
    collector = OptimizedIncrementalDataCollector()
    collector.memory_threshold_mb = args.memory_threshold
    collector.chunk_size = args.chunk_size
    
    trainer = EnhancedModelTrainer()
    trainer.optimization_config.update({
        'max_training_samples': args.max_training_samples,
        'use_feature_selection': args.enable_optimization,
        'enable_ensemble': args.enable_optimization
    })
    
    # Detect datasets
    files = collector.detect_datasets(args.dataset_dir)
    if not files:
        logger.error("No datasets found. Exiting.")
        return
    
    logger.info(f"\n📁 Found {len(files)} dataset files to process")
    
    # Interactive file selection
    if args.interactive:
        while True:
            display_file_selection_menu(files)
            
            try:
                choice = input("\nEnter your choice: ").lower().strip()
                
                if choice == 'quit':
                    logger.info("👋 Exiting...")
                    return
                elif choice == 'skip':
                    logger.info("Skipping file selection, will process all files")
                    break
                elif choice == 'all':
                    logger.info("Will process all files")
                    break
                elif choice.isdigit():
                    file_index = int(choice) - 1
                    if 0 <= file_index < len(files):
                        files = [files[file_index]]
                        logger.info(f"Selected: {files[0].name}")
                        break
                    else:
                        logger.error(f"Invalid file number. Choose 1-{len(files)}")
                else:
                    logger.error("Invalid choice. Try again.")
                    
            except (ValueError, KeyboardInterrupt):
                logger.info("Operation cancelled")
                return
    
    # Process files with enhanced user control
    try:
        for i, file_path in enumerate(files, 1):
            logger.info(f"\n📁 === FILE {i}/{len(files)}: {file_path.name} ===")
            
            # File size check and user confirmation
            file_size_gb = file_path.stat().st_size / (1024**3)
            
            if file_size_gb >= 10:
                logger.warning(f"⚠️  VERY LARGE FILE: {file_size_gb:.1f} GB")
                logger.info("This file will be processed in very small chunks to prevent memory issues.")
                
                if not get_user_confirmation("Do you want to process this large file?", default=False):
                    logger.info("⏭️  Skipping large file")
                    continue
                    
                # Reduce parameters for very large files
                max_samples = min(args.max_samples_per_file, 25000)
                logger.info(f"🔧 Reducing max samples to {max_samples:,} for this large file")
            
            elif file_size_gb >= 2:
                logger.warning(f"⚠️  LARGE FILE: {file_size_gb:.1f} GB")
                logger.info("This file will be processed carefully in chunks.")
                max_samples = args.max_samples_per_file
                
                if not get_user_confirmation("Process this file?", default=True):
                    logger.info("⏭️  Skipping file")
                    continue
            else:
                max_samples = args.max_samples_per_file
            
            # Process the file
            start_memory = MemoryManager.get_memory_usage()
            logger.info(f"💾 Memory usage before processing: {start_memory:.1f} MB")
            
            samples_added, status = collector.process_single_file_chunked(file_path, max_samples)
            
            end_memory = MemoryManager.get_memory_usage()
            logger.info(f"💾 Memory usage after processing: {end_memory:.1f} MB")
            
            if samples_added > 0:
                collector.print_enhanced_summary()
                
                # Check if we should train now
                total_samples = len(collector.features)
                feasible, message = trainer.enhanced_feasibility_check(collector.labels)
                
                logger.info(f"\n🎯 Current total samples: {total_samples:,}")
                logger.info(f"🎯 Training feasibility: {message}")
                
                # Auto-training check
                if total_samples >= args.auto_train_threshold and feasible:
                    if get_user_confirmation(f"Auto-train now with {total_samples:,} samples?", default=True):
                        logger.info(f"\n🧠 === TRAINING TRIGGERED ===")
                        
                        score = trainer.train_enhanced_models_with_progress(
                            collector.features, 
                            collector.labels,
                            args.enable_optimization
                        )
                        
                        if score > 0:
                            trainer.save_enhanced_models(args.model_dir)
                            collector.save_enhanced_progress(args.progress_file)
                            logger.info(f"✅ Training completed! Score: {score:.4f}")
                            
                            # Ask if user wants to continue or stop
                            if not get_user_confirmation("Continue processing more files?", default=False):
                                break
                        else:
                            logger.error("❌ Training failed")
                    else:
                        logger.info("Training skipped by user")
                elif not feasible:
                    logger.warning(f"⚠️  Cannot train yet: {message}")
                
            else:
                logger.warning(f"⚠️ No samples added from {file_path.name}: {status}")
            
            # Memory cleanup after each file
            MemoryManager.force_garbage_collect()
            
            # Interactive continuation for multiple files
            if i < len(files):
                logger.info(f"\n📊 Progress: {i}/{len(files)} files processed")
                logger.info(f"📊 Total samples collected: {len(collector.features):,}")
                
                # Show options
                logger.info("\nOptions:")
                logger.info("  y - Continue to next file")
                logger.info("  n - Stop processing files")
                logger.info("  t - Train model now")
                logger.info("  s - Show summary")
                
                try:
                    response = input("Choice [y/n/t/s]: ").lower().strip()
                    
                    if response == 'n':
                        logger.info("🛑 Stopping file processing")
                        break
                    elif response == 't':
                        if trainer.enhanced_feasibility_check(collector.labels)[0]:
                            score = trainer.train_enhanced_models_with_progress(
                                collector.features, 
                                collector.labels,
                                args.enable_optimization
                            )
                            if score > 0:
                                trainer.save_enhanced_models(args.model_dir)
                                collector.save_enhanced_progress(args.progress_file)
                        break
                    elif response == 's':
                        collector.print_enhanced_summary()
                        # Continue to next file after summary
                    # Default 'y' or empty - continue
                    
                except KeyboardInterrupt:
                    logger.info("\n⏹️  Processing interrupted by user")
                    break
        
        # Final training if not done yet
        if len(trainer.training_history) == 0:
            feasible, message = trainer.enhanced_feasibility_check(collector.labels)
            if feasible:
                logger.info(f"\n🧠 === FINAL TRAINING ===")
                logger.info(f"Training on {len(collector.features):,} samples")
                
                if get_user_confirmation("Start final training?", default=True):
                    score = trainer.train_enhanced_models_with_progress(
                        collector.features, 
                        collector.labels,
                        args.enable_optimization
                    )
                    
                    if score > 0:
                        trainer.save_enhanced_models(args.model_dir)
                        collector.save_enhanced_progress(args.progress_file)
                        
                        logger.info(f"✅ Training completed successfully!")
                        logger.info(f"🏆 Final model accuracy: {score:.4f}")
                        
                        # Performance summary
                        if trainer.model_performance:
                            perf = trainer.model_performance
                            logger.info("\n📊 === FINAL PERFORMANCE SUMMARY ===")
                            logger.info(f"🎯 Accuracy: {perf.get('accuracy', 0):.4f}")
                            logger.info(f"🎯 Precision: {perf.get('precision_macro', 0):.4f}")
                            logger.info(f"🎯 Recall: {perf.get('recall_macro', 0):.4f}")
                            logger.info(f"🎯 F1-Score: {perf.get('f1_macro', 0):.4f}")
                            
                            # NIDS performance assessment
                            if perf.get('accuracy', 0) >= 0.90:
                                logger.info("🟢 Model performance meets NIDS requirements (≥90% accuracy)")
                            elif perf.get('accuracy', 0) >= 0.85:
                                logger.info("🟡 Model performance is acceptable for NIDS (≥85% accuracy)")
                            else:
                                logger.warning("🔴 Model performance may be insufficient for production NIDS")
                                logger.info("💡 Consider: More training data, feature engineering, or hyperparameter tuning")
                    
                    else:
                        logger.error("❌ Training failed")
                else:
                    logger.info("Training skipped by user")
            else:
                logger.error(f"❌ Final training not feasible: {message}")
                logger.info("💡 Try collecting more diverse data or check data quality")
        
        else:
            logger.info("✅ Training already completed during processing")
        
        # Final summary
        collector.print_enhanced_summary()
        
        if trainer.training_history:
            latest = trainer.training_history[-1]
            logger.info(f"\n🏆 === TRAINING COMPLETE ===")
            logger.info(f"Best Model: {latest['model_type']}")
            logger.info(f"Accuracy: {latest['accuracy']:.4f}")
            logger.info(f"Training Time: {latest['training_time']:.1f}s")
            logger.info(f"Classes: {', '.join(latest['classes'])}")
            
            # NIDS deployment recommendations
            logger.info(f"\n🛡️ === NIDS DEPLOYMENT RECOMMENDATIONS ===")
            
            attack_classes = [cls for cls in latest['classes'] if cls != 'normal']
            if attack_classes:
                logger.info(f"✅ Attack types detected: {', '.join(attack_classes)}")
                logger.info(f"✅ Model can classify {len(latest['classes'])} categories")
            
            if latest['accuracy'] >= 0.95:
                logger.info("🟢 Excellent performance - ready for production deployment")
            elif latest['accuracy'] >= 0.90:
                logger.info("🟡 Good performance - suitable for production with monitoring")
            elif latest['accuracy'] >= 0.80:
                logger.info("🟠 Moderate performance - use with caution")
            else:
                logger.info("🔴 Low performance - needs improvement before deployment")
        
        logger.info(f"\n📁 Models saved to: {Path(args.model_dir).absolute()}")
        logger.info(f"📁 Progress saved to: {Path(args.progress_file).absolute()}")
        
    except KeyboardInterrupt:
        logger.info("\n⏹️  Training interrupted by user")
        logger.info("💾 Saving current progress...")
        
        try:
            collector.save_enhanced_progress(args.progress_file)
            if trainer.models:
                trainer.save_enhanced_models(args.model_dir)
            logger.info("✅ Progress saved successfully")
        except Exception as e:
            logger.error(f"❌ Failed to save progress: {e}")
    
    except Exception as e:
        logger.error(f"❌ Unexpected error: {e}")
        logger.info("💾 Attempting to save current progress...")
        
        try:
            collector.save_enhanced_progress(f"emergency_{args.progress_file}")
            logger.info("✅ Emergency progress saved")
        except:
            logger.error("❌ Could not save emergency progress")
    
    finally:
        logger.info("\n🏁 Enhanced NIDS ML Training System finished")
        logger.info("💡 To resume processing, run the script again with the same dataset directory")


if __name__ == "__main__":
    # Check required packages
    try:
        import psutil
    except ImportError as e:
        print(f"❌ Missing required package: {e}")
        print("💡 Install with: pip install psutil")
        exit(1)
    
    main()