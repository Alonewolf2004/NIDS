"""
Performance-Optimized Incremental ML Model Training
Fixes performance issues with large datasets and extreme class imbalance
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
from collections import defaultdict
warnings.filterwarnings('ignore')

# Optimized ML imports
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
from sklearn.preprocessing import StandardScaler, LabelEncoder, RobustScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    classification_report, 
    confusion_matrix, 
    accuracy_score,
    precision_recall_fscore_support,
    roc_auc_score
)
from sklearn.feature_selection import SelectKBest, f_classif
from imblearn.over_sampling import SMOTE
from imblearn.under_sampling import RandomUnderSampler
import joblib

class OptimizedIncrementalDataCollector:
    """Optimized collector with smart sampling"""
    
    def __init__(self):
        self.features = []
        self.labels = []
        
        # Reduced feature set for performance (20 features)
        self.feature_names = [
            'packet_size', 'protocol', 'src_port', 'dst_port',
            'tcp_flags', 'payload_size', 'is_well_known_port', 
            'port_difference', 'payload_entropy', 'packets_per_second',
            'bytes_per_second', 'avg_packet_size', 'packet_size_variance',
            'inter_arrival_time_mean', 'flags_count', 'protocol_anomaly_score',
            'port_scan_indicator', 'connection_state', 'header_length_ratio',
            'packet_direction_entropy'
        ]
        
        self.session_stats = {
            'total_files_processed': 0,
            'total_samples': 0,
            'session_start': datetime.now(),
            'files_completed': [],
            'class_distribution': defaultdict(int)
        }
    
    def detect_datasets(self, dataset_dir='datasets'):
        """Smart dataset detection with deduplication"""
        dataset_path = Path(dataset_dir)
        if not dataset_path.exists():
            print(f"❌ Dataset directory '{dataset_dir}' not found!")
            return []
        
        print(f"🔍 Scanning dataset directory: {dataset_path}")
        
        # Find all files
        file_extensions = ['*.csv', '*.txt', '*.data', '*.tsv']
        all_files = []
        
        for ext in file_extensions:
            all_files.extend(list(dataset_path.glob(ext)))
            all_files.extend(list(dataset_path.glob(f"**/{ext}")))
        
        # SMART DEDUPLICATION: Remove files with identical sizes (likely duplicates)
        unique_files = {}
        for file_path in all_files:
            if file_path.name.startswith('.'):
                continue
            
            size = file_path.stat().st_size
            # If we haven't seen this size, or this filename is "better"
            if size not in unique_files or len(file_path.name) < len(unique_files[size].name):
                unique_files[size] = file_path
        
        files_list = list(unique_files.values())
        
        if not files_list:
            print(f"❌ No dataset files found")
            return []
        
        print(f"📂 Found {len(files_list)} unique files (removed {len(all_files) - len(files_list)} duplicates)")
        
        # Sort by size for progressive complexity
        files_list.sort(key=lambda x: x.stat().st_size)
        
        print(f"\n📋 === DATASET FILES ===")
        for i, file_path in enumerate(files_list, 1):
            size_mb = file_path.stat().st_size / (1024 * 1024)
            print(f"  {i:2d}. {file_path.name} ({size_mb:.1f} MB)")
        
        return files_list
    
    def process_single_file(self, file_path, max_samples=None):
        """Optimized file processing with smart sampling"""
        print(f"\n🔄 Processing: {file_path.name}")
        start_time = time.time()
        
        try:
            samples_added = self._process_csv_file_optimized(file_path, max_samples)
            processing_time = time.time() - start_time
            
            self._update_session_stats(file_path, samples_added, processing_time)
            
            print(f"✅ Added {samples_added:,} samples in {processing_time:.1f}s")
            return samples_added, "Success"
            
        except Exception as e:
            error_msg = f"❌ Error: {str(e)}"
            print(error_msg)
            return 0, error_msg
    
    def _process_csv_file_optimized(self, csv_file, max_samples=None):
        """Optimized CSV processing with intelligent sampling"""
        # Smart loading
        df = self._smart_csv_load(csv_file)
        if df is None:
            return 0
        
        print(f"  📊 Loaded {len(df):,} rows, {df.shape[1]} columns")
        
        # SMART SAMPLING: Sample proportionally by class if too large
        if max_samples and len(df) > max_samples:
            label_col = self._detect_label_column(df)
            if label_col:
                df = self._stratified_sample(df, label_col, max_samples)
            else:
                df = df.sample(n=max_samples, random_state=42)
            print(f"  🎯 Sampled to {len(df):,} rows")
        
        # Detect labels
        label_column = self._detect_label_column(df)
        if not label_column:
            # Use filename-based labeling
            labels = [self._guess_label_from_filename(csv_file.name)] * len(df)
        else:
            labels = df[label_column].values
            df = df.drop(label_column, axis=1)
        
        # Show original distribution
        original_dist = pd.Series(labels).value_counts()
        print(f"  📈 Original labels: {dict(original_dist.head())}")
        
        # Process labels with fixed mapping
        processed_labels = self._process_labels_smart(labels)
        
        # Show processed distribution  
        processed_dist = pd.Series(processed_labels).value_counts()
        print(f"  📊 Processed: {dict(processed_dist)}")
        
        # Preprocess data
        df = self._preprocess_dataframe_fast(df)
        
        # Create features efficiently
        features = self._create_features_fast(df)
        
        # Add to collection
        for i, feature_row in enumerate(features):
            self.features.append(feature_row)
            self.labels.append(processed_labels[i])
            self.session_stats['class_distribution'][processed_labels[i]] += 1
        
        return len(features)
    
    def _stratified_sample(self, df, label_col, max_samples):
        """Sample data while preserving class ratios"""
        try:
            # Get class distribution
            class_counts = df[label_col].value_counts()
            total_samples = len(df)
            
            sampled_dfs = []
            remaining_samples = max_samples
            
            for class_name, count in class_counts.items():
                # Calculate proportional sample size
                proportion = count / total_samples
                class_sample_size = min(int(proportion * max_samples), remaining_samples, count)
                
                if class_sample_size > 0:
                    class_df = df[df[label_col] == class_name].sample(n=class_sample_size, random_state=42)
                    sampled_dfs.append(class_df)
                    remaining_samples -= class_sample_size
                    
                if remaining_samples <= 0:
                    break
            
            return pd.concat(sampled_dfs, ignore_index=True).sample(frac=1, random_state=42)
            
        except Exception as e:
            print(f"    Warning: Stratified sampling failed: {e}")
            return df.sample(n=min(max_samples, len(df)), random_state=42)
    
    def _detect_label_column(self, df):
        """Fast label column detection"""
        # Common label column names
        label_patterns = ['label', 'class', 'attack', 'target']
        
        for pattern in label_patterns:
            for col in df.columns:
                if pattern in col.lower():
                    return col
        
        # Check last column if it's categorical with reasonable unique values
        last_col = df.columns[-1]
        if df[last_col].dtype == 'object' and 2 <= df[last_col].nunique() <= 50:
            return last_col
        
        return None
    
    def _process_labels_smart(self, labels):
        """Smart and fast label processing"""
        processed = []
        
        # Optimized KDD mappings
        dos_attacks = {'back', 'land', 'neptune', 'pod', 'smurf', 'teardrop', 'apache2', 'udpstorm', 'mailbomb'}
        probe_attacks = {'ipsweep', 'nmap', 'portsweep', 'satan', 'saint', 'mscan'}
        r2l_attacks = {'ftp_write', 'guess_passwd', 'imap', 'multihop', 'phf', 'spy', 
                      'warezclient', 'warezmaster', 'sendmail', 'named', 'snmpgetattack', 'worm'}
        u2r_attacks = {'buffer_overflow', 'loadmodule', 'perl', 'rootkit', 'httptunnel', 'ps', 'sqlattack', 'xterm'}
        
        for label in labels:
            label_str = str(label).strip().lower()
            
            if label_str == 'normal' or label_str == 'benign':
                processed.append('normal')
            elif label_str in dos_attacks:
                processed.append('dos')
            elif label_str in probe_attacks:
                processed.append('probe')
            elif label_str in r2l_attacks:
                processed.append('r2l')
            elif label_str in u2r_attacks:
                processed.append('u2r')
            elif 'dos' in label_str or 'ddos' in label_str:
                processed.append('dos')
            elif 'scan' in label_str or 'probe' in label_str:
                processed.append('probe')
            elif 'web' in label_str or 'http' in label_str:
                processed.append('web')
            elif 'bot' in label_str:
                processed.append('botnet')
            else:
                processed.append('normal')  # Default
        
        return processed
    
    def _guess_label_from_filename(self, filename):
        """Guess label from filename"""
        filename_lower = filename.lower()
        if any(word in filename_lower for word in ['attack', 'ddos', 'dos', 'malicious']):
            return 'attack'
        return 'normal'
    
    def _smart_csv_load(self, csv_file):
        """Fast CSV loading"""
        try:
            # Try common configurations first
            for sep in [',', '\t', ';']:
                try:
                    df = pd.read_csv(
                        csv_file, 
                        sep=sep, 
                        low_memory=False,
                        na_values=['?', 'NaN', 'NULL', ''],
                        encoding='utf-8'
                    )
                    if df.shape[1] > 3:
                        return df
                except:
                    continue
            
            # Fallback with encoding detection
            for encoding in ['latin-1', 'iso-8859-1']:
                try:
                    df = pd.read_csv(csv_file, encoding=encoding, low_memory=False)
                    if df.shape[1] > 3:
                        return df
                except:
                    continue
        except Exception as e:
            print(f"    Could not load CSV: {e}")
        
        return None
    
    def _preprocess_dataframe_fast(self, df):
        """Fast preprocessing"""
        # Handle infinite/NaN values
        df = df.replace([np.inf, -np.inf], np.nan)
        df = df.fillna(0)
        
        # Quick categorical encoding
        for col in df.columns:
            if df[col].dtype == 'object':
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        return df
    
    def _create_features_fast(self, df):
        """Fast feature creation"""
        features = []
        
        for _, row in df.iterrows():
            # Create fixed-size feature vector
            feature_vector = [0.0] * len(self.feature_names)
            
            # Map first N columns directly
            for i in range(min(len(self.feature_names), len(row), df.shape[1])):
                try:
                    feature_vector[i] = float(row.iloc[i])
                except:
                    feature_vector[i] = 0.0
            
            features.append(feature_vector)
        
        return features
    
    def _update_session_stats(self, file_path, samples_added, processing_time):
        """Update stats"""
        self.session_stats['total_files_processed'] += 1
        self.session_stats['total_samples'] = len(self.features)
        self.session_stats['files_completed'].append({
            'filename': file_path.name,
            'samples': samples_added,
            'time': processing_time
        })
    
    def print_session_summary(self):
        """Print summary"""
        print(f"\n📊 === SESSION SUMMARY ===")
        print(f"Files: {self.session_stats['total_files_processed']}")
        print(f"Samples: {self.session_stats['total_samples']:,}")
        
        if self.session_stats['class_distribution']:
            print(f"Classes:")
            total = sum(self.session_stats['class_distribution'].values())
            for cls, count in sorted(self.session_stats['class_distribution'].items()):
                pct = count/total*100 if total > 0 else 0
                print(f"  {cls}: {count:,} ({pct:.1f}%)")
    
    def get_unique_classes(self):
        """Get unique classes"""
        return list(set(self.labels)) if self.labels else []
    
    def save_progress(self, filename):
        """Save progress"""
        data = {
            'features': self.features,
            'labels': self.labels,
            'session_stats': dict(self.session_stats),
            'timestamp': datetime.now()
        }
        with open(filename, 'wb') as f:
            pickle.dump(data, f)
        print(f"💾 Saved to {filename}")


class OptimizedModelTrainer:
    """Performance-optimized trainer"""
    
    def __init__(self):
        self.models = {}
        self.scalers = {}
        self.label_encoder = LabelEncoder()
        self.training_history = []
    
    def can_train(self, labels):
        """Check training feasibility"""
        unique_classes = len(set(labels))
        if unique_classes < 2:
            print(f"❌ Only {unique_classes} class found")
            return False
        
        min_samples = min([labels.count(cls) for cls in set(labels)])
        if min_samples < 10:
            print(f"❌ Minimum class has only {min_samples} samples")
            return False
        
        print(f"✅ Ready: {unique_classes} classes, min {min_samples} samples")
        return True
    
    def train_optimized_models(self, features, labels, max_training_samples=50000):
        """Optimized training with size limits"""
        print(f"\n🧠 === OPTIMIZED TRAINING ===")
        
        if not self.can_train(labels):
            return 0.0
        
        # PERFORMANCE OPTIMIZATION: Limit training data size
        if len(features) > max_training_samples:
            print(f"  📉 Sampling {max_training_samples:,} from {len(features):,} samples for training")
            indices = np.random.choice(len(features), max_training_samples, replace=False)
            features = [features[i] for i in indices]
            labels = [labels[i] for i in indices]
        
        start_time = time.time()
        
        # Prepare data
        X, y = self._prepare_data_optimized(features, labels)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
        
        # Scale
        scaler = StandardScaler()
        X_train_scaled = scaler.fit_transform(X_train)
        X_test_scaled = scaler.transform(X_test)
        
        # Train FAST models only
        models = {}
        
        print("🚀 Training optimized models...")
        
        # 1. Random Forest (fast and reliable)
        print("  Random Forest...")
        rf = RandomForestClassifier(
            n_estimators=100,  # Reduced from 200
            max_depth=10,      # Reduced from 20
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        rf.fit(X_train_scaled, y_train)
        rf_score = rf.score(X_test_scaled, y_test)
        models['random_forest'] = {'model': rf, 'score': rf_score}
        print(f"    Score: {rf_score:.4f}")
        
        # 2. Extra Trees (faster than RF)
        print("  Extra Trees...")
        et = ExtraTreesClassifier(
            n_estimators=50,   # Reduced
            max_depth=8,       # Reduced
            random_state=42,
            n_jobs=-1,
            class_weight='balanced'
        )
        et.fit(X_train_scaled, y_train)
        et_score = et.score(X_test_scaled, y_test)
        models['extra_trees'] = {'model': et, 'score': et_score}
        print(f"    Score: {et_score:.4f}")
        
        # 3. Skip Gradient Boosting (too slow for large datasets)
        # 4. Simplified Neural Network
        if len(X_train) < 10000:  # Only for smaller datasets
            print("  Neural Network...")
            nn = MLPClassifier(
                hidden_layer_sizes=(50,),  # Smaller network
                max_iter=100,              # Fewer iterations
                random_state=42,
                early_stopping=True
            )
            nn.fit(X_train_scaled, y_train)
            nn_score = nn.score(X_test_scaled, y_test)
            models['neural_network'] = {'model': nn, 'score': nn_score}
            print(f"    Score: {nn_score:.4f}")
        
        # Select best model
        best_name = max(models.keys(), key=lambda k: models[k]['score'])
        best_model = models[best_name]['model']
        best_score = models[best_name]['score']
        
        # Quick evaluation
        print(f"\n📊 Best Model: {best_name} (Score: {best_score:.4f})")
        
        # Store results
        self.models['supervised'] = best_model
        self.scalers['supervised'] = scaler
        
        training_time = time.time() - start_time
        print(f"⏱️  Training completed in {training_time:.1f}s")
        
        # Update history
        self.training_history.append({
            'timestamp': datetime.now(),
            'best_model': best_name,
            'best_score': best_score,
            'training_time': training_time,
            'classes': list(self.label_encoder.classes_)
        })
        
        return best_score
    
    def _prepare_data_optimized(self, features, labels):
        """Fast data preparation"""
        X = np.array(features)
        X = np.nan_to_num(X, nan=0.0, posinf=1e6, neginf=-1e6)
        
        y = self.label_encoder.fit_transform(labels)
        
        # Show distribution
        unique, counts = np.unique(labels, return_counts=True)
        print(f"  Classes: {dict(zip(unique, counts))}")
        
        # SMART BALANCING: Only if extreme imbalance and dataset not too large
        if len(counts) > 1:
            ratio = max(counts) / min(counts)
            if ratio > 20 and len(X) < 20000:  # Only balance small datasets with extreme imbalance
                print(f"  ⚖️  Balancing (ratio: {ratio:.1f}:1)...")
                X, y = self._balance_smart(X, y)
                print(f"  ✅ Balanced to {len(X):,} samples")
        
        return X, y
    
    def _balance_smart(self, X, y):
        """Smart balancing that doesn't explode dataset size"""
        try:
            # First undersample majority class
            undersampler = RandomUnderSampler(random_state=42, sampling_strategy='auto')
            X_under, y_under = undersampler.fit_resample(X, y)
            
            # Then light SMOTE
            min_samples = np.bincount(y_under).min()
            if min_samples > 1:
                k = min(3, min_samples - 1)
                smote = SMOTE(random_state=42, k_neighbors=k, sampling_strategy='auto')
                X_balanced, y_balanced = smote.fit_resample(X_under, y_under)
                return X_balanced, y_balanced
        except Exception as e:
            print(f"    Balancing failed: {e}")
        
        return X, y
    
    def save_models(self, model_dir='models'):
        """Save models"""
        model_path = Path(model_dir)
        model_path.mkdir(exist_ok=True)
        
        for name, model in self.models.items():
            joblib.dump(model, model_path / f"{name}_model.pkl")
        
        for name, scaler in self.scalers.items():
            joblib.dump(scaler, model_path / f"{name}_scaler.pkl")
        
        joblib.dump(self.label_encoder, model_path / "label_encoder.pkl")
        
        print(f"💾 Models saved to {model_path}")


def main():
    parser = argparse.ArgumentParser(description="Performance-Optimized Incremental ML Training")
    parser.add_argument("--dataset-dir", default="datasets", help="Dataset directory")
    parser.add_argument("--max-samples", type=int, default=20000, help="Max samples per file")
    parser.add_argument("--auto-train-threshold", type=int, default=30000, help="Auto-train threshold")
    parser.add_argument("--max-training-samples", type=int, default=50000, help="Max samples for training")
    
    args = parser.parse_args()
    
    print("🚀 === Performance-Optimized IDS Training ===")
    print(f"Max samples per file: {args.max_samples:,}")
    print(f"Auto-train threshold: {args.auto_train_threshold:,}")
    print(f"Max training samples: {args.max_training_samples:,}")
    
    collector = OptimizedIncrementalDataCollector()
    trainer = OptimizedModelTrainer()
    
    files = collector.detect_datasets(args.dataset_dir)
    if not files:
        return
    
    for i, file_path in enumerate(files, 1):
        print(f"\n📁 === FILE {i}/{len(files)} ===")
        
        samples_added, _ = collector.process_single_file(file_path, args.max_samples)
        
        if samples_added > 0:
            collector.print_session_summary()
            
            # Auto-train when threshold reached
            if (len(collector.features) >= args.auto_train_threshold and 
                trainer.can_train(collector.labels)):
                
                print(f"\n🎯 Auto-training at {len(collector.features):,} samples")
                trainer.train_optimized_models(
                    collector.features, 
                    collector.labels,
                    args.max_training_samples
                )
                trainer.save_models()
        
        # Simple continue prompt
        if i < len(files):
            response = input(f"\nContinue to next file? (y/n/t for train now): ").lower()
            if response == 'n':
                break
            elif response == 't':
                if trainer.can_train(collector.labels):
                    trainer.train_optimized_models(
                        collector.features, 
                        collector.labels,
                        args.max_training_samples
                    )
                    trainer.save_models()
    
    # Final training if needed
    if trainer.can_train(collector.labels) and not trainer.training_history:
        print(f"\n🧠 Final training...")
        trainer.train_optimized_models(
            collector.features, 
            collector.labels,
            args.max_training_samples
        )
        trainer.save_models()
    
    print(f"\n✅ Training complete!")
    if trainer.training_history:
        latest = trainer.training_history[-1]
        print(f"🏆 Best: {latest['best_model']} ({latest['best_score']:.4f})")


if __name__ == "__main__":
    main()