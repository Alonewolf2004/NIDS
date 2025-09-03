"""
NIDS ML Model Training with RandomForest
VERSION 3.3 - FINAL & ROBUST
- FINAL FIX: Automatically removes duplicate feature columns to prevent type errors during preprocessing.
- MODEL: Uses RandomForestClassifier.
- STRATEGY: Loads a large, safe sample of the data into memory.
"""

import pandas as pd
import numpy as np
import time
from pathlib import Path
from datetime import datetime
import argparse
import warnings
import hashlib
import logging
import psutil # For memory monitoring
import gc # Garbage collection
warnings.filterwarnings('ignore')

try:
    from tqdm import tqdm as tqdm_bar
except ImportError:
    class tqdm_bar:
        def __init__(self, total=None, desc="", unit="it", ncols=None):
            self.total, self.desc, self.unit, self.current = total, desc, unit, 0
            print(f"{self.desc}: Starting...")
        def update(self, n=1): self.current += n
        def close(self): print(f"\n{self.desc}: Complete!")
        def __enter__(self): return self
        def __exit__(self, *args): self.close()

# --- ML Imports ---
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
import joblib

# --- Basic Setup ---
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class DataHandler:
    """Handles data discovery, loading, and cleaning."""
    def detect_datasets(self, dataset_dir='datasets'):
        dataset_path = Path(dataset_dir)
        if not dataset_path.exists():
            logger.error(f"Dataset directory '{dataset_dir}' not found!")
            return []
        logger.info(f"Scanning dataset directory: {dataset_path}")
        all_files = list(dataset_path.rglob("*.csv"))
        unique_files = self._deduplicate_files_advanced(all_files)
        if not unique_files:
            logger.error("No unique CSV dataset files found.")
            return []
        logger.info(f"Found {len(unique_files)} unique CSV dataset files.")
        unique_files.sort(key=lambda x: x.stat().st_size)
        return unique_files

    def _deduplicate_files_advanced(self, all_files):
        unique_files = {}
        for file_path in all_files:
            try:
                stat = file_path.stat()
                with open(file_path, 'rb') as f:
                    first_chunk = f.read(1024)
                file_hash = hashlib.md5(f"{stat.st_size}{first_chunk}".encode()).hexdigest()
                if file_hash not in unique_files:
                    unique_files[file_hash] = file_path
            except Exception as e:
                logger.warning(f"Error hashing {file_path}: {e}")
        return list(unique_files.values())

    def _detect_csv_separator(self, csv_file):
        try:
            with open(csv_file, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline()
            separators = [',', ';', '\t', '|']
            counts = {sep: first_line.count(sep) for sep in separators}
            if max(counts.values()) > 1:
                return max(counts, key=counts.get)
        except Exception:
            pass
        return ','

    def load_and_sample_data(self, files, max_samples=2000000):
        """Loads data from files up to a maximum sample limit to prevent memory errors."""
        all_dfs = []
        total_rows = 0
        logger.info(f"Loading data with a limit of {max_samples:,} samples...")

        with tqdm_bar(total=max_samples, desc="Loading Samples", unit=" rows") as pbar:
            for file_path in files:
                if total_rows >= max_samples:
                    logger.info(f"Reached sample limit of {max_samples}. Stopping data loading.")
                    break
                try:
                    separator = self._detect_csv_separator(file_path)
                    df = pd.read_csv(file_path, sep=separator, low_memory=False, on_bad_lines='skip')
                    all_dfs.append(df)
                    rows_added = len(df)
                    total_rows += rows_added
                    pbar.update(rows_added)
                except Exception as e:
                    logger.warning(f"Could not load {file_path.name}: {e}")
        
        if not all_dfs:
            logger.error("No data could be loaded. Exiting.")
            return None

        logger.info("Combining loaded data...")
        full_df = pd.concat(all_dfs, ignore_index=True)
        gc.collect()
        
        if len(full_df) > max_samples:
            logger.info(f"Dataframe is larger than limit. Taking a random sample of {max_samples:,} rows.")
            full_df = full_df.sample(n=max_samples, random_state=42)
            gc.collect()

        logger.info(f"Loaded a total of {len(full_df):,} samples.")
        return full_df

class RandomForestTrainer:
    """Trains a RandomForest model on a given dataset."""
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.feature_columns = None
        self.X_train, self.X_test, self.y_train, self.y_test = None, None, None, None

    def _clean_labels(self, labels):
        if isinstance(labels, pd.DataFrame):
            labels = labels.iloc[:, 0]
        return labels.astype(str).str.strip().str.lower()

    def preprocess_data(self, df):
        """Prepares the loaded DataFrame for training."""
        logger.info("Starting data preprocessing...")

        # 1. Clean and de-duplicate column names
        df.columns = [str(col).strip().lower() for col in df.columns]
        
        # --- THIS IS THE FIX ---
        # Find duplicate columns and remove them, keeping the first occurrence
        is_duplicate = df.columns.duplicated(keep='first')
        if is_duplicate.any():
            logger.warning(f"Found and removed duplicate columns: {df.columns[is_duplicate].tolist()}")
            df = df.loc[:, ~is_duplicate]
        # ----------------------

        # 2. Find and separate the label column
        label_col = 'label'
        if label_col not in df.columns:
            for col in df.columns:
                if 'label' in col or 'class' in col:
                    label_col = col
                    break
        if label_col not in df.columns:
            logger.error("Could not automatically detect a label column.")
            return False
            
        logger.info(f"Detected '{label_col}' as the label column.")
        labels_raw = df.pop(label_col)
        labels = self._clean_labels(labels_raw)
        
        # 3. Preprocess features
        features = df
        for col in features.columns:
            features[col] = pd.to_numeric(features[col], errors='coerce')
        features.replace([np.inf, -np.inf], np.nan, inplace=True)
        features.fillna(0, inplace=True)
        self.feature_columns = features.columns.tolist()

        # 4. Encode labels
        y = self.label_encoder.fit_transform(labels)
        logger.info(f"Found {len(self.label_encoder.classes_)} unique classes.")

        # 5. Split data
        logger.info("Splitting data into training and testing sets...")
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(
            features, y, test_size=0.2, random_state=42, stratify=y
        )

        # 6. Scale features
        logger.info("Scaling features...")
        self.X_train = self.scaler.fit_transform(self.X_train)
        self.X_test = self.scaler.transform(self.X_test)

        logger.info("Preprocessing complete.")
        return True

    def train_model(self):
        """Initializes and trains the RandomForestClassifier."""
        logger.info("Training RandomForestClassifier model...")
        self.model = RandomForestClassifier(n_estimators=100, random_state=42, n_jobs=-1, verbose=1)
        start_time = time.time()
        self.model.fit(self.X_train, self.y_train)
        training_time = time.time() - start_time
        logger.info(f"Training complete in {training_time:.2f} seconds.")
        return True

    def evaluate_model(self):
        """Evaluates the trained model."""
        logger.info("Evaluating model...")
        y_pred = self.model.predict(self.X_test)
        accuracy = accuracy_score(self.y_test, y_pred)
        report = classification_report(self.y_test, y_pred, target_names=self.label_encoder.classes_, zero_division=0)
        logger.info("\n--- Model Evaluation Report ---")
        logger.info(f"Accuracy: {accuracy:.4f}")
        logger.info("\nClassification Report:\n" + report)
    
    def save_model_pipeline(self, output_dir='models', model_name='nids_randomforest'):
        """Saves the complete pipeline."""
        logger.info(f"Saving model pipeline to '{output_dir}' directory...")
        output_path = Path(output_dir)
        output_path.mkdir(exist_ok=True)
        try:
            joblib.dump(self.model, output_path / f"{model_name}.joblib")
            joblib.dump(self.scaler, output_path / "scaler.joblib")
            joblib.dump(self.label_encoder, output_path / "label_encoder.joblib")
            joblib.dump(self.feature_columns, output_path / "feature_columns.joblib")
            logger.info("Model pipeline saved successfully.")
        except Exception as e:
            logger.error(f"Error saving model: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="NIDS ML Model Training Pipeline with RandomForest")
    parser.add_argument('--dataset_dir', type=str, default='datasets', help='Directory containing dataset files')
    parser.add_argument('--model_dir', type=str, default='models', help='Directory to save trained models')
    parser.add_argument('--max_samples', type=int, default=2000000, help='Maximum number of samples to load into memory')
    args = parser.parse_args()

    # --- Main Pipeline ---
    data_handler = DataHandler()
    trainer = RandomForestTrainer()

    # 1. Find dataset files
    all_files = data_handler.detect_datasets(args.dataset_dir)
    
    if all_files:
        # 2. Load a sample of the data
        df = data_handler.load_and_sample_data(all_files, args.max_samples)
        
        if df is not None:
            # 3. Preprocess the data
            if trainer.preprocess_data(df):
                # 4. Train the model
                if trainer.train_model():
                    # 5. Evaluate and Save
                    trainer.evaluate_model()
                    trainer.save_model_pipeline(output_dir=args.model_dir)
                    logger.info("\n--- Training Pipeline Complete ---")