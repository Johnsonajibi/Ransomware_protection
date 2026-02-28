"""
Machine Learning Detection Layer
Advanced ransomware detection using ML/AI models
"""

import os
import json
import pickle
import logging
import numpy as np
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import hashlib

try:
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.preprocessing import StandardScaler
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import classification_report, confusion_matrix
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    logging.warning("scikit-learn not available, ML detection disabled")

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FeatureExtractor:
    """
    Extract features from files and processes for ML classification
    """
    
    def __init__(self):
        """Initialize feature extractor"""
        self.feature_names = [
            # File features
            'file_entropy',
            'file_size_log',
            'extension_is_suspicious',
            'has_double_extension',
            'file_age_hours',
            'modification_frequency',
            
            # Process features
            'process_cpu_percent',
            'process_memory_mb',
            'process_thread_count',
            'process_handle_count',
            'process_io_read_mb',
            'process_io_write_mb',
            
            # Behavioral features
            'files_modified_count',
            'files_deleted_count',
            'files_renamed_count',
            'network_connections_count',
            'registry_operations_count',
            'crypto_api_calls_count',
            
            # Statistical features
            'byte_frequency_entropy',
            'ascii_ratio',
            'printable_ratio',
            'high_entropy_blocks_ratio'
        ]
    
    def calculate_entropy(self, data: bytes, sample_size: int = 8192) -> float:
        """Calculate Shannon entropy of data"""
        if len(data) == 0:
            return 0.0
        
        # Sample for large files
        if len(data) > sample_size:
            data = data[:sample_size]
        
        # Calculate byte frequency
        byte_counts = np.bincount(np.frombuffer(data, dtype=np.uint8), minlength=256)
        probabilities = byte_counts / len(data)
        
        # Shannon entropy
        entropy = -np.sum(probabilities * np.log2(probabilities + 1e-10))
        return entropy
    
    def extract_file_features(self, file_path: str, 
                             file_data: Optional[bytes] = None) -> Dict[str, float]:
        """
        Extract features from a file
        
        Args:
            file_path: Path to file
            file_data: Optional file content (avoids re-reading)
            
        Returns:
            Dictionary of features
        """
        features = {}
        
        try:
            # Read file if not provided
            if file_data is None and os.path.exists(file_path):
                with open(file_path, 'rb') as f:
                    file_data = f.read()
            
            if file_data is None:
                return self._get_default_features()
            
            # File entropy
            features['file_entropy'] = self.calculate_entropy(file_data)
            
            # File size (log scale)
            features['file_size_log'] = np.log10(len(file_data) + 1)
            
            # Extension analysis
            ext = os.path.splitext(file_path)[1].lower()
            suspicious_extensions = [
                '.encrypted', '.locked', '.crypto', '.crypt', '.enc',
                '.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.js'
            ]
            features['extension_is_suspicious'] = float(ext in suspicious_extensions)
            
            # Double extension check
            basename = os.path.basename(file_path)
            features['has_double_extension'] = float(basename.count('.') > 1)
            
            # File age
            if os.path.exists(file_path):
                file_age = (datetime.now().timestamp() - os.path.getmtime(file_path)) / 3600
                features['file_age_hours'] = min(file_age, 720)  # Cap at 30 days
            else:
                features['file_age_hours'] = 0
            
            # Byte frequency analysis
            if len(file_data) > 0:
                byte_counts = np.bincount(np.frombuffer(file_data[:8192], dtype=np.uint8), minlength=256)
                byte_probs = byte_counts / len(file_data[:8192])
                features['byte_frequency_entropy'] = -np.sum(byte_probs * np.log2(byte_probs + 1e-10))
                
                # ASCII and printable ratio
                ascii_count = sum(1 for b in file_data[:8192] if 32 <= b < 127)
                features['ascii_ratio'] = ascii_count / len(file_data[:8192])
                
                printable_count = sum(1 for b in file_data[:8192] if 32 <= b < 127 or b in [9, 10, 13])
                features['printable_ratio'] = printable_count / len(file_data[:8192])
                
                # High entropy blocks
                block_size = 512
                high_entropy_blocks = 0
                for i in range(0, min(len(file_data), 8192), block_size):
                    block = file_data[i:i+block_size]
                    if len(block) >= block_size:
                        block_entropy = self.calculate_entropy(block)
                        if block_entropy > 7.5:
                            high_entropy_blocks += 1
                
                total_blocks = min(len(file_data), 8192) // block_size
                features['high_entropy_blocks_ratio'] = high_entropy_blocks / max(total_blocks, 1)
            
        except Exception as e:
            logger.error(f"Error extracting file features: {e}")
            return self._get_default_features()
        
        return features
    
    def extract_process_features(self, process_id: int, 
                                 behavior_data: Optional[Dict] = None) -> Dict[str, float]:
        """
        Extract features from a process
        
        Args:
            process_id: Process ID
            behavior_data: Optional behavioral statistics
            
        Returns:
            Dictionary of features
        """
        features = {}
        
        try:
            if not HAS_PSUTIL:
                return self._get_default_process_features()
            
            proc = psutil.Process(process_id)
            
            # CPU usage
            features['process_cpu_percent'] = proc.cpu_percent(interval=0.1)
            
            # Memory usage (MB)
            mem_info = proc.memory_info()
            features['process_memory_mb'] = mem_info.rss / (1024 * 1024)
            
            # Thread count
            features['process_thread_count'] = proc.num_threads()
            
            # Handle count
            try:
                features['process_handle_count'] = proc.num_handles()
            except:
                features['process_handle_count'] = 0
            
            # I/O statistics
            try:
                io_counters = proc.io_counters()
                features['process_io_read_mb'] = io_counters.read_bytes / (1024 * 1024)
                features['process_io_write_mb'] = io_counters.write_bytes / (1024 * 1024)
            except:
                features['process_io_read_mb'] = 0
                features['process_io_write_mb'] = 0
            
        except Exception as e:
            logger.error(f"Error extracting process features: {e}")
            return self._get_default_process_features()
        
        return features
    
    def extract_behavioral_features(self, behavior_data: Dict) -> Dict[str, float]:
        """
        Extract behavioral features from monitoring data
        
        Args:
            behavior_data: Dictionary with behavioral statistics
            
        Returns:
            Dictionary of features
        """
        return {
            'files_modified_count': float(behavior_data.get('files_modified', 0)),
            'files_deleted_count': float(behavior_data.get('files_deleted', 0)),
            'files_renamed_count': float(behavior_data.get('files_renamed', 0)),
            'network_connections_count': float(behavior_data.get('network_connections', 0)),
            'registry_operations_count': float(behavior_data.get('registry_operations', 0)),
            'crypto_api_calls_count': float(behavior_data.get('crypto_api_calls', 0)),
            'modification_frequency': float(behavior_data.get('modification_frequency', 0))
        }
    
    def extract_all_features(self, file_path: str = None, 
                            process_id: int = None,
                            behavior_data: Dict = None,
                            file_data: bytes = None) -> np.ndarray:
        """
        Extract all features for ML classification
        
        Returns:
            Feature vector as numpy array
        """
        all_features = {}
        
        # File features
        if file_path:
            file_features = self.extract_file_features(file_path, file_data)
            all_features.update(file_features)
        else:
            all_features.update(self._get_default_features())
        
        # Process features
        if process_id:
            process_features = self.extract_process_features(process_id, behavior_data)
            all_features.update(process_features)
        else:
            all_features.update(self._get_default_process_features())
        
        # Behavioral features
        if behavior_data:
            behavioral_features = self.extract_behavioral_features(behavior_data)
            all_features.update(behavioral_features)
        else:
            all_features.update(self._get_default_behavioral_features())
        
        # Convert to ordered array
        feature_vector = np.array([all_features.get(name, 0.0) for name in self.feature_names])
        
        return feature_vector
    
    def _get_default_features(self) -> Dict[str, float]:
        """Get default file features"""
        return {
            'file_entropy': 0.0,
            'file_size_log': 0.0,
            'extension_is_suspicious': 0.0,
            'has_double_extension': 0.0,
            'file_age_hours': 0.0,
            'byte_frequency_entropy': 0.0,
            'ascii_ratio': 0.0,
            'printable_ratio': 0.0,
            'high_entropy_blocks_ratio': 0.0
        }
    
    def _get_default_process_features(self) -> Dict[str, float]:
        """Get default process features"""
        return {
            'process_cpu_percent': 0.0,
            'process_memory_mb': 0.0,
            'process_thread_count': 0.0,
            'process_handle_count': 0.0,
            'process_io_read_mb': 0.0,
            'process_io_write_mb': 0.0
        }
    
    def _get_default_behavioral_features(self) -> Dict[str, float]:
        """Get default behavioral features"""
        return {
            'files_modified_count': 0.0,
            'files_deleted_count': 0.0,
            'files_renamed_count': 0.0,
            'network_connections_count': 0.0,
            'registry_operations_count': 0.0,
            'crypto_api_calls_count': 0.0,
            'modification_frequency': 0.0
        }


class MLRansomwareDetector:
    """
    Machine Learning ransomware detector
    """
    
    def __init__(self, model_path: str = "models/ransomware_classifier.pkl"):
        """
        Initialize ML detector
        
        Args:
            model_path: Path to trained model
        """
        self.model_path = model_path
        self.model = None
        self.scaler = None
        self.feature_extractor = FeatureExtractor()
        self.enabled = HAS_SKLEARN
        
        # Load model if exists
        if os.path.exists(model_path):
            self.load_model(model_path)
    
    def load_model(self, model_path: str) -> bool:
        """Load trained model"""
        try:
            if not HAS_SKLEARN:
                logger.error("scikit-learn not available")
                return False
            
            with open(model_path, 'rb') as f:
                model_data = pickle.load(f)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            
            logger.info(f"Loaded ML model from {model_path}")
            logger.info(f"Model type: {type(self.model).__name__}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {e}")
            return False
    
    def save_model(self, model_path: str) -> bool:
        """Save trained model"""
        try:
            os.makedirs(os.path.dirname(model_path), exist_ok=True)
            
            model_data = {
                'model': self.model,
                'scaler': self.scaler,
                'feature_names': self.feature_extractor.feature_names,
                'timestamp': datetime.now().isoformat()
            }
            
            with open(model_path, 'wb') as f:
                pickle.dump(model_data, f)
            
            logger.info(f"Model saved to {model_path}")
            return True
            
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False
    
    def predict(self, file_path: str = None, 
               process_id: int = None,
               behavior_data: Dict = None,
               file_data: bytes = None) -> Tuple[bool, float]:
        """
        Predict if sample is ransomware
        
        Args:
            file_path: Path to file
            process_id: Process ID
            behavior_data: Behavioral statistics
            file_data: Optional file content
            
        Returns:
            (is_ransomware, confidence)
        """
        try:
            if not self.enabled or self.model is None:
                return False, 0.0
            
            # Extract features
            features = self.feature_extractor.extract_all_features(
                file_path=file_path,
                process_id=process_id,
                behavior_data=behavior_data,
                file_data=file_data
            )
            
            # Scale features
            if self.scaler:
                features = self.scaler.transform(features.reshape(1, -1))
            else:
                features = features.reshape(1, -1)
            
            # Predict
            prediction = self.model.predict(features)[0]
            
            # Get probability if available
            if hasattr(self.model, 'predict_proba'):
                proba = self.model.predict_proba(features)[0]
                confidence = proba[1] if prediction == 1 else proba[0]
            else:
                confidence = 0.5
            
            is_ransomware = bool(prediction == 1)
            
            if is_ransomware:
                logger.warning(f"ML DETECTION: Ransomware (confidence: {confidence:.2%})")
            
            return is_ransomware, confidence
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {e}")
            return False, 0.0
    
    def train(self, training_data: List[Dict], labels: List[int]) -> bool:
        """
        Train the ML model
        
        Args:
            training_data: List of feature dictionaries
            labels: List of labels (0=benign, 1=ransomware)
            
        Returns:
            True if successful
        """
        try:
            if not HAS_SKLEARN:
                logger.error("scikit-learn required for training")
                return False
            
            if len(training_data) != len(labels):
                logger.error("Mismatched training data and labels")
                return False
            
            logger.info(f"Training ML model with {len(training_data)} samples...")
            
            # Extract features for all samples
            X = []
            for data in training_data:
                features = self.feature_extractor.extract_all_features(
                    file_path=data.get('file_path'),
                    process_id=data.get('process_id'),
                    behavior_data=data.get('behavior_data')
                )
                X.append(features)
            
            X = np.array(X)
            y = np.array(labels)
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            self.scaler = StandardScaler()
            X_train_scaled = self.scaler.fit_transform(X_train)
            X_test_scaled = self.scaler.transform(X_test)
            
            # Train Random Forest
            logger.info("Training Random Forest classifier...")
            self.model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
            self.model.fit(X_train_scaled, y_train)
            
            # Evaluate
            train_score = self.model.score(X_train_scaled, y_train)
            test_score = self.model.score(X_test_scaled, y_test)
            
            logger.info(f"Training accuracy: {train_score:.2%}")
            logger.info(f"Testing accuracy: {test_score:.2%}")
            
            # Detailed metrics
            y_pred = self.model.predict(X_test_scaled)
            logger.info("\nClassification Report:")
            logger.info(classification_report(y_test, y_pred, 
                                             target_names=['Benign', 'Ransomware']))
            
            # Feature importance
            feature_importance = self.model.feature_importances_
            top_features = np.argsort(feature_importance)[-10:]
            logger.info("\nTop 10 Important Features:")
            for idx in reversed(top_features):
                logger.info(f"  {self.feature_extractor.feature_names[idx]}: {feature_importance[idx]:.4f}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error training model: {e}")
            return False


if __name__ == "__main__":
    # Test ML detector
    print("Testing ML Ransomware Detector...")
    
    if not HAS_SKLEARN:
        print("ERROR: scikit-learn required. Install with: pip install scikit-learn")
        exit(1)
    
    detector = MLRansomwareDetector()
    
    # Test feature extraction
    print("\n=== Testing Feature Extraction ===")
    extractor = FeatureExtractor()
    
    # Create test file
    import tempfile
    test_file = tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.txt')
    test_file.write(b"Test content for ML detection")
    test_file.close()
    
    features = extractor.extract_all_features(file_path=test_file.name)
    print(f"Extracted {len(features)} features")
    print(f"Feature names: {extractor.feature_names[:5]}...")
    
    # Clean up
    os.unlink(test_file.name)
    
    # Test with synthetic training data
    print("\n=== Testing Model Training ===")
    print("Generating synthetic training data...")
    
    # Create synthetic dataset
    training_data = []
    labels = []
    
    # Benign samples (low entropy, normal behavior)
    for i in range(100):
        training_data.append({
            'behavior_data': {
                'files_modified': np.random.randint(0, 10),
                'files_deleted': 0,
                'modification_frequency': np.random.uniform(0, 1)
            }
        })
        labels.append(0)
    
    # Ransomware samples (high entropy, suspicious behavior)
    for i in range(100):
        training_data.append({
            'behavior_data': {
                'files_modified': np.random.randint(50, 200),
                'files_deleted': np.random.randint(10, 50),
                'modification_frequency': np.random.uniform(5, 20),
                'crypto_api_calls': np.random.randint(10, 100)
            }
        })
        labels.append(1)
    
    # Train model
    success = detector.train(training_data, labels)
    
    if success:
        print("\n✓ Model trained successfully!")
        
        # Save model
        model_path = "models/ransomware_classifier.pkl"
        detector.save_model(model_path)
        print(f"✓ Model saved to {model_path}")
        
        # Test prediction
        print("\n=== Testing Prediction ===")
        
        # Test benign
        is_malware, confidence = detector.predict(
            behavior_data={'files_modified': 5, 'files_deleted': 0}
        )
        print(f"Benign test: Ransomware={is_malware}, Confidence={confidence:.2%}")
        
        # Test ransomware
        is_malware, confidence = detector.predict(
            behavior_data={'files_modified': 150, 'files_deleted': 30, 'modification_frequency': 15}
        )
        print(f"Ransomware test: Ransomware={is_malware}, Confidence={confidence:.2%}")
    
    print("\nML Detector test complete!")
