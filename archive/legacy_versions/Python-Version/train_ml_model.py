"""
ML Model Training Script
Train ransomware detection model with labeled datasets
"""

import os
import sys
import json
import argparse
import logging
from datetime import datetime
from typing import List, Dict, Tuple
import numpy as np

try:
    from sklearn.model_selection import train_test_split, cross_val_score
    from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
    from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
    import joblib
    HAS_SKLEARN = True
except ImportError:
    HAS_SKLEARN = False
    print("ERROR: scikit-learn required. Install with: pip install scikit-learn")
    sys.exit(1)

from ml_detector import MLRansomwareDetector, FeatureExtractor

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class DatasetGenerator:
    """
    Generate synthetic training datasets for ransomware detection
    """
    
    def __init__(self):
        """Initialize dataset generator"""
        self.feature_extractor = FeatureExtractor()
    
    def generate_benign_samples(self, count: int) -> List[Dict]:
        """Generate benign file behavior samples"""
        samples = []
        
        for i in range(count):
            sample = {
                'behavior_data': {
                    'files_modified': np.random.randint(0, 15),
                    'files_deleted': np.random.randint(0, 3),
                    'files_renamed': np.random.randint(0, 5),
                    'network_connections': np.random.randint(0, 10),
                    'registry_operations': np.random.randint(0, 20),
                    'crypto_api_calls': np.random.randint(0, 5),
                    'modification_frequency': np.random.uniform(0, 2)
                },
                'label': 0,
                'category': 'benign'
            }
            samples.append(sample)
        
        return samples
    
    def generate_ransomware_samples(self, count: int) -> List[Dict]:
        """Generate ransomware behavior samples"""
        samples = []
        
        for i in range(count):
            # Ransomware typically shows high file activity
            sample = {
                'behavior_data': {
                    'files_modified': np.random.randint(50, 500),
                    'files_deleted': np.random.randint(10, 100),
                    'files_renamed': np.random.randint(20, 200),
                    'network_connections': np.random.randint(1, 5),
                    'registry_operations': np.random.randint(5, 50),
                    'crypto_api_calls': np.random.randint(50, 300),
                    'modification_frequency': np.random.uniform(10, 50)
                },
                'label': 1,
                'category': 'ransomware'
            }
            samples.append(sample)
        
        return samples
    
    def generate_dataset(self, benign_count: int, ransomware_count: int) -> Tuple[List, List]:
        """
        Generate complete dataset
        
        Returns:
            (samples, labels)
        """
        logger.info(f"Generating dataset: {benign_count} benign, {ransomware_count} ransomware")
        
        samples = []
        labels = []
        
        # Generate benign samples
        benign_samples = self.generate_benign_samples(benign_count)
        samples.extend(benign_samples)
        labels.extend([0] * benign_count)
        
        # Generate ransomware samples
        ransomware_samples = self.generate_ransomware_samples(ransomware_count)
        samples.extend(ransomware_samples)
        labels.extend([1] * ransomware_count)
        
        logger.info(f"✓ Generated {len(samples)} total samples")
        
        return samples, labels
    
    def load_dataset_from_file(self, file_path: str) -> Tuple[List, List]:
        """
        Load dataset from JSON file
        
        Format:
        [
            {"behavior_data": {...}, "label": 0},
            {"behavior_data": {...}, "label": 1},
            ...
        ]
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            samples = [item for item in data]
            labels = [item['label'] for item in data]
            
            logger.info(f"Loaded {len(samples)} samples from {file_path}")
            return samples, labels
        
        except Exception as e:
            logger.error(f"Error loading dataset: {e}")
            return [], []
    
    def save_dataset(self, samples: List, labels: List, file_path: str):
        """Save dataset to JSON file"""
        try:
            data = []
            for sample, label in zip(samples, labels):
                sample['label'] = label
                data.append(sample)
            
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            
            with open(file_path, 'w') as f:
                json.dump(data, f, indent=2)
            
            logger.info(f"✓ Dataset saved to {file_path}")
        
        except Exception as e:
            logger.error(f"Error saving dataset: {e}")


class ModelTrainer:
    """
    Train and evaluate ransomware detection models
    """
    
    def __init__(self):
        """Initialize trainer"""
        self.detector = MLRansomwareDetector()
        self.best_model = None
        self.best_score = 0.0
    
    def train_model(self, training_data: List[Dict], labels: List[int],
                   model_type: str = 'random_forest',
                   cross_validate: bool = True) -> bool:
        """
        Train model with given data
        
        Args:
            training_data: List of samples
            labels: List of labels
            model_type: 'random_forest' or 'gradient_boosting'
            cross_validate: Perform cross-validation
            
        Returns:
            True if successful
        """
        try:
            logger.info(f"Training {model_type} model...")
            logger.info(f"Dataset: {len(training_data)} samples")
            
            # Extract features
            logger.info("Extracting features...")
            X = []
            for data in training_data:
                features = self.detector.feature_extractor.extract_all_features(
                    file_path=data.get('file_path'),
                    process_id=data.get('process_id'),
                    behavior_data=data.get('behavior_data')
                )
                X.append(features)
            
            X = np.array(X)
            y = np.array(labels)
            
            logger.info(f"Feature matrix shape: {X.shape}")
            
            # Split data
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.2, random_state=42, stratify=y
            )
            
            # Scale features
            from sklearn.preprocessing import StandardScaler
            self.detector.scaler = StandardScaler()
            X_train_scaled = self.detector.scaler.fit_transform(X_train)
            X_test_scaled = self.detector.scaler.transform(X_test)
            
            # Select model
            if model_type == 'random_forest':
                model = RandomForestClassifier(
                    n_estimators=200,
                    max_depth=15,
                    min_samples_split=5,
                    min_samples_leaf=2,
                    random_state=42,
                    n_jobs=-1,
                    class_weight='balanced'
                )
            elif model_type == 'gradient_boosting':
                model = GradientBoostingClassifier(
                    n_estimators=100,
                    learning_rate=0.1,
                    max_depth=5,
                    random_state=42
                )
            else:
                logger.error(f"Unknown model type: {model_type}")
                return False
            
            # Cross-validation
            if cross_validate:
                logger.info("Performing 5-fold cross-validation...")
                cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5)
                logger.info(f"CV Scores: {cv_scores}")
                logger.info(f"CV Mean: {cv_scores.mean():.4f} (+/- {cv_scores.std() * 2:.4f})")
            
            # Train model
            logger.info("Training model...")
            model.fit(X_train_scaled, y_train)
            
            # Evaluate
            train_score = model.score(X_train_scaled, y_train)
            test_score = model.score(X_test_scaled, y_test)
            
            logger.info(f"Training accuracy: {train_score:.4f}")
            logger.info(f"Testing accuracy: {test_score:.4f}")
            
            # Predictions
            y_pred = model.predict(X_test_scaled)
            y_proba = model.predict_proba(X_test_scaled)[:, 1]
            
            # Detailed metrics
            logger.info("\nClassification Report:")
            print(classification_report(y_test, y_pred, 
                                       target_names=['Benign', 'Ransomware'],
                                       digits=4))
            
            logger.info("\nConfusion Matrix:")
            cm = confusion_matrix(y_test, y_pred)
            print(cm)
            
            # ROC AUC
            try:
                auc = roc_auc_score(y_test, y_proba)
                logger.info(f"\nROC AUC Score: {auc:.4f}")
            except:
                pass
            
            # Feature importance
            if hasattr(model, 'feature_importances_'):
                feature_importance = model.feature_importances_
                top_features = np.argsort(feature_importance)[-15:]
                
                logger.info("\nTop 15 Important Features:")
                for idx in reversed(top_features):
                    feat_name = self.detector.feature_extractor.feature_names[idx]
                    logger.info(f"  {feat_name:40s}: {feature_importance[idx]:.4f}")
            
            # Save best model
            if test_score > self.best_score:
                self.best_score = test_score
                self.best_model = model
                self.detector.model = model
                logger.info(f"\n✓ New best model (score: {test_score:.4f})")
            
            return True
        
        except Exception as e:
            logger.error(f"Error training model: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def save_best_model(self, output_path: str):
        """Save the best trained model"""
        if self.best_model is None:
            logger.error("No model trained yet")
            return False
        
        try:
            self.detector.model = self.best_model
            success = self.detector.save_model(output_path)
            
            if success:
                logger.info(f"\n✓ Best model saved to {output_path}")
                logger.info(f"  Test accuracy: {self.best_score:.4f}")
            
            return success
        
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            return False


def main():
    """Main training script"""
    parser = argparse.ArgumentParser(description='Train ML ransomware detection model')
    parser.add_argument('--dataset', help='Path to training dataset JSON file')
    parser.add_argument('--benign', type=int, default=500, help='Number of benign samples to generate')
    parser.add_argument('--ransomware', type=int, default=500, help='Number of ransomware samples')
    parser.add_argument('--model', choices=['random_forest', 'gradient_boosting'], 
                       default='random_forest', help='Model type')
    parser.add_argument('--output', default='models/ransomware_classifier.pkl', 
                       help='Output model path')
    parser.add_argument('--no-cv', action='store_true', help='Disable cross-validation')
    
    args = parser.parse_args()
    
    logger.info("=" * 70)
    logger.info("ML RANSOMWARE DETECTION MODEL TRAINING")
    logger.info("=" * 70)
    
    # Generate or load dataset
    generator = DatasetGenerator()
    
    if args.dataset and os.path.exists(args.dataset):
        logger.info(f"\nLoading dataset from {args.dataset}")
        samples, labels = generator.load_dataset_from_file(args.dataset)
    else:
        logger.info(f"\nGenerating synthetic dataset")
        samples, labels = generator.generate_dataset(args.benign, args.ransomware)
        
        # Save generated dataset
        dataset_path = 'datasets/training_data.json'
        generator.save_dataset(samples, labels, dataset_path)
    
    if len(samples) == 0:
        logger.error("No training data available")
        return 1
    
    # Train model
    trainer = ModelTrainer()
    
    logger.info(f"\nTraining {args.model} model...")
    success = trainer.train_model(
        samples, 
        labels, 
        model_type=args.model,
        cross_validate=not args.no_cv
    )
    
    if not success:
        logger.error("Training failed")
        return 1
    
    # Save model
    logger.info(f"\nSaving model to {args.output}")
    trainer.save_best_model(args.output)
    
    logger.info("\n" + "=" * 70)
    logger.info("✓ TRAINING COMPLETE!")
    logger.info("=" * 70)
    logger.info(f"\nModel saved to: {args.output}")
    logger.info(f"Best accuracy: {trainer.best_score:.2%}")
    logger.info("\nTo use the model:")
    logger.info("  from ml_detector import MLRansomwareDetector")
    logger.info(f"  detector = MLRansomwareDetector('{args.output}')")
    logger.info("  is_malware, confidence = detector.predict(file_path='...')")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
