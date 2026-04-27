# train_models.py
"""
Training script for Riley Falcon IDPS Machine Learning Models
Run this script once to generate all required .pkl files
"""

import numpy as np
import pickle
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
import os
import sys
from datetime import datetime

print("=" * 60)
print("RILEY FALCON SECURITY SERVICES - IDPS")
print("Machine Learning Model Training Script")
print("=" * 60)
print(f"Start Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)

# Create directory if it doesn't exist
os.makedirs('ml_models', exist_ok=True)
print(f"\n✅ Created directory: ml_models/")

# Set random seed for reproducibility
np.random.seed(42)

# 1. Train Anomaly Detection Model (Isolation Forest)
print("\n" + "=" * 40)
print("[1/3] Training Anomaly Detection Model...")
print("=" * 40)

n_samples = 10000
n_features = 15

print(f"   - Generating {n_samples} samples with {n_features} features...")

# Generate normal traffic data (95%)
X_normal = np.random.randn(n_samples, n_features)

# Generate anomalous traffic data (5%)
n_anomalies = int(n_samples * 0.05)
X_anomaly = np.random.randn(n_anomalies, n_features) * 3 + 2

# Combine
X_train = np.vstack([X_normal, X_anomaly])
print(f"   - Training data shape: {X_train.shape}")
print(f"   - Normal samples: {n_samples}")
print(f"   - Anomaly samples: {n_anomalies}")

# Train Isolation Forest
print("   - Training Isolation Forest model...")
anomaly_model = IsolationForest(
    contamination=0.05,
    random_state=42,
    n_estimators=100,
    max_samples='auto',
    bootstrap=False,
    verbose=0
)
anomaly_model.fit(X_train)

# Save anomaly model
model_path = 'ml_models/anomalymodel.pkl'
with open(model_path, 'wb') as f:
    pickle.dump(anomaly_model, f)
print(f"   ✅ Anomaly model saved to: {model_path}")

# 2. Train Scaler
print("\n" + "=" * 40)
print("[2/3] Training Scaler...")
print("=" * 40)

scaler = StandardScaler()
scaler.fit(X_train)
print(f"   - Scaler mean shape: {scaler.mean_.shape}")
print(f"   - Scaler scale shape: {scaler.scale_.shape}")

# Save scaler
scaler_path = 'ml_models/scaler.pkl'
with open(scaler_path, 'wb') as f:
    pickle.dump(scaler, f)
print(f"   ✅ Scaler saved to: {scaler_path}")

# 3. Train Signature Detection Model (Random Forest)
print("\n" + "=" * 40)
print("[3/3] Training Signature Detection Model...")
print("=" * 40)

# Create signature patterns for different attacks
attack_patterns = {
    'sql_injection': [1,0,1,0,1,0,1,0,1,0,1,0,1,0,1],
    'xss': [0,1,0,1,0,1,0,1,0,1,0,1,0,1,0],
    'port_scan': [1,1,0,0,1,1,0,0,1,1,0,0,1,1,0],
    'ddos': [1,1,1,0,1,1,1,0,1,1,1,0,1,1,1],
    'bruteforce': [0,1,1,1,0,1,1,1,0,1,1,1,0,1,1],
    'malware': [1,0,1,1,0,1,0,1,1,0,1,0,1,1,0],
    'phishing': [0,1,0,1,1,0,1,0,1,1,0,1,0,1,1],
    'privilege_escalation': [1,1,0,1,0,1,1,0,1,0,1,1,0,1,0]
}

print(f"   - Creating signature patterns for {len(attack_patterns)} attack types:")

# Generate training data
X_signature = []
y_signature = []

# Normal traffic (class 0)
n_normal = 8000
print(f"   - Generating {n_normal} normal traffic samples...")
for _ in range(n_normal):
    features = np.random.randn(n_features) * 0.5
    X_signature.append(features)
    y_signature.append(0)

# Attack traffic (class 1) with patterns
samples_per_attack = 400
for attack_name, pattern in attack_patterns.items():
    print(f"   - Generating {samples_per_attack} samples for: {attack_name}")
    for _ in range(samples_per_attack):
        noise = np.random.randn(n_features) * 0.2
        features = np.array(pattern) + noise
        X_signature.append(features)
        y_signature.append(1)

X_signature = np.array(X_signature)
y_signature = np.array(y_signature)

print(f"\n   - Final training data:")
print(f"     • Total samples: {len(X_signature)}")
print(f"     • Normal samples: {sum(1 for y in y_signature if y == 0)}")
print(f"     • Attack samples: {sum(1 for y in y_signature if y == 1)}")

# Train Random Forest
print("   - Training Random Forest model...")
signature_model = RandomForestClassifier(
    n_estimators=100,
    max_depth=15,
    min_samples_split=5,
    min_samples_leaf=2,
    random_state=42,
    n_jobs=-1,
    verbose=0
)
signature_model.fit(X_signature, y_signature)

# Calculate and display feature importance
feature_importance = signature_model.feature_importances_
print(f"\n   - Top 5 Important Features:")
top_features = sorted(enumerate(feature_importance), key=lambda x: x[1], reverse=True)[:5]
for idx, importance in top_features:
    print(f"     • Feature {idx}: {importance:.4f}")

# Save signature model
signature_path = 'ml_models/signature_model.pkl'
with open(signature_path, 'wb') as f:
    pickle.dump(signature_model, f)
print(f"   ✅ Signature model saved to: {signature_path}")

# Create __init__.py for ml_models
init_path = 'ml_models/__init__.py'
with open(init_path, 'w') as f:
    f.write('''"""
Machine Learning Models for Riley Falcon IDPS
This package contains trained ML models for intrusion detection:

- anomalymodel.pkl: Isolation Forest for anomaly detection
- scaler.pkl: StandardScaler for feature normalization
- signature_model.pkl: Random Forest for signature-based detection
"""

import os
import pickle
import numpy as np

class ModelLoader:
    """Utility class to load and use ML models"""
    
    def __init__(self):
        self.model_dir = os.path.dirname(os.path.abspath(__file__))
        self.anomaly_model = None
        self.scaler = None
        self.signature_model = None
        self.models_loaded = False
        
    def load_models(self):
        """Load all ML models"""
        try:
            with open(os.path.join(self.model_dir, 'anomalymodel.pkl'), 'rb') as f:
                self.anomaly_model = pickle.load(f)
            
            with open(os.path.join(self.model_dir, 'scaler.pkl'), 'rb') as f:
                self.scaler = pickle.load(f)
            
            with open(os.path.join(self.model_dir, 'signature_model.pkl'), 'rb') as f:
                self.signature_model = pickle.load(f)
            
            self.models_loaded = True
            print("✅ All ML models loaded successfully")
            return True
        except Exception as e:
            print(f"❌ Error loading models: {str(e)}")
            self.models_loaded = False
            return False
    
    def predict_anomaly(self, features):
        """Predict if features are anomalous (returns score 0-1)"""
        if not self.models_loaded:
            return 0.5
        try:
            features_scaled = self.scaler.transform([features])
            score = self.anomaly_model.score_samples(features_scaled)[0]
            anomaly_score = 1 / (1 + np.exp(-score))
            return float(anomaly_score)
        except Exception as e:
            print(f"Error in anomaly prediction: {e}")
            return 0.5
    
    def predict_signature(self, features):
        """Predict if features match known attack signatures (returns probability 0-1)"""
        if not self.models_loaded:
            return 0.5
        try:
            features_scaled = self.scaler.transform([features])
            probabilities = self.signature_model.predict_proba(features_scaled)[0]
            return float(probabilities[1])
        except Exception as e:
            print(f"Error in signature prediction: {e}")
            return 0.5
    
    def hybrid_detection(self, features, anomaly_weight=0.4, signature_weight=0.6):
        """Combine anomaly and signature detection"""
        anomaly_score = self.predict_anomaly(features)
        signature_score = self.predict_signature(features)
        hybrid_score = anomaly_weight * anomaly_score + signature_weight * signature_score
        return hybrid_score, anomaly_score, signature_score

# Create global model loader instance
model_loader = ModelLoader()
''')
print(f"   ✅ Created: {init_path}")

# Test the models
print("\n" + "=" * 40)
print("Testing Models...")
print("=" * 40)

try:
    from ml_models import model_loader
    model_loader.load_models()
    
    # Test with random features
    test_features = np.random.randn(n_features)
    anomaly_score = model_loader.predict_anomaly(test_features)
    signature_score = model_loader.predict_signature(test_features)
    hybrid_score, _, _ = model_loader.hybrid_detection(test_features)
    
    print(f"\n   Test Results:")
    print(f"   • Anomaly Score: {anomaly_score:.4f}")
    print(f"   • Signature Score: {signature_score:.4f}")
    print(f"   • Hybrid Score: {hybrid_score:.4f}")
    print("   ✅ Model test successful!")
    
except Exception as e:
    print(f"   ❌ Model test failed: {e}")

print("\n" + "=" * 60)
print("TRAINING COMPLETE!")
print("=" * 60)
print(f"\nFiles created in ml_models/:")
print("  1. anomalymodel.pkl  - Isolation Forest (Anomaly Detection)")
print("  2. scaler.pkl        - StandardScaler (Feature Normalization)")
print("  3. signature_model.pkl - Random Forest (Signature Detection)")
print("  4. __init__.py       - Model loader module")
print("\nTotal size: ~{:.2f} MB".format(
    sum(os.path.getsize(f"ml_models/{f}") for f in os.listdir("ml_models") if f.endswith('.pkl')) / (1024*1024)
))
print("\nNext steps:")
print("  1. Install requirements: pip install -r requirements.txt")
print("  2. Run the application: python run.py")
print("  3. Access the system at: http://localhost:5000")
print("\n" + "=" * 60)
print(f"End Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
print("=" * 60)