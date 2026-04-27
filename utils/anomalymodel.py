# utils/anomalymodel.py
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import joblib
import pickle
import os

class AnomalyModel:
    def __init__(self):
        self.model = None
        self.scaler = None
        
    def train_model(self):
        """Train anomaly detection model"""
        # Generate synthetic training data (in production, use real network data)
        np.random.seed(42)
        n_samples = 10000
        
        # Features: [packet_size, protocol, port, flags, ttl, window_size, payload_len, etc.]
        X_train = np.random.randn(n_samples, 15)
        
        # Add some anomalies (5% of data)
        n_anomalies = int(n_samples * 0.05)
        anomaly_indices = np.random.choice(n_samples, n_anomalies, replace=False)
        X_train[anomaly_indices] += np.random.randn(n_anomalies, 15) * 3
        
        # Train Isolation Forest
        self.model = IsolationForest(
            contamination=0.05,
            random_state=42,
            n_estimators=100,
            max_samples='auto'
        )
        self.model.fit(X_train)
        
        # Train scaler
        self.scaler = StandardScaler()
        self.scaler.fit(X_train)
        
        return self.model, self.scaler
    
    def save_models(self):
        """Save trained models"""
        os.makedirs('app/ml_models', exist_ok=True)
        
        with open('app/ml_models/anomalymodel.pkl', 'wb') as f:
            pickle.dump(self.model, f)
        
        with open('app/ml_models/scaler.pkl', 'wb') as f:
            pickle.dump(self.scaler, f)
        
        print("Models saved successfully!")

if __name__ == "__main__":
    trainer = AnomalyModel()
    trainer.train_model()
    trainer.save_models()