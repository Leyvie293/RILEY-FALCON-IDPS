# utils/ai_engine.py
"""
AI Engine for hybrid intrusion detection
Combines anomaly detection and signature-based detection
"""

import numpy as np
import pickle
import os
import sys
from datetime import datetime

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class AIEngine:
    def __init__(self):
        self.anomaly_model = None
        self.signature_model = None
        self.scaler = None
        self.models_loaded = False
        self.last_training = None
        self.training_samples = 0
        
        # Load models
        self._load_models()
    
    def _load_models(self):
        """Load pre-trained models"""
        model_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'ml_models')
        
        try:
            # Load anomaly model
            anomaly_path = os.path.join(model_dir, 'anomalymodel.pkl')
            if os.path.exists(anomaly_path):
                with open(anomaly_path, 'rb') as f:
                    self.anomaly_model = pickle.load(f)
                print("✅ Anomaly detection model loaded")
            
            # Load scaler
            scaler_path = os.path.join(model_dir, 'scaler.pkl')
            if os.path.exists(scaler_path):
                with open(scaler_path, 'rb') as f:
                    self.scaler = pickle.load(f)
                print("✅ Scaler loaded")
            
            # Load signature model
            sig_path = os.path.join(model_dir, 'signature_model.pkl')
            if os.path.exists(sig_path):
                with open(sig_path, 'rb') as f:
                    self.signature_model = pickle.load(f)
                print("✅ Signature detection model loaded")
            
            self.models_loaded = True
            self.last_training = datetime.now()
            
        except Exception as e:
            print(f"⚠️ Error loading AI models: {e}")
            print("   Using rule-based detection only")
            self.models_loaded = False
    
    def extract_features_from_packet(self, packet):
        """Extract features from packet and return 2D array"""
        try:
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            
            features = []
            
            # Basic packet features
            features.append(len(packet))  # packet length
            
            if IP in packet:
                features.append(packet[IP].ttl)  # TTL
                features.append(packet[IP].len)  # IP length
            else:
                features.append(64)
                features.append(0)
            
            # Protocol flags
            features.append(1 if TCP in packet else 0)
            features.append(1 if UDP in packet else 0)
            features.append(1 if ICMP in packet else 0)
            
            # TCP specific features
            if TCP in packet:
                features.append(packet[TCP].sport)  # source port
                features.append(packet[TCP].dport)  # dest port
                features.append(int(packet[TCP].flags))  # flags as int
                features.append(packet[TCP].window)  # window size
            else:
                features.append(0)
                features.append(0)
                features.append(0)
                features.append(8192)
            
            # UDP specific
            if UDP in packet:
                features.append(packet[UDP].sport)
                features.append(packet[UDP].dport)
                features.append(packet[UDP].len)
            else:
                features.append(0)
                features.append(0)
                features.append(0)
            
            # Ensure exactly 15 features
            while len(features) < 15:
                features.append(0)
            features = features[:15]
            
            # Convert to 2D array (1 sample, N features)
            features_2d = np.array(features).reshape(1, -1)
            
            # Apply scaler if available
            if self.scaler is not None:
                try:
                    features_2d = self.scaler.transform(features_2d)
                except Exception:
                    pass
            
            return features_2d
            
        except Exception as e:
            print(f"Feature extraction error: {e}")
            # Return zero features as fallback
            return np.zeros((1, 15))
    
    def extract_features_from_text(self, text):
        """Extract features from text for signature detection"""
        features = [
            len(text),
            text.count(' '),
            text.count('/'),
            text.count('.'),
            text.count('-'),
            text.count('_'),
            text.count('='),
            text.count('&'),
            text.count('?'),
            text.count('%'),
            text.count('+'),
            text.count('*'),
            text.count('$'),
            text.count('!'),
            text.count('@'),
        ]
        
        while len(features) < 15:
            features.append(0)
        features = features[:15]
        
        return np.array(features).reshape(1, -1)
    
    def detect_anomaly(self, features):
        """Detect anomaly using Isolation Forest"""
        try:
            if self.anomaly_model is None:
                return 0.0
            
            # Ensure 2D array
            if hasattr(features, 'ndim'):
                if features.ndim == 1:
                    features = features.reshape(1, -1)
                elif features.ndim == 3:
                    features = features.reshape(features.shape[0], -1)
            
            prediction = self.anomaly_model.predict(features)
            # Isolation Forest: -1 = anomaly, 1 = normal
            score = 1.0 if prediction[0] == -1 else 0.0
            return score
        except Exception as e:
            print(f"Anomaly detection error: {e}")
            return 0.0
    
    def detect_signature(self, features):
        """Detect signature using Random Forest"""
        try:
            if self.signature_model is None:
                return 0.0
            
            # Ensure 2D array
            if hasattr(features, 'ndim'):
                if features.ndim == 1:
                    features = features.reshape(1, -1)
                elif features.ndim == 3:
                    features = features.reshape(features.shape[0], -1)
            
            prediction = self.signature_model.predict(features)
            probability = self.signature_model.predict_proba(features)
            
            if len(prediction) > 0:
                score = float(probability[0][1]) if probability.shape[1] > 1 else float(prediction[0])
                return min(max(score, 0.0), 1.0)
            return 0.0
        except Exception as e:
            print(f"Signature detection error: {e}")
            return 0.0
    
    def hybrid_detection(self, features):
        """Combine anomaly and signature detection"""
        try:
            anomaly_score = self.detect_anomaly(features)
            signature_score = self.detect_signature(features)
            
            # Weighted average (anomaly is more critical)
            combined_score = (anomaly_score * 0.6) + (signature_score * 0.4)
            
            return combined_score, anomaly_score, signature_score
        except Exception as e:
            print(f"Hybrid detection error: {e}")
            return 0.0, 0.0, 0.0
    
    def get_threat_level(self, score):
        """Get threat level description"""
        if score >= 0.9:
            return "Critical Threat"
        elif score >= 0.7:
            return "High Threat"
        elif score >= 0.5:
            return "Medium Threat"
        elif score >= 0.3:
            return "Low Threat"
        else:
            return "Normal Traffic"
    
    def get_model_info(self):
        """Get model information"""
        return {
            'models_loaded': self.models_loaded,
            'last_training': self.last_training.isoformat() if self.last_training else None,
            'training_samples': self.training_samples,
            'has_anomaly_model': self.anomaly_model is not None,
            'has_signature_model': self.signature_model is not None,
            'has_scaler': self.scaler is not None
        }