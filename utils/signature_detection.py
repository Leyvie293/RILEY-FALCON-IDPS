# utils/signature_detection.py
"""
Signature-based detection module
Maintains and matches attack signatures
"""

import pickle
import os
import json
from datetime import datetime
import re

class SignatureModel:
    def __init__(self):
        self.model = None
        self.signatures = []
        self.load_signatures()
        
    def load_signatures(self):
        """Load pre-trained model and signatures"""
        model_path = 'ml_models/signature_model.pkl'
        
        try:
            with open(model_path, 'rb') as f:
                self.model = pickle.load(f)
            print("✅ Signature model loaded")
        except FileNotFoundError:
            print("⚠️ Signature model not found, using rule-based detection")
            self.model = None
        
        # Load signature rules
        self.load_signature_rules()
    
    def load_signature_rules(self):
        """Load signature rules from file"""
        rules_path = 'ml_models/signatures.json'
        
        # Default signatures
        self.signatures = [
            {
                'id': 1,
                'name': 'SQL Injection Attempt',
                'pattern': r'(union.*select|select.*from|insert.*into|delete.*from|drop.*table)',
                'severity': 'high',
                'description': 'Possible SQL injection attack detected'
            },
            {
                'id': 2,
                'name': 'XSS Attempt',
                'pattern': r'(<script>|javascript:|onerror=|onload=)',
                'severity': 'medium',
                'description': 'Possible Cross-Site Scripting (XSS) attack'
            },
            {
                'id': 3,
                'name': 'Port Scan',
                'pattern': r'(nmap|masscan|zmap)',
                'severity': 'medium',
                'description': 'Port scanning activity detected'
            },
            {
                'id': 4,
                'name': 'Brute Force Attack',
                'pattern': r'(hydra|medusa|ncrack)',
                'severity': 'high',
                'description': 'Possible brute force attack in progress'
            },
            {
                'id': 5,
                'name': 'Malware Download',
                'pattern': r'(\.exe|\.dll|\.bat|\.ps1|\.vbs)$',
                'severity': 'critical',
                'description': 'Executable file download detected'
            },
            {
                'id': 6,
                'name': 'Directory Traversal',
                'pattern': r'(\.\./|\.\.\\|%2e%2e%2f)',
                'severity': 'high',
                'description': 'Directory traversal attack attempt'
            },
            {
                'id': 7,
                'name': 'Command Injection',
                'pattern': r'(;|\||`|\$\(|%0a)',
                'severity': 'critical',
                'description': 'Possible command injection attempt'
            },
            {
                'id': 8,
                'name': 'Buffer Overflow',
                'pattern': r'(AAAAAAAA|BBBBBB|CCCCCC|%x|%n)',
                'severity': 'critical',
                'description': 'Possible buffer overflow attempt'
            }
        ]
        
        # Try to load custom signatures
        if os.path.exists(rules_path):
            try:
                with open(rules_path, 'r') as f:
                    custom = json.load(f)
                    self.signatures.extend(custom)
                print(f"✅ Loaded {len(custom)} custom signatures")
            except:
                pass
    
    def detect(self, text):
        """Detect signatures in text"""
        matches = []
        
        # Rule-based detection
        for sig in self.signatures:
            try:
                if re.search(sig['pattern'], text, re.IGNORECASE):
                    matches.append({
                        'signature': sig['name'],
                        'severity': sig['severity'],
                        'description': sig['description']
                    })
            except:
                continue
        
        # ML-based detection if model available
        if self.model is not None:
            try:
                # Extract features from text for ML model
                features = self._extract_features(text)
                prediction = self.model.predict([features])[0]
                probability = self.model.predict_proba([features])[0][1]
                
                if prediction == 1 and probability > 0.7:
                    matches.append({
                        'signature': 'ML Detected Anomaly',
                        'severity': 'medium' if probability < 0.9 else 'high',
                        'description': f'ML model detected anomaly with {probability:.2%} confidence'
                    })
            except:
                pass
        
        return matches
    
    def _extract_features(self, text):
        """Extract features from text for ML model"""
        features = [
            len(text),  # length
            text.count(' '),  # spaces
            text.count('/'),  # slashes
            text.count('.'),  # dots
            text.count('-'),  # hyphens
            text.count('_'),  # underscores
            text.count('='),  # equals
            text.count('&'),  # ampersands
            text.count('?'),  # question marks
            text.count('%'),  # percent signs
            text.count('+'),  # plus signs
            text.count('*'),  # asterisks
            text.count('$'),  # dollar signs
            text.count('!'),  # exclamation
            text.count('@'),  # at signs
        ]
        
        # Ensure exactly 15 features
        if len(features) < 15:
            features.extend([0] * (15 - len(features)))
        else:
            features = features[:15]
            
        return features
    
    def add_signature(self, name, pattern, severity, description):
        """Add new signature rule"""
        new_id = max([s['id'] for s in self.signatures], default=0) + 1
        
        signature = {
            'id': new_id,
            'name': name,
            'pattern': pattern,
            'severity': severity,
            'description': description,
            'created_at': datetime.now().isoformat()
        }
        
        self.signatures.append(signature)
        
        # Save to file
        rules_path = 'ml_models/signatures.json'
        try:
            with open(rules_path, 'w') as f:
                json.dump(self.signatures, f, indent=2)
            return True, "Signature added successfully"
        except Exception as e:
            return False, str(e)
    
    def remove_signature(self, sig_id):
        """Remove signature rule"""
        self.signatures = [s for s in self.signatures if s['id'] != sig_id]
        
        # Save to file
        rules_path = 'ml_models/signatures.json'
        try:
            with open(rules_path, 'w') as f:
                json.dump(self.signatures, f, indent=2)
            return True, "Signature removed successfully"
        except Exception as e:
            return False, str(e)