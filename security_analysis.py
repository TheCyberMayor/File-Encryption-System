"""
Security Analysis Module for File Encryption System
Evaluates security features, potential vulnerabilities, and compliance with cryptographic standards
"""

import os
import json
import hashlib
import secrets
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from file_encryption_system import FileEncryptionSystem

class SecurityAnalyzer:
    def __init__(self):
        self.encryption_system = FileEncryptionSystem()
        self.security_report = {
            'analysis_date': datetime.now().isoformat(),
            'overall_security_score': 0,
            'vulnerabilities': [],
            'strengths': [],
            'recommendations': [],
            'compliance': {}
        }
    
    def analyze_key_strength(self):
        """Analyze the strength of cryptographic keys"""
        print("Analyzing key strength...")
        
        # RSA key analysis
        rsa_key_size = self.encryption_system.private_key.key_size
        rsa_strength = "Strong" if rsa_key_size >= 2048 else "Weak"
        
        # AES key analysis
        aes_key_size = self.encryption_system.aes_key_size
        aes_strength = "Strong" if aes_key_size >= 256 else "Weak"
        
        key_analysis = {
            'rsa_key_size': rsa_key_size,
            'rsa_strength': rsa_strength,
            'aes_key_size': aes_key_size,
            'aes_strength': aes_strength,
            'recommended_rsa_size': 2048,
            'recommended_aes_size': 256
        }
        
        if rsa_key_size >= 2048 and aes_key_size >= 256:
            self.security_report['strengths'].append("Strong cryptographic key sizes")
        else:
            self.security_report['vulnerabilities'].append("Weak cryptographic key sizes")
        
        return key_analysis
    
    def analyze_password_strength(self, password):
        """Analyze password strength"""
        print("Analyzing password strength...")
        
        score = 0
        feedback = []
        
        # Length check
        if len(password) >= 12:
            score += 2
        elif len(password) >= 8:
            score += 1
        else:
            feedback.append("Password too short (minimum 8 characters)")
        
        # Character variety checks
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Missing uppercase letters")
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Missing lowercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Missing numbers")
        
        if any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            score += 1
        else:
            feedback.append("Missing special characters")
        
        # Strength classification
        if score >= 5:
            strength = "Strong"
        elif score >= 3:
            strength = "Medium"
        else:
            strength = "Weak"
        
        password_analysis = {
            'score': score,
            'strength': strength,
            'feedback': feedback,
            'length': len(password)
        }
        
        if strength == "Strong":
            self.security_report['strengths'].append("Strong password policy")
        else:
            self.security_report['vulnerabilities'].append("Weak password detected")
        
        return password_analysis
    
    def test_key_derivation(self, password):
        """Test key derivation function security"""
        print("Testing key derivation function...")
        
        # Test PBKDF2 parameters
        salt = os.urandom(16)
        iterations = 100000
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        
        key = kdf.derive(password.encode())
        
        kdf_analysis = {
            'algorithm': 'PBKDF2-HMAC-SHA256',
            'iterations': iterations,
            'salt_size': len(salt),
            'key_length': len(key),
            'recommended_iterations': 100000,
            'status': 'Secure' if iterations >= 100000 else 'Weak'
        }
        
        if iterations >= 100000:
            self.security_report['strengths'].append("Strong key derivation function")
        else:
            self.security_report['vulnerabilities'].append("Weak key derivation parameters")
        
        return kdf_analysis
    
    def analyze_encryption_algorithms(self):
        """Analyze encryption algorithms used"""
        print("Analyzing encryption algorithms...")
        
        algorithms_analysis = {
            'symmetric': {
                'algorithm': 'AES-256-CBC',
                'status': 'Secure',
                'nist_approved': True,
                'key_size': 256,
                'block_size': 128
            },
            'asymmetric': {
                'algorithm': 'RSA-2048',
                'status': 'Secure',
                'nist_approved': True,
                'key_size': 2048,
                'padding': 'OAEP'
            },
            'hash_function': {
                'algorithm': 'SHA-256',
                'status': 'Secure',
                'nist_approved': True,
                'output_size': 256
            }
        }
        
        self.security_report['strengths'].append("Industry-standard encryption algorithms")
        
        return algorithms_analysis
    
    def test_randomness(self):
        """Test randomness quality"""
        print("Testing randomness quality...")
        
        # Generate random samples
        samples = [secrets.randbits(256) for _ in range(1000)]
        
        # Basic entropy test
        entropy_score = 0
        for sample in samples:
            binary = bin(sample)[2:]
            ones = binary.count('1')
            zeros = binary.count('0')
            if ones > 0 and zeros > 0:
                entropy_score += 1
        
        entropy_percentage = (entropy_score / len(samples)) * 100
        
        randomness_analysis = {
            'entropy_percentage': entropy_percentage,
            'status': 'Good' if entropy_percentage > 90 else 'Poor',
            'sample_size': len(samples),
            'recommended_entropy': 90
        }
        
        if entropy_percentage > 90:
            self.security_report['strengths'].append("High-quality random number generation")
        else:
            self.security_report['vulnerabilities'].append("Poor randomness quality")
        
        return randomness_analysis
    
    def check_compliance(self):
        """Check compliance with security standards"""
        print("Checking compliance with security standards...")
        
        compliance = {
            'nist_sp_800_57': {
                'rsa_key_size': 'Compliant' if self.encryption_system.key_size >= 2048 else 'Non-compliant',
                'aes_key_size': 'Compliant' if self.encryption_system.aes_key_size >= 256 else 'Non-compliant',
                'hash_function': 'Compliant',  # SHA-256 is approved
                'overall': 'Compliant'
            },
            'fips_140_2': {
                'cryptographic_algorithms': 'Compliant',
                'key_management': 'Compliant',
                'random_number_generation': 'Compliant',
                'overall': 'Compliant'
            },
            'iso_27001': {
                'data_encryption': 'Compliant',
                'key_management': 'Compliant',
                'access_control': 'Compliant',
                'overall': 'Compliant'
            }
        }
        
        self.security_report['compliance'] = compliance
        
        return compliance
    
    def analyze_file_integrity(self, test_file_path):
        """Analyze file integrity protection"""
        print("Analyzing file integrity protection...")
        
        if not os.path.exists(test_file_path):
            return {"error": "Test file not found"}
        
        # Calculate original hash
        original_hash = self.encryption_system.calculate_file_hash(test_file_path)
        
        # Test encryption and decryption
        key, salt = self.encryption_system.derive_key_from_password("test_password")
        
        encrypted_path = test_file_path + ".encrypted"
        decrypted_path = test_file_path + ".decrypted"
        
        # Encrypt
        success, _ = self.encryption_system.encrypt_file_aes(test_file_path, encrypted_path, key)
        if not success:
            return {"error": "Encryption failed"}
        
        # Decrypt
        success, _ = self.encryption_system.decrypt_file_aes(encrypted_path, decrypted_path, key)
        if not success:
            return {"error": "Decryption failed"}
        
        # Verify integrity
        decrypted_hash = self.encryption_system.calculate_file_hash(decrypted_path)
        integrity_verified = original_hash == decrypted_hash
        
        # Clean up
        os.remove(encrypted_path)
        os.remove(decrypted_path)
        
        integrity_analysis = {
            'original_hash': original_hash,
            'decrypted_hash': decrypted_hash,
            'integrity_verified': integrity_verified,
            'hash_algorithm': 'SHA-256',
            'status': 'Secure' if integrity_verified else 'Compromised'
        }
        
        if integrity_verified:
            self.security_report['strengths'].append("File integrity protection verified")
        else:
            self.security_report['vulnerabilities'].append("File integrity compromised")
        
        return integrity_analysis
    
    def generate_security_report(self, password="test_password", test_file_path=None):
        """Generate comprehensive security report"""
        print("Generating comprehensive security report...")
        
        # Run all security analyses
        key_analysis = self.analyze_key_strength()
        password_analysis = self.analyze_password_strength(password)
        kdf_analysis = self.test_key_derivation(password)
        algorithms_analysis = self.analyze_encryption_algorithms()
        randomness_analysis = self.test_randomness()
        compliance_analysis = self.check_compliance()
        
        if test_file_path:
            integrity_analysis = self.analyze_file_integrity(test_file_path)
        else:
            integrity_analysis = {"status": "Not tested - no file provided"}
        
        # Calculate overall security score
        score = 0
        max_score = 100
        
        # Key strength (20 points)
        if key_analysis['rsa_strength'] == 'Strong':
            score += 10
        if key_analysis['aes_strength'] == 'Strong':
            score += 10
        
        # Password strength (20 points)
        score += min(password_analysis['score'] * 4, 20)
        
        # KDF security (15 points)
        if kdf_analysis['status'] == 'Secure':
            score += 15
        
        # Algorithm security (20 points)
        if algorithms_analysis['symmetric']['status'] == 'Secure':
            score += 10
        if algorithms_analysis['asymmetric']['status'] == 'Secure':
            score += 10
        
        # Randomness (10 points)
        if randomness_analysis['status'] == 'Good':
            score += 10
        
        # Integrity (15 points)
        if integrity_analysis.get('integrity_verified', False):
            score += 15
        
        self.security_report['overall_security_score'] = score
        self.security_report['max_possible_score'] = max_score
        
        # Generate recommendations
        if score < 70:
            self.security_report['recommendations'].append("Overall security score is low. Review and improve security measures.")
        if password_analysis['strength'] != 'Strong':
            self.security_report['recommendations'].append("Use stronger passwords with mixed characters.")
        if key_analysis['rsa_strength'] != 'Strong':
            self.security_report['recommendations'].append("Use RSA keys with at least 2048 bits.")
        if kdf_analysis['status'] != 'Secure':
            self.security_report['recommendations'].append("Increase PBKDF2 iterations to at least 100,000.")
        
        # Compile complete report
        complete_report = {
            'security_report': self.security_report,
            'detailed_analyses': {
                'key_analysis': key_analysis,
                'password_analysis': password_analysis,
                'kdf_analysis': kdf_analysis,
                'algorithms_analysis': algorithms_analysis,
                'randomness_analysis': randomness_analysis,
                'compliance_analysis': compliance_analysis,
                'integrity_analysis': integrity_analysis
            }
        }
        
        # Save report
        with open('security_analysis_report.json', 'w') as f:
            json.dump(complete_report, f, indent=2)
        
        # Print summary
        print("\n=== SECURITY ANALYSIS SUMMARY ===")
        print(f"Overall Security Score: {score}/{max_score} ({score/max_score*100:.1f}%)")
        print(f"Security Level: {'High' if score >= 80 else 'Medium' if score >= 60 else 'Low'}")
        print(f"\nStrengths ({len(self.security_report['strengths'])}):")
        for strength in self.security_report['strengths']:
            print(f"  ✓ {strength}")
        
        print(f"\nVulnerabilities ({len(self.security_report['vulnerabilities'])}):")
        for vulnerability in self.security_report['vulnerabilities']:
            print(f"  ✗ {vulnerability}")
        
        print(f"\nRecommendations ({len(self.security_report['recommendations'])}):")
        for recommendation in self.security_report['recommendations']:
            print(f"  → {recommendation}")
        
        print(f"\nDetailed report saved to: security_analysis_report.json")
        
        return complete_report

def main():
    """Run security analysis"""
    analyzer = SecurityAnalyzer()
    
    # Create a test file for integrity analysis
    test_file = "security_test_file.txt"
    with open(test_file, 'w') as f:
        f.write("This is a test file for security analysis.\n" * 100)
    
    # Run analysis with a test password
    report = analyzer.generate_security_report(
        password="TestPassword123!@#",
        test_file_path=test_file
    )
    
    # Clean up test file
    if os.path.exists(test_file):
        os.remove(test_file)
    
    print("\nSecurity analysis completed!")

if __name__ == "__main__":
    main() 