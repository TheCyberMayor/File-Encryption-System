"""
Performance Testing Module for File Encryption System
Evaluates encryption/decryption performance and compares with existing solutions
"""

import os
import time
import statistics
import json
from datetime import datetime
from file_encryption_system import FileEncryptionSystem
import hashlib

class PerformanceTester:
    def __init__(self):
        self.encryption_system = FileEncryptionSystem()
        self.test_results = []
        
    def create_test_files(self, sizes_mb=[1, 5, 10, 25, 50]):
        """Create test files of different sizes"""
        test_files = []
        
        for size_mb in sizes_mb:
            filename = f"test_file_{size_mb}MB.bin"
            size_bytes = size_mb * 1024 * 1024
            
            # Create file with random data
            with open(filename, 'wb') as f:
                f.write(os.urandom(size_bytes))
            
            test_files.append({
                'filename': filename,
                'size_mb': size_mb,
                'size_bytes': size_bytes
            })
            
        return test_files
    
    def test_aes_encryption(self, test_files, password="test_password"):
        """Test AES encryption performance"""
        results = []
        
        for test_file in test_files:
            print(f"Testing AES encryption for {test_file['filename']}...")
            
            # Derive key
            key, salt = self.encryption_system.derive_key_from_password(password)
            
            # Test encryption
            start_time = time.time()
            success, message = self.encryption_system.encrypt_file_aes(
                test_file['filename'], 
                test_file['filename'] + '.aes_encrypted', 
                key
            )
            encryption_time = time.time() - start_time
            
            if success:
                # Test decryption
                start_time = time.time()
                success, message = self.encryption_system.decrypt_file_aes(
                    test_file['filename'] + '.aes_encrypted',
                    test_file['filename'] + '.aes_decrypted',
                    key
                )
                decryption_time = time.time() - start_time
                
                # Verify integrity
                original_hash = self.encryption_system.calculate_file_hash(test_file['filename'])
                decrypted_hash = self.encryption_system.calculate_file_hash(test_file['filename'] + '.aes_decrypted')
                integrity_verified = original_hash == decrypted_hash
                
                # Calculate throughput
                encryption_throughput = test_file['size_mb'] / encryption_time  # MB/s
                decryption_throughput = test_file['size_mb'] / decryption_time  # MB/s
                
                results.append({
                    'method': 'AES-256-CBC',
                    'file_size_mb': test_file['size_mb'],
                    'encryption_time': encryption_time,
                    'decryption_time': decryption_time,
                    'encryption_throughput_mbps': encryption_throughput,
                    'decryption_throughput_mbps': decryption_throughput,
                    'integrity_verified': integrity_verified,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Clean up
                os.remove(test_file['filename'] + '.aes_encrypted')
                os.remove(test_file['filename'] + '.aes_decrypted')
        
        return results
    
    def test_hybrid_encryption(self, test_files, password="test_password"):
        """Test hybrid encryption performance"""
        results = []
        
        for test_file in test_files:
            print(f"Testing hybrid encryption for {test_file['filename']}...")
            
            # Test encryption
            start_time = time.time()
            success, message = self.encryption_system.encrypt_file_hybrid(
                test_file['filename'],
                test_file['filename'] + '.hybrid_encrypted',
                self.encryption_system.public_key,
                password
            )
            encryption_time = time.time() - start_time
            
            if success:
                # Test decryption
                start_time = time.time()
                success, message = self.encryption_system.decrypt_file_hybrid(
                    test_file['filename'] + '.hybrid_encrypted',
                    test_file['filename'] + '.hybrid_decrypted',
                    self.encryption_system.private_key,
                    password
                )
                decryption_time = time.time() - start_time
                
                # Verify integrity
                original_hash = self.encryption_system.calculate_file_hash(test_file['filename'])
                decrypted_hash = self.encryption_system.calculate_file_hash(test_file['filename'] + '.hybrid_decrypted')
                integrity_verified = original_hash == decrypted_hash
                
                # Calculate throughput
                encryption_throughput = test_file['size_mb'] / encryption_time  # MB/s
                decryption_throughput = test_file['size_mb'] / decryption_time  # MB/s
                
                results.append({
                    'method': 'Hybrid (AES + RSA)',
                    'file_size_mb': test_file['size_mb'],
                    'encryption_time': encryption_time,
                    'decryption_time': decryption_time,
                    'encryption_throughput_mbps': encryption_throughput,
                    'decryption_throughput_mbps': decryption_throughput,
                    'integrity_verified': integrity_verified,
                    'timestamp': datetime.now().isoformat()
                })
                
                # Clean up
                os.remove(test_file['filename'] + '.hybrid_encrypted')
                os.remove(test_file['filename'] + '.hybrid_encrypted.meta')
                os.remove(test_file['filename'] + '.hybrid_decrypted')
        
        return results
    
    def run_comprehensive_test(self, test_sizes=[1, 5, 10, 25, 50]):
        """Run comprehensive performance test"""
        print("Creating test files...")
        test_files = self.create_test_files(test_sizes)
        
        print("\n=== PERFORMANCE TESTING ===")
        print(f"Testing {len(test_files)} file sizes: {[f['size_mb'] for f in test_files]}MB")
        
        # Test AES encryption
        print("\n--- Testing AES Encryption ---")
        aes_results = self.test_aes_encryption(test_files)
        
        # Test hybrid encryption
        print("\n--- Testing Hybrid Encryption ---")
        hybrid_results = self.test_hybrid_encryption(test_files)
        
        # Combine results
        all_results = aes_results + hybrid_results
        
        # Generate report
        self.generate_performance_report(all_results)
        
        # Clean up test files
        for test_file in test_files:
            if os.path.exists(test_file['filename']):
                os.remove(test_file['filename'])
        
        return all_results
    
    def generate_performance_report(self, results):
        """Generate detailed performance report"""
        report = {
            'test_date': datetime.now().isoformat(),
            'summary': {},
            'detailed_results': results
        }
        
        # Calculate summary statistics
        aes_results = [r for r in results if r['method'] == 'AES-256-CBC']
        hybrid_results = [r for r in results if r['method'] == 'Hybrid (AES + RSA)']
        
        if aes_results:
            report['summary']['aes'] = {
                'avg_encryption_throughput': statistics.mean([r['encryption_throughput_mbps'] for r in aes_results]),
                'avg_decryption_throughput': statistics.mean([r['decryption_throughput_mbps'] for r in aes_results]),
                'min_encryption_throughput': min([r['encryption_throughput_mbps'] for r in aes_results]),
                'max_encryption_throughput': max([r['encryption_throughput_mbps'] for r in aes_results]),
                'integrity_verification_rate': sum([r['integrity_verified'] for r in aes_results]) / len(aes_results) * 100
            }
        
        if hybrid_results:
            report['summary']['hybrid'] = {
                'avg_encryption_throughput': statistics.mean([r['encryption_throughput_mbps'] for r in hybrid_results]),
                'avg_decryption_throughput': statistics.mean([r['decryption_throughput_mbps'] for r in hybrid_results]),
                'min_encryption_throughput': min([r['encryption_throughput_mbps'] for r in hybrid_results]),
                'max_encryption_throughput': max([r['encryption_throughput_mbps'] for r in hybrid_results]),
                'integrity_verification_rate': sum([r['integrity_verified'] for r in hybrid_results]) / len(hybrid_results) * 100
            }
        
        # Save report
        with open('performance_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        # Print summary
        print("\n=== PERFORMANCE SUMMARY ===")
        if aes_results:
            print(f"\nAES-256-CBC Results:")
            print(f"  Average Encryption Throughput: {report['summary']['aes']['avg_encryption_throughput']:.2f} MB/s")
            print(f"  Average Decryption Throughput: {report['summary']['aes']['avg_decryption_throughput']:.2f} MB/s")
            print(f"  Integrity Verification Rate: {report['summary']['aes']['integrity_verification_rate']:.1f}%")
        
        if hybrid_results:
            print(f"\nHybrid (AES + RSA) Results:")
            print(f"  Average Encryption Throughput: {report['summary']['hybrid']['avg_encryption_throughput']:.2f} MB/s")
            print(f"  Average Decryption Throughput: {report['summary']['hybrid']['avg_decryption_throughput']:.2f} MB/s")
            print(f"  Integrity Verification Rate: {report['summary']['hybrid']['integrity_verification_rate']:.1f}%")
        
        print(f"\nDetailed report saved to: performance_report.json")

def main():
    """Run performance tests"""
    tester = PerformanceTester()
    results = tester.run_comprehensive_test()
    
    print("\nPerformance testing completed!")

if __name__ == "__main__":
    main() 