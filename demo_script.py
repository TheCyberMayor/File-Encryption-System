"""
File Encryption System Demo Script
Demonstrates the capabilities of the file encryption system with practical examples
"""

import os
import time
from datetime import datetime
from file_encryption_system import FileEncryptionSystem

def create_demo_files():
    """Create demonstration files for testing"""
    print("Creating demonstration files...")
    
    # Create a text file with sample content
    with open("demo_text.txt", "w") as f:
        f.write("This is a demonstration file for the File Encryption System.\n")
        f.write("It contains sensitive information that needs to be protected.\n")
        f.write("The system uses AES-256-CBC and RSA-2048 for encryption.\n")
        f.write("This file will be encrypted and then decrypted to show the process.\n" * 10)
    
    # Create a binary file with random data
    with open("demo_binary.bin", "wb") as f:
        f.write(os.urandom(1024 * 1024))  # 1MB of random data
    
    print("✓ Demo files created: demo_text.txt, demo_binary.bin")

def demonstrate_aes_encryption():
    """Demonstrate AES encryption"""
    print("\n" + "="*50)
    print("DEMONSTRATION: AES-256-CBC Encryption")
    print("="*50)
    
    encryption_system = FileEncryptionSystem()
    password = "DemoPassword123!@#"
    
    # Derive key from password
    key, salt = encryption_system.derive_key_from_password(password)
    print(f"✓ Key derived from password (salt: {salt.hex()[:16]}...)")
    
    # Encrypt text file
    print("\n1. Encrypting text file...")
    start_time = time.time()
    success, message = encryption_system.encrypt_file_aes(
        "demo_text.txt", "demo_text_encrypted.aes", key
    )
    encryption_time = time.time() - start_time
    
    if success:
        print(f"✓ Text file encrypted successfully ({encryption_time:.3f}s)")
        
        # Decrypt text file
        print("\n2. Decrypting text file...")
        start_time = time.time()
        success, message = encryption_system.decrypt_file_aes(
            "demo_text_encrypted.aes", "demo_text_decrypted.txt", key
        )
        decryption_time = time.time() - start_time
        
        if success:
            print(f"✓ Text file decrypted successfully ({decryption_time:.3f}s)")
            
            # Verify integrity
            original_hash = encryption_system.calculate_file_hash("demo_text.txt")
            decrypted_hash = encryption_system.calculate_file_hash("demo_text_decrypted.txt")
            
            if original_hash == decrypted_hash:
                print("✓ File integrity verified - content matches exactly")
            else:
                print("✗ File integrity check failed")
    
    # Encrypt binary file
    print("\n3. Encrypting binary file...")
    start_time = time.time()
    success, message = encryption_system.encrypt_file_aes(
        "demo_binary.bin", "demo_binary_encrypted.aes", key
    )
    encryption_time = time.time() - start_time
    
    if success:
        print(f"✓ Binary file encrypted successfully ({encryption_time:.3f}s)")
        
        # Decrypt binary file
        print("\n4. Decrypting binary file...")
        start_time = time.time()
        success, message = encryption_system.decrypt_file_aes(
            "demo_binary_encrypted.aes", "demo_binary_decrypted.bin", key
        )
        decryption_time = time.time() - start_time
        
        if success:
            print(f"✓ Binary file decrypted successfully ({decryption_time:.3f}s)")
            
            # Verify integrity
            original_hash = encryption_system.calculate_file_hash("demo_binary.bin")
            decrypted_hash = encryption_system.calculate_file_hash("demo_binary_decrypted.bin")
            
            if original_hash == decrypted_hash:
                print("✓ File integrity verified - content matches exactly")
            else:
                print("✗ File integrity check failed")

def demonstrate_hybrid_encryption():
    """Demonstrate hybrid encryption"""
    print("\n" + "="*50)
    print("DEMONSTRATION: Hybrid Encryption (AES + RSA)")
    print("="*50)
    
    encryption_system = FileEncryptionSystem()
    password = "DemoPassword123!@#"
    
    print(f"✓ Using RSA-{encryption_system.key_size} for key exchange")
    print(f"✓ Using AES-{encryption_system.aes_key_size} for file encryption")
    
    # Encrypt text file with hybrid method
    print("\n1. Encrypting text file with hybrid encryption...")
    start_time = time.time()
    success, message = encryption_system.encrypt_file_hybrid(
        "demo_text.txt", "demo_text_hybrid_encrypted.bin",
        encryption_system.public_key, password
    )
    encryption_time = time.time() - start_time
    
    if success:
        print(f"✓ Text file encrypted with hybrid method ({encryption_time:.3f}s)")
        
        # Decrypt text file
        print("\n2. Decrypting text file with hybrid method...")
        start_time = time.time()
        success, message = encryption_system.decrypt_file_hybrid(
            "demo_text_hybrid_encrypted.bin", "demo_text_hybrid_decrypted.txt",
            encryption_system.private_key, password
        )
        decryption_time = time.time() - start_time
        
        if success:
            print(f"✓ Text file decrypted with hybrid method ({decryption_time:.3f}s)")
            
            # Verify integrity
            original_hash = encryption_system.calculate_file_hash("demo_text.txt")
            decrypted_hash = encryption_system.calculate_file_hash("demo_text_hybrid_decrypted.txt")
            
            if original_hash == decrypted_hash:
                print("✓ File integrity verified - content matches exactly")
            else:
                print("✗ File integrity check failed")
    
    # Encrypt binary file with hybrid method
    print("\n3. Encrypting binary file with hybrid encryption...")
    start_time = time.time()
    success, message = encryption_system.encrypt_file_hybrid(
        "demo_binary.bin", "demo_binary_hybrid_encrypted.bin",
        encryption_system.public_key, password
    )
    encryption_time = time.time() - start_time
    
    if success:
        print(f"✓ Binary file encrypted with hybrid method ({encryption_time:.3f}s)")
        
        # Decrypt binary file
        print("\n4. Decrypting binary file with hybrid method...")
        start_time = time.time()
        success, message = encryption_system.decrypt_file_hybrid(
            "demo_binary_hybrid_encrypted.bin", "demo_binary_hybrid_decrypted.bin",
            encryption_system.private_key, password
        )
        decryption_time = time.time() - start_time
        
        if success:
            print(f"✓ Binary file decrypted with hybrid method ({decryption_time:.3f}s)")
            
            # Verify integrity
            original_hash = encryption_system.calculate_file_hash("demo_binary.bin")
            decrypted_hash = encryption_system.calculate_file_hash("demo_binary_hybrid_decrypted.bin")
            
            if original_hash == decrypted_hash:
                print("✓ File integrity verified - content matches exactly")
            else:
                print("✗ File integrity check failed")

def demonstrate_key_management():
    """Demonstrate key management features"""
    print("\n" + "="*50)
    print("DEMONSTRATION: Key Management")
    print("="*50)
    
    encryption_system = FileEncryptionSystem()
    
    # Show current keys
    print("1. Current RSA Key Information:")
    print(f"   - Key size: {encryption_system.private_key.key_size} bits")
    print(f"   - Public key: {encryption_system.public_key.public_numbers().n.bit_length()} bits")
    
    # Generate new keys
    print("\n2. Generating new RSA key pair...")
    start_time = time.time()
    new_private_key, new_public_key = encryption_system.generate_rsa_key_pair()
    key_generation_time = time.time() - start_time
    
    print(f"✓ New RSA-{new_private_key.key_size} key pair generated ({key_generation_time:.3f}s)")
    
    # Test key serialization
    print("\n3. Testing key serialization...")
    try:
        # Serialize public key
        from cryptography.hazmat.primitives import serialization
        public_pem = new_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        print(f"✓ Public key serialized ({len(public_pem)} bytes)")
        
        # Serialize private key
        private_pem = new_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        print(f"✓ Private key serialized ({len(private_pem)} bytes)")
        
    except Exception as e:
        print(f"✗ Key serialization failed: {e}")

def demonstrate_performance_comparison():
    """Demonstrate performance comparison between methods"""
    print("\n" + "="*50)
    print("DEMONSTRATION: Performance Comparison")
    print("="*50)
    
    encryption_system = FileEncryptionSystem()
    password = "DemoPassword123!@#"
    
    # Create a larger test file
    test_file = "performance_test_file.bin"
    with open(test_file, "wb") as f:
        f.write(os.urandom(5 * 1024 * 1024))  # 5MB
    
    print(f"✓ Created test file: {test_file} ({os.path.getsize(test_file) / 1024 / 1024:.1f} MB)")
    
    # Test AES encryption performance
    print("\n1. Testing AES encryption performance...")
    key, salt = encryption_system.derive_key_from_password(password)
    
    start_time = time.time()
    success, message = encryption_system.encrypt_file_aes(
        test_file, test_file + ".aes_encrypted", key
    )
    aes_encryption_time = time.time() - start_time
    
    if success:
        start_time = time.time()
        success, message = encryption_system.decrypt_file_aes(
            test_file + ".aes_encrypted", test_file + ".aes_decrypted", key
        )
        aes_decryption_time = time.time() - start_time
        
        if success:
            aes_throughput_enc = 5 / aes_encryption_time
            aes_throughput_dec = 5 / aes_decryption_time
            print(f"✓ AES Encryption: {aes_encryption_time:.3f}s ({aes_throughput_enc:.2f} MB/s)")
            print(f"✓ AES Decryption: {aes_decryption_time:.3f}s ({aes_throughput_dec:.2f} MB/s)")
    
    # Test hybrid encryption performance
    print("\n2. Testing hybrid encryption performance...")
    
    start_time = time.time()
    success, message = encryption_system.encrypt_file_hybrid(
        test_file, test_file + ".hybrid_encrypted",
        encryption_system.public_key, password
    )
    hybrid_encryption_time = time.time() - start_time
    
    if success:
        start_time = time.time()
        success, message = encryption_system.decrypt_file_hybrid(
            test_file + ".hybrid_encrypted", test_file + ".hybrid_decrypted",
            encryption_system.private_key, password
        )
        hybrid_decryption_time = time.time() - start_time
        
        if success:
            hybrid_throughput_enc = 5 / hybrid_encryption_time
            hybrid_throughput_dec = 5 / hybrid_decryption_time
            print(f"✓ Hybrid Encryption: {hybrid_encryption_time:.3f}s ({hybrid_throughput_enc:.2f} MB/s)")
            print(f"✓ Hybrid Decryption: {hybrid_decryption_time:.3f}s ({hybrid_throughput_dec:.2f} MB/s)")
    
    # Performance comparison
    print("\n3. Performance Comparison:")
    if 'aes_encryption_time' in locals() and 'hybrid_encryption_time' in locals():
        speedup = hybrid_encryption_time / aes_encryption_time
        print(f"   - AES is {speedup:.2f}x faster than hybrid for encryption")
        print(f"   - Hybrid provides additional security with RSA key exchange")
    
    # Clean up test files
    cleanup_files = [
        test_file, test_file + ".aes_encrypted", test_file + ".aes_decrypted",
        test_file + ".hybrid_encrypted", test_file + ".hybrid_encrypted.meta",
        test_file + ".hybrid_decrypted"
    ]
    
    for file in cleanup_files:
        if os.path.exists(file):
            os.remove(file)

def cleanup_demo_files():
    """Clean up all demonstration files"""
    print("\n" + "="*50)
    print("CLEANING UP DEMO FILES")
    print("="*50)
    
    demo_files = [
        "demo_text.txt", "demo_text_encrypted.aes", "demo_text_decrypted.txt",
        "demo_binary.bin", "demo_binary_encrypted.aes", "demo_binary_decrypted.bin",
        "demo_text_hybrid_encrypted.bin", "demo_text_hybrid_decrypted.txt",
        "demo_binary_hybrid_encrypted.bin", "demo_binary_hybrid_decrypted.bin"
    ]
    
    for file in demo_files:
        if os.path.exists(file):
            os.remove(file)
            print(f"✓ Removed: {file}")
        else:
            print(f"- Not found: {file}")

def main():
    """Run the complete demonstration"""
    print("FILE ENCRYPTION SYSTEM DEMONSTRATION")
    print("="*60)
    print(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("="*60)
    
    try:
        # Create demo files
        create_demo_files()
        
        # Demonstrate AES encryption
        demonstrate_aes_encryption()
        
        # Demonstrate hybrid encryption
        demonstrate_hybrid_encryption()
        
        # Demonstrate key management
        demonstrate_key_management()
        
        # Demonstrate performance comparison
        demonstrate_performance_comparison()
        
        # Clean up
        cleanup_demo_files()
        
        print("\n" + "="*60)
        print("DEMONSTRATION COMPLETED SUCCESSFULLY!")
        print("="*60)
        print("\nKey Features Demonstrated:")
        print("✓ AES-256-CBC encryption/decryption")
        print("✓ Hybrid encryption (AES + RSA)")
        print("✓ Secure key management")
        print("✓ File integrity verification")
        print("✓ Performance benchmarking")
        print("✓ Support for text and binary files")
        
        print("\nNext Steps:")
        print("1. Run 'python file_encryption_system.py' to use the GUI")
        print("2. Run 'python performance_test.py' for detailed performance analysis")
        print("3. Run 'python security_analysis.py' for security assessment")
        
    except Exception as e:
        print(f"\n✗ Demonstration failed: {e}")
        print("Please check the error and try again.")

if __name__ == "__main__":
    main() 