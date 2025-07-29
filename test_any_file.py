#!/usr/bin/env python3
"""
Flexible test script for file encryption and decryption
"""

from file_encryption_system import FileEncryptionSystem
import os
import hashlib
import sys

def test_file_encryption(file_path):
    """Test encryption and decryption of any file"""
    
    # Initialize encryption system
    encryption_system = FileEncryptionSystem()
    password = "TestPassword123!"
    
    # Get file info
    file_name = os.path.basename(file_path)
    file_ext = os.path.splitext(file_name)[1]
    
    # File paths
    aes_encrypted = f"{os.path.splitext(file_name)[0]}_aes_encrypted.aes"
    aes_decrypted = f"{os.path.splitext(file_name)[0]}_aes_decrypted{file_ext}"
    hybrid_encrypted = f"{os.path.splitext(file_name)[0]}_hybrid_encrypted.bin"
    hybrid_decrypted = f"{os.path.splitext(file_name)[0]}_hybrid_decrypted{file_ext}"
    
    print("=" * 60)
    print("FILE ENCRYPTION/DECRYPTION TEST")
    print("=" * 60)
    
    # Check if original file exists
    if not os.path.exists(file_path):
        print(f"❌ Error: {file_path} not found!")
        print("Available files in current directory:")
        for f in os.listdir('.'):
            if os.path.isfile(f):
                size = os.path.getsize(f)
                print(f"   - {f} ({size:,} bytes)")
        return
    
    # Get original file info
    original_size = os.path.getsize(file_path)
    print(f"📄 Original file: {file_path}")
    print(f"📏 Size: {original_size:,} bytes ({original_size/1024/1024:.2f} MB)")
    print(f"📋 Extension: {file_ext}")
    
    # Calculate original file hash
    with open(file_path, 'rb') as f:
        original_hash = hashlib.sha256(f.read()).hexdigest()
    print(f"🔍 Original Hash: {original_hash[:16]}...")
    print()
    
    # Test 1: AES Encryption
    print("🔒 TEST 1: AES-256-CBC Encryption")
    print("-" * 40)
    
    try:
        # Derive key from password
        key, salt = encryption_system.derive_key_from_password(password)
        print(f"✓ Key derived (salt: {salt.hex()[:16]}...)")
        
        # Encrypt with AES
        success, message = encryption_system.encrypt_file_aes(
            file_path, aes_encrypted, key
        )
        
        if success:
            aes_size = os.path.getsize(aes_encrypted)
            print(f"✓ AES Encryption: {message}")
            print(f"📏 Encrypted size: {aes_size:,} bytes ({aes_size/1024/1024:.2f} MB)")
            print(f"📊 Overhead: {aes_size - original_size} bytes")
            
            # Decrypt with AES
            success, message = encryption_system.decrypt_file_aes(
                aes_encrypted, aes_decrypted, key
            )
            
            if success:
                decrypted_size = os.path.getsize(aes_decrypted)
                print(f"✓ AES Decryption: {message}")
                print(f"📏 Decrypted size: {decrypted_size:,} bytes")
                
                # Verify integrity
                with open(aes_decrypted, 'rb') as f:
                    decrypted_hash = hashlib.sha256(f.read()).hexdigest()
                
                if original_hash == decrypted_hash:
                    print("✅ File integrity verified - AES test PASSED!")
                else:
                    print("❌ File integrity check failed - AES test FAILED!")
            else:
                print(f"❌ AES Decryption failed: {message}")
        else:
            print(f"❌ AES Encryption failed: {message}")
            
    except Exception as e:
        print(f"❌ AES test error: {e}")
    
    print()
    
    # Test 2: Hybrid Encryption
    print("🔐 TEST 2: Hybrid (AES + RSA) Encryption")
    print("-" * 40)
    
    try:
        # Encrypt with hybrid method
        success, message = encryption_system.encrypt_file_hybrid(
            file_path, hybrid_encrypted, 
            encryption_system.public_key, password
        )
        
        if success:
            hybrid_size = os.path.getsize(hybrid_encrypted)
            metadata_size = os.path.getsize(hybrid_encrypted + '.meta')
            total_size = hybrid_size + metadata_size
            
            print(f"✓ Hybrid Encryption: {message}")
            print(f"📏 Main file: {hybrid_size:,} bytes ({hybrid_size/1024/1024:.2f} MB)")
            print(f"📏 Metadata: {metadata_size:,} bytes")
            print(f"📏 Total: {total_size:,} bytes ({total_size/1024/1024:.2f} MB)")
            print(f"📊 Overhead: {total_size - original_size} bytes")
            
            # Decrypt with hybrid method
            success, message = encryption_system.decrypt_file_hybrid(
                hybrid_encrypted, hybrid_decrypted,
                encryption_system.private_key, password
            )
            
            if success:
                decrypted_size = os.path.getsize(hybrid_decrypted)
                print(f"✓ Hybrid Decryption: {message}")
                print(f"📏 Decrypted size: {decrypted_size:,} bytes")
                
                # Verify integrity
                with open(hybrid_decrypted, 'rb') as f:
                    decrypted_hash = hashlib.sha256(f.read()).hexdigest()
                
                if original_hash == decrypted_hash:
                    print("✅ File integrity verified - Hybrid test PASSED!")
                else:
                    print("❌ File integrity check failed - Hybrid test FAILED!")
            else:
                print(f"❌ Hybrid Decryption failed: {message}")
        else:
            print(f"❌ Hybrid Encryption failed: {message}")
            
    except Exception as e:
        print(f"❌ Hybrid test error: {e}")
    
    print()
    print("=" * 60)
    print("TEST SUMMARY")
    print("=" * 60)
    
    # Check which files were created
    files_created = []
    for file in [aes_encrypted, aes_decrypted, hybrid_encrypted, hybrid_decrypted]:
        if os.path.exists(file):
            files_created.append(file)
    
    print(f"📁 Files created: {len(files_created)}")
    for file in files_created:
        size = os.path.getsize(file)
        print(f"   - {file}: {size:,} bytes")
    
    print()
    print("🎉 File encryption/decryption test completed!")
    print("💡 You can now open the decrypted files to verify they work correctly.")

def main():
    """Main function"""
    if len(sys.argv) > 1:
        # Use file specified in command line
        file_path = sys.argv[1]
    else:
        # Use default test file
        file_path = "test_document.txt"
        print("No file specified. Using test_document.txt")
        print("To test a specific file, run: python test_any_file.py <filename>")
        print()
    
    test_file_encryption(file_path)

if __name__ == "__main__":
    main() 