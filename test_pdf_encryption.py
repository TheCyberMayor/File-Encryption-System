#!/usr/bin/env python3
"""
Test script for PDF encryption and decryption
"""

from file_encryption_system import FileEncryptionSystem
import os
import hashlib

def test_pdf_encryption():
    """Test encryption and decryption of the PDF file"""
    
    # Initialize encryption system
    encryption_system = FileEncryptionSystem()
    password = "TestPassword123!"
    
    # File paths
    original_file = "2024-2025-HARMATTAN-PUBLICATION.pdf"
    aes_encrypted = "2024-2025-HARMATTAN-PUBLICATION_aes_encrypted.aes"
    aes_decrypted = "2024-2025-HARMATTAN-PUBLICATION_aes_decrypted.pdf"
    hybrid_encrypted = "2024-2025-HARMATTAN-PUBLICATION_hybrid_encrypted.bin"
    hybrid_decrypted = "2024-2025-HARMATTAN-PUBLICATION_hybrid_decrypted.pdf"
    
    print("=" * 60)
    print("PDF ENCRYPTION/DECRYPTION TEST")
    print("=" * 60)
    
    # Check if original file exists
    if not os.path.exists(original_file):
        print(f"❌ Error: {original_file} not found!")
        return
    
    # Get original file info
    original_size = os.path.getsize(original_file)
    print(f"📄 Original PDF: {original_file}")
    print(f"📏 Size: {original_size:,} bytes ({original_size/1024/1024:.2f} MB)")
    
    # Calculate original file hash
    with open(original_file, 'rb') as f:
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
            original_file, aes_encrypted, key
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
            original_file, hybrid_encrypted, 
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
    print("🎉 PDF encryption/decryption test completed!")
    print("💡 You can now open the decrypted PDF files to verify they work correctly.")

if __name__ == "__main__":
    test_pdf_encryption() 