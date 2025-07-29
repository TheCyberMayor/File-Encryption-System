#!/usr/bin/env python3
"""
File Encryption System - Command Line Interface (CLI)
Provides terminal-based commands for file encryption and decryption
"""

import argparse
import sys
import os
from datetime import datetime
from file_encryption_system import FileEncryptionSystem

def print_banner():
    """Print the application banner"""
    print("=" * 60)
    print("FILE ENCRYPTION SYSTEM - COMMAND LINE INTERFACE")
    print("=" * 60)
    print("Version: 1.0 | Author: File Encryption System")
    print("=" * 60)

def encrypt_file(args):
    """Encrypt a file using specified method"""
    try:
        # Initialize encryption system
        encryption_system = FileEncryptionSystem()
        
        # Check if input file exists
        if not os.path.exists(args.input):
            print(f"ERROR: Input file '{args.input}' not found!")
            return False
        
        # Get file info
        file_size = os.path.getsize(args.input)
        print(f"Input file: {args.input}")
        print(f"Size: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
        
        if args.method.lower() == 'aes':
            # AES encryption
            print(f"Encrypting with AES-256-CBC...")
            key, salt = encryption_system.derive_key_from_password(args.password)
            
            # Store salt in a separate file for decryption
            salt_file = args.output + '.salt'
            with open(salt_file, 'wb') as f:
                f.write(salt)
            
            success, message = encryption_system.encrypt_file_aes(
                args.input, args.output, key
            )
            
            if success:
                encrypted_size = os.path.getsize(args.output)
                overhead = encrypted_size - file_size
                print(f"SUCCESS: {message}")
                print(f"Encrypted size: {encrypted_size:,} bytes")
                print(f"Overhead: {overhead} bytes")
                return True
            else:
                print(f"ERROR: {message}")
                return False
                
        elif args.method.lower() == 'hybrid':
            # Hybrid encryption
            print(f"Encrypting with Hybrid (AES + RSA)...")
            
            success, message = encryption_system.encrypt_file_hybrid(
                args.input, args.output, 
                encryption_system.public_key, args.password
            )
            
            if success:
                encrypted_size = os.path.getsize(args.output)
                metadata_size = os.path.getsize(args.output + '.meta')
                total_size = encrypted_size + metadata_size
                overhead = total_size - file_size
                
                print(f"SUCCESS {message}")
                print(f"SIZE Main file: {encrypted_size:,} bytes")
                print(f"SIZE Metadata: {metadata_size:,} bytes")
                print(f"SIZE Total: {total_size:,} bytes")
                print(f"INFO Overhead: {overhead} bytes")
                return True
            else:
                print(f"ERROR {message}")
                return False
        else:
            print(f"ERROR Error: Unknown method '{args.method}'. Use 'aes' or 'hybrid'")
            return False
            
    except Exception as e:
        print(f"ERROR Error: {e}")
        return False

def decrypt_file(args):
    """Decrypt a file using specified method"""
    try:
        # Initialize encryption system
        encryption_system = FileEncryptionSystem()
        
        # Check if input file exists
        if not os.path.exists(args.input):
            print(f"ERROR Error: Input file '{args.input}' not found!")
            return False
        
        # Get file info
        file_size = os.path.getsize(args.input)
        print(f"FILE Input file: {args.input}")
        print(f"SIZE Size: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)")
        
        if args.method.lower() == 'aes':
            # AES decryption
            print(f"DECRYPT Decrypting with AES-256-CBC...")
            
            # Load salt from file
            salt_file = args.input + '.salt'
            if not os.path.exists(salt_file):
                print(f"ERROR Error: Salt file '{salt_file}' not found! Cannot decrypt without salt.")
                return False
            
            with open(salt_file, 'rb') as f:
                salt = f.read()
            
            key, _ = encryption_system.derive_key_from_password(args.password, salt)
            
            success, message = encryption_system.decrypt_file_aes(
                args.input, args.output, key
            )
            
            if success:
                decrypted_size = os.path.getsize(args.output)
                print(f"SUCCESS {message}")
                print(f"SIZE Decrypted size: {decrypted_size:,} bytes")
                
                # Verify integrity if original file exists
                original_file = args.input.replace('_encrypted.aes', '').replace('_encrypted.bin', '')
                if os.path.exists(original_file):
                    if encryption_system.verify_file_integrity(original_file, args.output):
                        print("SUCCESS File integrity verified")
                    else:
                        print("ERROR File integrity check failed")
                return True
            else:
                print(f"ERROR {message}")
                return False
                
        elif args.method.lower() == 'hybrid':
            # Hybrid decryption
            print(f"DECRYPT Decrypting with Hybrid (AES + RSA)...")
            
            success, message = encryption_system.decrypt_file_hybrid(
                args.input, args.output,
                encryption_system.private_key, args.password
            )
            
            if success:
                decrypted_size = os.path.getsize(args.output)
                print(f"SUCCESS {message}")
                print(f"SIZE Decrypted size: {decrypted_size:,} bytes")
                
                # Verify integrity if original file exists
                original_file = args.input.replace('_encrypted.bin', '').replace('_encrypted.aes', '')
                if os.path.exists(original_file):
                    if encryption_system.verify_file_integrity(original_file, args.output):
                        print("SUCCESS File integrity verified")
                    else:
                        print("ERROR File integrity check failed")
                return True
            else:
                print(f"ERROR {message}")
                return False
        else:
            print(f"ERROR Error: Unknown method '{args.method}'. Use 'aes' or 'hybrid'")
            return False
            
    except Exception as e:
        print(f"ERROR Error: {e}")
        return False

def generate_keys(args):
    """Generate new RSA key pair"""
    try:
        print("KEY Generating new RSA key pair...")
        encryption_system = FileEncryptionSystem()
        
        # Generate new keys
        start_time = datetime.now()
        new_private_key, new_public_key = encryption_system.generate_rsa_key_pair()
        generation_time = (datetime.now() - start_time).total_seconds()
        
        # Save keys
        encryption_system.private_key = new_private_key
        encryption_system.public_key = new_public_key
        encryption_system.save_keys()
        
        print(f"SUCCESS New RSA-{new_private_key.key_size} key pair generated successfully")
        print(f"⏱️  Generation time: {generation_time:.3f} seconds")
        print(f"📁 Keys saved to: encryption_keys.json")
        
        return True
        
    except Exception as e:
        print(f"ERROR Error generating keys: {e}")
        return False

def show_info(args):
    """Show system information and key details"""
    try:
        encryption_system = FileEncryptionSystem()
        
        print("INFO SYSTEM INFORMATION")
        print("-" * 30)
        print(f"KEY RSA Key Size: {encryption_system.private_key.key_size} bits")
        print(f"SECURE AES Key Size: {encryption_system.aes_key_size} bits")
        print(f"ENCRYPT IV Size: {encryption_system.iv_size} bytes")
        print(f"🧂 Salt Size: {encryption_system.salt_size} bytes")
        print(f"📁 Keys File: {encryption_system.keys_file}")
        
        # Check if keys file exists
        if os.path.exists(encryption_system.keys_file):
            keys_size = os.path.getsize(encryption_system.keys_file)
            print(f"SIZE Keys File Size: {keys_size:,} bytes")
        else:
            print("SIZE Keys File: Not found")
        
        print()
        print("🔧 ENCRYPTION METHODS")
        print("-" * 30)
        print("• AES-256-CBC: Fast symmetric encryption")
        print("• Hybrid (AES + RSA): Combines speed and security")
        print("• PBKDF2: Password-based key derivation")
        print("• SHA-256: Hash function for integrity")
        
        return True
        
    except Exception as e:
        print(f"ERROR Error getting system info: {e}")
        return False

def test_performance(args):
    """Run performance test"""
    try:
        print("🚀 Running performance test...")
        from performance_test import PerformanceTester
        
        tester = PerformanceTester()
        results = tester.run_comprehensive_test([1, 5, 10])  # Test with smaller files for CLI
        
        print("SUCCESS Performance test completed!")
        return True
        
    except Exception as e:
        print(f"ERROR Error running performance test: {e}")
        return False

def security_analysis(args):
    """Run security analysis"""
    try:
        print("ENCRYPT Running security analysis...")
        from security_analysis import SecurityAnalyzer
        
        analyzer = SecurityAnalyzer()
        report = analyzer.generate_security_report(
            password=args.password if args.password else "TestPassword123!"
        )
        
        print("SUCCESS Security analysis completed!")
        return True
        
    except Exception as e:
        print(f"ERROR Error running security analysis: {e}")
        return False

def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="File Encryption System - Command Line Interface",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a file with AES
  python file_encryption_cli.py encrypt -i document.pdf -o encrypted.aes -m aes -p "MyPassword123!"

  # Encrypt a file with Hybrid method
  python file_encryption_cli.py encrypt -i document.pdf -o encrypted.bin -m hybrid -p "MyPassword123!"

  # Decrypt an AES file
  python file_encryption_cli.py decrypt -i encrypted.aes -o decrypted.pdf -m aes -p "MyPassword123!"

  # Decrypt a Hybrid file
  python file_encryption_cli.py decrypt -i encrypted.bin -o decrypted.pdf -m hybrid -p "MyPassword123!"

  # Generate new keys
  python file_encryption_cli.py keys

  # Show system info
  python file_encryption_cli.py info

  # Run performance test
  python file_encryption_cli.py test

  # Run security analysis
  python file_encryption_cli.py security -p "MyPassword123!"
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a file')
    encrypt_parser.add_argument('-i', '--input', required=True, help='Input file path')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Output file path')
    encrypt_parser.add_argument('-m', '--method', required=True, choices=['aes', 'hybrid'], 
                               help='Encryption method (aes or hybrid)')
    encrypt_parser.add_argument('-p', '--password', required=True, help='Encryption password')
    encrypt_parser.set_defaults(func=encrypt_file)
    
    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a file')
    decrypt_parser.add_argument('-i', '--input', required=True, help='Input file path')
    decrypt_parser.add_argument('-o', '--output', required=True, help='Output file path')
    decrypt_parser.add_argument('-m', '--method', required=True, choices=['aes', 'hybrid'], 
                               help='Decryption method (aes or hybrid)')
    decrypt_parser.add_argument('-p', '--password', required=True, help='Decryption password')
    decrypt_parser.set_defaults(func=decrypt_file)
    
    # Generate keys command
    keys_parser = subparsers.add_parser('keys', help='Generate new RSA key pair')
    keys_parser.set_defaults(func=generate_keys)
    
    # Info command
    info_parser = subparsers.add_parser('info', help='Show system information')
    info_parser.set_defaults(func=show_info)
    
    # Test command
    test_parser = subparsers.add_parser('test', help='Run performance test')
    test_parser.set_defaults(func=test_performance)
    
    # Security command
    security_parser = subparsers.add_parser('security', help='Run security analysis')
    security_parser.add_argument('-p', '--password', help='Password for security analysis')
    security_parser.set_defaults(func=security_analysis)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Show banner
    print_banner()
    
    # Execute command
    if hasattr(args, 'func'):
        success = args.func(args)
        if success:
            print("\nSUCCESS Operation completed successfully!")
        else:
            print("\nERROR Operation failed!")
            sys.exit(1)
    else:
        parser.print_help()

if __name__ == "__main__":
    main() 