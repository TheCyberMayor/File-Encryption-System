import os
import hashlib
import json
import base64
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class FileEncryptionSystem:
    def __init__(self):
        self.backend = default_backend()
        self.aes_key_size = 256
        self.rsa_key_size = 2048
        self.salt_size = 16
        self.iv_size = 16
        self.keys_file = "encryption_keys.json"
        
        # Load existing keys or generate new ones
        self.private_key = None
        self.public_key = None
        self.load_keys()
        
        if not self.private_key or not self.public_key:
            self.generate_new_keys()
    
    def generate_rsa_key_pair(self):
        """Generate RSA key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.rsa_key_size,
            backend=self.backend
        )
        public_key = private_key.public_key()
        return private_key, public_key
    
    def generate_aes_key(self):
        """Generate a random AES key"""
        return os.urandom(32)  # 32 bytes = 256 bits for AES-256
    
    def derive_key_from_password(self, password, salt=None):
        """Derive encryption key from password using PBKDF2"""
        if salt is None:
            salt = os.urandom(self.salt_size)
        
        key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            100000,  # iterations
            dklen=32  # 32 bytes = 256 bits for AES-256
        )
        
        # Ensure key is exactly 32 bytes for AES-256
        if len(key) != 32:
            # Truncate or pad to exactly 32 bytes
            if len(key) > 32:
                key = key[:32]
            else:
                key = key.ljust(32, b'\x00')
        
        return key, salt
    
    def encrypt_file_aes(self, file_path, output_path, key):
        """Encrypt file using AES-256-CBC"""
        try:
            # Validate key size
            if len(key) != 32:
                return False, f"Invalid key size ({len(key) * 8} bits). Expected 256 bits (32 bytes)."
            
            # Read the file
            with open(file_path, 'rb') as file:
                data = file.read()
            
            # Generate IV
            iv = os.urandom(self.iv_size)
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            encryptor = cipher.encryptor()
            
            # Pad data to block size
            padded_data = self._pad_data(data)
            
            # Encrypt data
            encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
            
            # Combine IV and encrypted data
            final_data = iv + encrypted_data
            
            # Write encrypted file
            with open(output_path, 'wb') as file:
                file.write(final_data)
            
            return True, "File encrypted successfully"
            
        except Exception as e:
            return False, f"Encryption error: {str(e)}"
    
    def decrypt_file_aes(self, file_path, output_path, key):
        """Decrypt file using AES-256-CBC"""
        try:
            # Validate key size
            if len(key) != 32:
                return False, f"Invalid key size ({len(key) * 8} bits). Expected 256 bits (32 bytes)."
            
            # Read the encrypted file
            with open(file_path, 'rb') as file:
                data = file.read()
            
            # Extract IV and encrypted data
            iv = data[:self.iv_size]
            encrypted_data = data[self.iv_size:]
            
            # Create cipher
            cipher = Cipher(
                algorithms.AES(key),
                modes.CBC(iv),
                backend=self.backend
            )
            decryptor = cipher.decryptor()
            
            # Decrypt data
            decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
            
            # Remove padding
            try:
                unpadded_data = self._unpad_data(decrypted_data)
            except ValueError as e:
                return False, f"Padding error: {str(e)}"
            except Exception as e:
                return False, f"Unpadding error: {str(e)}"
            
            # Write decrypted file
            with open(output_path, 'wb') as file:
                file.write(unpadded_data)
            
            return True, "File decrypted successfully"
            
        except Exception as e:
            return False, f"Decryption error: {str(e)}"
    
    def encrypt_file_hybrid(self, file_path, output_path, public_key, password):
        """Hybrid encryption: AES for file, RSA for AES key"""
        try:
            # Generate AES key
            aes_key = self.generate_aes_key()
            
            # Encrypt file with AES
            success, message = self.encrypt_file_aes(file_path, output_path, aes_key)
            if not success:
                return False, message
            
            # Encrypt AES key with RSA
            encrypted_aes_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Create metadata
            metadata = {
                'encrypted_key': base64.b64encode(encrypted_aes_key).decode('utf-8'),
                'timestamp': datetime.now().isoformat(),
                'algorithm': 'AES-256-CBC + RSA-2048',
                'file_size': os.path.getsize(file_path)
            }
            
            # Save metadata
            metadata_path = output_path + '.meta'
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            return True, "File encrypted with hybrid encryption"
            
        except Exception as e:
            return False, f"Hybrid encryption error: {str(e)}"
    
    def decrypt_file_hybrid(self, file_path, output_path, private_key, password):
        """Decrypt file using hybrid decryption"""
        try:
            # Load metadata
            metadata_path = file_path + '.meta'
            with open(metadata_path, 'r') as f:
                metadata = json.load(f)
            
            # Decrypt AES key
            encrypted_aes_key = base64.b64decode(metadata['encrypted_key'])
            aes_key = private_key.decrypt(
                encrypted_aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # Decrypt file with AES
            success, message = self.decrypt_file_aes(file_path, output_path, aes_key)
            if not success:
                return False, message
            
            return True, "File decrypted with hybrid decryption"
            
        except Exception as e:
            return False, f"Hybrid decryption error: {str(e)}"
    
    def _pad_data(self, data):
        """PKCS7 padding"""
        block_size = 16
        padding_length = block_size - (len(data) % block_size)
        
        # If data is already aligned to block size, add a full block of padding
        if padding_length == 0:
            padding_length = block_size
            
        padding = bytes([padding_length] * padding_length)
        return data + padding
    
    def _unpad_data(self, data):
        """Remove PKCS7 padding"""
        if len(data) == 0:
            return data
        
        padding_length = data[-1]
        
        # Validate padding length
        if padding_length > 16 or padding_length == 0:
            raise ValueError(f"Invalid padding length: {padding_length}")
        
        # Check if we have enough data
        if len(data) < padding_length:
            raise ValueError("Data too short for padding")
        
        # Check if padding is correct
        expected_padding = bytes([padding_length] * padding_length)
        actual_padding = data[-padding_length:]
        
        if actual_padding != expected_padding:
            raise ValueError(f"Invalid padding bytes. Expected: {expected_padding.hex()}, Got: {actual_padding.hex()}")
        
        return data[:-padding_length]
    
    def save_keys(self):
        """Save RSA keys to file"""
        try:
            if self.private_key and self.public_key:
                # Serialize keys
                private_pem = self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                )
                
                public_pem = self.public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
                
                # Save to file
                keys_data = {
                    'private_key': private_pem.decode('utf-8'),
                    'public_key': public_pem.decode('utf-8'),
                    'timestamp': datetime.now().isoformat()
                }
                
                with open(self.keys_file, 'w') as f:
                    json.dump(keys_data, f, indent=2)
                
                return True, "Keys saved successfully"
            else:
                return False, "No keys to save"
                
        except Exception as e:
            return False, f"Error saving keys: {str(e)}"
    
    def load_keys(self):
        """Load RSA keys from file"""
        try:
            if os.path.exists(self.keys_file):
                with open(self.keys_file, 'r') as f:
                    keys_data = json.load(f)
                
                # Deserialize keys
                private_pem = keys_data['private_key'].encode('utf-8')
                public_pem = keys_data['public_key'].encode('utf-8')
                
                self.private_key = serialization.load_pem_private_key(
                    private_pem,
                    password=None,
                    backend=self.backend
                )
                
                self.public_key = serialization.load_pem_public_key(
                    public_pem,
                    backend=self.backend
                )
                
                return True, "Keys loaded successfully"
            else:
                return False, "Keys file not found"
                
        except Exception as e:
            return False, f"Error loading keys: {str(e)}"
    
    def generate_new_keys(self):
        """Generate new RSA key pair and save"""
        try:
            self.private_key, self.public_key = self.generate_rsa_key_pair()
            success, message = self.save_keys()
            if success:
                return True, "New keys generated and saved"
            else:
                return False, f"Keys generated but failed to save: {message}"
        except Exception as e:
            return False, f"Error generating keys: {str(e)}"
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        try:
            hash_sha256 = hashlib.sha256()
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hash_sha256.update(chunk)
            return hash_sha256.hexdigest()
        except Exception as e:
            return None
    
    def verify_file_integrity(self, original_path, decrypted_path):
        """Verify file integrity by comparing hashes"""
        try:
            original_hash = self.calculate_file_hash(original_path)
            decrypted_hash = self.calculate_file_hash(decrypted_path)
            return original_hash == decrypted_hash
        except Exception as e:
            return False 