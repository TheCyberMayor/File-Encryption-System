"""
File Encryption System
A comprehensive file encryption solution using AES and RSA algorithms
Based on the proposal document requirements
"""

import os
import base64
import hashlib
import json
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import bcrypt
import threading
import time
from datetime import datetime
import secrets

class FileEncryptionSystem:
    def __init__(self):
        self.backend = default_backend()
        self.key_size = 2048  # RSA key size
        self.aes_key_size = 256  # AES key size in bits
        self.iv_size = 16  # Initialization vector size
        self.salt_size = 16  # Salt size for key derivation
        
        # Initialize key storage
        self.keys_file = "encryption_keys.json"
        self.load_keys()
        
    def generate_rsa_key_pair(self):
        """Generate RSA public and private key pair"""
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
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
        """Save encryption keys securely"""
        try:
            keys_data = {
                'public_key': base64.b64encode(
                    self.public_key.public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                    )
                ).decode('utf-8'),
                'private_key': base64.b64encode(
                    self.private_key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.PKCS8,
                        encryption_algorithm=serialization.NoEncryption()
                    )
                ).decode('utf-8'),
                'created_at': datetime.now().isoformat()
            }
            
            with open(self.keys_file, 'w') as f:
                json.dump(keys_data, f, indent=2)
            
            return True
        except Exception as e:
            print(f"Error saving keys: {e}")
            return False
    
    def load_keys(self):
        """Load encryption keys"""
        try:
            if os.path.exists(self.keys_file):
                with open(self.keys_file, 'r') as f:
                    keys_data = json.load(f)
                
                # Load public key
                public_key_bytes = base64.b64decode(keys_data['public_key'])
                self.public_key = serialization.load_pem_public_key(
                    public_key_bytes,
                    backend=self.backend
                )
                
                # Load private key
                private_key_bytes = base64.b64decode(keys_data['private_key'])
                self.private_key = serialization.load_pem_private_key(
                    private_key_bytes,
                    password=None,
                    backend=self.backend
                )
            else:
                # Generate new keys
                self.private_key, self.public_key = self.generate_rsa_key_pair()
                self.save_keys()
                
        except Exception as e:
            print(f"Error loading keys: {e}")
            # Generate new keys if loading fails
            self.private_key, self.public_key = self.generate_rsa_key_pair()
            self.save_keys()
    
    def calculate_file_hash(self, file_path):
        """Calculate SHA-256 hash of file"""
        hash_sha256 = hashlib.sha256()
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def verify_file_integrity(self, original_path, decrypted_path):
        """Verify file integrity by comparing hashes"""
        original_hash = self.calculate_file_hash(original_path)
        decrypted_hash = self.calculate_file_hash(decrypted_path)
        return original_hash == decrypted_hash

class FileEncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("File Encryption System")
        self.root.geometry("800x600")
        self.root.configure(bg='#f0f0f0')
        
        # Initialize encryption system
        self.encryption_system = FileEncryptionSystem()
        
        # Variables
        self.selected_file = tk.StringVar()
        self.output_path = tk.StringVar()
        self.password = tk.StringVar()
        self.encryption_method = tk.StringVar(value="hybrid")
        
        self.setup_ui()
    
    def setup_ui(self):
        """Setup the user interface"""
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Title
        title_label = ttk.Label(main_frame, text="File Encryption System", 
                               font=('Arial', 16, 'bold'))
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # File selection
        ttk.Label(main_frame, text="Select File:").grid(row=1, column=0, sticky=tk.W, pady=5)
        ttk.Entry(main_frame, textvariable=self.selected_file, width=50).grid(row=1, column=1, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_file).grid(row=1, column=2, padx=(5, 0), pady=5)
        
        # Output path
        ttk.Label(main_frame, text="Output Path:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Entry(main_frame, textvariable=self.output_path, width=50).grid(row=2, column=1, pady=5)
        ttk.Button(main_frame, text="Browse", command=self.browse_output).grid(row=2, column=2, padx=(5, 0), pady=5)
        
        # Password
        ttk.Label(main_frame, text="Password:").grid(row=3, column=0, sticky=tk.W, pady=5)
        password_entry = ttk.Entry(main_frame, textvariable=self.password, show="*", width=50)
        password_entry.grid(row=3, column=1, pady=5)
        
        # Encryption method
        ttk.Label(main_frame, text="Method:").grid(row=4, column=0, sticky=tk.W, pady=5)
        method_frame = ttk.Frame(main_frame)
        method_frame.grid(row=4, column=1, sticky=tk.W, pady=5)
        
        ttk.Radiobutton(method_frame, text="AES Only", variable=self.encryption_method, 
                       value="aes").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(method_frame, text="Hybrid (AES + RSA)", variable=self.encryption_method, 
                       value="hybrid").pack(side=tk.LEFT)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=3, pady=20)
        
        ttk.Button(button_frame, text="Encrypt File", command=self.encrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Decrypt File", command=self.decrypt_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Generate New Keys", command=self.generate_new_keys).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear", command=self.clear_fields).pack(side=tk.LEFT, padx=5)
        
        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate')
        self.progress.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10)
        
        # Status text
        self.status_text = scrolledtext.ScrolledText(main_frame, height=10, width=80)
        self.status_text.grid(row=7, column=0, columnspan=3, pady=10)
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
    
    def browse_file(self):
        """Browse for input file"""
        filename = filedialog.askopenfilename(
            title="Select file to encrypt/decrypt",
            filetypes=[("All files", "*.*"), ("Text files", "*.txt"), ("Documents", "*.docx;*.pdf")]
        )
        if filename:
            self.selected_file.set(filename)
            # Auto-generate output path
            base_name = os.path.splitext(filename)[0]
            if self.encryption_method.get() == "hybrid":
                self.output_path.set(base_name + "_encrypted.bin")
            else:
                self.output_path.set(base_name + "_encrypted.aes")
    
    def browse_output(self):
        """Browse for output file"""
        filename = filedialog.asksaveasfilename(
            title="Save encrypted/decrypted file as",
            defaultextension=".bin"
        )
        if filename:
            self.output_path.set(filename)
    
    def log_message(self, message):
        """Add message to status text"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.status_text.insert(tk.END, f"[{timestamp}] {message}\n")
        self.status_text.see(tk.END)
        self.root.update()
    
    def encrypt_file(self):
        """Encrypt the selected file"""
        if not self.selected_file.get() or not self.output_path.get():
            messagebox.showerror("Error", "Please select input and output files")
            return
        
        if not self.password.get():
            messagebox.showerror("Error", "Please enter a password")
            return
        
        # Start progress bar
        self.progress.start()
        
        # Run encryption in separate thread
        thread = threading.Thread(target=self._encrypt_file_thread)
        thread.daemon = True
        thread.start()
    
    def _encrypt_file_thread(self):
        """Encrypt file in background thread"""
        try:
            self.log_message("Starting encryption...")
            
            if self.encryption_method.get() == "aes":
                # AES encryption
                key, salt = self.encryption_system.derive_key_from_password(self.password.get())
                success, message = self.encryption_system.encrypt_file_aes(
                    self.selected_file.get(), self.output_path.get(), key
                )
            else:
                # Hybrid encryption
                success, message = self.encryption_system.encrypt_file_hybrid(
                    self.selected_file.get(), self.output_path.get(), 
                    self.encryption_system.public_key, self.password.get()
                )
            
            if success:
                self.log_message("✓ " + message)
                self.log_message(f"Original file size: {os.path.getsize(self.selected_file.get())} bytes")
                self.log_message(f"Encrypted file size: {os.path.getsize(self.output_path.get())} bytes")
                
                # Calculate and display hash
                original_hash = self.encryption_system.calculate_file_hash(self.selected_file.get())
                self.log_message(f"Original file hash: {original_hash[:16]}...")
                
            else:
                self.log_message("✗ " + message)
                
        except Exception as e:
            self.log_message(f"✗ Error: {str(e)}")
        finally:
            self.progress.stop()
    
    def decrypt_file(self):
        """Decrypt the selected file"""
        if not self.selected_file.get() or not self.output_path.get():
            messagebox.showerror("Error", "Please select input and output files")
            return
        
        if not self.password.get():
            messagebox.showerror("Error", "Please enter a password")
            return
        
        # Start progress bar
        self.progress.start()
        
        # Run decryption in separate thread
        thread = threading.Thread(target=self._decrypt_file_thread)
        thread.daemon = True
        thread.start()
    
    def _decrypt_file_thread(self):
        """Decrypt file in background thread"""
        try:
            self.log_message("Starting decryption...")
            
            if self.encryption_method.get() == "aes":
                # AES decryption
                key, salt = self.encryption_system.derive_key_from_password(self.password.get())
                success, message = self.encryption_system.decrypt_file_aes(
                    self.selected_file.get(), self.output_path.get(), key
                )
            else:
                # Hybrid decryption
                success, message = self.encryption_system.decrypt_file_hybrid(
                    self.selected_file.get(), self.output_path.get(), 
                    self.encryption_system.private_key, self.password.get()
                )
            
            if success:
                self.log_message("✓ " + message)
                self.log_message(f"Decrypted file size: {os.path.getsize(self.output_path.get())} bytes")
                
                # Verify integrity if original file exists
                original_file = self.selected_file.get().replace("_encrypted.bin", "").replace("_encrypted.aes", "")
                if os.path.exists(original_file):
                    if self.encryption_system.verify_file_integrity(original_file, self.output_path.get()):
                        self.log_message("✓ File integrity verified")
                    else:
                        self.log_message("✗ File integrity check failed")
                
            else:
                self.log_message("✗ " + message)
                
        except Exception as e:
            self.log_message(f"✗ Error: {str(e)}")
        finally:
            self.progress.stop()
    
    def generate_new_keys(self):
        """Generate new RSA key pair"""
        try:
            self.log_message("Generating new RSA key pair...")
            self.encryption_system.private_key, self.encryption_system.public_key = \
                self.encryption_system.generate_rsa_key_pair()
            self.encryption_system.save_keys()
            self.log_message("✓ New keys generated and saved successfully")
        except Exception as e:
            self.log_message(f"✗ Error generating keys: {str(e)}")
    
    def clear_fields(self):
        """Clear all input fields"""
        self.selected_file.set("")
        self.output_path.set("")
        self.password.set("")
        self.status_text.delete(1.0, tk.END)
        self.log_message("Fields cleared")

def main():
    """Main function to run the application"""
    root = tk.Tk()
    app = FileEncryptionGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 