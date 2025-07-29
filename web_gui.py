import streamlit as st
import tempfile
import os
from file_encryption_system import FileEncryptionSystem

encryption_system = FileEncryptionSystem()
st.set_page_config(page_title="File Encryption System Web GUI", layout="centered")
st.title("🔒 File Encryption System - Web GUI")

st.markdown("""
This web app allows you to encrypt and decrypt files using AES-256 encryption. 
All operations are performed locally on the server.
""")

mode = st.radio("Select Operation", ["Encrypt", "Decrypt"])

if mode == "Encrypt":
    st.header("Encrypt a File")
    uploaded_file = st.file_uploader("Choose a file to encrypt", type=None)
    password = st.text_input("Password", type="password")
    method = st.selectbox("Encryption Method", ["AES (Recommended)"])  # Only AES for now
    if st.button("Encrypt"):
        if not uploaded_file or not password:
            st.error("Please provide both a file and a password.")
        else:
            with tempfile.NamedTemporaryFile(delete=False) as temp_in:
                temp_in.write(uploaded_file.read())
                input_path = temp_in.name
            output_path = input_path + ".enc"
            key, salt = encryption_system.derive_key_from_password(password)
            success, message = encryption_system.encrypt_file_aes(input_path, output_path, key)
            if success:
                with open(output_path, "rb") as f:
                    st.download_button("Download Encrypted File", f, file_name="encrypted_file.aes")
                with open(output_path + ".salt", "wb") as f:
                    f.write(salt)
                with open(output_path + ".salt", "rb") as f:
                    st.download_button("Download Salt File (Required for Decryption)", f, file_name="encrypted_file.aes.salt")
                st.success("File encrypted successfully!")
            else:
                st.error(f"Encryption failed: {message}")
            os.remove(input_path)
            if os.path.exists(output_path):
                os.remove(output_path)
            if os.path.exists(output_path + ".salt"):
                os.remove(output_path + ".salt")
elif mode == "Decrypt":
    st.header("Decrypt a File")
    uploaded_file = st.file_uploader("Choose an encrypted file (.aes)", type=None)
    salt_file = st.file_uploader("Choose the corresponding salt file (.aes.salt)", type=None)
    password = st.text_input("Password", type="password")
    if st.button("Decrypt"):
        if not uploaded_file or not salt_file or not password:
            st.error("Please provide the encrypted file, salt file, and password.")
        else:
            with tempfile.NamedTemporaryFile(delete=False) as temp_in:
                temp_in.write(uploaded_file.read())
                input_path = temp_in.name
            with tempfile.NamedTemporaryFile(delete=False) as temp_salt:
                temp_salt.write(salt_file.read())
                salt_path = temp_salt.name
            output_path = input_path + ".dec"
            with open(salt_path, "rb") as f:
                salt = f.read()
            key, _ = encryption_system.derive_key_from_password(password, salt)
            success, message = encryption_system.decrypt_file_aes(input_path, output_path, key)
            if success:
                with open(output_path, "rb") as f:
                    st.download_button("Download Decrypted File", f, file_name="decrypted_file")
                st.success("File decrypted successfully!")
            else:
                st.error(f"Decryption failed: {message}")
            os.remove(input_path)
            os.remove(salt_path)
            if os.path.exists(output_path):
                os.remove(output_path) 