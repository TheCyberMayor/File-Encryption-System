from flask import Flask, request, jsonify, send_file
import os
import tempfile
from file_encryption_system_server import FileEncryptionSystem

app = Flask(__name__)
encryption_system = FileEncryptionSystem()

@app.route('/')
def index():
    return 'File Encryption System CLI API is running.'

@app.route('/encrypt', methods=['POST'])
def encrypt():
    file = request.files.get('file')
    password = request.form.get('password')
    method = request.form.get('method', 'aes')
    if not file or not password:
        return jsonify({'error': 'Missing file or password'}), 400
    
    # Save uploaded file to temp
    with tempfile.NamedTemporaryFile(delete=False) as temp_in:
        file.save(temp_in)
        input_path = temp_in.name
    
    output_path = input_path + '.enc'
    if method == 'aes':
        key, salt = encryption_system.derive_key_from_password(password)
        success, message = encryption_system.encrypt_file_aes(input_path, output_path, key)
        if not success:
            os.remove(input_path)
            return jsonify({'error': message}), 500
        # Save salt for decryption
        with open(output_path + '.salt', 'wb') as f:
            f.write(salt)
    else:
        return jsonify({'error': 'Only AES method supported in API demo'}), 400
    
    # Return encrypted file
    response = send_file(output_path, as_attachment=True, download_name='encrypted_file.aes')
    # Clean up temp files after response
    @response.call_on_close
    def cleanup():
        os.remove(input_path)
        os.remove(output_path)
        if os.path.exists(output_path + '.salt'):
            os.remove(output_path + '.salt')
    return response

@app.route('/decrypt', methods=['POST'])
def decrypt():
    file = request.files.get('file')
    password = request.form.get('password')
    salt_file = request.files.get('salt')
    method = request.form.get('method', 'aes')
    if not file or not password or not salt_file:
        return jsonify({'error': 'Missing file, password, or salt'}), 400
    
    # Save uploaded files to temp
    with tempfile.NamedTemporaryFile(delete=False) as temp_in:
        file.save(temp_in)
        input_path = temp_in.name
    with tempfile.NamedTemporaryFile(delete=False) as temp_salt:
        salt_file.save(temp_salt)
        salt_path = temp_salt.name
    
    output_path = input_path + '.dec'
    if method == 'aes':
        with open(salt_path, 'rb') as f:
            salt = f.read()
        key, _ = encryption_system.derive_key_from_password(password, salt)
        success, message = encryption_system.decrypt_file_aes(input_path, output_path, key)
        if not success:
            os.remove(input_path)
            os.remove(salt_path)
            return jsonify({'error': message}), 500
    else:
        return jsonify({'error': 'Only AES method supported in API demo'}), 400
    
    # Return decrypted file
    response = send_file(output_path, as_attachment=True, download_name='decrypted_file')
    @response.call_on_close
    def cleanup():
        os.remove(input_path)
        os.remove(salt_path)
        os.remove(output_path)
    return response

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 