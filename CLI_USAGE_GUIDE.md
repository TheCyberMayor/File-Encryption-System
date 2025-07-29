# File Encryption System - Terminal Usage Guide

## 🖥️ **Terminal-Based Encryption Tools**

The File Encryption System provides multiple terminal-based interfaces for command-line operations.

## 📋 **Available Tools**

### 1. **Python CLI** (`file_encryption_cli.py`)
- Full-featured command-line interface
- All encryption/decryption operations
- System information and testing

### 2. **Windows Batch Script** (`encrypt.bat`)
- Simple Windows batch commands
- Easy to use for basic operations
- No PowerShell required

### 3. **PowerShell Script** (`encrypt.ps1`)
- Advanced PowerShell interface
- Better error handling and features
- Colored output and validation

## 🔧 **Python CLI Usage**

### **Basic Commands**

#### **Show Help**
```bash
python file_encryption_cli.py --help
```

#### **Show System Information**
```bash
python file_encryption_cli.py info
```

#### **Generate New Keys**
```bash
python file_encryption_cli.py keys
```

### **Encryption Commands**

#### **AES Encryption**
```bash
python file_encryption_cli.py encrypt -i "input_file.pdf" -o "encrypted_file.aes" -m aes -p "MyPassword123!"
```

#### **Hybrid Encryption**
```bash
python file_encryption_cli.py encrypt -i "input_file.pdf" -o "encrypted_file.bin" -m hybrid -p "MyPassword123!"
```

### **Decryption Commands**

#### **AES Decryption**
```bash
python file_encryption_cli.py decrypt -i "encrypted_file.aes" -o "decrypted_file.pdf" -m aes -p "MyPassword123!"
```

#### **Hybrid Decryption**
```bash
python file_encryption_cli.py decrypt -i "encrypted_file.bin" -o "decrypted_file.pdf" -m hybrid -p "MyPassword123!"
```

### **Testing Commands**

#### **Performance Test**
```bash
python file_encryption_cli.py test
```

#### **Security Analysis**
```bash
python file_encryption_cli.py security -p "MyPassword123!"
```

## 🪟 **Windows Batch Script Usage**

### **Basic Commands**

#### **Show Help**
```cmd
encrypt.bat
```

#### **Show System Information**
```cmd
encrypt.bat info
```

#### **Generate New Keys**
```cmd
encrypt.bat keys
```

### **Encryption Commands**

#### **AES Encryption**
```cmd
encrypt.bat encrypt "document.pdf" "MyPassword123"
```

#### **Hybrid Encryption**
```cmd
encrypt.bat hybrid "document.pdf" "MyPassword123"
```

### **Decryption Commands**

#### **AES Decryption**
```cmd
encrypt.bat decrypt "document_encrypted.aes" "MyPassword123"
```

## ⚡ **PowerShell Script Usage**

### **Basic Commands**

#### **Show Help**
```powershell
.\encrypt.ps1
```

#### **Show System Information**
```powershell
.\encrypt.ps1 info
```

#### **Generate New Keys**
```powershell
.\encrypt.ps1 keys
```

### **Encryption Commands**

#### **AES Encryption**
```powershell
.\encrypt.ps1 encrypt -InputFile "document.pdf" -Password "MyPassword123"
```

#### **Hybrid Encryption**
```powershell
.\encrypt.ps1 hybrid -InputFile "document.pdf" -Password "MyPassword123"
```

#### **Custom Output File**
```powershell
.\encrypt.ps1 encrypt -InputFile "document.pdf" -OutputFile "my_encrypted_file.aes" -Password "MyPassword123"
```

### **Decryption Commands**

#### **AES Decryption**
```powershell
.\encrypt.ps1 decrypt -InputFile "document_encrypted.aes" -Password "MyPassword123"
```

#### **Hybrid Decryption**
```powershell
.\encrypt.ps1 decrypt -InputFile "document_encrypted.bin" -Method hybrid -Password "MyPassword123"
```

### **Testing Commands**

#### **Performance Test**
```powershell
.\encrypt.ps1 test
```

#### **Security Analysis**
```powershell
.\encrypt.ps1 security -Password "MyPassword123"
```

## 📝 **Practical Examples**

### **Example 1: Encrypt a PDF Document**

#### **Using Python CLI**
```bash
python file_encryption_cli.py encrypt -i "C:\Users\HP\Downloads\document.pdf" -o "document_encrypted.aes" -m aes -p "SecurePassword123!"
```

#### **Using Batch Script**
```cmd
encrypt.bat encrypt "C:\Users\HP\Downloads\document.pdf" "SecurePassword123!"
```

#### **Using PowerShell**
```powershell
.\encrypt.ps1 encrypt -InputFile "C:\Users\HP\Downloads\document.pdf" -Password "SecurePassword123!"
```

### **Example 2: Decrypt an Encrypted File**

#### **Using Python CLI**
```bash
python file_encryption_cli.py decrypt -i "document_encrypted.aes" -o "document_decrypted.pdf" -m aes -p "SecurePassword123!"
```

#### **Using Batch Script**
```cmd
encrypt.bat decrypt "document_encrypted.aes" "SecurePassword123!"
```

#### **Using PowerShell**
```powershell
.\encrypt.ps1 decrypt -InputFile "document_encrypted.aes" -Password "SecurePassword123!"
```

### **Example 3: Encrypt with Hybrid Method**

#### **Using Python CLI**
```bash
python file_encryption_cli.py encrypt -i "sensitive_document.docx" -o "sensitive_encrypted.bin" -m hybrid -p "VerySecurePassword456!"
```

#### **Using Batch Script**
```cmd
encrypt.bat hybrid "sensitive_document.docx" "VerySecurePassword456!"
```

#### **Using PowerShell**
```powershell
.\encrypt.ps1 hybrid -InputFile "sensitive_document.docx" -Password "VerySecurePassword456!"
```

## 🔍 **File Extensions**

### **Input Files**
- **Any file type**: `.pdf`, `.docx`, `.txt`, `.jpg`, `.mp4`, etc.
- **No restrictions**: Works with all file formats

### **Output Files**
- **AES Encryption**: `.aes` extension
- **Hybrid Encryption**: `.bin` extension + `.meta` metadata file
- **Decrypted Files**: Original file extension restored

## ⚠️ **Important Notes**

### **Password Requirements**
- **Minimum**: 8 characters
- **Recommended**: 12+ characters with mixed types
- **Characters**: Uppercase, lowercase, numbers, special characters

### **File Paths**
- **Spaces**: Use quotes around file paths with spaces
- **Special characters**: Escape special characters in paths
- **Relative paths**: Use relative paths for files in current directory

### **Security**
- **Keep passwords safe**: Store passwords securely
- **Backup keys**: Keep backup of encryption keys
- **Test decryption**: Always test decryption after encryption

## 🚀 **Advanced Usage**

### **Batch Processing**
```bash
# Encrypt multiple files
for file in *.pdf; do
    python file_encryption_cli.py encrypt -i "$file" -o "${file%.pdf}_encrypted.aes" -m aes -p "MyPassword123!"
done
```

### **Automated Scripts**
```powershell
# PowerShell automation
$files = Get-ChildItem -Path "C:\Documents" -Filter "*.pdf"
foreach ($file in $files) {
    .\encrypt.ps1 encrypt -InputFile $file.FullName -Password "MyPassword123!"
}
```

## 🆘 **Troubleshooting**

### **Common Issues**

#### **"File not found" Error**
- Check file path is correct
- Use absolute paths if needed
- Ensure file exists in specified location

#### **"Permission denied" Error**
- Run as administrator if needed
- Check file permissions
- Ensure write access to output directory

#### **"Invalid key size" Error**
- This has been fixed in the latest version
- Update to the latest code if using older version

#### **"Decryption failed" Error**
- Verify password is correct
- Ensure using same encryption method
- Check if metadata file exists (for hybrid)

### **Getting Help**
```bash
# Show help for any command
python file_encryption_cli.py --help
python file_encryption_cli.py encrypt --help
```

## 📊 **Performance Tips**

### **For Large Files**
- Use AES method for better performance
- Hybrid method adds minimal overhead
- Both methods are optimized for large files

### **For Multiple Files**
- Use batch scripts for automation
- Consider parallel processing for many files
- Monitor system resources during encryption

---

**🎉 You now have complete terminal-based control over the File Encryption System!** 