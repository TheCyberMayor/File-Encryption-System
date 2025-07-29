@echo off
echo ========================================
echo    FILE ENCRYPTION SYSTEM - BATCH
echo ========================================
echo.

if "%1"=="" (
    echo Usage: encrypt.bat [command] [options]
    echo.
    echo Commands:
    echo   encrypt [file] [password]     - Encrypt file with AES
    echo   decrypt [file] [password]     - Decrypt file with AES
    echo   hybrid [file] [password]      - Encrypt file with Hybrid method
    echo   info                          - Show system information
    echo   keys                          - Generate new keys
    echo.
    echo Examples:
    echo   encrypt.bat encrypt document.pdf MyPassword123
    echo   encrypt.bat decrypt document_encrypted.aes MyPassword123
    echo   encrypt.bat hybrid document.pdf MyPassword123
    echo   encrypt.bat info
    echo   encrypt.bat keys
    echo.
    pause
    exit /b
)

if "%1"=="encrypt" (
    if "%2"=="" (
        echo Error: Please specify a file to encrypt
        pause
        exit /b
    )
    if "%3"=="" (
        echo Error: Please specify a password
        pause
        exit /b
    )
    echo Encrypting %2 with AES...
    python file_encryption_cli.py encrypt -i "%2" -o "%2_aes_encrypted.aes" -m aes -p "%3"
    echo.
    echo Encryption completed! Output: %2_aes_encrypted.aes
    pause
    exit /b
)

if "%1"=="decrypt" (
    if "%2"=="" (
        echo Error: Please specify a file to decrypt
        pause
        exit /b
    )
    if "%3"=="" (
        echo Error: Please specify a password
        pause
        exit /b
    )
    echo Decrypting %2 with AES...
    python file_encryption_cli.py decrypt -i "%2" -o "%2_decrypted" -m aes -p "%3"
    echo.
    echo Decryption completed!
    pause
    exit /b
)

if "%1"=="hybrid" (
    if "%2"=="" (
        echo Error: Please specify a file to encrypt
        pause
        exit /b
    )
    if "%3"=="" (
        echo Error: Please specify a password
        pause
        exit /b
    )
    echo Encrypting %2 with Hybrid method...
    python file_encryption_cli.py encrypt -i "%2" -o "%2_hybrid_encrypted.bin" -m hybrid -p "%3"
    echo.
    echo Encryption completed! Output: %2_hybrid_encrypted.bin
    pause
    exit /b
)

if "%1"=="info" (
    echo Showing system information...
    python file_encryption_cli.py info
    pause
    exit /b
)

if "%1"=="keys" (
    echo Generating new keys...
    python file_encryption_cli.py keys
    pause
    exit /b
)

echo Unknown command: %1
echo Use: encrypt.bat [encrypt^|decrypt^|hybrid^|info^|keys]
pause 