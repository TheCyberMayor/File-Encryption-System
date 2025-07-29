#!/usr/bin/env pwsh
<#
.SYNOPSIS
    File Encryption System - PowerShell Interface

.DESCRIPTION
    Provides PowerShell commands for file encryption and decryption operations.

.PARAMETER Command
    The command to execute: encrypt, decrypt, hybrid, info, keys, test, security

.PARAMETER InputFile
    Path to the input file for encryption/decryption

.PARAMETER OutputFile
    Path to the output file (optional, will auto-generate if not specified)

.PARAMETER Method
    Encryption method: aes or hybrid

.PARAMETER Password
    Password for encryption/decryption

.EXAMPLE
    .\encrypt.ps1 encrypt -InputFile "document.pdf" -Password "MyPassword123"
    
.EXAMPLE
    .\encrypt.ps1 decrypt -InputFile "document_encrypted.aes" -Password "MyPassword123"
    
.EXAMPLE
    .\encrypt.ps1 hybrid -InputFile "document.pdf" -Password "MyPassword123"
    
.EXAMPLE
    .\encrypt.ps1 info
    
.EXAMPLE
    .\encrypt.ps1 keys
#>

param(
    [Parameter(Mandatory=$true, Position=0)]
    [ValidateSet("encrypt", "decrypt", "hybrid", "info", "keys", "test", "security")]
    [string]$Command,
    
    [Parameter(Mandatory=$false)]
    [string]$InputFile,
    
    [Parameter(Mandatory=$false)]
    [string]$OutputFile,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet("aes", "hybrid")]
    [string]$Method = "aes",
    
    [Parameter(Mandatory=$false)]
    [string]$Password
)

# Function to display banner
function Show-Banner {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   FILE ENCRYPTION SYSTEM - POWERSHELL" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
}

# Function to show help
function Show-Help {
    Write-Host "Usage: .\encrypt.ps1 [command] [options]" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Commands:" -ForegroundColor Green
    Write-Host "  encrypt -InputFile <file> -Password <pass> [-Method aes|hybrid]" -ForegroundColor White
    Write-Host "  decrypt -InputFile <file> -Password <pass> [-Method aes|hybrid]" -ForegroundColor White
    Write-Host "  hybrid  -InputFile <file> -Password <pass>" -ForegroundColor White
    Write-Host "  info" -ForegroundColor White
    Write-Host "  keys" -ForegroundColor White
    Write-Host "  test" -ForegroundColor White
    Write-Host "  security -Password <pass>" -ForegroundColor White
    Write-Host ""
    Write-Host "Examples:" -ForegroundColor Green
    Write-Host "  .\encrypt.ps1 encrypt -InputFile 'document.pdf' -Password 'MyPassword123'" -ForegroundColor Gray
    Write-Host "  .\encrypt.ps1 decrypt -InputFile 'document_encrypted.aes' -Password 'MyPassword123'" -ForegroundColor Gray
    Write-Host "  .\encrypt.ps1 hybrid -InputFile 'document.pdf' -Password 'MyPassword123'" -ForegroundColor Gray
    Write-Host "  .\encrypt.ps1 info" -ForegroundColor Gray
    Write-Host "  .\encrypt.ps1 keys" -ForegroundColor Gray
    Write-Host "  .\encrypt.ps1 test" -ForegroundColor Gray
    Write-Host "  .\encrypt.ps1 security -Password 'MyPassword123'" -ForegroundColor Gray
}

# Main execution
Show-Banner

switch ($Command) {
    "encrypt" {
        if (-not $InputFile) {
            Write-Host "❌ Error: Input file is required for encryption" -ForegroundColor Red
            Show-Help
            exit 1
        }
        if (-not $Password) {
            Write-Host "❌ Error: Password is required for encryption" -ForegroundColor Red
            Show-Help
            exit 1
        }
        if (-not $OutputFile) {
            $OutputFile = if ($Method -eq "hybrid") { 
                "$InputFile`_hybrid_encrypted.bin" 
            } else { 
                "$InputFile`_aes_encrypted.aes" 
            }
        }
        
        Write-Host "🔒 Encrypting $InputFile with $Method method..." -ForegroundColor Green
        python file_encryption_cli.py encrypt -i "$InputFile" -o "$OutputFile" -m $Method -p "$Password"
    }
    
    "decrypt" {
        if (-not $InputFile) {
            Write-Host "❌ Error: Input file is required for decryption" -ForegroundColor Red
            Show-Help
            exit 1
        }
        if (-not $Password) {
            Write-Host "❌ Error: Password is required for decryption" -ForegroundColor Red
            Show-Help
            exit 1
        }
        if (-not $OutputFile) {
            $OutputFile = "$InputFile`_decrypted"
        }
        
        Write-Host "🔓 Decrypting $InputFile with $Method method..." -ForegroundColor Green
        python file_encryption_cli.py decrypt -i "$InputFile" -o "$OutputFile" -m $Method -p "$Password"
    }
    
    "hybrid" {
        if (-not $InputFile) {
            Write-Host "❌ Error: Input file is required for hybrid encryption" -ForegroundColor Red
            Show-Help
            exit 1
        }
        if (-not $Password) {
            Write-Host "❌ Error: Password is required for hybrid encryption" -ForegroundColor Red
            Show-Help
            exit 1
        }
        if (-not $OutputFile) {
            $OutputFile = "$InputFile`_hybrid_encrypted.bin"
        }
        
        Write-Host "🔐 Encrypting $InputFile with Hybrid method..." -ForegroundColor Green
        python file_encryption_cli.py encrypt -i "$InputFile" -o "$OutputFile" -m hybrid -p "$Password"
    }
    
    "info" {
        Write-Host "📊 Showing system information..." -ForegroundColor Green
        python file_encryption_cli.py info
    }
    
    "keys" {
        Write-Host "🔑 Generating new keys..." -ForegroundColor Green
        python file_encryption_cli.py keys
    }
    
    "test" {
        Write-Host "🚀 Running performance test..." -ForegroundColor Green
        python file_encryption_cli.py test
    }
    
    "security" {
        if (-not $Password) {
            $Password = "TestPassword123!"
            Write-Host "⚠️  No password provided, using default password for security analysis" -ForegroundColor Yellow
        }
        Write-Host "🔒 Running security analysis..." -ForegroundColor Green
        python file_encryption_cli.py security -p "$Password"
    }
    
    default {
        Write-Host "❌ Unknown command: $Command" -ForegroundColor Red
        Show-Help
        exit 1
    }
}

Write-Host ""
Write-Host "✅ Operation completed!" -ForegroundColor Green 