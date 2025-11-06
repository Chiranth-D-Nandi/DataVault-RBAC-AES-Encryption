# Data Vault - File Encryption with Role-Based Access Control

A secure desktop application for file encryption and storage management, featuring AES-256 encryption and role-based access control (RBAC) for enhanced data security.

## Overview

Data Vault is a GTK3-based desktop application that provides enterprise-grade file encryption with granular access control. The system implements a two-tier role structure (Admin and Staff) to manage encrypted file storage, with comprehensive audit logging for compliance and security monitoring.

## Features

### Core Functionality
- AES-256-CBC Encryption: Military-grade encryption using OpenSSL
- Role-Based Access Control (RBAC): Separate interfaces for Admin and Staff users
- Secure Key Management: Random per-session key generation with separate key file storage
- User Authentication: Secure login system with password validation
- Access Logging: CSV-based audit trail for all encryption operations

### Staff Features
- Upload files to encrypted vault
- Automatic file encryption with secure key generation
- Original file auto-deletion after successful encryption
- Simple, intuitive file selection interface

### Admin Features
- Decrypt vault files using encrypted file + key pair
- View comprehensive access logs
- Audit trail of all encryption operations with timestamps
- User and access management capabilities

## Security Features

- Password Requirements
  - Minimum 8 characters
  - Must contain at least 1 special character
  
- Encryption Details:
  - AES-256 in CBC mode
  - Randomly generated 256-bit keys
  - Randomly generated 128-bit initialization vectors (IVs)
  - Keys stored separately from encrypted files

- File Handling:
  - Original files securely deleted after encryption
  - Encrypted files maintain original extension with `_encrypted` suffix
  - Decrypted files tagged with `_decrypted` suffix

## Installation
PREREQUISITES: NONE!!
### Windows Installation
This project has been packaged using Inno Setup. Just download the fully packaged, ready to install .exe file on your WindowsPC and install it. 
## Usage

### First Time Setup

1. Launch the application
2. Click "Register New Staff/User"
3. Create an admin account with:
   - Username
   - Password (min 8 chars with special character)
   - Role: Admin

### Staff Workflow

1. Login with staff credentials
2. Click "Choose a file" to select a file
3. Click "Upload to Vault" to encrypt
4. Original file is deleted, encrypted file and key are saved

### Admin Workflow

1. Login with admin credentials
2. To Decrypt:
   - Select the encrypted file
   - Select the corresponding `.key` file
   - Click "Decrypt File"
3. To View Logs:
   - Click "View Access Logs"
   - Review all encryption operations with timestamps

## File Structure

```
datavault/
├── main.c              # GTK3 GUI and main application logic
├── enc.c               # Encryption implementation
├── enc.h               # Encryption header
├── dec.c               # Decryption implementation
├── dec.h               # Decryption header
├── userda.txt          # User credentials database
├── access_log.csv      # Audit log (generated)
└── logo.png            # Application logo
```

## Access Log Format

The `access_log.csv` file contains:
```
username,file_encrypted,timestamp
staff1,document.pdf,06-11-2025 14:30:45
```

## Technical Architecture

### Technologies Used
- Language: C
- GUI Framework: GTK3
- Cryptography: OpenSSL (libssl, libcrypto)
- **File I/O**: Standard C library

### Encryption Process
1. Generate random 256-bit AES key
2. Generate random 128-bit IV
3. Save key and IV to `.key` file
4. Encrypt file using AES-256-CBC
5. Save encrypted file with `_encrypted` suffix
6. Delete original file
7. Log operation to audit trail

### Decryption Process
1. Read key and IV from `.key` file
2. Decrypt encrypted file using AES-256-CBC
3. Save decrypted file with `_decrypted` suffix
4. Preserve original file extension

## Development Challenges Overcome

- OpenSSL-GTK3 Integration: Successfully bridged cryptographic operations with GUI event handling
- Error Handling: Implemented comprehensive error checking for file I/O and cryptographic operations
- System-Level Cryptography: Managed secure random number generation and proper cipher context handling
- Cross-Platform Considerations: Designed for portability with Windows distribution via Inno Setup

## Security Considerations

Important Notes:
- Keep `.key` files secure - they are required for decryption
- User credentials are stored in plaintext in `userda.txt` (suitable for demonstration; production systems should use hashed passwords)
- Access logs contain sensitive operation information
- Encrypted files cannot be recovered without the corresponding key file

## Future Enhancements
- [ ] Database backend for user management
- [ ] File integrity verification (HMAC)
- [ ] Batch file encryption
- [ ] Export/import functionality for logs
- [ ] Multi-factor authentication

## License

No License / All Rights Reserved

## Author

Chiranth D Nandi
