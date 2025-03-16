# Hardware-Based License Key Protection System

## Overview

This repository contains a robust license key protection system designed for software applications. It implements hardware fingerprinting, secure encryption, and time verification to create a reliable licensing mechanism that protects your software from unauthorized use.

The system consists of three main components:
- **Key Generator**: Creates unique license keys based on hardware ID
- **Security System**: Manages hardware fingerprinting, encryption, and license verification
- **Application Example**: Demonstrates how to integrate the protection system (WordReplacer)

## Protection Mechanisms

The system implements multiple layers of security to protect your software:

1. **Hardware Fingerprinting**
   - CPU identification (ProcessorId, Name, NumberOfCores)
   - BIOS information (Manufacturer, SerialNumber, Version)
   - Motherboard details (Manufacturer, Product, SerialNumber)
   - Disk drive information (Model, SerialNumber)
   - MAC address of the network adapter
   - Operating system platform information

2. **Cryptographic Protection**
   - RSA-2048 asymmetric encryption for key security
   - AES-256 symmetric encryption for license data
   - SHA-256 hashing for hardware fingerprint generation
   - PKCS7 padding for secure data handling
   - Base64 encoding with random noise for string obfuscation

3. **Anti-Tampering Measures**
   - NTP time verification against multiple servers (pool.ntp.org, time.google.com, etc.)
   - System time manipulation detection with 5-minute tolerance threshold
   - XOR operations with device-specific keys for additional encryption
   - Hardware component verification requiring at least 2 matching components

4. **License Management**
   - Time-limited licenses with configurable duration (1-365 days)
   - License expiration based on activation date
   - Secure storage of license data in encrypted format
   - License extension capability without reinstallation
   - Last verification timestamp tracking

5. **Implementation Security**
   - Secret key integration in validation algorithm
   - Exception handling to prevent information leakage
   - Randomized server selection for time verification
   - Hardware tolerance allowing for minor system changes
   - Encrypted on-disk license storage

## Components

### 1. Key Generator (`keygen.py`)

A standalone application for generating license keys based on:
- Hardware ID
- License duration (in days)
- Current date
- Secret key

![Key Generator Screenshot](key_generator_screenshot.png)

### 2. Security System (`security_system.py`)

The core security module provides:

- **EnhancedHardwareID**: Collects hardware information to create a unique device fingerprint
- **SecurityModule**: Handles encryption, time verification, and other security features
- **SecureLicenseManager**: Manages license validation, storage, and verification

### 3. Application Example (`word_replacer.py`)

Demonstrates integration with an actual application:
- License validation on startup
- Technical dialog for license information and renewal
- Activation dialog for new installations

## How It Works

1. **Hardware ID Generation**:
   - Collects information from CPU, BIOS, motherboard, disk, MAC address, and OS
   - Creates a unique fingerprint hash for the device

2. **License Creation**:
   - Administrator uses KeyGenerator to create a license key based on user's Hardware ID
   - Key incorporates the hardware ID, current date, validity period, and secret key

3. **License Activation**:
   - User enters the license key in the application
   - System verifies the key against the hardware
   - License data is encrypted and stored securely

4. **Ongoing Verification**:
   - Application checks license validity at startup and during operations
   - Verifies system time against NTP servers to prevent tampering
   - Confirms hardware matches the original activation hardware

## Integration Guide

### Prerequisites

- Python 3.6 or higher
- Required packages: PyQt5, cryptography, ntplib, wmi, python-docx

### Installation

```bash
pip install PyQt5 cryptography ntplib wmi python-docx
```

### Integrating with Your Application

1. **Include the Security System**:
   ```python
   from security_system import SecureLicenseManager
   ```

2. **Initialize License Manager**:
   ```python
   license_manager = SecureLicenseManager()
   ```

3. **Verify License on Startup**:
   ```python
   is_valid, message = license_manager.verify_license()
   if not is_valid:
       # Show activation dialog or exit
   ```

4. **Check License Before Critical Operations**:
   ```python
   def important_function():
       is_valid, message = license_manager.verify_license()
       if not is_valid:
           # Handle unlicensed state
           return False
       # Proceed with function
   ```

### Customization

**Important**: Before deploying, replace `"YourSecretKeyHere"` with your own secret key in both `keygen.py` and `security_system.py` files.

## Security Considerations

- The secret key should be strong and kept confidential
- Consider obfuscating the source code before distribution
- The license validation relies on hardware components that may change if users upgrade their systems
- The system requires internet access for NTP time verification

## Limitations

- Hardware upgrades may invalidate licenses (system allows for some flexibility)
- Requires proper error handling for systems without internet access
- Advanced users might attempt to reverse-engineer the protection

## License Extension Process

1. User provides their Hardware ID from the Technical dialog
2. Administrator generates a new key using the KeyGenerator
3. User enters the new key in the Technical dialog
4. The system adds the new license duration to the remaining time

## Example Application: Word Replacer

The included Word Replacer application demonstrates how to implement the licensing system:

- It processes Word documents in a selected folder
- Replaces specific text in documents that start with "@@" prefix
- Includes license activation and technical dialogs
- Shows days remaining and hardware ID information

This example is provided only to demonstrate the integration of the licensing system and can be replaced with your own application logic.

## Troubleshooting

- **License Invalid After Hardware Change**: If major hardware components are changed, a new license key will be required
- **Time Verification Failures**: Ensure the system has internet access for NTP verification
- **Activation Issues**: Verify the correct Hardware ID is being used for key generation

## Contributing

Contributions to improve the security system are welcome. Please feel free to submit pull requests or open issues for discussion.

## Disclaimer

This licensing system provides a reasonable level of protection but cannot guarantee complete security against determined attackers. Always consider additional protection measures for highly sensitive applications.
