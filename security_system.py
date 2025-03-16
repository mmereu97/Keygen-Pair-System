import os
import time
import ntplib
import socket
import random
import hashlib
import platform
import json
import uuid
import base64
import wmi
from typing import Dict, Tuple, Optional
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import serialization
from cryptography.fernet import Fernet

class EnhancedHardwareID:
    """Hardware fingerprinting class"""
    def __init__(self):
        self.wmi_client = wmi.WMI()
    
    def get_cpu_info(self) -> str:
        try:
            cpu_info = self.wmi_client.Win32_Processor()[0]
            return f"{cpu_info.ProcessorId}:{cpu_info.Name}:{cpu_info.NumberOfCores}"
        except Exception:
            return ""

    def get_bios_info(self) -> str:
        try:
            bios = self.wmi_client.Win32_BIOS()[0]
            return f"{bios.Manufacturer}:{bios.SerialNumber}:{bios.Version}"
        except Exception:
            return ""

    def get_baseboard_info(self) -> str:
        try:
            board = self.wmi_client.Win32_BaseBoard()[0]
            return f"{board.Manufacturer}:{board.Product}:{board.SerialNumber}"
        except Exception:
            return ""

    def get_disk_info(self) -> str:
        try:
            disks = self.wmi_client.Win32_DiskDrive()
            system_disk = next((disk for disk in disks if disk.Index == 0), None)
            if system_disk:
                return f"{system_disk.Model}:{system_disk.SerialNumber}"
            return ""
        except Exception:
            return ""

    def get_mac_address(self) -> str:
        try:
            mac = ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                           for elements in range(0,8*6,8)][::-1])
            return mac
        except Exception:
            return ""

    def generate_hardware_fingerprint(self) -> Dict[str, str]:
        fingerprint = {
            'cpu': self.get_cpu_info(),
            'bios': self.get_bios_info(),
            'board': self.get_baseboard_info(),
            'disk': self.get_disk_info(),
            'mac': self.get_mac_address(),
            'os': platform.platform()
        }
        return fingerprint

    def calculate_hardware_id(self) -> str:
        fingerprint = self.generate_hardware_fingerprint()
        combined_info = '|'.join([
            str(fingerprint.get('cpu', '')),
            str(fingerprint.get('bios', '')),
            str(fingerprint.get('board', '')),
            str(fingerprint.get('disk', '')),
            str(fingerprint.get('mac', '')),
            str(fingerprint.get('os', ''))
        ])
        return hashlib.sha256(combined_info.encode()).hexdigest()[:32]

class SecurityModule:
    """Core security functionality"""
    def __init__(self):
        self.ntp_servers = [
            'pool.ntp.org',
            'time.google.com',
            'time.windows.com',
            'time.apple.com'
        ]
        self.time_threshold = 300  # 5 minute tolerance
        self.rsa_key = self._generate_rsa_key()
        self.device_key = self._generate_device_specific_key()
        
    def _generate_rsa_key(self) -> rsa.RSAPrivateKey:
        return rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
    
    def _generate_device_specific_key(self) -> bytes:
        device_info = [
            platform.machine(),
            platform.processor(),
            platform.node(),
            str(self._get_disk_serial()),
            str(self._get_cpu_info()),
            platform.platform()
        ]
        combined = ":".join(filter(None, device_info))
        return hashlib.sha256(combined.encode()).digest()

    def _get_disk_serial(self) -> str:
        try:
            if platform.system() == "Windows":
                c = wmi.WMI()
                for disk in c.Win32_DiskDrive():
                    return disk.SerialNumber.strip()
            return ""
        except:
            return ""

    def _get_cpu_info(self) -> str:
        try:
            if platform.system() == "Windows":
                c = wmi.WMI()
                for cpu in c.Win32_Processor():
                    return cpu.ProcessorId.strip()
            return ""
        except:
            return ""

    def verify_time(self) -> Tuple[bool, str]:
        for server in random.sample(self.ntp_servers, 2):
            try:
                ntp_client = ntplib.NTPClient()
                response = ntp_client.request(server)
                ntp_time = datetime.fromtimestamp(response.tx_time)
                local_time = datetime.now()
                
                time_diff = abs((ntp_time - local_time).total_seconds())
                
                if time_diff > self.time_threshold:
                    return False, "System time manipulation detected"
                
                return True, "Time verification successful"
            except:
                continue
        return False, "Could not verify time"

    def encrypt_license_data(self, data: dict) -> Tuple[bytes, bytes]:
        # Generate a random AES key
        aes_key = os.urandom(32)
        iv = os.urandom(16)
        
        # Create AES cipher
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        
        # Pad and encrypt data
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        data_bytes = str(data).encode()
        padded_data = padder.update(data_bytes) + padder.finalize()
        encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
        
        # Combine IV and encrypted data
        final_data = iv + encrypted_data
        
        # Encrypt AES key with RSA
        encrypted_key = self.rsa_key.public_key().encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # XOR with device-specific key
        device_encrypted_data = self._xor_with_device_key(final_data)
        
        return device_encrypted_data, encrypted_key

    def decrypt_license_data(self, encrypted_data: bytes, encrypted_key: bytes) -> dict:
        try:
            # Decrypt AES key with RSA
            aes_key = self.rsa_key.decrypt(
                encrypted_key,
                asym_padding.OAEP(
                    mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            
            # XOR with device-specific key
            decrypted_data = self._xor_with_device_key(encrypted_data)
            
            # Separate IV and data
            iv = decrypted_data[:16]
            cipher_text = decrypted_data[16:]
            
            # Create AES cipher
            cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            
            # Decrypt data
            padded_data = decryptor.update(cipher_text) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            data = unpadder.update(padded_data) + unpadder.finalize()
            
            return eval(data.decode())
        except Exception as e:
            raise Exception(f"Decryption failed: {str(e)}")

    def _xor_with_device_key(self, data: bytes) -> bytes:
        if not data:
            return data
            
        result = bytearray(len(data))
        for i in range(len(data)):
            result[i] = data[i] ^ self.device_key[i % len(self.device_key)]
            
        return bytes(result)

    def obfuscate_string(self, text: str) -> str:
        b64 = base64.b64encode(text.encode()).decode()
        noise = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=8))
        return f"{noise}{b64}{noise[::-1]}"

    def deobfuscate_string(self, obfuscated: str) -> str:
        try:
            b64_str = obfuscated[8:-8]
            return base64.b64decode(b64_str).decode()
        except:
            return ""

class SecureLicenseManager:
    """License management class"""
    def __init__(self):
        self.license_file = "license.dat"
        self.hardware_id = EnhancedHardwareID()
        self.security = SecurityModule()
        
    def save_license(self, license_key: str) -> Tuple[bool, str]:
        time_valid, time_message = self.security.verify_time()
        if not time_valid:
            return False, f"Time verification failed: {time_message}"

        valid, new_days = self.validate_license_key(license_key)
        if not valid:
            return False, "Invalid license key"

        try:
            current_days = 0
            if os.path.exists(self.license_file):
                is_valid, message = self.verify_license()
                if is_valid:
                    current_days = int(message.split(": ")[1])

            license_data = {
                'key': self.security.obfuscate_string(license_key),
                'hwid': self.hardware_id.calculate_hardware_id(),
                'fingerprint': self.hardware_id.generate_hardware_fingerprint(),
                'activation_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'days_valid': current_days + new_days,
                'last_verified': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            }

            encrypted_data, encrypted_key = self.security.encrypt_license_data(license_data)
            
            with open(self.license_file, 'wb') as f:
                f.write(len(encrypted_key).to_bytes(4, 'big'))
                f.write(encrypted_key)
                f.write(encrypted_data)
                
            return True, "License activated successfully"

        except Exception as e:
            return False, f"Error saving license: {str(e)}"

    def verify_license(self) -> Tuple[bool, str]:
        try:
            time_valid, time_message = self.security.verify_time()
            if not time_valid:
                return False, f"Time verification failed: {time_message}"

            if not os.path.exists(self.license_file):
                return False, "No license found"

            with open(self.license_file, 'rb') as f:
                key_length = int.from_bytes(f.read(4), 'big')
                encrypted_key = f.read(key_length)
                encrypted_data = f.read()

            license_data = self.security.decrypt_license_data(encrypted_data, encrypted_key)
            license_data['key'] = self.security.deobfuscate_string(license_data['key'])

            current_fingerprint = self.hardware_id.generate_hardware_fingerprint()
            stored_fingerprint = license_data['fingerprint']
            
            matches = 0
            for component in ['cpu', 'bios', 'board']:
                if stored_fingerprint.get(component) == current_fingerprint.get(component):
                    matches += 1
            
            if matches < 2:
                return False, "Hardware verification failed"

            activation_date = datetime.strptime(license_data['activation_date'], 
                                              '%Y-%m-%d %H:%M:%S')
            days_valid = license_data['days_valid']
            
            if datetime.now() - activation_date > timedelta(days=days_valid):
                return False, "License expired"
                
            days_left = days_valid - (datetime.now() - activation_date).days
            
            license_data['last_verified'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            encrypted_data, encrypted_key = self.security.encrypt_license_data(license_data)
            with open(self.license_file, 'wb') as f:
                f.write(len(encrypted_key).to_bytes(4, 'big'))
                f.write(encrypted_key)
                f.write(encrypted_data)
            
            return True, f"License valid. Days remaining: {days_left}"
            
        except Exception as e:
            return False, f"License verification failed: {str(e)}"

    def validate_license_key(self, license_key: str) -> Tuple[bool, int]:
        try:
            hwid = self.hardware_id.calculate_hardware_id()
            current_date = datetime.now().strftime('%Y-%m-%d')
            
            for days in range(1, 366):
                key_base = f"{hwid}:{current_date}:{days}:YourSecretKeyHere"
                test_key = hashlib.sha256(key_base.encode()).hexdigest()[:32]
                if test_key == license_key:
                    return True, days
            return False, 0
        except:
            return False, 0

    def get_hardware_id(self) -> str:
        return self.hardware_id.calculate_hardware_id()