import os
import base64
import json
import logging
import time
import hashlib
from datetime import datetime, timedelta
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asym_padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key, load_pem_public_key,
    Encoding, PrivateFormat, PublicFormat, NoEncryption
)
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
from cryptography import x509
import ipaddress
import uuid
import zlib

logger = logging.getLogger(__name__)

class SecureChannel:
    """
    Provides secure communication capabilities for transmitting
    sensitive data with encryption, authentication, and integrity.
    """
    
    def __init__(self, key=None, iv=None):
        """
        Initialize a secure channel with optional key and IV.
        
        Args:
            key (bytes, optional): Encryption key. If None, a key will be generated.
            iv (bytes, optional): Initialization vector. If None, an IV will be generated.
        """
        self.key = key or os.urandom(32)  # 256-bit key
        self.iv = iv or os.urandom(16)    # 128-bit IV
        self.session_id = str(uuid.uuid4())
        self.sequence_number = 0
        self.messages = []
    
    def encrypt_message(self, message, compress=True):
        """
        Encrypt a message for secure transmission.
        
        Args:
            message: The message to encrypt (dict, list, or str)
            compress (bool): Whether to compress the message before encryption
            
        Returns:
            dict: Encrypted message with metadata
        """
        try:
            # Convert message to JSON if it's a dict or list
            if isinstance(message, (dict, list)):
                plain_text = json.dumps(message).encode('utf-8')
            else:
                plain_text = str(message).encode('utf-8')
            
            # Compress if requested
            if compress and len(plain_text) > 100:
                plain_text = zlib.compress(plain_text)
                compressed = True
            else:
                compressed = False
            
            # Add padding
            padder = padding.PKCS7(128).padder()
            padded_data = padder.update(plain_text) + padder.finalize()
            
            # Encrypt with AES-256 in CBC mode
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(self.iv))
            encryptor = cipher.encryptor()
            cipher_text = encryptor.update(padded_data) + encryptor.finalize()
            
            # Create HMAC for integrity verification
            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(cipher_text)
            signature = h.finalize()
            
            # Increment sequence number
            self.sequence_number += 1
            
            # Create the complete encrypted message
            encrypted_message = {
                'encrypted_data': base64.b64encode(cipher_text).decode('utf-8'),
                'iv': base64.b64encode(self.iv).decode('utf-8'),
                'signature': base64.b64encode(signature).decode('utf-8'),
                'compressed': compressed,
                'timestamp': datetime.utcnow().isoformat(),
                'session_id': self.session_id,
                'sequence': self.sequence_number,
                'size': len(plain_text)
            }
            
            # Store message metadata for audit purposes
            self.messages.append({
                'timestamp': datetime.utcnow(),
                'sequence': self.sequence_number,
                'size': len(plain_text),
                'encrypted_size': len(cipher_text),
                'status': 'sent'
            })
            
            return encrypted_message
            
        except Exception as e:
            logger.error(f"Encryption error: {str(e)}")
            raise
    
    def decrypt_message(self, encrypted_message):
        """
        Decrypt a message received via the secure channel.
        
        Args:
            encrypted_message (dict): The encrypted message to decrypt
            
        Returns:
            The decrypted message (dict, list, or str)
        """
        try:
            # Extract components
            cipher_text = base64.b64decode(encrypted_message['encrypted_data'])
            iv = base64.b64decode(encrypted_message['iv'])
            signature = base64.b64decode(encrypted_message['signature'])
            compressed = encrypted_message.get('compressed', False)
            
            # Verify HMAC signature
            h = hmac.HMAC(self.key, hashes.SHA256())
            h.update(cipher_text)
            try:
                h.verify(signature)
            except InvalidSignature:
                logger.error("Message integrity check failed - HMAC verification error")
                raise ValueError("Message integrity check failed")
            
            # Decrypt the cipher text
            cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded_plain_text = decryptor.update(cipher_text) + decryptor.finalize()
            
            # Remove padding
            unpadder = padding.PKCS7(128).unpadder()
            plain_text = unpadder.update(padded_plain_text) + unpadder.finalize()
            
            # Decompress if necessary
            if compressed:
                plain_text = zlib.decompress(plain_text)
            
            # Store message metadata for audit purposes
            self.messages.append({
                'timestamp': datetime.utcnow(),
                'sequence': encrypted_message.get('sequence', -1),
                'size': encrypted_message.get('size', len(plain_text)),
                'encrypted_size': len(cipher_text),
                'status': 'received'
            })
            
            # Try to parse as JSON
            try:
                return json.loads(plain_text.decode('utf-8'))
            except:
                # Return as string if not valid JSON
                return plain_text.decode('utf-8')
            
        except Exception as e:
            logger.error(f"Decryption error: {str(e)}")
            raise
    
    def generate_key_pair(self):
        """
        Generate a new RSA key pair for asymmetric encryption.
        
        Returns:
            tuple: (private_key, public_key) as PEM strings
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048
        )
        
        # Extract public key
        public_key = private_key.public_key()
        
        # Serialize to PEM format
        private_pem = private_key.private_bytes(
            encoding=Encoding.PEM,
            format=PrivateFormat.PKCS8,
            encryption_algorithm=NoEncryption()
        ).decode('utf-8')
        
        public_pem = public_key.public_bytes(
            encoding=Encoding.PEM,
            format=PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
        
        return private_pem, public_pem
    
    def asymmetric_encrypt(self, message, public_key_pem):
        """
        Encrypt a message using asymmetric encryption with a public key.
        
        Args:
            message: The message to encrypt
            public_key_pem (str): Public key in PEM format
            
        Returns:
            dict: Encrypted message
        """
        try:
            # Convert message to bytes
            if isinstance(message, (dict, list)):
                plain_text = json.dumps(message).encode('utf-8')
            else:
                plain_text = str(message).encode('utf-8')
            
            # Load public key
            public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
            
            # For large messages, use hybrid encryption (asymmetrically encrypt a symmetric key)
            if len(plain_text) > 200:
                # Generate a random symmetric key
                symmetric_key = os.urandom(32)
                
                # Encrypt the symmetric key with the public key
                encrypted_key = public_key.encrypt(
                    symmetric_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Use the symmetric key to encrypt the message
                temp_channel = SecureChannel(key=symmetric_key)
                encrypted_data = temp_channel.encrypt_message(message)
                
                # Include the encrypted symmetric key
                encrypted_data['encrypted_key'] = base64.b64encode(encrypted_key).decode('utf-8')
                encrypted_data['encryption_method'] = 'hybrid'
                
                return encrypted_data
            else:
                # For small messages, encrypt directly with the public key
                encrypted_data = public_key.encrypt(
                    plain_text,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                return {
                    'encrypted_data': base64.b64encode(encrypted_data).decode('utf-8'),
                    'encryption_method': 'asymmetric',
                    'timestamp': datetime.utcnow().isoformat(),
                }
                
        except Exception as e:
            logger.error(f"Asymmetric encryption error: {str(e)}")
            raise
    
    def asymmetric_decrypt(self, encrypted_message, private_key_pem):
        """
        Decrypt a message using asymmetric encryption with a private key.
        
        Args:
            encrypted_message (dict): The encrypted message
            private_key_pem (str): Private key in PEM format
            
        Returns:
            The decrypted message
        """
        try:
            # Load private key
            private_key = load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )
            
            encryption_method = encrypted_message.get('encryption_method', 'asymmetric')
            
            if encryption_method == 'hybrid':
                # Decrypt the symmetric key
                encrypted_key = base64.b64decode(encrypted_message['encrypted_key'])
                symmetric_key = private_key.decrypt(
                    encrypted_key,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Create a channel with the decrypted symmetric key
                temp_channel = SecureChannel(key=symmetric_key)
                
                # Decrypt the message
                return temp_channel.decrypt_message(encrypted_message)
            else:
                # Direct asymmetric decryption
                encrypted_data = base64.b64decode(encrypted_message['encrypted_data'])
                plain_text = private_key.decrypt(
                    encrypted_data,
                    asym_padding.OAEP(
                        mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                        algorithm=hashes.SHA256(),
                        label=None
                    )
                )
                
                # Try to parse as JSON
                try:
                    return json.loads(plain_text.decode('utf-8'))
                except:
                    # Return as string if not valid JSON
                    return plain_text.decode('utf-8')
                
        except Exception as e:
            logger.error(f"Asymmetric decryption error: {str(e)}")
            raise
    
    def generate_derived_key(self, password, salt=None):
        """
        Generate a key derived from a password using PBKDF2.
        
        Args:
            password (str): The password to derive a key from
            salt (bytes, optional): Salt for key derivation. If None, a random salt is generated.
            
        Returns:
            tuple: (derived_key, salt)
        """
        salt = salt or os.urandom(16)
        
        # Use PBKDF2 with many iterations for security
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=salt,
            iterations=100000,  # High iteration count for security
        )
        
        key = kdf.derive(password.encode('utf-8'))
        return key, salt
    
    def create_secure_tunnel(self, remote_public_key_pem):
        """
        Create a secure tunnel for communication with a remote party.
        
        Args:
            remote_public_key_pem (str): Public key of the remote party
            
        Returns:
            dict: Tunnel information
        """
        # Generate a session key for this tunnel
        session_key = os.urandom(32)
        session_iv = os.urandom(16)
        
        # Encrypt the session key with the remote party's public key
        encrypted_session = self.asymmetric_encrypt(
            {
                'key': base64.b64encode(session_key).decode('utf-8'),
                'iv': base64.b64encode(session_iv).decode('utf-8'),
                'timestamp': datetime.utcnow().isoformat(),
                'expires': (datetime.utcnow() + timedelta(hours=24)).isoformat(),
                'session_id': str(uuid.uuid4())
            },
            remote_public_key_pem
        )
        
        # Create a new channel with the session key
        tunnel = SecureChannel(key=session_key, iv=session_iv)
        
        return {
            'tunnel': tunnel,
            'handshake': encrypted_session,
            'created_at': datetime.utcnow().isoformat(),
            'expires_at': (datetime.utcnow() + timedelta(hours=24)).isoformat()
        }
    
    def sign_message(self, message, private_key_pem):
        """
        Create a digital signature for a message.
        
        Args:
            message: The message to sign
            private_key_pem (str): Private key in PEM format
            
        Returns:
            str: Base64-encoded signature
        """
        try:
            # Convert message to bytes
            if isinstance(message, (dict, list)):
                message_bytes = json.dumps(message).encode('utf-8')
            else:
                message_bytes = str(message).encode('utf-8')
            
            # Load private key
            private_key = load_pem_private_key(
                private_key_pem.encode('utf-8'),
                password=None
            )
            
            # Create signature
            signature = private_key.sign(
                message_bytes,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return base64.b64encode(signature).decode('utf-8')
            
        except Exception as e:
            logger.error(f"Signature error: {str(e)}")
            raise
    
    def verify_signature(self, message, signature, public_key_pem):
        """
        Verify a digital signature for a message.
        
        Args:
            message: The message to verify
            signature (str): Base64-encoded signature
            public_key_pem (str): Public key in PEM format
            
        Returns:
            bool: True if signature is valid, False otherwise
        """
        try:
            # Convert message to bytes
            if isinstance(message, (dict, list)):
                message_bytes = json.dumps(message).encode('utf-8')
            else:
                message_bytes = str(message).encode('utf-8')
            
            # Load public key
            public_key = load_pem_public_key(public_key_pem.encode('utf-8'))
            
            # Decode signature
            signature_bytes = base64.b64decode(signature)
            
            # Verify signature
            public_key.verify(
                signature_bytes,
                message_bytes,
                asym_padding.PSS(
                    mgf=asym_padding.MGF1(hashes.SHA256()),
                    salt_length=asym_padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            
            return True
            
        except InvalidSignature:
            logger.warning("Signature verification failed")
            return False
        except Exception as e:
            logger.error(f"Signature verification error: {str(e)}")
            return False
    
    def get_message_history(self, last_n=None):
        """
        Get message history for audit purposes.
        
        Args:
            last_n (int, optional): Number of most recent messages to retrieve
            
        Returns:
            list: Message history
        """
        history = [
            {
                'timestamp': msg['timestamp'].isoformat(),
                'sequence': msg['sequence'],
                'size': msg['size'],
                'encrypted_size': msg.get('encrypted_size', 0),
                'status': msg['status'],
                'compression_ratio': round(msg['size'] / msg['encrypted_size'], 2) if msg.get('encrypted_size', 0) > 0 else 0
            }
            for msg in self.messages
        ]
        
        if last_n is not None:
            return history[-last_n:]
        return history

class SecureDataStorage:
    """
    Provides encrypted storage for sensitive data.
    """
    
    def __init__(self, master_key=None):
        """
        Initialize encrypted storage with an optional master key.
        
        Args:
            master_key (bytes, optional): Master encryption key. If None, a key will be generated.
        """
        self.master_key = master_key or os.urandom(32)
        self.storage = {}
    
    def encrypt_and_store(self, key, data):
        """
        Encrypt and store data.
        
        Args:
            key (str): Storage key
            data: Data to encrypt and store
            
        Returns:
            bool: True if successful
        """
        try:
            # Create a secure channel for encryption
            channel = SecureChannel(key=self.master_key)
            
            # Encrypt the data
            encrypted_data = channel.encrypt_message(data)
            
            # Store with metadata
            self.storage[key] = {
                'data': encrypted_data,
                'created_at': datetime.utcnow().isoformat(),
                'hash': hashlib.sha256(json.dumps(encrypted_data).encode('utf-8')).hexdigest()
            }
            
            return True
            
        except Exception as e:
            logger.error(f"Storage encryption error: {str(e)}")
            return False
    
    def retrieve_and_decrypt(self, key):
        """
        Retrieve and decrypt stored data.
        
        Args:
            key (str): Storage key
            
        Returns:
            The decrypted data, or None if not found or error
        """
        try:
            # Check if key exists
            if key not in self.storage:
                return None
            
            # Get the encrypted data
            encrypted_entry = self.storage[key]
            
            # Create a secure channel for decryption
            channel = SecureChannel(key=self.master_key)
            
            # Decrypt the data
            decrypted_data = channel.decrypt_message(encrypted_entry['data'])
            
            return decrypted_data
            
        except Exception as e:
            logger.error(f"Storage decryption error: {str(e)}")
            return None
    
    def list_stored_keys(self):
        """
        List all keys in the storage.
        
        Returns:
            list: List of storage keys with metadata
        """
        return [
            {
                'key': key,
                'created_at': entry['created_at'],
                'hash': entry['hash']
            }
            for key, entry in self.storage.items()
        ]
    
    def delete_stored_data(self, key):
        """
        Delete stored data.
        
        Args:
            key (str): Storage key
            
        Returns:
            bool: True if deleted, False if not found
        """
        if key in self.storage:
            del self.storage[key]
            return True
        return False
    
    def clear_all_data(self):
        """
        Clear all stored data.
        
        Returns:
            int: Number of items cleared
        """
        count = len(self.storage)
        self.storage.clear()
        return count
    
    def export_encrypted_backup(self, backup_password):
        """
        Export an encrypted backup of all stored data.
        
        Args:
            backup_password (str): Password to encrypt the backup
            
        Returns:
            dict: Encrypted backup data
        """
        try:
            # Derive a key from the password
            key_derivation = SecureChannel()
            derived_key, salt = key_derivation.generate_derived_key(backup_password)
            
            # Create a secure channel for encryption
            backup_channel = SecureChannel(key=derived_key)
            
            # Encrypt the entire storage
            encrypted_backup = backup_channel.encrypt_message(self.storage)
            
            # Add backup metadata
            backup_data = {
                'backup_data': encrypted_backup,
                'salt': base64.b64encode(salt).decode('utf-8'),
                'created_at': datetime.utcnow().isoformat(),
                'item_count': len(self.storage),
                'version': '1.0'
            }
            
            return backup_data
            
        except Exception as e:
            logger.error(f"Backup encryption error: {str(e)}")
            raise
    
    def import_encrypted_backup(self, backup_data, backup_password):
        """
        Import an encrypted backup.
        
        Args:
            backup_data (dict): Encrypted backup data
            backup_password (str): Password to decrypt the backup
            
        Returns:
            bool: True if successful
        """
        try:
            # Extract backup components
            encrypted_data = backup_data['backup_data']
            salt = base64.b64decode(backup_data['salt'])
            
            # Derive the key from the password
            key_derivation = SecureChannel()
            derived_key, _ = key_derivation.generate_derived_key(backup_password, salt)
            
            # Create a secure channel for decryption
            backup_channel = SecureChannel(key=derived_key)
            
            # Decrypt the backup
            decrypted_storage = backup_channel.decrypt_message(encrypted_data)
            
            # Verify and update storage
            if isinstance(decrypted_storage, dict):
                self.storage = decrypted_storage
                return True
            else:
                logger.error("Backup format error: decrypted data is not a dictionary")
                return False
                
        except Exception as e:
            logger.error(f"Backup import error: {str(e)}")
            return False


# Utility functions for secure operations

def generate_secure_token(length=32):
    """
    Generate a cryptographically secure random token.
    
    Args:
        length (int): Token length in bytes
        
    Returns:
        str: Base64-encoded token
    """
    token_bytes = os.urandom(length)
    return base64.urlsafe_b64encode(token_bytes).decode('utf-8').rstrip('=')

def constant_time_compare(a, b):
    """
    Compare two strings in constant time to prevent timing attacks.
    
    Args:
        a (str): First string
        b (str): Second string
        
    Returns:
        bool: True if strings are equal
    """
    if len(a) != len(b):
        return False
        
    result = 0
    for x, y in zip(a, b):
        result |= ord(x) ^ ord(y)
    return result == 0

def create_secure_hash(data, salt=None):
    """
    Create a secure hash of data.
    
    Args:
        data: Data to hash
        salt (bytes, optional): Salt for hashing. If None, a random salt is generated.
        
    Returns:
        tuple: (hash_str, salt)
    """
    salt = salt or os.urandom(16)
    
    # Convert to bytes if needed
    if isinstance(data, (dict, list)):
        data_bytes = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = bytes(data)
    
    # Create a salted hash
    h = hashlib.sha256()
    h.update(salt)
    h.update(data_bytes)
    hash_digest = h.digest()
    
    return base64.b64encode(hash_digest).decode('utf-8'), base64.b64encode(salt).decode('utf-8')

def verify_secure_hash(data, expected_hash, salt):
    """
    Verify that data matches an expected hash.
    
    Args:
        data: Data to verify
        expected_hash (str): Expected Base64-encoded hash
        salt (str): Base64-encoded salt used in hashing
        
    Returns:
        bool: True if hash matches
    """
    # Decode salt
    salt_bytes = base64.b64decode(salt)
    
    # Convert to bytes if needed
    if isinstance(data, (dict, list)):
        data_bytes = json.dumps(data).encode('utf-8')
    elif isinstance(data, str):
        data_bytes = data.encode('utf-8')
    else:
        data_bytes = bytes(data)
    
    # Create a salted hash
    h = hashlib.sha256()
    h.update(salt_bytes)
    h.update(data_bytes)
    hash_digest = h.digest()
    
    computed_hash = base64.b64encode(hash_digest).decode('utf-8')
    
    # Compare in constant time
    return constant_time_compare(computed_hash, expected_hash)