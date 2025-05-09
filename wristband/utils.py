from fastapi import Request
import json
from cryptography.fernet import Fernet
import base64
import os
import logging


class CookieEncryptor:
    def __init__(self, secret_key=None):
        """Initialize with a secret key or generate one"""
        if secret_key is None:
            # Generate a new key if none is provided
            self.secret_key = Fernet.generate_key()
        else:
            # Ensure the key is in the correct format for Fernet
            if isinstance(secret_key, str):
                key_bytes = secret_key.encode()
                # Make sure it's the right length and base64 URL-safe encoded
                if len(key_bytes) != 44 or not all(c in b'-_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789=' for c in key_bytes):
                    key_bytes = base64.urlsafe_b64encode(key_bytes.ljust(32)[:32])
                self.secret_key = key_bytes
            else:
                self.secret_key = secret_key
                
        self.cipher = Fernet(self.secret_key)
    
    def encrypt(self, data) -> str:
        """Encrypt data (dict) to a string suitable for cookies"""
        if not isinstance(data, dict):
            raise TypeError("Data must be a dictionary")
            
        json_data: bytes = json.dumps(data).encode()
        encrypted: bytes = self.cipher.encrypt(json_data)
        return base64.b64encode(encrypted).decode()
    
    def decrypt(self, encrypted_str: str) -> dict:
        """Decrypt a cookie string back to a dictionary"""
        if not encrypted_str:
            return {}
            
        try:
            decoded = base64.b64decode(encrypted_str)
            decrypted_bytes = self.cipher.decrypt(decoded)
            return json.loads(decrypted_bytes.decode())
        except Exception as e:
            # Return empty dict on decryption failure
            return {}

async def debug_request(request: Request, call_next):
    print("\n=== Incoming Request ===")
    print(f"Method: {request.method}")
    print(f"URL: {request.url}")
    print("Headers:")
    for name, value in request.headers.items():
        print(f"  {name}: {value}")
    body: bytes = await request.body()
    if body:
        try:
            body_json = json.loads(body)
            print("Body:")
            print(json.dumps(body_json, indent=2))
        except:
            print(f"Body: {body.decode()}")
    print("=====================\n")
    
    response = await call_next(request)
    return response


def to_bool(env_val: str) -> bool:
        return env_val.strip().lower() in ["true", "1", "yes"]


def get_logger(name: str = __name__) -> logging.Logger:
    """
    Returns a configured logger instance.
    
    Args:
        name: The name for the logger, defaults to the module name
        
    Returns:
        A configured logger instance
    """
    # Configure logger
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
    logging.basicConfig(level=LOG_LEVEL)

    return logging.getLogger(name)