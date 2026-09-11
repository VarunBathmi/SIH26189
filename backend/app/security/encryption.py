import hashlib
from cryptography.fernet import Fernet
from app.config import settings

# Initialize Fernet cipher
fernet_cipher = Fernet(settings.FERNET_KEY.encode() if isinstance(settings.FERNET_KEY, str) else settings.FERNET_KEY)

def generate_hash_id(value: str) -> str:
    """
    Generate deterministic 64-character SHA-256 hash ID for public graph nodes.
    Preserves anonymity while enabling cross-document graph linking.
    """
    normalized = value.strip().lower()
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

def encrypt_name(name: str) -> tuple[str, str]:
    """
    Encrypt a real PII name with Fernet (AES-128-CBC + HMAC-SHA256)
    and compute its deterministic hash_id.
    Returns: (encrypted_str, hash_id)
    """
    name_bytes = name.strip().encode("utf-8")
    encrypted = fernet_cipher.encrypt(name_bytes).decode("utf-8")
    hash_id = generate_hash_id(name)
    return encrypted, hash_id

def decrypt_name(encrypted_text: str) -> str:
    """
    Decrypt an encrypted PII string back to the real name.
    """
    try:
        decrypted_bytes = fernet_cipher.decrypt(encrypted_text.encode("utf-8"))
        return decrypted_bytes.decode("utf-8")
    except Exception as e:
        raise ValueError(f"Failed to decrypt entity name: {str(e)}")
