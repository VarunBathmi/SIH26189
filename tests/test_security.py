import pytest
from app.security.encryption import encrypt_name, decrypt_name, generate_hash_id

def test_cryptographic_roundtrip():
    original = "Confidential Suspect Name"
    encrypted, hash_id = encrypt_name(original)
    
    assert hash_id is not None
    assert len(hash_id) == 64
    assert encrypted != original
    assert decrypt_name(encrypted) == original

def test_deterministic_hash_id():
    name = "Vikas Yadav"
    h1 = generate_hash_id(name)
    h2 = generate_hash_id("  vikas yadav ") # whitespace and case insensitive
    assert h1 == h2
