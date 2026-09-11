import hashlib
import hmac
from typing import Dict, Any

# Deterministic visual block mapping (4 visual density levels mapped across 16 hex nibbles)
# 0-3: ░ (Light shade)
# 4-7: ▒ (Medium shade)
# 8-11: ▓ (Dark shade)
# 12-15: █ (Full block)
BLOCK_MAP = {
    '0': '░', '1': '░', '2': '░', '3': '░',
    '4': '▒', '5': '▒', '6': '▒', '7': '▒',
    '8': '▓', '9': '▓', 'a': '▓', 'b': '▓',
    'c': '█', 'd': '█', 'e': '█', 'f': '█'
}

def generate_sha256(file_bytes: bytes) -> str:
    """
    Generate SHA-256 cryptographic fingerprint from raw binary evidence bytes.
    Treats SHA-256 as an immutable digital evidence integrity fingerprint.
    """
    if not isinstance(file_bytes, (bytes, bytearray)):
        raise TypeError("file_bytes must be raw bytes")
    return hashlib.sha256(file_bytes).hexdigest().lower()

def verify_sha256(file_bytes: bytes, expected_hash: str) -> bool:
    """
    Verify evidence binary bytes against an expected SHA-256 hash using constant-time comparison.
    """
    if not expected_hash:
        return False
    actual_hash = generate_sha256(file_bytes)
    return hmac.compare_digest(actual_hash.lower(), expected_hash.strip().lower())

def format_hash_blocks(hex_hash: str) -> str:
    """
    Format 64-character hex hash into a professional forensic 4x4 matrix representation.
    Example:
    C6D4 99DC A525 8052
    11A1 1B3E 4033 4D5C
    32A0 FF1F 1C2D ACC4
    BB59 1F3D AE8A 3E27
    """
    clean_hex = hex_hash.strip().upper()
    if len(clean_hex) != 64:
        clean_hex = clean_hex.ljust(64, '0')[:64]
    
    # Split into 16 chunks of 4 hex chars
    chunks = [clean_hex[i:i+4] for i in range(0, 64, 4)]
    # Group every 4 chunks into one line
    lines = [" ".join(chunks[i:i+4]) for i in range(0, 16, 4)]
    return "\n".join(lines)

def generate_visual_symbols(hex_hash: str) -> str:
    """
    Generate deterministic visual symbol block representation from the SHA-256 fingerprint.
    Note: This is strictly a UI visual representation for rapid human scannability,
    not a cryptographic cipher.
    """
    clean_hex = hex_hash.strip().lower()
    symbols = "".join(BLOCK_MAP.get(c, '░') for c in clean_hex)
    
    # Format into groups of 4 symbols separated by spaces, 4 groups per row
    chunks = [symbols[i:i+4] for i in range(0, 64, 4)]
    lines = [" ".join(chunks[i:i+4]) for i in range(0, len(chunks), 4)]
    return "\n".join(lines)

def get_evidence_fingerprint_bundle(file_bytes: bytes) -> Dict[str, Any]:
    """
    Compute full cryptographic evidence fingerprint bundle.
    """
    sha_hash = generate_sha256(file_bytes)
    return {
        "algorithm": "SHA-256",
        "fingerprint": sha_hash,
        "formatted_blocks": format_hash_blocks(sha_hash),
        "visual_symbols": generate_visual_symbols(sha_hash),
        "byte_size": len(file_bytes),
        "disclaimer": "SHA-256 is an immutable cryptographic fingerprint used for forensic evidence integrity verification. Visual symbols are a deterministic UI representation."
    }
