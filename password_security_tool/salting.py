import os
import binascii
from typing import Union

# =================================================
# SALT GENERATION
# =================================================

def generate_salt(length: int = 16) -> bytes:
    """
    Generate a cryptographically secure random salt.
    
    Salts are used to prevent:
    - Rainbow table attacks (precomputed hash tables)
    - Hash reuse across identical passwords
    - Parallel attacks on multiple users
    
    Args:
        length: Salt length in bytes (default: 16 bytes = 128 bits)
                Minimum recommended: 16 bytes
                Common values: 16, 32, 64 bytes
    
    Returns:
        Cryptographically secure random bytes
    
    NOTE:
    Salting alone does NOT slow down brute-force attacks on individual passwords.
    Key stretching algorithms (bcrypt, PBKDF2, Argon2) are needed for that.
    Salting prevents attackers from cracking multiple passwords simultaneously.
    """
    if length < 8:
        raise ValueError("Salt length must be at least 8 bytes (64 bits)")
    
    return os.urandom(length)


def generate_salt_hex(length: int = 16) -> str:
    """
    Generate a cryptographically secure random salt as hexadecimal string.
    
    This is the preferred function for most use cases as hex strings are:
    - Easy to store in databases (text fields)
    - Easy to display in GUIs
    - Easy to pass as command-line arguments
    - Human-readable for debugging
    
    Args:
        length: Salt length in bytes (hex string will be 2x this length)
    
    Returns:
        Hex-encoded salt string (e.g., "a3f5c9...")
    """
    return binascii.hexlify(generate_salt(length)).decode('ascii')


# =================================================
# SALT ENCODING/DECODING
# =================================================

def salt_to_hex(salt: bytes) -> str:
    """
    Convert binary salt to hexadecimal string.
    
    Args:
        salt: Binary salt bytes
    
    Returns:
        Hex-encoded string
    """
    if not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes")
    
    return binascii.hexlify(salt).decode('ascii')


def hex_to_salt(hex_string: str) -> bytes:
    """
    Convert hexadecimal string back to binary salt.
    
    Args:
        hex_string: Hex-encoded salt string
    
    Returns:
        Binary salt bytes
    
    Raises:
        ValueError: If hex_string is not valid hexadecimal
    """
    if not isinstance(hex_string, str):
        raise TypeError("Hex string must be a string")
    
    try:
        return binascii.unhexlify(hex_string)
    except binascii.Error as e:
        raise ValueError(f"Invalid hexadecimal string: {e}")


# =================================================
# SALT APPLICATION
# =================================================

def apply_salt(password: str, salt: Union[str, bytes], 
               position: str = "suffix", encoding: str = "utf-8") -> bytes:
    """
    Apply salt to a password.
    
    Args:
        password: Plain text password
        salt: Salt as bytes or hex string
        position: Where to place salt:
                 - "suffix": password + salt (default, most common)
                 - "prefix": salt + password
                 - "both": salt + password + salt (extra security)
        encoding: Password encoding (default: utf-8)
    
    Returns:
        Salted password as bytes, ready for hashing
    
    IMPORTANT:
    The position and encoding must be IDENTICAL during both
    hashing and verification, or the hashes won't match!
    
    NOTE:
    Salting order doesn't significantly affect security.
    Consistency is what matters.
    """
    # Validate inputs
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    
    if len(password) == 0:
        raise ValueError("Password cannot be empty")
    
    # Convert salt to bytes if it's a hex string
    if isinstance(salt, str):
        salt = hex_to_salt(salt)
    elif not isinstance(salt, bytes):
        raise TypeError("Salt must be bytes or hex string")
    
    # Encode password
    password_bytes = password.encode(encoding)
    
    # Apply salt based on position
    position = position.lower()
    
    if position == "suffix":
        return password_bytes + salt
    elif position == "prefix":
        return salt + password_bytes
    elif position == "both":
        return salt + password_bytes + salt
    else:
        raise ValueError(f"Invalid position: {position}. Use 'suffix', 'prefix', or 'both'")


# =================================================
# PEPPER SUPPORT (ADVANCED)
# =================================================

# Application-level secret (should be stored securely, NOT in code)
# This is just an example - in production, load from environment variable or secure vault
DEFAULT_PEPPER = None

def set_pepper(pepper: str):
    """
    Set application-wide pepper (secret key).
    
    Pepper is a secret value added to ALL passwords before hashing.
    Unlike salts (which are unique per user and stored with the hash),
    pepper is:
    - The same for all users
    - NOT stored in the database
    - Kept secret in application configuration
    
    This adds an extra layer of security: even if the database is stolen,
    attackers can't crack passwords without also knowing the pepper.
    
    Args:
        pepper: Secret string (should be long and random)
    """
    global DEFAULT_PEPPER
    DEFAULT_PEPPER = pepper


def apply_salt_and_pepper(password: str, salt: Union[str, bytes], 
                          pepper: str = None, position: str = "suffix") -> bytes:
    """
    Apply both salt and pepper to a password.
    
    Order: password + pepper + salt
    
    Args:
        password: Plain text password
        salt: Per-user salt (unique for each user)
        pepper: Application-wide secret (same for all users)
        position: Salt position (suffix, prefix, both)
    
    Returns:
        Salted and peppered password bytes
    """
    # Use global pepper if not provided
    if pepper is None:
        pepper = DEFAULT_PEPPER or ""
    
    # Combine password and pepper first
    combined = password + pepper
    
    # Then apply salt
    return apply_salt(combined, salt, position)


# =================================================
# UTILITY FUNCTIONS
# =================================================

def validate_salt(salt: Union[str, bytes], min_length: int = 16) -> bool:
    """
    Validate that a salt meets minimum security requirements.
    
    Args:
        salt: Salt to validate (bytes or hex string)
        min_length: Minimum length in bytes
    
    Returns:
        True if valid, False otherwise
    """
    try:
        # Convert to bytes if hex string
        if isinstance(salt, str):
            salt = hex_to_salt(salt)
        
        # Check length
        if len(salt) < min_length:
            return False
        
        # Check that it's not all zeros (bad RNG indicator)
        if salt == b'\x00' * len(salt):
            return False
        
        return True
    
    except Exception:
        return False


def get_salt_info(salt: Union[str, bytes]) -> dict:
    """
    Get information about a salt.
    
    Returns:
        Dictionary with salt metadata:
        - length_bytes: Salt length in bytes
        - length_bits: Salt length in bits
        - hex_representation: Hex string
        - is_secure: Whether it meets minimum requirements
    """
    # Convert to bytes if needed
    if isinstance(salt, str):
        hex_repr = salt
        salt_bytes = hex_to_salt(salt)
    else:
        salt_bytes = salt
        hex_repr = salt_to_hex(salt)
    
    length_bytes = len(salt_bytes)
    length_bits = length_bytes * 8
    is_secure = validate_salt(salt_bytes)
    
    return {
        "length_bytes": length_bytes,
        "length_bits": length_bits,
        "hex_representation": hex_repr,
        "is_secure": is_secure,
        "security_level": get_security_level(length_bytes)
    }


def get_security_level(salt_length_bytes: int) -> str:
    """
    Evaluate security level based on salt length.
    
    Returns:
        Security level description
    """
    if salt_length_bytes >= 32:
        return "Excellent (256+ bits)"
    elif salt_length_bytes >= 16:
        return "Good (128+ bits)"
    elif salt_length_bytes >= 8:
        return "Acceptable (64+ bits)"
    else:
        return "Weak (< 64 bits)"


# =================================================
# TESTING & EXAMPLES
# =================================================

if __name__ == "__main__":
    print("Salt Generation and Management Demo")
    print("=" * 70)
    
    # Example 1: Generate and display salt
    print("\n1. Generate Salt:")
    salt_bytes = generate_salt(16)
    salt_hex = salt_to_hex(salt_bytes)
    print(f"   Binary (first 10 bytes): {salt_bytes[:10]}...")
    print(f"   Hex: {salt_hex}")
    
    # Example 2: Generate hex salt directly
    print("\n2. Generate Hex Salt Directly:")
    salt_hex2 = generate_salt_hex(16)
    print(f"   Hex: {salt_hex2}")
    
    # Example 3: Apply salt to password
    print("\n3. Apply Salt to Password:")
    password = "MySecurePassword123"
    salted_suffix = apply_salt(password, salt_hex, "suffix")
    salted_prefix = apply_salt(password, salt_hex, "prefix")
    salted_both = apply_salt(password, salt_hex, "both")
    
    print(f"   Original password: {password}")
    print(f"   Suffix (first 30 chars): {salted_suffix[:30]}...")
    print(f"   Prefix (first 30 chars): {salted_prefix[:30]}...")
    print(f"   Both (first 30 chars): {salted_both[:30]}...")
    
    # Example 4: Salt information
    print("\n4. Salt Information:")
    info = get_salt_info(salt_hex)
    print(f"   Length: {info['length_bytes']} bytes ({info['length_bits']} bits)")
    print(f"   Security Level: {info['security_level']}")
    print(f"   Is Secure: {info['is_secure']}")
    
    # Example 5: Pepper usage
    print("\n5. Pepper Example:")
    set_pepper("MyApplicationSecret2024!")
    peppered = apply_salt_and_pepper(password, salt_hex)
    print(f"   With pepper (first 30 chars): {peppered[:30]}...")
    
    # Example 6: Validation
    print("\n6. Salt Validation:")
    weak_salt = generate_salt(4)  # Only 4 bytes
    print(f"   16-byte salt valid: {validate_salt(salt_hex)}")
    print(f"   4-byte salt valid: {validate_salt(weak_salt)}")
    
    print("\n" + "=" * 70)
