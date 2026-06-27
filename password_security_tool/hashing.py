import hashlib
import bcrypt
from typing import Tuple, Optional, Dict
from salting import generate_salt, apply_salt

# =================================================
# HASH TYPE DETECTION
# =================================================

HASH_LENGTHS = {
    32: ["md5", "ntlm"],
    40: ["sha1"],
    56: ["sha224"],
    64: ["sha256"],
    96: ["sha384"],
    128: ["sha512"]
}

def detect_hash_type(hash_string: str) -> Optional[str]:
    """
    Attempts to detect hash type based on hash length and format.
    
    Returns:
        Detected hash type as string, or None if unrecognized
    """
    hash_string = hash_string.strip()
    hash_length = len(hash_string)
    
    # Check for bcrypt (starts with $2a$, $2b$, or $2y$)
    if hash_string.startswith(('$2a$', '$2b$', '$2y$')):
        return "bcrypt"
    
    # Check for common hash lengths
    if hash_length in HASH_LENGTHS:
        possible_types = HASH_LENGTHS[hash_length]
        if len(possible_types) == 1:
            return possible_types[0]
        else:
            # Default to most common for that length
            return possible_types[0]
    
    return None


def parse_hash_salt(hash_string: str) -> Tuple[str, Optional[str]]:
    """
    Parses hash:salt format commonly used in hash dumps.
    
    Args:
        hash_string: String in format "hash" or "hash:salt"
    
    Returns:
        (hash, salt) tuple where salt is None if not present
    """
    parts = hash_string.split(':', 1)
    if len(parts) == 2:
        return parts[0].strip(), parts[1].strip()
    return parts[0].strip(), None


# =================================================
# BASIC HASHING (INSECURE – FOR DEMONSTRATION ONLY)
# =================================================

def md5_hash(password: str) -> str:
    """
    Generate MD5 hash.
    
    ⚠️ SECURITY WARNING:
    MD5 is cryptographically broken and should NOT be used
    for password storage. Included only for educational comparison
    and testing against legacy systems.
    """
    return hashlib.md5(password.encode()).hexdigest()


def sha1_hash(password: str) -> str:
    """
    Generate SHA-1 hash.
    
    ⚠️ SECURITY WARNING:
    SHA-1 is deprecated due to collision attacks.
    Included for historical and comparison purposes only.
    """
    return hashlib.sha1(password.encode()).hexdigest()


def ntlm_hash(password: str) -> str:
    """
    Generate NTLM hash (Windows password hashing).
    
    ⚠️ SECURITY WARNING:
    NTLM is an obsolete authentication protocol with known vulnerabilities.
    Included for penetration testing and legacy system analysis.
    """
    # NTLM = MD4(UTF-16LE(password))
    return hashlib.new('md4', password.encode('utf-16le')).hexdigest()


# =================================================
# SECURE HASHING (SHA-2 FAMILY)
# =================================================

def sha224_hash(password: str) -> str:
    """Generate SHA-224 hash."""
    return hashlib.sha224(password.encode()).hexdigest()


def sha256_hash(password: str) -> str:
    """
    Generate SHA-256 hash.
    
    NOTE: Secure for integrity checks, but NOT ideal alone for password storage
    without salting and key stretching. Use bcrypt for production.
    """
    return hashlib.sha256(password.encode()).hexdigest()


def sha384_hash(password: str) -> str:
    """Generate SHA-384 hash."""
    return hashlib.sha384(password.encode()).hexdigest()


def sha512_hash(password: str) -> str:
    """Generate SHA-512 hash."""
    return hashlib.sha512(password.encode()).hexdigest()


# =================================================
# SALTED HASHING
# =================================================

def salted_sha256(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Generate SHA-256 hash with a random salt.
    
    Args:
        password: Plain text password
        salt: Optional salt (generates new one if not provided)
    
    Returns:
        (salt, hashed_password) tuple
    """
    if salt is None:
        salt = generate_salt()
    
    salted_password = apply_salt(password, salt)
    
    # Ensure salted_password is bytes before hashing
    if isinstance(salted_password, str):
        salted_password = salted_password.encode()
    
    hashed = hashlib.sha256(salted_password).hexdigest()
    return salt, hashed


def verify_salted_sha256(password: str, salt: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored salted SHA-256 hash.
    """
    _, computed_hash = salted_sha256(password, salt)
    return computed_hash == stored_hash


def salted_sha512(password: str, salt: Optional[str] = None) -> Tuple[str, str]:
    """
    Generate SHA-512 hash with a random salt.
    """
    if salt is None:
        salt = generate_salt()
    
    salted_password = apply_salt(password, salt)
    
    if isinstance(salted_password, str):
        salted_password = salted_password.encode()
    
    hashed = hashlib.sha512(salted_password).hexdigest()
    return salt, hashed


def verify_salted_sha512(password: str, salt: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored salted SHA-512 hash.
    """
    _, computed_hash = salted_sha512(password, salt)
    return computed_hash == stored_hash


# =================================================
# BCRYPT (RECOMMENDED FOR PASSWORD STORAGE)
# =================================================

def bcrypt_hash(password: str, cost: int = 12) -> str:
    """
    Generate bcrypt hash.
    
    Bcrypt automatically applies salting and key stretching,
    making it resistant to brute-force attacks.
    
    Args:
        password: Plain text password
        cost: Cost factor (4-31). Higher = more secure but slower.
              Default 12 is recommended for most applications.
    
    ⚠️ NOTE FOR CRACKING:
    Bcrypt is intentionally SLOW. Brute-force attacks on bcrypt
    are computationally expensive by design.
    """
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=cost))
    return hashed.decode()


def bcrypt_verify(password: str, hashed: str) -> bool:
    """
    Verify a plaintext password against a bcrypt hash.
    """
    try:
        return bcrypt.checkpw(password.encode(), hashed.encode())
    except Exception:
        return False


# =================================================
# UNIFIED HASHING INTERFACE
# =================================================

HASH_FUNCTIONS = {
    "md5": md5_hash,
    "sha1": sha1_hash,
    "sha224": sha224_hash,
    "sha256": sha256_hash,
    "sha384": sha384_hash,
    "sha512": sha512_hash,
    "ntlm": ntlm_hash,
}


def hash_password(password: str, algorithm: str = "sha256") -> str:
    """
    Unified interface for hashing passwords with any supported algorithm.
    
    Args:
        password: Plain text password
        algorithm: Hash algorithm name (md5, sha1, sha256, sha512, ntlm, bcrypt)
    
    Returns:
        Hashed password as hexadecimal string
    
    Raises:
        ValueError: If algorithm is not supported
    """
    algorithm = algorithm.lower()
    
    if algorithm == "bcrypt":
        return bcrypt_hash(password)
    
    if algorithm not in HASH_FUNCTIONS:
        raise ValueError(f"Unsupported hash algorithm: {algorithm}")
    
    return HASH_FUNCTIONS[algorithm](password)


def verify_password(password: str, stored_hash: str, 
                   algorithm: Optional[str] = None, 
                   salt: Optional[str] = None) -> bool:
    """
    Unified interface for verifying passwords.
    
    Args:
        password: Plain text password to verify
        stored_hash: Hash to compare against
        algorithm: Hash algorithm (auto-detected if None)
        salt: Salt for salted hashes (optional)
    
    Returns:
        True if password matches, False otherwise
    """
    # Auto-detect algorithm if not provided
    if algorithm is None:
        algorithm = detect_hash_type(stored_hash)
        if algorithm is None:
            raise ValueError("Could not detect hash type")
    
    algorithm = algorithm.lower()
    
    # Handle bcrypt specially
    if algorithm == "bcrypt":
        return bcrypt_verify(password, stored_hash)
    
    # Handle salted hashes
    if salt:
        if algorithm == "sha256":
            return verify_salted_sha256(password, salt, stored_hash)
        elif algorithm == "sha512":
            return verify_salted_sha512(password, salt, stored_hash)
    
    # Generate hash and compare
    computed_hash = hash_password(password, algorithm)
    return computed_hash == stored_hash


def get_supported_algorithms() -> list:
    """Returns list of all supported hash algorithms."""
    return list(HASH_FUNCTIONS.keys()) + ["bcrypt"]


def get_algorithm_info(algorithm: str) -> Dict[str, any]:
    """
    Returns information about a specific hash algorithm.
    
    Returns dict with:
        - name: Algorithm name
        - hash_length: Expected hash length in characters
        - secure: Whether it's cryptographically secure
        - recommended: Whether it's recommended for new systems
    """
    info_map = {
        "md5": {
            "name": "MD5",
            "hash_length": 32,
            "secure": False,
            "recommended": False,
            "notes": "Cryptographically broken, use only for legacy systems"
        },
        "sha1": {
            "name": "SHA-1",
            "hash_length": 40,
            "secure": False,
            "recommended": False,
            "notes": "Deprecated due to collision attacks"
        },
        "sha224": {
            "name": "SHA-224",
            "hash_length": 56,
            "secure": True,
            "recommended": False,
            "notes": "Secure but uncommon, SHA-256 preferred"
        },
        "sha256": {
            "name": "SHA-256",
            "hash_length": 64,
            "secure": True,
            "recommended": True,
            "notes": "Secure with proper salting, but bcrypt preferred for passwords"
        },
        "sha384": {
            "name": "SHA-384",
            "hash_length": 96,
            "secure": True,
            "recommended": True,
            "notes": "Secure, part of SHA-2 family"
        },
        "sha512": {
            "name": "SHA-512",
            "hash_length": 128,
            "secure": True,
            "recommended": True,
            "notes": "Highly secure, part of SHA-2 family"
        },
        "ntlm": {
            "name": "NTLM",
            "hash_length": 32,
            "secure": False,
            "recommended": False,
            "notes": "Legacy Windows authentication, obsolete"
        },
        "bcrypt": {
            "name": "bcrypt",
            "hash_length": 60,
            "secure": True,
            "recommended": True,
            "notes": "Industry standard for password storage, includes salting and key stretching"
        }
    }
    
    return info_map.get(algorithm.lower(), {})


# =================================================
# TESTING & EXAMPLES
# =================================================

if __name__ == "__main__":
    test_password = "MySecureP@ss123"
    
    print("Hash Algorithm Comparison")
    print("=" * 70)
    print(f"Password: {test_password}\n")
    
    # Test all algorithms
    for algo in get_supported_algorithms():
        try:
            hashed = hash_password(test_password, algo)
            info = get_algorithm_info(algo)
            print(f"{info['name']:10} | {hashed}")
            print(f"           | Length: {len(hashed)}, Secure: {info['secure']}, "
                  f"Recommended: {info['recommended']}")
            print()
        except Exception as e:
            print(f"{algo}: Error - {e}\n")
    
    # Test hash detection
    print("\n" + "=" * 70)
    print("Hash Type Detection Examples:")
    print("=" * 70)
    
    test_hashes = {
        "5f4dcc3b5aa765d61d8327deb882cf99": "password (MD5)",
        "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8": "password (SHA-1)",
        "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8": "password (SHA-256)",
    }
    
    for hash_val, label in test_hashes.items():
        detected = detect_hash_type(hash_val)
        print(f"{label:30} -> Detected: {detected}")
    
    print("\n" + "=" * 70)
