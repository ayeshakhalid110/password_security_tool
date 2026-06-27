import itertools
import string
import time
import math
from typing import Optional, Callable, Set
from hashing import hash_password, verify_password, detect_hash_type

# =================================================
# CHARACTER SET PRESETS
# =================================================

CHARSET_PRESETS = {
    "digits": string.digits,  # 0-9 (10 chars)
    "lowercase": string.ascii_lowercase,  # a-z (26 chars)
    "uppercase": string.ascii_uppercase,  # A-Z (26 chars)
    "letters": string.ascii_letters,  # a-z, A-Z (52 chars)
    "alphanumeric": string.ascii_letters + string.digits,  # a-z, A-Z, 0-9 (62 chars)
    "alphanumeric_lower": string.ascii_lowercase + string.digits,  # a-z, 0-9 (36 chars)
    "symbols": "!@#$%^&*()-_=+[]{}|;:',.<>?/",  # Common symbols (29 chars)
    "all": string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:',.<>?/",  # All printable (91 chars)
}


def get_charset(preset: str = None, 
                use_lowercase: bool = False,
                use_uppercase: bool = False, 
                use_digits: bool = False,
                use_symbols: bool = False,
                custom_chars: str = "") -> str:
    """
    Build a character set for brute force attack.
    
    Args:
        preset: Preset name from CHARSET_PRESETS (overrides individual flags)
        use_lowercase: Include a-z
        use_uppercase: Include A-Z
        use_digits: Include 0-9
        use_symbols: Include special characters
        custom_chars: Additional custom characters
    
    Returns:
        Character set as string
    """
    if preset and preset in CHARSET_PRESETS:
        return CHARSET_PRESETS[preset] + custom_chars
    
    charset = ""
    if use_lowercase:
        charset += string.ascii_lowercase
    if use_uppercase:
        charset += string.ascii_uppercase
    if use_digits:
        charset += string.digits
    if use_symbols:
        charset += "!@#$%^&*()-_=+[]{}|;:',.<>?/"
    
    charset += custom_chars
    
    # Remove duplicates while preserving order
    seen: Set[str] = set()
    unique_charset = ""
    for char in charset:
        if char not in seen:
            seen.add(char)
            unique_charset += char
    
    return unique_charset


def estimate_search_space(charset_size: int, min_length: int, max_length: int) -> dict:
    """
    Calculate the total number of combinations to try.
    
    Formula: Σ(n^i) for i from min_length to max_length
    Where n = charset size
    
    Returns:
        Dictionary with search space info:
        - total_combinations: Total passwords to try
        - readable: Human-readable format (e.g., "2.8 trillion")
        - estimated_time: Dict with time estimates at various speeds
    """
    total = sum(charset_size ** length for length in range(min_length, max_length + 1))
    
    # Human-readable format
    if total >= 1e15:
        readable = f"{total/1e15:.2f} quadrillion"
    elif total >= 1e12:
        readable = f"{total/1e12:.2f} trillion"
    elif total >= 1e9:
        readable = f"{total/1e9:.2f} billion"
    elif total >= 1e6:
        readable = f"{total/1e6:.2f} million"
    elif total >= 1e3:
        readable = f"{total/1e3:.2f} thousand"
    else:
        readable = str(total)
    
    # Estimate time at various speeds (average case: find in half the time)
    avg_attempts = total / 2
    
    speeds = {
        "1K/s": avg_attempts / 1_000,
        "1M/s": avg_attempts / 1_000_000,
        "1B/s": avg_attempts / 1_000_000_000,
    }
    
    time_estimates = {}
    for speed_name, seconds in speeds.items():
        if seconds < 60:
            time_estimates[speed_name] = f"{seconds:.2f} seconds"
        elif seconds < 3600:
            time_estimates[speed_name] = f"{seconds/60:.2f} minutes"
        elif seconds < 86400:
            time_estimates[speed_name] = f"{seconds/3600:.2f} hours"
        elif seconds < 31536000:
            time_estimates[speed_name] = f"{seconds/86400:.2f} days"
        else:
            time_estimates[speed_name] = f"{seconds/31536000:.2f} years"
    
    return {
        "total_combinations": total,
        "readable": readable,
        "estimated_time": time_estimates
    }


# =================================================
# BRUTE FORCE ATTACK CLASS
# =================================================

class BruteForceAttack:
    """
    Advanced brute force password cracking engine.
    
    Features:
    - Multi-algorithm support
    - Configurable character sets
    - Progress reporting
    - Early termination
    - Performance metrics
    - Salt support
    """
    
    def __init__(self):
        self.stopped = False
        self.attempts = 0
        self.start_time = 0
    
    def stop(self):
        """Stop the attack."""
        self.stopped = True
    
    def reset(self):
        """Reset attack state."""
        self.stopped = False
        self.attempts = 0
        self.start_time = 0
    
    def attack(self,
               target_hash: str = None,
               min_length: int = 1,
               max_length: int = 4,
               charset: str = None,
               algorithm: Optional[str] = None,
               salt: Optional[str] = None,
               progress_callback: Optional[Callable] = None,
               # Charset building options (if charset not provided)
               charset_preset: str = "alphanumeric_lower",
               use_lowercase: bool = False,
               use_uppercase: bool = False,
               use_digits: bool = False,
               use_symbols: bool = False,
               # Educational mode: provide password to auto-generate hash
               plaintext_password: Optional[str] = None) -> dict:
        """
        Perform brute force attack on a password hash.
        
        Args:
            target_hash: Hash to crack (can be empty if plaintext_password is provided)
            min_length: Minimum password length to try (default: 1)
            max_length: Maximum password length to try (default: 4)
            charset: Character set to use (if None, built from other params)
            algorithm: Hash algorithm (auto-detected if None, required if plaintext_password)
            salt: Salt for salted hashes
            progress_callback: Function called with progress updates
                              Signature: callback(attempts, total, current, length, hash_rate)
            charset_preset: Preset charset name (default: "alphanumeric_lower")
            use_lowercase/uppercase/digits/symbols: Build custom charset
            plaintext_password: (EDUCATIONAL MODE) Provide password to auto-generate hash
        
        Returns:
            Result dictionary
        
        EDUCATIONAL MODE:
            If plaintext_password is provided, the function will:
            1. Hash it with the specified algorithm
            2. Display the generated hash
            3. Perform the attack on that hash
            This is useful for demonstrations and testing.
        
        WARNING:
            Brute force attacks have exponential time complexity.
            A 6-character password with 62-char charset has 56 billion combinations!
        """
        self.reset()
        self.start_time = time.time()
        
        # EDUCATIONAL MODE: Generate hash from plaintext password
        if plaintext_password is not None:
            if algorithm is None:
                return {
                    "success": False,
                    "error": "Algorithm must be specified when using plaintext_password mode"
                }
            
            # Generate hash from plaintext
            if salt:
                from salting import salted_sha256, salted_sha512
                if algorithm.lower() == "sha256":
                    salt_hex, generated_hash = salted_sha256(plaintext_password, salt)
                elif algorithm.lower() == "sha512":
                    salt_hex, generated_hash = salted_sha512(plaintext_password, salt)
                else:
                    # For other algorithms, hash with salt manually
                    generated_hash = hash_password(plaintext_password, algorithm)
            else:
                generated_hash = hash_password(plaintext_password, algorithm)
            
            target_hash = generated_hash
            
            # Return the generated hash info for display
            educational_mode = True
            educational_hash = generated_hash
        else:
            educational_mode = False
            educational_hash = None
        
        # Auto-detect algorithm
        if algorithm is None:
            algorithm = detect_hash_type(target_hash)
            if algorithm is None:
                return {
                    "success": False,
                    "error": "Could not detect hash type"
                }
        
        # Build charset
        if charset is None:
            charset = get_charset(
                preset=charset_preset,
                use_lowercase=use_lowercase,
                use_uppercase=use_uppercase,
                use_digits=use_digits,
                use_symbols=use_symbols
            )
        
        if not charset:
            return {
                "success": False,
                "error": "Character set is empty"
            }
        
        # Calculate search space
        search_space = estimate_search_space(len(charset), min_length, max_length)
        
        # Start attack
        for length in range(min_length, max_length + 1):
            if self.stopped:
                elapsed = time.time() - self.start_time
                return {
                    "success": False,
                    "error": "Attack stopped by user",
                    "attempts": self.attempts,
                    "time_seconds": round(elapsed, 2),
                    "hash_rate": round(self.attempts / elapsed if elapsed > 0 else 0, 2)
                }
            
            # Try all combinations of this length
            for combo in itertools.product(charset, repeat=length):
                if self.stopped:
                    break
                
                self.attempts += 1
                guess = ''.join(combo)
                
                # Check if this matches
                result = self._try_password(guess, target_hash, algorithm, salt)
                if result:
                    result["charset_size"] = len(charset)
                    result["charset"] = charset[:20] + "..." if len(charset) > 20 else charset
                    result["search_space"] = search_space
                    if educational_mode:
                        result["educational_mode"] = True
                        result["original_password"] = plaintext_password
                        result["generated_hash"] = educational_hash
                    return result
                
                # Progress callback (every 1000 attempts to reduce overhead)
                if progress_callback and self.attempts % 1000 == 0:
                    elapsed = time.time() - self.start_time
                    hash_rate = self.attempts / elapsed if elapsed > 0 else 0
                    progress_callback(
                        self.attempts, 
                        search_space["total_combinations"],
                        guess,
                        length,
                        hash_rate
                    )
        
        # Attack completed without finding password
        elapsed = time.time() - self.start_time
        hash_rate = self.attempts / elapsed if elapsed > 0 else 0
        
        return {
            "success": False,
            "attack_type": "Brute Force Attack",
            "hash_algorithm": algorithm,
            "attempts": self.attempts,
            "time_seconds": round(elapsed, 2),
            "hash_rate": round(hash_rate, 2),
            "max_length": max_length,
            "charset_size": len(charset),
            "search_space": search_space,
            "message": f"Password not found in search space (tried all combinations up to length {max_length})"
        }
    
    def _try_password(self, password: str, target_hash: str,
                     algorithm: str, salt: Optional[str]) -> Optional[dict]:
        """Try a single password candidate."""
        try:
            if salt:
                is_match = verify_password(password, target_hash, algorithm, salt)
            else:
                computed_hash = hash_password(password, algorithm)
                is_match = computed_hash == target_hash
            
            if is_match:
                elapsed = time.time() - self.start_time
                hash_rate = self.attempts / elapsed if elapsed > 0 else 0
                
                return {
                    "success": True,
                    "attack_type": "Brute Force Attack",
                    "hash_algorithm": algorithm,
                    "password": password,
                    "password_length": len(password),
                    "attempts": self.attempts,
                    "time_seconds": round(elapsed, 2),
                    "hash_rate": round(hash_rate, 2)
                }
        except Exception:
            pass
        
        return None


# =================================================
# STANDALONE FUNCTION
# =================================================

def brute_force_attack(target_hash: str = None,
                      min_length: int = 1,
                      max_length: int = 4,
                      charset_preset: str = "alphanumeric_lower",
                      algorithm: Optional[str] = None,
                      salt: Optional[str] = None,
                      progress_callback: Optional[Callable] = None,
                      plaintext_password: Optional[str] = None) -> dict:
    """
    Simplified brute force attack function.
    
    Args:
        target_hash: Hash to crack (can be None if using plaintext_password)
        min_length: Minimum password length
        max_length: Maximum password length (be careful with large values!)
        charset_preset: Character set preset name
        algorithm: Hash algorithm (required if using plaintext_password, auto-detected otherwise)
        salt: Salt for salted hashes
        progress_callback: Progress update function
        plaintext_password: (EDUCATIONAL MODE) Password to hash and crack
    
    Returns:
        Result dictionary
    
    Example 1 (Normal mode):
        result = brute_force_attack(
            target_hash="900150983cd24fb0d6963f7d28e17f72",  # MD5 of "abc"
            max_length=3,
            charset_preset="lowercase",
            algorithm="md5"
        )
    
    Example 2 (Educational mode):
        result = brute_force_attack(
            plaintext_password="abc",
            max_length=3,
            charset_preset="lowercase",
            algorithm="md5"
        )
    """
    attacker = BruteForceAttack()
    return attacker.attack(
        target_hash=target_hash,
        min_length=min_length,
        max_length=max_length,
        charset_preset=charset_preset,
        algorithm=algorithm,
        salt=salt,
        progress_callback=progress_callback,
        plaintext_password=plaintext_password
    )


# =================================================
# UTILITY FUNCTIONS
# =================================================

def calculate_max_feasible_length(charset_size: int, 
                                  max_time_seconds: float = 3600,
                                  hash_rate: float = 1_000_000) -> int:
    """
    Calculate maximum password length that can be cracked within time limit.
    
    Args:
        charset_size: Size of character set
        max_time_seconds: Maximum time willing to wait (default: 1 hour)
        hash_rate: Expected hashes per second (default: 1M/s)
    
    Returns:
        Maximum feasible password length
    """
    max_attempts = max_time_seconds * hash_rate
    
    length = 1
    total = 0
    while True:
        total += charset_size ** length
        if total > max_attempts:
            return length - 1
        length += 1


# =================================================
# TESTING & EXAMPLES
# =================================================

if __name__ == "__main__":
    print("Brute Force Attack Testing")
    print("=" * 70)
    
    # Test 1: Show search space calculations
    print("\nTest 1: Search Space Estimates")
    print("-" * 70)
    
    test_cases = [
        (10, 1, 3, "digits only, length 1-3"),
        (26, 1, 4, "lowercase only, length 1-4"),
        (36, 1, 4, "alphanumeric (lowercase), length 1-4"),
        (62, 1, 6, "alphanumeric (mixed case), length 1-6"),
    ]
    
    for charset_size, min_len, max_len, description in test_cases:
        space = estimate_search_space(charset_size, min_len, max_len)
        print(f"\n{description}:")
        print(f"  Charset size: {charset_size}")
        print(f"  Combinations: {space['readable']}")
        print(f"  Time estimates:")
        for speed, time_str in space['estimated_time'].items():
            print(f"    At {speed}: {time_str}")
    
    # Test 2: Crack a simple password (Educational Mode)
    print("\n" + "=" * 70)
    print("\nTest 2: Educational Mode - Cracking password '123'")
    print("-" * 70)
    
    result = brute_force_attack(
        plaintext_password="123",  # Provide password, tool will hash it
        max_length=3,
        charset_preset="digits",
        algorithm="md5"
    )
    
    if result["success"]:
        print(f"✓ Cracked successfully!")
        print(f"  Original password: {result['original_password']}")
        print(f"  Generated hash: {result['generated_hash']}")
        print(f"  Cracked password: {result['password']}")
        print(f"  Match: {result['password'] == result['original_password']}")
        print(f"  Attempts: {result['attempts']:,}")
        print(f"  Time: {result['time_seconds']}s")
        print(f"  Hash rate: {result['hash_rate']:,.0f} h/s")
    else:
        print(f"✗ Failed to crack")
        print(f"  Reason: {result.get('message', 'Unknown')}")
    
    # Test 3: Traditional mode (crack existing hash)
    print("\n" + "=" * 70)
    print("\nTest 3: Traditional Mode - Cracking MD5 hash")
    print("-" * 70)
    
    test_hash = "202cb962ac59075b964b07152d234b70"  # MD5 of "123"
    
    result = brute_force_attack(
        target_hash=test_hash,
        max_length=3,
        charset_preset="digits",
        algorithm="md5"
    )
    
    if result["success"]:
        print(f"✓ Cracked successfully!")
        print(f"  Password: {result['password']}")
        print(f"  Attempts: {result['attempts']:,}")
        print(f"  Time: {result['time_seconds']}s")
        print(f"  Hash rate: {result['hash_rate']:,.0f} h/s")
    else:
        print(f"✗ Failed to crack")
        print(f"  Reason: {result.get('message', 'Unknown')}")
    
    # Test 4: Calculate feasible lengths
    print("\n" + "=" * 70)
    print("\nTest 4: Maximum Feasible Lengths (1 hour time limit)")
    print("-" * 70)
    
    for charset_name, charset in [("digits", 10), ("lowercase", 26), 
                                   ("alphanumeric", 62), ("all", 91)]:
        max_len = calculate_max_feasible_length(charset, 3600, 1_000_000)
        print(f"  {charset_name:15} (size {charset:2}): up to {max_len} characters")
    
    print("\n" + "=" * 70)
