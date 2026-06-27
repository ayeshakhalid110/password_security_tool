import time
from typing import Optional, Callable, List
from hashing import hash_password, verify_password, detect_hash_type

class DictionaryAttack:
    """
    Advanced dictionary-based password cracking engine.
    
    Features:
    - Multi-algorithm support (MD5, SHA-1, SHA-256, SHA-512, NTLM, bcrypt)
    - Salt support for salted hashes
    - Progress callbacks for GUI integration
    - Case transformations and variations
    - Performance statistics and hash rate calculation
    - Early termination support
    """
    
    def __init__(self):
        self.stopped = False
        self.attempts = 0
        self.start_time = 0
        
    def stop(self):
        """Stop the attack (for GUI cancel button)."""
        self.stopped = True
    
    def reset(self):
        """Reset attack state for new attack."""
        self.stopped = False
        self.attempts = 0
        self.start_time = 0
    
    def attack(self, 
               target_hash: str = None,
               wordlist_path: str = "wordlist.txt",
               algorithm: Optional[str] = None,
               salt: Optional[str] = None,
               case_variations: bool = True,
               progress_callback: Optional[Callable] = None,
               wordlist: Optional[List[str]] = None,
               plaintext_password: Optional[str] = None) -> Optional[dict]:
        """
        Perform dictionary attack on a password hash.
        
        Args:
            target_hash: The hash to crack (can be None if plaintext_password provided)
            wordlist_path: Path to wordlist file (default: wordlist.txt)
            algorithm: Hash algorithm (auto-detected if None, required if plaintext_password)
            salt: Salt for salted hashes (optional)
            case_variations: Try uppercase/lowercase variations
            progress_callback: Function to call with progress updates
                              Signature: callback(attempts, total, current_word, hash_rate)
            wordlist: Pre-loaded wordlist (optional, overrides wordlist_path)
            plaintext_password: (EDUCATIONAL MODE) Provide password to hash and crack
        
        Returns:
            Dictionary with crack results, or None if unsuccessful
        """
        self.reset()
        self.start_time = time.time()
        
        # EDUCATIONAL MODE: Generate hash from plaintext
        educational_mode = False
        educational_hash = None
        
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
                    salt_hex, educational_hash = salted_sha256(plaintext_password, salt)
                elif algorithm.lower() == "sha512":
                    salt_hex, educational_hash = salted_sha512(plaintext_password, salt)
                else:
                    educational_hash = hash_password(plaintext_password, algorithm)
            else:
                educational_hash = hash_password(plaintext_password, algorithm)
            
            target_hash = educational_hash
            educational_mode = True
        
        # Auto-detect algorithm if not provided
        if algorithm is None:
            algorithm = detect_hash_type(target_hash)
            if algorithm is None:
                return {
                    "success": False,
                    "error": "Could not detect hash type",
                    "target_hash": target_hash
                }
        
        # Load wordlist
        if wordlist is None:
            try:
                with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                    wordlist = [line.strip() for line in f if line.strip()]
            except FileNotFoundError:
                return {
                    "success": False,
                    "error": f"Wordlist not found: {wordlist_path}"
                }
        
        # Remove duplicates and empty entries
        wordlist = list(dict.fromkeys(wordlist))  # Preserves order, removes duplicates
        total_words = len(wordlist)
        
        if total_words == 0:
            return {
                "success": False,
                "error": "Wordlist is empty"
            }
        
        # Perform attack
        for idx, word in enumerate(wordlist):
            if self.stopped:
                return {
                    "success": False,
                    "error": "Attack stopped by user",
                    "attempts": self.attempts,
                    "time_seconds": round(time.time() - self.start_time, 2)
                }
            
            # Try original word
            result = self._try_password(word, target_hash, algorithm, salt, "original")
            if result:
                if educational_mode:
                    result["educational_mode"] = True
                    result["original_password"] = plaintext_password
                    result["generated_hash"] = educational_hash
                return result
            
            # Try case variations if enabled
            if case_variations and word.isalpha():
                # Uppercase
                result = self._try_password(word.upper(), target_hash, algorithm, salt, "uppercase")
                if result:
                    return result
                
                # Lowercase
                result = self._try_password(word.lower(), target_hash, algorithm, salt, "lowercase")
                if result:
                    return result
                
                # Capitalize (first letter uppercase)
                result = self._try_password(word.capitalize(), target_hash, algorithm, salt, "capitalize")
                if result:
                    return result
            
            # Progress callback (every 100 words to reduce overhead)
            if progress_callback and idx % 100 == 0:
                elapsed = time.time() - self.start_time
                hash_rate = self.attempts / elapsed if elapsed > 0 else 0
                progress_callback(self.attempts, total_words, word, hash_rate)
        
        # Attack failed
        elapsed = time.time() - self.start_time
        hash_rate = self.attempts / elapsed if elapsed > 0 else 0
        
        return {
            "success": False,
            "attack_type": "Dictionary Attack",
            "hash_algorithm": algorithm,
            "attempts": self.attempts,
            "time_seconds": round(elapsed, 2),
            "hash_rate": round(hash_rate, 2),
            "message": f"Password not found in wordlist ({total_words} words tested)"
        }
    
    def _try_password(self, password: str, target_hash: str, 
                     algorithm: str, salt: Optional[str], 
                     variation: str) -> Optional[dict]:
        """
        Try a single password candidate.
        
        Returns:
            Result dict if successful, None otherwise
        """
        self.attempts += 1
        
        try:
            # Generate hash for this password
            if salt:
                # For salted hashes, we need special handling
                is_match = verify_password(password, target_hash, algorithm, salt)
            else:
                # For unsalted hashes, compare directly
                computed_hash = hash_password(password, algorithm)
                is_match = computed_hash == target_hash
            
            if is_match:
                elapsed = time.time() - self.start_time
                hash_rate = self.attempts / elapsed if elapsed > 0 else 0
                
                return {
                    "success": True,
                    "attack_type": "Dictionary Attack",
                    "hash_algorithm": algorithm,
                    "password": password,
                    "attempts": self.attempts,
                    "time_seconds": round(elapsed, 2),
                    "hash_rate": round(hash_rate, 2),
                    "variation_used": variation
                }
        except Exception as e:
            # Continue on error (e.g., bcrypt format issues)
            pass
        
        return None


# =================================================
# STANDALONE FUNCTION (For backward compatibility)
# =================================================

def dictionary_attack(target_hash: str = None, 
                     wordlist_path: str = "wordlist.txt",
                     algorithm: Optional[str] = None,
                     salt: Optional[str] = None,
                     case_variations: bool = True,
                     progress_callback: Optional[Callable] = None,
                     plaintext_password: Optional[str] = None) -> Optional[dict]:
    """
    Simplified dictionary attack function.
    
    This is a convenience wrapper around the DictionaryAttack class.
    For more control (like stopping attacks), use the class directly.
    
    Args:
        target_hash: Hash to crack (can be None if plaintext_password provided)
        wordlist_path: Path to wordlist file
        algorithm: Hash algorithm (auto-detected if None, required if plaintext_password)
        salt: Salt for salted hashes
        case_variations: Try case transformations
        progress_callback: Progress update function
        plaintext_password: (EDUCATIONAL MODE) Password to hash and crack
    
    Returns:
        Result dictionary or None
    
    Example:
        result = dictionary_attack(
            "5f4dcc3b5aa765d61d8327deb882cf99",  # MD5 of "password"
            algorithm="md5"
        )
        if result and result["success"]:
            print(f"Cracked: {result['password']}")
    """
    attacker = DictionaryAttack()
    return attacker.attack(
        target_hash=target_hash,
        wordlist_path=wordlist_path,
        algorithm=algorithm,
        salt=salt,
        case_variations=case_variations,
        progress_callback=progress_callback,
        plaintext_password=plaintext_password
    )


# =================================================
# ADVANCED DICTIONARY VARIATIONS
# =================================================

def generate_word_variations(word: str, max_variations: int = 10) -> List[str]:
    """
    Generate common password variations of a dictionary word.
    
    Examples:
        "password" -> ["password", "Password", "PASSWORD", "p@ssword", 
                      "password1", "password!", "Password123", etc.]
    
    Args:
        word: Base word
        max_variations: Maximum number of variations to generate
    
    Returns:
        List of password variations
    """
    variations = [word]
    
    # Case variations
    if word.isalpha():
        variations.append(word.upper())
        variations.append(word.lower())
        variations.append(word.capitalize())
    
    # Common substitutions (leet speak)
    substitutions = {
        'a': '@', 'e': '3', 'i': '1', 'o': '0', 's': '$', 't': '7'
    }
    
    leet_word = word
    for char, replacement in substitutions.items():
        leet_word = leet_word.replace(char, replacement)
    if leet_word != word:
        variations.append(leet_word)
        variations.append(leet_word.capitalize())
    
    # Number suffixes
    for num in ['1', '123', '12', '2024', '!']:
        variations.append(word + num)
        variations.append(word.capitalize() + num)
    
    # Number prefixes
    for num in ['1', '123']:
        variations.append(num + word)
    
    # Exclamation and special chars
    variations.append(word + '!')
    variations.append(word + '@')
    variations.append(word.capitalize() + '!')
    
    # Remove duplicates and limit
    variations = list(dict.fromkeys(variations))
    return variations[:max_variations]


# =================================================
# TESTING & EXAMPLES
# =================================================

if __name__ == "__main__":
    print("Dictionary Attack Testing")
    print("=" * 70)
    
    # Test 1: Simple MD5 crack
    print("\nTest 1: Cracking MD5 hash of 'password'")
    test_hash = "5f4dcc3b5aa765d61d8327deb882cf99"  # MD5 of "password"
    
    # Create a small test wordlist
    test_wordlist = ["admin", "123456", "password", "qwerty", "letmein"]
    
    result = dictionary_attack(
        target_hash=test_hash,
        algorithm="md5",
        wordlist_path="wordlist.txt"  # Will use your actual wordlist if it exists
    )
    
    if result and result.get("success"):
        print(f"✓ Cracked successfully!")
        print(f"  Password: {result['password']}")
        print(f"  Attempts: {result['attempts']}")
        print(f"  Time: {result['time_seconds']}s")
        print(f"  Hash rate: {result['hash_rate']:.2f} h/s")
    else:
        print(f"✗ Failed to crack")
        if result:
            print(f"  Reason: {result.get('error', result.get('message', 'Unknown'))}")
    
    # Test 2: Word variations
    print("\n" + "=" * 70)
    print("\nTest 2: Word Variations for 'password'")
    variations = generate_word_variations("password", max_variations=15)
    for i, var in enumerate(variations, 1):
        print(f"  {i:2}. {var}")
    
    print("\n" + "=" * 70)
