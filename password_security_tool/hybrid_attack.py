import time
from typing import Optional, Callable, List
from hashing import hash_password, verify_password, detect_hash_type

# =================================================
# TRANSFORMATION RULES
# =================================================

def generate_hybrid_candidates(word: str, 
                               enable_numbers: bool = True,
                               enable_symbols: bool = True,
                               enable_leet: bool = True,
                               enable_case: bool = True,
                               max_number: int = 999) -> List[str]:
    """
    Generate hybrid password candidates from a dictionary word.
    
    Transformation categories:
    1. Case variations (Password, PASSWORD, pAsSwOrD)
    2. Number suffixes/prefixes (password123, 2024password)
    3. Symbol suffixes (password!, password@, password#)
    4. Leet speak (p@ssword, pa$$word)
    5. Combinations (Password123!, P@ssw0rd)
    
    Args:
        word: Base dictionary word
        enable_numbers: Add number transformations
        enable_symbols: Add symbol transformations
        enable_leet: Apply leet speak substitutions
        enable_case: Add case variations
        max_number: Maximum number to append/prepend
    
    Returns:
        List of password candidates
    """
    candidates = [word]  # Original word
    
    # ---------- CASE VARIATIONS ----------
    if enable_case and word.isalpha():
        candidates.append(word.capitalize())  # Password
        candidates.append(word.upper())       # PASSWORD
        candidates.append(word.lower())       # password
        
        # Alternating case (not very common, but included)
        if len(word) > 1:
            candidates.append(word[0].upper() + word[1:].lower())  # Password
    
    # ---------- LEET SPEAK ----------
    leet_variations = []
    if enable_leet:
        leet_map = {
            'a': '@', 'A': '@',
            'e': '3', 'E': '3',
            'i': '1', 'I': '1',
            'o': '0', 'O': '0',
            's': '$', 'S': '$',
            't': '7', 'T': '7',
            'l': '1', 'L': '1',
            'g': '9', 'G': '9'
        }
        
        # Apply common leet substitutions
        leet_word = word
        for char, replacement in leet_map.items():
            leet_word = leet_word.replace(char, replacement)
        
        if leet_word != word:
            leet_variations.append(leet_word)
            leet_variations.append(leet_word.capitalize())
    
    candidates.extend(leet_variations)
    
    # ---------- NUMBER TRANSFORMATIONS ----------
    if enable_numbers:
        # Common numbers
        common_numbers = ['1', '12', '123', '1234', '00', '01', '2024', '2025', '69', '420']
        
        # Limited range for slider numbers
        if max_number <= 20:
            range_numbers = [str(i) for i in range(max_number + 1)]
        else:
            # Sample numbers for larger ranges to avoid explosion
            range_numbers = [str(i) for i in range(10)]  # 0-9
            range_numbers.extend([str(i) for i in range(10, min(100, max_number + 1), 10)])  # 10, 20, 30...
        
        all_numbers = list(set(common_numbers + range_numbers))
        
        base_words = [word, word.capitalize()] + leet_variations
        
        for base in base_words:
            for num in all_numbers:
                candidates.append(f"{base}{num}")      # password123
                candidates.append(f"{num}{base}")      # 123password
    
    # ---------- SYMBOL TRANSFORMATIONS ----------
    if enable_symbols:
        symbols = ['!', '@', '#', '$', '*', '_', '.', '?']
        
        base_words = [word, word.capitalize()] + leet_variations
        
        for base in base_words:
            for sym in symbols:
                candidates.append(f"{base}{sym}")      # password!
                candidates.append(f"{sym}{base}")      # !password
    
    # ---------- COMBINATION TRANSFORMATIONS ----------
    # Most common: Capitalize + numbers + symbol
    if enable_case and enable_numbers and enable_symbols:
        combo_words = [word.capitalize()]
        if leet_variations:
            combo_words.append(leet_variations[0].capitalize())
        
        for base in combo_words:
            # Common patterns
            candidates.append(f"{base}123")       # Password123
            candidates.append(f"{base}123!")      # Password123!
            candidates.append(f"{base}1")         # Password1
            candidates.append(f"{base}1!")        # Password1!
            candidates.append(f"{base}2024")      # Password2024
            candidates.append(f"{base}@123")      # Password@123
    
    # Remove duplicates while preserving order
    seen = set()
    unique_candidates = []
    for candidate in candidates:
        if candidate not in seen:
            seen.add(candidate)
            unique_candidates.append(candidate)
    
    return unique_candidates


# =================================================
# HYBRID ATTACK CLASS
# =================================================

class HybridAttack:
    """
    Advanced hybrid password cracking engine.
    
    Combines dictionary attacks with transformation rules:
    - Case variations
    - Number suffixes/prefixes
    - Symbol additions
    - Leet speak substitutions
    - Combination patterns
    
    This is more efficient than pure brute force for passwords
    based on common words with simple modifications.
    """
    
    def __init__(self, wordlist_path: str = "wordlist.txt"):
        self.wordlist_path = wordlist_path
        self.attempts = 0
        self.start_time = 0
        self.stopped = False
    
    def stop(self):
        """Stop the attack."""
        self.stopped = True
    
    def reset(self):
        """Reset attack state."""
        self.stopped = False
        self.attempts = 0
        self.start_time = 0
    
    def load_wordlist(self) -> List[str]:
        """Load and deduplicate wordlist."""
        try:
            with open(self.wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
                wordlist = [line.strip().lower() for line in f if line.strip()]
                # Remove duplicates
                return list(dict.fromkeys(wordlist))
        except FileNotFoundError:
            return []
    
    def attack(
        self,
        target_hash: str = None,
        algorithm: Optional[str] = None,
        salt: Optional[str] = None,
        max_number: int = 999,
        enable_numbers: bool = True,
        enable_symbols: bool = True,
        enable_leet: bool = True,
        enable_case: bool = True,
        progress_callback: Optional[Callable] = None,
        plaintext_password: Optional[str] = None
    ) -> dict:
        """
        Perform hybrid attack on a password hash.
        
        Args:
            target_hash: Hash to crack (can be None if using plaintext_password)
            algorithm: Hash algorithm (auto-detected if None)
            salt: Salt for salted hashes
            max_number: Maximum number for transformations
            enable_numbers: Apply number transformations
            enable_symbols: Apply symbol transformations
            enable_leet: Apply leet speak
            enable_case: Apply case variations
            progress_callback: Progress update function
                              Signature: callback(attempts, total_words, current_word, candidates_tested, hash_rate)
            plaintext_password: (EDUCATIONAL MODE) Password to hash and crack
        
        Returns:
            Result dictionary with crack details
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
                    "error": "Algorithm must be specified in educational mode"
                }
            
            if salt:
                from salting import salted_sha256, salted_sha512
                if algorithm.lower() == "sha256":
                    _, educational_hash = salted_sha256(plaintext_password, salt)
                elif algorithm.lower() == "sha512":
                    _, educational_hash = salted_sha512(plaintext_password, salt)
                else:
                    educational_hash = hash_password(plaintext_password, algorithm)
            else:
                educational_hash = hash_password(plaintext_password, algorithm)
            
            target_hash = educational_hash
            educational_mode = True
        
        # Auto-detect algorithm
        if algorithm is None:
            algorithm = detect_hash_type(target_hash)
            if algorithm is None:
                return {
                    "success": False,
                    "error": "Could not detect hash type"
                }
        
        # Load wordlist
        wordlist = self.load_wordlist()
        if not wordlist:
            return {
                "success": False,
                "error": f"Wordlist not found: {self.wordlist_path}"
            }
        
        total_words = len(wordlist)
        
        # Perform attack
        for word_idx, word in enumerate(wordlist):
            if self.stopped:
                elapsed = time.time() - self.start_time
                return {
                    "success": False,
                    "error": "Attack stopped by user",
                    "attempts": self.attempts,
                    "time_seconds": round(elapsed, 2)
                }
            
            # Generate all candidates for this word
            candidates = generate_hybrid_candidates(
                word,
                enable_numbers=enable_numbers,
                enable_symbols=enable_symbols,
                enable_leet=enable_leet,
                enable_case=enable_case,
                max_number=max_number
            )
            
            # Test each candidate
            for candidate in candidates:
                self.attempts += 1
                
                try:
                    if salt:
                        is_match = verify_password(candidate, target_hash, algorithm, salt)
                    else:
                        computed_hash = hash_password(candidate, algorithm)
                        is_match = computed_hash == target_hash
                    
                    if is_match:
                        elapsed = time.time() - self.start_time
                        hash_rate = self.attempts / elapsed if elapsed > 0 else 0
                        
                        result = {
                            "success": True,
                            "attack_type": "Hybrid Attack",
                            "hash_algorithm": algorithm,
                            "password": candidate,
                            "base_word": word,
                            "transformation": self._identify_transformation(word, candidate),
                            "attempts": self.attempts,
                            "time_seconds": round(elapsed, 2),
                            "hash_rate": round(hash_rate, 2)
                        }
                        
                        if educational_mode:
                            result["educational_mode"] = True
                            result["original_password"] = plaintext_password
                            result["generated_hash"] = educational_hash
                        
                        return result
                
                except Exception:
                    pass
                
                # Progress callback (every 500 attempts)
                if progress_callback and self.attempts % 500 == 0:
                    elapsed = time.time() - self.start_time
                    hash_rate = self.attempts / elapsed if elapsed > 0 else 0
                    progress_callback(self.attempts, total_words, word, len(candidates), hash_rate)
        
        # Attack failed
        elapsed = time.time() - self.start_time
        hash_rate = self.attempts / elapsed if elapsed > 0 else 0
        
        return {
            "success": False,
            "attack_type": "Hybrid Attack",
            "hash_algorithm": algorithm,
            "attempts": self.attempts,
            "time_seconds": round(elapsed, 2),
            "hash_rate": round(hash_rate, 2),
            "words_tested": total_words,
            "message": f"Password not found using hybrid transformations on {total_words} words"
        }
    
    def _identify_transformation(self, base: str, result: str) -> str:
        """Identify what transformation was applied."""
        if result == base:
            return "none (original word)"
        elif result == base.capitalize():
            return "capitalized"
        elif result == base.upper():
            return "uppercase"
        elif result.endswith('!'):
            return "exclamation suffix"
        elif result.endswith('@'):
            return "@ suffix"
        elif result[-1].isdigit():
            return "number suffix"
        elif result[0].isdigit():
            return "number prefix"
        elif '@' in result or '3' in result or '$' in result:
            return "leet speak"
        else:
            return "complex transformation"


# =================================================
# STANDALONE FUNCTION
# =================================================

def hybrid_attack(
    target_hash: str = None,
    algorithm: Optional[str] = None,
    salt: Optional[str] = None,
    wordlist_path: str = "wordlist.txt",
    max_number: int = 999,
    enable_numbers: bool = True,
    enable_symbols: bool = True,
    enable_leet: bool = True,
    enable_case: bool = True,
    progress_callback: Optional[Callable] = None,
    plaintext_password: Optional[str] = None
) -> dict:
    """
    Simplified hybrid attack function.
    
    Args:
        target_hash: Hash to crack (or None if using plaintext_password)
        algorithm: Hash algorithm
        salt: Salt for salted hashes
        wordlist_path: Path to wordlist
        max_number: Maximum number for transformations
        enable_numbers/symbols/leet/case: Transformation toggles
        progress_callback: Progress update function
        plaintext_password: (EDUCATIONAL MODE) Password to hash and crack
    
    Returns:
        Result dictionary
    
    Example (Educational Mode):
        result = hybrid_attack(
            plaintext_password="password",
            algorithm="md5",
            max_number=100
        )
        # Will hash "password" and try: password, Password, password123,
        # password!, p@ssword, etc.
    """
    attacker = HybridAttack(wordlist_path)
    return attacker.attack(
        target_hash=target_hash,
        algorithm=algorithm,
        salt=salt,
        max_number=max_number,
        enable_numbers=enable_numbers,
        enable_symbols=enable_symbols,
        enable_leet=enable_leet,
        enable_case=enable_case,
        progress_callback=progress_callback,
        plaintext_password=plaintext_password
    )


# =================================================
# TESTING & EXAMPLES
# =================================================

if __name__ == "__main__":
    print("Hybrid Attack Testing")
    print("=" * 70)
    
    # Test 1: Show transformation examples
    print("\nTest 1: Transformation Examples for 'password'")
    print("-" * 70)
    candidates = generate_hybrid_candidates("password", max_number=10)
    print(f"Generated {len(candidates)} candidates:")
    for i, candidate in enumerate(candidates[:20], 1):  # Show first 20
        print(f"  {i:2}. {candidate}")
    if len(candidates) > 20:
        print(f"  ... and {len(candidates) - 20} more")
    
    # Test 2: Educational mode
    print("\n" + "=" * 70)
    print("\nTest 2: Educational Mode - Cracking 'password123'")
    print("-" * 70)
    
    result = hybrid_attack(
        plaintext_password="password123",
        algorithm="md5",
        max_number=200
    )
    
    if result["success"]:
        print(f"✓ Cracked successfully!")
        print(f"  Original: {result['original_password']}")
        print(f"  Cracked: {result['password']}")
        print(f"  Base word: {result['base_word']}")
        print(f"  Transformation: {result['transformation']}")
        print(f"  Attempts: {result['attempts']:,}")
        print(f"  Time: {result['time_seconds']}s")
        print(f"  Hash rate: {result['hash_rate']:,.0f} h/s")
    else:
        print(f"✗ Failed to crack")
        print(f"  Error: {result.get('error', result.get('message', 'Unknown'))}")
    
    print("\n" + "=" * 70)
