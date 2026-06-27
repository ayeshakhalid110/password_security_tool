import subprocess
import os
import sys
import time
import tempfile
import re
from typing import Optional, Callable
from hashing import hash_password, detect_hash_type

# =================================================
# HASHCAT DETECTION
# =================================================

def is_hashcat_installed() -> bool:
    """
    Check if Hashcat is installed and accessible.
    
    Returns:
        True if Hashcat is available, False otherwise
    """
    try:
        result = subprocess.run(
            ['hashcat', '--version'],
            capture_output=True,
            timeout=5,
            text=True
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def get_hashcat_version() -> Optional[str]:
    """Get Hashcat version string if installed."""
    try:
        result = subprocess.run(
            ['hashcat', '--version'],
            capture_output=True,
            timeout=5,
            text=True
        )
        if result.returncode == 0:
            return result.stdout.strip().split('\n')[0]
    except:
        pass
    return None


# =================================================
# HASH TYPE MAPPING
# =================================================

# Map our algorithm names to Hashcat mode numbers
HASHCAT_MODES = {
    "md5": 0,
    "sha1": 100,
    "sha256": 1400,
    "sha512": 1700,
    "ntlm": 1000,
    "bcrypt": 3200,
    # Salted variants
    "salted_md5": 10,
    "salted_sha1": 110,
    "salted_sha256": 1410,
    "salted_sha512": 1710,
}


def get_hashcat_mode(algorithm: str, has_salt: bool = False) -> Optional[int]:
    """
    Get Hashcat mode number for an algorithm.
    
    Args:
        algorithm: Hash algorithm name
        has_salt: Whether hash is salted
    
    Returns:
        Hashcat mode number or None if unsupported
    """
    algorithm = algorithm.lower()
    
    if has_salt and f"salted_{algorithm}" in HASHCAT_MODES:
        return HASHCAT_MODES[f"salted_{algorithm}"]
    elif algorithm in HASHCAT_MODES:
        return HASHCAT_MODES[algorithm]
    
    return None


# =================================================
# MASK GENERATION
# =================================================

def generate_smart_mask(plaintext: str) -> str:
    """
    Analyzes password to create optimized Hashcat mask.
    
    Hashcat mask placeholders:
    - ?l = lowercase (a-z)
    - ?u = uppercase (A-Z)
    - ?d = digit (0-9)
    - ?s = special chars
    - ?a = all printable ASCII
    - ?b = all bytes (0x00-0xFF)
    
    Args:
        plaintext: The password to analyze
    
    Returns:
        Hashcat mask string
    """
    if not plaintext:
        return ""
    
    length = len(plaintext)
    
    # Check password composition
    has_lower = any(c.islower() for c in plaintext)
    has_upper = any(c.isupper() for c in plaintext)
    has_digit = any(c.isdigit() for c in plaintext)
    has_special = any(not c.isalnum() for c in plaintext)
    
    # Pure digit (fastest)
    if plaintext.isdigit():
        return "?d" * length
    
    # Pure lowercase
    elif plaintext.isalpha() and plaintext.islower():
        return "?l" * length
    
    # Pure uppercase
    elif plaintext.isalpha() and plaintext.isupper():
        return "?u" * length
    
    # Lowercase + digits (common: password123)
    elif has_lower and has_digit and not has_upper and not has_special:
        mask = ""
        for char in plaintext:
            if char.islower():
                mask += "?l"
            elif char.isdigit():
                mask += "?d"
        return mask
    
    # Mixed case letters only
    elif plaintext.isalpha() and has_lower and has_upper:
        mask = ""
        for char in plaintext:
            if char.islower():
                mask += "?l"
            else:
                mask += "?u"
        return mask
    
    # Alphanumeric (letters + digits)
    elif plaintext.isalnum():
        mask = ""
        for char in plaintext:
            if char.isalpha():
                if char.islower():
                    mask += "?l"
                else:
                    mask += "?u"
            else:
                mask += "?d"
        return mask
    
    # Has special characters - use full ASCII
    else:
        return "?a" * length


# =================================================
# HASHCAT ATTACK CLASS
# =================================================

class HashcatAttack:
    """
    Professional Hashcat integration with fallback support.
    
    Features:
    - Multiple attack modes (mask, dictionary, hybrid)
    - Multi-algorithm support
    - Progress parsing
    - Educational mode
    - Graceful fallback if Hashcat not installed
    """
    
    def __init__(self):
        self.hashcat_available = is_hashcat_installed()
        self.temp_dir = tempfile.gettempdir()
    
    def attack(self,
               target_hash: str = None,
               algorithm: Optional[str] = None,
               salt: Optional[str] = None,
               attack_mode: str = "mask",
               wordlist_path: str = "wordlist.txt",
               mask: Optional[str] = None,
               max_length: int = 6,
               progress_callback: Optional[Callable] = None,
               plaintext_password: Optional[str] = None) -> dict:
        """
        Perform Hashcat attack or simulate if not available.
        
        Args:
            target_hash: Hash to crack (or None if using plaintext_password)
            algorithm: Hash algorithm
            salt: Salt for salted hashes
            attack_mode: "mask" (brute force), "dictionary", or "hybrid"
            wordlist_path: Path to wordlist for dictionary/hybrid attacks
            mask: Custom mask (auto-generated if None in mask mode)
            max_length: Max password length for mask generation
            progress_callback: Progress update function
            plaintext_password: (EDUCATIONAL MODE) Password to hash and crack
        
        Returns:
            Result dictionary
        """
        # EDUCATIONAL MODE: Generate hash
        educational_mode = False
        educational_hash = None
        
        if plaintext_password is not None:
            if algorithm is None:
                return {
                    "success": False,
                    "error": "Algorithm required in educational mode"
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
            
            # Ensure hash is lowercase for Hashcat compatibility
            educational_hash = educational_hash.lower()
            target_hash = educational_hash
            educational_mode = True
            
            # Auto-generate mask if not provided
            if attack_mode == "mask" and mask is None:
                mask = generate_smart_mask(plaintext_password)
        
        # Ensure target_hash is lowercase
        if target_hash:
            target_hash = target_hash.lower()
        
        # Check if Hashcat is available
        if not self.hashcat_available:
            return self._fallback_mode(
                target_hash, algorithm, salt, attack_mode,
                educational_mode, plaintext_password, educational_hash
            )
        
        # Auto-detect algorithm
        if algorithm is None:
            algorithm = detect_hash_type(target_hash)
            if algorithm is None:
                return {
                    "success": False,
                    "error": "Could not detect hash type"
                }
        
        # Get Hashcat mode
        hashcat_mode = get_hashcat_mode(algorithm, salt is not None)
        if hashcat_mode is None:
            return {
                "success": False,
                "error": f"Algorithm '{algorithm}' not supported by Hashcat"
            }
        
        # Run appropriate attack
        start_time = time.time()
        
        if attack_mode == "mask":
            if mask is None:
                mask = "?a" * max_length
            result = self._run_mask_attack(target_hash, hashcat_mode, mask, salt)
        
        elif attack_mode == "dictionary":
            result = self._run_dictionary_attack(target_hash, hashcat_mode, wordlist_path, salt)
        
        elif attack_mode == "hybrid":
            result = self._run_hybrid_attack(target_hash, hashcat_mode, wordlist_path, salt)
        
        else:
            return {
                "success": False,
                "error": f"Unknown attack mode: {attack_mode}"
            }
        
        # Add timing and educational info
        result["time_seconds"] = round(time.time() - start_time, 2)
        result["hash_algorithm"] = algorithm
        result["attack_type"] = f"Hashcat {attack_mode.capitalize()} Attack"
        result["hashcat_mode"] = hashcat_mode
        
        if educational_mode:
            result["educational_mode"] = True
            result["original_password"] = plaintext_password
            result["generated_hash"] = educational_hash
        
        return result
    
    def _run_mask_attack(self, target_hash: str, mode: int, mask: str, salt: Optional[str]) -> dict:
        """Execute Hashcat mask (brute force) attack."""
        # Create temp files
        hash_file = os.path.join(self.temp_dir, "hashcat_target.txt")
        output_file = os.path.join(self.temp_dir, "hashcat_output.txt")
        
        # Ensure hash is lowercase (Hashcat expects lowercase hex)
        target_hash = target_hash.lower()
        
        # Write hash (with salt if present) - ADD NEWLINE
        try:
            with open(hash_file, "w") as f:
                if salt:
                    f.write(f"{target_hash}:{salt}\n")
                else:
                    f.write(f"{target_hash}\n")
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to write hash file: {str(e)}"
            }
        
        # Build command - REMOVE --force, ADD --self-test-disable
        cmd = [
            "hashcat",
            "-m", str(mode),
            "-a", "3",  # Mask attack
            hash_file,
            mask,
            "-o", output_file,
            "--potfile-disable",
            "--self-test-disable",  # Skip self-test for speed
            "--quiet",
            "--force"  # Keep force to avoid warnings
        ]
        
        try:
            # Run hashcat
            result = subprocess.run(cmd, timeout=300, capture_output=True, text=True)
            
            # Debug: Check for errors in stderr
            if result.stderr and "error" in result.stderr.lower():
                print(f"Hashcat stderr: {result.stderr}")
            
            # Check results
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    content = f.read().strip()
                
                if content:
                    # Parse: hash:password or hash:salt:password
                    parts = content.split(":")
                    password = parts[-1]
                    
                    return {
                        "success": True,
                        "password": password,
                        "mask_used": mask,
                        "attempts": self._calculate_keyspace(mask)
                    }
            
            # If no output file or empty, password not found
            return {
                "success": False,
                "message": "Password not found with given mask",
                "mask_used": mask,
                "keyspace": self._calculate_keyspace(mask)
            }
        
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Attack timed out (5 minutes limit)",
                "mask_used": mask
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Hashcat execution error: {str(e)}",
                "mask_used": mask
            }
        
        finally:
            # Cleanup
            for f in [hash_file, output_file]:
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except:
                        pass
    
    def _calculate_keyspace(self, mask: str) -> int:
        """Calculate total combinations for a mask."""
        keyspace = 1
        charset_sizes = {
            '?l': 26,   # lowercase
            '?u': 26,   # uppercase
            '?d': 10,   # digits
            '?s': 33,   # special chars
            '?a': 95,   # all printable ASCII
            '?b': 256,  # all bytes
        }
        
        i = 0
        while i < len(mask):
            if i < len(mask) - 1 and mask[i] == '?':
                charset = mask[i:i+2]
                if charset in charset_sizes:
                    keyspace *= charset_sizes[charset]
                    i += 2
                    continue
            keyspace *= 95  # Assume printable ASCII for unknown
            i += 1
        
        return keyspace
    
    def _run_dictionary_attack(self, target_hash: str, mode: int, wordlist: str, salt: Optional[str]) -> dict:
        """Execute Hashcat dictionary attack."""
        hash_file = os.path.join(self.temp_dir, "hashcat_target.txt")
        output_file = os.path.join(self.temp_dir, "hashcat_output.txt")
        
        # Ensure hash is lowercase
        target_hash = target_hash.lower()
        
        # Check if wordlist exists
        if not os.path.exists(wordlist):
            return {
                "success": False,
                "error": f"Wordlist not found: {wordlist}"
            }
        
        try:
            with open(hash_file, "w") as f:
                if salt:
                    f.write(f"{target_hash}:{salt}\n")
                else:
                    f.write(f"{target_hash}\n")
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to write hash file: {str(e)}"
            }
        
        cmd = [
            "hashcat",
            "-m", str(mode),
            "-a", "0",  # Dictionary attack
            hash_file,
            wordlist,
            "-o", output_file,
            "--potfile-disable",
            "--self-test-disable",
            "--quiet",
            "--force"
        ]
        
        try:
            result = subprocess.run(cmd, timeout=300, capture_output=True, text=True)
            
            if result.stderr and "error" in result.stderr.lower():
                print(f"Hashcat stderr: {result.stderr}")
            
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    content = f.read().strip()
                
                if content:
                    parts = content.split(":")
                    password = parts[-1]
                    
                    return {
                        "success": True,
                        "password": password,
                        "wordlist_used": wordlist
                    }
            
            return {
                "success": False,
                "message": "Password not found in wordlist",
                "wordlist_used": wordlist
            }
        
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Attack timed out",
                "wordlist_used": wordlist
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Hashcat execution error: {str(e)}",
                "wordlist_used": wordlist
            }
        
        finally:
            for f in [hash_file, output_file]:
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except:
                        pass
    
    def _run_hybrid_attack(self, target_hash: str, mode: int, wordlist: str, salt: Optional[str]) -> dict:
        """Execute Hashcat hybrid attack (wordlist + mask)."""
        hash_file = os.path.join(self.temp_dir, "hashcat_target.txt")
        output_file = os.path.join(self.temp_dir, "hashcat_output.txt")
        
        # Ensure hash is lowercase
        target_hash = target_hash.lower()
        
        # Check if wordlist exists
        if not os.path.exists(wordlist):
            return {
                "success": False,
                "error": f"Wordlist not found: {wordlist}"
            }
        
        try:
            with open(hash_file, "w") as f:
                if salt:
                    f.write(f"{target_hash}:{salt}\n")
                else:
                    f.write(f"{target_hash}\n")
        except Exception as e:
            return {
                "success": False,
                "error": f"Failed to write hash file: {str(e)}"
            }
        
        # Hybrid mode 6: wordlist + mask (e.g., password + ?d?d?d)
        cmd = [
            "hashcat",
            "-m", str(mode),
            "-a", "6",  # Hybrid wordlist + mask
            hash_file,
            wordlist,
            "?d?d?d",  # Append up to 3 digits
            "-o", output_file,
            "--potfile-disable",
            "--self-test-disable",
            "--quiet",
            "--force"
        ]
        
        try:
            result = subprocess.run(cmd, timeout=300, capture_output=True, text=True)
            
            if result.stderr and "error" in result.stderr.lower():
                print(f"Hashcat stderr: {result.stderr}")
            
            if os.path.exists(output_file):
                with open(output_file, "r") as f:
                    content = f.read().strip()
                
                if content:
                    parts = content.split(":")
                    password = parts[-1]
                    
                    return {
                        "success": True,
                        "password": password,
                        "attack_mode": "hybrid (wordlist + mask)"
                    }
            
            return {
                "success": False,
                "message": "Password not found with hybrid attack",
                "attack_mode": "hybrid"
            }
        
        except subprocess.TimeoutExpired:
            return {
                "success": False,
                "error": "Attack timed out",
                "attack_mode": "hybrid"
            }
        
        except Exception as e:
            return {
                "success": False,
                "error": f"Hashcat execution error: {str(e)}",
                "attack_mode": "hybrid"
            }
        
        finally:
            for f in [hash_file, output_file]:
                if os.path.exists(f):
                    try:
                        os.remove(f)
                    except:
                        pass
    
    def _fallback_mode(self, target_hash, algorithm, salt, attack_mode,
                      educational_mode, plaintext_password, educational_hash) -> dict:
        """
        Fallback when Hashcat is not installed.
        Provides informative message and suggests using Python crackers.
        """
        return {
            "success": False,
            "hashcat_available": False,
            "error": "Hashcat not installed on this system",
            "message": "Hashcat is a GPU-accelerated password cracking tool that can crack passwords 1000x-100000x faster than Python implementations.",
            "install_instructions": {
                "windows": "Download from https://hashcat.net/hashcat/ and add to PATH",
                "linux": "Install via: sudo apt install hashcat",
                "macos": "Install via: brew install hashcat"
            },
            "alternative": "Use Dictionary Attack, Brute Force Attack, or Hybrid Attack from the menu instead",
            "performance_comparison": {
                "python_speed": "~1,000 - 10,000 hashes/second (CPU)",
                "hashcat_cpu": "~100,000 - 1M hashes/second",
                "hashcat_gpu": "~1B - 100B hashes/second (with modern GPU)"
            }
        }


# =================================================
# STANDALONE FUNCTION
# =================================================

def hashcat_attack(target_hash: str = None,
                  algorithm: Optional[str] = None,
                  salt: Optional[str] = None,
                  attack_mode: str = "mask",
                  wordlist_path: str = "wordlist.txt",
                  mask: Optional[str] = None,
                  max_length: int = 6,
                  progress_callback: Optional[Callable] = None,
                  plaintext_password: Optional[str] = None) -> dict:
    """
    Simplified Hashcat attack function.
    
    Args:
        target_hash: Hash to crack
        algorithm: Hash algorithm
        salt: Salt for salted hashes
        attack_mode: "mask", "dictionary", or "hybrid"
        wordlist_path: Path to wordlist
        mask: Custom Hashcat mask
        max_length: Max length for auto-generated mask
        progress_callback: Progress updates
        plaintext_password: (EDUCATIONAL MODE) Password to hash and crack
    
    Returns:
        Result dictionary
    
    Example (Educational Mode):
        result = hashcat_attack(
            plaintext_password="password123",
            algorithm="md5",
            attack_mode="mask"
        )
    """
    attacker = HashcatAttack()
    return attacker.attack(
        target_hash=target_hash,
        algorithm=algorithm,
        salt=salt,
        attack_mode=attack_mode,
        wordlist_path=wordlist_path,
        mask=mask,
        max_length=max_length,
        progress_callback=progress_callback,
        plaintext_password=plaintext_password
    )


# =================================================
# TESTING
# =================================================

if __name__ == "__main__":
    print("Hashcat Integration Testing")
    print("=" * 70)
    
    # Check if Hashcat is installed
    print(f"\n1. Hashcat Detection:")
    if is_hashcat_installed():
        version = get_hashcat_version()
        print(f"   ✓ Hashcat is installed: {version}")
    else:
        print(f"   ✗ Hashcat is NOT installed")
        print(f"   → Will use fallback mode with informative messages")
    
    # Test mask generation
    print(f"\n2. Mask Generation Examples:")
    test_passwords = ["1234", "hello", "Hello", "password123", "P@ssw0rd!", "pass"]
    for pwd in test_passwords:
        mask = generate_smart_mask(pwd)
        print(f"   '{pwd}' → {mask}")
    
    # Test educational mode with "pass"
    print(f"\n3. Educational Mode Test - Password: 'pass':")
    result = hashcat_attack(
        plaintext_password="pass",
        algorithm="sha256",
        attack_mode="mask"
    )
    
    if result.get("hashcat_available") == False:
        print(f"   ℹ Hashcat not available - showing fallback info:")
        print(f"   Error: {result['error']}")
        print(f"   Alternative: {result['alternative']}")
    elif result["success"]:
        print(f"   ✓ Successfully cracked!")
        print(f"   Password: {result['password']}")
        print(f"   Time: {result['time_seconds']}s")
        print(f"   Mask: {result.get('mask_used')}")
        print(f"   Hash: {result.get('generated_hash')}")
    else:
        print(f"   ✗ Failed: {result.get('error', result.get('message'))}")
        if 'mask_used' in result:
            print(f"   Mask tried: {result['mask_used']}")
        if 'keyspace' in result:
            print(f"   Keyspace: {result['keyspace']:,} combinations")
    
    # Test with MD5 too
    print(f"\n4. Educational Mode Test - Password: 'test123' (MD5):")
    result = hashcat_attack(
        plaintext_password="test123",
        algorithm="md5",
        attack_mode="mask"
    )
    
    if result.get("hashcat_available") == False:
        print(f"   ℹ Hashcat not available")
    elif result["success"]:
        print(f"   ✓ Successfully cracked!")
        print(f"   Password: {result['password']}")
        print(f"   Time: {result['time_seconds']}s")
        print(f"   Mask: {result.get('mask_used')}")
    else:
        print(f"   ✗ Failed: {result.get('error', result.get('message'))}")
    
    print("\n" + "=" * 70)
