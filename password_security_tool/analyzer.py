import re
from entropy import calculate_entropy

# Frequently observed weak password patterns
COMMON_PATTERNS = ["123", "abc", "password", "qwerty", "admin", "letmein", 
                   "welcome", "monkey", "dragon", "master", "sunshine"]

def has_sequential_chars(password):
    """Detect sequential characters like '123', 'abc', 'xyz'"""
    sequences = []
    
    # Check for numeric sequences
    for i in range(len(password) - 2):
        if password[i:i+3].isdigit():
            if ord(password[i+1]) == ord(password[i]) + 1 and ord(password[i+2]) == ord(password[i+1]) + 1:
                sequences.append(password[i:i+3])
    
    # Check for alphabetic sequences (case-insensitive)
    lower_pass = password.lower()
    for i in range(len(lower_pass) - 2):
        if lower_pass[i:i+3].isalpha():
            if ord(lower_pass[i+1]) == ord(lower_pass[i]) + 1 and ord(lower_pass[i+2]) == ord(lower_pass[i+1]) + 1:
                sequences.append(password[i:i+3])
    
    return sequences

def has_repeated_chars(password):
    """Detect repeated characters like 'aaa', '111'"""
    for i in range(len(password) - 2):
        if password[i] == password[i+1] == password[i+2]:
            return True
    return False

def analyze_password(password, dictionary_words=None):
    """
    Analyzes password strength and returns detailed assessment.
    Returns: (strength, entropy, issues, is_crackable)
    """
    issues = []
    score = 0
    
    # Load dictionary internally if not provided
    if dictionary_words is None:
        try:
            with open("wordlist.txt", "r", encoding="utf-8", errors="ignore") as f:
                dictionary_words = [line.strip().lower() for line in f if line.strip()]
        except FileNotFoundError:
            dictionary_words = []
    
    # ---------------- LENGTH ----------------
    length = len(password)
    if length < 6:
        issues.append("Password is critically short (minimum 8 characters recommended)")
        score -= 2
    elif length < 8:
        issues.append("Password is too short (minimum 8 characters recommended)")
        score -= 1
    elif length >= 16:
        score += 3  # Very strong length bonus
    elif length >= 12:
        score += 2  # Strong length bonus
    else:
        score += 1
    
    # ---------------- CHARACTER VARIETY ----------------
    has_upper = bool(re.search(r"[A-Z]", password))
    has_lower = bool(re.search(r"[a-z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_special = bool(re.search(r"[!@#$%^&*()\-_=+\[\]{};:'\",.<>?/\\|`~]", password))
    
    char_variety = sum([has_upper, has_lower, has_digit, has_special])
    
    if has_upper:
        score += 1
    else:
        issues.append("Missing uppercase letters (A-Z)")
    
    if has_lower:
        score += 1
    else:
        issues.append("Missing lowercase letters (a-z)")
    
    if has_digit:
        score += 1
    else:
        issues.append("Missing numeric digits (0-9)")
    
    if has_special:
        score += 2  # Special chars are more valuable
    else:
        issues.append("Missing special characters (!@#$%^&*...)")
    
    # Bonus for using all character types
    if char_variety == 4:
        score += 1
    
    # ---------------- COMMON PATTERNS ----------------
    password_lower = password.lower()
    for pattern in COMMON_PATTERNS:
        if pattern in password_lower:
            issues.append(f"Contains commonly used pattern: '{pattern}'")
            score -= 2  # Higher penalty for common patterns
    
    # ---------------- SEQUENTIAL CHARACTERS ----------------
    sequences = has_sequential_chars(password)
    if sequences:
        issues.append(f"Contains sequential characters: {', '.join(set(sequences))}")
        score -= 1
    
    # ---------------- REPEATED CHARACTERS ----------------
    if has_repeated_chars(password):
        issues.append("Contains repeated characters (e.g., 'aaa', '111')")
        score -= 1
    
    # ---------------- DICTIONARY CHECK ----------------
    dictionary_found = False
    for word in dictionary_words:
        if len(word) > 3 and word in password_lower:
            issues.append(f"Contains dictionary word: '{word}'")
            score -= 2
            dictionary_found = True
            break
    
    # ---------------- ENTROPY CALCULATION ----------------
    entropy = calculate_entropy(password)
    
    # Add entropy-based scoring
    if entropy >= 80:
        score += 3
    elif entropy >= 60:
        score += 2
    elif entropy >= 40:
        score += 1
    else:
        score -= 1
    
    # ---------------- FINAL STRENGTH ASSESSMENT ----------------
    # Determine if password is crackable
    is_crackable = True
    
    # Very strong passwords are practically uncrackable with basic methods
    if entropy >= 80 and length >= 16 and char_variety >= 3 and not dictionary_found:
        strength = "Very Strong (Extremely Difficult to Crack)"
        is_crackable = False
        issues.insert(0, "This password is exceptionally strong and would take an impractical amount of time to crack with standard methods")
    elif entropy >= 70 and length >= 14 and char_variety >= 3:
        strength = "Very Strong"
        score += 2
    elif entropy >= 60 and score >= 6:
        strength = "Strong"
    elif entropy >= 45 or score >= 3:
        strength = "Moderate"
    elif entropy >= 30 or score >= 1:
        strength = "Weak"
    else:
        strength = "Very Weak"
    
    # Add overall assessment
    if not is_crackable:
        issues.append("⚠️  Password analyzer cannot reliably predict cracking time for this password")
    
    return strength, entropy, issues, is_crackable
