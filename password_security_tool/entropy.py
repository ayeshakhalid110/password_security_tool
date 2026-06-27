import math
from collections import Counter

def calculate_entropy(password: str, method: str = "guessing") -> float:
    """
    Calculates password entropy using specified method.
    
    Args:
        password: The password string to analyze
        method: "guessing" (default) or "shannon"
            - guessing: L × log2(N) - estimates brute-force resistance
            - shannon: True Shannon entropy based on character frequency
    
    Returns:
        Entropy value in bits (higher = stronger)
    
    Guessing Entropy Formula:
        Entropy = L × log2(N)
        Where:
            L = length of password
            N = size of character set (charset) used
    
    Shannon Entropy Formula:
        Entropy = -Σ(p(x) × log2(p(x)))
        Where p(x) is the probability of character x
    """
    if not password:
        return 0.0
    
    if method == "shannon":
        return calculate_shannon_entropy(password)
    else:
        return calculate_guessing_entropy(password)


def calculate_guessing_entropy(password: str) -> float:
    """
    Calculates guessing entropy (brute-force resistance).
    This estimates how many bits of entropy an attacker must overcome
    when trying all possible combinations from the detected character set.
    """
    if not password:
        return 0.0
    
    # Define complete character categories
    categories = {
        "lowercase": set("abcdefghijklmnopqrstuvwxyz"),
        "uppercase": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "digits": set("0123456789"),
        "symbols": set("!@#$%^&*()-_=+[]{};:',.<>?/\\|`~\""),
        "space": set(" ")
    }
    
    # Calculate charset size based on categories used
    charset_size = 0
    password_chars = set(password)
    
    for category_name, charset in categories.items():
        if password_chars & charset:  # If any char from this category is used
            charset_size += len(charset)
    
    # Handle characters not in predefined categories (Unicode, etc.)
    uncategorized_chars = password_chars
    for charset in categories.values():
        uncategorized_chars -= charset
    
    if uncategorized_chars:
        # Add space for extended ASCII or Unicode characters
        charset_size += len(uncategorized_chars)
    
    # Minimum charset size is 1 (prevents log2(0))
    if charset_size == 0:
        charset_size = 1
    
    # Calculate guessing entropy
    entropy = len(password) * math.log2(charset_size)
    
    return round(entropy, 2)


def calculate_shannon_entropy(password: str) -> float:
    """
    Calculates true Shannon entropy based on character frequency distribution.
    This measures the actual randomness/unpredictability of the password.
    
    Formula: H = -Σ(p(x) × log2(p(x)))
    Where p(x) is the probability (frequency) of each character
    """
    if not password:
        return 0.0
    
    # Count character frequencies
    char_counts = Counter(password)
    password_length = len(password)
    
    # Calculate Shannon entropy
    entropy = 0.0
    for count in char_counts.values():
        probability = count / password_length
        entropy -= probability * math.log2(probability)
    
    # Scale by password length to get total entropy
    total_entropy = entropy * password_length
    
    return round(total_entropy, 2)


def get_charset_info(password: str) -> dict:
    """
    Returns detailed information about character set usage.
    Useful for detailed password analysis reports.
    
    Returns:
        dict with keys: charset_size, categories_used, unique_chars
    """
    categories = {
        "lowercase": set("abcdefghijklmnopqrstuvwxyz"),
        "uppercase": set("ABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "digits": set("0123456789"),
        "symbols": set("!@#$%^&*()-_=+[]{};:',.<>?/\\|`~\""),
        "space": set(" ")
    }
    
    password_chars = set(password)
    categories_used = []
    charset_size = 0
    
    for category_name, charset in categories.items():
        if password_chars & charset:
            categories_used.append(category_name)
            charset_size += len(charset)
    
    # Check for uncategorized characters
    uncategorized = password_chars
    for charset in categories.values():
        uncategorized -= charset
    
    if uncategorized:
        categories_used.append("extended")
        charset_size += len(uncategorized)
    
    return {
        "charset_size": charset_size,
        "categories_used": categories_used,
        "unique_chars": len(password_chars),
        "password_length": len(password)
    }


def estimate_crack_time(entropy: float, guesses_per_second: int = 1_000_000_000) -> dict:
    """
    Estimates time to crack based on entropy and attack speed.
    
    Args:
        entropy: Password entropy in bits
        guesses_per_second: Attack speed (default: 1 billion/sec for modern GPU)
    
    Returns:
        dict with time estimates in various units
    """
    total_combinations = 2 ** entropy
    # Average case: attacker finds password halfway through search space
    average_attempts = total_combinations / 2
    
    seconds = average_attempts / guesses_per_second
    
    minutes = seconds / 60
    hours = minutes / 60
    days = hours / 24
    years = days / 365.25
    
    # Determine best unit to display
    if years > 1:
        time_str = f"{years:.2e} years" if years > 1000 else f"{years:.2f} years"
    elif days > 1:
        time_str = f"{days:.2f} days"
    elif hours > 1:
        time_str = f"{hours:.2f} hours"
    elif minutes > 1:
        time_str = f"{minutes:.2f} minutes"
    else:
        time_str = f"{seconds:.2f} seconds"
    
    return {
        "seconds": seconds,
        "minutes": minutes,
        "hours": hours,
        "days": days,
        "years": years,
        "readable": time_str
    }


# Example usage and testing
if __name__ == "__main__":
    test_passwords = [
        "password",
        "P@ssw0rd!",
        "Tr0ub4dor&3",
        "correcthorsebatterystaple",
        "aaaaaa",
        "Xk9#mL2$pQ7@"
    ]
    
    print("Password Entropy Analysis")
    print("=" * 70)
    
    for pwd in test_passwords:
        guessing = calculate_entropy(pwd, "guessing")
        shannon = calculate_entropy(pwd, "shannon")
        charset_info = get_charset_info(pwd)
        crack_time = estimate_crack_time(guessing)
        
        print(f"\nPassword: {pwd}")
        print(f"  Length: {len(pwd)}")
        print(f"  Charset Size: {charset_info['charset_size']}")
        print(f"  Categories: {', '.join(charset_info['categories_used'])}")
        print(f"  Guessing Entropy: {guessing} bits")
        print(f"  Shannon Entropy: {shannon} bits")
        print(f"  Estimated Crack Time: {crack_time['readable']}")
    
    print("\n" + "=" * 70)
