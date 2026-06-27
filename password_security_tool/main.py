"""
Password Analyzer and Cracking Tool
====================================
Educational security testing tool for password strength analysis and attack simulations.

Author: [Your Name]
Version: 1.0.0
Date: 2025

Purpose: Final Year Project - Information Security
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# Version information
VERSION = "1.0.0"
APP_NAME = "Password Analyzer and Cracking Tool"

# =================================================
# PRE-FLIGHT CHECKS
# =================================================

def check_dependencies():
    """
    Check if all required Python packages are installed.
    Returns: (success: bool, missing_packages: list)
    """
    required_packages = {
        'tkinter': 'tkinter (should be built-in)',
        'hashlib': 'hashlib (should be built-in)',
        'bcrypt': 'bcrypt',
        'itertools': 'itertools (should be built-in)'
    }
    
    missing = []
    
    for package, display_name in required_packages.items():
        try:
            __import__(package)
        except ImportError:
            missing.append(display_name)
    
    return len(missing) == 0, missing


def check_required_files():
    """
    Check if required files exist and create them if needed.
    Returns: (success: bool, issues: list)
    """
    issues = []
    
    # Check for wordlist.txt
    if not os.path.exists("wordlist.txt"):
        try:
            # Create a basic wordlist
            with open("wordlist.txt", "w", encoding="utf-8") as f:
                basic_words = [
                    "password", "123456", "12345678", "qwerty", "abc123",
                    "monkey", "1234567", "letmein", "trustno1", "dragon",
                    "baseball", "iloveyou", "master", "sunshine", "ashley",
                    "bailey", "shadow", "123123", "654321", "superman",
                    "qazwsx", "michael", "football", "welcome", "jesus",
                    "ninja", "mustang", "password123", "admin", "test"
                ]
                f.write("\n".join(basic_words))
            print("[INFO] Created basic wordlist.txt with common passwords")
        except Exception as e:
            issues.append(f"Could not create wordlist.txt: {e}")
    
    # Create necessary directories
    directories = ["logs", "reports"]
    for directory in directories:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            issues.append(f"Could not create directory '{directory}': {e}")
    
    return len(issues) == 0, issues


def initialize_logging():
    """Initialize the logging system."""
    try:
        from logger import log_event
        log_event(f"{APP_NAME} v{VERSION} started", "INFO")
        return True
    except Exception as e:
        print(f"[WARNING] Could not initialize logging: {e}")
        return False


# =================================================
# MAIN APPLICATION
# =================================================

def show_startup_screen():
    """Display startup information in console."""
    print("=" * 70)
    print(f"{APP_NAME} v{VERSION}".center(70))
    print("=" * 70)
    print("Educational Password Security Testing Tool")
    print("For Information Security Research and Learning")
    print("=" * 70)
    print()


def main():
    """
    Application entry point.
    
    Performs pre-flight checks, initializes the GUI, and handles errors.
    """
    
    # Show startup screen
    show_startup_screen()
    
    # Check Python version
    if sys.version_info < (3, 7):
        print("[ERROR] Python 3.7 or higher is required")
        print(f"Current version: {sys.version}")
        sys.exit(1)
    
    print("[1/5] Checking Python dependencies...")
    deps_ok, missing = check_dependencies()
    if not deps_ok:
        print("[ERROR] Missing required packages:")
        for pkg in missing:
            print(f"  - {pkg}")
        print("\nInstall missing packages using:")
        print("  pip install bcrypt")
        sys.exit(1)
    print("✓ All dependencies found")
    
    print("[2/5] Checking required files...")
    files_ok, issues = check_required_files()
    if not files_ok:
        print("[WARNING] File issues detected:")
        for issue in issues:
            print(f"  - {issue}")
        print("Application will continue but some features may not work")
    else:
        print("✓ All required files present")
    
    print("[3/5] Initializing logging system...")
    if initialize_logging():
        print("✓ Logging initialized")
    else:
        print("⚠ Logging initialization failed (non-critical)")
    
    print("[4/5] Importing GUI components...")
    try:
        from gui import PasswordToolGUI
        print("✓ GUI components loaded")
    except ImportError as e:
        print("[ERROR] gui.py or PasswordToolGUI class not found")
        print("Make sure gui.py exists and contains class PasswordToolGUI")
        print(f"Reason: {e}")
        
        # Show error dialog if tkinter is available
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror(
                "Import Error",
                f"Failed to import GUI:\n\n{e}\n\n"
                "Make sure gui.py exists in the same directory as main.py"
            )
        except:
            pass
        
        sys.exit(1)
    
    print("[5/5] Starting application...")
    print()
    
    try:
        # Create root window
        root = tk.Tk()
        
        # Set window icon (if available)
        try:
            root.iconbitmap("icon.ico")  # Optional: add your icon file
        except:
            pass  # Icon file not found, continue without it
        
        # Initialize GUI
        app = PasswordToolGUI(root)
        
        # Center window after GUI is fully built
        root.update_idletasks()
        window_width = root.winfo_width()
        window_height = root.winfo_height()
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        
        # Calculate position
        x = (screen_width // 2) - (window_width // 2)
        y = (screen_height // 2) - (window_height // 2)
        
        # Ensure window is not positioned off-screen
        x = max(0, x)
        y = max(0, y)
        
        root.geometry(f"+{x}+{y}")
        
        print("✓ Application started successfully")
        print("=" * 70)
        print()
        
        # Log successful startup
        try:
            from logger import log_event
            log_event("GUI initialized successfully", "INFO")
        except:
            pass
        
        # Start event loop
        root.mainloop()
        
        # Log shutdown
        try:
            from logger import log_event
            log_event("Application closed normally", "INFO")
        except:
            pass
    
    except KeyboardInterrupt:
        print("\n[INFO] Application interrupted by user")
        sys.exit(0)
    
    except Exception as error:
        print("[ERROR] Application failed to start")
        print(f"Error Type: {type(error).__name__}")
        print(f"Reason: {error}")
        print()
        
        # Log error
        try:
            from logger import log_event
            log_event(f"Application crash: {type(error).__name__} - {error}", "ERROR")
        except:
            pass
        
        # Show error dialog
        try:
            messagebox.showerror(
                "Startup Error",
                f"Failed to start application:\n\n"
                f"Error Type: {type(error).__name__}\n"
                f"Reason: {error}\n\n"
                f"Check the console for more details."
            )
        except:
            pass
        
        # Print traceback for debugging
        import traceback
        print("\nFull traceback:")
        print("-" * 70)
        traceback.print_exc()
        print("-" * 70)
        
        sys.exit(1)


# =================================================
# ENTRY POINT
# =================================================

if __name__ == "__main__":
    main()
