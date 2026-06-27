import os
import json
from datetime import datetime
from typing import Optional, Dict, Any
import threading

# =================================================
# LOG LEVELS
# =================================================

class LogLevel:
    """Log level constants."""
    DEBUG = 0
    INFO = 1
    WARNING = 2
    ERROR = 3
    CRITICAL = 4
    SUCCESS = 5
    ATTACK = 6

    @staticmethod
    def to_string(level: int) -> str:
        """Convert log level to string."""
        mapping = {
            0: "DEBUG",
            1: "INFO",
            2: "WARNING",
            3: "ERROR",
            4: "CRITICAL",
            5: "SUCCESS",
            6: "ATTACK"
        }
        return mapping.get(level, "UNKNOWN")


# =================================================
# SECURITY LOGGER CLASS
# =================================================

class SecurityLogger:
    """
    Professional security logging system with rotation and structured logging.
    
    Features:
    - Multiple log files (attacks, system, errors)
    - Log rotation (size-based)
    - Structured JSON logging
    - Thread-safe operations
    - Configurable log levels
    - Performance metrics tracking
    """
    
    def __init__(self, 
                 log_dir: str = "logs",
                 max_file_size: int = 10 * 1024 * 1024,  # 10 MB
                 min_level: int = LogLevel.INFO,
                 enable_console: bool = False):
        """
        Initialize the security logger.
        
        Args:
            log_dir: Directory for log files
            max_file_size: Max size per log file before rotation (bytes)
            min_level: Minimum log level to record
            enable_console: Also print logs to console
        """
        self.log_dir = log_dir
        self.max_file_size = max_file_size
        self.min_level = min_level
        self.enable_console = enable_console
        
        # Thread lock for safe concurrent logging
        self._lock = threading.Lock()
        
        # Create log directory if it doesn't exist
        os.makedirs(log_dir, exist_ok=True)
        
        # Log file paths
        self.attack_log = os.path.join(log_dir, "attacks.log")
        self.system_log = os.path.join(log_dir, "system.log")
        self.error_log = os.path.join(log_dir, "errors.log")
        self.json_log = os.path.join(log_dir, "structured.jsonl")  # JSON Lines format
    
    def _should_log(self, level: int) -> bool:
        """Check if this log level should be recorded."""
        return level >= self.min_level
    
    def _rotate_if_needed(self, filepath: str):
        """Rotate log file if it exceeds max size."""
        try:
            if os.path.exists(filepath) and os.path.getsize(filepath) > self.max_file_size:
                # Create backup with timestamp
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"{filepath}.{timestamp}.old"
                os.rename(filepath, backup_path)
        except Exception:
            pass  # Silent failure
    
    def _write_log(self, filepath: str, content: str):
        """Thread-safe log writing with rotation."""
        with self._lock:
            try:
                self._rotate_if_needed(filepath)
                with open(filepath, "a", encoding="utf-8") as f:
                    f.write(content + "\n")
            except Exception:
                pass  # Silent failure
    
    def log(self, 
            message: str,
            level: int = LogLevel.INFO,
            event_type: str = "GENERAL",
            metadata: Optional[Dict[str, Any]] = None):
        """
        Generic logging method.
        
        Args:
            message: Log message
            level: Log level (LogLevel constant)
            event_type: Type of event (ATTACK, SYSTEM, etc.)
            metadata: Additional structured data
        """
        if not self._should_log(level):
            return
        
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        level_str = LogLevel.to_string(level)
        
        # Text format for human-readable logs
        text_entry = f"[{timestamp}] [{level_str}] [{event_type}] {message}"
        
        # JSON format for structured logs
        json_entry = {
            "timestamp": timestamp,
            "level": level_str,
            "event_type": event_type,
            "message": message,
            "metadata": metadata or {}
        }
        
        # Console output
        if self.enable_console:
            print(text_entry)
        
        # Write to appropriate log files
        if level >= LogLevel.ERROR:
            self._write_log(self.error_log, text_entry)
        
        if event_type == "ATTACK" or level == LogLevel.ATTACK:
            self._write_log(self.attack_log, text_entry)
        else:
            self._write_log(self.system_log, text_entry)
        
        # Always write to structured JSON log
        self._write_log(self.json_log, json.dumps(json_entry))
    
    # Convenience methods for different log levels
    
    def debug(self, message: str, event_type: str = "DEBUG", metadata: Optional[Dict] = None):
        """Log debug message."""
        self.log(message, LogLevel.DEBUG, event_type, metadata)
    
    def info(self, message: str, event_type: str = "INFO", metadata: Optional[Dict] = None):
        """Log info message."""
        self.log(message, LogLevel.INFO, event_type, metadata)
    
    def warning(self, message: str, event_type: str = "WARNING", metadata: Optional[Dict] = None):
        """Log warning message."""
        self.log(message, LogLevel.WARNING, event_type, metadata)
    
    def error(self, message: str, event_type: str = "ERROR", metadata: Optional[Dict] = None):
        """Log error message."""
        self.log(message, LogLevel.ERROR, event_type, metadata)
    
    def critical(self, message: str, event_type: str = "CRITICAL", metadata: Optional[Dict] = None):
        """Log critical message."""
        self.log(message, LogLevel.CRITICAL, event_type, metadata)
    
    def success(self, message: str, event_type: str = "SUCCESS", metadata: Optional[Dict] = None):
        """Log success message."""
        self.log(message, LogLevel.SUCCESS, event_type, metadata)
    
    # Attack-specific logging methods
    
    def log_attack_start(self, attack_type: str, target_hash: str, algorithm: str, metadata: Optional[Dict] = None):
        """Log the start of an attack."""
        message = f"Attack started: {attack_type} on {algorithm} hash"
        meta = metadata or {}
        meta.update({
            "attack_type": attack_type,
            "target_hash": target_hash[:16] + "...",  # Truncate for security
            "algorithm": algorithm
        })
        self.log(message, LogLevel.ATTACK, "ATTACK_START", meta)
    
    def log_attack_end(self, attack_type: str, success: bool, password: Optional[str] = None,
                      attempts: int = 0, time_seconds: float = 0, hash_rate: float = 0,
                      metadata: Optional[Dict] = None):
        """Log the end of an attack."""
        if success:
            message = f"Attack succeeded: {attack_type} - Password cracked in {attempts:,} attempts ({time_seconds:.2f}s)"
            level = LogLevel.SUCCESS
            event = "ATTACK_SUCCESS"
        else:
            message = f"Attack failed: {attack_type} - {attempts:,} attempts ({time_seconds:.2f}s)"
            level = LogLevel.INFO
            event = "ATTACK_FAILED"
        
        meta = metadata or {}
        meta.update({
            "attack_type": attack_type,
            "success": success,
            "attempts": attempts,
            "time_seconds": time_seconds,
            "hash_rate": hash_rate
        })
        
        if success and password:
            meta["password_length"] = len(password)
            # Don't log actual password for security
        
        self.log(message, level, event, meta)
    
    def log_password_analyzed(self, strength: str, entropy: float, issues: list):
        """Log password analysis results."""
        message = f"Password analyzed - Strength: {strength}, Entropy: {entropy:.2f} bits, Issues: {len(issues)}"
        metadata = {
            "strength": strength,
            "entropy": entropy,
            "issue_count": len(issues),
            "issues": issues[:5]  # First 5 issues only
        }
        self.log(message, LogLevel.INFO, "ANALYSIS", metadata)
    
    def log_hash_generated(self, algorithm: str, has_salt: bool):
        """Log hash generation."""
        message = f"Hash generated using {algorithm}" + (" with salt" if has_salt else "")
        metadata = {
            "algorithm": algorithm,
            "salted": has_salt
        }
        self.log(message, LogLevel.INFO, "HASH_GEN", metadata)
    
    def get_recent_logs(self, log_type: str = "system", limit: int = 100) -> list:
        """
        Retrieve recent log entries.
        
        Args:
            log_type: "system", "attack", or "error"
            limit: Maximum number of entries to return
        
        Returns:
            List of log lines (most recent first)
        """
        log_map = {
            "system": self.system_log,
            "attack": self.attack_log,
            "error": self.error_log
        }
        
        filepath = log_map.get(log_type, self.system_log)
        
        if not os.path.exists(filepath):
            return []
        
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                lines = f.readlines()
                return lines[-limit:][::-1]  # Last N lines, reversed
        except Exception:
            return []
    
    def get_attack_stats(self) -> Dict[str, Any]:
        """
        Calculate statistics from attack logs.
        
        Returns:
            Dictionary with attack statistics
        """
        stats = {
            "total_attacks": 0,
            "successful_attacks": 0,
            "failed_attacks": 0,
            "attack_types": {},
            "algorithms_targeted": {}
        }
        
        if not os.path.exists(self.json_log):
            return stats
        
        try:
            with open(self.json_log, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                        
                        if entry.get("event_type") == "ATTACK_START":
                            stats["total_attacks"] += 1
                            
                            meta = entry.get("metadata", {})
                            attack_type = meta.get("attack_type", "unknown")
                            algorithm = meta.get("algorithm", "unknown")
                            
                            stats["attack_types"][attack_type] = stats["attack_types"].get(attack_type, 0) + 1
                            stats["algorithms_targeted"][algorithm] = stats["algorithms_targeted"].get(algorithm, 0) + 1
                        
                        elif entry.get("event_type") == "ATTACK_SUCCESS":
                            stats["successful_attacks"] += 1
                        
                        elif entry.get("event_type") == "ATTACK_FAILED":
                            stats["failed_attacks"] += 1
                    
                    except json.JSONDecodeError:
                        continue
        
        except Exception:
            pass
        
        return stats
    
    def clear_logs(self, log_type: Optional[str] = None):
        """
        Clear log files.
        
        Args:
            log_type: Specific log to clear ("system", "attack", "error", "all")
                     If None, clears all logs
        """
        if log_type is None or log_type == "all":
            files_to_clear = [self.system_log, self.attack_log, self.error_log, self.json_log]
        else:
            log_map = {
                "system": self.system_log,
                "attack": self.attack_log,
                "error": self.error_log,
                "json": self.json_log
            }
            files_to_clear = [log_map.get(log_type)]
        
        for filepath in files_to_clear:
            if filepath and os.path.exists(filepath):
                try:
                    os.remove(filepath)
                except Exception:
                    pass


# =================================================
# GLOBAL LOGGER INSTANCE
# =================================================

# Create a global logger instance for convenience
_global_logger = None

def get_logger() -> SecurityLogger:
    """Get or create global logger instance."""
    global _global_logger
    if _global_logger is None:
        _global_logger = SecurityLogger()
    return _global_logger


# =================================================
# BACKWARD-COMPATIBLE FUNCTIONS
# =================================================

def log_event(message: str, event_type: str = "INFO"):
    """
    Legacy log function for backward compatibility.
    
    Parameters:
    - message (str): Description of the event
    - event_type (str): INFO | ATTACK | ERROR | SUCCESS | WARNING
    """
    logger = get_logger()
    
    # Map event types to log levels
    level_map = {
        "DEBUG": LogLevel.DEBUG,
        "INFO": LogLevel.INFO,
        "WARNING": LogLevel.WARNING,
        "ERROR": LogLevel.ERROR,
        "CRITICAL": LogLevel.CRITICAL,
        "SUCCESS": LogLevel.SUCCESS,
        "ATTACK": LogLevel.ATTACK
    }
    
    level = level_map.get(event_type.upper(), LogLevel.INFO)
    logger.log(message, level, event_type.upper())


# Convenience functions
def log_info(message: str, metadata: Optional[Dict] = None):
    """Log info message."""
    get_logger().info(message, metadata=metadata)

def log_error(message: str, metadata: Optional[Dict] = None):
    """Log error message."""
    get_logger().error(message, metadata=metadata)

def log_success(message: str, metadata: Optional[Dict] = None):
    """Log success message."""
    get_logger().success(message, metadata=metadata)

def log_attack_start(attack_type: str, target_hash: str, algorithm: str, metadata: Optional[Dict] = None):
    """Log attack start."""
    get_logger().log_attack_start(attack_type, target_hash, algorithm, metadata)

def log_attack_end(attack_type: str, success: bool, password: Optional[str] = None,
                  attempts: int = 0, time_seconds: float = 0, hash_rate: float = 0,
                  metadata: Optional[Dict] = None):
    """Log attack end."""
    get_logger().log_attack_end(attack_type, success, password, attempts, time_seconds, hash_rate, metadata)


# =================================================
# TESTING
# =================================================

if __name__ == "__main__":
    print("Security Logger Testing")
    print("=" * 70)
    
    # Create logger with console output for testing
    logger = SecurityLogger(enable_console=True)
    
    # Test different log levels
    print("\n1. Testing Log Levels:")
    logger.debug("This is a debug message")
    logger.info("This is an info message")
    logger.warning("This is a warning message")
    logger.error("This is an error message")
    logger.critical("This is a critical message")
    logger.success("This is a success message")
    
    # Test attack logging
    print("\n2. Testing Attack Logging:")
    logger.log_attack_start("Dictionary Attack", "5f4dcc3b5aa765d61d8327deb882cf99", "md5")
    logger.log_attack_end("Dictionary Attack", True, "password", 12345, 5.67, 2176.5)
    
    # Test password analysis logging
    print("\n3. Testing Analysis Logging:")
    logger.log_password_analyzed("Weak", 35.5, ["Too short", "No special chars"])
    
    # Test statistics
    print("\n4. Attack Statistics:")
    stats = logger.get_attack_stats()
    print(f"   Total attacks: {stats['total_attacks']}")
    print(f"   Successful: {stats['successful_attacks']}")
    print(f"   Failed: {stats['failed_attacks']}")
    
    # Test recent logs retrieval
    print("\n5. Recent Attack Logs:")
    recent = logger.get_recent_logs("attack", limit=5)
    for log in recent:
        print(f"   {log.strip()}")
    
    print("\n" + "=" * 70)
    print(f"\nLogs saved to: {logger.log_dir}/")
    print(f"  - attacks.log (attack-specific)")
    print(f"  - system.log (general logs)")
    print(f"  - errors.log (errors only)")
    print(f"  - structured.jsonl (JSON format)")
