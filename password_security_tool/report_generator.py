import os
from datetime import datetime
from typing import Optional, List, Dict


class ReportGenerator:
    """Generate text security reports."""
    
    def __init__(self, report_dir: str = "reports"):
        self.report_dir = report_dir
        os.makedirs(report_dir, exist_ok=True)
    
    def generate_full_report(self, password: str, strength: str, entropy: float,
                            issues: List[str], attack_results: Optional[List[Dict]] = None,
                            format: str = "txt") -> str:
        """Generate text security report."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"security_report_{timestamp}.txt"
        content = self._generate_text_report(password, strength, entropy, issues, attack_results)
        
        filepath = os.path.join(self.report_dir, filename)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return filepath
    
    def _generate_text_report(self, password, strength, entropy, issues, attack_results) -> str:
        """Generate detailed text report."""
        lines = [
            "=" * 70,
            "PASSWORD SECURITY ANALYSIS REPORT".center(70),
            "=" * 70,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "=" * 70,
            "1. PASSWORD ANALYSIS",
            "=" * 70,
            f"Password (Masked)    : {'*' * len(password)}",
            f"Password Length      : {len(password)} characters",
            f"Strength Rating      : {strength}",
            f"Entropy              : {entropy:.2f} bits",
            ""
        ]
        
        # Security Issues
        if issues:
            lines.append("Security Issues Found:")
            for i, issue in enumerate(issues, 1):
                lines.append(f"  {i}. {issue}")
            lines.append("")
        else:
            lines.append("Security Issues Found: None\n")
        
        # Attack Results
        if attack_results:
            lines.extend([
                "=" * 70,
                "2. ATTACK RESULTS",
                "=" * 70,
                ""
            ])
            
            for i, result in enumerate(attack_results, 1):
                lines.extend([
                    f"Attack #{i}: {result.get('attack_type', 'Unknown')}",
                    "-" * 70,
                    f"  Status           : {'SUCCESS' if result.get('success') else 'FAILED'}",
                    f"  Algorithm        : {result.get('hash_algorithm', 'N/A')}",
                    f"  Attempts         : {result.get('attempts', 0):,}",
                    f"  Time Taken       : {result.get('time_seconds', 0):.2f} seconds",
                    f"  Hash Rate        : {result.get('hash_rate', 0):,.0f} hashes/sec",
                    ""
                ])
        
        # Recommendations
        lines.extend([
            "=" * 70,
            "3. SECURITY RECOMMENDATIONS",
            "=" * 70
        ])
        
        recommendations = self._generate_recommendations(strength, entropy, issues, attack_results)
        for i, rec in enumerate(recommendations, 1):
            lines.append(f"{i}. {rec}")
        
        lines.extend([
            "",
            "=" * 70,
            "END OF REPORT",
            "=" * 70
        ])
        
        return "\n".join(lines)
    
    def _generate_recommendations(self, strength, entropy, issues, attack_results) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        # Based on strength
        if strength in ["Very Weak", "Weak"]:
            recommendations.append("URGENT: Change this password immediately - highly vulnerable")
            recommendations.append("Use at least 12 characters with mixed case, numbers, and symbols")
        elif strength == "Moderate":
            recommendations.append("Consider strengthening with more character variety")
        else:
            recommendations.append("Password strength is good - maintain this level of security")
        
        # Based on entropy
        if entropy < 40:
            recommendations.append("Low entropy - add more randomness to your password")
        elif entropy < 60:
            recommendations.append("Moderate entropy - consider adding 2-3 more characters")
        
        # Based on issues
        if issues:
            if any("short" in issue.lower() for issue in issues):
                recommendations.append("Increase password length to at least 12 characters")
            if any("uppercase" in issue.lower() for issue in issues):
                recommendations.append("Add uppercase letters (A-Z)")
            if any("lowercase" in issue.lower() for issue in issues):
                recommendations.append("Add lowercase letters (a-z)")
            if any("digit" in issue.lower() for issue in issues):
                recommendations.append("Include numeric digits (0-9)")
            if any("special" in issue.lower() for issue in issues):
                recommendations.append("Add special characters (!@#$%^&*)")
            if any("dictionary" in issue.lower() for issue in issues):
                recommendations.append("Avoid common dictionary words")
            if any("pattern" in issue.lower() for issue in issues):
                recommendations.append("Remove predictable patterns like '123' or 'abc'")
        
        # Based on attack results
        if attack_results:
            successful = [r for r in attack_results if r.get('success')]
            if successful:
                fastest = min(successful, key=lambda x: x.get('time_seconds', float('inf')))
                if fastest.get('time_seconds', 0) < 1:
                    recommendations.append(f"CRITICAL: Cracked in <1 second - change immediately!")
                elif fastest.get('time_seconds', 0) < 60:
                    recommendations.append(f"Cracked in {fastest.get('time_seconds'):.1f}s - use stronger password")
        
        # General recommendations
        recommendations.extend([
            "Use a password manager for complex passwords",
            "Enable two-factor authentication (2FA)",
            "Never reuse passwords across services"
        ])
        
        return recommendations


# Backward-compatible function
def generate_report(password: str, strength: str, entropy: float, cracked: bool,
                   issues: Optional[List[str]] = None,
                   attack_results: Optional[List[Dict]] = None,
                   format: str = "txt") -> str:
    """Generate password security report."""
    generator = ReportGenerator()
    
    try:
        if attack_results is None and cracked:
            attack_results = [{
                "success": True,
                "attack_type": "Analysis",
                "attempts": 0,
                "time_seconds": 0,
                "hash_rate": 0
            }]
        
        filepath = generator.generate_full_report(
            password=password,
            strength=strength,
            entropy=entropy,
            issues=issues or [],
            attack_results=attack_results,
            format=format
        )
        
        return f"[✔] Report generated: {filepath}"
    except Exception as e:
        return f"[✘] Failed to generate report: {e}"


if __name__ == "__main__":
    # Test
    test_data = {
        "password": "Password123!",
        "strength": "Moderate",
        "entropy": 65.5,
        "issues": ["Contains dictionary word", "Common pattern detected"],
        "attack_results": [{
            "success": True,
            "attack_type": "Dictionary Attack",
            "hash_algorithm": "md5",
            "attempts": 10000,
            "time_seconds": 2.5,
            "hash_rate": 4000
        }]
    }
    
    generator = ReportGenerator()
    filepath = generator.generate_full_report(**test_data)
    print(f"✓ Report generated: {filepath}")
