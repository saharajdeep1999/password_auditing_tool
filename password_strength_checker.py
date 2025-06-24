import re

def check_strength(password):
    score = 0
    issues = []
    
    # Length check
    if len(password) < 12:
        issues.append("Too short (<12 characters)")
    else:
        score += 1
    
    # Complexity checks
    checks = [
        (r'[A-Z]', "No uppercase letters"),
        (r'[a-z]', "No lowercase letters"),
        (r'[0-9]', "No numbers"),
        (r'[\!\@\#\$\%\^\&\*\(\)]', "No special characters")
    ]
    
    for regex, msg in checks:
        if not re.search(regex, password):
            issues.append(msg)
        else:
            score += 1
    
    # Common patterns
    weak_patterns = [
        "123456", "password", "qwerty", 
        "admin", "welcome", current_year
    ]
    
    if any(patt in password.lower() for patt in weak_patterns):
        issues.append("Contains weak pattern")
        score = max(0, score-2)
    
    return {
        "score": min(score, 5),  # 5-point scale
        "issues": issues
    }
