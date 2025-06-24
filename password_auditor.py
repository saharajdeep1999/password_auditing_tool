import re
import requests
import hashlib
import logging
import getpass
import json
import argparse
from datetime import datetime

# Configure logging
logging.basicConfig(level=logging.ERROR, format='%(asctime)s - %(levelname)s: %(message)s')

def visual_strength_meter(score):
    """Create a color-coded visual strength meter"""
    colors = ["\033[91m", "\033[93m", "\033[92m"]  # Red, Yellow, Green
    meter = "[" + "█" * score + " " * (5-score) + "]"
    
    if score <= 2:
        return colors[0] + meter + "\033[0m"
    elif score <= 4:
        return colors[1] + meter + "\033[0m"
    else:
        return colors[2] + meter + "\033[0m"

def check_strength(password):
    current_year = str(datetime.now().year)
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

def check_hibp(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=3
        )
        response.raise_for_status()
        hashes = (line.split(':') for line in response.text.splitlines())
        for h, count in hashes:
            if h == suffix:
                return int(count)  # Number of breaches
        return 0
    except Exception as e:
        logging.error(f"HIBP API error: {str(e)}")
        return -1

def dictionary_check(password, wordlist="rockyou.txt"):
    try:
        with open(wordlist, 'r', errors='ignore', encoding='latin-1') as f:
            common_passwords = {line.strip() for line in f}
        return password in common_passwords
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist}")
        return False
    except Exception as e:
        logging.error(f"Dictionary error: {str(e)}")
        return False

def check_policy(password, min_length=12, min_score=4):
    strength = check_strength(password)
    return strength["score"] >= min_score and len(password) >= min_length

def audit_password(password, wordlist):
    results = {
        "strength": check_strength(password),
        "breach_count": check_hibp(password),
        "in_dictionary": dictionary_check(password, wordlist),
        "policy_compliant": check_policy(password)
    }
    
    # Generate recommendation
    recommendations = []
    if results["breach_count"] > 0:
        recommendations.append(f"Password found in {results['breach_count']} breaches - change immediately!")
    if results["in_dictionary"]:
        recommendations.append("Password is in common wordlists - choose something more unique")
    if not results["policy_compliant"]:
        recommendations.append("Password doesn't meet security policy requirements")
    if not recommendations:
        recommendations.append("Password meets basic security standards")
    
    results["recommendations"] = recommendations
    return results

def generate_json_report(report, filename=None):
    """Generate JSON report, save to file or print to stdout"""
    # Create a safe copy without color codes
    report_copy = report.copy()
    if 'strength' in report_copy:
        report_copy['strength'].pop('visual_meter', None)
    
    json_data = json.dumps(report_copy, indent=2)
    
    if filename:
        with open(filename, 'w') as f:
            f.write(json_data)
        print(f"\nJSON report saved to {filename}")
    else:
        print("\nJSON Report:")
        print(json_data)

def main():
    parser = argparse.ArgumentParser(description='Password Security Auditor')
    parser.add_argument('--wordlist', default='rockyou.txt', 
                        help='Path to wordlist file')
    parser.add_argument('--json', action='store_true',
                        help='Output report in JSON format')
    parser.add_argument('--output', default=None,
                        help='Filename to save JSON report')
    args = parser.parse_args()

    print("=== Password Security Auditor ===")
    print("WARNING: Only audit your own passwords with proper authorization\n")
    
    password = getpass.getpass("Enter password to audit (input hidden): ")
    
    print("\nAuditing...")
    report = audit_password(password, args.wordlist)
    
    # Add visual meter to strength report
    report['strength']['visual_meter'] = visual_strength_meter(
        report['strength']['score']
    )
    
    # Clear password from memory ASAP
    del password
    
    if args.json:
        generate_json_report(report, args.output)
        return
    
    # Terminal output
    print("\n=== Audit Report ===")
    print(f"Strength Meter: {report['strength']['visual_meter']} ({report['strength']['score']}/5)")
    if report['strength']['issues']:
        print("Issues:")
        for issue in report['strength']['issues']:
            print(f"  - {issue}")
    
    print(f"\nBreach Status: {'Exposed in ' + str(report['breach_count']) + ' breaches' if report['breach_count'] > 0 else 'Not found in known breaches'}")
    print(f"Dictionary Status: {'Found in common wordlists' if report['in_dictionary'] else 'Not in common wordlists'}")
    print(f"Policy Compliance: {'Compliant' if report['policy_compliant'] else 'Non-compliant'}")
    
    print("\nRecommendations:")
    for rec in report['recommendations']:
        print(f"  - {rec}")
    
    # Offer to save as JSON
    save = input("\nSave as JSON? (y/N): ").lower()
    if save == 'y':
        filename = input("Filename [audit_report.json]: ") or "audit_report.json"
        generate_json_report(report, filename)

if __name__ == "__main__":
    main()
