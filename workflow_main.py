def audit_password(password):
    results = {}
    
    # Never store passwords!
    results["strength"] = check_strength(password)
    results["breach_count"] = check_hibp(password)
    results["in_dictionary"] = dictionary_check(password)
    results["policy_compliant"] = check_policy(password)
    
    return results

# Example usage
if __name__ == "__main__":
    import getpass
    pwd = getpass.getpass("Password to audit: ")
    report = audit_password(pwd)
    print(report)
