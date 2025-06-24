import requests
import hashlib

def check_hibp(password):
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    
    try:
        response = requests.get(
            f"https://api.pwnedpasswords.com/range/{prefix}",
            timeout=3
        )
        hashes = [line.split(':') for line in response.text.splitlines()]
        for h, count in hashes:
            if h == suffix:
                return int(count)  # Number of breaches
        return 0
    except:
        return -1  # API error

