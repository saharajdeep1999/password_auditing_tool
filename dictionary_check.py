def dictionary_check(password, wordlist="rockyou.txt"):
    try:
        with open(wordlist, 'r', errors='ignore') as f:
            common = {line.strip() for line in f}
        return password in common
    except:
        return False  # File error
