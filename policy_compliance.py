def check_policy(password, min_length=12, min_score=4):
    strength = check_strength(password)
    return strength["score"] >= min_score and len(password) >= min_length
