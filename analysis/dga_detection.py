import math


def shannon_entropy(domain):

    prob = [float(domain.count(c)) / len(domain) for c in set(domain)]

    return -sum([p * math.log2(p) for p in prob])


def consonant_ratio(domain):

    vowels = "aeiou"

    letters = [c for c in domain if c.isalpha()]

    if not letters:
        return 0

    consonants = [c for c in letters if c not in vowels]

    return len(consonants) / len(letters)


def dga_score(domain):

    score = 0

    d = domain.lower()

    # longitud
    if len(d) > 20:
        score += 1

    # entropía
    entropy = shannon_entropy(d)
    if entropy > 3.5:
        score += 2

    # consonantes
    ratio = consonant_ratio(d)
    if ratio > 0.7:
        score += 1

    return score


def is_suspicious_domain(domain):

    score = dga_score(domain)

    return score >= 3