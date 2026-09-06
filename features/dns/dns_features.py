import math
from collections import Counter


def shannon_entropy(text):
    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)

    return -sum(
        (count / total) * math.log2(count / total)
        for count in counts.values()
    )


def count_transitions(text):
    """
    Count transitions between alphabetic and numeric characters.
    Example:
        ab12cd -> 2 transitions
    """
    count = 0

    for i in range(1, len(text)):
        prev_is_digit = text[i - 1].isdigit()
        curr_is_digit = text[i].isdigit()

        if prev_is_digit != curr_is_digit:
            count += 1

    return count


def max_consecutive_run(text, predicate):
    """
    Maximum consecutive characters satisfying predicate.
    """
    best = 0
    current = 0

    for char in text:
        if predicate(char):
            current += 1
            best = max(best, current)
        else:
            current = 0

    return best


def extract_dns_features(domain):
    domain = str(domain).strip().lower()

    if not domain:
        return {
            "domain_length": 0,
            "entropy": 0.0,
            "digit_ratio": 0.0,
            "letter_ratio": 0.0,
            "unique_char_ratio": 0.0,
            "hyphen_ratio": 0.0,
            "num_labels": 0,
            "max_label_length": 0,
            "first_label_length": 0,
            "subdomain_length": 0,
            "digit_letter_transitions": 0,
            "max_consecutive_digits": 0,
            "max_consecutive_letters": 0,
        }

    # DNS labels separated by dots.
    labels = [label for label in domain.split(".") if label]

    # Features on the complete observed query name.
    length = len(domain)
    digits = sum(c.isdigit() for c in domain)
    letters = sum(c.isalpha() for c in domain)
    hyphens = domain.count("-")
    unique_chars = len(set(domain))

    first_label = labels[0] if labels else ""

    # Treat everything before the final two labels as subdomain material
    # when enough labels are present.
    if len(labels) > 2:
        subdomain = ".".join(labels[:-2])
    elif len(labels) > 1:
        subdomain = labels[0]
    else:
        subdomain = ""

    return {
        "domain_length": length,
        "entropy": shannon_entropy(domain),
        "digit_ratio": digits / length,
        "letter_ratio": letters / length,
        "unique_char_ratio": unique_chars / length,
        "hyphen_ratio": hyphens / length,
        "num_labels": len(labels),
        "max_label_length": max((len(label) for label in labels), default=0),
        "first_label_length": len(first_label),
        "subdomain_length": len(subdomain),
        "digit_letter_transitions": count_transitions(domain),
        "max_consecutive_digits": max_consecutive_run(
            domain,
            lambda c: c.isdigit()
        ),
        "max_consecutive_letters": max_consecutive_run(
            domain,
            lambda c: c.isalpha()
        ),
    }