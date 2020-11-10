import string as _string
import random
__all__ = ["char", "string"]

# Same length as str(uuid.uuid4())
DEFAULT_RANDOM_LENGTH = 36
CHARSETS = {
    "a-z": _string.ascii_lowercase,
    "A-Z": _string.ascii_uppercase,
    "0-9": _string.digits,
    "!": _string.punctuation
}
CHARSET_CACHE = {}
RANDOM = random.SystemRandom()


def allowed_chars(charsets):
    """ "a-z0-9" -> "abcdefghijklmnopqrstuvwxyz0123456789" """
    legal_chars = CHARSET_CACHE.get(charsets, None)
    if legal_chars is None:
        legal_chars = ""
        for charset, chars in CHARSETS.items():
            if charset in charsets:
                legal_chars += chars
        CHARSET_CACHE[charsets] = legal_chars
    return legal_chars


def char(charsets="a-zA-Z0-9"):
    return RANDOM.choice(allowed_chars(charsets))


def string(length=DEFAULT_RANDOM_LENGTH, charsets="a-z A-Z 0-9"):
    chars = allowed_chars(charsets)
    return "".join(RANDOM.choice(chars) for _ in range(length))


def description_string():
    s = string()
    pos = RANDOM.randint(0, DEFAULT_RANDOM_LENGTH)
    return s[:pos] + u'\u4e16\u754c' + s[pos:]


def string_from_constraints(**constraints):
    """
    Each key of `constraints` is a charset, and the value is the number of values to pull from that charset.

    Example
    =======
    >>> # This pulls 1 punctuation, 1 lowercase, 1 uppercase, 1 digit, and 16 more from any of those sets
    >>> valid_password = {
    ...     "!": 1,
    ...     "a-z": 1,
    ...     "A-Z": 1,
    ...     "0-9": 1,
    ...     "a-z A-Z 0-9 !": 16
    ... }
    ...
    >>> print(string_from_constraints(**valid_password))
    sK-1N2agX{!<%o7kU(-H

    """
    chars = []
    for charset, count in constraints.items():
        rule_chars = allowed_chars(charset)
        chars.extend(RANDOM.choice(rule_chars) for _ in range(count))
    RANDOM.shuffle(chars)
    return "".join(chars)