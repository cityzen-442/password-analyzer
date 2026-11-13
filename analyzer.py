import math
import re
from getpass import getpass
from pathlib import Path

LETTERS = "abcdefghijklmnopqrstuvwxyz"
DIGITS = "0123456789"
KEYBOARD_ROWS = ["qwertyuiop", "asdfghjkl", "zxcvbnm", "1234567890"]

# Bits of entropy per word for a 7,776-word Diceware-style list: log2(7776)
BITS_PER_WORD = 12.9

# Leetspeak characters and the letters they usually stand for
LEET = str.maketrans({"4": "a", "@": "a", "3": "e", "1": "i",
                      "0": "o", "5": "s", "$": "s", "7": "t"})

# How many points each failed check removes from the score
PENALTIES = {
    "length": 10,
    "common": 100,
    "repeats": 15,
    "sequences": 15,
    "keyboard": 20,
    "years": 15,
    "words": 25,
    "chunks": 25,
    "dupwords": 30,
    "structure": 40,
    "personal": 40,
}


def load_common_passwords(filename="common_passwords.txt"):
    """Load the common password list into a set for fast lookups."""
    path = Path(__file__).parent / filename
    with open(path, encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


def ask_personal_info():
    """Optionally ask for names/nicknames to look for inside the password."""
    raw = input("Optional: names or personal words (separate with commas or "
                "spaces), or press Enter to skip: ")
    items = [x.lower() for x in re.split(r"[,\s]+", raw)]
    return [x for x in items if len(x) >= 3]


def detect_passphrase(password):
    """Return the list of words if this looks like a passphrase, else None."""
    words = [w for w in re.split(r"[-\s]+", password.strip()) if w]
    if len(words) >= 3 and all(w.isalpha() and len(w) >= 2 for w in words):
        return words
    return None


def check_length(password):
    # I chose 12 because longer passwords are harder to guess,
    # and current guidance favors length over complexity.
    if len(password) >= 12:
        return (True, "Good length")
    else:
        return (False, "Too short, use at least 12 characters")


def check_character_types(password):
    """Return which character categories the password contains."""
    return {
        "lowercase": bool(re.search(r"[a-z]", password)),
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "digit": bool(re.search(r"\d", password)),
        "symbol": bool(re.search(r"[^A-Za-z0-9]", password)),
    }


def check_common_password(password, common_passwords):
    """Check if the password appears in the common password list."""
    if password.lower() in common_passwords:
        return (False, "This is a very common password, do not use it")
    return (True, "Not found in the common password list")


def check_repeats(password):
    """Find 3 or more identical characters in a row, like 'aaa'."""
    if re.search(r"(.)\1{2,}", password):
        return (False, "Contains repeated characters (like 'aaa')")
    return (True, "No repeated characters")


def check_sequences(password, length=3):
    """Find runs like 'abc' or '123', forwards or backwards."""
    text = password.lower()
    for source in (LETTERS, DIGITS):
        for i in range(len(text) - length + 1):
            chunk = text[i:i + length]
            if chunk in source or chunk in source[::-1]:
                return (False, f"Contains a sequence ('{chunk}')")
    return (True, "No obvious sequences")


def check_keyboard_walks(password, length=4):
    """Find keys that sit side by side, like 'qwer' or 'asdf'."""
    text = password.lower()
    for row in KEYBOARD_ROWS:
        for i in range(len(text) - length + 1):
            chunk = text[i:i + length]
            if chunk in row or chunk in row[::-1]:
                return (False, f"Contains a keyboard pattern ('{chunk}')")
    return (True, "No keyboard patterns")


def check_years(password):
    """Find years like 1987 or 2024."""
    match = re.search(r"(19|20)\d{2}", password)
    if match:
        return (False, f"Contains a year ('{match.group()}')")
    return (True, "No years found")


def check_common_words(password, common_passwords):
    """Find common words (5+ letters) hiding inside the password."""
    text = password.lower()
    for word in common_passwords:
        if len(word) >= 5 and word in text:
            return (False, f"Contains a common word ('{word}')")
    return (True, "No common words found")


def check_repeated_chunks(password):
    """Find a chunk of 3+ characters repeated, like 'abcabc'."""
    match = re.search(r"(.{3,})\1", password.lower())
    if match:
        return (False, f"Contains a repeated chunk ('{match.group(1)}')")
    return (True, "No repeated chunks")


def check_duplicate_words(words):
    """Fail if a passphrase uses the same word more than once."""
    seen = set()
    for w in (word.lower() for word in words):
        if w in seen:
            return (False, f"Passphrase repeats a word ('{w}')")
        seen.add(w)
    return (True, "No repeated words")


def check_structure(password):
    """Flag the very common shape: letters, then digits, then symbols."""
    letters_digits_symbols = re.fullmatch(r"[A-Za-z]+\d+[^A-Za-z0-9]*", password)
    letters_symbols_digits = re.fullmatch(r"[A-Za-z]+[^A-Za-z0-9]+\d*", password)
    if letters_digits_symbols or letters_symbols_digits:
        return (False, "Follows a predictable shape (word, then digits/symbols)")
    return (True, "No predictable word+digits+symbol shape")


def numeric_forms(item):
    """Ways a name can be turned into digits: hex, binary, ASCII codes."""
    data = item.encode("utf-8")
    forms = [
        ("hex", data.hex()),
        ("binary", "".join(f"{b:08b}" for b in data)),
        ("ASCII-code", "".join(str(b) for b in data)),
    ]
    # Names made only of hex letters (like 'dead' or 'face') can be read
    # as a hex number and converted to decimal or binary.
    if all(c in "0123456789abcdef" for c in item):
        number = int(item, 16)
        forms.append(("hex-value", str(number)))
        forms.append(("hex-value binary", f"{number:b}"))
    return forms


def has_piece(text, form, min_len):
    """True if any piece of `form` (at least min_len long) is inside text."""
    if len(form) < 4:
        return False
    n = min(min_len, len(form))
    return any(form[i:i + n] in text for i in range(len(form) - n + 1))


def check_personal_info(password, items):
    """Look for the user's own names, and digits derived from them."""
    if not items:
        return (True, "Personal-info check skipped (nothing entered)")

    text = password.lower()
    decoded = text.translate(LEET)  # undo leetspeak: 4 -> a, 3 -> e, ...

    for item in items:
        if item in text or item in decoded:
            return (False, f"Contains personal info ('{item}')")
        if item[::-1] in text or item[::-1] in decoded:
            return (False, f"Contains personal info, reversed ('{item}')")
        for label, form in numeric_forms(item):
            min_len = 8 if "binary" in label else 5
            if has_piece(text, form, min_len):
                return (False, f"Contains the {label} form of '{item}'")
    return (True, "No personal info found")


def calculate_entropy(password):
    """Estimate entropy in bits: length x log2(charset size)."""
    types = check_character_types(password)
    charset_size = 0
    if types["lowercase"]:
        charset_size += 26
    if types["uppercase"]:
        charset_size += 26
    if types["digit"]:
        charset_size += 10
    if types["symbol"]:
        charset_size += 32

    if charset_size == 0:
        return 0.0
    return len(password) * math.log2(charset_size)


def calculate_passphrase_entropy(words):
    """Estimate entropy for a passphrase: unique words x bits per word."""
    unique_words = {w.lower() for w in words}
    return len(unique_words) * BITS_PER_WORD


def calculate_score(bits, results):
    """Start from entropy (max 100), then subtract penalties for failed checks."""
    score = min(bits, 100)
    for name, passed, message in results:
        if not passed:
            score -= PENALTIES[name]
    return max(0, round(score))


def verdict(score):
    """Turn the score into a simple label."""
    if score < 40:
        return "Weak"
    elif score < 60:
        return "Fair"
    elif score < 80:
        return "Strong"
    else:
        return "Very strong"


def analyze(password, common_passwords, personal_items=None):
    """Run every check and return the results, entropy and score."""
    personal_items = personal_items or []
    passphrase_words = detect_passphrase(password)

    if passphrase_words:
        # Random passphrases may contain everyday words, so skip this check
        words_result = (True, "Common-word check skipped (passphrase)")
        dup_result = check_duplicate_words(passphrase_words)
        bits = calculate_passphrase_entropy(passphrase_words)
    else:
        words_result = check_common_words(password, common_passwords)
        dup_result = (True, "Repeated-word check skipped (not a passphrase)")
        bits = calculate_entropy(password)

    results = [
        ("length", *check_length(password)),
        ("common", *check_common_password(password, common_passwords)),
        ("repeats", *check_repeats(password)),
        ("sequences", *check_sequences(password)),
        ("keyboard", *check_keyboard_walks(password)),
        ("years", *check_years(password)),
        ("words", *words_result),
        ("chunks", *check_repeated_chunks(password)),
        ("dupwords", *dup_result),
        ("structure", *check_structure(password)),
        ("personal", *check_personal_info(password, personal_items)),
    ]

    return {
        "results": results,
        "bits": bits,
        "score": calculate_score(bits, results),
        "passphrase_words": passphrase_words,
    }


def main():
    common_passwords = load_common_passwords()

    personal_items = ask_personal_info()  # not secret, so plain input()
    password = getpass("Enter a password to analyze: ")
    analysis = analyze(password, common_passwords, personal_items)

    print()
    print("=== Password Analysis ===")
    print(f"Length: {len(password)}")

    types = check_character_types(password)
    found = [name for name, present in types.items() if present]
    print(f"Character types: {', '.join(found) if found else 'none'}")
    print()

    for name, passed, message in analysis["results"]:
        print(f"[{'PASS' if passed else 'FAIL'}] {message}")

    print()
    words = analysis["passphrase_words"]
    if words:
        count = len({w.lower() for w in words})
        print(f"Passphrase detected: {count} unique words")
        print(f"Entropy: {analysis['bits']:.1f} bits (words x {BITS_PER_WORD})")
        print("Note: this assumes the words were chosen randomly.")
    else:
        print(f"Entropy: {analysis['bits']:.1f} bits")

    print(f"Score: {analysis['score']}/100")
    print(f"Verdict: {verdict(analysis['score'])}")


if __name__ == "__main__":
    main()