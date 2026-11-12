import re
from getpass import getpass
from pathlib import Path


def load_common_passwords(filename="common_passwords.txt"):
    """Load the common password list into a set for fast lookups."""
    path = Path(__file__).parent / filename
    with open(path, encoding="utf-8", errors="ignore") as f:
        return {line.strip().lower() for line in f if line.strip()}


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
    else:
        return (True, "Not found in the common password list")


def main():
    common_passwords = load_common_passwords()

    password = getpass("Enter a password to analyze: ")
    print(f"Length: {len(password)}")

    is_long_enough, message = check_length(password)
    print(message)

    is_not_common, message = check_common_password(password, common_passwords)
    print(message)

    for category, present in check_character_types(password).items():
        print(f"{category}: {'yes' if present else 'no'}")


if __name__ == "__main__":
    main()