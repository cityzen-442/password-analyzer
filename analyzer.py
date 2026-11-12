import re
from getpass import getpass


def check_length(password):
    # I chose 8 because longer passwords are harder to guess,
    # and current guidance favors length over complexity.
    if len(password) >= 8:
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


def main():
    password = getpass("Enter a password to analyze: ")
    print(f"Length: {len(password)}")

    is_long_enough, match = check_length(password)
    print(match)

    for category, present in check_character_types(password).items():
        print(f"{category}: {'yes' if present else 'no'}")


if __name__ == "__main__":
    main()